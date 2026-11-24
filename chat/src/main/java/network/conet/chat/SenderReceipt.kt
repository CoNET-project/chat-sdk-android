package network.conet.chat

import org.json.JSONArray
import org.json.JSONObject
import java.util.UUID

/**
 * The sender delivery receipt (`beamio_chat_delivery_receipt_v1`): after the page has stored an inbound message and sent `ackInbound`, the module
 * tells the message's sender that it arrived. The sender's page turns it into "Delivered".
 *
 * Rules (the delivery-receipt protocol over `setRoutes`; vectors DR-01..18). Kept apart from the module so
 * every decision is testable without Android:
 *  - **Whitelist.** Only an ordinary user chat message earns a receipt: a JSON envelope whose signed text is a pending message with a non-empty
 *    `sendId`, no `type`, no group id, and whose own `text` does not hold a typed frame, a call signal or an array. A receipt, a call-control signal,
 *    a voice message, a group message and every type this code does not know earn none ([classify]).
 *  - **Routes come from the page** ([setRoutes], full replacement, validated, memory only). A receipt whose sender has no route waits in a bounded
 *    queue (from, sendId, armorHash; no text) and is sent when a later `setRoutes` brings that sender, or dropped after [QUEUE_TTL_MS].
 *  - **One message, one receipt**: by armorHash and by (from, sendId) (a copy with another armor still earns none).
 *  - **At most [IN_FLIGHT_MAX] receipts at once**; the rest wait in the same queue. Receipts run on the worker, never on the command thread.
 *  - **Session-bound**: [Pipeline.clear] (identity clear, account switch, session end) drops routes, queue and the dedupe sets; a receipt whose
 *    session ended is dropped before it is built and again before it is posted.
 * Nothing here holds a key or signs; the signing and the send are the module's `handleSend`.
 */
internal object SenderReceipt {
    const val TYPE = "beamio_chat_delivery_receipt_v1"
    const val MAX_ROUTES = 256
    const val MAX_ARMOR_BYTES = 32 * 1024
    const val QUEUE_MAX = 128
    const val QUEUE_TTL_MS = 10 * 60 * 1000L
    const val DEDUPE_MAX = 1024
    const val IN_FLIGHT_MAX = 2

    /** A send that never reports back must not hold a slot for ever. */
    const val IN_FLIGHT_STALE_MS = 30_000L
    private const val PGP_MARK = "BEGIN PGP PUBLIC KEY"
    private val EOA_RE = Regex("^0x[0-9a-f]{40}$")

    // ---- the whitelist ------------------------------------------------------------------------------------------------

    sealed class Verdict {
        class Ordinary(val sendId: String) : Verdict()

        /** [reason]: `receipt`, `control`, `voice`, `unknown_type`, `group`, `reply`, `call_record`, `no_send_id`, `not_chat`. */
        class Reject(val reason: String) : Verdict()
    }

    private fun parseObject(text: String?): JSONObject? {
        val t = text?.trim().orEmpty()
        if (!t.startsWith("{")) return null
        return runCatching { JSONObject(t) }.getOrNull()
    }

    private fun typeReason(type: Any?): String {
        val t = type as? String ?: return "unknown_type"
        return when {
            t == TYPE -> "receipt"
            t.startsWith("voice_") -> if (BeamioConetChatCallSignal.KINDS.containsKey(t)) "control" else "voice"
            else -> "unknown_type"
        }
    }

    private fun present(o: JSONObject, key: String): Boolean = o.has(key) && !o.isNull(key)

    /** The reason one layer's top-level fields exclude it from receipts, or null. Only the top level counts: a nested `voiceMessage.type` does not. */
    private fun layerReason(o: JSONObject): String? = when {
        present(o, "type") -> typeReason(o.opt("type"))
        present(o, "groupId") -> "group"
        present(o, "reply") -> "reply"
        present(o, "callRecord") -> "call_record"
        else -> null
    }

    /** Layers the unwrapping follows (compatible with the page's `extractInboundSendId`). */
    const val MAX_DEPTH = 6

    /**
     * Whether [plaintext] (a decrypted line) is an ordinary user chat message that may earn a receipt, and its `sendId` (vectors
     * DR-23..30; the same rule as the iOS SDK).
     *
     * The signed envelope (`{timestamp, text, from, signMessage}`) is not a layer: its top level is checked for the exclusion fields like any layer, but the count starts with its `text`. Its signed text is the page's
     * ChatMessage (layer 1). The unwrapping follows a string `text` that is a JSON object, at most [MAX_DEPTH] object layers (a seventh object layer
     * earns nothing: fail closed); the text that ends it is the user's words (any non-object) and is not looked at. A layer whose top level carries `type`, `groupId`, `reply` or `callRecord` excludes the message; so does a
     * first layer that is not an object (plain text, an array, a scalar, a failed parse), more than [MAX_DEPTH] object layers, and
     * the absence of a non-empty string `sendId` in the first layer itself (an inner layer's does not stand in for it). Text, quote, voiceMessage, fileMessage (image, video, PDF, archive
     * and any file) and paymentCard messages are ordinary.
     */
    fun classify(plaintext: String): Verdict {
        val envelope = parseObject(plaintext) ?: return Verdict.Reject("not_chat")
        layerReason(envelope)?.let { return Verdict.Reject(it) }
        // A call signal may sit under base64 or in an array; the call-signal reader finds those too.
        if (BeamioConetChatCallSignal.classify(plaintext) != null) return Verdict.Reject("control")
        var cur: String = envelope.optString("text", "").ifEmpty { envelope.optString("message", "") }
        var sendId = ""
        var depth = 0
        while (true) {
            val t = cur.trim()
            val layer: JSONObject
            val parsed = if (t.startsWith("{")) runCatching { JSONObject(t) }.getOrNull() else null
            if (parsed == null) {
                // The first layer must be a message object: a payload that is an array, a scalar, plain text or unparsable earns nothing. Below it a
                // text that is no object (plain words, "[1,2]", "123", "true", "null", broken JSON) is the user's own text, the leaf: it ends the
                // unwrapping and is not looked at.
                if (depth == 0) return Verdict.Reject("not_chat")
                break
            }
            layer = parsed
            depth++
            if (depth > MAX_DEPTH) return Verdict.Reject("not_chat")
            layerReason(layer)?.let { return Verdict.Reject(it) }
            if (depth == 1) {
                // The first layer carries its own sendId; one found only in an inner layer does not stand in for it.
                sendId = layer.opt("sendId").let { if (it is String) it else "" }
                if (sendId.isEmpty()) return Verdict.Reject("no_send_id")
            }
            cur = layer.opt("text").let { if (it is String) it else break }
        }
        return if (sendId.isEmpty()) Verdict.Reject("no_send_id") else Verdict.Ordinary(sendId)
    }

    // ---- setRoutes ----------------------------------------------------------------------------------------------------

    sealed class SetResult {
        /** [routes]: eoa (lower case) → `{eoaAddress, userPublicKeyArmored, routerArmoredPublicKey}`. */
        class Ok(val routes: Map<String, JSONObject>, val accepted: Int, val dropped: Int) : SetResult()

        /** `not_ready`, `bad_request` or `signer_mismatch`. Nothing changes. */
        class Err(val code: String) : SetResult()
    }

    /**
     * Validates one `setRoutes` body against the session's account ([sessionEoa], null or blank when there is no session). The whole command is
     * refused (`bad_request`) for a non-array `routes`, a missing `eoa`, more than [MAX_ROUTES] rows or any armor over [MAX_ARMOR_BYTES]; a command
     * for another account is `signer_mismatch`; a row that is not an object, has no valid address or lacks a PGP block in either key is dropped on its own.
     */
    fun setRoutes(body: JSONObject, sessionEoa: String?): SetResult {
        if (sessionEoa.isNullOrBlank()) return SetResult.Err("not_ready")
        val arr = body.opt("routes") as? JSONArray ?: return SetResult.Err("bad_request")
        val eoa = (body.opt("eoa") as? String)?.trim()?.lowercase().orEmpty()
        if (eoa.isEmpty()) return SetResult.Err("bad_request")
        if (eoa != sessionEoa.trim().lowercase()) return SetResult.Err("signer_mismatch")
        if (arr.length() > MAX_ROUTES) return SetResult.Err("bad_request")
        for (i in 0 until arr.length()) {
            val row = arr.optJSONObject(i) ?: continue
            for (k in listOf("userPublicKeyArmored", "routerArmoredPublicKey")) {
                val v = row.opt(k) as? String ?: continue
                if (v.toByteArray(Charsets.UTF_8).size > MAX_ARMOR_BYTES) return SetResult.Err("bad_request")
            }
        }
        val out = LinkedHashMap<String, JSONObject>()
        var dropped = 0
        for (i in 0 until arr.length()) {
            val row = arr.optJSONObject(i)
            if (row == null) {
                dropped++
                continue
            }
            val address = listOf("eoaAddress", "eoa", "address").firstNotNullOfOrNull { (row.opt(it) as? String)?.trim()?.lowercase()?.takeIf { v -> v.isNotEmpty() } }
            val user = row.opt("userPublicKeyArmored") as? String
            val router = row.opt("routerArmoredPublicKey") as? String
            if (address == null || !EOA_RE.matches(address) || user == null || router == null || !user.contains(PGP_MARK) || !router.contains(PGP_MARK)) {
                dropped++
                continue
            }
            // The same address twice: the later row wins.
            out[address] = JSONObject().put("eoaAddress", address).put("userPublicKeyArmored", user).put("routerArmoredPublicKey", router)
        }
        return SetResult.Ok(out, out.size, dropped)
    }

    // ---- the capability -----------------------------------------------------------------------------------------------

    /** The hello capability that tells the page this SDK sends the sender receipts safely (revision 1, vectors DR-21). */
    const val CAPABILITY = "receipt.delivery.v1"

    /**
     * DR-21: whether this build has everything the capability promises: the limits of the protocol, the typed answers of `setRoutes` with the
     * account check, the whitelist, the two dedupe sets, the in-flight limit, the queue and the clear. The hello declares the capability only when
     * this is true, so a part weakened or removed makes the SDK stop declaring it. Pure; runs once at start with a fake executor.
     */
    fun implementationComplete(): Boolean = try {
        probe()
    } catch (_: Throwable) {
        false
    }

    private fun probe(): Boolean {
        if (MAX_ROUTES != 256 || MAX_ARMOR_BYTES != 32 * 1024 || QUEUE_MAX != 128 || QUEUE_TTL_MS != 10 * 60 * 1000L) return false
        if (DEDUPE_MAX != 1024 || IN_FLIGHT_MAX != 2 || MAX_DEPTH != 6) return false
        val me = "0x" + "1".repeat(40)
        val peer = "0x" + "2".repeat(40)
        val key = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nx\n-----END PGP PUBLIC KEY BLOCK-----"
        val row = JSONObject().put("eoaAddress", peer).put("userPublicKeyArmored", key).put("routerArmoredPublicKey", key)
        fun body(routes: Any?, eoa: String?) = JSONObject().apply { if (routes != null) put("routes", routes); if (eoa != null) put("eoa", eoa) }
        // setRoutes answers: every failure is typed, the account is checked
        if ((setRoutes(body(JSONArray(), me), null) as? SetResult.Err)?.code != "not_ready") return false
        if ((setRoutes(body("x", me), me) as? SetResult.Err)?.code != "bad_request") return false
        if ((setRoutes(body(JSONArray(), peer), me) as? SetResult.Err)?.code != "signer_mismatch") return false
        val ok = setRoutes(body(JSONArray().put(row), me), me) as? SetResult.Ok ?: return false
        // whitelist
        fun line(inner: JSONObject) = JSONObject().put("text", inner.toString()).put("signMessage", "0xs").toString()
        val chat = { id: String -> line(JSONObject().put("sendId", id).put("text", "hi")) }
        if (classify(chat("a")) !is Verdict.Ordinary) return false
        if (classify(line(JSONObject().put("sendId", "a").put("text", JSONObject().put("type", TYPE).toString()))) !is Verdict.Reject) return false
        if (classify(line(JSONObject().put("sendId", "a").put("reply", JSONObject()))) !is Verdict.Reject) return false
        if (classify(chat("")) !is Verdict.Reject) return false
        // queue, dedupe, in-flight limit, clear
        val jobs = ArrayList<Runnable>()
        var started = 0
        lateinit var p: Pipeline
        p = Pipeline(execute = { jobs.add(it) }, alive = { true }, ownEoa = { me }, send = { _, _, _ -> started++ }, log = {})
        if (p.onAcked(chat("1"), "h1", peer) != "queued") return false
        if (p.onAcked(chat("1"), "h1", peer) != "already_receipted") return false
        if (p.onAcked(chat("1"), "h-other-armor", peer) != "already_receipted") return false
        if (p.onAcked(chat("9"), "h1", peer) != "already_receipted") return false // the same armor under another sendId is the same copy
        p.onAcked(chat("2"), "h2", peer)
        p.onAcked(chat("3"), "h3", peer)
        if (p.queueSize() != 3 || started != 0) return false // no route yet: queued, nothing sent
        p.setRoutes(ok.routes)
        while (jobs.isNotEmpty()) jobs.removeAt(0).run()
        if (started != IN_FLIGHT_MAX || p.inFlightCount() != IN_FLIGHT_MAX || p.queueSize() != 1) return false
        p.clear()
        return p.routeCount() == 0 && p.queueSize() == 0
    }

    // ---- the pipeline -------------------------------------------------------------------------------------------------

    private class Item(val from: String, val sendId: String, val armorHash: String, val at: Long)

    private class Job(val token: Long, val item: Item, val route: JSONObject, val epoch: Long)

    private fun boundedAdd(set: LinkedHashSet<String>, key: String, cap: Int): Boolean {
        if (!set.add(key)) return false
        if (set.size > cap) set.iterator().let { it.next(); it.remove() }
        return true
    }

    /**
     * One session's receipt state: the contacts' routes, the queue of receipts still to send, the in-flight slots and the dedupe sets. All of it is
     * under one lock; [send] and [execute] run outside it. [send] hands the route and the payload to the module's `handleSend` and must call its
     * `done` once when the receipt has been posted or has failed (a send that never does is released after [IN_FLIGHT_STALE_MS]).
     */
    class Pipeline(
        private val execute: (Runnable) -> Unit,
        private val alive: () -> Boolean,
        private val ownEoa: () -> String,
        private val send: (route: JSONObject, payload: String, done: () -> Unit) -> Unit,
        private val log: (String) -> Unit,
        private val nowMs: () -> Long = { System.currentTimeMillis() },
        private val newId: () -> String = { UUID.randomUUID().toString() },
    ) {
        private val lock = Any()
        private var routes: Map<String, JSONObject> = emptyMap()
        private val queue = ArrayDeque<Item>()
        private val inFlight = HashMap<Long, Long>()
        private val seenPairs = LinkedHashSet<String>()
        private val seenArmors = LinkedHashSet<String>()
        private var nextToken = 0L
        private var epoch = 0L

        /**
         * A message the page has stored. Returns what became of it: `queued`, or the reason it earns none. The mailbox ACK is not decided here.
         */
        fun onAcked(plaintext: String, armorHash: String, from: String): String {
            val sendId = when (val v = classify(plaintext)) {
                is Verdict.Reject -> return skip(v.reason)
                is Verdict.Ordinary -> v.sendId
            }
            val fromLower = from.trim().lowercase()
            if (fromLower.isEmpty()) return skip("no_sender")
            if (fromLower == ownEoa().trim().lowercase()) return skip("self")
            synchronized(lock) {
                val pair = "$fromLower:$sendId"
                if (armorHash.isNotBlank() && seenArmors.contains(armorHash)) return skip("already_receipted")
                if (seenPairs.contains(pair)) return skip("already_receipted")
                if (armorHash.isNotBlank()) boundedAdd(seenArmors, armorHash, DEDUPE_MAX)
                boundedAdd(seenPairs, pair, DEDUPE_MAX)
                queue.addLast(Item(fromLower, sendId, armorHash, nowMs()))
                while (queue.size > QUEUE_MAX) {
                    queue.removeFirst()
                    log("[send] kind=receipt dropped=queue_full")
                }
            }
            log("[send] kind=receipt queued")
            pump()
            return "queued"
        }

        /** The page's full route table replaces the old one; queued receipts whose sender is now known go out. */
        fun setRoutes(table: Map<String, JSONObject>) {
            synchronized(lock) { routes = LinkedHashMap(table) }
            pump()
        }

        /**
         * Identity clear, account switch, session end: routes, queue and dedupe sets are dropped. A receipt already handed to the worker is not posted
         * (its epoch is gone); it still frees its slot when it ends, so the slots stay true.
         */
        fun clear() {
            synchronized(lock) {
                epoch++
                routes = emptyMap()
                queue.clear()
                seenPairs.clear()
                seenArmors.clear()
            }
        }

        fun routeCount(): Int = synchronized(lock) { routes.size }

        fun queueSize(): Int = synchronized(lock) { queue.size }

        fun inFlightCount(): Int = synchronized(lock) { inFlight.size }

        private fun skip(reason: String): String {
            log("[send] kind=receipt skip=$reason")
            return reason
        }

        /** Starts what the slots and the routes allow. */
        private fun pump() {
            val jobs = ArrayList<Job>()
            var expired = 0
            synchronized(lock) {
                val t = nowMs()
                val it = queue.iterator()
                while (it.hasNext()) {
                    if (t - it.next().at >= QUEUE_TTL_MS) {
                        it.remove()
                        expired++
                    }
                }
                inFlight.entries.removeAll { t - it.value >= IN_FLIGHT_STALE_MS }
                val q = queue.iterator()
                while (q.hasNext() && inFlight.size < IN_FLIGHT_MAX) {
                    val item = q.next()
                    val route = routes[item.from] ?: continue
                    q.remove()
                    val token = ++nextToken
                    inFlight[token] = t
                    jobs.add(Job(token, item, route, epoch))
                }
            }
            if (expired > 0) log("[send] kind=receipt dropped=expired n=$expired")
            for (job in jobs) execute(Runnable { run(job) })
        }

        private fun release(job: Job) {
            val had = synchronized(lock) { inFlight.remove(job.token) != null }
            if (had) pump()
        }

        private fun current(job: Job): Boolean = synchronized(lock) { job.epoch == epoch } && alive()

        private fun run(job: Job) {
            try {
                if (!current(job)) {
                    log("[send] kind=receipt skip=session_ended")
                    release(job)
                    return
                }
                val now = nowMs()
                val receipt = JSONObject()
                    .put("type", TYPE)
                    .put("sendId", job.item.sendId)
                    .put("armorHash", job.item.armorHash)
                    .put("deliveredAt", now)
                    .put("from", ownEoa())
                val pending = JSONObject()
                    .put("sendId", newId())
                    .put("from", "me")
                    .put("text", receipt.toString())
                    .put("createdAt", now)
                log("[send] kind=receipt start")
                val done = java.util.concurrent.atomic.AtomicBoolean(false)
                send(job.route, pending.toString()) {
                    if (done.compareAndSet(false, true)) release(job)
                }
            } catch (e: Exception) {
                log("[send] kind=receipt failed=${e.javaClass.simpleName}")
                release(job)
            }
        }
    }
}
