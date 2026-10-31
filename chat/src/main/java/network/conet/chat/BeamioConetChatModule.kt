package network.conet.chat

import android.content.Context
import android.os.Handler
import android.os.Looper
import android.util.Log
import org.json.JSONArray
import org.json.JSONObject
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/**
 * Native Conet Chat module — WorkerCommand / WorkerOutbound parity with
 * `@conet.project/chat-sdk`, model 1B signing (the host PWA signs, see
 * [BeamioConetChatSignBroker]).
 *
 * Wire contract (same as the iOS `ConetChatSDK`):
 *  - PWA → native: `handleCommand({ type, reqId, … })`
 *  - native → PWA: `{ action: "chatModuleEvent", event: { type: "ready" | "ack" | "event:*", … } }`
 *    and `{ action: "chatModuleSignRequest", … }` (through the same emitter).
 */
object BeamioConetChatModule {
    private const val TAG = "BeamioConetChat"

    /** Entry / mailbox node with optional route PGP (from the PWA `setNodes`). */
    data class Node(
        val ip: String,
        val domain: String,
        val region: String,
        val armoredPublicKey: String,
    ) {
        fun asStoreNode() = BeamioChatPgpStore.SiNode(ip, domain, region)
    }

    class Session {
        @Volatile var eoa: String = ""
        @Volatile var pgpPrivateKeyArmored: String = ""
        @Volatile var pgpPublicKeyArmored: String = ""
        @Volatile var pgpPassphrase: String = ""
        @Volatile var ownRouteArmoredPublicKey: String = ""
        @Volatile var mailboxIp: String = ""
        @Volatile var nodes: List<Node> = emptyList()
        @Volatile var routes: List<JSONObject> = emptyList()
        @Volatile var conetRpcUrl: String = "https://rpc1.conet.network"
        @Volatile var ipfsBaseUrl: String = "https://ipfs.conet.network/api"
        @Volatile var ipfsWriteBaseUrl: String = ""
        @Volatile var apiBaseUrl: String = "https://beamio.app/api"
        @Volatile var chatIndexRegistryAddress: String = "0x1511Caa71081C84d8a591490D1b83879088EED72"
        @Volatile var chainId: Int = 224422
        @Volatile var history: BeamioConetChatHistoryStore? = null
        @Volatile var destroyed: Boolean = false
    }

    private val lock = Any()
    private var session: Session? = null
    private var appContext: Context? = null

    @Volatile
    private var emitFn: ((JSONObject) -> Unit)? = null
    private val listen = BeamioConetChatListenSession()
    private val voiceSessions = HashSet<String>()
    private val seenArmor = object : LinkedHashMap<String, Boolean>(256, 0.75f, false) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Boolean>?): Boolean = size > 512
    }
    private val main = Handler(Looper.getMainLooper())
    private val io = Executors.newCachedThreadPool { r ->
        Thread(r, "conet-chat-module").apply { isDaemon = true }
    }

    fun isAvailable(): Boolean = true

    fun isRunning(): Boolean = synchronized(lock) { session != null } && listen.isRunning()

    /**
     * Entry point for every PWA command. [emit] delivers payloads to the web layer
     * (the shell dispatches them as a `cashtreesandroid` `CustomEvent`).
     */
    fun handleCommand(context: Context, body: JSONObject, emit: (JSONObject) -> Unit) {
        appContext = context.applicationContext
        emitFn = emit
        BeamioConetChatSignBroker.setEmit(emit)
        when (val type = body.optString("type", "")) {
            "init" -> handleInit(body)
            "setRoutes" -> currentSession()?.let { s -> body.optJSONArray("routes")?.let { s.routes = objects(it) } }
            "setNodes" -> currentSession()?.let { s -> body.optJSONArray("nodes")?.let { s.nodes = parseNodes(it) } }
            "nodesResponse" -> Unit
            "send" -> handleSend(body)
            "sendGroup", "issueGroupRoster", "issueGroupTombstone" -> handleGroup(body)
            "queryPresence" -> handleQueryPresence(body)
            "queryNativeWake" -> handleQueryNativeWake(body)
            "historyLoad" -> handleHistoryLoad(body)
            "historyRead" -> handleHistoryRead(body)
            "historyAppend" -> handleHistoryAppend(body)
            "mailboxCommand" -> handleMailboxCommand(body)
            "ownMailboxCommand" -> {
                currentSession()?.let { body.put("routerArmoredPublicKey", it.ownRouteArmoredPublicKey) }
                handleMailboxCommand(body)
            }
            "voiceFrame" -> handleVoiceFrame(body)
            "voiceListen" -> handleVoiceListen(body)
            "voiceUnlisten" -> handleVoiceUnlisten(body)
            "pause" -> {
                listen.pause()
                emitEvent(JSONObject().put("type", "event:status").put("payload", statusPayload("idle", "paused")))
            }
            "resume" -> resumeListen()
            "destroy" -> destroy()
            else -> Log.w(TAG, "unknown command $type")
        }
    }

    /** PWA answered a `chatModuleSignRequest`. */
    fun fulfillSign(body: JSONObject) = BeamioConetChatSignBroker.fulfill(body)

    // ---- init / routes / nodes -----------------------------------------------------

    private fun handleInit(body: JSONObject) {
        val reqId = body.optInt("reqId", 0)
        val ctx = appContext ?: return
        val payload = body.optJSONObject("payload")
        if (payload == null) {
            ack(reqId, false, error = "missing_payload")
            return
        }
        val s = Session()
        synchronized(lock) {
            listen.stop()
            session?.history?.destroy()
            session = s
        }

        payload.optJSONObject("identity")?.let { id ->
            s.eoa = normalizeAddress(id.optString("eoaAddress", "").ifBlank { id.optString("eoa", "") })
            s.pgpPrivateKeyArmored = id.optString("pgpPrivateKeyArmored", "")
            s.pgpPublicKeyArmored = id.optString("pgpPublicKeyArmored", "")
            s.pgpPassphrase = id.optString("pgpPassphrase", "")
            s.ownRouteArmoredPublicKey = id.optString("ownRouteArmoredPublicKey", "")
                .ifBlank { id.optString("routePublicKeyArmored", "") }
            s.mailboxIp = id.optString("mailboxIp", "")
        }
        if (s.pgpPrivateKeyArmored.isEmpty() || s.ownRouteArmoredPublicKey.isEmpty()) {
            BeamioChatPgpStore.load(ctx)?.let { kc ->
                if (s.pgpPrivateKeyArmored.isEmpty()) s.pgpPrivateKeyArmored = kc.privateKeyArmor
                if (s.pgpPublicKeyArmored.isEmpty()) s.pgpPublicKeyArmored = kc.publicKeyArmor
                if (s.ownRouteArmoredPublicKey.isEmpty()) s.ownRouteArmoredPublicKey = kc.routePublicKeyArmor
                if (s.mailboxIp.isEmpty()) s.mailboxIp = kc.mailboxIp
                if (s.eoa.isEmpty()) s.eoa = normalizeAddress(kc.eoa)
            }
        }
        s.conetRpcUrl = payload.optString("conetRpcUrl", "").ifBlank { s.conetRpcUrl }
        s.ipfsBaseUrl = payload.optString("ipfsBaseUrl", "").ifBlank { s.ipfsBaseUrl }
        s.ipfsWriteBaseUrl = payload.optString("ipfsWriteBaseUrl", "")
        s.apiBaseUrl = payload.optString("apiBaseUrl", "").ifBlank { s.apiBaseUrl }
        s.chatIndexRegistryAddress = payload.optString("chatIndexRegistryAddress", "")
            .ifBlank { s.chatIndexRegistryAddress }
        if (payload.has("chainId")) s.chainId = payload.optInt("chainId", s.chainId)

        val nodesRaw = payload.optJSONArray("nodes")
        if (nodesRaw != null) {
            s.nodes = parseNodes(nodesRaw)
        } else {
            val saved = BeamioChatPgpStore.loadSiNodes(ctx)
            if (saved.isNotEmpty()) s.nodes = saved.map { Node(it.ip, it.domain, it.region, "") }
        }
        payload.optJSONArray("routes")?.let { s.routes = objects(it) }

        if (s.eoa.isEmpty() || !s.pgpPrivateKeyArmored.contains("BEGIN PGP PRIVATE KEY")) {
            ack(reqId, false, error = "missing_identity")
            return
        }

        // Keep the killed-app voice path working: it reads the PGP key / route / roster from here.
        try {
            BeamioChatPgpStore.upsertFromWeb(
                ctx,
                JSONObject()
                    .put("privateKeyArmor", s.pgpPrivateKeyArmored)
                    .put("publicKeyArmor", s.pgpPublicKeyArmored)
                    .put("routePublicKeyArmor", s.ownRouteArmoredPublicKey)
                    .put("eoa", s.eoa),
            )
            if (s.nodes.isNotEmpty() && BeamioChatPgpStore.loadSiNodes(ctx).isEmpty()) {
                BeamioChatPgpStore.storeChainRoster(ctx, s.nodes.map { it.asStoreNode() }, s.mailboxIp.ifBlank { null })
            }
        } catch (e: Exception) {
            Log.w(TAG, "persist identity: ${e.message}")
        }

        BeamioOpenPgpHost.shared(ctx).ensureReady { ok ->
            if (!ok) {
                ack(reqId, false, error = "openpgp_not_ready")
                return@ensureReady
            }
            val history = BeamioConetChatHistoryStore(
                eoa = s.eoa,
                chainId = s.chainId,
                conetRpcUrl = s.conetRpcUrl,
                ipfsBaseUrl = s.ipfsBaseUrl,
                ipfsWriteBaseUrl = s.ipfsWriteBaseUrl.ifBlank { null },
                apiBaseUrl = s.apiBaseUrl,
                registryAddress = s.chatIndexRegistryAddress,
                log = { level, msg ->
                    // Shape only (counts / short cid) — never plaintext or key material.
                    Log.i(TAG, msg)
                    emitEvent(JSONObject().put("type", "event:log").put("level", level).put("message", msg))
                },
            )
            s.history = history
            // Listen first: it must not wait on the (sign-dependent) history key derivation.
            emitEvent(JSONObject().put("type", "ready").put("reqId", reqId))
            startListen(ctx, s)
            history.prepare { }
        }
    }

    // ---- send ---------------------------------------------------------------------

    private fun handleSend(body: JSONObject) {
        val reqId = body.optInt("reqId", 0)
        val ctx = appContext
        val s = currentSession()
        val to = body.optJSONObject("to")
        if (ctx == null || s == null || to == null) {
            ack(reqId, false, error = "not_ready")
            return
        }
        val payload = body.optString("payload", "")
        val sendId = body.optString("sendId", "").ifBlank { UUID.randomUUID().toString() }
        val noPush = body.optBoolean("beamioNoPush", false)
        val userPgp = to.optString("userPublicKeyArmored", "").trim()
        val mailboxRoute = to.optString("routerArmoredPublicKey", "").trim()
        if (!userPgp.contains("BEGIN PGP PUBLIC KEY")) {
            ack(reqId, false, error = "missing_recipient_pgp")
            return
        }
        if (noPush && !mailboxRoute.contains("BEGIN PGP PUBLIC KEY")) {
            ack(reqId, false, error = "NoPush requires recipient mailbox routerArmoredPublicKey")
            return
        }
        val host = BeamioOpenPgpHost.shared(ctx)
        BeamioConetChatSignBroker.requestEip191(payload) { signResult ->
            val signature = signResult.getOrElse {
                ack(reqId, false, error = it.message ?: "sign_failed")
                return@requestEip191
            }
            val envelope = JSONObject()
                .put("timestamp", System.currentTimeMillis())
                .put("text", payload)
                .put("from", s.eoa)
                .put("signMessage", signature)
            host.encryptUtf8JsonBase64(envelope.toString(), userPgp) { enc ->
                val armor = enc.getOrElse {
                    ack(reqId, false, error = it.message ?: "encrypt_failed")
                    return@encryptUtf8JsonBase64
                }
                val finish = { finalArmor: String ->
                    io.execute {
                        val ok = postToEntries(ctx, finalArmor, mailboxRoute, s)
                        ack(reqId, true, result = JSONObject().put("sent", ok).put("sendId", sendId))
                    }
                }
                if (noPush) {
                    host.wrapArmorToMailboxWork(armor, mailboxRoute, true) { wrapped ->
                        wrapped.fold(
                            onSuccess = { finish(it) },
                            onFailure = { ack(reqId, false, error = it.message ?: "wrap_failed") },
                        )
                    }
                } else {
                    finish(armor)
                }
            }
        }
    }

    private fun handleGroup(body: JSONObject) {
        val reqId = body.optInt("reqId", 0)
        val ctx = appContext
        val s = currentSession()
        val request = body.optJSONObject("request")
        val members = request?.optJSONObject("roster")?.optJSONArray("members")
        if (ctx == null || s == null || request == null || members == null || members.length() == 0) {
            // Roster / tombstone requests without members are acknowledged as a no-op.
            ack(reqId, true, result = JSONObject().put("ok", true))
            return
        }
        val text = request.optString("body", "").ifBlank { request.optString("text", "") }
        val groupId = request.optString("groupId", "")
            .ifBlank { request.optJSONObject("roster")?.optString("groupId", "").orEmpty() }
        val host = BeamioOpenPgpHost.shared(ctx)
        BeamioConetChatSignBroker.requestEip191(text) { signResult ->
            val signature = signResult.getOrElse {
                ack(reqId, false, error = "group_sign_failed")
                return@requestEip191
            }
            val envelope = JSONObject()
                .put("timestamp", System.currentTimeMillis())
                .put("text", text)
                .put("from", s.eoa)
                .put("signMessage", signature)
                .put("groupId", groupId)
            io.execute {
                var delivered = 0
                val latch = CountDownLatch(members.length())
                for (i in 0 until members.length()) {
                    val member = members.optJSONObject(i)
                    val pgp = member?.optString("userPublicKeyArmored", "")
                        ?.ifBlank { member.optString("pgpPublicKeyArmored", "") }.orEmpty()
                    val route = member?.optString("routerArmoredPublicKey", "").orEmpty()
                    if (!pgp.contains("BEGIN PGP PUBLIC KEY")) {
                        latch.countDown()
                        continue
                    }
                    host.encryptUtf8JsonBase64(envelope.toString(), pgp) { enc ->
                        io.execute {
                            try {
                                val armor = enc.getOrNull()
                                if (armor != null && postToEntries(ctx, armor, route, s)) {
                                    synchronized(this) { delivered += 1 }
                                }
                            } finally {
                                latch.countDown()
                            }
                        }
                    }
                }
                latch.await(60, TimeUnit.SECONDS)
                ack(reqId, true, result = JSONObject().put("delivered", delivered).put("members", members.length()))
            }
        }
    }

    // ---- presence / native wake ---------------------------------------------------

    private fun handleQueryPresence(body: JSONObject) {
        val reqId = body.optInt("reqId", 0)
        val s = currentSession()
        if (s == null) {
            ack(reqId, false, error = "not_ready")
            return
        }
        val contacts = body.optJSONArray("contacts")?.let { objects(it) }.orEmpty()
        if (contacts.isEmpty()) {
            ack(reqId, true, result = JSONObject())
            return
        }
        io.execute {
            val result = JSONObject()
            val latch = CountDownLatch(contacts.size)
            for (c in contacts) {
                val target = normalizeAddress(c.optString("address", "").ifBlank { c.optString("eoaAddress", "") })
                val route = c.optString("routerArmoredPublicKey", "")
                if (target.isEmpty() || !route.contains("BEGIN PGP PUBLIC KEY")) {
                    latch.countDown()
                    continue
                }
                postSignedMailboxCommand(
                    s, route,
                    JSONObject().put("command", "wallet_online_query").put("targetWallet", target),
                ) { ok, json ->
                    try {
                        if (ok && json != null && json.optBoolean("ok", false)) {
                            val online = json.optBoolean("online", false)
                            synchronized(result) { result.put(target, online) }
                            emitEvent(
                                JSONObject().put("type", "event:presence").put(
                                    "payload",
                                    JSONObject().put("wallet", target).put("online", online).put("ok", true),
                                ),
                            )
                        }
                    } finally {
                        latch.countDown()
                    }
                }
            }
            latch.await(30, TimeUnit.SECONDS)
            ack(reqId, true, result = result)
        }
    }

    private fun handleQueryNativeWake(body: JSONObject) {
        val reqId = body.optInt("reqId", 0)
        val s = currentSession()
        val contact = body.optJSONObject("contact")
        if (s == null || contact == null) {
            ack(reqId, false, error = "not_ready")
            return
        }
        val target = normalizeAddress(contact.optString("address", "").ifBlank { contact.optString("eoaAddress", "") })
        val route = contact.optString("routerArmoredPublicKey", "")
        if (target.isEmpty() || !route.contains("BEGIN PGP PUBLIC KEY")) {
            ack(reqId, false, error = "bad_native_wake")
            return
        }
        postSignedMailboxCommand(
            s, route,
            JSONObject().put("command", "wallet_native_wake_query").put("targetWallet", target),
        ) { ok, json ->
            if (ok && json != null && json.optBoolean("ok", false)) {
                ack(
                    reqId, true,
                    result = JSONObject().put("ok", true).put("wallet", target)
                        .put("nativeWakeable", json.optBoolean("nativeWakeable", false)),
                )
            } else {
                ack(reqId, true, result = JSONObject().put("ok", false).put("wallet", target))
            }
        }
    }

    // ---- history ------------------------------------------------------------------

    private fun handleHistoryLoad(body: JSONObject) {
        val reqId = body.optInt("reqId", 0)
        val hist = currentSession()?.history
        if (hist == null || !hist.isReady()) {
            // History key derivation (a PWA signature) may still be in flight: not an error.
            ack(reqId, true, result = JSONObject.NULL)
            return
        }
        hist.load(
            body.optJSONObject("options"),
            emitBuffer = { peer, entries, isTail ->
                emitEvent(
                    JSONObject().put("type", "event:historyBuffer").put(
                        "payload",
                        JSONObject()
                            .put("peer", peer)
                            .put("entries", JSONArray().also { arr -> entries.forEach { arr.put(it.toJson()) } })
                            .put("isTail", isTail),
                    ),
                )
            },
            done = { ack(reqId, true, result = JSONObject.NULL) },
        )
    }

    private fun handleHistoryRead(body: JSONObject) {
        val reqId = body.optInt("reqId", 0)
        val hist = currentSession()?.history
        if (hist == null || !hist.isReady()) {
            ack(reqId, true, result = JSONArray())
            return
        }
        hist.read(body.optJSONObject("options")) { entries ->
            ack(reqId, true, result = JSONArray().also { arr -> entries.forEach { arr.put(it.toJson()) } })
        }
    }

    private fun handleHistoryAppend(body: JSONObject) {
        val reqId = body.optInt("reqId", 0)
        val hist = currentSession()?.history
        val entry = body.optJSONObject("entry")
        if (hist == null || entry == null || !hist.isReady()) {
            ack(reqId, false, error = "history_not_ready")
            return
        }
        hist.append(entry) { ok ->
            ack(reqId, ok, result = JSONObject().put("ok", ok), error = if (ok) null else "append_failed")
        }
    }

    // ---- mailbox commands / voice ----------------------------------------------------

    private fun handleMailboxCommand(body: JSONObject) {
        val reqId = body.optInt("reqId", 0)
        val s = currentSession()
        if (s == null) {
            ack(reqId, false, error = "not_ready")
            return
        }
        val routeKey = body.optString("routerArmoredPublicKey", "")
        val command = body.optJSONObject("command")
        if (command == null || !routeKey.contains("BEGIN PGP PUBLIC KEY")) {
            ack(reqId, false, error = "bad_mailbox_command")
            return
        }
        postSignedMailboxCommand(s, routeKey, command) { ok, _ ->
            ack(reqId, true, result = JSONObject().put("ok", ok))
        }
    }

    private fun handleVoiceListen(body: JSONObject) {
        val reqId = body.optInt("reqId", 0)
        val sessionId = body.optString("sessionId", "")
        synchronized(lock) { voiceSessions.add(sessionId) }
        // The shell's native voice signaling owns the voice SSE — never open a second one.
        ack(reqId, true, result = JSONObject().put("ok", true).put("delegated", true).put("sessionId", sessionId))
    }

    private fun handleVoiceUnlisten(body: JSONObject) {
        val reqId = body.optInt("reqId", 0)
        synchronized(lock) { voiceSessions.remove(body.optString("sessionId", "")) }
        ack(reqId, true, result = JSONObject().put("ok", true))
    }

    private fun handleVoiceFrame(body: JSONObject) {
        val reqId = body.optInt("reqId", 0)
        val s = currentSession()
        if (s == null) {
            ack(reqId, false, error = "not_ready")
            return
        }
        val routeKey = body.optString("routerArmoredPublicKey", "")
        val frame = body.optJSONObject("frame")
        if (frame == null || !routeKey.contains("BEGIN PGP PUBLIC KEY")) {
            ack(reqId, false, error = "bad_voice_frame")
            return
        }
        postSignedMailboxCommand(s, routeKey, frame) { ok, _ ->
            ack(reqId, true, result = JSONObject().put("sent", ok))
        }
    }

    // ---- listen lifecycle -------------------------------------------------------------

    private fun startListen(ctx: Context, s: Session) {
        listen.start(ctx, s, onStatus = { st, d -> emitStatus(st, d) }, onInbound = { p, h, v -> handleInbound(p, h, v) })
    }

    private fun resumeListen() {
        val ctx = appContext ?: return
        val s = currentSession() ?: return
        listen.resume(ctx, s, onStatus = { st, d -> emitStatus(st, d) }, onInbound = { p, h, v -> handleInbound(p, h, v) })
    }

    private fun destroy() {
        listen.stop()
        BeamioConetChatSignBroker.cancelAll("destroyed")
        synchronized(lock) {
            session?.destroyed = true
            session?.history?.destroy()
            session?.history = null
            session = null
            voiceSessions.clear()
        }
        emitEvent(JSONObject().put("type", "event:status").put("payload", statusPayload("destroyed", null)))
    }

    private fun emitStatus(status: String, detail: String?) {
        emitEvent(JSONObject().put("type", "event:status").put("payload", statusPayload(status, detail)))
    }

    // ---- inbound + dual receipts -------------------------------------------------------

    private fun handleInbound(plaintext: String, armorHash: String, viaDomain: String) {
        val ctx = appContext ?: return
        val s = currentSession() ?: return
        // The sender fans one message out to several entries; the mailbox then forwards each
        // copy. Identical armor (same keccak) is one message: no second event, no second receipt.
        if (armorHash.isNotEmpty() && !markSeen(armorHash)) return
        verifyEnvelope(ctx, plaintext) { from ->
            if (from.isNullOrEmpty()) {
                emitEvent(
                    JSONObject().put("type", "event:log").put("level", "warn")
                        .put("message", "inbound verify failed — drop"),
                )
                return@verifyEnvelope
            }
            emitEvent(
                JSONObject().put("type", "event:message").put(
                    "payload",
                    JSONObject()
                        .put("line", plaintext)
                        .put("from", from)
                        .put("armorHash", armorHash)
                        .put("viaDomain", viaDomain)
                        .put("plain", false),
                ),
            )
            emitDualReceipts(ctx, s, plaintext, armorHash, from)
        }
    }

    /**
     * Recover the EIP-191 signer. A claimed `from` that differs from the signer is passed on for the app to flag:
     * the recovered address is the only trusted sender identity.
     */
    private fun verifyEnvelope(ctx: Context, plaintext: String, completion: (String?) -> Unit) {
        val obj = try {
            JSONObject(plaintext)
        } catch (_: Exception) {
            completion(null)
            return
        }
        val text = when {
            obj.has("text") && obj.opt("text") is String -> obj.getString("text")
            obj.has("message") && obj.opt("message") is String -> obj.getString("message")
            else -> {
                completion(null)
                return
            }
        }
        val sig = obj.optString("signMessage", "")
        if (sig.isEmpty()) {
            completion(null)
            return
        }
        // The recovered signer is the sender. A claimed `from` that differs is
        // not dropped here: the app keeps the message under the signer and shows
        // a warning for the false claim.
        BeamioOpenPgpHost.shared(ctx).verifyMessage(text, sig) { result ->
            completion(result.getOrNull())
        }
    }

    /** Mailbox ACK (delete offline copy) + sender `beamio_chat_delivery_receipt_v1`. */
    private fun emitDualReceipts(ctx: Context, s: Session, plaintext: String, armorHash: String, from: String) {
        if (s.ownRouteArmoredPublicKey.contains("BEGIN PGP PUBLIC KEY")) {
            postSignedMailboxCommand(
                s, s.ownRouteArmoredPublicKey,
                JSONObject().put("command", "gossip_delivery_ack").put("armorHash", armorHash),
            ) { _, _ -> }
        }
        val fromLower = from.lowercase()
        val route = s.routes.firstOrNull {
            normalizeAddress(it.optString("address", "").ifBlank { it.optString("eoaAddress", "").ifBlank { it.optString("eoa", "") } }) == fromLower
        } ?: return
        if (!route.optString("userPublicKeyArmored", "").contains("BEGIN PGP PUBLIC KEY")) return

        val receipt = JSONObject()
            .put("type", "beamio_chat_delivery_receipt_v1")
            .put("sendId", extractSendId(plaintext).orEmpty())
            .put("armorHash", armorHash)
            .put("deliveredAt", System.currentTimeMillis())
            .put("from", s.eoa)
        val pending = JSONObject()
            .put("sendId", UUID.randomUUID().toString())
            .put("from", "me")
            .put("text", receipt.toString())
            .put("createdAt", System.currentTimeMillis())
        handleSend(
            JSONObject()
                .put("reqId", -1)
                .put("to", route)
                .put("payload", pending.toString())
                .put("sendId", UUID.randomUUID().toString())
                .put("beamioNoPush", true),
        )
    }

    // ---- shared helpers -----------------------------------------------------------------

    /** Sign (via the PWA) + encrypt a mailbox command to [routerArmoredPublicKey], POST via entry ≠ B. */
    private fun postSignedMailboxCommand(
        s: Session,
        routerArmoredPublicKey: String,
        command: JSONObject,
        completion: (ok: Boolean, json: JSONObject?) -> Unit,
    ) {
        val ctx = appContext
        if (ctx == null) {
            completion(false, null)
            return
        }
        val cmd = JSONObject(command.toString())
        if (!cmd.has("walletAddress")) cmd.put("walletAddress", s.eoa)
        if (!cmd.has("timestamp")) cmd.put("timestamp", System.currentTimeMillis() / 1000)
        val message = cmd.toString()
        BeamioConetChatSignBroker.requestEip191(message) { signResult ->
            val signature = signResult.getOrNull()
            if (signature == null) {
                completion(false, null)
                return@requestEip191
            }
            BeamioOpenPgpHost.shared(ctx).encryptSignedRouteCommand(message, signature, routerArmoredPublicKey) { enc ->
                val armor = enc.getOrNull()
                if (armor == null) {
                    completion(false, null)
                    return@encryptSignedRouteCommand
                }
                io.execute {
                    var json: JSONObject? = null
                    val ok = postToEntries(ctx, armor, routerArmoredPublicKey, s) { body ->
                        json = try {
                            JSONObject(body)
                        } catch (_: Exception) {
                            null
                        }
                    }
                    completion(ok, json)
                }
            }
        }
    }

    /**
     * POST via entry ≠ B (blocking). Wraps the armor to the entry route PGP when known, like the
     * TS gossip core (`outerWrap`). [onBody] receives the 2xx response body (mailbox JSON replies).
     */
    private fun postToEntries(
        ctx: Context,
        armor: String,
        mailboxRoute: String,
        s: Session,
        onBody: ((String) -> Unit)? = null,
    ): Boolean {
        val exclude = HashSet<String>()
        BeamioSiCipherPost.normalizeIp(s.mailboxIp)?.let { exclude.add(it) }
        if (mailboxRoute.contains("BEGIN PGP")) {
            for (n in s.nodes) {
                if (n.armoredPublicKey.isNotEmpty() &&
                    BeamioConetChatListenSession.fingerprintsOverlap(mailboxRoute, n.armoredPublicKey)
                ) {
                    BeamioSiCipherPost.normalizeIp(n.ip)?.let { exclude.add(it) }
                }
            }
        }
        val host = BeamioOpenPgpHost.shared(ctx)
        val candidates = s.nodes.filter { n ->
            val ip = BeamioSiCipherPost.normalizeIp(n.ip) ?: return@filter false
            ip !in exclude
        }.shuffled()

        for (entry in candidates.take(4)) {
            var postArmor = armor
            if (entry.armoredPublicKey.contains("BEGIN PGP PUBLIC KEY")) {
                val latch = CountDownLatch(1)
                host.wrapArmorToEntryRoute(armor, entry.armoredPublicKey) { r ->
                    r.getOrNull()?.let { postArmor = it }
                    latch.countDown()
                }
                latch.await(8, TimeUnit.SECONDS)
            }
            val result = BeamioSiCipherPost.post(postArmor, listOf(entry.asStoreNode()), exclude, maxAttempts = 1)
            if (result.ok) {
                onBody?.invoke(result.body)
                return true
            }
        }
        // Fallback: any roster node excluding the mailbox.
        val roster = s.nodes.map { it.asStoreNode() }
        val result = if (roster.isEmpty()) {
            BeamioSiCipherPost.post(armor, BeamioChatPgpStore.loadSiNodes(ctx), exclude)
        } else {
            BeamioSiCipherPost.post(armor, roster, exclude)
        }
        if (result.ok) onBody?.invoke(result.body)
        return result.ok
    }

    /** `true` the first time [armorHash] is seen (bounded, last 512). */
    private fun markSeen(armorHash: String): Boolean = synchronized(seenArmor) {
        if (seenArmor.containsKey(armorHash)) false else {
            seenArmor[armorHash] = true
            true
        }
    }

    private fun currentSession(): Session? = synchronized(lock) {
        session?.takeIf { !it.destroyed }
    }

    private fun emitEvent(payload: JSONObject) {
        val out = JSONObject().put("action", "chatModuleEvent").put("event", payload)
        main.post {
            try {
                emitFn?.invoke(out)
            } catch (e: Exception) {
                Log.w(TAG, "emit failed: ${e.message}")
            }
        }
    }

    private fun ack(reqId: Int, ok: Boolean, result: Any? = null, error: String? = null) {
        if (reqId < 0) return
        val payload = JSONObject().put("type", "ack").put("reqId", reqId).put("ok", ok)
        if (ok && result != null) payload.put("result", result)
        if (!ok) payload.put("error", error ?: "error")
        emitEvent(payload)
    }

    private fun statusPayload(status: String, detail: String?): JSONObject =
        JSONObject().put("status", status).also { if (!detail.isNullOrBlank()) it.put("detail", detail) }

    private fun objects(arr: JSONArray): List<JSONObject> =
        (0 until arr.length()).mapNotNull { arr.optJSONObject(it) }

    private fun parseNodes(raw: JSONArray): List<Node> {
        // The PWA `nodeInfo` carries `ip_addr`, native roster rows carry `ip`. A row with only a
        // domain is resolved through the chain roster in the store; without an IP an entry can
        // never be reached over HTTP.
        val rosterIpByDomain = HashMap<String, String>()
        appContext?.let { ctx ->
            for (kn in BeamioChatPgpStore.loadSiNodes(ctx)) {
                if (kn.domain.isNotEmpty()) rosterIpByDomain[kn.domain.uppercase()] = kn.ip
            }
        }
        val out = ArrayList<Node>()
        for (i in 0 until raw.length()) {
            val n = raw.optJSONObject(i) ?: continue
            var ip = n.optString("ip", "").ifBlank { n.optString("ip_addr", "") }
            val domain = n.optString("domain", "")
            if (BeamioSiCipherPost.normalizeIp(ip) == null && domain.isNotEmpty()) {
                rosterIpByDomain[domain.uppercase()]?.let { ip = it }
            }
            if (ip.isEmpty() && domain.isEmpty()) continue
            out.add(
                Node(
                    ip = ip,
                    domain = domain,
                    region = n.optString("region", ""),
                    armoredPublicKey = n.optString("armoredPublicKey", "")
                        .ifBlank { n.optString("pgpPublicKeyArmored", "") },
                ),
            )
        }
        return out
    }

    private fun normalizeAddress(raw: String): String = raw.trim().lowercase()

    private fun extractSendId(plaintext: String): String? {
        val obj = try {
            JSONObject(plaintext)
        } catch (_: Exception) {
            return null
        }
        obj.optString("sendId", "").takeIf { it.isNotEmpty() }?.let { return it }
        val inner = obj.optString("text", "")
        return try {
            JSONObject(inner).optString("sendId", "").takeIf { it.isNotEmpty() }
        } catch (_: Exception) {
            null
        }
    }
}
