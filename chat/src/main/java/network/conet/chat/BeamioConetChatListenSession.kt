package network.conet.chat

import android.content.Context
import android.util.Log
import org.json.JSONArray
import org.json.JSONObject
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

private typealias StatusHandler = (status: String, detail: String?) -> Unit
private typealias InboundHandler = (plaintext: String, armorHash: String, viaDomain: String) -> Unit

/**
 * Mailbox SSE listen: encrypt `mailbox_listen` to the **B route PGP**, HTTP/SSE via an
 * entry **C ≠ B**. Reconnects until [stop] / [pause].
 */
internal class BeamioConetChatListenSession {
    private val lock = Any()
    private var generation = 0
    private var running = false
    private var paused = false
    private var sseHandle: BeamioSiCipherPost.SseHandle? = null

    fun isRunning(): Boolean = synchronized(lock) { running && !paused }

    fun pause() {
        synchronized(lock) { paused = true }
        stopCurrentSse()
    }

    fun resume(
        context: Context,
        session: BeamioConetChatModule.Session,
        onStatus: StatusHandler,
        onInbound: InboundHandler,
    ) {
        synchronized(lock) { paused = false }
        start(context, session, onStatus, onInbound)
    }

    fun start(
        context: Context,
        session: BeamioConetChatModule.Session,
        onStatus: StatusHandler,
        onInbound: InboundHandler,
    ) {
        val gen = synchronized(lock) {
            generation += 1
            running = true
            paused = false
            generation
        }
        stopCurrentSse()
        onStatus("connecting", null)
        val app = context.applicationContext
        Thread({ listenLoop(app, session, gen, onStatus, onInbound) }, "conet-chat-listen")
            .apply { isDaemon = true }
            .start()
    }

    fun stop() {
        synchronized(lock) {
            running = false
            generation += 1
        }
        stopCurrentSse()
    }

    private fun stopCurrentSse() {
        val handle = synchronized(lock) {
            val h = sseHandle
            sseHandle = null
            h
        }
        handle?.cancel()
    }

    private fun stillAlive(gen: Int): Boolean =
        synchronized(lock) { running && generation == gen && !paused }

    private fun listenLoop(
        app: Context,
        session: BeamioConetChatModule.Session,
        gen: Int,
        onStatus: StatusHandler,
        onInbound: InboundHandler,
    ) {
        while (stillAlive(gen)) {
            try {
                runOneListen(app, session, gen, onStatus, onInbound)
            } catch (e: Exception) {
                if (stillAlive(gen)) onStatus("reconnecting", e.message ?: "listen_error")
            }
            if (!stillAlive(gen)) break
            onStatus("reconnecting", "retry")
            try {
                Thread.sleep(RETRY_MS)
            } catch (_: InterruptedException) {
                break
            }
        }
    }

    private fun runOneListen(
        app: Context,
        session: BeamioConetChatModule.Session,
        gen: Int,
        onStatus: StatusHandler,
        onInbound: InboundHandler,
    ) {
        val ownRoute = session.ownRouteArmoredPublicKey
        if (!ownRoute.contains("BEGIN PGP PUBLIC KEY")) throw IllegalStateException("missing_own_route")
        val mailboxIps = mailboxIps(session)

        val message = JSONObject()
            .put("command", "mailbox_listen")
            .put("walletAddress", session.eoa)
            .put("instanceId", UUID.randomUUID().toString())
            .toString()

        val signature = await(30) { cb ->
            BeamioConetChatSignBroker.requestEip191(message, completion = cb)
        }
        val innerArmor = await(20) { cb ->
            BeamioOpenPgpHost.shared(app).encryptSignedRouteCommand(message, signature, ownRoute, cb)
        }
        if (!stillAlive(gen)) return

        val withPgp = session.nodes.filter { n ->
            val ip = BeamioSiCipherPost.normalizeIp(n.ip) ?: return@filter false
            ip !in mailboxIps && n.armoredPublicKey.contains("BEGIN PGP PUBLIC KEY")
        }
        val fallback = session.nodes.filter { n ->
            val ip = BeamioSiCipherPost.normalizeIp(n.ip) ?: return@filter false
            ip !in mailboxIps
        }
        val roster = (if (withPgp.isNotEmpty()) withPgp else fallback)
            .associateBy { BeamioSiCipherPost.normalizeIp(it.ip) }
        if (roster.isEmpty()) throw IllegalStateException("no_entry_c")
        val siNodes = roster.values.map { BeamioChatPgpStore.SiNode(it.ip, it.domain, it.region) }

        val skip = mailboxIps.toMutableSet()
        var lastError: String? = null
        for (attempt in 0 until MAX_ENTRY_ATTEMPTS) {
            if (!stillAlive(gen)) return
            val picked = BeamioSiCipherPost.getRandomNode(siNodes, skip) ?: break
            val entryIp = BeamioSiCipherPost.normalizeIp(picked.ip) ?: continue
            skip.add(entryIp)
            val entry = roster[entryIp] ?: continue
            val url = BeamioSiCipherPost.postUrl(entryIp) ?: continue
            val armored = if (entry.armoredPublicKey.contains("BEGIN PGP PUBLIC KEY")) {
                try {
                    await(15) { cb ->
                        BeamioOpenPgpHost.shared(app).wrapArmorToEntryRoute(innerArmor, entry.armoredPublicKey, cb)
                    }
                } catch (_: Exception) {
                    innerArmor
                }
            } else {
                innerArmor
            }
            Log.i(TAG, "mailbox_listen entry=$entryIp domain=${entry.domain}")
            val started = System.currentTimeMillis()
            val err = openSse(app, url, armored, session, gen, entry.domain, onStatus, onInbound)
            val latency = (System.currentTimeMillis() - started).toInt()
            if (err == null) return
            when {
                err.startsWith("HTTP 0") || err.contains("ConnectException", true) ||
                    err.contains("SocketTimeout", true) || err.contains("UnknownHost", true) ||
                    err.contains("Failed to connect", true) || err.contains("unreachable", true) ->
                    BeamioSiCipherPost.scoreEntry(entryIp, reachable = false, latencyMs = latency)
                err.startsWith("HTTP ") ->
                    BeamioSiCipherPost.scoreEntry(entryIp, reachable = true, latencyMs = 500)
                err == "root_stop" || err == "server_closed" ->
                    BeamioSiCipherPost.scoreEntry(entryIp, reachable = true, latencyMs = minOf(latency, 400))
            }
            lastError = err
            if (err == "root_stop" || !stillAlive(gen)) return
        }
        throw IllegalStateException(lastError ?: "all_entries_failed")
    }

    /** Returns `null` when the stream ended cleanly (caller stops), else the close reason. */
    private fun openSse(
        app: Context,
        url: String,
        armored: String,
        session: BeamioConetChatModule.Session,
        gen: Int,
        viaDomain: String,
        onStatus: StatusHandler,
        onInbound: InboundHandler,
    ): String? {
        val openLatch = CountDownLatch(1)
        val closedLatch = CountDownLatch(1)
        var closeReason: String? = null
        val handle = BeamioSiCipherPost.postSse(
            url = url,
            armor = armored,
            onOpen = {
                onStatus("listening", "handshake")
                openLatch.countDown()
            },
            onEvent = { payload -> handleSsePayload(app, payload, session, viaDomain, onStatus, onInbound) },
            onClosed = { reason ->
                closeReason = reason
                openLatch.countDown()
                closedLatch.countDown()
            },
        )
        synchronized(lock) { sseHandle = handle }

        openLatch.await(15, TimeUnit.SECONDS)
        if (!stillAlive(gen)) {
            handle.cancel()
            return "root_stop"
        }
        closedLatch.await(6, TimeUnit.HOURS)
        synchronized(lock) { if (sseHandle === handle) sseHandle = null }
        if (!stillAlive(gen)) return "root_stop"
        return closeReason ?: "server_closed"
    }

    private fun handleSsePayload(
        app: Context,
        payload: String,
        session: BeamioConetChatModule.Session,
        viaDomain: String,
        onStatus: StatusHandler,
        onInbound: InboundHandler,
    ) {
        val trimmed = payload.trim()
        if (trimmed.isEmpty()) return
        // Length and shape only. Never log ciphertext or plaintext.
        val isPgp = trimmed.contains("BEGIN PGP MESSAGE")
        Log.i(TAG, "sse event len=${trimmed.length} pgp=$isPgp via=$viaDomain")

        try {
            val obj = JSONObject(trimmed)
            val type = obj.optString("type")
            if (type == "mailbox_keepalive" || obj.has("epoch") || obj.has("status")) {
                onStatus("listening", "heartbeat")
                return
            }
            if (obj.optBoolean("ok", false) && (obj.has("kind") || obj.has("nodeWallet"))) {
                onStatus("listening", "handshake")
                return
            }
        } catch (_: Exception) {
        }

        val armored = findInboundArmor(trimmed)
        if (armored == null || !armored.contains("BEGIN PGP MESSAGE")) return

        BeamioOpenPgpHost.shared(app).decryptInboundArmor(
            session.pgpPrivateKeyArmored,
            session.pgpPassphrase,
            armored,
        ) { result ->
            result.onSuccess { dec ->
                var line = normalizeInboundPlaintext(dec.text)
                if (line.isBlank()) return@onSuccess
                try {
                    val env = JSONObject(line)
                    env.put("_beamioPgpArmorHash", dec.armorHash)
                    line = env.toString()
                } catch (_: Exception) {
                }
                onInbound(line, dec.armorHash, viaDomain)
            }
            result.onFailure { err ->
                val msg = err.message.orEmpty()
                if (msg.contains("No decryption key", ignoreCase = true)) {
                    Log.w(TAG, "inbound PGP not for this listen key")
                } else {
                    Log.w(TAG, "inbound decrypt: $msg")
                }
            }
        }
    }

    private fun <T> await(seconds: Long, request: ((Result<T>) -> Unit) -> Unit): T {
        val latch = CountDownLatch(1)
        var out: Result<T>? = null
        request { r ->
            out = r
            latch.countDown()
        }
        if (!latch.await(seconds, TimeUnit.SECONDS)) throw IllegalStateException("timeout_${seconds}s")
        return out!!.getOrThrow()
    }

    companion object {
        private const val TAG = "BeamioConetChat"
        private const val RETRY_MS = 6_000L
        private const val MAX_ENTRY_ATTEMPTS = 4

        internal fun mailboxIps(session: BeamioConetChatModule.Session): Set<String> {
            val set = HashSet<String>()
            BeamioSiCipherPost.normalizeIp(session.mailboxIp)?.let { set.add(it) }
            for (n in session.nodes) {
                if (n.armoredPublicKey.contains("BEGIN PGP PUBLIC KEY") &&
                    fingerprintsOverlap(session.ownRouteArmoredPublicKey, n.armoredPublicKey)
                ) {
                    BeamioSiCipherPost.normalizeIp(n.ip)?.let { set.add(it) }
                }
            }
            return set
        }

        internal fun fingerprintsOverlap(a: String, b: String): Boolean {
            if (a.trim() == b.trim()) return a.isNotBlank()
            val na = normalizeArmorBody(a)
            val nb = normalizeArmorBody(b)
            if (na.isEmpty() || nb.isEmpty()) return false
            return na == nb || na.take(64) == nb.take(64)
        }

        private fun normalizeArmorBody(armor: String): String =
            armor.lineSequence()
                .map { it.trim() }
                .filter {
                    it.isNotEmpty() && !it.startsWith("-----") &&
                        !it.startsWith("Version") && !it.startsWith("Comment")
                }
                .joinToString("")
                .filter { it.isLetterOrDigit() || it == '+' || it == '/' || it == '=' }

        /**
         * SI business frames are raw JSON `{"data":"<OpenPGP armor>"}`. Prefer the JSON
         * parser so `\n` escapes become real newlines; slicing BEGIN..END out of the raw
         * text leaves literal `\\n` and OpenPGP rejects it ("Misformed armored text").
         */
        internal fun findInboundArmor(payload: String): String? {
            val trimmed = payload.trim()
            if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
                try {
                    val obj = if (trimmed.startsWith("[")) {
                        JSONArray(trimmed).optJSONObject(0)
                    } else {
                        JSONObject(trimmed)
                    }
                    if (obj != null) walkArmor(obj, 0)?.let { return it }
                } catch (_: Exception) {
                }
            }
            if (trimmed.contains("BEGIN PGP MESSAGE")) {
                val start = trimmed.indexOf("-----BEGIN PGP MESSAGE-----")
                val end = trimmed.indexOf("-----END PGP MESSAGE-----")
                var raw = if (start >= 0 && end > start) {
                    trimmed.substring(start, end + "-----END PGP MESSAGE-----".length)
                } else {
                    trimmed
                }
                if (raw.contains("\\n")) {
                    raw = raw.replace("\\r\\n", "\n").replace("\\n", "\n").replace("\\r", "\n")
                }
                return raw
            }
            return null
        }

        private fun walkArmor(obj: JSONObject, depth: Int): String? {
            if (depth > 6) return null
            for (key in listOf("data", "message", "armor", "ciphertext", "payload")) {
                val v = obj.opt(key) ?: continue
                when (v) {
                    is String -> {
                        if (v.contains("BEGIN PGP MESSAGE")) return v
                        try {
                            walkArmor(JSONObject(v), depth + 1)?.let { return it }
                        } catch (_: Exception) {
                        }
                    }
                    is JSONObject -> walkArmor(v, depth + 1)?.let { return it }
                }
            }
            return null
        }

        /** Inbound plaintext is JSON, or base64(JSON) from `encryptUtf8JsonBase64`. */
        internal fun normalizeInboundPlaintext(raw: String): String {
            val trimmed = raw.trim()
            if (trimmed.startsWith("{") || trimmed.startsWith("[")) return trimmed
            return try {
                val decoded = String(ConetChatCryptoUtil.base64Decode(trimmed), Charsets.UTF_8).trim()
                if (decoded.startsWith("{") || decoded.startsWith("[")) decoded else trimmed
            } catch (_: Exception) {
                trimmed
            }
        }
    }
}
