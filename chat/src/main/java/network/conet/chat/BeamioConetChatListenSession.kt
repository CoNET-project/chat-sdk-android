package network.conet.chat

import android.content.Context
import android.util.Log
import network.conet.chat.nativekey.NativeWallet
import network.conet.chat.nativekey.NativePgp
import org.json.JSONArray
import org.json.JSONObject
import java.security.SecureRandom
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

private typealias StatusHandler = (status: String, detail: String?) -> Unit
/** `armor` is the inbound OpenPGP armor (still encrypted to the user key), kept for the inbox store. */
internal typealias InboundHandler = (plaintext: String, armorHash: String, viaDomain: String, armor: String) -> Unit

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
    /** Last frame from the mailbox that opened with this listen's stream key (ms). */
    @Volatile private var lastSealedFrameAtMs = 0L

    /**
     * Milliseconds since the mailbox last spoke on this listen (handshake,
     * keepalive, message). Large after the process was frozen in the background:
     * the stream may be gone even though nothing reported it.
     */
    fun msSinceLastMailboxFrame(): Long = System.currentTimeMillis() - lastSealedFrameAtMs

    fun isRunning(): Boolean = synchronized(lock) { running && !paused }

    /** Started and not stopped (it may be paused). */
    fun isActive(): Boolean = synchronized(lock) { running }

    fun pause() {
        synchronized(lock) { paused = true }
        stopCurrentSse()
        // A loop waiting to retry ends now instead of after its backoff.
        retryNow()
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
        retryNow()
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
        var failures = 0
        while (stillAlive(gen)) {
            var reopenNow = false
            val tryStarted = System.currentTimeMillis()
            try {
                reopenNow = runOneListen(app, session, gen, onStatus, onInbound)
            } catch (e: Exception) {
                if (stillAlive(gen)) onStatus("reconnecting", e.message ?: "listen_error")
            }
            if (!stillAlive(gen)) break
            // The mailbox answered on this try: the network works, start the backoff over.
            if (reopenNow || lastSealedFrameAtMs >= tryStarted) failures = 0 else failures += 1
            onStatus("reconnecting", if (reopenNow) "relisten" else "retry")
            // A listen that worked and then dropped reopens at once (new command).
            // Otherwise back off (2 s … 30 s); the network coming back or the app
            // coming to the foreground cuts the wait short ([retryNow]).
            val waitMs = if (reopenNow) {
                BeamioListenPolicy.RELISTEN_MS
            } else {
                BeamioListenPolicy.retryDelayMs(failures, Math.random())
            }
            if (!reopenNow) Log.i(TAG, "listen retry in ${waitMs / 1000}s (failures=$failures)")
            try {
                waitBeforeRetry(waitMs)
            } catch (_: InterruptedException) {
                break
            }
        }
    }

    private val retrySignal = Object()
    private var retryKicked = false

    /** Cut a retry wait short (network back, app in the foreground, paused). */
    fun retryNow() {
        synchronized(retrySignal) {
            retryKicked = true
            retrySignal.notifyAll()
        }
    }

    private fun waitBeforeRetry(ms: Long) {
        synchronized(retrySignal) {
            if (!retryKicked) retrySignal.wait(ms)
            retryKicked = false
        }
    }

    /**
     * One signed `mailbox_listen` (one instanceId) tried on entries until one
     * works. Returns true when the mailbox answered on a stream that then
     * dropped: the caller builds a new command instead of reusing this one.
     */
    private fun runOneListen(
        app: Context,
        session: BeamioConetChatModule.Session,
        gen: Int,
        onStatus: StatusHandler,
        onInbound: InboundHandler,
    ): Boolean {
        val ownRoute = session.ownRouteArmoredPublicKey
        if (!ownRoute.contains("BEGIN PGP PUBLIC KEY")) throw IllegalStateException("missing_own_route")
        val routeKeyId = BeamioOwnRouteCheck.routeKeyId(ownRoute)
        session.listenRouteKeyId = routeKeyId
        val mailboxIps = mailboxIps(session)

        // Fresh stream key per listen: B seals every SSE frame with it, so the
        // entry relaying the stream cannot read the recipient key ID. Memory only.
        val streamKey = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val message = JSONObject()
            .put("command", "mailbox_listen")
            .put("walletAddress", session.eoa)
            .put("instanceId", UUID.randomUUID().toString())
            .put("streamKey", ConetChatCryptoUtil.base64Encode(streamKey))
            .toString()

        val signature = await(30) { cb ->
            BeamioConetChatSignBroker.requestEip191(message, completion = cb)
        }
        val innerArmor = await(20) { cb ->
            BeamioOpenPgpHost.shared(app).encryptSignedRouteCommand(message, signature, ownRoute, cb)
        }
        if (!stillAlive(gen)) return false

        // Only nodes with a PGP route key are entries. Without a key the entry cannot be wrapped, and the inner armor is
        // never sent unwrapped, so there is no fallback to unkeyed nodes.
        val roster = BeamioChatPgpStore.keyedEntries(session.nodes.map { it.asStoreNode() }, mailboxIps)
        if (roster.isEmpty()) throw IllegalStateException("no_entry_key")
        val siNodes = roster.values.toList()

        val skip = mailboxIps.toMutableSet()
        var lastError: String? = null
        for (attempt in 0 until MAX_ENTRY_ATTEMPTS) {
            if (!stillAlive(gen)) return false
            val picked = BeamioSiCipherPost.getRandomNode(siNodes, skip) ?: break
            val entryIp = BeamioSiCipherPost.normalizeIp(picked.ip) ?: continue
            skip.add(entryIp)
            val entry = roster[entryIp] ?: continue
            val url = BeamioSiCipherPost.postUrl(entryIp) ?: continue
            // A failed wrap skips this entry. The inner armor is never posted unwrapped.
            val armored: String = try {
                await<String>(15) { cb ->
                    BeamioOpenPgpHost.shared(app).wrapArmorToEntryRoute(innerArmor, entry.armoredPublicKey, cb)
                }
            } catch (e: Exception) {
                Log.w(TAG, "mailbox_listen entry=$entryIp wrap failed: ${e.message}; entry skipped")
                continue
            }
            Log.i(TAG, "mailbox_listen entry=$entryIp domain=${entry.domain} route=${routeKeyId.ifEmpty { "?" }}")
            val started = System.currentTimeMillis()
            val err = openSse(app, url, armored, streamKey, session, gen, entry.domain, onStatus, onInbound)
            val latency = (System.currentTimeMillis() - started).toInt()
            if (err == null) return false
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
            if (err == "root_stop" || !stillAlive(gen)) return false
            // The mailbox registered this listen under its instanceId. Reusing this
            // command on another entry lets the old socket's late close remove the
            // new session at the mailbox: build a new command instead.
            if (lastSealedFrameAtMs >= started) return true
        }
        throw IllegalStateException(lastError ?: "all_entries_failed")
    }

    /** Returns `null` when the stream ended cleanly (caller stops), else the close reason. */
    private fun openSse(
        app: Context,
        url: String,
        armored: String,
        streamKey: ByteArray,
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
            // The mailbox's sealed keepalive comes every 60–180 s: wait longer than
            // that before calling the stream dead (120 s cut healthy listens).
            idleTimeoutMs = 200_000,
            onOpen = {
                // HTTP 200 only means the entry took the request. "listening" is
                // reported when the mailbox's sealed handshake frame arrives.
                openLatch.countDown()
            },
            onEvent = { payload ->
                openStreamFrame(payload, streamKey)?.let { frame ->
                    lastSealedFrameAtMs = System.currentTimeMillis()
                    handleSsePayload(app, frame, session, viaDomain, onStatus, onInbound)
                }
            },
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
            // The mailbox's first frame: `{status:200, kind:'mailbox', instanceId, nodeWallet, …}`.
            if (obj.optString("kind") == "mailbox" || (obj.optBoolean("ok", false) && obj.has("nodeWallet"))) {
                onStatus("listening", "handshake")
                return
            }
            if (type == "mailbox_keepalive" || obj.has("epoch") || obj.has("status")) {
                onStatus("listening", "heartbeat")
                return
            }
        } catch (_: Exception) {
        }

        val armored = findInboundArmor(trimmed)
        if (armored == null || !armored.contains("BEGIN PGP MESSAGE")) return

        decryptArmor(app, session, armored, onFailure = { restartAfterDecryptFailure() }) { line, hash ->
            onInbound(line, hash, viaDomain, armored)
        }
    }

    @Volatile private var lastDecryptRestartMs = 0L

    /**
     * A message on this stream could not be decrypted (the crypto host failed
     * even after rebuilding). It was not ACKed, so the mailbox still holds it and
     * sends it again to a new listen: reopen the stream (at most every 30 s).
     */
    private fun restartAfterDecryptFailure() {
        val handle = synchronized(lock) {
            val now = System.currentTimeMillis()
            if (now - lastDecryptRestartMs < 30_000L) return
            lastDecryptRestartMs = now
            sseHandle
        } ?: return
        Log.w(TAG, "inbound decrypt failed; reopening the mailbox listen")
        handle.cancel()
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

        private val SEALED_FRAME = Regex("^[A-Za-z0-9+/]+={0,2}$")

        /**
         * Open one mailbox SSE frame with this listen's stream key:
         * `base64(iv[12] ‖ AES-256-GCM ciphertext ‖ tag[16])`, plaintext JSON padded
         * with spaces. Every mailbox seals every frame; anything else (plain JSON,
         * a frame that does not open) is dropped. Never logs the key or contents.
         * Pure JVM (unit-testable).
         */
        internal fun openStreamFrame(payload: String, key: ByteArray): String? {
            val trimmed = payload.trim()
            if (trimmed.isEmpty()) return null
            if (trimmed.length < 40 || !SEALED_FRAME.matches(trimmed)) {
                runCatching { Log.w(TAG, "mailbox frame not sealed; dropped len=${trimmed.length}") }
                return null
            }
            return try {
                val blob = ConetChatCryptoUtil.base64Decode(trimmed)
                if (blob.size < 12 + 16 + 1) return null
                val cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(
                    javax.crypto.Cipher.DECRYPT_MODE,
                    javax.crypto.spec.SecretKeySpec(key, "AES"),
                    javax.crypto.spec.GCMParameterSpec(128, blob, 0, 12),
                )
                String(cipher.doFinal(blob, 12, blob.size - 12), Charsets.UTF_8).trim()
            } catch (_: Exception) {
                runCatching { Log.w(TAG, "mailbox frame did not open len=${trimmed.length}") }
                null
            }
        }

        /**
         * Decrypt one inbound armor with the session PGP key into the chat line
         * the app expects (with `_beamioPgpArmorHash`). Also used to replay the
         * inbox store. Never logs plaintext.
         */
        internal fun decryptArmor(
            app: Context,
            session: BeamioConetChatModule.Session,
            armored: String,
            onFailure: (() -> Unit)? = null,
            onLine: (line: String, armorHash: String) -> Unit,
        ) {
            // Native decryption inside the wallet boundary (§36-B): the vault holds the PGP key and its passphrase, and
            // only the plaintext comes back. The callback runs on the main thread, as it did from the WebView host.
            // An unreadable store is a failed decrypt (unknown, retried by the listen), never an uncaught exception on the listen thread (25.52Y.84).
            val outcome = try {
                NativeWallet.pgp(app).decryptInbound(armored)
            } catch (_: Exception) {
                network.conet.chat.nativekey.NativePgp.Outcome.fail("store_unreadable")
            }
            android.os.Handler(android.os.Looper.getMainLooper()).post {
                val text = outcome.value
                if (outcome.ok && text != null) {
                    var line = normalizeInboundPlaintext(text)
                    if (line.isBlank()) return@post
                    val armorHash = NativePgp.armorHash(armored)
                    try {
                        val env = JSONObject(line)
                        env.put("_beamioPgpArmorHash", armorHash)
                        line = env.toString()
                    } catch (_: Exception) {
                    }
                    onLine(line, armorHash)
                } else if (outcome.code == "not_recipient") {
                    Log.w(TAG, "inbound PGP not for this listen key")
                } else {
                    Log.w(TAG, "inbound decrypt failed: ${outcome.code}")
                    onFailure?.invoke()
                }
            }
        }
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
