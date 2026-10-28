package network.conet.chat

import android.content.Context
import android.os.Handler
import android.os.Looper
import android.util.Base64
import android.util.Log
import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedInputStream
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

/**
 * Mailbox `mailbox_listen` SSE engine (encrypt to B route PGP, HTTP via entry C ≠ B).
 * Host apps call [ConetChat]; this class is an implementation detail of the AAR.
 */
internal class ConetChatEngine {
    private companion object {
        const val TAG = "ConetChat"
        const val CONNECT_TIMEOUT_MS = 12_000
        const val IDLE_TIMEOUT_MS = 120_000
        const val READ_CHUNK = 4096
        const val RETRY_MS = 6_000L
    }

    private data class Session(
        val privateKeyHex: String,
        val pgpPrivateKeyArmored: String,
        val pgpPublicKeyArmored: String,
        val ownRouteArmoredPublicKey: String,
        val mailboxIp: String,
        val eoa: String,
        val nodes: List<ConetChatNode>,
        val pgpPassphrase: String = "",
    )

    private val main = Handler(Looper.getMainLooper())
    private val io = Executors.newCachedThreadPool()
    private val running = AtomicBoolean(false)
    private val sessionRef = AtomicReference<Session?>(null)
    private val emitterRef = AtomicReference<ConetChat.ConetChatEmitter?>(null)
    private val appCtx = AtomicReference<Context?>(null)
    private var listenConn: HttpURLConnection? = null
    private var listenGeneration = 0

    @Volatile
    private var cryptoProvider: () -> ConetChatCrypto? = { null }

    @Volatile
    private var persistenceProvider: () -> ConetChatPersistence? = { null }

    fun bindDeps(
        cryptoProvider: () -> ConetChatCrypto?,
        persistenceProvider: () -> ConetChatPersistence?,
    ) {
        this.cryptoProvider = cryptoProvider
        this.persistenceProvider = persistenceProvider
    }

    fun isRunning(): Boolean = running.get() && sessionRef.get() != null

    fun bindEmitter(emitter: ConetChat.ConetChatEmitter?) {
        emitterRef.set(emitter)
    }

    fun start(context: Context, initJson: String): Boolean {
        val app = context.applicationContext
        appCtx.set(app)
        if (cryptoProvider() == null) {
            emitStatus("error", "not_installed")
            return false
        }
        val body = try {
            JSONObject(initJson.ifBlank { "{}" })
        } catch (e: Exception) {
            Log.w(TAG, "init parse failed: ${e.message}")
            emitStatus("error", "bad_init_json")
            return false
        }
        val privateKeyHex = body.optString("privateKeyHex", "").trim()
        val pgpPrivate = body.optString("pgpPrivateKeyArmored", "").trim()
            .ifBlank { body.optString("privateKeyArmor", "").trim() }
        val ownRoute = body.optString("ownRouteArmoredPublicKey", "").trim()
            .ifBlank { body.optString("routePublicKeyArmor", "").trim() }
        if (privateKeyHex.length < 64 || !pgpPrivate.contains("BEGIN PGP PRIVATE KEY")) {
            emitStatus("error", "missing_identity")
            return false
        }
        if (!ownRoute.contains("BEGIN PGP PUBLIC KEY")) {
            emitStatus("error", "missing_own_route")
            return false
        }
        val nodes = parseNodes(body.opt("nodes"))
        val mailboxFromBody = ConetChatNetwork.normalizeIp(body.optString("mailboxIp", ""))
        val mailboxIp = mailboxFromBody
            ?: persistenceProvider()?.loadMailboxIp()?.let { ConetChatNetwork.normalizeIp(it) }
            ?: ""
        val eoa = body.optString("eoa", "").trim()
            .ifBlank { body.optString("eoaAddress", "").trim() }
        val session = Session(
            privateKeyHex = privateKeyHex.removePrefix("0x").removePrefix("0X"),
            pgpPrivateKeyArmored = pgpPrivate,
            pgpPublicKeyArmored = body.optString("pgpPublicKeyArmored", "").trim()
                .ifBlank { body.optString("publicKeyArmor", "").trim() },
            ownRouteArmoredPublicKey = ownRoute,
            mailboxIp = mailboxIp,
            eoa = eoa,
            nodes = nodes,
            pgpPassphrase = body.optString("pgpPassphrase", ""),
        )
        try {
            persistenceProvider()?.upsertIdentity(
                pgpPrivateArmor = session.pgpPrivateKeyArmored,
                pgpPublicArmor = session.pgpPublicKeyArmored,
                routePublicArmor = session.ownRouteArmoredPublicKey,
                eoa = session.eoa,
            )
            if (session.mailboxIp.isNotBlank() && session.nodes.isNotEmpty()) {
                persistenceProvider()?.storeRoster(session.nodes, session.mailboxIp)
            }
        } catch (e: Exception) {
            Log.w(TAG, "persistence upsert: ${e.message}")
        }

        stopInternal(keepEmitter = true)
        sessionRef.set(session)
        running.set(true)
        val gen = ++listenGeneration
        emitStatus("connecting")
        Log.i(
            TAG,
            "start eoa=${session.eoa.take(10)} nodes=${session.nodes.size} mailbox=${session.mailboxIp}",
        )
        io.execute { listenLoop(session, gen) }
        return true
    }

    fun stop() {
        stopInternal(keepEmitter = true)
        emitStatus("stopped")
    }

    fun destroy() {
        stopInternal(keepEmitter = false)
        sessionRef.set(null)
        appCtx.set(null)
    }

    fun updateNodes(nodesJson: String): Boolean {
        val session = sessionRef.get() ?: return false
        val nodes = try {
            parseNodes(JSONArray(nodesJson.ifBlank { "[]" }))
        } catch (_: Exception) {
            return false
        }
        if (nodes.isEmpty()) return false
        sessionRef.set(session.copy(nodes = nodes))
        return true
    }

    private fun stopInternal(keepEmitter: Boolean) {
        running.set(false)
        listenGeneration++
        try {
            listenConn?.disconnect()
        } catch (_: Exception) {
        }
        listenConn = null
        if (!keepEmitter) emitterRef.set(null)
    }

    private fun listenLoop(session: Session, gen: Int) {
        while (running.get() && listenGeneration == gen) {
            val live = sessionRef.get() ?: session
            try {
                runOneListen(live, gen)
            } catch (e: Exception) {
                if (running.get() && listenGeneration == gen) {
                    Log.w(TAG, "listen error: ${e.message}")
                    emitStatus("reconnecting", e.message ?: "listen_error")
                }
            }
            if (!running.get() || listenGeneration != gen) break
            emitStatus("reconnecting", "retry")
            try {
                Thread.sleep(RETRY_MS)
            } catch (_: InterruptedException) {
                break
            }
        }
    }

    private fun runOneListen(session: Session, gen: Int) {
        val ownRoute = session.ownRouteArmoredPublicKey
        val mailboxIps = buildSet {
            ConetChatNetwork.normalizeIp(session.mailboxIp)?.let { add(it) }
            for (n in session.nodes) {
                if (n.armoredPublicKey.isNotBlank() && fingerprintsOverlap(ownRoute, n.armoredPublicKey)) {
                    ConetChatNetwork.normalizeIp(n.ip)?.let { add(it) }
                }
            }
        }

        val command = JSONObject()
            .put("command", "mailbox_listen")
            .put("walletAddress", session.eoa)
            .put("instanceId", UUID.randomUUID().toString())
            .toString()

        val innerArmor = awaitEncryptRouteCommand(session.privateKeyHex, command, ownRoute)
            ?: throw IllegalStateException("encrypt_route_command_failed")
        if (!running.get() || listenGeneration != gen) return

        val withPgp = session.nodes.filter { n ->
            val ip = ConetChatNetwork.normalizeIp(n.ip) ?: return@filter false
            ip !in mailboxIps && n.armoredPublicKey.contains("BEGIN PGP PUBLIC KEY")
        }
        val fallback = session.nodes.filter { n ->
            val ip = ConetChatNetwork.normalizeIp(n.ip) ?: return@filter false
            ip !in mailboxIps
        }
        val roster = if (withPgp.isNotEmpty()) withPgp else fallback
        if (roster.isEmpty()) {
            emitStatus("reconnecting", "no_entry_c")
            throw IllegalStateException("no_entry_c")
        }

        val candidates = roster.map {
            ConetChatNetwork.EntryCandidate(
                ip = it.ip,
                domain = it.domain,
                armoredPublicKey = it.armoredPublicKey,
            )
        }
        var lastError: String? = null
        val skip = mailboxIps.toMutableSet()
        for (_attempt in 0 until 4) {
            if (!running.get() || listenGeneration != gen) return
            val entry = ConetChatNetwork.getRandomNode(candidates, excludeIps = skip)
                ?: break
            val entryIp = ConetChatNetwork.normalizeIp(entry.ip) ?: continue
            skip.add(entryIp)
            val url = ConetChatNetwork.postUrl(entryIp) ?: continue
            val armored = if (entry.armoredPublicKey.contains("BEGIN PGP PUBLIC KEY")) {
                awaitWrapArmor(innerArmor, entry.armoredPublicKey) ?: innerArmor
            } else {
                innerArmor
            }
            Log.i(TAG, "mailbox_listen entry=$entryIp domain=${entry.domain}")
            val started = System.currentTimeMillis()
            val err = openSse(url, armored, session, gen, entry.domain) ?: "sse_error"
            val latency = (System.currentTimeMillis() - started).toInt()
            // getRandomNode already probed reachable; demote on connect/HTTP failure.
            when {
                err.startsWith("HTTP 0") ||
                    err.contains("ConnectException", ignoreCase = true) ||
                    err.contains("SocketTimeout", ignoreCase = true) ||
                    err.contains("UnknownHost", ignoreCase = true) ||
                    err.contains("Failed to connect", ignoreCase = true) ||
                    err.contains("Network is unreachable", ignoreCase = true) ->
                    ConetChatNetwork.scoreEntry(entryIp, reachable = false, latencyMs = latency)
                err.startsWith("HTTP ") ->
                    ConetChatNetwork.scoreEntry(entryIp, reachable = true, latencyMs = 500)
                err == "root_stop" || err == "server_closed" ->
                    ConetChatNetwork.scoreEntry(entryIp, reachable = true, latencyMs = minOf(latency, 400))
            }
            lastError = err
            if (err == "root_stop" || !running.get() || listenGeneration != gen) return
        }
        throw IllegalStateException(lastError ?: "all_entries_failed")
    }

    private fun openSse(
        url: String,
        armored: String,
        session: Session,
        gen: Int,
        viaDomain: String,
    ): String? {
        var conn: HttpURLConnection? = null
        try {
            conn = (URL(url).openConnection() as HttpURLConnection).apply {
                requestMethod = "POST"
                connectTimeout = CONNECT_TIMEOUT_MS
                readTimeout = IDLE_TIMEOUT_MS
                doOutput = true
                setRequestProperty("Content-Type", "application/json;charset=UTF-8")
                setRequestProperty("Accept", "text/event-stream")
                setRequestProperty("Connection", "keep-alive")
            }
            listenConn = conn
            val body = JSONObject().put("data", armored).toString()
            OutputStreamWriter(conn.outputStream, Charsets.UTF_8).use { it.write(body) }
            val code = conn.responseCode
            if (code !in 200..299 || conn.inputStream == null) {
                return "HTTP $code"
            }
            emitStatus("listening")
            val stream = BufferedInputStream(conn.inputStream)
            val buf = ByteArray(READ_CHUNK)
            val sse = StringBuilder()
            var lastActivity = System.currentTimeMillis()
            while (running.get() && listenGeneration == gen) {
                if (System.currentTimeMillis() - lastActivity > IDLE_TIMEOUT_MS) {
                    return "idle_timeout"
                }
                val n = try {
                    stream.read(buf)
                } catch (e: Exception) {
                    return e.message ?: "read_error"
                }
                if (n < 0) return "server_closed"
                lastActivity = System.currentTimeMillis()
                sse.append(String(buf, 0, n, Charsets.UTF_8))
                while (true) {
                    val crlf = sse.indexOf("\r\n\r\n")
                    val lf = sse.indexOf("\n\n")
                    val idx = when {
                        crlf >= 0 && (lf < 0 || crlf <= lf) -> crlf to 4
                        lf >= 0 -> lf to 2
                        else -> break
                    }
                    val block = sse.substring(0, idx.first)
                    sse.delete(0, idx.first + idx.second)
                    handleSseBlock(block, session, viaDomain)
                }
            }
            return if (!running.get() || listenGeneration != gen) "root_stop" else "server_closed"
        } catch (e: Exception) {
            return e.message ?: "sse_error"
        } finally {
            try {
                conn?.disconnect()
            } catch (_: Exception) {
            }
            if (listenConn === conn) listenConn = null
        }
    }

    private fun handleSseBlock(block: String, session: Session, viaDomain: String) {
        val dataLines = block.lineSequence()
            .map { it.trimEnd() }
            .filter { it.startsWith("data:") }
            .map { it.removePrefix("data:").trimStart() }
            .toList()
        val payload = (if (dataLines.isNotEmpty()) dataLines.joinToString("\n") else block).trim()
        if (payload.isEmpty()) return

        try {
            val obj = JSONObject(payload)
            val type = obj.optString("type")
            if (type == "mailbox_keepalive" || obj.has("epoch") || obj.has("status")) {
                emitStatus("listening", "heartbeat")
                return
            }
            if (obj.optBoolean("ok", false) && (obj.has("kind") || obj.has("nodeWallet"))) {
                emitStatus("listening", "handshake")
                return
            }
        } catch (_: Exception) {
        }

        val prefix = payload.take(96).replace('\n', ' ')
        Log.i(TAG, "inbound frame len=${payload.length} prefix=$prefix")
        val armored = findInboundArmor(payload)
        if (armored == null) {
            Log.w(TAG, "inbound armor miss len=${payload.length}")
            return
        }
        if (!armored.contains("BEGIN PGP MESSAGE")) {
            Log.w(TAG, "inbound armor missing BEGIN")
            return
        }
        val crypto = cryptoProvider()
        if (crypto == null) {
            Log.e(TAG, "inbound cryptoProvider null")
            return
        }
        crypto.decryptInboundArmor(
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
                Log.i(TAG, "inbound decrypt ok len=${line.length}")
                emitMessage(line, dec.armorHash, viaDomain)
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

    /**
     * SI business frames are raw JSON `{"data":"<OpenPGP armor>"}` (not SSE `data:` lines).
     * Prefer JSONObject so JSON `\n` escapes become real newlines; slicing BEGIN..END out of
     * the raw JSON text leaves literal `\\n` and OpenPGP decrypt fails.
     */
    private fun findInboundArmor(payload: String): String? {
        val trimmed = payload.trim()
        if (trimmed.startsWith("{")) {
            try {
                walkArmor(JSONObject(trimmed), 0)?.let { return it }
            } catch (_: Exception) {
            }
        }
        if (trimmed.contains("BEGIN PGP MESSAGE")) {
            val start = trimmed.indexOf("-----BEGIN PGP MESSAGE-----")
            val end = trimmed.indexOf("-----END PGP MESSAGE-----")
            if (start >= 0 && end > start) {
                val slice = trimmed.substring(start, end + "-----END PGP MESSAGE-----".length)
                // Raw JSON source may still contain escaped newlines if parse above failed.
                return if (slice.contains("\\n")) {
                    slice.replace("\\r\\n", "\n").replace("\\n", "\n").replace("\\r", "\r")
                } else {
                    slice
                }
            }
            return trimmed
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

    private fun normalizeInboundPlaintext(raw: String): String {
        val trimmed = raw.trim()
        if (trimmed.startsWith("{") || trimmed.startsWith("[")) return trimmed
        return try {
            val decoded = String(
                Base64.decode(trimmed, Base64.DEFAULT),
                Charsets.UTF_8,
            ).trim()
            if (decoded.startsWith("{") || decoded.startsWith("[")) decoded else trimmed
        } catch (_: Exception) {
            trimmed
        }
    }

    private fun awaitEncryptRouteCommand(
        privateKeyHex: String,
        commandJson: String,
        routeArmor: String,
    ): String? {
        val crypto = cryptoProvider() ?: run {
            Log.e(TAG, "encrypt_route_command: cryptoProvider null")
            return null
        }
        val latch = CountDownLatch(1)
        var out: String? = null
        var err: String? = null
        crypto.encryptRouteCommand(privateKeyHex, commandJson, routeArmor) { result ->
            out = result.getOrNull()
            err = result.exceptionOrNull()?.message
            latch.countDown()
        }
        val finished = latch.await(20, TimeUnit.SECONDS)
        if (!finished) {
            Log.e(TAG, "encrypt_route_command: timeout 20s")
            return null
        }
        if (out.isNullOrBlank()) {
            Log.e(TAG, "encrypt_route_command_failed: ${err ?: "empty"}")
        }
        return out
    }

    private fun awaitWrapArmor(inner: String, entryArmor: String): String? {
        val crypto = cryptoProvider() ?: return inner
        val latch = CountDownLatch(1)
        var out: String? = null
        crypto.wrapArmorToEntryRoute(inner, entryArmor) { result ->
            out = result.getOrNull()
            latch.countDown()
        }
        latch.await(15, TimeUnit.SECONDS)
        return out
    }

    private fun fingerprintsOverlap(a: String, b: String): Boolean {
        if (a == b) return true
        val na = normalizeArmorBody(a)
        val nb = normalizeArmorBody(b)
        if (na.isEmpty() || nb.isEmpty()) return false
        return na == nb || na.take(64) == nb.take(64)
    }

    private fun normalizeArmorBody(armor: String): String =
        armor.lineSequence()
            .map { it.trim() }
            .filter {
                it.isNotEmpty() &&
                    !it.startsWith("-----") &&
                    !it.startsWith("Version") &&
                    !it.startsWith("Comment")
            }
            .joinToString("")
            .filter { it.isLetterOrDigit() || it == '+' || it == '/' || it == '=' }

    private fun parseNodes(raw: Any?): List<ConetChatNode> {
        val arr = when (raw) {
            is JSONArray -> raw
            is String -> try {
                JSONArray(raw)
            } catch (_: Exception) {
                return emptyList()
            }
            else -> return emptyList()
        }
        val out = ArrayList<ConetChatNode>()
        for (i in 0 until arr.length()) {
            val obj = arr.optJSONObject(i) ?: continue
            val ip = ConetChatNetwork.normalizeIp(
                obj.optString("ip", "").ifBlank { obj.optString("ip_addr", "") },
            ) ?: continue
            out.add(
                ConetChatNode(
                    ip = ip,
                    domain = obj.optString("domain", "").trim(),
                    region = obj.optString("region", "").trim(),
                    armoredPublicKey = obj.optString("armoredPublicKey", "")
                        .ifBlank { obj.optString("pgpPublicKey", "") }
                        .trim(),
                ),
            )
        }
        return out
    }

    fun emitStatus(status: String, detail: String? = null) {
        val d = JSONObject()
            .put("action", ConetChat.EVENT_ACTION)
            .put("kind", "status")
            .put("status", status)
        if (!detail.isNullOrBlank()) d.put("detail", detail)
        emit(d)
    }

    private fun emitMessage(line: String, armorHash: String, viaDomain: String) {
        emit(
            JSONObject()
                .put("action", ConetChat.EVENT_ACTION)
                .put("kind", "message")
                .put("line", line)
                .put("armorHash", armorHash)
                .put("viaDomain", viaDomain)
                .put("wasPlaintext", false),
        )
    }

    private fun emit(detail: JSONObject) {
        main.post {
            try {
                emitterRef.get()?.emit(detail)
            } catch (e: Exception) {
                Log.w(TAG, "emit failed: ${e.message}")
            }
        }
    }
}
