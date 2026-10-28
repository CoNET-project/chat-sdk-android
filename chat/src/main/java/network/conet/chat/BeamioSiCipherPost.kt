package network.conet.chat

import android.util.Log
import org.json.JSONObject
import java.io.BufferedInputStream
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import kotlin.random.Random

/**
 * OpenPGP ciphertext POST + mailbox SSE to Guardian SI entries.
 *
 * Target is `http://{Guardian ip}/post` with body `{ "data": armor }` only
 * (HTTP; never HTTPS domain posts). The host app must allow cleartext traffic to
 * those IPs (`android:usesCleartextTraffic="true"` or a network security config).
 *
 * Entry choice is [getRandomNode]: IP-reachable nodes only, weighted by [scoreEntry].
 */
object BeamioSiCipherPost {
    private const val TAG = "BeamioSiPost"

    /** A failed IP stays out of [getRandomNode] this long, then may be probed again. */
    private const val UNREACHABLE_TTL_MS = 120_000L

    /** Upper bound for one [post] call across all attempts (the PWA bridge waits ~15 s). */
    private const val TOTAL_BUDGET_MS = 13_000L

    data class Result(
        val ok: Boolean,
        val status: Int,
        val body: String,
        val error: String,
    )

    /** Higher is better. Unscored reachable nodes start at 80. */
    private val entryScores = ConcurrentHashMap<String, Int>()

    /** IP → epoch ms until which [getRandomNode] must not return it. */
    private val unreachableUntil = ConcurrentHashMap<String, Long>()

    private val sseExecutor = Executors.newCachedThreadPool { r ->
        Thread(r, "conet-chat-sse").apply { isDaemon = true }
    }

    fun normalizeIp(raw: String?): String? {
        var trimmed = raw?.trim().orEmpty()
        if (trimmed.isEmpty() || trimmed.contains("/") || trimmed.contains(" ")) return null
        if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
            trimmed = trimmed.substring(1, trimmed.length - 1)
        }
        if (trimmed.contains(":")) {
            if (trimmed.count { it == ':' } < 2 || trimmed.contains(".")) return null
            return trimmed
        }
        val parts = trimmed.split(".")
        if (parts.size != 4) return null
        for (part in parts) {
            if (part.isEmpty() || part.length > 3) return null
            if (part.length > 1 && part.startsWith("0")) return null
            val n = part.toIntOrNull() ?: return null
            if (n !in 0..255) return null
        }
        return trimmed
    }

    fun postUrl(ip: String): String? {
        val norm = normalizeIp(ip) ?: return null
        return if (norm.contains(":")) "http://[$norm]/post" else "http://$norm/post"
    }

    /**
     * Score one entry after an IP probe, POST or SSE open.
     * `reachable == false` zeroes the score and keeps the IP out of every later
     * [getRandomNode] result for [UNREACHABLE_TTL_MS].
     */
    fun scoreEntry(ip: String, reachable: Boolean, latencyMs: Int) {
        val ipNorm = normalizeIp(ip) ?: return
        if (!reachable) {
            unreachableUntil[ipNorm] = System.currentTimeMillis() + UNREACHABLE_TTL_MS
            entryScores[ipNorm] = 0
            return
        }
        unreachableUntil.remove(ipNorm)
        val speed = maxOf(1, 500 - minOf(maxOf(latencyMs, 0), 500))
        val prev = maxOf(entryScores[ipNorm] ?: 80, 1)
        entryScores[ipNorm] = minOf(2000, prev / 2 + speed)
    }

    fun isMarkedUnreachable(ip: String): Boolean {
        val ipNorm = normalizeIp(ip) ?: return false
        val until = unreachableUntil[ipNorm] ?: return false
        if (until > System.currentTimeMillis()) return true
        unreachableUntil.remove(ipNorm)
        return false
    }

    /**
     * One roster node that answered an HTTP probe on port 80, weighted to higher
     * scores. Unreachable IPs are scored out and are never returned.
     */
    fun getRandomNode(
        nodes: List<BeamioChatPgpStore.SiNode>,
        excludeIps: Set<String>,
        probeTimeoutMs: Int = 2_000,
    ): BeamioChatPgpStore.SiNode? {
        val blocked = excludeIps.mapNotNull { normalizeIp(it) }.toSet()
        val now = System.currentTimeMillis()
        unreachableUntil.entries.removeIf { it.value <= now }
        val dead = unreachableUntil.keys.toSet()
        val scores = entryScores.toMap()

        val pool = ArrayList<BeamioChatPgpStore.SiNode>()
        val seen = HashSet<String>()
        for (node in nodes) {
            val ip = normalizeIp(node.ip) ?: continue
            if (ip in blocked || ip in dead || !seen.add(ip)) continue
            pool.add(BeamioChatPgpStore.SiNode(ip = ip, domain = node.domain, region = node.region))
        }

        var probes = 0
        while (pool.isNotEmpty() && probes < 6) {
            val picked = weightedPick(pool, scores) ?: return null
            probes++
            val probe = probeIp(picked.ip, probeTimeoutMs)
            if (probe.reachable) {
                scoreEntry(picked.ip, reachable = true, latencyMs = probe.latencyMs)
                return picked
            }
            scoreEntry(picked.ip, reachable = false, latencyMs = probe.latencyMs)
            pool.removeAll { normalizeIp(it.ip) == picked.ip }
        }
        return null
    }

    /**
     * Weighted by [scoreEntry]. Mailbox / caller excludes are dropped.
     * Each attempt is `http://{ip}/post`. A dead IP is not offered again.
     */
    fun post(
        armor: String,
        nodes: List<BeamioChatPgpStore.SiNode>,
        excludeIps: Set<String>,
        maxAttempts: Int = 4,
    ): Result {
        val trimmed = armor.trim()
        if (!trimmed.contains("BEGIN PGP MESSAGE")) {
            return Result(false, 0, "", "not_pgp")
        }
        val body = JSONObject().put("data", trimmed).toString()
        val blocked = excludeIps.mapNotNull { normalizeIp(it) }.toSet()
        val roster = nodes.mapNotNull { node ->
            val ip = normalizeIp(node.ip) ?: return@mapNotNull null
            if (ip in blocked) return@mapNotNull null
            BeamioChatPgpStore.SiNode(ip = ip, domain = node.domain, region = node.region)
        }
        if (roster.isEmpty()) return Result(false, 0, "", "no_si_roster")

        val skip = excludeIps.toMutableSet()
        val attempts = maxAttempts.coerceAtLeast(1)
        val started = System.currentTimeMillis()
        var lastStatus = 0
        var lastErr = ""
        repeat(attempts) {
            val remaining = TOTAL_BUDGET_MS - (System.currentTimeMillis() - started)
            if (remaining < 2_500) return Result(false, lastStatus, "", lastErr.ifEmpty { "post_failed" })
            val node = getRandomNode(roster, skip, probeTimeoutMs = minOf(2_000L, remaining / 3).toInt())
                ?: return Result(false, lastStatus, "", lastErr.ifEmpty { "post_failed" })
            skip.add(node.ip)
            val url = postUrl(node.ip) ?: return@repeat
            val left = TOTAL_BUDGET_MS - (System.currentTimeMillis() - started)
            if (left < 1_500) return Result(false, lastStatus, "", lastErr.ifEmpty { "post_failed" })
            val t0 = System.currentTimeMillis()
            val (status, text) = httpPost(url, body, minOf(12_000L, left - 500).toInt())
            lastStatus = status
            val latency = (System.currentTimeMillis() - t0).toInt()
            if (status in 200..299) {
                val capped = if (text.length > 48_000) text.substring(0, 48_000) else text
                if (!bodyOk(capped)) {
                    // SI may answer HTTP 200 with `{ "ok": false, "error": … }`. Trust the body.
                    Log.i(TAG, "http 2xx but body ok=false status=$status")
                    scoreEntry(node.ip, reachable = true, latencyMs = 500)
                    return@repeat
                }
                scoreEntry(node.ip, reachable = true, latencyMs = latency)
                Log.i(TAG, "http ip ok status=$status latencyMs=$latency")
                return Result(true, status, capped, "")
            }
            if (status == 0) {
                lastErr = "connect_failed"
                scoreEntry(node.ip, reachable = false, latencyMs = latency)
            } else {
                lastErr = "http_$status"
                scoreEntry(node.ip, reachable = true, latencyMs = 500)
            }
        }
        Log.i(TAG, "http ip failed status=$lastStatus")
        return Result(false, lastStatus, "", lastErr.ifEmpty { "post_failed" })
    }

    // ---- SSE ---------------------------------------------------------------------

    /** Cancel handle for a running [postSse]. */
    class SseHandle internal constructor() {
        @Volatile
        internal var conn: HttpURLConnection? = null

        @Volatile
        var cancelled: Boolean = false
            private set

        fun cancel() {
            cancelled = true
            try {
                conn?.disconnect()
            } catch (_: Exception) {
            }
        }
    }

    /**
     * POST `{ data: armor }` and keep the connection open for SSE frames.
     * [onOpen] fires after a 2xx status; [onEvent] receives one payload per frame;
     * [onClosed] fires exactly once with a short reason (`server_closed`, `HTTP 502`, …).
     */
    fun postSse(
        url: String,
        armor: String,
        connectTimeoutMs: Int = 12_000,
        idleTimeoutMs: Int = 120_000,
        onOpen: () -> Unit,
        onEvent: (String) -> Unit,
        onClosed: (String) -> Unit,
    ): SseHandle {
        val handle = SseHandle()
        sseExecutor.execute {
            var reason = "server_closed"
            var conn: HttpURLConnection? = null
            try {
                conn = (URL(url).openConnection() as HttpURLConnection).apply {
                    requestMethod = "POST"
                    connectTimeout = connectTimeoutMs
                    readTimeout = idleTimeoutMs
                    doOutput = true
                    setRequestProperty("Content-Type", "application/json;charset=UTF-8")
                    setRequestProperty("Accept", "text/event-stream")
                    setRequestProperty("Connection", "keep-alive")
                }
                handle.conn = conn
                val body = JSONObject().put("data", armor).toString()
                OutputStreamWriter(conn.outputStream, Charsets.UTF_8).use { it.write(body) }
                val code = conn.responseCode
                if (code !in 200..299 || conn.inputStream == null) {
                    reason = "HTTP $code"
                } else {
                    onOpen()
                    val stream = BufferedInputStream(conn.inputStream)
                    val buf = ByteArray(4096)
                    val sse = StringBuilder()
                    while (!handle.cancelled) {
                        val n = stream.read(buf)
                        if (n < 0) break
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
                            val payload = frameToPayload(block)
                            if (payload.isNotEmpty()) onEvent(payload)
                        }
                    }
                    reason = if (handle.cancelled) "root_stop" else "server_closed"
                }
            } catch (e: Exception) {
                reason = if (handle.cancelled) "root_stop" else (e.message ?: "sse_error")
            } finally {
                try {
                    conn?.disconnect()
                } catch (_: Exception) {
                }
                handle.conn = null
                onClosed(reason)
            }
        }
        return handle
    }

    /** SI sends raw JSON frames; classic SSE `data:` lines are accepted too. */
    private fun frameToPayload(block: String): String {
        val dataLines = block.lineSequence()
            .map { it.trimEnd() }
            .filter { it.startsWith("data:") }
            .map { it.removePrefix("data:").trimStart() }
            .toList()
        return (if (dataLines.isNotEmpty()) dataLines.joinToString("\n") else block).trim()
    }

    // ---- internals ---------------------------------------------------------------

    private fun weightedPick(
        pool: List<BeamioChatPgpStore.SiNode>,
        scores: Map<String, Int>,
    ): BeamioChatPgpStore.SiNode? {
        if (pool.isEmpty()) return null
        val weights = pool.map { node ->
            val ip = normalizeIp(node.ip) ?: return@map 1
            maxOf(scores[ip] ?: 80, 1)
        }
        val total = weights.sum()
        if (total <= 0) return pool.random()
        var draw = Random.nextInt(total)
        for (i in weights.indices) {
            draw -= weights[i]
            if (draw < 0) return pool[i]
        }
        return pool.last()
    }

    /** Any HTTP status means the IP answered. Timeout and connection errors do not. */
    private fun probeIp(ip: String, timeoutMs: Int): ProbeResult {
        val url = if (ip.contains(":")) "http://[$ip]/" else "http://$ip/"
        val started = System.currentTimeMillis()
        var conn: HttpURLConnection? = null
        return try {
            conn = (URL(url).openConnection() as HttpURLConnection).apply {
                requestMethod = "GET"
                connectTimeout = timeoutMs
                readTimeout = timeoutMs
                instanceFollowRedirects = false
                setRequestProperty("Accept", "text/html")
            }
            val code = conn.responseCode
            val latency = (System.currentTimeMillis() - started).toInt()
            ProbeResult(reachable = code > 0, latencyMs = latency)
        } catch (_: Exception) {
            ProbeResult(reachable = false, latencyMs = timeoutMs)
        } finally {
            conn?.disconnect()
        }
    }

    /** Prefer JSON `ok` / `success` when present; empty or non-JSON 2xx → true. */
    private fun bodyOk(text: String): Boolean {
        val trimmed = text.trim()
        if (trimmed.isEmpty()) return true
        return try {
            val obj = JSONObject(trimmed)
            when {
                obj.has("ok") -> obj.optBoolean("ok", true)
                obj.has("success") -> obj.optBoolean("success", true)
                else -> true
            }
        } catch (_: Exception) {
            true
        }
    }

    private fun httpPost(url: String, body: String, readTimeoutMs: Int): Pair<Int, String> {
        var conn: HttpURLConnection? = null
        return try {
            conn = (URL(url).openConnection() as HttpURLConnection).apply {
                requestMethod = "POST"
                connectTimeout = 10_000
                readTimeout = readTimeoutMs
                doOutput = true
                setRequestProperty("Content-Type", "application/json")
            }
            OutputStreamWriter(conn.outputStream, Charsets.UTF_8).use { it.write(body) }
            val code = conn.responseCode
            val stream = if (code in 200..299) conn.inputStream else conn.errorStream
            val text = stream?.let {
                BufferedReader(InputStreamReader(it, Charsets.UTF_8)).use { r -> r.readText() }
            }.orEmpty()
            code to text
        } catch (_: Exception) {
            0 to ""
        } finally {
            conn?.disconnect()
        }
    }

    private data class ProbeResult(val reachable: Boolean, val latencyMs: Int)
}
