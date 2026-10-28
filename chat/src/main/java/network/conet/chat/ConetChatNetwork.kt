package network.conet.chat

import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.ConcurrentHashMap
import kotlin.random.Random

/**
 * Guardian / SI entry helpers: HTTP-only URLs, scored [getRandomNode], IP reachability gate.
 */
object ConetChatNetwork {
    data class EntryCandidate(
        val ip: String,
        val domain: String = "",
        val armoredPublicKey: String = "",
    )

    /** Higher is better. Unscored reachable nodes start at 80. */
    private val entryScores = ConcurrentHashMap<String, Int>()

    /** IPs that failed the reachability probe. [getRandomNode] never returns these. */
    private val unreachableIps = ConcurrentHashMap.newKeySet<String>()

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

    /** HTTP only — never HTTPS domain posts. */
    fun postUrl(ip: String): String? {
        val norm = normalizeIp(ip) ?: return null
        return if (norm.contains(":")) "http://[$norm]/post" else "http://$norm/post"
    }

    /**
     * Score one entry after an IP probe or an HTTP POST.
     * Unreachable IPs are zeroed and never returned by [getRandomNode].
     */
    fun scoreEntry(ip: String, reachable: Boolean, latencyMs: Int) {
        val ipNorm = normalizeIp(ip) ?: return
        if (!reachable) {
            unreachableIps.add(ipNorm)
            entryScores[ipNorm] = 0
            return
        }
        unreachableIps.remove(ipNorm)
        val speed = maxOf(1, 500 - minOf(maxOf(latencyMs, 0), 500))
        val prev = maxOf(entryScores[ipNorm] ?: 80, 1)
        entryScores[ipNorm] = minOf(2000, prev / 2 + speed)
    }

    /**
     * Prefer high-scoring entries. Probe `http://{ip}/` first;
     * unreachable IPs are scored out and never returned to the caller.
     */
    fun getRandomNode(
        nodes: List<EntryCandidate>,
        excludeIps: Set<String> = emptySet(),
        probeTimeoutMs: Int = 2_000,
    ): EntryCandidate? {
        val blocked = excludeIps.mapNotNull { normalizeIp(it) }.toSet()
        val dead = unreachableIps.toSet()
        val scores = entryScores.toMap()

        val pool = ArrayList<EntryCandidate>()
        val seen = HashSet<String>()
        for (node in nodes) {
            val ip = normalizeIp(node.ip) ?: continue
            if (ip in blocked || ip in dead || !seen.add(ip)) continue
            pool.add(EntryCandidate(ip = ip, domain = node.domain, armoredPublicKey = node.armoredPublicKey))
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

    private fun weightedPick(
        pool: List<EntryCandidate>,
        scores: Map<String, Int>,
    ): EntryCandidate? {
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
            }
            val code = conn.responseCode
            ProbeResult(reachable = code > 0, latencyMs = (System.currentTimeMillis() - started).toInt())
        } catch (_: Exception) {
            ProbeResult(reachable = false, latencyMs = timeoutMs)
        } finally {
            conn?.disconnect()
        }
    }

    private data class ProbeResult(val reachable: Boolean, val latencyMs: Int)
}
