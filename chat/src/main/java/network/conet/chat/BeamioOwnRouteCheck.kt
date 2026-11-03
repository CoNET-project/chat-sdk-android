package network.conet.chat

import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import org.json.JSONArray
import org.json.JSONObject

/**
 * Own mailbox route vs the chain record (AddressPGP `searchKey`).
 *
 * 2026-11-02 RC3: a listen ran on a mailbox the chain never had. The page had
 * picked a random node after a failed chain read and handed it to the module,
 * so calls and cancels sent to the chain mailbox never arrived. The module now
 * logs the route key ID of every listen and checks it against the chain once a
 * listen starts: a failed read is retried with backoff (never treated as "no
 * record"), and a different chain route wins: the listen reopens on it.
 *
 * The route key ID is the key ID of the route key's encryption subkey: that is
 * what AddressPGP stores as `routePgpKeyID` and what SI node domains are named
 * after. Only key IDs are logged, never armor or wallet addresses.
 */
internal object BeamioOwnRouteCheck {
    const val ADDRESS_PGP = "0x684b0ac760cEE9c9b85de36d69746420648Cf9e2"
    /** keccak256("searchKey(address)")[0..4] */
    private const val SEARCH_KEY_SELECTOR = "052f2778"
    /** Waits between chain reads while they fail (ms); the last one repeats. */
    val RETRY_DELAYS_MS = longArrayOf(5_000, 15_000, 30_000, 60_000, 120_000, 300_000)

    sealed class ChainRoute {
        data class Ok(val routeKeyId: String, val routeArmor: String) : ChainRoute()
        /** The read worked; the account has no route on chain. */
        object Empty : ChainRoute()
        /** RPC error, timeout, bad reply: unknown, never "no record". */
        data class Error(val reason: String) : ChainRoute()
    }

    sealed class Verdict {
        object Match : Verdict()
        data class Switch(val routeKeyId: String, val routeArmor: String) : Verdict()
        /** Chain has no route: keep listening; registering is the page's job. */
        object NoRoute : Verdict()
        data class Retry(val reason: String) : Verdict()
    }

    fun verdict(listenArmor: String, chain: ChainRoute): Verdict = when (chain) {
        is ChainRoute.Error -> Verdict.Retry(chain.reason)
        is ChainRoute.Empty -> Verdict.NoRoute
        is ChainRoute.Ok -> {
            val listenId = routeKeyId(listenArmor)
            val chainId = chain.routeKeyId.ifBlank { routeKeyId(chain.routeArmor) }.uppercase()
            val same = if (listenId.isNotEmpty() && chainId.isNotEmpty()) {
                listenId == chainId
            } else {
                BeamioConetChatListenSession.fingerprintsOverlap(listenArmor, chain.routeArmor)
            }
            if (same) Verdict.Match else Verdict.Switch(chainId, chain.routeArmor)
        }
    }

    /**
     * Read until one read works, sleeping [RETRY_DELAYS_MS] after each failure.
     * [sleep] returns false to give up (session gone). Returns the last verdict.
     */
    fun reconcile(
        listenArmor: () -> String,
        read: () -> ChainRoute,
        sleep: (Long) -> Boolean,
        onRetry: (reason: String, waitMs: Long) -> Unit = { _, _ -> },
    ): Verdict {
        var attempt = 0
        while (true) {
            val v = verdict(listenArmor(), read())
            if (v !is Verdict.Retry) return v
            val waitMs = RETRY_DELAYS_MS[minOf(attempt, RETRY_DELAYS_MS.size - 1)]
            attempt += 1
            onRetry(v.reason, waitMs)
            if (!sleep(waitMs)) return v
        }
    }

    // ---- key ID --------------------------------------------------------------

    /** Route key ID (encryption subkey, else primary), upper-case hex; "" if unreadable. */
    fun routeKeyId(armor: String): String {
        val bytes = dearmor(armor) ?: return ""
        var primary = ""
        var pos = 0
        while (pos < bytes.size) {
            val head = bytes[pos].toInt() and 0xff
            if (head and 0x80 == 0) return primary
            val tag: Int
            var len: Int
            var p = pos + 1
            if (head and 0x40 != 0) {
                tag = head and 0x3f
                if (p >= bytes.size) return primary
                val o1 = bytes[p].toInt() and 0xff
                when {
                    o1 < 192 -> { len = o1; p += 1 }
                    o1 < 224 -> {
                        if (p + 1 >= bytes.size) return primary
                        len = ((o1 - 192) shl 8) + (bytes[p + 1].toInt() and 0xff) + 192; p += 2
                    }
                    o1 == 255 -> {
                        if (p + 4 >= bytes.size) return primary
                        len = readBe(bytes, p + 1, 4); p += 5
                    }
                    else -> return primary // partial lengths never appear in key packets
                }
            } else {
                tag = (head shr 2) and 0x0f
                when (head and 0x03) {
                    0 -> { if (p >= bytes.size) return primary; len = bytes[p].toInt() and 0xff; p += 1 }
                    1 -> { if (p + 1 >= bytes.size) return primary; len = readBe(bytes, p, 2); p += 2 }
                    2 -> { if (p + 3 >= bytes.size) return primary; len = readBe(bytes, p, 4); p += 4 }
                    else -> return primary
                }
            }
            if (len < 0 || p + len > bytes.size) return primary
            if (tag == 6 || tag == 14) {
                val id = keyIdOfPacket(bytes, p, len)
                if (tag == 14 && id.isNotEmpty()) return id
                if (tag == 6 && primary.isEmpty()) primary = id
            }
            pos = p + len
        }
        return primary
    }

    private fun keyIdOfPacket(b: ByteArray, off: Int, len: Int): String {
        if (len < 1) return ""
        val body = b.copyOfRange(off, off + len)
        return when (body[0].toInt()) {
            4 -> {
                val md = MessageDigest.getInstance("SHA-1")
                md.update(byteArrayOf(0x99.toByte(), (len shr 8).toByte(), len.toByte()))
                md.update(body)
                hex(md.digest().copyOfRange(12, 20))
            }
            6 -> {
                val md = MessageDigest.getInstance("SHA-256")
                md.update(byteArrayOf(0x9B.toByte(), (len ushr 24).toByte(), (len shr 16).toByte(), (len shr 8).toByte(), len.toByte()))
                md.update(body)
                hex(md.digest().copyOfRange(0, 8))
            }
            else -> ""
        }
    }

    private fun dearmor(armor: String): ByteArray? {
        val lines = armor.replace("\r", "").lines().map { it.trim() }
        val begin = lines.indexOfFirst { it.startsWith("-----BEGIN PGP PUBLIC KEY BLOCK") }
        if (begin < 0) return null
        val end = lines.indexOfFirst { it.startsWith("-----END PGP PUBLIC KEY BLOCK") }
        if (end <= begin) return null
        var i = begin + 1
        // Armor headers ("Version: …") end at the first blank line, when present.
        if (lines.subList(i, end).any { it.isEmpty() } && lines[i].contains(':')) {
            while (i < end && lines[i].isNotEmpty()) i++
        }
        val body = lines.subList(i, end).filter { it.isNotEmpty() && !it.startsWith("=") && !it.contains(':') }
            .joinToString("")
        return try {
            ConetChatCryptoUtil.base64Decode(body)
        } catch (_: Exception) {
            null
        }
    }

    // ---- chain read ----------------------------------------------------------

    fun searchKeyCallData(eoa: String): String {
        val addr = eoa.trim().lowercase().removePrefix("0x")
        require(addr.length == 40 && addr.all { it in '0'..'9' || it in 'a'..'f' }) { "bad address" }
        return "0x$SEARCH_KEY_SELECTOR${"0".repeat(24)}$addr"
    }

    /** ABI-decode `searchKey` → (userPgpKeyID, userPublicKeyArmored, routePgpKeyID, routePublicKeyArmored(base64), routeOnline). */
    fun decodeSearchKeyResult(resultHex: String): ChainRoute {
        val raw = resultHex.trim().removePrefix("0x")
        if (raw.isEmpty() || raw.length % 2 != 0) return ChainRoute.Error("empty_reply")
        val data = try {
            ByteArray(raw.length / 2) { raw.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
        } catch (_: NumberFormatException) {
            return ChainRoute.Error("bad_reply")
        }
        if (data.size < 5 * 32) return ChainRoute.Error("short_reply")
        return try {
            val routeId = abiString(data, 2).trim()
            val routeB64 = abiString(data, 3).trim()
            if (routeId.isEmpty() && routeB64.isEmpty()) return ChainRoute.Empty
            val armor = try {
                String(ConetChatCryptoUtil.base64Decode(routeB64.replace(Regex("\\s+"), "")), Charsets.UTF_8).replace("\r", "").trim()
            } catch (_: Exception) {
                ""
            }
            if (!armor.contains("BEGIN PGP PUBLIC KEY")) return ChainRoute.Empty
            ChainRoute.Ok(routeId.uppercase(), armor)
        } catch (e: Exception) {
            ChainRoute.Error("bad_reply")
        }
    }

    private fun abiString(data: ByteArray, index: Int): String {
        val off = readBeLong(data, index * 32).toInt()
        val len = readBeLong(data, off).toInt()
        require(off >= 0 && len >= 0 && off + 32 + len <= data.size)
        return String(data, off + 32, len, Charsets.UTF_8)
    }

    /** One `eth_call` (no `from`). Errors come back as [ChainRoute.Error]. */
    fun readChainRoute(rpcUrl: String, eoa: String, timeoutMs: Int = 8_000): ChainRoute {
        val call = try {
            JSONObject().put("to", ADDRESS_PGP).put("data", searchKeyCallData(eoa))
        } catch (_: IllegalArgumentException) {
            return ChainRoute.Error("bad_address")
        }
        val body = JSONObject()
            .put("jsonrpc", "2.0").put("id", 1).put("method", "eth_call")
            .put("params", JSONArray().put(call).put("latest"))
            .toString()
        return try {
            val conn = (URL(rpcUrl).openConnection() as HttpURLConnection).apply {
                requestMethod = "POST"
                connectTimeout = timeoutMs
                readTimeout = timeoutMs
                doOutput = true
                setRequestProperty("Content-Type", "application/json")
            }
            try {
                conn.outputStream.use { it.write(body.toByteArray()) }
                val code = conn.responseCode
                if (code !in 200..299) return ChainRoute.Error("HTTP $code")
                val text = conn.inputStream.bufferedReader().use { it.readText() }
                val obj = JSONObject(text)
                if (obj.has("error")) return ChainRoute.Error("rpc_error")
                decodeSearchKeyResult(obj.optString("result", ""))
            } finally {
                conn.disconnect()
            }
        } catch (e: Exception) {
            ChainRoute.Error(e.javaClass.simpleName)
        }
    }

    private fun readBe(b: ByteArray, off: Int, n: Int): Int {
        var v = 0
        for (i in 0 until n) v = (v shl 8) or (b[off + i].toInt() and 0xff)
        return v
    }

    private fun readBeLong(b: ByteArray, off: Int): Long {
        require(off >= 0 && off + 32 <= b.size)
        for (i in 0 until 24) require(b[off + i].toInt() == 0)
        var v = 0L
        for (i in 24 until 32) v = (v shl 8) or (b[off + i].toLong() and 0xff)
        return v
    }

    private fun hex(b: ByteArray): String = b.joinToString("") { "%02X".format(it.toInt() and 0xff) }
}
