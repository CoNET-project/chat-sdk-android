package network.conet.chat.nativekey

import network.conet.chat.ConetChatCryptoUtil
import org.json.JSONArray
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

/**
 * Read-only access to AddressPGP (spec 25.36, P-IMP-PGP): the public record `_pgpKeys(address)` and the encrypted backup
 * `getEncryptedPrivateKey()`, read at one block. Only `eth_blockNumber` and `eth_call` are used, and only the two view
 * selectors below are encoded. No write method exists here (25.36.2 item 5).
 *
 * The contract address and the endpoint are parameters. The owner has not confirmed them (25.36.4), so nothing in this
 * file fixes them. A failed read is [SOURCE_UNAVAILABLE]. It is never read as "no record" or "no backup" (25.36.2 item 4).
 */
internal object AddressPgpRead {
    const val SOURCE_UNAVAILABLE = "pgp_source_unavailable"

    /** `_pgpKeys(address)`: (string pgpKeyID, string publicKeyArmored, string encrypKeyArmored, bool exists). */
    const val SIG_PGP_KEYS = "_pgpKeys(address)"

    /** `getEncryptedPrivateKey()`: string. It reads `msg.sender`, so the call must carry `from` = the account. */
    const val SIG_ENCRYPTED_BACKUP = "getEncryptedPrivateKey()"

    data class Record(
        val pgpKeyId: String,
        val publicKeyArmored: String,
        val encryptKeyArmored: String,
        val exists: Boolean,
    )

    /** One read: the same [block] for both calls (25.36.2 item 3). An empty [backupText] is "no backup", not a failure. */
    data class Snapshot(val block: Long, val record: Record, val backupText: String)

    /** One JSON-RPC call. Returns the `result` value, or throws on any transport, HTTP or RPC error. */
    fun interface Rpc {
        fun call(method: String, params: JSONArray): Any?
    }

    /** The first four bytes of keccak256 of the signature, as `0x` + 8 hex digits. */
    fun selector(signature: String): String =
        "0x" + ConetChatCryptoUtil.keccak256(signature.toByteArray(Charsets.UTF_8)).take(4).joinToString("") { "%02x".format(it) }

    /** Call data for [signature] with an optional address argument. */
    fun encodeCall(signature: String, addressArg: String?): String =
        selector(signature) + (addressArg?.let { padAddress(it) } ?: "")

    private fun padAddress(address: String): String {
        val a = address.removePrefix("0x").lowercase()
        require(Regex("[0-9a-f]{40}").matches(a)) { "bad address" }
        return a.padStart(64, '0')
    }

    /** Decodes `(string, string, string, bool)`. `null` for anything that is not a well-formed encoding. */
    fun decodeRecord(hex: String): Record? {
        val b = hexToBytes(hex) ?: return null
        if (b.size < 128) return null
        val a = readString(b, wordAsInt(b, 0) ?: return null) ?: return null
        val p = readString(b, wordAsInt(b, 32) ?: return null) ?: return null
        val c = readString(b, wordAsInt(b, 64) ?: return null) ?: return null
        val exists = when (wordAsInt(b, 96)) {
            0 -> false
            1 -> true
            else -> return null
        }
        return Record(a, p, c, exists)
    }

    /** Decodes a single `string` return. `null` when malformed. The empty string is a valid result. */
    fun decodeString(hex: String): String? {
        val b = hexToBytes(hex) ?: return null
        if (b.size < 64) return null
        return readString(b, wordAsInt(b, 0) ?: return null)
    }

    /**
     * Reads the record and the backup for [eoa] at one block. Any failure, including a malformed answer, is
     * `Result.failure` with [SOURCE_UNAVAILABLE].
     */
    private inline fun <T> step(name: String, block: () -> T): T {
        val t0 = DiagTiming.now()
        try {
            return block()
        } catch (e: Exception) {
            DiagTiming.log("chain.step:$name", t0, "fail:" + e.javaClass.simpleName)
            throw e
        }
    }

    fun snapshot(rpc: Rpc, contract: String, eoa: String): Result<Snapshot> = runCatching {
        // diag5 (logging only): each step logs its label, milliseconds and the exception class on failure. No message, no content.
        val tag = step("blockNumber") { rpc.call("eth_blockNumber", JSONArray()) as? String ?: error(SOURCE_UNAVAILABLE) }
        val recordHex = step("record") {
            rpc.call(
                "eth_call",
                JSONArray().put(JSONObject().put("to", contract).put("data", encodeCall(SIG_PGP_KEYS, eoa))).put(tag),
            ) as? String ?: error(SOURCE_UNAVAILABLE)
        }
        val backupHex = step("backup") {
            rpc.call(
                "eth_call",
                JSONArray()
                    .put(JSONObject().put("from", eoa).put("to", contract).put("data", encodeCall(SIG_ENCRYPTED_BACKUP, null)))
                    .put(tag),
            ) as? String ?: error(SOURCE_UNAVAILABLE)
        }
        val record = decodeRecord(recordHex) ?: error(SOURCE_UNAVAILABLE)
        val backup = decodeString(backupHex) ?: error(SOURCE_UNAVAILABLE)
        Snapshot(tag.removePrefix("0x").toLong(16), record, backup)
    }.fold(
        onSuccess = { Result.success(it) },
        onFailure = { Result.failure(IllegalStateException(SOURCE_UNAVAILABLE)) },
    )

    /**
     * The hash of block [n] as the endpoint returns it for [tag] (eth_getBlockByNumber). Null when the call fails or the endpoint answers another
     * block. Shared by every two-endpoint read (draft 第 6 版 T-3, r2.5.20 第 7 版).
     */
    fun blockHashAt(rpc: Rpc, tag: String, n: Long): String? = try {
        val o = rpc.call("eth_getBlockByNumber", JSONArray().put(tag).put(false)) as? JSONObject
        if (o == null || o.getString("number").removePrefix("0x").toLong(16) != n) null else o.getString("hash")
    } catch (e: Exception) {
        null
    }

    /**
     * The record and the backup at one block [tag] (draft r2.5.20 第 6 版 T-3: both endpoints are read at the same block N). Any transport or decode
     * failure is a failure of this endpoint; the caller decides what a failure means.
     */
    fun snapshotAt(rpc: Rpc, contract: String, eoa: String, tag: String): Result<Snapshot> = runCatching {
        val recordHex = rpc.call(
            "eth_call",
            JSONArray().put(JSONObject().put("to", contract).put("data", encodeCall(SIG_PGP_KEYS, eoa))).put(tag),
        ) as? String ?: error(SOURCE_UNAVAILABLE)
        val backupHex = rpc.call(
            "eth_call",
            JSONArray()
                .put(JSONObject().put("from", eoa).put("to", contract).put("data", encodeCall(SIG_ENCRYPTED_BACKUP, null)))
                .put(tag),
        ) as? String ?: error(SOURCE_UNAVAILABLE)
        val record = decodeRecord(recordHex) ?: error(SOURCE_UNAVAILABLE)
        val backup = decodeString(backupHex) ?: error(SOURCE_UNAVAILABLE)
        Snapshot(tag.removePrefix("0x").toLong(16), record, backup)
    }.fold(
        onSuccess = { Result.success(it) },
        onFailure = { Result.failure(IllegalStateException(SOURCE_UNAVAILABLE)) },
    )

    /**
     * The production transport: JSON-RPC over HTTPS POST. No WebSocket. Only https endpoints are accepted, and the
     * endpoint itself is supplied by the caller (25.36.4 item 3 is pending).
     */
    class HttpRpc(private val url: String, private val timeoutMs: Int = 8_000) : Rpc {
        init {
            require(url.startsWith("https://")) { "https endpoint required" }
        }

        override fun call(method: String, params: JSONArray): Any? {
            val conn = URL(url).openConnection() as HttpURLConnection
            try {
                conn.requestMethod = "POST"
                conn.connectTimeout = timeoutMs
                conn.readTimeout = timeoutMs
                conn.doOutput = true
                conn.setRequestProperty("Content-Type", "application/json")
                val body = JSONObject().put("jsonrpc", "2.0").put("id", 1).put("method", method).put("params", params)
                conn.outputStream.use { it.write(body.toString().toByteArray(Charsets.UTF_8)) }
                if (conn.responseCode !in 200..299) error("http ${conn.responseCode}")
                val text = conn.inputStream.bufferedReader(Charsets.UTF_8).use { it.readText() }
                val reply = JSONObject(text)
                if (reply.has("error") && !reply.isNull("error")) error("rpc error")
                return reply.opt("result")
            } finally {
                conn.disconnect()
            }
        }
    }

    private fun wordAsInt(b: ByteArray, at: Int): Int? {
        if (at < 0 || at + 32 > b.size) return null
        for (i in 0 until 28) if (b[at + i] != 0.toByte()) return null
        val v = ((b[at + 28].toInt() and 0xFF) shl 24) or ((b[at + 29].toInt() and 0xFF) shl 16) or
            ((b[at + 30].toInt() and 0xFF) shl 8) or (b[at + 31].toInt() and 0xFF)
        return if (v < 0) null else v
    }

    private fun readString(b: ByteArray, offset: Int): String? {
        val len = wordAsInt(b, offset) ?: return null
        val start = offset + 32
        if (start < 0 || start + len > b.size) return null
        return String(b, start, len, Charsets.UTF_8)
    }

    private fun hexToBytes(hex: String): ByteArray? {
        val h = hex.removePrefix("0x")
        if (h.length % 2 != 0 || !Regex("[0-9a-fA-F]*").matches(h)) return null
        return ByteArray(h.length / 2) { h.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    }
}
