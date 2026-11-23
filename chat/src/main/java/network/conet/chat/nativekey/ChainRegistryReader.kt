package network.conet.chat.nativekey

import org.json.JSONArray
import org.json.JSONObject
import java.net.ConnectException
import java.net.HttpURLConnection
import java.net.SocketTimeoutException
import java.net.URL

/** The result of one `eth_call`, as the transport reports it (§25.52HH.4). */
internal sealed class EthCallResult {
    /** The `result` value: `0x` hex. */
    class Value(val hex: String) : EthCallResult()

    /** A revert: the error data, or null when the node gave none. */
    class Reverted(val data: String?) : EthCallResult()

    /** A transport, HTTP, RPC, or decoding failure of the JSON-RPC envelope. */
    class Failed(val outcome: RawOutcome) : EthCallResult()
}

/**
 * The JSON-RPC reads of the registry (draft r2.5.20 第 7 版, confirmed by the interface seat): one `eth_call` at a block tag, the block number, and the
 * block by number. None throws; a failure is a failed result or null.
 */
internal interface EthTransport {
    /** One read-only `eth_call` at [blockTag] to one URL, within [timeoutMs]. */
    fun call(url: String, to: String, data: String, blockTag: String, timeoutMs: Long): EthCallResult

    /** `eth_blockNumber` as a `0x` hex string, or null on any failure. */
    fun blockNumber(url: String, timeoutMs: Long): String?

    /** `eth_getBlockByNumber(blockTag, false)`: the number and the hash the endpoint returns, or null on any failure. */
    fun blockByNumber(url: String, blockTag: String, timeoutMs: Long): BlockRef?
}

/** A block as an endpoint reports it: its number (`0x` hex) and its hash. */
internal data class BlockRef(val number: String, val hash: String)

/**
 * The live read of the current registry (§25.52HH.1, HI.2): `getAccount(address)` and `getOwnerByAccountName(string)`, as `eth_call` only. A revert is
 * classified exactly (HH.4); every failure is an invalid result, and no failure is "no record".
 *
 * Two endpoints, agreed (draft r2.5.20 第 7 版): both are read at one block N (A's block number), each must return block N with the same hash, and
 * both must give the same answer. Only both exact AccountNotFound (or both zero owner) is absent. A single absence, a disagreement, or any error is
 * invalid, which the binding decision reports as `lookup_unavailable` (retry, never create).
 */
internal class ChainRegistryReader(
    private val transport: EthTransport = HttpEthTransport(),
    private val registry: String = AccountRegistryRead.current.registry,
    private val endpoints: List<RegistryEndpoint> = AccountRegistryRead.current.endpoints.take(2),
    private val nowMs: () -> Long = { System.nanoTime() / 1_000_000L },
) : RegistryReader {

    /** The decoded answer of one read: the raw outcome, and the bound EOA of a tag read. */
    internal class Decoded(val raw: RawOutcome, val eoa: String? = null)

    override fun readAccount(eoa: String, deadlineMs: Long): RegistryRead {
        val data = callData(SIG_GET_ACCOUNT, addressWord(eoa) ?: return RegistryRead.Invalid("semantic_failed"))
        return one(BindingKind.EOA, deadlineMs, data, ::decodeAccount)
    }

    override fun readOwner(tag: String, deadlineMs: Long): RegistryRead {
        val data = callDataString(SIG_OWNER_BY_NAME, tag)
        return one(BindingKind.TAG, deadlineMs, data, ::decodeOwner)
    }

    private fun budget(deadlineMs: Long): Long? = RegistryBudget.perCallTimeout(deadlineMs, nowMs())

    private fun interpret(kind: BindingKind, r: EthCallResult, decode: (String) -> Decoded): RegistryRead {
        val decoded = when (r) {
            is EthCallResult.Value -> decode(r.hex)
            is EthCallResult.Reverted -> Decoded(RegistryMapping.classifyRevertData(r.data))
            is EthCallResult.Failed -> Decoded(r.outcome)
        }
        return when (val reg = RegistryMapping.map(kind, decoded.raw)) {
            is RegistryRead.Found -> RegistryRead.Found(decoded.eoa)
            else -> reg
        }
    }

    private fun one(kind: BindingKind, deadlineMs: Long, data: String, decode: (String) -> Decoded): RegistryRead {
        if (endpoints.size < 2) return RegistryRead.Invalid("endpoints_short")
        val a = endpoints[0].url
        val b = endpoints[1].url
        // The block is A's number N. Both endpoints must answer at N with the same hash (RP-05, RP-08 of the rpc-state vectors).
        val tagTimeout = budget(deadlineMs) ?: return RegistryRead.Invalid("budget_exceeded")
        val tag = transport.blockNumber(a, tagTimeout) ?: return RegistryRead.Invalid("rpc_error")
        val n = tag.removePrefix("0x").toLongOrNull(16) ?: return RegistryRead.Invalid("decode_failed")
        val ta0 = budget(deadlineMs) ?: return RegistryRead.Invalid("budget_exceeded")
        val blockA = transport.blockByNumber(a, tag, ta0) ?: return RegistryRead.Invalid("rpc_error")
        val tb0 = budget(deadlineMs) ?: return RegistryRead.Invalid("budget_exceeded")
        val blockB = transport.blockByNumber(b, tag, tb0) ?: return RegistryRead.Invalid("rpc_error")
        if (blockA.number.removePrefix("0x").toLongOrNull(16) != n || blockB.number.removePrefix("0x").toLongOrNull(16) != n) {
            return RegistryRead.Invalid("block_mismatch")
        }
        if (blockA.hash != blockB.hash) return RegistryRead.Invalid("hash_mismatch")
        val tA = budget(deadlineMs) ?: return RegistryRead.Invalid("budget_exceeded")
        val ra = interpret(kind, transport.call(a, registry, data, tag, tA), decode)
        val tB = budget(deadlineMs) ?: return RegistryRead.Invalid("budget_exceeded")
        val rb = interpret(kind, transport.call(b, registry, data, tag, tB), decode)
        return when {
            ra is RegistryRead.Absent && rb is RegistryRead.Absent -> RegistryRead.Absent
            ra is RegistryRead.Found && rb is RegistryRead.Found && ra.eoa == rb.eoa -> ra
            ra is RegistryRead.Invalid -> ra
            rb is RegistryRead.Invalid -> rb
            else -> RegistryRead.Invalid("disagree")
        }
    }

    companion object {
        const val SIG_GET_ACCOUNT = "getAccount(address)"
        const val SIG_OWNER_BY_NAME = "getOwnerByAccountName(string)"

        /** Call data: the 4-byte selector of [signature] and the encoded argument words. */
        fun callData(signature: String, argWords: String): String = AddressPgpRead.selector(signature) + argWords

        /** The address argument as one word, or null when the EOA is not a lower-case `0x` address. */
        fun addressWord(eoa: String): String? {
            if (!Regex("^0x[0-9a-f]{40}$").matches(eoa)) return null
            return "0".repeat(24) + eoa.removePrefix("0x")
        }

        /** Call data for a string argument: the offset word, the length word, and the UTF-8 bytes padded to 32. */
        fun callDataString(signature: String, value: String): String {
            val b = value.toByteArray(Charsets.UTF_8)
            val padded = b.joinToString("") { "%02x".format(it) }.padEnd(((b.size + 31) / 32) * 64, '0')
            return callData(signature, "%064x".format(32) + "%064x".format(b.size) + padded)
        }

        private fun bytesOf(hex: String): ByteArray? {
            val h = hex.removePrefix("0x")
            if (h.length % 2 != 0 || !h.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) return null
            return ByteArray(h.length / 2) { h.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
        }

        private fun wordAt(b: ByteArray, offset: Int): java.math.BigInteger? {
            if (offset < 0 || offset + 32 > b.size) return null
            return java.math.BigInteger(1, b.copyOfRange(offset, offset + 32))
        }

        /**
         * `getAccount` (the `Account` tuple, dynamic, §25.52HH.1; source AccountRegistry.sol): the head is 12 words, `accountName` is the first
         * head word (an offset from the tuple start), and `exists` is the tenth. A non-empty `accountName` with `exists` true is a bound record.
         */
        internal fun decodeAccount(hex: String): Decoded {
            val b = bytesOf(hex) ?: return Decoded(RawOutcome.DECODE_FAILED)
            val tuple = wordAt(b, 0)?.toInt()?.takeIf { it == 32 } ?: return Decoded(RawOutcome.DECODE_FAILED)
            val existsWord = wordAt(b, tuple + 9 * 32) ?: return Decoded(RawOutcome.DECODE_FAILED)
            if (existsWord.signum() == 0) return Decoded(RawOutcome.EXISTS_FALSE)
            if (existsWord != java.math.BigInteger.ONE) return Decoded(RawOutcome.SEMANTIC_FAILED)
            val nameOffset = wordAt(b, tuple)?.toInt() ?: return Decoded(RawOutcome.DECODE_FAILED)
            val nameStart = tuple + nameOffset
            val nameLen = wordAt(b, nameStart)?.toInt() ?: return Decoded(RawOutcome.DECODE_FAILED)
            if (nameLen < 0 || nameStart + 32 + nameLen > b.size) return Decoded(RawOutcome.DECODE_FAILED)
            if (nameLen == 0) return Decoded(RawOutcome.EXISTS_TRUE_NAME_EMPTY)
            return Decoded(RawOutcome.BOUND)
        }

        /** `getOwnerByAccountName`: one address word. The upper 12 bytes must be zero; the zero address is no record (HH.4). */
        internal fun decodeOwner(hex: String): Decoded {
            val b = bytesOf(hex) ?: return Decoded(RawOutcome.DECODE_FAILED)
            if (b.size != 32) return Decoded(RawOutcome.DECODE_FAILED)
            if (b.copyOfRange(0, 12).any { it != 0.toByte() }) return Decoded(RawOutcome.SEMANTIC_FAILED)
            val addr = b.copyOfRange(12, 32)
            if (addr.all { it == 0.toByte() }) return Decoded(RawOutcome.ZERO_ADDRESS)
            return Decoded(RawOutcome.BOUND, "0x" + addr.joinToString("") { "%02x".format(it) })
        }
    }
}

/** One JSON-RPC POST for the block reads. Null on any failure; nothing is logged. */
internal fun postRpc(url: String, method: String, params: JSONArray, timeoutMs: Long): JSONObject? {
    var conn: HttpURLConnection? = null
    return try {
        val ms = timeoutMs.toInt().coerceAtLeast(1)
        conn = (URL(url).openConnection() as HttpURLConnection).apply {
            connectTimeout = ms
            readTimeout = ms
            requestMethod = "POST"
            doOutput = true
            setRequestProperty("Content-Type", "application/json")
        }
        val body = JSONObject().put("jsonrpc", "2.0").put("id", 1).put("method", method).put("params", params)
        conn.outputStream.use { it.write(body.toString().toByteArray(Charsets.UTF_8)) }
        if (conn.responseCode !in 200..299) null else JSONObject(conn.inputStream.bufferedReader(Charsets.UTF_8).use { it.readText() })
    } catch (_: Exception) {
        null
    } finally {
        conn?.disconnect()
    }
}

/**
 * The production transport: HTTPS JSON-RPC, POST, with the read timeout of the call. Errors are sorted into [EthCallResult]; nothing is logged, and
 * no request value is written to a log.
 */
internal class HttpEthTransport : EthTransport {
    override fun call(url: String, to: String, data: String, blockTag: String, timeoutMs: Long): EthCallResult {
        val body = JSONObject()
            .put("jsonrpc", "2.0")
            .put("id", 1)
            .put("method", "eth_call")
            .put("params", JSONArray().put(JSONObject().put("to", to).put("data", data)).put(blockTag))
        val ms = timeoutMs.toInt().coerceAtLeast(1)
        var conn: HttpURLConnection? = null
        return try {
            conn = (URL(url).openConnection() as HttpURLConnection).apply {
                connectTimeout = ms
                readTimeout = ms
                requestMethod = "POST"
                doOutput = true
                setRequestProperty("Content-Type", "application/json")
            }
            conn.outputStream.use { it.write(body.toString().toByteArray(Charsets.UTF_8)) }
            if (conn.responseCode !in 200..299) return EthCallResult.Failed(RawOutcome.HTTP_ERROR)
            parse(conn.inputStream.bufferedReader(Charsets.UTF_8).use { it.readText() })
        } catch (_: SocketTimeoutException) {
            EthCallResult.Failed(RawOutcome.TIMEOUT)
        } catch (_: ConnectException) {
            EthCallResult.Failed(RawOutcome.CONNECTION_REFUSED)
        } catch (_: Exception) {
            EthCallResult.Failed(RawOutcome.RPC_ERROR)
        } finally {
            conn?.disconnect()
        }
    }

    override fun blockNumber(url: String, timeoutMs: Long): String? =
        postRpc(url, "eth_blockNumber", JSONArray(), timeoutMs)?.opt("result") as? String

    override fun blockByNumber(url: String, blockTag: String, timeoutMs: Long): BlockRef? {
        val r = postRpc(url, "eth_getBlockByNumber", JSONArray().put(blockTag).put(false), timeoutMs)?.optJSONObject("result") ?: return null
        val number = r.optString("number")
        val hash = r.optString("hash")
        return if (number.isEmpty() || hash.isEmpty()) null else BlockRef(number, hash)
    }

    companion object {
        /** The JSON-RPC envelope. An error with hex error data is a revert; other errors are RPC failures. */
        internal fun parse(text: String): EthCallResult {
            val json = try {
                JSONObject(text)
            } catch (_: Exception) {
                return EthCallResult.Failed(RawOutcome.NON_JSON)
            }
            val err = json.opt("error")
            if (err != null && err != JSONObject.NULL) {
                val data = (err as? JSONObject)?.opt("data") as? String
                return if (data != null && data.startsWith("0x")) EthCallResult.Reverted(data) else EthCallResult.Failed(RawOutcome.RPC_ERROR)
            }
            if (!json.has("result") || json.isNull("result")) return EthCallResult.Failed(RawOutcome.NO_RESULT)
            val result = json.opt("result") as? String ?: return EthCallResult.Failed(RawOutcome.DECODE_FAILED)
            return EthCallResult.Value(result)
        }
    }
}
