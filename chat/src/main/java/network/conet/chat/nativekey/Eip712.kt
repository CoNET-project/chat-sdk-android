package network.conet.chat.nativekey

import network.conet.chat.ConetChatCryptoUtil
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.math.BigDecimal
import java.math.BigInteger

/**
 * EIP-712 typed-data hashing and signing in native code (replaces the WebView `ethers.Wallet` path, AND-K-c2 and
 * A-4). The result matches ethers v6 `TypedDataEncoder` and `Wallet.signTypedData(domain, types, value)`.
 *
 * Supported: atomic types (address, bool, uintN, intN, bytesN, bytes, string), arrays (`T[]` and `T[n]`), and
 * struct types that refer to each other. The EIP712Domain type is built from the domain members present, in the
 * order name, version, chainId, verifyingContract, salt. An unknown domain member, a missing value, or a malformed
 * value returns `null`, and nothing is signed.
 */
object Eip712 {
    private val DOMAIN_ORDER: List<Pair<String, String>> = listOf(
        "name" to "string",
        "version" to "string",
        "chainId" to "uint256",
        "verifyingContract" to "address",
        "salt" to "bytes32",
    )

    private class Field(val name: String, val type: String)

    /** `0x` + r || s || v for the EIP-712 digest of [typedData], or `null` when the input is not supported. */
    fun signTypedData(privateKey: ByteArray, typedData: JSONObject): String? {
        val d = digest(typedData) ?: return null
        return Eip191Signer.signDigest(privateKey, d)
    }

    /** keccak256(0x1901 || hashStruct(EIP712Domain) || hashStruct(primaryType)), or `null`. */
    fun digest(typedData: JSONObject): ByteArray? {
        val primary = typedData.optString("primaryType", "")
        if (primary.isEmpty() || primary == "EIP712Domain") return null
        val domain = typedData.optJSONObject("domain") ?: return null
        val value = typedData.optJSONObject("value") ?: typedData.optJSONObject("message") ?: return null
        val structs = parseTypes(typedData.optJSONObject("types") ?: return null) ?: return null
        val all = LinkedHashMap(structs)
        all["EIP712Domain"] = domainFields(domain) ?: return null
        if (!all.containsKey(primary)) return null
        val domainHash = hashStruct(all, "EIP712Domain", domain) ?: return null
        val messageHash = hashStruct(all, primary, value) ?: return null
        return ConetChatCryptoUtil.keccak256(byteArrayOf(0x19, 0x01) + domainHash + messageHash)
    }

    private fun parseTypes(types: JSONObject): LinkedHashMap<String, List<Field>>? {
        val out = LinkedHashMap<String, List<Field>>()
        for (name in types.keys()) {
            if (name == "EIP712Domain") continue
            val arr = types.optJSONArray(name) ?: return null
            val fields = ArrayList<Field>()
            for (i in 0 until arr.length()) {
                val f = arr.optJSONObject(i) ?: return null
                val fieldName = f.optString("name", "")
                val fieldType = f.optString("type", "")
                if (fieldName.isEmpty() || fieldType.isEmpty()) return null
                fields.add(Field(fieldName, fieldType))
            }
            out[name] = fields
        }
        return out
    }

    /** The EIP712Domain members present in [domain], in the fixed order. An unknown member makes the domain invalid. */
    private fun domainFields(domain: JSONObject): List<Field>? {
        for (key in domain.keys()) {
            if (DOMAIN_ORDER.none { it.first == key }) return null
        }
        return DOMAIN_ORDER.filter { domain.has(it.first) }.map { Field(it.first, it.second) }
    }

    private fun hashStruct(all: Map<String, List<Field>>, name: String, obj: JSONObject): ByteArray? =
        encodeData(all, name, obj)?.let { ConetChatCryptoUtil.keccak256(it) }

    private fun encodeData(all: Map<String, List<Field>>, name: String, obj: JSONObject): ByteArray? {
        val fields = all[name] ?: return null
        val out = ByteArrayOutputStream()
        out.write(typeHash(all, name))
        for (f in fields) {
            val raw = obj.opt(f.name)
            if (raw == null || raw == JSONObject.NULL) return null
            out.write(encodeValue(all, f.type, raw) ?: return null)
        }
        return out.toByteArray()
    }

    private fun typeHash(all: Map<String, List<Field>>, name: String): ByteArray =
        ConetChatCryptoUtil.keccak256(encodeType(all, name).toByteArray(Charsets.UTF_8))

    /** `Primary(type name,…)` followed by every referenced struct, sorted by name (EIP-712 encodeType). */
    private fun encodeType(all: Map<String, List<Field>>, primary: String): String {
        val deps = java.util.TreeSet<String>()
        fun visit(n: String) {
            for (f in all[n].orEmpty()) {
                val base = f.type.substringBefore('[')
                if (all.containsKey(base) && base != primary && deps.add(base)) visit(base)
            }
        }
        visit(primary)
        return format(all, primary) + deps.joinToString("") { format(all, it) }
    }

    private fun format(all: Map<String, List<Field>>, name: String): String =
        name + "(" + all[name].orEmpty().joinToString(",") { "${it.type} ${it.name}" } + ")"

    private fun encodeValue(all: Map<String, List<Field>>, type: String, v: Any): ByteArray? {
        if (type.endsWith("]")) {
            val base = type.substring(0, type.lastIndexOf('['))
            val arr = v as? JSONArray ?: return null
            val fixed = type.substring(type.lastIndexOf('[') + 1, type.length - 1)
            if (fixed.isNotEmpty() && fixed.toIntOrNull() != arr.length()) return null
            val out = ByteArrayOutputStream()
            for (i in 0 until arr.length()) {
                val item = arr.opt(i)
                if (item == null || item == JSONObject.NULL) return null
                out.write(encodeValue(all, base, item) ?: return null)
            }
            return ConetChatCryptoUtil.keccak256(out.toByteArray())
        }
        if (all.containsKey(type)) {
            val o = v as? JSONObject ?: return null
            return hashStruct(all, type, o)
        }
        return when {
            type == "string" -> (v as? String)?.let { ConetChatCryptoUtil.keccak256(it.toByteArray(Charsets.UTF_8)) }
            type == "bytes" -> hexBytes(v as? String)?.let { ConetChatCryptoUtil.keccak256(it) }
            type == "bool" -> (v as? Boolean)?.let { word(if (it) BigInteger.ONE else BigInteger.ZERO) }
            type == "address" -> address(v as? String)?.let { word(BigInteger(1, it)) }
            type.startsWith("uint") -> integer(v, type.removePrefix("uint"), signed = false)?.let { word(it) }
            type.startsWith("int") -> integer(v, type.removePrefix("int"), signed = true)?.let { word(it.mod(MOD256)) }
            type.startsWith("bytes") -> fixedBytes(v as? String, type.removePrefix("bytes"))
            else -> null
        }
    }

    private val MOD256: BigInteger = BigInteger.ONE.shiftLeft(256)

    /** A 32-byte big-endian word. [value] must already be in 0 until 2^256. */
    private fun word(value: BigInteger): ByteArray {
        val raw = value.toByteArray()
        val out = ByteArray(32)
        val n = minOf(raw.size, 32)
        System.arraycopy(raw, raw.size - n, out, 32 - n, n)
        return out
    }

    private fun address(s: String?): ByteArray? {
        val b = hexBytes(s) ?: return null
        return if (b.size == 20) b else null
    }

    private fun fixedBytes(s: String?, n: String): ByteArray? {
        val size = n.toIntOrNull() ?: return null
        if (size !in 1..32) return null
        val b = hexBytes(s) ?: return null
        if (b.size != size) return null
        val out = ByteArray(32)
        System.arraycopy(b, 0, out, 0, size)
        return out
    }

    private fun integer(v: Any, bits: String, signed: Boolean): BigInteger? {
        val width = if (bits.isEmpty()) 256 else bits.toIntOrNull() ?: return null
        if (width !in 8..256 || width % 8 != 0) return null
        val x = bigOf(v) ?: return null
        return if (signed) {
            val lo = BigInteger.ONE.shiftLeft(width - 1).negate()
            val hi = BigInteger.ONE.shiftLeft(width - 1)
            if (x < lo || x >= hi) null else x
        } else {
            if (x.signum() < 0 || x.bitLength() > width) null else x
        }
    }

    /** Integer from a JSON number or string: decimal, or hex with a `0x` prefix. */
    private fun bigOf(v: Any): BigInteger? = try {
        when (v) {
            is Int -> BigInteger.valueOf(v.toLong())
            is Long -> BigInteger.valueOf(v)
            is Double -> BigDecimal(v.toString()).toBigIntegerExact()
            is String -> {
                val t = v.trim()
                if (t.startsWith("0x") || t.startsWith("0X")) BigInteger(t.substring(2), 16) else BigInteger(t)
            }
            else -> null
        }
    } catch (e: Exception) {
        null
    }

    /** Bytes from a `0x`-prefixed even-length hex string, or `null`. */
    private fun hexBytes(s: String?): ByteArray? {
        if (s == null || !(s.startsWith("0x") || s.startsWith("0X"))) return null
        val h = s.substring(2)
        if (h.length % 2 != 0 || !h.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) return null
        return ByteArray(h.length / 2) { i -> h.substring(i * 2, i * 2 + 2).toInt(16).toByte() }
    }
}
