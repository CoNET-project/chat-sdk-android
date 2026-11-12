package network.conet.chat.nativekey

import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.util.regex.Pattern

/** Result of a native wallet command. [code] is `ok` or a refusal code; no key material is ever in it. */
data class NativeOutcome(val code: String, val value: String? = null, val address: String? = null)

/**
 * Native signing for the chat SDK (spec 25.23, C2 `gossipSign` and W5 `signMessage` for the kinds in use).
 *
 * - The signed bytes are the caller's UTF-8 bytes, EIP-191, with no prefix, no re-serialisation and no
 *   normalisation (25.23.1).
 * - `gossip` accepts only the `gossip_delivery_ack` shape, checked in the order of the reference
 *   generator. `envelope` and `group` refuse that shape (25.23.2, `cross_purpose`).
 * - Kinds outside {gossip, envelope, group} are refused with `kind`.
 * - Without a native key the answer is `no_key`; with a record that cannot be unlocked, `locked`.
 */
object NativeMessageSigner {
    const val KIND_GOSSIP = "gossip"
    const val KIND_ENVELOPE = "envelope"
    const val KIND_GROUP = "group"
    val KINDS: Set<String> = setOf(KIND_GOSSIP, KIND_ENVELOPE, KIND_GROUP)

    const val ACK_COMMAND = "gossip_delivery_ack"
    const val MAX_GOSSIP_BYTES = 2048
    private val ACK_KEYS = setOf("command", "walletAddress", "armorHash", "timestamp", "sendId")
    private val ARMOR_HASH = Pattern.compile("^0x[0-9a-f]{64}$")
    private const val TS_MIN = 1_000_000_000L
    private const val TS_MAX = 9_999_999_999L

    fun sign(vault: NativeWalletVault, kind: String, message: ByteArray): NativeOutcome {
        val state = vault.state()
        if (state is NativeWalletVault.State.NoKey) return NativeOutcome("no_key")
        if (state is NativeWalletVault.State.Locked) return NativeOutcome("locked")
        if (kind !in KINDS) return NativeOutcome("kind")
        val key = vault.unlock() ?: return NativeOutcome("locked")
        try {
            val eoa = WalletAddress.fromPrivateKey(key) ?: return NativeOutcome("locked")
            val gate = check(kind, message, eoa)
            if (gate != null) return NativeOutcome(gate)
            val signature = Eip191Signer.sign(key, message) ?: return NativeOutcome("locked")
            return NativeOutcome("ok", value = signature, address = eoa)
        } finally {
            key.fill(0)
        }
    }

    /** `null` when the bytes may be signed for [kind], otherwise the refusal code. */
    fun check(kind: String, message: ByteArray, eoa: String): String? {
        if (kind !in KINDS) return "kind"
        if (kind == KIND_GOSSIP) return checkGossipAck(message, eoa)
        // envelope and group: refuse text that is shaped like a delivery ack (even an incomplete one).
        val parsed = try {
            StrictJson.parse(decodeUtf8(message) ?: return null, rejectTopLevelDuplicates = false)
        } catch (e: StrictJson.Invalid) {
            return null
        }
        if (parsed is Map<*, *> && parsed["command"] == ACK_COMMAND) return "cross_purpose"
        return null
    }

    /** Reference order: size, JSON, object, duplicate keys, unknown keys, command, walletAddress, armorHash, timestamp, sendId. */
    private fun checkGossipAck(message: ByteArray, eoa: String): String? {
        if (message.size > MAX_GOSSIP_BYTES) return "too_long"
        val text = decodeUtf8(message) ?: return "not_json"
        val parsed = try {
            StrictJson.parse(text, rejectTopLevelDuplicates = true)
        } catch (e: StrictJson.DuplicateKey) {
            return "duplicate_key"
        } catch (e: StrictJson.Invalid) {
            return "not_json"
        }
        if (parsed !is Map<*, *>) return "not_object"
        if (parsed.keys.any { it !in ACK_KEYS }) return "unknown_key"
        if (parsed["command"] != ACK_COMMAND) return "command"
        val wallet = parsed["walletAddress"]
        if (wallet !is String || wallet.lowercase() != eoa.lowercase()) return "wallet_mismatch"
        val armor = parsed["armorHash"]
        if (armor !is String || !ARMOR_HASH.matcher(armor).matches()) return "armor_hash"
        val ts = parsed["timestamp"]
        if (ts !is StrictJson.Num || !isIntegerIn(ts.value, TS_MIN, TS_MAX)) return "timestamp"
        if (parsed.containsKey("sendId")) {
            val sendId = parsed["sendId"]
            if (sendId !is String || sendId.isEmpty()) return "send_id"
        }
        return null
    }

    private fun isIntegerIn(v: java.math.BigDecimal, min: Long, max: Long): Boolean {
        val stripped = v.stripTrailingZeros()
        if (stripped.scale() > 0) return false
        return v >= java.math.BigDecimal(min) && v <= java.math.BigDecimal(max)
    }

    private fun decodeUtf8(bytes: ByteArray): String? {
        val decoder = Charsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
        return try {
            decoder.decode(ByteBuffer.wrap(bytes)).toString()
        } catch (e: java.nio.charset.CharacterCodingException) {
            null
        }
    }
}
