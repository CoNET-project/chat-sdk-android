package network.conet.chat.nativekey

import network.conet.chat.BeamioConetChatCallSignal
import org.json.JSONObject
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets

/**
 * `pgpDecryptInbound` (spec 25.34, A1): decrypt an OpenPGP message to this account's PGP key inside the native layer, and
 * return the plaintext with its call signal. The plaintext crosses the bridge only in the ack; nothing is cached, stored
 * or logged here. The module checks `reqId` and the no-key gate first (25.26.4c); [answer] does the rest in the spec's order.
 */
internal object PgpDecryptInbound {
    /** Upper bound for `armoredMessage`, UTF-8 bytes (25.34.2). The default is the interface owner's; PM to confirm. */
    const val MAX_ARMOR_BYTES = 65536

    private val TOP_LEVEL = setOf("type", "reqId", "accountKey", "armoredMessage")

    /**
     * Forbidden key names (25.34.2): the list in the spec, plus the identity names of 25.19.2 that the contract already
     * refuses. Matched case-insensitively at any depth. Only the name is ever reported.
     */
    private val FORBIDDEN = setOf(
        "privateKeyHex", "privateKeyArmored", "privateKeyArmor", "pgpPrivateKeyArmored",
        "pgpPassphrase", "walletPrivateKey", "mnemonic",
    ).map { it.lowercase() }.toSet()

    /** What the module needs from the account's PGP record. */
    interface Source {
        /** The account's encryption subkey key ID as 16 hex digits, or null when there is no ready PGP record. */
        fun subkeyKeyIdHex(): String?

        /** Decrypts with the record's key (the vault's own refusals included). */
        fun decryptLiteral(armoredMessage: String): NativePgp.LiteralResult
    }

    /** The reply: an ack `result` object, or an ack error code. */
    class Answer private constructor(val result: JSONObject?, val error: String?) {
        val ok: Boolean get() = error == null

        companion object {
            fun ok(result: JSONObject) = Answer(result, null)
            fun fail(code: String) = Answer(null, code)
        }
    }

    /**
     * The refusal for the gate (25.34.4), or null when the call may read its payload. G0 is `no_key`, G1 is `not_ready`,
     * and a locked record in G2 is `locked`. None of them reads `armoredMessage`.
     */
    fun gateRefusal(gate: NoKeyGate.Gate, locked: Boolean): String? = when {
        gate == NoKeyGate.Gate.G0 -> "no_key"
        locked -> "locked"
        gate == NoKeyGate.Gate.G1 -> "not_ready"
        else -> null
    }

    /**
     * `reqId` as the ack echoes it: a string, or a non-negative JSON integer. Anything else is null (25.28.3). A-01 uses a
     * string; A-16 uses an object, which gives null and `bad_request`.
     */
    /** The reqId when it is valid (25.52AW.1: a string of 1 to 64 printable ASCII, or an integer 0 to 2^53-1), else null. */
    fun reqIdOf(body: JSONObject): Any? = body.opt("reqId")?.takeIf { ShellRecordPolicy.reqIdValid(it) }

    /** The first forbidden key name found at any depth, or null. */
    internal fun forbiddenKey(node: Any?): String? = when (node) {
        is JSONObject -> node.keys().asSequence().map { it.toString() }.firstNotNullOfOrNull { k ->
            if (k.lowercase() in FORBIDDEN) k else forbiddenKey(node.opt(k))
        }
        is org.json.JSONArray -> (0 until node.length()).asSequence().firstNotNullOfOrNull { forbiddenKey(node.opt(it)) }
        else -> null
    }

    /** Runs the spec's order after the gate. [unlockedEoa] is the account the native wallet has unlocked. */
    fun answer(body: JSONObject, unlockedEoa: String, source: Source): Answer {
        // Step 1: forbidden key material is refused before anything else is read (A-12).
        if (forbiddenKey(body) != null) return Answer.fail("key_over_bridge_refused")
        // Structure and types: unknown top-level fields and wrong types are bad_request (A-15).
        if (body.keys().asSequence().any { it !in TOP_LEVEL }) return Answer.fail("bad_request")
        val accountKey = body.opt("accountKey") as? String ?: return Answer.fail("bad_request")
        val armor = body.opt("armoredMessage") as? String ?: return Answer.fail("bad_request")
        // Length is judged before any armor parsing (A-13).
        if (armor.toByteArray(StandardCharsets.UTF_8).size > MAX_ARMOR_BYTES) return Answer.fail("payload_too_large")
        // accountKey is `eoa:workspace` (D5). Only the EOA is checked against the unlocked account here (A-14).
        if (!accountMatches(accountKey, unlockedEoa)) return Answer.fail("account_mismatch")
        // OpenPGP encrypted message with an integrity-protected packet (A-09, A-10).
        val recipients = NativePgp.recipientKeyIds(armor) ?: return Answer.fail("not_openpgp_message")
        // Recipient: at least one non-anonymous key ID must be this account's subkey, checked before decrypt (A-11).
        val subkey = source.subkeyKeyIdHex()?.uppercase() ?: return Answer.fail("not_ready")
        if (recipients.none { it != 0L && hex16(it) == subkey }) return Answer.fail("recipient_mismatch")
        // Decrypt with the record's key.
        val literal = source.decryptLiteral(armor)
        if (!literal.ok) return Answer.fail(decryptCode(literal.code))
        val bytes = literal.bytes ?: return Answer.fail("decrypt_failed")
        // Plaintext: a binary literal must be valid UTF-8. Text literals were already CRLF-normalised by the reader.
        val text = if (literal.format == 'b'.code) {
            strictUtf8(bytes) ?: return Answer.fail("plaintext_not_utf8")
        } else {
            String(bytes, StandardCharsets.UTF_8)
        }
        // Classify with the same rules as the Android call-signal reader. No signal is not an error.
        val signal = BeamioConetChatCallSignal.classify(text)
        val signalJson: Any = if (signal == null) {
            JSONObject.NULL
        } else {
            JSONObject()
                .put("kind", signal.kind)
                .put("type", signal.type)
                .put("callId", signal.callId)
                .put("sessionId", signal.sessionId)
                .also { if (signal.rejectReason != null) it.put("rejectReason", signal.rejectReason) }
        }
        return Answer.ok(JSONObject().put("plaintext", text).put("signal", signalJson))
    }

    private fun accountMatches(accountKey: String, unlockedEoa: String): Boolean {
        val cut = accountKey.lastIndexOf(':')
        if (cut <= 0 || cut == accountKey.length - 1) return false
        return accountKey.substring(0, cut).equals(unlockedEoa, ignoreCase = true)
    }

    /** Vault and literal refusals mapped to the spec's codes (25.34.3). */
    private fun decryptCode(code: String): String = when (code) {
        "pgp_locked" -> "locked"
        "no_pgp_key" -> "not_ready"
        "bad_message" -> "not_openpgp_message"
        "not_recipient" -> "recipient_mismatch"
        else -> "decrypt_failed"
    }

    private fun hex16(keyId: Long): String = String.format("%016X", keyId)

    private fun strictUtf8(bytes: ByteArray): String? = try {
        StandardCharsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(bytes))
            .toString()
    } catch (_: Exception) {
        null
    }
}
