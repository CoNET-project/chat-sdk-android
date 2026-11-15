package network.conet.chat.nativekey

import network.conet.chat.ConetChatCryptoUtil
import org.json.JSONObject

/**
 * W5 `chatRouteRegister` (spec 25.28.3, 25.28.4, 25.28.5; the vectors chat-route-register-vectors.v1.json, PV-1 to PV-4). The native side builds
 * the eight-line registration message, seals the PGP private armor under the EOA key (the backup format), and signs the message with EIP-191.
 * The page never supplies the message, the wallet, the timestamp, the nonce, the signature, or any key field.
 *
 * This core is pure: the timestamp, the nonce and the backup IV are inputs, so the vectors can be checked byte for byte. The bridge path
 * supplies the live values (a millisecond clock, 16 random bytes, a random 12-byte IV) and reads the vault.
 */
object ChatRouteRegister {
    const val DOMAIN = "Beamio regiestChatRoute"
    const val BAD_REQUEST = "bad_request"
    const val NO_PGP_KEY = "no_pgp_key"
    const val SIG_REJECTED = "sig_rejected"

    /** The request fields that the page may send (spec 25.28.3). */
    private val REQUEST_FIELDS = setOf("type", "reqId", "keyID", "publicKeyArmored", "routeKeyID")

    /** Fields the page may not send; each one is bad_request (spec 25.28.3). */
    private val FORBIDDEN_FIELDS = setOf(
        "wallet", "message", "signature", "timestamp", "nonce", "encrypKeyArmored", "privateKeyHex", "pgpPrivateArmorSha256",
        "pgpPrivateArmored", "pgpPrivateKeyArmored",
    )

    /** The page's request, validated: the three string fields, trimmed. */
    class Request(val keyID: String, val publicKeyArmored: String, val routeKeyID: String)

    sealed class Parsed {
        class Ok(val request: Request) : Parsed()
        class Refused(val code: String) : Parsed()
    }

    /** The result of a build: the fields of the ack `result` (spec 25.28.3), or the refusal code. */
    sealed class Built {
        class Ok(
            val wallet: String,
            val keyID: String,
            val publicKeyArmored: String,
            val encrypKeyArmored: String,
            val routeKeyID: String,
            val timestamp: Long,
            val nonce: String,
            val signature: String,
            val message: String,
        ) : Built()

        class Refused(val code: String) : Built()
    }

    /** Validates the page's request shape before any state is read (spec 25.28.3 禁止字段, 25.28.4 字段规则). */
    fun parse(body: JSONObject): Parsed {
        val keys = body.keys().asSequence().map { it.toString() }.toSet()
        if (keys.any { it in FORBIDDEN_FIELDS }) return Parsed.Refused(BAD_REQUEST)
        if (keys.any { it !in REQUEST_FIELDS }) return Parsed.Refused(BAD_REQUEST)
        val rawKeyID = body.opt("keyID") as? String ?: return Parsed.Refused(BAD_REQUEST)
        val rawRouteKeyID = body.opt("routeKeyID") as? String ?: return Parsed.Refused(BAD_REQUEST)
        // keyID and routeKeyID may not contain CR or LF, checked on the value as sent: a trailing CR is refused, not trimmed away (spec 25.28.4; NR-10).
        if (rawKeyID.any { it == '\r' || it == '\n' } || rawRouteKeyID.any { it == '\r' || it == '\n' }) return Parsed.Refused(BAD_REQUEST)
        val keyID = rawKeyID.trim()
        val routeKeyID = rawRouteKeyID.trim()
        // keyID: 16 upper-case hex digits (spec 25.28.3).
        if (!Regex("^[0-9A-F]{16}$").matches(keyID)) return Parsed.Refused(BAD_REQUEST)
        if (routeKeyID.isEmpty()) return Parsed.Refused(BAD_REQUEST)
        val publicKeyArmored = stringField(body, "publicKeyArmored") ?: return Parsed.Refused(BAD_REQUEST)
        // publicKeyArmored: the strict base64 text of the armor (spec 25.28.3).
        if (NativePgpBackup.strictBase64(publicKeyArmored) == null) return Parsed.Refused(BAD_REQUEST)
        return Parsed.Ok(Request(keyID, publicKeyArmored, routeKeyID))
    }

    private fun stringField(body: JSONObject, name: String): String? {
        val raw = body.opt(name) as? String ?: return null
        return raw.trim()
    }

    /**
     * Builds the registration for [wallet] (lower-case EOA) with the EOA private key bytes and the PGP private armor. [timestampMs] and
     * [nonce] (`0x` plus 32 lower-case hex digits) and the backup [iv] (12 bytes) are inputs; in production they are live values.
     */
    fun build(
        request: Request,
        wallet: String,
        eoaPrivateKey: ByteArray,
        pgpPrivateArmor: ByteArray?,
        timestampMs: Long,
        nonce: String,
        iv: ByteArray,
    ): Built {
        if (pgpPrivateArmor == null) return Built.Refused(NO_PGP_KEY)
        if (!Regex("^0x[0-9a-f]{32}$").matches(nonce) || iv.size != 12) return Built.Refused(BAD_REQUEST)
        // The page's public key must be the vault's PGP key: the primary fingerprints must match (spec 25.28.5, sig_rejected; NR-11).
        val vaultFingerprint = NativePgp.parseSecret(String(pgpPrivateArmor, Charsets.UTF_8))?.fingerprint?.lowercase()
            ?: return Built.Refused(NO_PGP_KEY)
        val publicArmor = NativePgpBackup.strictBase64(request.publicKeyArmored)?.toString(Charsets.UTF_8)
            ?: return Built.Refused(BAD_REQUEST)
        val pageFingerprint = PgpPublicIdentity.parse(publicArmor)?.fingerprint?.lowercase() ?: return Built.Refused(SIG_REJECTED)
        if (pageFingerprint != vaultFingerprint) return Built.Refused(SIG_REJECTED)
        val passwordString = NativePgpBackup.passwordString(eoaPrivateKey)
        val encrypKeyArmored = NativePgpBackup.encryptArmor(passwordString, pgpPrivateArmor, iv)
        val message = listOf(
            DOMAIN,
            "wallet:${wallet.lowercase()}",
            "keyID:${request.keyID}",
            "publicKeyArmoredHash:${ConetChatCryptoUtil.keccakUtf8Hex(request.publicKeyArmored)}",
            "encrypKeyArmoredHash:${ConetChatCryptoUtil.keccakUtf8Hex(encrypKeyArmored)}",
            "routeKeyID:${request.routeKeyID}",
            "timestamp:$timestampMs",
            "nonce:$nonce",
        ).joinToString("\n")
        val signature = Eip191Signer.sign(eoaPrivateKey, message.toByteArray(Charsets.UTF_8)) ?: return Built.Refused(SIG_REJECTED)
        return Built.Ok(
            wallet = wallet.lowercase(),
            keyID = request.keyID,
            publicKeyArmored = request.publicKeyArmored,
            encrypKeyArmored = encrypKeyArmored,
            routeKeyID = request.routeKeyID,
            timestamp = timestampMs,
            nonce = nonce,
            signature = signature,
            message = message,
        )
    }
}
