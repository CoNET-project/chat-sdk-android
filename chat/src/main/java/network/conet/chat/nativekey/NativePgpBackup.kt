package network.conet.chat.nativekey

import network.conet.chat.ConetChatCryptoUtil
import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Restores the PGP key of an account from the PWA's encrypted backup (P-IMP-PGP option A, spec 25.25.8). The format is
 * the one the PWA writes with `aesGcmEncrypt` (chat.ts:758–766): key = SHA-256(UTF-8 of the account's private-key string,
 * "0x" + 64 lower-case hex); AES-256-GCM, 12-byte IV, 16-byte tag, no additional data; the blob is base64(iv ‖ ct ‖ tag),
 * standard alphabet, padded, no whitespace. The vector file is `pgp-backup-compat-vectors.v1.json`.
 *
 * Everything runs in native code. The wallet key is read for one call and zeroed. The armor goes into the PGP vault and is
 * never returned to a caller. The decode is strict on purpose: divergence D-2 (the PWA accepts whitespace, this does not).
 */
internal object NativePgpBackup {
    private const val IV_BYTES = 12
    private const val TAG_BYTES = 16

    /** The PWA's `acc.signingKey.privateKey` string: "0x" + 64 lower-case hex. */
    fun passwordString(privateKey: ByteArray): String =
        "0x" + privateKey.joinToString("") { "%02x".format(it.toInt() and 0xFF) }

    /**
     * Strict base64: standard alphabet, padded to a multiple of four, '=' only at the end, no whitespace and no other
     * characters. Returns null on any other input. (The SDK's `ConetChatCryptoUtil.base64Decode` is lenient and is not used.)
     */
    internal fun strictBase64(text: String): ByteArray? {
        if (text.isEmpty() || text.length % 4 != 0) return null
        val out = ByteArrayOutputStream(text.length / 4 * 3)
        var i = 0
        while (i < text.length) {
            val c0 = value(text[i])
            val c1 = value(text[i + 1])
            val last = i + 4 == text.length
            val pad2 = text[i + 2] == '='
            val pad3 = text[i + 3] == '='
            if (c0 < 0 || c1 < 0) return null
            if ((pad2 || pad3) && !last) return null
            if (pad2 && !pad3) return null
            val c2 = if (pad2) 0 else value(text[i + 2])
            val c3 = if (pad3) 0 else value(text[i + 3])
            if (c2 < 0 || c3 < 0) return null
            out.write((c0 shl 2) or (c1 shr 4))
            if (!pad2) out.write(((c1 and 0x0F) shl 4) or (c2 shr 2))
            if (!pad3) out.write(((c2 and 0x03) shl 6) or c3)
            i += 4
        }
        return out.toByteArray()
    }

    private fun value(ch: Char): Int = when (ch) {
        in 'A'..'Z' -> ch - 'A'
        in 'a'..'z' -> ch - 'a' + 26
        in '0'..'9' -> ch - '0' + 52
        '+' -> 62
        '/' -> 63
        else -> -1
    }

    /**
     * Encrypts [armor] (UTF-8 bytes) under the key derived from [passwordString], with the given 12-byte [iv]. Returns the
     * backup text base64(iv ‖ ct ‖ tag), standard alphabet, padded, no whitespace: the format [decryptArmor] reads. The IV
     * must be random in production; the acceptance vectors pass a fixed one.
     */
    fun encryptArmor(passwordString: String, armor: ByteArray, iv: ByteArray): String {
        require(iv.size == IV_BYTES) { "iv must be 12 bytes" }
        val key = MessageDigest.getInstance("SHA-256").digest(passwordString.toByteArray(Charsets.UTF_8))
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
            val sealed = cipher.doFinal(armor)
            return ConetChatCryptoUtil.base64Encode(iv + sealed)
        } finally {
            key.fill(0)
        }
    }

    /**
     * Decrypts [backupBase64] with the key derived from [passwordString]. Returns the armor bytes (UTF-8), or null when
     * the input is malformed, truncated, or the tag does not verify. Pure: no vault access.
     */
    fun decryptArmor(passwordString: String, backupBase64: String): ByteArray? {
        val raw = strictBase64(backupBase64) ?: return null
        if (raw.size < IV_BYTES + TAG_BYTES) return null
        val key = MessageDigest.getInstance("SHA-256").digest(passwordString.toByteArray(Charsets.UTF_8))
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, raw.copyOfRange(0, IV_BYTES)))
            cipher.doFinal(raw.copyOfRange(IV_BYTES, raw.size))
        } catch (_: Exception) {
            null
        } finally {
            key.fill(0)
        }
    }

    /** The first subkey's 64-bit key ID, upper-case hex: the PWA's `subkeyKeyID` (`getKeyIDs()[1]`, chat.ts:43 reading). */
    @Suppress("DEPRECATION")
    fun subkeyKeyId(secret: NativePgp.Secret): String? {
        val sub = secret.ring.secretKeys.asSequence().drop(1).firstOrNull() ?: return null
        return "%016X".format(sub.keyID)
    }
}
