package network.conet.chat.nativekey

import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import org.json.JSONObject
import java.math.BigInteger
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * The recovery-code record (spec 25.26.4e.3, path A), in the layout the PWA writes (`createRecover`) and reads
 * (`restoreWithRedeem`): base64 of `{stored, img}`. `stored` holds Argon2id parameters and a salt; `img` is base64 of
 * `iv(12) || AES-GCM ciphertext+tag`, whose key is Argon2id(password = recovery code, salt, m, t, p, 32 bytes). The
 * plaintext is the base64 of the BIP-39 phrase. Nothing here logs its input or output.
 */
internal object RecoveryRecord {
    /** Upper bounds, so a hostile or damaged record cannot ask for unbounded memory or time. */
    const val MAX_M_KB = 65_536
    const val MAX_T = 10
    const val MAX_P = 4

    class Stored(val m: Int, val t: Int, val p: Int, val salt: ByteArray)

    class Parsed(val stored: Stored, val imgBase64: String)

    /** Parses base64(JSON {stored, img}). `null` when any part is missing, out of range, or not decodable. */
    fun parse(recordBase64: String): Parsed? {
        return try {
            val json = JSONObject(String(Base64.getDecoder().decode(recordBase64.trim()), Charsets.UTF_8))
            val s = json.getJSONObject("stored")
            val inRange = s.optString("algo") == "argon2id" && s.optInt("v") == 19 &&
                s.getInt("m") in 8..MAX_M_KB && s.getInt("t") in 1..MAX_T && s.getInt("p") in 1..MAX_P
            val salt = Base64.getDecoder().decode(s.getString("salt"))
            val img = json.getString("img")
            if (!inRange || salt.isEmpty() || img.isEmpty()) {
                null
            } else {
                Parsed(Stored(s.getInt("m"), s.getInt("t"), s.getInt("p"), salt), img)
            }
        } catch (_: Exception) {
            null
        }
    }

    /** Argon2id (RFC 9106, version 0x13) with a 32-byte output: the key the PWA derives with @noble/hashes. */
    fun argon2idKey(password: ByteArray, stored: Stored): ByteArray {
        val params = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withVersion(Argon2Parameters.ARGON2_VERSION_13)
            .withIterations(stored.t)
            .withMemoryAsKB(stored.m)
            .withParallelism(stored.p)
            .withSalt(stored.salt)
            .build()
        val gen = Argon2BytesGenerator()
        gen.init(params)
        val out = ByteArray(32)
        gen.generateBytes(password, out)
        return out
    }

    /**
     * Opens `img` with the key from [password]. Returns the phrase's UTF-8 bytes, or `null` for a wrong password, a
     * tampered record, or a malformed inner layer. The caller zeroes the result.
     */
    fun decryptMnemonic(stored: Stored, imgBase64: String, password: ByteArray): ByteArray? {
        val combined = try {
            Base64.getDecoder().decode(imgBase64)
        } catch (_: IllegalArgumentException) {
            return null
        }
        if (combined.size < 12 + 16) return null
        val key = argon2idKey(password, stored)
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, combined.copyOfRange(0, 12)))
            val inner = cipher.doFinal(combined, 12, combined.size - 12)
            // Inner layer: the phrase is stored as the base64 of its UTF-8 bytes (createRecover: toBase64(phrase)).
            return Base64.getDecoder().decode(inner)
        } catch (_: Exception) {
            return null
        } finally {
            key.fill(0)
        }
    }
}

/** The recovery code format (25.26.4e.3 step 2): what `uuid62.v4()` produces, 22 base62 characters, at most 128 bits. */
internal object RecoveryCode {
    private const val ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    private const val LENGTH = 22

    fun isValid(code: ByteArray): Boolean {
        if (code.size != LENGTH) return false
        var value = BigInteger.ZERO
        for (b in code) {
            val i = ALPHABET.indexOf(b.toInt().toChar())
            if (i < 0) return false
            value = value.multiply(BigInteger.valueOf(62)).add(BigInteger.valueOf(i.toLong()))
        }
        return value.bitLength() <= 128
    }
}
