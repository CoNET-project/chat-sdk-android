package network.conet.chat.nativekey

import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import org.json.JSONObject
import java.util.Base64
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * The recovery record (spec §25.42.5 steps 5 to 7; §25.26.4e.3): base64 of `{stored, img}`, as the PWA writes it
 * (`createRecover`) and reads it (`restoreWithRedeem`, `restoreWithUserPin`). `stored` holds the algorithm, version, Argon2id
 * parameters, the salt and the PIN hash (the hash is not used to restore). `img` is base64 of `iv(12) || ciphertext || tag(16)`.
 * The key is Argon2id(password, salt, m, t, p, 32 bytes). The plaintext is the base64 of the BIP-39 phrase. Nothing here
 * logs its input or output.
 *
 * ARGON2-DEP (§25.42.11): the Argon2id provider is a fixed choice. [argon2idKey] is the only place that names it.
 * It is BouncyCastle, which the build already carries (bcprov 1.87). Its output matches the PWA's @noble/hashes on the
 * synthetic vectors.
 */
internal object RecoveryRecord {
    /**
     * Bounds on the stored Argon2id parameters (spec §25.47.6, r3ab), so a damaged record cannot ask for unbounded memory
     * or time: 8192 <= m <= 65536 KB (the same 8 MiB floor as the X-19 wrapper), 1 <= t <= 10, 1 <= p <= 4, m >= 8p;
     * the output is 32 bytes and v must be 19. Checked before any decryption: a record outside these is `record_invalid`.
     */
    const val MIN_M_KB = 8_192
    const val MAX_M_KB = 65_536
    const val MAX_T = 10
    const val MAX_P = 4

    class Stored(val m: Int, val t: Int, val p: Int, val salt: ByteArray)

    class Parsed(val stored: Stored, val imgBase64: String)

    /** Opening outcome: the phrase's UTF-8 bytes, a wrong password (the GCM tag does not verify), or a malformed record. */
    sealed class Opened {
        class Ok(val phrase: ByteArray) : Opened()
        object WrongPassword : Opened()
        object Malformed : Opened()
    }

    /** Parses base64(JSON {stored, img}). `null` when a required part is missing, out of range, or not decodable. */
    fun parse(recordBase64: String): Parsed? {
        return try {
            val json = JSONObject(String(Base64.getDecoder().decode(recordBase64.trim()), Charsets.UTF_8))
            val s = json.getJSONObject("stored")
            val fieldsOk = s.optString("algo") == "argon2id" && s.optInt("v") == 19 &&
                s.optString("hash").isNotEmpty()
            val inRange = s.getInt("m") in MIN_M_KB..MAX_M_KB && s.getInt("t") in 1..MAX_T && s.getInt("p") in 1..MAX_P &&
                s.getInt("m") >= 8 * s.getInt("p")
            val salt = Base64.getDecoder().decode(s.getString("salt"))
            val img = json.getString("img")
            if (!fieldsOk || !inRange || salt.isEmpty() || img.isEmpty()) {
                null
            } else {
                Parsed(Stored(s.getInt("m"), s.getInt("t"), s.getInt("p"), salt), img)
            }
        } catch (_: Exception) {
            null
        }
    }

    /** Argon2id (RFC 9106, version 0x13), 32-byte output. ARGON2-DEP: the provider is pending the project's selection. */
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

    /** Opens `img` with the key derived from [password] (UTF-8 bytes). The caller zeroes the returned phrase. */
    fun open(
        stored: Stored,
        imgBase64: String,
        password: ByteArray,
        kdf: (ByteArray, Stored) -> ByteArray = { p, s -> argon2idKey(p, s) },
    ): Opened {
        val combined = try {
            Base64.getDecoder().decode(imgBase64)
        } catch (_: IllegalArgumentException) {
            return Opened.Malformed
        }
        if (combined.size < 12 + 16) return Opened.Malformed
        // The KDF is a parameter only so the tests can count its calls (§25.47.9). Production passes the default.
        val key = kdf(password, stored)
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, combined.copyOfRange(0, 12)))
            val inner = cipher.doFinal(combined, 12, combined.size - 12)
            // Inner layer: the phrase is stored as base64 of its UTF-8 bytes (createRecover: toBase64(phrase)).
            return try {
                Opened.Ok(Base64.getDecoder().decode(inner))
            } catch (_: IllegalArgumentException) {
                Opened.Malformed
            }
        } catch (_: AEADBadTagException) {
            return Opened.WrongPassword
        } catch (_: Exception) {
            return Opened.Malformed
        } finally {
            key.fill(0)
        }
    }
}

/**
 * The recovery code shape (§25.42.4, §25.26.4e.3 step 2): 22 characters of `[0-9A-Za-z]`, after trimming leading and
 * trailing ASCII whitespace. This is the shape `uuid62.v4()` produces. The check is on the shape only.
 */
internal object RecoveryCode {
    private const val LENGTH = 22

    /** The normalised code bytes, or `null` when the input is not a code. The result is a new array. */
    fun normalize(raw: ByteArray): ByteArray? {
        var start = 0
        var end = raw.size
        while (start < end && isAsciiSpace(raw[start])) start++
        while (end > start && isAsciiSpace(raw[end - 1])) end--
        if (end - start != LENGTH) return null
        for (i in start until end) {
            val c = raw[i].toInt().toChar()
            val ok = c in '0'..'9' || c in 'a'..'z' || c in 'A'..'Z'
            if (!ok) return null
        }
        return raw.copyOfRange(start, end)
    }

    /** ASCII whitespace: space, tab, LF, VT, FF, CR. */
    fun isAsciiSpace(b: Byte): Boolean = b == 0x20.toByte() || (b in 0x09..0x0D)
}
