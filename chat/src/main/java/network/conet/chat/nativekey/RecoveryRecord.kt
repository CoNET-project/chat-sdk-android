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

    /** The PWA's Argon2id parameters for a new record (`defaultBrowserParams`): 32 MiB, 3 passes, 1 lane, 32-byte output, 16-byte salt. */
    const val SEAL_M_KB = 32 * 1024
    const val SEAL_T = 3
    const val SEAL_P = 1
    const val SEAL_SALT_BYTES = 16

    /** A fresh `stored` (random salt) and the key Argon2id derives from [password] with it. The caller zeroes the key. */
    fun newStored(
        password: ByteArray,
        random: java.security.SecureRandom,
        kdf: (ByteArray, Stored) -> ByteArray = { p, st -> argon2idKey(p, st) },
    ): Pair<Stored, ByteArray> {
        val stored = Stored(SEAL_M_KB, SEAL_T, SEAL_P, ByteArray(SEAL_SALT_BYTES).also { random.nextBytes(it) })
        return stored to kdf(password, stored)
    }

    /**
     * Seals [phrase] (the UTF-8 bytes of the BIP-39 phrase) under [key], as `createRecover` does: the plaintext is the base64 of the phrase, the
     * ciphertext is AES-256-GCM, and the result is base64 of `iv(12) || ciphertext || tag(16)`. [iv] is a fresh random 12 bytes.
     */
    fun seal(key: ByteArray, phrase: ByteArray, iv: ByteArray): String {
        require(key.size == 32 && iv.size == 12)
        val inner = Base64.getEncoder().encodeToString(phrase).toByteArray(Charsets.UTF_8)
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
            return Base64.getEncoder().encodeToString(iv + cipher.doFinal(inner))
        } finally {
            inner.fill(0)
        }
    }

    /**
     * The record text the registry holds: base64 of `{stored, img}`. [storedHashKey] is the key Argon2id derived from the record's own password
     * (the PWA stores it as `hash`); the `stored` fields are the ones [parse] checks.
     */
    fun record(stored: Stored, storedHashKey: ByteArray, imgBase64: String): String {
        val s = JSONObject()
            .put("algo", "argon2id").put("v", 19).put("m", stored.m).put("t", stored.t).put("p", stored.p)
            .put("salt", Base64.getEncoder().encodeToString(stored.salt))
            .put("hash", Base64.getEncoder().encodeToString(storedHashKey))
        val json = JSONObject().put("stored", s).put("img", imgBase64)
        return Base64.getEncoder().encodeToString(json.toString().toByteArray(Charsets.UTF_8))
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
