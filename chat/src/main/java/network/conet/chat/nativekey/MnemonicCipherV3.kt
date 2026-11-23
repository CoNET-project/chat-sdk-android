package network.conet.chat.nativekey

import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * The mnemonic cipher format v3 (2026-11-22): Argon2id + AES-256-GCM for a record that is protected by a
 * six-digit passcode. The envelope is `{v:3, mode:"passcode", eoa, kdf, salt, iv, alg, ct}`; salt, iv and ct are standard base64; ct is the
 * AES-GCM ciphertext with its 16-byte tag. The derived key is never stored with the ciphertext. The passcode is the UTF-8 bytes of the
 * string as given (the six-digit rule is the PWA's; this function does not apply it).
 *
 * Opening answers the closed code set of section 5: `ok`, `unlock_failed` (a wrong passcode and a failed GCM tag, which cannot be told apart),
 * `verify_failed` (version, parameters, sizes, or the derived address not matching the envelope). A version other than 3 is refused before any
 * decryption attempt.
 *
 * Known limit (accepted by the reviewer): the phrase returned by [open] and taken by [seal] is a Kotlin String, and a JVM String cannot be
 * zeroed. Copies are kept as small as the API allows: the passcode is turned into bytes only for the KDF and those bytes are zeroed at once;
 * the derived key and the decrypted plaintext bytes are zeroed when used; the phrase String is created once, held only by the caller for the
 * run, and never logged or stored by this code. A caller that needs a byte-level guarantee must keep the phrase as bytes end to end, which
 * this API does not yet do.
 */
internal object MnemonicCipherV3 {
    const val VERSION = 3
    const val MODE = "passcode"
    const val ALG = "AES-256-GCM"
    const val KDF = "argon2id/m=32768/t=3/p=1/dkLen=32"
    const val M_KIB = 32768
    const val T = 3
    const val P = 1
    const val DK_BYTES = 32
    const val SALT_BYTES = 16
    const val IV_BYTES = 12
    const val TAG_BITS = 128

    const val CODE_OK = "ok"
    const val CODE_UNLOCK_FAILED = "unlock_failed"
    const val CODE_VERIFY_FAILED = "verify_failed"

    /** The envelope fields as they are on the wire (base64 for salt, iv, ct). */
    data class Envelope(
        val v: Int,
        val mode: String,
        val eoa: String,
        val kdf: String,
        val saltB64: String,
        val ivB64: String,
        val alg: String,
        val ctB64: String,
    )

    /** The result of [open]: the code, and the phrase only when the code is [CODE_OK]. */
    class Opened(val code: String, val phrase: String? = null)

    /** The AAD of an EOA (lower case, `0x` and 40 hex). */
    fun aad(eoa: String): ByteArray = "beamio-mnemonic-cipher-v3|argon2id-aes256gcm|${eoa.lowercase()}".toByteArray(Charsets.UTF_8)

    /** A fresh random salt (16 bytes) for one record. */
    fun newSalt(random: SecureRandom = SecureRandom()): ByteArray = ByteArray(SALT_BYTES).also { random.nextBytes(it) }

    /** A fresh random IV (12 bytes) for one encryption. */
    fun newIv(random: SecureRandom = SecureRandom()): ByteArray = ByteArray(IV_BYTES).also { random.nextBytes(it) }

    /** Argon2id (RFC 9106, version 0x13) of [passcode] (UTF-8) with [salt]: 32 bytes. The caller zeroes the result. */
    fun deriveKey(passcode: String, salt: ByteArray): ByteArray {
        val params = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withVersion(Argon2Parameters.ARGON2_VERSION_13)
            .withIterations(T)
            .withMemoryAsKB(M_KIB)
            .withParallelism(P)
            .withSalt(salt)
            .build()
        val gen = Argon2BytesGenerator()
        gen.init(params)
        val pw = passcode.toByteArray(Charsets.UTF_8)
        val out = ByteArray(DK_BYTES)
        try {
            gen.generateBytes(pw, out)
        } finally {
            pw.fill(0)
        }
        return out
    }

    /**
     * Seals [phrase] for [eoa] under [passcode] with the given [salt] and [iv] (both random in production; fixed only in the test vectors).
     * Returns the envelope. The derived key is zeroed here.
     */
    fun seal(eoa: String, passcode: String, phrase: String, salt: ByteArray, iv: ByteArray): Envelope {
        require(salt.size == SALT_BYTES && iv.size == IV_BYTES) { "bad salt or iv size" }
        val key = deriveKey(passcode, salt)
        try {
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_BITS, iv))
            c.updateAAD(aad(eoa))
            val ct = c.doFinal(phrase.toByteArray(Charsets.UTF_8))
            val b64 = java.util.Base64.getEncoder()
            return Envelope(
                v = VERSION,
                mode = MODE,
                eoa = eoa.lowercase(),
                kdf = KDF,
                saltB64 = b64.encodeToString(salt),
                ivB64 = b64.encodeToString(iv),
                alg = ALG,
                ctB64 = b64.encodeToString(ct),
            )
        } finally {
            key.fill(0)
        }
    }

    /**
     * The envelope format check without decryption: version, mode, kdf and alg as fixed, base64 that decodes, and the sizes
     * of salt, iv and ct. A failure is verify_failed in the sync answer, and nothing is written.
     */
    fun formatOk(env: Envelope): Boolean {
        if (env.v != VERSION || env.mode != MODE || env.kdf != KDF || env.alg != ALG) return false
        val b64 = java.util.Base64.getDecoder()
        return try {
            val salt = b64.decode(env.saltB64)
            val iv = b64.decode(env.ivB64)
            val ct = b64.decode(env.ctB64)
            salt.size == SALT_BYTES && iv.size == IV_BYTES && ct.size >= TAG_BITS / 8
        } catch (_: IllegalArgumentException) {
            false
        }
    }

    /**
     * Opens [env] under [passcode]. Order: version, mode, kdf, alg, sizes (all `verify_failed` before any decryption); then the GCM
     * decryption with the AAD of the envelope's `eoa` (`unlock_failed` on any failure); then the derived address against that `eoa`
     * (`verify_failed` on a mismatch). Only a phrase whose address matches is returned. The caller checks that the envelope's `eoa` is the
     * account it expects.
     */
    fun open(env: Envelope, passcode: String): Opened {
        if (env.v != VERSION) return Opened(CODE_VERIFY_FAILED)
        if (env.mode != MODE || env.kdf != KDF || env.alg != ALG) return Opened(CODE_VERIFY_FAILED)
        val b64 = java.util.Base64.getDecoder()
        val salt = try { b64.decode(env.saltB64) } catch (_: IllegalArgumentException) { return Opened(CODE_VERIFY_FAILED) }
        val iv = try { b64.decode(env.ivB64) } catch (_: IllegalArgumentException) { return Opened(CODE_VERIFY_FAILED) }
        val ct = try { b64.decode(env.ctB64) } catch (_: IllegalArgumentException) { return Opened(CODE_VERIFY_FAILED) }
        if (salt.size != SALT_BYTES || iv.size != IV_BYTES || ct.size < TAG_BITS / 8) return Opened(CODE_VERIFY_FAILED)
        val key = deriveKey(passcode, salt)
        val pt: ByteArray = try {
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_BITS, iv))
            c.updateAAD(aad(env.eoa))
            c.doFinal(ct)
        } catch (_: Exception) {
            return Opened(CODE_UNLOCK_FAILED)
        } finally {
            key.fill(0)
        }
        val phrase = String(pt, Charsets.UTF_8)
        pt.fill(0)
        val derived = MnemonicDerivation.deriveKey(phrase)?.let { WalletAddress.fromPrivateKey(it) }?.lowercase()
        if (derived == null || derived != env.eoa.lowercase()) return Opened(CODE_VERIFY_FAILED)
        return Opened(CODE_OK, phrase)
    }
}
