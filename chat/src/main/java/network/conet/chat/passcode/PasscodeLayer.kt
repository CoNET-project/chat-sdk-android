package network.conet.chat.passcode

import java.security.SecureRandom
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * The passcode layer of a native record (frozen shell passcode protocol v1, sections 7–8; iOS appendix parity).
 * Key: PBKDF2-HMAC-SHA256, 600 000 rounds, 32 bytes ([PasscodeKdf]), from a 16-byte random salt that is new for every write.
 * AEAD: AES-256-GCM, 96-bit IV, 128-bit tag. Stored form: IV(12) || ciphertext || tag(16). The inner (hardware) layer is applied by the caller.
 * AAD binds the record to its account and its kind: `beamio-native-wallet-v1|p|<eoa>|v1` (account key), `beamio-native-wallet-v1|m|<eoa>|v1` (phrase).
 */
object PasscodeLayer {
    const val SALT_BYTES = 16
    const val IV_BYTES = 12
    const val TAG_BITS = 128
    private const val MIN_BLOB = IV_BYTES + TAG_BITS / 8

    private val random = SecureRandom()

    fun aadForAccountKey(eoa: String): ByteArray = "beamio-native-wallet-v1|p|${eoa.lowercase()}|v1".toByteArray(Charsets.UTF_8)

    fun aadForPhrase(eoa: String): ByteArray = "beamio-native-wallet-v1|m|${eoa.lowercase()}|v1".toByteArray(Charsets.UTF_8)

    /** A new random salt. Every write uses a new one. */
    fun newSalt(): ByteArray = ByteArray(SALT_BYTES).also { random.nextBytes(it) }

    /** Seals [inner] under [passcode]. Returns IV || ciphertext || tag. The derived key is zeroed before returning. */
    fun seal(passcode: String, salt: ByteArray, aad: ByteArray, inner: ByteArray): ByteArray {
        require(salt.size == SALT_BYTES) { "salt must be $SALT_BYTES bytes" }
        val key = PasscodeKdf.derive(passcode, salt)
        try {
            val iv = ByteArray(IV_BYTES).also { random.nextBytes(it) }
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_BITS, iv))
            cipher.updateAAD(aad)
            return iv + cipher.doFinal(inner)
        } finally {
            key.fill(0)
        }
    }

    /**
     * Opens a blob with [passcode]. Null means the blob did not open: a wrong passcode, a wrong account (AAD), or a tampered blob.
     * A wrong passcode is never distinguishable from a tampered blob here; the caller counts nothing on the native side (protocol 3.2).
     */
    fun open(passcode: String, salt: ByteArray, aad: ByteArray, blob: ByteArray): ByteArray? {
        if (salt.size != SALT_BYTES || blob.size < MIN_BLOB) return null
        val key = PasscodeKdf.derive(passcode, salt)
        try {
            val iv = blob.copyOfRange(0, IV_BYTES)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_BITS, iv))
            cipher.updateAAD(aad)
            return try {
                cipher.doFinal(blob, IV_BYTES, blob.size - IV_BYTES)
            } catch (_: AEADBadTagException) {
                null
            }
        } finally {
            key.fill(0)
        }
    }
}
