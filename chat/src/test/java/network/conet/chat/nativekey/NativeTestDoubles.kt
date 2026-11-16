package network.conet.chat.nativekey

import java.io.IOException
import java.security.GeneralSecurityException
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Thrown to simulate the process dying at a chosen point. It is not an Exception, so no cleanup runs. */
/** The synthetic account used by the vault tests (spec test key, not a wallet). */
internal const val SYN_EOA = "0x39581c72b8c7d0de85ff22cf3ae178ae813957aa"

internal class NativeTestCrash : Error("simulated crash")

internal class NativeTestWrap : KeyWrap {
    var failSeal = false
    var opens = 0
    var openOverride: ((ByteArray) -> ByteArray)? = null
    private var secret: SecretKey = newKey()

    override fun seal(aad: ByteArray, plain: ByteArray): ByteArray {
        if (failSeal) throw IllegalStateException("keystore unavailable")
        val iv = ByteArray(12).also { SecureRandom().nextBytes(it) }
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, secret, GCMParameterSpec(128, iv))
        c.updateAAD(aad)
        return iv + c.doFinal(plain)
    }

    override fun open(aad: ByteArray, sealed: ByteArray): ByteArray? {
        opens++
        return try {
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.DECRYPT_MODE, secret, GCMParameterSpec(128, sealed.copyOfRange(0, 12)))
            c.updateAAD(aad)
            val plain = c.doFinal(sealed.copyOfRange(12, sealed.size))
            openOverride?.invoke(plain) ?: plain
        } catch (e: GeneralSecurityException) {
            null
        }
    }

    override fun deleteKey(): Boolean {
        secret = newKey()
        return true
    }

    private fun newKey(): SecretKey = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
}

internal class NativeTestFiles : VaultFiles {
    val map = HashMap<String, ByteArray>()
    var failWrite: String? = null
    var failDelete: String? = null
    /** A removal that returns without removing, as the old AndroidVaultFiles did (the file stays, nothing is thrown). */
    var silentDeleteFailure: String? = null
    var crashAfterWrite: String? = null

    override fun read(name: String): ByteArray? = map[name]?.copyOf()

    override fun write(name: String, bytes: ByteArray) {
        if (failWrite == name) throw IOException("disk full")
        map[name] = bytes.copyOf()
        if (crashAfterWrite == name) throw NativeTestCrash()
    }

    override fun delete(name: String) {
        if (failDelete == name) throw IOException("cannot remove")
        if (silentDeleteFailure == name) return
        map.remove(name)
    }
}
