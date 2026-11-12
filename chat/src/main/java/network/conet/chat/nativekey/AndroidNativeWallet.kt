package network.conet.chat.nativekey

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import network.conet.chat.BeamioChatWalletKeyStore
import network.conet.chat.ConetChatCryptoUtil
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * AndroidKeyStore AES-256-GCM wrapping key (spec 25.17.5, alias `beamio.wallet.wrap.v1`). StrongBox is
 * tried first and the TEE used when it is not available. Not verified on a device in this build: the
 * behaviour of the real Keystore is a device-acceptance item.
 */
class AndroidKeyWrap(private val alias: String = KEY_ALIAS) : KeyWrap {
    private fun keyStore(): KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    private fun existingKey(): SecretKey? = keyStore().getKey(alias, null) as? SecretKey

    private fun createKey(): SecretKey =
        try {
            generate(strongBox = true)
        } catch (e: Exception) {
            generate(strongBox = false)
        }

    private fun generate(strongBox: Boolean): SecretKey {
        if (strongBox && Build.VERSION.SDK_INT < 28) throw IllegalStateException("StrongBox needs API 28")
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        val spec = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
        if (strongBox && Build.VERSION.SDK_INT >= 28) spec.setIsStrongBoxBacked(true)
        gen.init(spec.build())
        return gen.generateKey()
    }

    override fun seal(aad: ByteArray, plain: ByteArray): ByteArray {
        val key = existingKey() ?: createKey()
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, key)
        c.updateAAD(aad)
        return c.iv + c.doFinal(plain)
    }

    override fun open(aad: ByteArray, sealed: ByteArray): ByteArray? {
        if (sealed.size < 13) return null
        return try {
            val key = existingKey() ?: return null
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, sealed.copyOfRange(0, 12)))
            c.updateAAD(aad)
            c.doFinal(sealed.copyOfRange(12, sealed.size))
        } catch (e: Exception) {
            null
        }
    }

    override fun deleteKey() {
        try {
            keyStore().deleteEntry(alias)
        } catch (_: Exception) {
        }
    }

    companion object {
        const val KEY_ALIAS = "beamio.wallet.wrap.v1"
    }
}

/** Files under the app's private directory. Writes go to a temp file, are synced, then renamed. */
class AndroidVaultFiles(private val dir: File) : VaultFiles {
    override fun read(name: String): ByteArray? {
        val f = File(dir, name)
        return if (f.isFile) f.readBytes() else null
    }

    override fun write(name: String, bytes: ByteArray) {
        if (!dir.isDirectory && !dir.mkdirs()) throw IOException("vault directory unavailable")
        val tmp = File(dir, "$name.tmp")
        FileOutputStream(tmp).use { out ->
            out.write(bytes)
            out.flush()
            out.fd.sync()
        }
        if (!tmp.renameTo(File(dir, name))) {
            tmp.delete()
            throw IOException("vault rename failed")
        }
    }

    override fun delete(name: String) {
        File(dir, name).delete()
        File(dir, "$name.tmp").delete()
    }
}

/** The app's single native wallet vault, and the one-time adoption of the pre-upgrade key. */
object NativeWallet {
    private const val DIR = "native_wallet_v1"

    @Volatile
    private var instance: NativeWalletVault? = null

    fun vault(context: Context): NativeWalletVault =
        instance ?: synchronized(this) {
            instance ?: NativeWalletVault(
                AndroidKeyWrap(),
                AndroidVaultFiles(File(context.applicationContext.filesDir, DIR)),
            ).also { instance = it }
        }

    /**
     * Upgrade path: when the vault is empty and the pre-upgrade store (`BeamioChatWalletKeyStore`) holds a
     * wallet key that decrypts, the key is imported into the vault. The old copy is removed only after the
     * vault has confirmed it. Returns `true` when a key was adopted.
     */
    @Synchronized
    fun migrateLegacy(context: Context): Boolean {
        val app = context.applicationContext
        val v = vault(app)
        if (v.state() !is NativeWalletVault.State.NoKey) return false
        val legacy = BeamioChatWalletKeyStore.load(app) ?: return false
        val key = ConetChatCryptoUtil.hexToBytes(legacy.privateKeyHex) ?: return false
        return try {
            val result = v.importKey(legacy.eoa, key, NativeWalletVault.SOURCE_LEGACY)
            if (result == NativeWalletVault.Import.OK) BeamioChatWalletKeyStore.clear(app)
            result == NativeWalletVault.Import.OK
        } finally {
            key.fill(0)
        }
    }
}
