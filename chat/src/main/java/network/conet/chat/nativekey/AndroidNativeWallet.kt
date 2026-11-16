package network.conet.chat.nativekey

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import network.conet.chat.BeamioChatPgpStore
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

    override fun deleteKey(): Boolean = try {
        keyStore().deleteEntry(alias)
        !keyStore().containsAlias(alias)
    } catch (_: Exception) {
        false
    }

    companion object {
        const val KEY_ALIAS = "beamio.wallet.wrap.v1"
    }
}

/** Files under the app's private directory. Writes go to a temp file, are synced, then renamed. */
class AndroidVaultFiles(private val dir: File) : VaultFiles {
    /**
     * The bytes of [name], or null only when the name is absent from a readable directory. A name present but not a regular file, or a directory
     * that exists but cannot be listed, is a read failure (throws): it is never taken for "no record", which would answer no_key (25.52Y.84).
     */
    override fun read(name: String): ByteArray? {
        val f = File(dir, name)
        // Absent is only NoSuchFileException from the stat. Any other failure (permission, I/O, a parent that is not a directory) is a read
        // failure: unknown, never "no record" (Y.104 第 3 条, Y.105 第 2 条).
        val attributes = try {
            java.nio.file.Files.readAttributes(f.toPath(), java.nio.file.attribute.BasicFileAttributes::class.java)
        } catch (_: java.nio.file.NoSuchFileException) {
            if (dir.exists() && dir.list() == null) throw IOException("vault directory cannot be listed")
            return null
        } catch (e: IOException) {
            throw IOException("vault entry cannot be read", e)
        }
        if (!attributes.isRegularFile) throw IOException("vault entry is not a regular file")
        return f.readBytes()
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

    override fun exists(name: String): Boolean = File(dir, name).exists()

    /**
     * Removes the file and its temp leftover. A removal that does not take effect throws (the file is still there), so no caller can take a
     * failed removal for a done one (spec 25.25.5, 25.52Y.42 第 4 项 (e)).
     */
    override fun delete(name: String) {
        for (f in listOf(File(dir, name), File(dir, "$name.tmp"))) {
            if (f.exists() && !f.delete() && f.exists()) throw IOException("vault delete failed")
        }
    }

    /** The file names in the directory, for the page-copy discovery (§25.52AD.2). Empty when the directory does not exist. */
    fun names(): List<String> = dir.list()?.toList().orEmpty()
}

/** The app's single native wallet vault, and the one-time adoption of the pre-upgrade key. */
object NativeWallet {
    private const val DIR = "native_wallet_v1"

    @Volatile
    private var instance: NativeWalletVault? = null

    /** The directory the vault and the PGP migration store their sealed files in (same wrap key). */
    internal fun migrationFiles(context: Context): VaultFiles =
        AndroidVaultFiles(File(context.applicationContext.filesDir, DIR))

    /** The file names in the vault directory (for the identity clear, which must find PGP records without an account). */
    internal fun migrationNames(context: Context): List<String> =
        (migrationFiles(context) as? AndroidVaultFiles)?.names().orEmpty()

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

    /**
     * The PGP vault of the wallet's active account. Without a wallet key it serves no record ([NativePgpVault.NO_ACCOUNT]).
     * Each account has its own PGP record in the same directory and wrap key; the wallet record is not touched.
     */
    internal fun pgp(context: Context): NativePgpVault {
        val app = context.applicationContext
        val eoa = (vault(app).state() as? NativeWalletVault.State.Ready)?.eoa ?: NativePgpVault.NO_ACCOUNT
        return pgpFor(app, eoa)
    }

    /** The active PGP record of [eoa]. A value that is not a canonical address serves no record. */
    internal fun pgpFor(context: Context, eoa: String): NativePgpVault =
        NativePgpVault(
            AndroidKeyWrap(),
            AndroidVaultFiles(File(context.applicationContext.filesDir, DIR)),
            accountOrNone(eoa),
        )

    /**
     * The restore device for [eoa] (P-IMP-PGP): the same wrap and files as [pgpFor], so a restored record is the one that
     * [pgpFor] reads afterwards.
     */
    internal fun pgpRestoreDevice(context: Context, eoa: String, id: String): PgpRestoreDevice =
        PgpRestoreDevice(
            id,
            accountOrNone(eoa),
            AndroidKeyWrap(),
            AndroidVaultFiles(File(context.applicationContext.filesDir, DIR)),
        )

    /** The pending slot of [eoa]: a generated key awaiting its registration. It is never the active identity. */
    internal fun pendingPgpFor(context: Context, eoa: String): NativePgpVault =
        NativePgpVault(
            AndroidKeyWrap(),
            AndroidVaultFiles(File(context.applicationContext.filesDir, DIR)),
            accountOrNone(eoa),
            NativePgpVault.Slot.PENDING,
        )

    private fun accountOrNone(eoa: String): String {
        val lower = eoa.lowercase()
        return if (Regex("^0x[0-9a-f]{40}$").matches(lower)) lower else NativePgpVault.NO_ACCOUNT
    }

    /**
     * Upgrade path for the PGP key. When the EOA record is present and the PGP record is not, and the pre-upgrade PGP
     * store holds a private key for the same account, the key is copied into the vault. The legacy copy is kept: this
     * version never clears L (r3as §25.52.3, PGP migration U5), and the migration reads it. The legacy store never held a
     * passphrase; the passphrase arrives with `init`. Returns `true` when a key was adopted.
     */
    @Synchronized
    fun migrateLegacyPgp(context: Context): Boolean {
        val app = context.applicationContext
        val eoa = (vault(app).state() as? NativeWalletVault.State.Ready)?.eoa ?: return false
        val pgpVault = pgpFor(app, eoa)
        if (pgpVault.state() !is NativePgpVault.State.NoKey) return false
        val armor = BeamioChatPgpStore.legacyPrivateArmor(app)
        if (!armor.contains("BEGIN PGP PRIVATE KEY")) return false
        val legacyEoa = BeamioChatPgpStore.load(app)?.eoa?.trim()?.lowercase().orEmpty()
        if (legacyEoa.isNotEmpty() && legacyEoa != eoa) return false
        return pgpVault.put(eoa, armor, "") == NativePgpVault.Put.OK
    }
}
