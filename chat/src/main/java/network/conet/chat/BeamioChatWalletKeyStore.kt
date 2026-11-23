package network.conet.chat

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Pre-upgrade wallet key store. The app no longer writes here: the native vault
 * (`nativekey.NativeWallet`) holds the key, and [NativeWallet.migrateLegacy] moves an
 * existing key into it once, then calls [clear]. This object only reads and clears
 * the old copy, and normalises key strings for callers.
 *
 * The old copy is AES-GCM ciphertext under an Android Keystore key. Hosts should
 * exclude [PREFS] from backup; a restored copy cannot be decrypted anyway.
 */
object BeamioChatWalletKeyStore {
    const val PREFS = "beamio_chat_wallet_v1"
    private const val KEY_ALIAS = "beamio_chat_wallet_v1"
    private const val KEY_EOA = "eoa"
    private const val KEY_IV = "iv"
    private const val KEY_CT = "ct"
    private const val TAG = "BeamioChatWallet"
    private val HEX_KEY = Regex("^[0-9a-f]{64}$")

    data class Stored(val eoa: String, val privateKeyHex: String)

    /** 64 hex chars, no 0x, lower case; empty when not a private key. */
    fun normalizeKey(raw: String?): String {
        val t = raw.orEmpty().trim().removePrefix("0x").removePrefix("0X").lowercase()
        return if (HEX_KEY.matches(t)) t else ""
    }

    private fun secretKey(): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getKey(KEY_ALIAS, null) as? SecretKey)?.let { return it }
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        gen.init(
            KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build(),
        )
        return gen.generateKey()
    }

    fun load(context: Context): Stored? {
        val p = context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val eoa = p.getString(KEY_EOA, "").orEmpty()
        val iv = p.getString(KEY_IV, "").orEmpty()
        val ct = p.getString(KEY_CT, "").orEmpty()
        if (eoa.isEmpty() || iv.isEmpty() || ct.isEmpty()) return null
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(
                Cipher.DECRYPT_MODE,
                secretKey(),
                GCMParameterSpec(128, Base64.decode(iv, Base64.NO_WRAP)),
            )
            val key = normalizeKey(String(cipher.doFinal(Base64.decode(ct, Base64.NO_WRAP)), Charsets.US_ASCII))
            if (key.isEmpty()) null else Stored(eoa, key)
        } catch (e: Exception) {
            Log.w(TAG, "wallet key unreadable: ${e.javaClass.simpleName}")
            null
        }
    }

    /** The EOA of the legacy wallet copy, for the account cleanup (25.52Y.91). Null when there is none; throws when unreadable. */
    internal fun ownerEoa(context: Context): String? =
        context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(KEY_EOA, "").orEmpty().trim().lowercase().ifEmpty { null }

    /**
     * Read-only presence of the published copy for the key-only criterion. Reads the ciphertext field only; it
     * does not decrypt, so a copy that cannot be decrypted still counts as present. A read failure is Unknown. When the platform reads the copy as
     * empty, the backing file (and its .bak) is checked: a file that exists and is not a clean empty map (corrupt XML read as empty) is Unknown, never
     * Absent. Writes and removes nothing.
     */
    internal fun publishedCopyState(context: Context): network.conet.chat.nativekey.NativeWalletVault.PublishedWalletCopy {
        val app = context.applicationContext
        return classifyPublishedCopy(
            readCiphertext = { app.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(KEY_CT, "").orEmpty() },
            // The directory is resolved inside the read, so a failure to resolve it is Unknown, never a crash of the caller.
            readFile = { name -> java.io.File(java.io.File(app.applicationInfo.dataDir, "shared_prefs"), name).let { f -> if (f.exists()) f.readBytes() else null } },
        )
    }

    private val EMPTY_MAP = Regex("^(<\\?xml[^>]*\\?>)?\\s*(<map\\s*/>|<map>\\s*</map>)\\s*$")

    /** [readFile] returns the bytes of a file under shared_prefs, or null when it does not exist; it may throw. */
    internal fun classifyPublishedCopy(
        readCiphertext: () -> String,
        readFile: (String) -> ByteArray? = { null },
    ): network.conet.chat.nativekey.NativeWalletVault.PublishedWalletCopy =
        try {
            if (readCiphertext().isNotEmpty()) network.conet.chat.nativekey.NativeWalletVault.PublishedWalletCopy.Present
            else if (listOf("$PREFS.xml", "$PREFS.xml.bak").any { n -> readFile(n)?.let { b -> !EMPTY_MAP.matches(String(b, Charsets.UTF_8).trim()) } == true }) network.conet.chat.nativekey.NativeWalletVault.PublishedWalletCopy.Unknown
            else network.conet.chat.nativekey.NativeWalletVault.PublishedWalletCopy.Absent
        } catch (_: Exception) {
            network.conet.chat.nativekey.NativeWalletVault.PublishedWalletCopy.Unknown
        }
}
