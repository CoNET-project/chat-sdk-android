package network.conet.chat.nativekey

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import org.json.JSONObject

/**
 * The storage of one encrypted entry, the backend of [AccountPgpK]. A read or a list that cannot be done throws; there is no plain fallback.
 */
internal interface AccountPgpKBackend {
    /** The value of [name], or null when there is none. Throws when the store cannot be read. */
    fun get(name: String): String?

    /** Stores [value] under [name]. False when the write did not complete. */
    fun put(name: String, value: String): Boolean

    /** The names in the store. Throws when the store cannot be read. */
    fun names(): Set<String>
}

/**
 * K (§25.52Y.1): the SDK account PGP item. One item per account and workspace, in the encrypted SDK store, separate from L (the legacy copy,
 * `beamio_chat_pgp_v1`). Its body is UTF-8 JSON with `eoa` (lower case), `workspace`, `keyId`, `publicKeyArmor`, `privateKeyArmor` and `createdAt`.
 * It holds a PGP private key: it is never stored in a plain file and never returned over the bridge.
 */
internal class AccountPgpK(private val backend: AccountPgpKBackend) {

    /** The item name of [eoa] in [workspace]: it contains both, and it begins with the K prefix, so it never equals an L key. */
    fun itemName(eoa: String, workspace: String): String = PREFIX + eoa.lowercase() + "|" + workspace

    /**
     * Writes the item and reads it back (§25.52Y.1 第 6 项): the key ID and the public armor must match. Returns false when the write or the read-back
     * does not match; the caller then removes what it wrote (never a silent overwrite of another account's item).
     */
    fun write(eoa: String, workspace: String, keyId: String, publicArmor: String, privateArmor: String, createdAt: Long): Boolean {
        val lower = eoa.lowercase()
        val body = JSONObject()
            .put("eoa", lower)
            .put("workspace", workspace)
            .put("keyId", keyId)
            .put("publicKeyArmor", publicArmor)
            .put("privateKeyArmor", privateArmor)
            .put("createdAt", createdAt)
        val name = itemName(lower, workspace)
        if (!backend.put(name, body.toString())) return false
        val back = read(lower, workspace) ?: return false
        return back.optString("keyId") == keyId && back.optString("publicKeyArmor") == publicArmor
    }

    /**
     * The item of [eoa] in [workspace], or null when there is none. Throws when the store cannot be read (never null for that), and returns null
     * only when the store is readable and has no item.
     */
    fun read(eoa: String, workspace: String): JSONObject? {
        val raw = backend.get(itemName(eoa, workspace)) ?: return null
        val json = JSONObject(raw)
        // The item must be the one it is named for; any other content is treated as unreadable by the caller.
        if (json.optString("eoa") != eoa.lowercase() || json.optString("workspace") != workspace) throw IllegalStateException("K item mismatch")
        return json
    }

    /** True when the item of [eoa] in [workspace] exists. Throws when the store cannot be read. */
    fun existsFor(eoa: String, workspace: String): Boolean = backend.names().contains(itemName(eoa, workspace))

    /** True when any K item exists (§25.48.4, the tag path). Throws when the store cannot be read. */
    fun existsAny(): Boolean = backend.names().any { it.startsWith(PREFIX) }

    companion object {
        /** The prefix of every K item name. */
        const val PREFIX = "K.v1|"

        /** The encrypted file of the K items. Distinct from L's file (`beamio_chat_pgp_v1`). */
        const val PREFS = "beamio_sdk_account_pgp_k_v1"

        /**
         * The production store: EncryptedSharedPreferences with a master key. If it cannot be opened, every read and list throws (unreadable): there is
         * no plain fallback for a private key.
         */
        fun forDevice(context: Context): AccountPgpK = AccountPgpK(EncryptedBackend(context.applicationContext))
    }

    private class EncryptedBackend(private val app: Context) : AccountPgpKBackend {
        private fun prefs() = EncryptedSharedPreferences.create(
            app,
            PREFS,
            MasterKey.Builder(app).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build(),
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
        )

        override fun get(name: String): String? = prefs().getString(name, null)

        override fun put(name: String, value: String): Boolean = prefs().edit().putString(name, value).commit()

        override fun names(): Set<String> = prefs().all.keys.toSet()
    }
}

/**
 * The local sources of the binding lookup from the device (HH.2, §25.52Y.1, §25.48.4), as a pure function so the decision can be tested. [kState]
 * is the result of reading K for the EOA (or for any account, on the tag path): present, absent, or unreadable.
 */
internal object BindingLocalSources {
    enum class KState { PRESENT, ABSENT, UNREADABLE }

    /**
     * EOA path: a positive source is the wallet key of the account or its K; an unreadable keychain or K is an unreadable source (fail closed).
     * Tag path: kPresent is "any K exists" (§25.48.4) and the wallet key is the wallet record; an unreadable K makes the device state unknown.
     */
    fun of(keyReady: Boolean, vaultUnreadable: Boolean, kState: KState): Pair<LocalSource, BindingDevice> {
        val kPresent = kState == KState.PRESENT
        val local = when {
            keyReady || kPresent -> LocalSource.POSITIVE
            vaultUnreadable || kState == KState.UNREADABLE -> LocalSource.UNREADABLE
            else -> LocalSource.NONE
        }
        return local to BindingDevice(kPresent = keyReady || kPresent, walletRecord = keyReady)
    }
}
