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

    /** Removes [name]. False when the removal did not complete; the caller reports it, it is never silent. */
    fun remove(name: String): Boolean
}

/** The outcome of a write that must not overwrite (§25.52Y.1 第 6 项): written, an item already there (not overwritten), or failed (rolled back). */
internal enum class AccountPgpKWrite {
    WRITTEN,
    EXISTS,

    /** The write failed and what was written was removed: the device holds no K for it. */
    FAILED,

    /** The write failed and its removal failed too: a half item may remain. The caller must not treat the account as created, and must report it. */
    FAILED_RESIDUE,
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

    /**
     * Writes the item only when none exists (§25.52Y.1 第 6 项: an existing item is never overwritten). A write that does not read back is removed
     * again, so no half item is left; a failed removal is reported as FAILED too, and the caller must not treat the account as created.
     */
    fun writeIfAbsent(eoa: String, workspace: String, keyId: String, publicArmor: String, privateArmor: String, createdAt: Long): AccountPgpKWrite {
        if (existsFor(eoa, workspace)) return AccountPgpKWrite.EXISTS
        val name = itemName(eoa, workspace)
        // Any exception in the write or its read-back is a failed write too: the same removal and outcome apply (never a half item left silently).
        val written = try {
            write(eoa, workspace, keyId, publicArmor, privateArmor, createdAt)
        } catch (_: Exception) {
            false
        }
        if (written) return AccountPgpKWrite.WRITTEN
        val removed = try {
            backend.remove(name)
        } catch (_: Exception) {
            false
        }
        return if (removed) AccountPgpKWrite.FAILED else AccountPgpKWrite.FAILED_RESIDUE
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

        /** The same production backend, for the account cleanup (25.52Y.91): it lists and removes the K items; it never writes a new one. */
        fun cleanupBackend(context: Context): AccountPgpKBackend = EncryptedBackend(context.applicationContext)
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

        override fun remove(name: String): Boolean = prefs().edit().remove(name).commit()
    }
}

/**
 * The local sources of the binding lookup from the device (HH.2, §25.52Y.1, §25.48.4, §25.52Z.3 第 7 项), as a pure function so the decision can be
 * tested. [kActive] and [kNonActive] say whether the account's K is in the ACTIVE slot or another slot. [kUnreadable] is a K that cannot be read.
 *  - EOA path: the wallet key, an ACTIVE K or a non-ACTIVE K is a positive source (BL-54).
 *  - Tag path: a non-ACTIVE K counts in kPresent (BL-53), so with a zero registry answer it is lookup_unavailable, never a create.
 *  - An unreadable keychain or K is an unreadable source (fail closed).
 */
internal object BindingLocalSources {
    fun of(
        keyReady: Boolean,
        vaultUnreadable: Boolean,
        kActive: Boolean,
        kNonActive: Boolean,
        kUnreadable: Boolean,
        kPresent: Boolean = false,
    ): Pair<LocalSource, BindingDevice> {
        // [kPresent] is "any K exists on the device" (§25.48.4); it can hold a K whose slot is not classified (BL-50, BL-51).
        val anyK = kActive || kNonActive || kPresent
        val local = when {
            keyReady || anyK -> LocalSource.POSITIVE
            vaultUnreadable || kUnreadable -> LocalSource.UNREADABLE
            else -> LocalSource.NONE
        }
        return local to BindingDevice(kPresent = keyReady || anyK, walletRecord = keyReady)
    }
}
