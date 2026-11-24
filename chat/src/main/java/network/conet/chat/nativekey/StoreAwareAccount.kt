package network.conet.chat.nativekey

import android.content.Context
import java.io.File

/**
 * The account a PGP command works for when the wallet vault holds no record but the two-state store names one (0.2.30). After a page sync the
 * store is the account's source and the vault is no longer written (the store is primary), so a command that looked only at the vault
 * answered `no_key` for an account that exists. This object is the one place that reads the store for the PGP commands (pgpRestore*, pgpMigrate,
 * identityPublic and the K_pgp upgrade).
 *
 * It only widens the case "the vault has no record" (NoKey). Every other vault state is decided by the caller exactly as before, so an account
 * whose vault is Ready keeps its own path.
 *
 *  - a plain set is an account of its own, and its key derives from the stored phrase in memory ([StoreKeyAdapter.plainKey]);
 *  - a v3 set is an account only while this session holds its key ([StoreKeyAdapter.sessionKey]); otherwise it exists and needs the passcode
 *    (`not_ready`, `passcode_not_provided`), and is never `no_key`;
 *  - a store that cannot be read is unknown (`not_ready`, `unreadable`), never `no_key`;
 *  - an absent store is `no_key`.
 *
 * Nothing here writes. The phrase and the key never leave this layer: the callers receive a fresh key copy and zero it, and nothing is put on the
 * bridge.
 */
internal object StoreAwareAccount {
    enum class Source { STORE_PLAIN, STORE_SESSION }

    sealed class Resolution {
        /** The store names an account that can sign in this session. */
        class Account(val eoa: String, val source: Source) : Resolution()

        /** The account exists or may exist, but cannot be used now: [reason] is the `not_ready` reason. Retryable, nothing is missing. */
        class NotReady(val reason: String) : Resolution()

        /** The store holds no account (confirmed absent). */
        object NoKey : Resolution()
    }

    /** The store decision for a vault with no record. [sessionKeyHeld] answers whether this session holds the key of a v3 set's account. */
    fun resolve(store: MnemonicSetStore.Current, sessionKeyHeld: (MnemonicSetStore.Current.Found) -> Boolean): Resolution = when (store) {
        is MnemonicSetStore.Current.Absent -> Resolution.NoKey
        is MnemonicSetStore.Current.Unknown -> Resolution.NotReady(NoKeyGate.NOT_READY_UNREADABLE)
        is MnemonicSetStore.Current.Found -> when (store.kind) {
            MnemonicSetStore.Kind.PLAIN -> Resolution.Account(store.eoa.lowercase(), Source.STORE_PLAIN)
            MnemonicSetStore.Kind.V3 ->
                if (sessionKeyHeld(store)) Resolution.Account(store.eoa.lowercase(), Source.STORE_SESSION)
                else Resolution.NotReady(NoKeyGate.NOT_READY_PASSCODE_REQUIRED)
        }
    }

    /**
     * The account whose PGP vault record is served: the wallet vault's Ready account first; only without one, the store's account (a plain set, or a
     * v3 set the session holds the key of). Anything else serves no record. [store] is asked only when the vault has no Ready account.
     */
    internal fun pgpAccountOf(vaultReadyEoa: String?, store: () -> Resolution): String =
        vaultReadyEoa ?: (store() as? Resolution.Account)?.eoa ?: NativePgpVault.NO_ACCOUNT

    /** The current set of the store; a read that fails is unknown (never absent). Read only. */
    fun storeCurrent(app: Context): MnemonicSetStore.Current = try {
        MnemonicSetStore(File(app.applicationContext.noBackupFilesDir, MnemonicSetStore.DIRECTORY)).current()
    } catch (_: Exception) {
        MnemonicSetStore.Current.Unknown("store_unreadable")
    }

    /** [resolve] on the device: the store as it is now, and the session's held key. */
    fun resolveOnDevice(app: Context): Resolution = resolve(storeCurrent(app)) { found ->
        SessionKeyHolder.keyFor(found.eoa)?.also { it.fill(0) } != null
    }

    /**
     * A fresh copy of the key of [account], re-derived from the store now, or null when the store no longer names that account's key (the set
     * changed, the session lock was lost, the phrase does not derive the set's EOA). The caller zeroes the copy.
     */
    fun keyOf(app: Context, account: Resolution.Account): ByteArray? = keyOf(storeCurrent(app), account)

    internal fun keyOf(current: MnemonicSetStore.Current, account: Resolution.Account): ByteArray? {
        val found = current as? MnemonicSetStore.Current.Found ?: return null
        if (!found.eoa.equals(account.eoa, ignoreCase = true)) return null
        return when (account.source) {
            Source.STORE_PLAIN -> StoreKeyAdapter.plainKey(current)
            Source.STORE_SESSION -> StoreKeyAdapter.sessionKey(current)
        }
    }
}
