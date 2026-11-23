package network.conet.chat.nativekey

/**
 * The effective source of the native account (store-primary rule). The two-state store is the main source:
 *  - store current plain: the store answers, the vault is not consulted;
 *  - store current v3: it answers only when the session is ready for its account (the passphrase of pwaWalletSync); no fallback to the vault;
 *  - store absent: the read-only vault answers (Ready uses the vault; NoKey and Locked or unreadable are not ready there);
 *  - store unknown: not ready, no fallback.
 * Pure: it reads only the states it is given.
 */
internal object NativeSource {

    sealed class Source {
        /** The store answers for [eoa] (plain, or v3 with the session ready). */
        class Store(val eoa: String, val kind: MnemonicSetStore.Kind) : Source()
        /** The store is absent: the vault path decides ([eoa] is the vault's Ready account, or null when it has none). */
        class Vault(val eoa: String?) : Source()
        /** Not ready: no answer from the store and no fallback. [reason] is a diagnostic code. */
        class Blocked(val reason: String) : Source()
    }

    fun decide(vault: NativeWalletVault.State?, store: MnemonicSetStore.Current, readyEoa: String?): Source = when (store) {
        is MnemonicSetStore.Current.Found -> when (store.kind) {
            MnemonicSetStore.Kind.PLAIN -> Source.Store(store.eoa.lowercase(), MnemonicSetStore.Kind.PLAIN)
            MnemonicSetStore.Kind.V3 ->
                if (readyEoa != null && readyEoa.equals(store.eoa, ignoreCase = true)) {
                    Source.Store(store.eoa.lowercase(), MnemonicSetStore.Kind.V3)
                } else {
                    Source.Blocked("v3_waits_passphrase")
                }
        }
        is MnemonicSetStore.Current.Absent -> Source.Vault((vault as? NativeWalletVault.State.Ready)?.eoa?.lowercase())
        is MnemonicSetStore.Current.Unknown -> Source.Blocked("store_unknown")
    }

    /** The account of an answering source, or null when the source does not name one (blocked, or the vault has no Ready account). */
    fun accountOf(source: Source): String? = when (source) {
        is Source.Store -> source.eoa
        is Source.Vault -> source.eoa
        is Source.Blocked -> null
    }
}
