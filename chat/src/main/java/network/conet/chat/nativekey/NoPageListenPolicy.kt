package network.conet.chat.nativekey

/**
 * The start decision of the no-page listen (pgpReady and walletKey). Pure: it reads only the states it is given.
 *
 * - The account and the wallet key: a Ready vault gives its account (the vault key is used, as before; the store answers only for that account).
 *   A NoKey vault with a plain current set gives the set's account and key (in memory, zeroed by the caller). A v3 set does not start the listen
 *   until the passphrase of step (2) is there. An absent, unknown or Locked vault, and an unknown store, do not start.
 * - PGP readiness: the native PGP vault is Ready, or the published PGP store holds its private armor. In the second case the store's account must
 *   be the wallet account (case-insensitive); a mismatch does not start the listen. The PGP store is read only.
 *
 * Each refusal names a diagnostic code; no key material is in a code.
 */
internal object NoPageListenPolicy {

    enum class WalletSource { VAULT, STORE_PLAIN, STORE_SESSION }

    sealed class Decision {
        class Start(val eoa: String, val source: WalletSource) : Decision()
        class Refuse(val diag: String) : Decision()
    }

    fun decide(
        vault: NativeWalletVault.State?,
        store: MnemonicSetStore.Current,
        pgpVaultReady: Boolean,
        pgpStoreHasPrivate: Boolean,
        pgpStoreEoa: String?,
        pgpStorePresent: Boolean = true,
        routePublicPresent: Boolean = true,
        sessionReadyEoa: String? = null,
    ): Decision {
        val (eoa, source) = when (vault) {
            null -> return Decision.Refuse("vault_unknown")
            is NativeWalletVault.State.Ready -> vault.eoa to WalletSource.VAULT
            is NativeWalletVault.State.Locked -> return Decision.Refuse("vault_locked")
            is NativeWalletVault.State.NoKey -> when (store) {
                is MnemonicSetStore.Current.Found -> when (store.kind) {
                    MnemonicSetStore.Kind.PLAIN -> store.eoa to WalletSource.STORE_PLAIN
                    MnemonicSetStore.Kind.V3 ->
                        if (sessionReadyEoa != null && sessionReadyEoa.equals(store.eoa, ignoreCase = true)) {
                            store.eoa to WalletSource.STORE_SESSION
                        } else {
                            return Decision.Refuse("v3_waits_passphrase")
                        }
                }
                is MnemonicSetStore.Current.Absent -> return Decision.Refuse("no_store_set")
                is MnemonicSetStore.Current.Unknown -> return Decision.Refuse("store_unknown")
            }
        }
        if (!pgpVaultReady) {
            if (!pgpStoreHasPrivate) return Decision.Refuse("pgp_not_ready")
            if (pgpStoreEoa.isNullOrBlank() || !pgpStoreEoa.equals(eoa, ignoreCase = true)) {
                return Decision.Refuse("pgp_store_eoa_mismatch")
            }
        }
        // The published PGP store supplies the public and the route armor and the mailbox; without the store the listen has no identity.
        if (!pgpStorePresent) return Decision.Refuse("pgp_store_missing")
        // The route public key is used by the listen (route registration and the listen's own route check): its absence refuses with a code.
        if (!routePublicPresent) return Decision.Refuse("route_public_missing")
        return Decision.Start(eoa.lowercase(), source)
    }
}
