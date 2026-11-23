package network.conet.chat.nativekey

import network.conet.chat.nativekey.NoPageListenPolicy.Decision
import network.conet.chat.nativekey.NoPageListenPolicy.WalletSource
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The no-page listen start decision (pgpReady and walletKey). Synthetic accounts only. Covers: a Ready vault; a NoKey vault with a
 * plain set; a v3 set; an absent, unknown or Locked vault; an unknown store; PGP readiness from the vault or from the published PGP store; and the
 * PGP store account that differs from the wallet account (the listen does not start).
 */
class NoPageListenPolicyTest {

    private val eoa = "0xd49251e1e9f4d4d5bac808861fa4ce23053c986f"
    private val other = "0x2222222222222222222222222222222222222222"
    private val phrase = "fog spot notable regret pizza coffee harvest ensure fog spot notable reflect"
    private val plain = MnemonicSetStore.Current.Found(eoa, MnemonicSetStore.Kind.PLAIN, phrase, 0)
    private val v3 = MnemonicSetStore.Current.Found(eoa, MnemonicSetStore.Kind.V3, "{}", 1)

    private fun refuse(d: Decision): String = (d as Decision.Refuse).diag

    /** Positive: a Ready vault starts with its own account and the vault key (PGP ready from the vault). */
    @Test
    fun aReadyVaultStartsWithItsAccount() {
        val d = NoPageListenPolicy.decide(NativeWalletVault.State.Ready(eoa), MnemonicSetStore.Current.Absent, true, false, null) as Decision.Start
        assertEquals(eoa, d.eoa)
        assertEquals(WalletSource.VAULT, d.source)
    }

    /** Positive: NoKey with a plain set starts with the set's account, and the key comes from the set. */
    @Test
    fun aNoKeyVaultWithAPlainSetStartsFromTheSet() {
        val d = NoPageListenPolicy.decide(NativeWalletVault.State.NoKey, plain, true, false, null) as Decision.Start
        assertEquals(eoa, d.eoa)
        assertEquals(WalletSource.STORE_PLAIN, d.source)
    }

    /** Negative: NoKey with only a v3 set does not start until the step (2) passphrase. */
    @Test
    fun aNoKeyVaultWithOnlyAV3SetDoesNotStart() {
        assertEquals("v3_waits_passphrase", refuse(NoPageListenPolicy.decide(NativeWalletVault.State.NoKey, v3, true, false, null)))
    }

    /** Negative: NoKey with no set, or an unknown store, does not start. */
    @Test
    fun aNoKeyVaultWithoutASetOrWithAnUnknownStoreDoesNotStart() {
        assertEquals("no_store_set", refuse(NoPageListenPolicy.decide(NativeWalletVault.State.NoKey, MnemonicSetStore.Current.Absent, true, false, null)))
        assertEquals("store_unknown", refuse(NoPageListenPolicy.decide(NativeWalletVault.State.NoKey, MnemonicSetStore.Current.Unknown("x"), true, false, null)))
    }

    /** Negative: a Locked vault, and an unknown (unreadable) vault, do not start, whatever the store holds. */
    @Test
    fun aLockedOrUnknownVaultDoesNotStart() {
        assertEquals("vault_locked", refuse(NoPageListenPolicy.decide(NativeWalletVault.State.Locked("unreadable"), plain, true, false, null)))
        assertEquals("vault_unknown", refuse(NoPageListenPolicy.decide(null, plain, true, false, null)))
    }

    /** Positive: PGP is ready from the published PGP store when its armor is there and its account is the wallet account. */
    @Test
    fun pgpReadyFromTheStoreWithTheSameAccountStarts() {
        val d = NoPageListenPolicy.decide(NativeWalletVault.State.Ready(eoa), MnemonicSetStore.Current.Absent, false, true, eoa.uppercase().replace("0X", "0x"))
        assertTrue(d is Decision.Start)
    }

    /** Negative: PGP is not ready when neither the vault nor the store has it. */
    @Test
    fun pgpNotReadyWithoutAnySourceDoesNotStart() {
        assertEquals("pgp_not_ready", refuse(NoPageListenPolicy.decide(NativeWalletVault.State.Ready(eoa), MnemonicSetStore.Current.Absent, false, false, null)))
    }

    /** Negative: the published PGP store's account differs from the wallet account, so the listen does not start. */
    @Test
    fun aPgpStoreOfAnotherAccountDoesNotStart() {
        assertEquals(
            "pgp_store_eoa_mismatch",
            refuse(NoPageListenPolicy.decide(NativeWalletVault.State.NoKey, plain, false, true, other)),
        )
        assertEquals(
            "pgp_store_eoa_mismatch",
            refuse(NoPageListenPolicy.decide(NativeWalletVault.State.Ready(eoa), MnemonicSetStore.Current.Absent, false, true, null)),
        )
    }

    /** Negative (the route public key is used by the listen): the store holds only the private armor and no route public key; the listen does not start, with route_public_missing. */
    @Test
    fun aStoreWithOnlyThePrivateArmorAndNoRoutePublicKeyIsRefusedWithACode() {
        val d = NoPageListenPolicy.decide(
            NativeWalletVault.State.Ready(eoa), MnemonicSetStore.Current.Absent, false, true, eoa,
            pgpStorePresent = true, routePublicPresent = false,
        )
        assertEquals("route_public_missing", refuse(d))
    }

    /** Positive: the same store with its route public key starts (the route key is present, the account matches). */
    @Test
    fun aStoreWithThePrivateArmorAndTheRoutePublicKeyStarts() {
        val d = NoPageListenPolicy.decide(
            NativeWalletVault.State.Ready(eoa), MnemonicSetStore.Current.Absent, false, true, eoa,
            pgpStorePresent = true, routePublicPresent = true,
        )
        assertTrue(d is Decision.Start)
    }

    /** Negative: no PGP store at all is refused with a code, never a silent return. */
    @Test
    fun noPgpStoreIsRefusedWithACode() {
        val d = NoPageListenPolicy.decide(
            NativeWalletVault.State.Ready(eoa), MnemonicSetStore.Current.Absent, true, false, null,
            pgpStorePresent = false, routePublicPresent = false,
        )
        assertEquals("pgp_store_missing", refuse(d))
    }
}
