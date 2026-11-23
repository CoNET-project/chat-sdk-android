package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The store-primary source rule . Pure cases: the store decides first; a v3 set needs the session; the vault is read only and
 * answers only when the store is absent; an unknown store never falls back.
 */
class NativeSourceTest {

    private val a = "0x1111111111111111111111111111111111111111"
    private val b = "0x2222222222222222222222222222222222222222"

    private fun plain(eoa: String) = MnemonicSetStore.Current.Found(eoa, MnemonicSetStore.Kind.PLAIN, "fog", 1)
    private fun v3(eoa: String) = MnemonicSetStore.Current.Found(eoa, MnemonicSetStore.Kind.V3, "{}", 1)

    /** Positive: the vault is Ready for A but the store's plain set is B: the store answers for B; the vault is not consulted. */
    @Test
    fun aPlainStoreSetWinsOverAReadyVaultOfAnotherAccount() {
        val s = NativeSource.decide(NativeWalletVault.State.Ready(a), plain(b), null)
        assertTrue(s is NativeSource.Source.Store)
        assertEquals(b, NativeSource.accountOf(s))
    }

    /** Negative: a v3 store set does not fall back to the vault, even when the vault is Ready for the same account; ready only with the session. */
    @Test
    fun aV3StoreSetDoesNotFallBackToTheVault() {
        val blocked = NativeSource.decide(NativeWalletVault.State.Ready(a), v3(a), null)
        assertTrue(blocked is NativeSource.Source.Blocked)
        assertNull(NativeSource.accountOf(blocked))
        assertEquals(a, NativeSource.accountOf(NativeSource.decide(NativeWalletVault.State.Ready(a), v3(a), a)))
    }

    /** Positive: an absent store leaves the read-only vault in charge (Ready gives its account; NoKey and Locked give none). */
    @Test
    fun anAbsentStoreUsesTheVault() {
        assertEquals(a, NativeSource.accountOf(NativeSource.decide(NativeWalletVault.State.Ready(a), MnemonicSetStore.Current.Absent, null)))
        assertNull(NativeSource.accountOf(NativeSource.decide(NativeWalletVault.State.NoKey, MnemonicSetStore.Current.Absent, null)))
        assertNull(NativeSource.accountOf(NativeSource.decide(NativeWalletVault.State.Locked("unreadable"), MnemonicSetStore.Current.Absent, null)))
    }

    /** Negative: an unknown store is not ready and never falls back to the vault. */
    @Test
    fun anUnknownStoreIsBlockedWithoutFallback() {
        val s = NativeSource.decide(NativeWalletVault.State.Ready(a), MnemonicSetStore.Current.Unknown("set_missing"), null)
        assertTrue(s is NativeSource.Source.Blocked)
        assertEquals("store_unknown", (s as NativeSource.Source.Blocked).reason)
    }

    /** Negative: a blocked source signs nothing and never calls the vault path. */
    @Test
    fun aBlockedSourceNeverCallsTheVaultSign() {
        var called = 0
        val out = NativeMessageSigner.signBySource(
            NativeSource.Source.Blocked("store_unknown"), MnemonicSetStore.Current.Unknown("x"), NativeMessageSigner.KIND_ENVELOPE, byteArrayOf(1),
        ) { called++; NativeOutcome("ok") }
        assertEquals("locked", out.code)
        assertEquals(0, called)
        assertFalse(NativeMessageSigner.storeMayAnswer(MnemonicSetStore.Current.Unknown("x")))
    }
}
