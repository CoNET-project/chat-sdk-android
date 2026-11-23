package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The record layer follows the effective source (2026-11-22): the store's own copy when the store answers, the vault's
 * Ready copy when the store is absent, and nothing read or written when the source is blocked. The copy of another account is never touched.
 */
class ShellRecordEffectiveSourceTest {

    private val a = "0x1111111111111111111111111111111111111111"
    private val b = "0x2222222222222222222222222222222222222222"
    private val phrase = "fog spot notable regret pizza coffee harvest ensure fog spot notable reflect"

    private fun resolveWith(
        vault: NativeWalletVault.State,
        store: MnemonicSetStore.Current,
        readyEoa: String?,
        touched: MutableList<String>,
    ): ShellRecordAccount {
        val source = NativeSource.decide(vault, store, readyEoa)
        val ready = ShellRecordAccounts.sessionReadyFor(vault, store, readyEoa)
        return ShellRecordAccounts.resolve(
            vault = vault,
            sessionReady = ready,
            sessionGate = true,
            bound = a,
            copyNames = { emptyList() },
            storeOf = { eoa -> touched += eoa.lowercase(); SealedPageRecordStore(NativeTestWrap(), NativeTestFiles(), "$eoa:default") },
            source = source,
        )
    }

    /** Positive: store B (plain) and vault Ready(A), session ready for B: the record is B's; only B's copy is touched, A's is not. */
    @Test
    fun theStoreAccountsCopyIsTheOnlyOneTouched() {
        val touched = mutableListOf<String>()
        val got = resolveWith(
            NativeWalletVault.State.Ready(a), MnemonicSetStore.Current.Found(b, MnemonicSetStore.Kind.PLAIN, phrase, 1), b, touched,
        )
        assertTrue(got is ShellRecordAccount.Ready)
        assertEquals(b, (got as ShellRecordAccount.Ready).eoa)
        assertEquals(listOf(b), touched)
    }

    /** Positive: an absent store falls back to the vault's Ready account (A). */
    @Test
    fun anAbsentStoreFallsBackToTheVaultAccount() {
        val touched = mutableListOf<String>()
        val got = resolveWith(NativeWalletVault.State.Ready(a), MnemonicSetStore.Current.Absent, a, touched)
        assertEquals(a, (got as ShellRecordAccount.Ready).eoa)
        assertTrue(touched.all { it == a })
    }

    /** Negative: an unknown store is not ready; no copy is read or written. */
    @Test
    fun anUnknownStoreTouchesNothing() {
        val touched = mutableListOf<String>()
        val got = resolveWith(NativeWalletVault.State.Ready(a), MnemonicSetStore.Current.Unknown("set_missing"), a, touched)
        assertEquals(ShellRecordAccount.NotReady, got)
        assertTrue(touched.isEmpty())
    }

    /** Negative: a v3 store set without the session is not ready; no copy is read or written (A's copy is not filled in). */
    @Test
    fun aV3SetWithoutTheSessionTouchesNothing() {
        val touched = mutableListOf<String>()
        val got = resolveWith(
            NativeWalletVault.State.Ready(a), MnemonicSetStore.Current.Found(b, MnemonicSetStore.Kind.V3, "{}", 1), null, touched,
        )
        assertEquals(ShellRecordAccount.NotReady, got)
        assertTrue(touched.isEmpty())
    }
}
