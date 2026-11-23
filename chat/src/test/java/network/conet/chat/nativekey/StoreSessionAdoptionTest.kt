package network.conet.chat.nativekey

import network.conet.chat.nativekey.NativeWalletVault.State
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The store-only session (option A). Synthetic data. Positive: NoKey with a plain set of the init account adopts (the key derives
 * the account, so the signer can sign for it). Negative: NoKey with a v3 set does not adopt; another account does not adopt; an absent or unknown
 * store does not adopt; a Ready vault keeps its own path and does not adopt from the store.
 */
class StoreSessionAdoptionTest {

    private val phrase = "fog spot notable regret pizza coffee harvest ensure fog spot notable reflect"
    private val eoa = "0xd49251e1e9f4d4d5bac808861fa4ce23053c986f"
    private val other = "0x2222222222222222222222222222222222222222"
    private val plain = MnemonicSetStore.Current.Found(eoa, MnemonicSetStore.Kind.PLAIN, phrase, 0)

    /** Positive: NoKey with a plain set of this account adopts; the key is the account's key. */
    @Test
    fun noKeyWithAPlainSetOfTheAccountAdopts() {
        val a = StoreSessionAdoption.plainAdoption(State.NoKey, plain, eoa)
        assertTrue(a != null)
        assertEquals(eoa, a!!.eoa)
        assertEquals(eoa, WalletAddress.fromPrivateKey(a.key)?.lowercase())
        a.key.fill(0)
    }

    /** Negative: NoKey with a v3 set does not adopt (it waits for the step (2) passphrase). */
    @Test
    fun noKeyWithAV3SetDoesNotAdopt() {
        val v3 = MnemonicSetStore.Current.Found(eoa, MnemonicSetStore.Kind.V3, "{}", 1)
        assertNull(StoreSessionAdoption.plainAdoption(State.NoKey, v3, eoa))
    }

    /** Negative: a plain set of another account does not adopt for this init account. */
    @Test
    fun aPlainSetOfAnotherAccountDoesNotAdopt() {
        assertNull(StoreSessionAdoption.plainAdoption(State.NoKey, plain, other))
    }

    /** Negative: an absent or unknown store does not adopt. */
    @Test
    fun absentOrUnknownStoreDoesNotAdopt() {
        assertNull(StoreSessionAdoption.plainAdoption(State.NoKey, MnemonicSetStore.Current.Absent, eoa))
        assertNull(StoreSessionAdoption.plainAdoption(State.NoKey, MnemonicSetStore.Current.Unknown("set_missing"), eoa))
    }

    /** Negative: a Ready vault keeps its own path; the store does not adopt on a Ready vault, and a Locked or unreadable vault does not either. */
    @Test
    fun readyLockedAndUnreadableVaultsDoNotAdoptFromTheStore() {
        assertNull(StoreSessionAdoption.plainAdoption(State.Ready(eoa), plain, eoa))
        assertNull(StoreSessionAdoption.plainAdoption(State.Locked("unreadable"), plain, eoa))
        assertNull(StoreSessionAdoption.plainAdoption(null, plain, eoa))
    }
}
