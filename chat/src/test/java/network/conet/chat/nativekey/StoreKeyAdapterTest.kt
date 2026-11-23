package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

/**
 * The read-only key source of the store (step 1). Synthetic data. Positive: a plain set gives the key of its EOA, and the store is unchanged.
 * Negative: a v3 set, an absent store, an unknown state, and a set whose phrase does not derive its EOA give no key.
 */
class StoreKeyAdapterTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private val phrase = "fog spot notable regret pizza coffee harvest ensure fog spot notable reflect"
    private val eoa = "0xd49251e1e9f4d4d5bac808861fa4ce23053c986f"

    /** Positive: a plain current set derives its own EOA's key; the store files do not change. */
    @Test
    fun aPlainSetGivesTheKeyOfItsEoaAndLeavesTheStoreUnchanged() {
        val store = MnemonicSetStore(File(tmp.root, MnemonicSetStore.DIRECTORY))
        store.writePlain(eoa, phrase)
        val before = File(tmp.root, "${MnemonicSetStore.DIRECTORY}/set.$eoa.plain.1.v1").readBytes()
        val key = StoreKeyAdapter.plainKey(store.current())
        assertNotNull(key)
        assertEquals(eoa, WalletAddress.fromPrivateKey(key!!)?.lowercase())
        key.fill(0)
        assertEquals(true, before.contentEquals(File(tmp.root, "${MnemonicSetStore.DIRECTORY}/set.$eoa.plain.1.v1").readBytes()))
    }

    /** Negative: a v3 set gives no key here (the passcode is not in this step). */
    @Test
    fun aV3SetGivesNoKeyHere() {
        val store = MnemonicSetStore(File(tmp.root, MnemonicSetStore.DIRECTORY))
        store.writeEnvelope(MnemonicCipherV3.seal(eoa, "482913", phrase, MnemonicCipherV3.newSalt(), MnemonicCipherV3.newIv()))
        assertNull(StoreKeyAdapter.plainKey(store.current()))
    }

    /** Negative: an absent store and an unknown state give no key. */
    @Test
    fun absentAndUnknownGiveNoKey() {
        val store = MnemonicSetStore(File(tmp.root, MnemonicSetStore.DIRECTORY))
        assertNull(StoreKeyAdapter.plainKey(store.current()))
        assertNull(StoreKeyAdapter.plainKey(MnemonicSetStore.Current.Unknown("set_missing")))
    }

    /** Negative: a plain set whose phrase does not derive the set's EOA gives no key. */
    @Test
    fun aPhraseThatDoesNotDeriveTheSetEoaGivesNoKey() {
        val other = "0x2222222222222222222222222222222222222222"
        assertNull(StoreKeyAdapter.plainKey(MnemonicSetStore.Current.Found(other, MnemonicSetStore.Kind.PLAIN, phrase, 0)))
    }
}
