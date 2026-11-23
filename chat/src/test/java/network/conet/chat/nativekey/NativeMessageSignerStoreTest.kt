package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

/**
 * The signing path from the current set of the store (order step 1, signing). Synthetic data. Positive: a plain current set signs with its
 * own account key (ok, the address of the set's EOA, a 65-byte signature). Negative: a v3 set, an absent store, and an unknown state give no
 * store signature (null: the vault fallback follows); a bad kind refuses even from the store.
 */
class NativeMessageSignerStoreTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private val phrase = "fog spot notable regret pizza coffee harvest ensure fog spot notable reflect"
    private val eoa = "0xd49251e1e9f4d4d5bac808861fa4ce23053c986f"
    private val message = "synthetic signing text".toByteArray(Charsets.UTF_8)

    /** Positive: a plain current set signs; the address is the set's EOA and the signature is 65 bytes (0x + 130 hex). */
    @Test
    fun aPlainCurrentSetSignsWithItsOwnKey() {
        val store = MnemonicSetStore(File(tmp.root, MnemonicSetStore.DIRECTORY))
        store.writePlain(eoa, phrase)
        val out = NativeMessageSigner.signFromStore(store.current(), NativeMessageSigner.KIND_ENVELOPE, message)
        assertEquals("ok", out!!.code)
        assertEquals(eoa, out.address)
        assertTrue(out.value!!.matches(Regex("^0x[0-9a-fA-F]{130}$")))
    }

    /** Negative: a v3 set gives no store signature here (the passcode is not in this step). */
    @Test
    fun aV3SetGivesNoStoreSignature() {
        val store = MnemonicSetStore(File(tmp.root, MnemonicSetStore.DIRECTORY))
        store.writeEnvelope(MnemonicCipherV3.seal(eoa, "482913", phrase, MnemonicCipherV3.newSalt(), MnemonicCipherV3.newIv()))
        assertNull(NativeMessageSigner.signFromStore(store.current(), NativeMessageSigner.KIND_ENVELOPE, message))
    }

    /** Negative: an absent store and an unknown state give no store signature (null), so the vault fallback decides. */
    @Test
    fun absentAndUnknownGiveNoStoreSignature() {
        val store = MnemonicSetStore(File(tmp.root, MnemonicSetStore.DIRECTORY))
        assertNull(NativeMessageSigner.signFromStore(store.current(), NativeMessageSigner.KIND_ENVELOPE, message))
        assertNull(NativeMessageSigner.signFromStore(MnemonicSetStore.Current.Unknown("set_missing"), NativeMessageSigner.KIND_ENVELOPE, message))
    }

    /** Negative: a bad kind is refused even from the store (the same refusal as the vault path). */
    @Test
    fun aBadKindIsRefusedFromTheStore() {
        val store = MnemonicSetStore(File(tmp.root, MnemonicSetStore.DIRECTORY))
        store.writePlain(eoa, phrase)
        assertEquals("kind", NativeMessageSigner.signFromStore(store.current(), "not_a_kind", message)!!.code)
    }

    /** Positive (store-primary): a plain set answers whatever the vault holds. */
    @Test
    fun aPlainSetAnswersWhateverTheVaultHolds() {
        val current = MnemonicSetStore.Current.Found(eoa, MnemonicSetStore.Kind.PLAIN, phrase, 0)
        assertTrue(NativeMessageSigner.storeMayAnswer(current))
    }

    /** Negative: an absent or unknown store never answers; the store does not answer for a v3 set without the session. */
    @Test
    fun anAbsentOrUnknownStoreDoesNotAnswer() {
        assertFalse(NativeMessageSigner.storeMayAnswer(MnemonicSetStore.Current.Absent))
        assertFalse(NativeMessageSigner.storeMayAnswer(MnemonicSetStore.Current.Unknown("set_missing")))
    }
}
