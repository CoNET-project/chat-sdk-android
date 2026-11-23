package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

/**
 * after an identity clear the retained mnemonic sets are not re-adopted automatically. The identity_cleared
 * marker makes the store answer absent; no set file and no pointer byte changes; an explicit write of a new set releases the marker.
 */
class IdentityClearedStoreTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private val eoa = "0xd49251e1e9f4d4d5bac808861fa4ce23053c986f"
    private val phrase = "fog spot notable regret pizza coffee harvest ensure fog spot notable reflect"

    private fun store() = MnemonicSetStore(File(tmp.root, MnemonicSetStore.DIRECTORY))
    private fun pointer() = File(tmp.root, "${MnemonicSetStore.DIRECTORY}/current.v1")
    private fun setFile() = File(tmp.root, "${MnemonicSetStore.DIRECTORY}/set.$eoa.plain.1.v1")

    /** Positive: the marker makes the retained set absent; the set file and the pointer keep their bytes. */
    @Test
    fun theMarkerAnswersAbsentAndChangesNoBytes() {
        val s = store()
        assertTrue(s.writePlain(eoa, phrase) is MnemonicSetStore.Write.Stored)
        val setBytes = setFile().readBytes()
        val pointerBytes = pointer().readBytes()
        assertFalse(s.identityCleared())
        assertTrue(s.markIdentityCleared())
        assertTrue(s.identityCleared())
        assertTrue("the store answers absent after the clear", s.current() is MnemonicSetStore.Current.Absent)
        assertTrue("the retained set file is kept byte for byte", setFile().readBytes().contentEquals(setBytes))
        assertTrue("the pointer is not written", pointer().readBytes().contentEquals(pointerBytes))
    }

    /**
     * after the identity clear the PWA re-provisions. A successful pwaWalletSync write of another account releases
     * the marker and that account answers normally; before that nothing is adopted.
     */
    @Test
    fun aPwaReprovisionOfAnotherAccountReleasesTheMarker() {
        val s = store()
        s.writePlain(eoa, phrase)
        s.markIdentityCleared()
        assertTrue("nothing is adopted before the PWA re-provisions", s.current() is MnemonicSetStore.Current.Absent)
        val otherPhrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        val derived = MnemonicDerivation.deriveKey(otherPhrase)?.let { WalletAddress.fromPrivateKey(it) }?.lowercase()
        assertTrue("the other synthetic phrase derives an account", derived != null)
        assertTrue(s.writePlain(derived!!, otherPhrase) is MnemonicSetStore.Write.Stored)
        assertFalse("the successful write releases the marker", s.identityCleared())
        val current = s.current() as MnemonicSetStore.Current.Found
        assertEquals("the re-provisioned account answers normally", derived, current.eoa)
    }

    /** Positive: an explicit write of a new set (a restore or an import) releases the marker and the set answers again. */
    @Test
    fun anExplicitWriteReleasesTheMarker() {
        val s = store()
        s.writePlain(eoa, phrase)
        s.markIdentityCleared()
        assertTrue(s.current() is MnemonicSetStore.Current.Absent)
        val again = (s.stagePlain(eoa, phrase) as MnemonicSetStore.Stage.Ready).staged
        assertTrue("the same phrase is idempotent and the commit still releases the marker", again.commit())
        assertFalse(s.identityCleared())
        assertTrue(s.current() is MnemonicSetStore.Current.Found)
    }
}
