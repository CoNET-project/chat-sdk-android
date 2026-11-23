package network.conet.chat.nativekey

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 *  (b): after a rollback moves the pending marker to an isolated name (keepMarkerAsIsolated), the old record has been read
 * back byte for byte before the marker is kept, so the account is ready and it is the old account, with its own bytes.
 */
class OverwriteRollbackResidueTest {
    private val phraseA = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    private val phraseB = "legal winner thank year wave sausage worth useful legal winner thank yellow"

    private fun keyOf(p: String) = checkNotNull(MnemonicDerivation.deriveKey(p))
    private fun eoaOf(p: String) = checkNotNull(WalletAddress.fromPrivateKey(keyOf(p)))

    @Test fun aMarkerKeptAfterAConfirmedRestoreLeavesTheOldAccountReadyWithItsOwnBytes() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        val eoaA = eoaOf(phraseA)
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importMnemonicKey(eoaA, keyOf(phraseA), phraseA))
        val oldRec = files.map[NativeWalletVault.REC]!!.copyOf()
        val oldMnem = files.map[NativeWalletVault.MNEM]!!.copyOf()
        // The new record fails before any fixed name is written: the restore of the old copy is confirmed, and the marker is kept as isolated.
        files.failWrite = NativeWalletVault.REC
        assertEquals(NativeWalletVault.SyncOutcome.WRITE_FAILED,
            NativeWalletVault(wrap, files).syncPhrase(eoaOf(phraseB), keyOf(phraseB), phraseB))
        assertTrue("the marker was moved to an isolated name", files.map.keys.none { it == NativeWalletVault.PENDING })
        val fresh = NativeWalletVault(wrap, files)
        val state = fresh.state()
        assertTrue("the old account is ready: $state", state is NativeWalletVault.State.Ready)
        assertEquals("the EOA is the old account, not the new phrase's", eoaA, (state as NativeWalletVault.State.Ready).eoa)
        assertArrayEquals("the record bytes are the old ones", oldRec, files.map[NativeWalletVault.REC])
        assertArrayEquals("the phrase bytes are the old ones", oldMnem, files.map[NativeWalletVault.MNEM])
    }
}
