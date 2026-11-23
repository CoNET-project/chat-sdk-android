package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 *  (c) with E9-2 N2′: the G1 reason. g1_uninitialized needs a verified phrase; key_only needs every phrase position read and
 * none valid; a marker alone, an unreadable record, or an unreadable copy is unreadable.
 */
class G1ReasonKeyOnlyTest {
    private val phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

    private fun eoaOf(p: String) = checkNotNull(WalletAddress.fromPrivateKey(checkNotNull(MnemonicDerivation.deriveKey(p))))
    private fun keyOf(p: String) = checkNotNull(MnemonicDerivation.deriveKey(p))

    @Test fun aKeyOnlyRecordWithNoPhraseAnywhereIsKeyOnly() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importKey(eoaOf(phrase), keyOf(phrase)))
        val vault = NativeWalletVault(wrap, files)
        val state = vault.state()
        assertEquals("key_only", NoKeyGate.notReadyReasonOf(state, vault))
    }

    @Test fun aRecordWithAVerifiedPhraseNotYetInitialisedIsG1Uninitialized() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importMnemonicKey(eoaOf(phrase), keyOf(phrase), phrase))
        val vault = NativeWalletVault(wrap, files)
        assertEquals("g1_uninitialized", NoKeyGate.notReadyReasonOf(vault.state(), vault))
    }

    @Test fun anUnreadableIsolatedPhraseCopyIsUnreadableNotKeyOnly() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importKey(eoaOf(phrase), keyOf(phrase)))
        // A phrase copy that cannot be read: its position is not confirmed empty, so key_only is not reported.
        files.map[NativeWalletVault.MNEM + ".isolated.2026-11-18T00:00:00Z.dead0001"] = "not a record".toByteArray(Charsets.UTF_8)
        val vault = NativeWalletVault(wrap, files)
        assertEquals("unreadable", NoKeyGate.notReadyReasonOf(vault.state(), vault))
    }

    @Test fun aMarkerOnlyOrAnUnreadableRecordIsUnreadable() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        val vault = NativeWalletVault(wrap, files)
        assertEquals("unreadable", NoKeyGate.notReadyReasonOf(NativeWalletVault.State.Locked("record_missing"), vault))
        assertEquals("unreadable", NoKeyGate.notReadyReasonOf(NativeWalletVault.State.Locked("unreadable"), vault))
        assertEquals("unreadable", NoKeyGate.notReadyReasonOf(NativeWalletVault.State.Locked("marker_mismatch"), vault))
    }
}
