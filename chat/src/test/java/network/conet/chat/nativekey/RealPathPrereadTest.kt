package network.conet.chat.nativekey

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * E3: positive and negative pre-read cases, each produced by the real write path (no hand-written marker), with the 2026-11-18
 * decision: an unsettled overwrite is unknown; a first-write half window, an import residue, a settled move and a marker written without the field
 * keep their answers. A locked overwrite is not reported absent and is not written over.
 */
class RealPathPrereadTest {
    private val phraseA = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    private val phraseB = "legal winner thank year wave sausage worth useful legal winner thank yellow"
    private fun keyOf(p: String) = checkNotNull(MnemonicDerivation.deriveKey(p))
    private fun eoaOf(p: String) = checkNotNull(WalletAddress.fromPrivateKey(keyOf(p)))
    private val wrap = NativeTestWrap()

    private fun answer(files: NativeTestFiles) = MnemonicPreread.vaultAnswerOrUnknown(NativeWalletVault(wrap, files))

    // ---- positives: an unsettled overwrite is unknown ----

    @Test fun positiveAnInterruptedOverwriteIsUnknown() {
        val files = NativeTestFiles()
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importMnemonicKey(eoaOf(phraseA), keyOf(phraseA), phraseA))
        files.crashAfterWrite = NativeWalletVault.REC
        try { NativeWalletVault(wrap, files).syncPhrase(eoaOf(phraseB), keyOf(phraseB), phraseB) } catch (_: NativeTestCrash) {}
        files.crashAfterWrite = null
        assertTrue("unknown: ${answer(files)}", answer(files) is MnemonicPreread.Answer.Unknown)
    }

    @Test fun positiveAnOverwriteRolledForwardStaysUnknown() {
        // Covered with the field check in OverwriteFlagPathsTest.aRollForwardKeepsTheOverwriteFieldAndTheAnswerStaysUnknown.
        val files = NativeTestFiles()
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importMnemonicKey(eoaOf(phraseA), keyOf(phraseA), phraseA))
        files.crashAfterWrite = NativeWalletVault.REC
        try { NativeWalletVault(wrap, files).syncPhrase(eoaOf(phraseB), keyOf(phraseB), phraseB) } catch (_: NativeTestCrash) {}
        files.crashAfterWrite = null
        files.failWrite = NativeWalletVault.COMMIT
        NativeWalletVault(wrap, files).settleForWrite()
        files.failWrite = null
        assertTrue("unknown after roll-forward", answer(files) is MnemonicPreread.Answer.Unknown)
    }

    // ---- negatives: the other cases keep their answers ----

    @Test fun negativeAFirstWriteInterruptedBeforeTheCommitKeepsItsAnswer() {
        val files = NativeTestFiles()
        files.crashAfterWrite = NativeWalletVault.COMMIT
        try { NativeWalletVault(wrap, files).importMnemonicKey(eoaOf(phraseA), keyOf(phraseA), phraseA) } catch (_: NativeTestCrash) {}
        files.crashAfterWrite = null
        assertFalse("a first write writes no overwrite marker", NativeWalletVault(wrap, files).overwriteIntentUnsettled())
        // E9.1-1 (first write, half window): the phrase at the fixed position reads and verifies, so valid.
        assertTrue("valid under E9.1-1: ${answer(files)}", answer(files) is MnemonicPreread.Answer.Valid)
    }

    @Test fun negativeAnImportResidueMarkIsValid() {
        val files = NativeTestFiles()
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importMnemonicKey(eoaOf(phraseA), keyOf(phraseA), phraseA))
        assertTrue("the import left a MARK", files.map.containsKey(NativeWalletVault.MARK))
        assertFalse("not an overwrite", NativeWalletVault(wrap, files).overwriteIntentUnsettled())
        assertTrue("valid", answer(files) is MnemonicPreread.Answer.Valid)
    }

    @Test fun negativeAnOverwriteThatRolledBackAndWasKeptAsIsolatedIsNotUnknownByTheMarker() {
        val files = NativeTestFiles()
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importMnemonicKey(eoaOf(phraseA), keyOf(phraseA), phraseA))
        files.failWrite = NativeWalletVault.REC
        assertEquals(NativeWalletVault.SyncOutcome.WRITE_FAILED, NativeWalletVault(wrap, files).syncPhrase(eoaOf(phraseB), keyOf(phraseB), phraseB))
        assertFalse("the marker was kept as isolated", files.map.containsKey(NativeWalletVault.PENDING))
        assertFalse(NativeWalletVault(wrap, files).overwriteIntentUnsettled())
        assertTrue("the old account answers valid", answer(files) is MnemonicPreread.Answer.Valid)
    }

    // ---- locked overwrite: not absent, not written over ----

    @Test fun lockedOverwriteIsNotAbsentAndNotWrittenOver() {
        val files = NativeTestFiles()
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importMnemonicKey(eoaOf(phraseA), keyOf(phraseA), phraseA))
        files.crashAfterWrite = NativeWalletVault.REC
        try { NativeWalletVault(wrap, files).syncPhrase(eoaOf(phraseB), keyOf(phraseB), phraseB) } catch (_: NativeTestCrash) {}
        files.crashAfterWrite = null
        val before = files.map.mapValues { it.value.copyOf() }
        assertFalse("not absent", answer(files) is MnemonicPreread.Answer.Absent)
        val answer = NativeWalletVault(wrap, files).syncPhrase(eoaOf(phraseA), keyOf(phraseA), phraseA)
        assertTrue("the sync does not write over an unsettled overwrite: $answer", answer != NativeWalletVault.SyncOutcome.UPDATED)
        assertEquals(before.keys, files.map.keys)
        before.forEach { (name, bytes) -> assertArrayEquals("$name unchanged", bytes, files.map[name]) }
    }
}
