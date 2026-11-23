package network.conet.chat.nativekey

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Fault injection (project 2026-11-18, keep residue): keepAsIsolated runs addPendingEntry(kind=keep), then the rename, then appendAudit, then
 * removePendingEntry. A crash after the audit row and before the removal leaves a settled keep residue with the fixed names still present.
 * Each test injects the crash on the real path (NativeTestFiles.crashAfterWrite on the audit file) and asks the real pre-read.
 */
class KeepCrashWindowTest {
    private val phraseA = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    private fun keyOf(p: String) = checkNotNull(MnemonicDerivation.deriveKey(p))
    private fun eoaOf(p: String) = checkNotNull(WalletAddress.fromPrivateKey(keyOf(p)))
    private val wrap = NativeTestWrap()

    /** A complete import of A, then the production isolation with a crash right after the first audit row (before the keep entry is removed). */
    private fun crashBetweenAuditAndRemoval(): NativeTestFiles {
        val files = NativeTestFiles()
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importMnemonicKey(eoaOf(phraseA), keyOf(phraseA), phraseA))
        files.crashAfterWrite = NativeWalletVault.AUDIT
        try {
            NativeWalletVault(wrap, files).isolateWrittenRecords(mnemonicPlanned = true)
        } catch (_: NativeTestCrash) {
        }
        files.crashAfterWrite = null
        return files
    }

    private fun keepEntries(files: NativeTestFiles): List<JSONObject> {
        val raw = files.map[NativeWalletVault.PENDING] ?: return emptyList()
        val items = JSONObject(String(raw, Charsets.UTF_8)).getJSONArray("items")
        return (0 until items.length()).map { items.getJSONObject(it) }.filter { it.optString("kind") == "keep" }
    }

    @Test fun aCrashBetweenTheAuditRowAndTheKeepRemovalLeavesAKeepResidueThatIsValid() {
        val files = crashBetweenAuditAndRemoval()
        // The residue is real: a keep entry remains, its audit row exists, and the fixed phrase record is still in place.
        assertTrue("a keep entry remains", keepEntries(files).isNotEmpty())
        assertTrue("the audit row of the move exists", String(files.map.getValue(NativeWalletVault.AUDIT), Charsets.UTF_8).contains("\"isolated\""))
        assertTrue("the fixed phrase record is still there", files.map.containsKey(NativeWalletVault.MNEM))
        assertFalse("the residue is a keep entry, not an overwrite", NativeWalletVault(wrap, files).overwriteIntentUnsettled())
        // The real pre-read: not an overwrite, so the valid account answers valid.
        assertTrue("valid: ${MnemonicPreread.vaultAnswerOrUnknown(NativeWalletVault(wrap, files))}",
            MnemonicPreread.vaultAnswerOrUnknown(NativeWalletVault(wrap, files)) is MnemonicPreread.Answer.Valid)
    }

    @Test fun theSameResidueAfterTheOrphanAuditScanIsStillValid() {
        val files = crashBetweenAuditAndRemoval()
        assertTrue("a keep entry remains before the scan", keepEntries(files).isNotEmpty())
        // The orphan audit scan runs at the next settle (reconcileOrphanAudits): it finishes the bookkeeping, then the pre-read is taken again.
        assertTrue("the scan completes", NativeWalletVault(wrap, files).reconcileOrphanAudits())
        assertTrue("valid after the scan: ${MnemonicPreread.vaultAnswerOrUnknown(NativeWalletVault(wrap, files))}",
            MnemonicPreread.vaultAnswerOrUnknown(NativeWalletVault(wrap, files)) is MnemonicPreread.Answer.Valid)
    }

    /**
     * A separate window (registered apart from the settled residue above): the crash lands after addPendingEntry (the keep entry
     * is written) and before the rename. Nothing has moved, so the fixed names are intact, and the real pre-read answers valid.
     */
    @Test fun aCrashBeforeTheRenameLeavesAKeepEntryWithNothingMovedAndTheRealPreReadIsValid() {
        val files = NativeTestFiles()
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importMnemonicKey(eoaOf(phraseA), keyOf(phraseA), phraseA))
        val fixedBefore = files.map.filterKeys { it == NativeWalletVault.REC || it == NativeWalletVault.MNEM || it == NativeWalletVault.COMMIT }
            .mapValues { it.value.copyOf() }
        files.crashAfterWrite = NativeWalletVault.PENDING
        try {
            NativeWalletVault(wrap, files).isolateWrittenRecords(mnemonicPlanned = true)
        } catch (_: NativeTestCrash) {
        }
        files.crashAfterWrite = null
        // The keep entry was written before the rename; the rename did not happen.
        assertTrue("a keep entry was written", keepEntries(files).isNotEmpty())
        assertTrue("nothing was moved: the fixed names are intact", fixedBefore.all { (name, bytes) -> files.map[name]?.contentEquals(bytes) == true })
        assertFalse("no isolated copy exists", files.map.keys.any { it.contains(".isolated.") })
        assertFalse("not an overwrite", NativeWalletVault(wrap, files).overwriteIntentUnsettled())
        assertTrue("valid: ${MnemonicPreread.vaultAnswerOrUnknown(NativeWalletVault(wrap, files))}",
            MnemonicPreread.vaultAnswerOrUnknown(NativeWalletVault(wrap, files)) is MnemonicPreread.Answer.Valid)
    }
}
