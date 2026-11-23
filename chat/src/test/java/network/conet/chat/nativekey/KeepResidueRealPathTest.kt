package network.conet.chat.nativekey

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Keep residue on the production path. keepAsIsolated (the rollback of isolateWrittenRecords, used by NativeAccountCreate) writes a keep entry
 * before the move and removes it after a successful audit row. A keep entry stays only when the audit row fails; the next write settles it
 * (reconcileOrphanAudits, removeKeepEntries). This test follows that real path and checks the keep entry never carries the overwrite field.
 */
class KeepResidueRealPathTest {
    private val phraseA = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    private val phraseB = "legal winner thank year wave sausage worth useful legal winner thank yellow"
    private fun keyOf(p: String) = checkNotNull(MnemonicDerivation.deriveKey(p))
    private fun eoaOf(p: String) = checkNotNull(WalletAddress.fromPrivateKey(keyOf(p)))

    @Test fun aKeepEntryFromAFailedAuditRowIsNotAnOverwriteAndTheNextWriteSettlesIt() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importMnemonicKey(eoaOf(phraseA), keyOf(phraseA), phraseA))
        // The rollback moves the fixed names aside; the audit row of the first move cannot be written, so its keep entry stays.
        files.failWrite = NativeWalletVault.AUDIT
        NativeWalletVault(wrap, files).isolateWrittenRecords(mnemonicPlanned = true)
        files.failWrite = null
        val pending = JSONObject(String(files.map.getValue(NativeWalletVault.PENDING), Charsets.UTF_8))
        val items = pending.getJSONArray("items")
        assertTrue("the residue is keep entries", items.length() > 0 && (0 until items.length()).all { items.getJSONObject(it).optString("kind") == "keep" })
        assertFalse("a keep entry never carries the overwrite field", pending.has("overwrite"))
        assertFalse("not an unsettled overwrite", NativeWalletVault(wrap, files).overwriteIntentUnsettled())
        // The next write runs the settle first: the keep entries are settled (backfilled and removed) and the first account is back under its fixed
        // names. The new write is then refused because an account exists (RECORD_EXISTS), so nothing is overwritten.
        val next = NativeWalletVault(wrap, files).importMnemonicKey(eoaOf(phraseB), keyOf(phraseB), phraseB)
        val stateAfter = NativeWalletVault(wrap, files).state()
        assertEquals("the next write is refused because the first account exists", NativeWalletVault.Import.RECORD_EXISTS, next)
        assertTrue("the first account is ready again: $stateAfter", stateAfter is NativeWalletVault.State.Ready)
        assertEquals("it is the first account", eoaOf(phraseA), (stateAfter as NativeWalletVault.State.Ready).eoa)
        val keepLeft = files.map[NativeWalletVault.PENDING]?.let { JSONObject(String(it, Charsets.UTF_8)).getJSONArray("items").length() } ?: 0
        assertEquals("no keep entry left", 0, keepLeft)
    }
}
