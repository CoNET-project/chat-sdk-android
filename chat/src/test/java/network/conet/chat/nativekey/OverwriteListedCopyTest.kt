package network.conet.chat.nativekey

import org.json.JSONObject
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 *  on the unsettled overwrite (2026-11-18, the scene "覆盖尚未结清"): when the pending marker carries overwrite=true and lists an isolated
 * phrase copy that does not read, and there is no other valid copy, the pre-read answers unknown (not absent). A marker without the field keeps the
 * 2026-11-17 behaviour (the listed unreadable copy is ignored, so absent). Each window is produced by the real overwrite path.
 */
class OverwriteListedCopyTest {
    private val phraseA = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    private val phraseB = "legal winner thank year wave sausage worth useful legal winner thank yellow"
    private fun keyOf(p: String) = checkNotNull(MnemonicDerivation.deriveKey(p))
    private fun eoaOf(p: String) = checkNotNull(WalletAddress.fromPrivateKey(keyOf(p)))
    private val base = NativeTestWrap()
    private val wrap: KeyWrap = object : KeyWrap by base { override fun presence(): WrapKeyPresence = WrapKeyPresence.PRESENT }

    /** The overwrite window (crash after the new record), then the listed phrase copy of A is made unreadable (deterministic corruption). */
    private fun windowWithListedCopyUnreadable(): NativeTestFiles {
        val files = NativeTestFiles()
        assertTrue(NativeWalletVault(wrap, files).importMnemonicKey(eoaOf(phraseA), keyOf(phraseA), phraseA) == NativeWalletVault.Import.OK)
        files.crashAfterWrite = NativeWalletVault.REC
        try {
            NativeWalletVault(wrap, files).syncPhrase(eoaOf(phraseB), keyOf(phraseB), phraseB)
        } catch (_: NativeTestCrash) {
        }
        files.crashAfterWrite = null
        val listed = files.map.keys.single { it.startsWith("${NativeWalletVault.MNEM}.isolated.") }
        files.map[listed] = JSONObject().put("record", NativeWalletVault.RECORD_VERSION).put("eoa", eoaOf(phraseA)).put("sealed", "00".repeat(40))
            .toString().toByteArray(Charsets.UTF_8)
        return files
    }

    /** The same window with the overwrite field removed from the marker: the 2026-11-17 format. */
    private fun withoutTheOverwriteField(files: NativeTestFiles): NativeTestFiles {
        val raw = files.map.getValue(NativeWalletVault.PENDING)
        files.map[NativeWalletVault.PENDING] = JSONObject(String(raw, Charsets.UTF_8)).also { it.remove("overwrite") }
            .toString().toByteArray(Charsets.UTF_8)
        return files
    }

    /** The production overload: the legacy report decides the absent answer. */
    private fun production(files: NativeTestFiles, legacy: LegacyReportState) =
        MnemonicPreread.vaultAnswer(NativeWalletVault(wrap, files)) { legacy }

    @Test fun anUnsettledOverwriteWithAListedUnreadableCopyAndNoOtherValidCopyIsUnknown() {
        val files = windowWithListedCopyUnreadable()
        assertTrue("the marker is an overwrite", NativeWalletVault(wrap, files).overwriteMarkerNew())
        assertTrue("unknown, not absent: ${production(files, LegacyReportState.ABSENT)}",
            production(files, LegacyReportState.ABSENT) is MnemonicPreread.Answer.Unknown)
    }

    @Test fun theSameWindowInTheOldFormatKeepsItsAnswer() {
        val files = withoutTheOverwriteField(windowWithListedCopyUnreadable())
        assertTrue("no overwrite field", !NativeWalletVault(wrap, files).overwriteMarkerNew())
        assertTrue("absent as before (2026-11-17 behaviour): ${production(files, LegacyReportState.ABSENT)}",
            production(files, LegacyReportState.ABSENT) is MnemonicPreread.Answer.Absent)
    }
}
