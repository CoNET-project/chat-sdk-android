package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * LEG-1..4 on the pre-read side (E9.11.29 r2): LEG-1 absent -> Absent; LEG-2 found -> not Absent (Unknown); LEG-3 unreadable -> not Absent (Unknown);
 * LEG-4 (shell did not report) -> not Absent (Unknown). The shellRecordRead answers of LEG-1..4 are the shell-read bridge and are not covered here.
 *
 * Hotfix (S25 pre-read): with no valid native phrase, the pre-read answer is absent only when the shell reported the legacy store absent (PY.15).
 * found, unreadable, a missing report, and a failed read of the report are unknown. A valid native phrase is ready and never reads the report (K.5).
 */
class MnemonicPrereadLegacyTest {
    private val phrase = "legal winner thank year wave sausage worth useful legal winner thank yellow"

    private fun emptyVault(): NativeWalletVault = NativeWalletVault(NativeTestWrap(), NativeTestFiles())

    private fun validVault(): NativeWalletVault {
        val wrap = NativeTestWrap(); val files = NativeTestFiles()
        val key = checkNotNull(MnemonicDerivation.deriveKey(phrase))
        val eoa = checkNotNull(WalletAddress.fromPrivateKey(key))
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importMnemonicKey(eoa, key, phrase))
        return NativeWalletVault(wrap, files)
    }

    @Test fun absentReportOnAnEmptyDeviceIsAbsent() {
        assertTrue(MnemonicPreread.vaultAnswer(emptyVault()) { LegacyReportState.ABSENT } is MnemonicPreread.Answer.Absent)
    }

    @Test fun unreadableReportIsUnknownNotAbsent() {
        assertTrue(MnemonicPreread.vaultAnswer(emptyVault()) { LegacyReportState.UNREADABLE } is MnemonicPreread.Answer.Unknown)
    }

    @Test fun foundReportIsUnknownNotAbsent() {
        assertTrue(MnemonicPreread.vaultAnswer(emptyVault()) { LegacyReportState.FOUND } is MnemonicPreread.Answer.Unknown)
    }

    @Test fun aMissingReportIsUnknownNotAbsent() {
        assertTrue(MnemonicPreread.vaultAnswer(emptyVault()) { LegacyReportState.NOT_REPORTED } is MnemonicPreread.Answer.Unknown)
    }

    @Test fun aFailedReadOfTheReportIsUnknownNotAbsent() {
        val answer = MnemonicPreread.vaultAnswer(emptyVault()) { LegacyReportState.READ_FAILED }
        assertTrue(answer is MnemonicPreread.Answer.Unknown)
    }

    @Test fun aValidNativePhraseIsReadyAndDoesNotReadTheReport() {
        var reads = 0
        val answer = MnemonicPreread.vaultAnswer(validVault()) { reads++; LegacyReportState.FOUND }
        assertTrue("ready", answer is MnemonicPreread.Answer.Valid)
        assertEquals("the report is not read (K.5)", 0, reads)
    }
}
