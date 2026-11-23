package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * F3 gate (2026-11-20): the orphan-armor settle needs the pre-read to answer Absent, which covers the current phrase, the
 * isolated copies and the legacy report. Paired behaviour tests:
 *  - REC and MARK read faults with the phrase position empty, no copy, legacy report absent -> confirmed (settles, no_key);
 *  - a valid phrase in an isolated copy (current phrase empty) -> not confirmed;
 *  - a read fault on the phrase position -> not confirmed (unknown, not_ready);
 *  - a legacy report that is not absent -> not confirmed.
 * E9.1-3 applies to the Valid direction; the REC/MARK fault does not decide the phrase source.
 */
class NoWalletConfirmedTest {
    private val phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    private val key = checkNotNull(MnemonicDerivation.deriveKey(phrase))
    private val eoa = checkNotNull(WalletAddress.fromPrivateKey(key))

    private fun confirmed(files: NativeTestFiles, report: LegacyStoreReport_State): Boolean =
        noWalletConfirmedBy(MnemonicPreread.vaultAnswerOrUnknown(NativeWalletVault(NativeTestWrap(), files)) { report.state })

    private data class LegacyStoreReport_State(val state: LegacyReportState)

    @Test
    fun recAndMarkFaultsWithAnEmptyPhraseSourceAreConfirmedAbsent() {
        val files = NativeTestFiles()
        files.failRead = { name -> name == NativeWalletVault.REC || name == NativeWalletVault.MARK }
        assertTrue("E9.1-3: the REC/MARK fault does not decide; the empty phrase source is no wallet", confirmed(files, LegacyStoreReport_State(LegacyReportState.ABSENT)))
    }

    @Test
    fun aValidPhraseInAnIsolatedCopyIsNotConfirmedAbsent() {
        val files = NativeTestFiles()
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(NativeTestWrap(), files).importMnemonicKey(eoa, key, phrase))
        // The current phrase position is emptied; the same valid phrase stays in an isolated copy.
        val copy = files.map[NativeWalletVault.MNEM]!!.copyOf()
        files.map.remove(NativeWalletVault.MNEM)
        files.map["${NativeWalletVault.MNEM}.isolated.20261120T000000Z00000000"] = copy
        files.failRead = { name -> name == NativeWalletVault.REC || name == NativeWalletVault.MARK }
        assertFalse("a copy holding a valid phrase is an account source, not absent", confirmed(files, LegacyStoreReport_State(LegacyReportState.ABSENT)))
    }

    @Test
    fun aPhrasePositionReadFaultIsNotConfirmed() {
        val files = NativeTestFiles()
        files.failRead = { name -> name == NativeWalletVault.MNEM }
        assertFalse("the phrase-position fault is unknown", confirmed(files, LegacyStoreReport_State(LegacyReportState.ABSENT)))
    }

    @Test
    fun aLegacyReportThatIsNotAbsentIsNotConfirmed() {
        val files = NativeTestFiles()
        assertFalse("without the shell's absent report the native source alone is not enough", confirmed(files, LegacyStoreReport_State(LegacyReportState.NOT_REPORTED)))
    }

    /** a read fault on a sealed copy of the phrase source is unknown, even when the current phrase position is empty. */
    @Test
    fun aSealedCopyReadFaultWithAnEmptyCurrentPhraseIsNotConfirmed() {
        val files = NativeTestFiles()
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(NativeTestWrap(), files).importMnemonicKey(eoa, key, phrase))
        val copyName = "${NativeWalletVault.MNEM}.isolated.20261120T000000Z00000000"
        files.map[copyName] = files.map[NativeWalletVault.MNEM]!!.copyOf()
        files.map.remove(NativeWalletVault.MNEM)
        files.failRead = { name -> name == NativeWalletVault.REC || name == NativeWalletVault.MARK || name == copyName }
        assertFalse("a sealed copy that cannot be read is unknown, never confirmed absent", confirmed(files, LegacyStoreReport_State(LegacyReportState.ABSENT)))
    }
}

/** walletStatus no_key and the orphan-armor settle share one judgment; the module guard is a source guard (the module is not unit-constructible). */
class WalletStatusNoKeyJudgmentTest {
    private val module: String by lazy {
        java.io.File("src/main/java/network/conet/chat/BeamioConetChatModule.kt").readText(Charsets.UTF_8)
    }

    @Test
    fun walletStatusNoKeyNeedsTheSameConfirmedAbsentJudgment() {
        val route = module.substringAfter("NoKeyGate.Route.WALLET_STATUS -> {").substringBefore("NoKeyGate.Route.PASSCODE_STATUS -> {")
        val judgment = route.indexOf("noWalletConfirmedBy(")
        val answer = route.indexOf("NoKeyGate.walletStatusFor(statusGate, state")
        assertTrue("the shared judgment is applied on the walletStatus route", judgment > 0)
        assertTrue("it comes before the walletStatus answer", judgment in 0 until answer)
        assertTrue("it reads the pre-read over every phrase source", route.contains("MnemonicPreread.vaultAnswerOrUnknown("))
    }
}
