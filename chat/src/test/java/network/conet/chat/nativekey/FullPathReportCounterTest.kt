package network.conet.chat.nativekey

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Test
import java.util.concurrent.atomic.AtomicInteger

/**
 * E9.11.33 r2-amend6 (independent review, §3 of the request): the full-path counter. Every path runs on a counting VaultFiles: the shellRecordRead
 * branches and the pre-read read the report only through LegacyStoreReport.readReport (counted); state(), walletStatus and walletEoaAddress
 * read the report zero times.
 */
class FullPathReportCounterTest {
    private val eoa = DerivedAccount.ADDRESS

    /** A VaultFiles that counts each read of the report name, and nothing else. */
    private class CountingFiles(val inner: VaultFiles) : VaultFiles {
        val reportReads = AtomicInteger(0)
        override fun read(name: String): ByteArray? {
            if (name == ClearFlagFiles.LEGACY_REPORT) reportReads.incrementAndGet()
            return inner.read(name)
        }
        override fun write(name: String, bytes: ByteArray) = inner.write(name, bytes)
        override fun delete(name: String) = inner.delete(name)
        override fun names(): List<String> = inner.names()
    }

    @Test fun everyReportReadComesFromReadReportAndTheStateAndWalletPathsReadNone() {
        val files = CountingFiles(NativeTestFiles())
        files.inner.write(ClearFlagFiles.LEGACY_REPORT, "unreadable".toByteArray(Charsets.UTF_8))
        val readReportCalls = AtomicInteger(0)
        // the device flags over the counting files; the supplier is the one reader (readReport)
        val flags = DeviceFlagFiles(files) {
            readReportCalls.incrementAndGet()
            LegacyStoreReport.readReportIn(files)
        }

        // shellRecordRead: the no-record branches read the report once each (the account is empty)
        val store = SealedPageRecordStore(NativeTestWrap(), NativeTestFiles(), "$eoa:default")
        val accounts = listOf(ShellRecordAccount.Unknown, ShellRecordAccount.Ready(store, eoa), ShellRecordAccount.Locked, ShellRecordAccount.Unreadable)
        for (acc in accounts) {
            for (outcome in listOf<ImportOutcome?>(null, ImportOutcome.ABSENT, ImportOutcome.NOT_DONE, ImportOutcome.LEGACY_UNREADABLE)) {
                ShellRecordBridge(account = { acc }, migrating = { false }, outcome = { outcome }, flags = flags)
                    .handle(ShellOrigin.EMBEDDED_PAGE, JSONObject().put("type", "shellRecordRead").put("reqId", "p"), 40)
            }
        }
        assertEquals("every report read in shellRecordRead is a readReport call", readReportCalls.get(), files.reportReads.get())
        assertEquals("the bridge reached the reader", true, readReportCalls.get() > 0)

        // pre-read: the report is read through the reader only
        val beforePreread = files.reportReads.get()
        val wrap = NativeTestWrap()
        val vault = NativeWalletVault(wrap, files)
        MnemonicPreread.vaultAnswer(vault) { LegacyStoreReport.readReportIn(files) }
        assertEquals("the pre-read reads the report once, through readReport", beforePreread + 1, files.reportReads.get())

        // state(), walletStatus and walletEoaAddress: zero reads of the report
        val beforeState = files.reportReads.get()
        val state = vault.state()
        assertEquals("state() reads no report", beforeState, files.reportReads.get())
        NoKeyGate.walletStatusFor(NoKeyGate.Gate.G0, state)
        assertEquals("walletStatus reads no report", beforeState, files.reportReads.get())
        WalletCredential.eoaAddress(vault, NoKeyGate.Gate.G2)
        assertEquals("walletEoaAddress reads no report", beforeState, files.reportReads.get())
    }
}
