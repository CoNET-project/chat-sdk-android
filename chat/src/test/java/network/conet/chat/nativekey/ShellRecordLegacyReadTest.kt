package network.conet.chat.nativekey

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException

/**
 * E9.11.29-r2 (K.3) LEG-1..4 at the shellRecordRead bridge (hotfix). No native copy, no pointer. The answer follows the shell's legacy report when no
 * import has run: absent (LEG-1), error import_not_done for found (LEG-2), error legacy_store_unreadable for unreadable (LEG-3, nothing written,
 * retryable), migrating for a missing report (LEG-4). A failed read of the report is record_unreadable, never absent.
 */
class ShellRecordLegacyReadTest {
    private val eoa = DerivedAccount.ADDRESS

    private class FakeFlags(var report: () -> LegacyReportState) : DeviceFlags {
        var setUnreadableCalls = 0
        override fun accountPointer(): Boolean = false
        override fun setAccountPointer() = Unit
        override fun accountAddress(): String? = null
        override fun setAccountAddress(eoa: String) = Unit
        override fun legacyUnreadable(): Boolean = false
        override fun setLegacyUnreadable() { setUnreadableCalls++ }
        override fun clearLegacyUnreadable() = Unit
        override fun legacyReport(): LegacyReportState = report()
    }

    /** A known account whose native copy is empty: the no-record branch. */
    private fun bridge(flags: FakeFlags, outcome: ImportOutcome?, store: SealedPageRecordStore) = ShellRecordBridge(
        account = { ShellRecordAccount.Ready(store, eoa, nativeKeyPresent = false, pointedKeyPresent = false) },
        migrating = { false },
        outcome = { outcome },
        flags = flags,
    )

    private fun read(flags: FakeFlags, outcome: ImportOutcome?): JSONObject {
        val store = SealedPageRecordStore(NativeTestWrap(), NativeTestFiles(), "$eoa:default")
        val req = JSONObject().put("type", "shellRecordRead").put("reqId", "leg")
        val resp = bridge(flags, outcome, store).handle(ShellOrigin.EMBEDDED_PAGE, req, 500, nativeWrite = false)
        return resp.optJSONObject("result") ?: resp
    }

    @Test fun leg1AbsentReportAnswersAbsent() {
        val r = read(FakeFlags { LegacyReportState.ABSENT }, null)
        assertEquals("absent", r.getString("code"))
    }

    @Test fun leg2FoundReportAnswersImportNotDone() {
        val r = read(FakeFlags { LegacyReportState.FOUND }, null)
        assertEquals("error", r.getString("code"))
        assertEquals("import_not_done", r.getString("sub"))
    }

    @Test fun leg3UnreadableReportAnswersLegacyStoreUnreadableWithNothingWritten() {
        val flags = FakeFlags { LegacyReportState.UNREADABLE }
        val r = read(flags, null)
        assertEquals("error", r.getString("code"))
        assertEquals("legacy_store_unreadable", r.getString("sub"))
        assertEquals("nothing is written by the read", 0, flags.setUnreadableCalls)
    }

    @Test fun leg4NoReportAnswersMigrating() {
        val r = read(FakeFlags { LegacyReportState.NOT_REPORTED }, null)
        assertEquals("migrating", r.getString("code"))
    }

    @Test fun aFailedReadOfTheReportIsRecordUnreadableNotAbsent() {
        val r = read(FakeFlags { LegacyReportState.READ_FAILED }, null)
        assertEquals("error", r.getString("code"))
        assertEquals("record_unreadable", r.getString("sub"))
    }

    @Test fun anImportOutcomeUnreadableWithoutAReportAnswersMigratingAndWritesNoMarker() {
        // E9.11.33 r2-amend6 §5.3/§5.6: no report: migrating; the read path writes no marker.
        val flags = FakeFlags { LegacyReportState.NOT_REPORTED }
        val r = read(flags, ImportOutcome.LEGACY_UNREADABLE)
        assertEquals("migrating", r.getString("code"))
        assertEquals(0, flags.setUnreadableCalls)
    }

    @Test fun aReportedUnreadableWinsOverTheOutcomePath() {
        val flags = FakeFlags { LegacyReportState.UNREADABLE }
        val r = read(flags, ImportOutcome.LEGACY_UNREADABLE)
        assertEquals("legacy_store_unreadable", r.getString("sub"))
        assertEquals(0, flags.setUnreadableCalls)
    }

    @Test fun theAnswerIsRetryableOnTheNextRead() {
        var report: LegacyReportState = LegacyReportState.UNREADABLE
        val flags = FakeFlags { report }
        assertEquals("legacy_store_unreadable", read(flags, null).getString("sub"))
        report = LegacyReportState.ABSENT
        assertEquals("absent", read(flags, null).getString("code"))
        assertTrue(true)
    }
}
