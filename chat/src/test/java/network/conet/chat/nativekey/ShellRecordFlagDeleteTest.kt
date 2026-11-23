package network.conet.chat.nativekey

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException

/**
 * 25.52Y.84 (coordinator, 2026-11-16): a flag or page-copy removal that does not take effect is a mapped non-success code, never a silent
 * success. Each call site has a test; the import chain and the read path share [clearLegacyCode] and [applyImportMarker].
 */
class ShellRecordFlagDeleteTest {
    /** Flags whose writes or clears throw, as a flag file that cannot be written or removed does. */
    private class FakeFlags(
        private val failSet: Boolean = false,
        private val failClear: Boolean = false,
    ) : DeviceFlags {
        private var pointer = false
        private var legacy = true

        /** True while the legacy marker is set (a clear that did not take effect leaves it set). */
        val legacyMarkerKept: Boolean get() = legacy

        override fun accountPointer(): Boolean = pointer

        override fun setAccountPointer() {
            if (failSet) throw IOException("cannot write")
            pointer = true
        }

        override fun accountAddress(): String? = null

        override fun setAccountAddress(eoa: String) {
            if (failSet) throw IOException("cannot write")
        }

        override fun legacyUnreadable(): Boolean = legacy

        override fun setLegacyUnreadable() {
            if (failSet) throw IOException("cannot write")
            legacy = true
        }

        override fun clearLegacyUnreadable() {
            if (failClear) throw IOException("cannot remove")
            legacy = false
        }
    }

    /** Import, `absent`: the marker clear does not take effect, so the import is import_failed (applyImportMarker, the ABSENT branch). */
    @Test
    fun importAbsentWithAFailedMarkerClearIsImportFailed() {
        assertEquals(ShellImportCode.IMPORT_FAILED, applyImportMarker(FakeFlags(failClear = true), ShellImportCode.ABSENT))
    }

    /** Import, `exists`: the same mapping on the EXISTS branch. */
    @Test
    fun importExistsWithAFailedMarkerClearIsImportFailed() {
        assertEquals(ShellImportCode.IMPORT_FAILED, applyImportMarker(FakeFlags(failClear = true), ShellImportCode.EXISTS))
    }

    /** Import, `import_ok`: the pointer write does not take effect, so the import is not reported as done (the IMPORT_OK branch). */
    @Test
    fun importOkWithAFailedPointerWriteIsImportFailed() {
        assertEquals(ShellImportCode.IMPORT_FAILED, applyImportMarker(FakeFlags(failSet = true), ShellImportCode.IMPORT_OK))
    }

    /** The same branches with flags that take effect keep the code: the mapping only changes a failed flag. */
    @Test
    fun importCodeIsUnchangedWhenTheFlagsTakeEffect() {
        assertEquals(ShellImportCode.IMPORT_OK, applyImportMarker(FakeFlags(), ShellImportCode.IMPORT_OK))
        assertEquals(ShellImportCode.ABSENT, applyImportMarker(FakeFlags(), ShellImportCode.ABSENT))
    }

    /**
     * The read path's `absent` (noRecord, the ABSENT branch) and the readable-record repair (repairFlags) both use [clearLegacyCode]: a clear
     * that does not take effect is clear_incomplete, and a clear that takes effect is null.
     */
    @Test
    fun aFailedLegacyClearIsRecordUnreadableOnTheReadPath() {
        // Read-path sub codes only: record_unreadable is retryable, never clear_incomplete or write_failed.
        assertEquals("record_unreadable", clearLegacyCode(FakeFlags(failClear = true)))
        assertNull(clearLegacyCode(FakeFlags()))
    }

    /** The page-copy removal of this account (SealedPageRecordStore.erase): false when the removal does not take effect, true when it does. */
    @Test
    fun eraseReportsFalseWhenTheRemovalDoesNotTakeEffect() {
        val wrap = NativeTestWrap()
        val base = NativeTestFiles()
        val store = SealedPageRecordStore(wrap, base, "0x2222222222222222222222222222222222222222:default")
        val before = base.map.keys.toSet()
        store.write(JSONObject().put("rev", 1))
        val name = (base.map.keys - before).single()

        val blocked = SealedPageRecordStore(wrap, DeleteFailsFor(base) { it == name }, "0x2222222222222222222222222222222222222222:default")
        assertFalse("a removal that does not take effect is not a success", blocked.erase())
        assertTrue("the copy is still there", base.map.containsKey(name))

        assertTrue("a removal that takes effect is confirmed", SealedPageRecordStore(wrap, base, "0x2222222222222222222222222222222222222222:default").erase())
        assertFalse(base.map.containsKey(name))
    }

    /**
     * Through the page's read (`shellRecordRead`, the ABSENT branch of noRecord): a flag clear that does not take effect answers `ok:true` with
     * result.code `error` and result.sub `record_unreadable` (25.52Y.99). The marker is kept, nothing is removed, and neither clear_incomplete nor
     * write_failed appears on the read path.
     */
    @Test
    fun aFlagClearThatFailsOnTheReadPathAnswersRecordUnreadableAndKeepsTheFlag() {
        val eoa = "0x2222222222222222222222222222222222222222"
        val files = NativeTestFiles()
        val store = SealedPageRecordStore(NativeTestWrap(), files, "$eoa:default")
        val flags = FakeFlags(failClear = true)
        val bridge = ShellRecordBridge(
            account = { ShellRecordAccount.Ready(store, eoa) },
            migrating = { false },
            outcome = { ImportOutcome.ABSENT },
            flags = flags,
        )

        val resp = bridge.handle(ShellOrigin.EMBEDDED_PAGE, JSONObject().put("type", "shellRecordRead").put("reqId", "r1"), 40)

        assertTrue(resp.getBoolean("ok"))
        val result = resp.getJSONObject("result")
        assertEquals("error", result.getString("code"))
        assertEquals("record_unreadable", result.getString("sub"))
        val text = resp.toString()
        assertFalse("no clear_incomplete on the read path", text.contains("clear_incomplete"))
        assertFalse("no write_failed on the read path", text.contains("write_failed"))
        assertNull("nothing is written", store.read())
        assertTrue("the failed clear keeps the flag", flags.legacyMarkerKept)
    }
}
