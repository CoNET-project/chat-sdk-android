package network.conet.chat.nativekey

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.atomic.AtomicInteger

/**
 * E9.11.33 r2-amend6 §5.3 / §5.4 / §5.6 and §5.7 (item 4) at the bridge: the report first, then the import outcome; the storage lock; the marker
 * rules (no write from a read or an unreadable import; clears only on absent, on a valid copy, and on a successful import).
 */
class ShellRecordReportAnswersTest {
    private val eoa = DerivedAccount.ADDRESS

    /** Device flags that record every write and clear, with a fixed report. */
    private class RecordingFlags(private val state: LegacyReportState, private val marker: Boolean = false) : DeviceFlags {
        val sets = AtomicInteger(0)
        val clears = AtomicInteger(0)
        override fun accountPointer(): Boolean = false
        override fun setAccountPointer() = Unit
        override fun accountAddress(): String? = null
        override fun setAccountAddress(eoa: String) = Unit
        override fun legacyUnreadable(): Boolean = marker
        override fun setLegacyUnreadable() { sets.incrementAndGet() }
        override fun clearLegacyUnreadable() { clears.incrementAndGet() }
        override fun legacyReport(): LegacyReportState = state
    }

    private fun read(account: ShellRecordAccount, outcome: ImportOutcome?, flags: DeviceFlags, migrating: Boolean = false): JSONObject =
        ShellRecordBridge(
            account = { account },
            migrating = { migrating },
            outcome = { outcome },
            flags = flags,
        ).handle(ShellOrigin.EMBEDDED_PAGE, JSONObject().put("type", "shellRecordRead").put("reqId", "t"), 40).v()

    // B-5: a reported FOUND with an ABSENT import answers import_not_done (not absent).
    @Test fun b5ReportedFoundWithAnAbsentImportIsImportNotDone() {
        val flags = RecordingFlags(LegacyReportState.FOUND)
        val r = read(ShellRecordAccount.Unknown, ImportOutcome.ABSENT, flags)
        assertEquals("import_not_done", r.getString("sub"))
        assertEquals(0, flags.sets.get())
    }

    // B-6: a reported ABSENT is absent even when this start's import reported the store unreadable.
    @Test fun b6ReportedAbsentWinsOverAnUnreadableImport() {
        val flags = RecordingFlags(LegacyReportState.ABSENT)
        val r = read(ShellRecordAccount.Unknown, ImportOutcome.LEGACY_UNREADABLE, flags)
        assertEquals("absent", r.getString("code"))
        assertEquals(0, flags.sets.get())
    }

    // R2A5: a reported ABSENT clears the marker; an UNREADABLE report neither clears nor writes; a FOUND that is not imported neither clears nor writes.
    @Test fun r2a5AbsentClearsTheMarker() {
        val flags = RecordingFlags(LegacyReportState.ABSENT, marker = true)
        assertEquals("absent", read(ShellRecordAccount.Unknown, null, flags).getString("code"))
        assertTrue("the absent answer clears the marker", flags.clears.get() >= 1)
    }

    @Test fun r2a5UnreadableReportNeitherClearsNorWrites() {
        val flags = RecordingFlags(LegacyReportState.UNREADABLE, marker = true)
        assertEquals("legacy_store_unreadable", read(ShellRecordAccount.Unknown, null, flags).getString("sub"))
        assertEquals(0, flags.sets.get())
        assertEquals(0, flags.clears.get())
    }

    @Test fun r2a5FoundNotImportedNeitherClearsNorWrites() {
        val flags = RecordingFlags(LegacyReportState.FOUND, marker = true)
        assertEquals("import_not_done", read(ShellRecordAccount.Unknown, null, flags).getString("sub"))
        assertEquals(0, flags.sets.get())
        assertEquals(0, flags.clears.get())
    }

    // R2A6-IMPORT-no-marker: an unreadable import with no report (the shell did not report) answers migrating and writes no marker.
    @Test fun r2a6ImportNoMarkerWithNoReportIsMigrating() {
        val flags = RecordingFlags(LegacyReportState.NOT_REPORTED)
        assertEquals("migrating", read(ShellRecordAccount.Unknown, ImportOutcome.LEGACY_UNREADABLE, flags).getString("code"))
        assertEquals(0, flags.sets.get())
    }

    // STORELOCK: a locked store answers storage_locked, exactly once, never not_ready.
    @Test fun storeLockAnswersStorageLockedOnce() {
        val flags = RecordingFlags(LegacyReportState.ABSENT)
        val r = read(ShellRecordAccount.Locked, null, flags)
        assertEquals("error", r.getString("code"))
        assertEquals("storage_locked", r.getString("sub"))
    }

    // STORELOCK-write: a locked store on a write answers write_failed, exactly once.
    @Test fun storeLockAnswersWriteFailedOnAWrite() {
        val flags = RecordingFlags(LegacyReportState.ABSENT)
        val body = JSONObject().put("type", "shellRecordWrite").put("reqId", "w").put("record", JSONObject().put("rev", 0))
        val r = ShellRecordBridge(
            account = { ShellRecordAccount.Locked },
            migrating = { false },
            outcome = { null },
            flags = flags,
        ).handle(ShellOrigin.EMBEDDED_PAGE, body, 80, nativeWrite = false).v()
        assertEquals("write_failed", r.getString("code"))
    }

    // E1: a native copy that cannot be read answers record_unreadable, whatever the report says, never absent.
    @Test fun e1UnreadableCopyIsRecordUnreadable() {
        val flags = RecordingFlags(LegacyReportState.ABSENT)
        assertEquals("record_unreadable", read(ShellRecordAccount.Unreadable, null, flags).getString("sub"))
    }

    // E2: an import whose derived address differs writes nothing, is NOT_DONE, and a reported FOUND answers import_not_done.
    @Test fun e2AddressMismatchIsNotDoneAndAFoundReportAnswersImportNotDone() {
        val outcome = java.util.concurrent.atomic.AtomicReference<ImportOutcome?>(null)
        val store = SealedPageRecordStore(NativeTestWrap(), NativeTestFiles(), "$eoa:default")
        val legacy = JSONObject().put("rev", 0).put("mnemonicPhrase", "M")
            .put("profiles", org.json.JSONArray().put(JSONObject().put("keyID", eoa).put("privateKeyArmor", DerivedAccount.KEY)))
        val flow = ShellImportFlow(
            storeFor = { store },
            addressOf = { _ -> "0x" + "1".repeat(40) },
            pgpStep = { _, _ -> },
            outcome = outcome,
        )
        assertEquals(ShellImportCode.ADDRESS_MISMATCH, flow.run(eoa, LegacyWalletRecord.Found(legacy.toString().toByteArray(Charsets.UTF_8)), null))
        assertEquals(ImportOutcome.NOT_DONE, outcome.get())
        assertEquals("nothing is written", null, store.read())
        val flags = RecordingFlags(LegacyReportState.FOUND)
        assertEquals("import_not_done", read(ShellRecordAccount.Unknown, outcome.get(), flags).getString("sub"))
    }

    // D1: a found record that does not parse is NOT_DONE (import_not_done), and writes no marker.
    @Test fun d1UnparseableFoundRecordIsNotDone() {
        val outcome = java.util.concurrent.atomic.AtomicReference<ImportOutcome?>(null)
        val flow = ShellImportFlow(
            storeFor = { SealedPageRecordStore(NativeTestWrap(), NativeTestFiles(), "$eoa:default") },
            addressOf = { armor -> ShellRecordPolicy.addressOfArmor(armor) },
            pgpStep = { _, _ -> },
            outcome = outcome,
        )
        val code = flow.run(eoa, LegacyWalletRecord.Found("not json".toByteArray(Charsets.UTF_8)), null)
        assertEquals(ShellImportCode.IMPORT_FAILED, code)
        assertEquals(ImportOutcome.NOT_DONE, outcome.get())
    }

    // READ_FAILED: the three users. The bridge answers record_unreadable; the create guard refuses; the pre-read is unknown.
    @Test fun readFailedIsRecordUnreadableAtTheBridge() {
        val flags = RecordingFlags(LegacyReportState.READ_FAILED)
        assertEquals("record_unreadable", read(ShellRecordAccount.Unknown, null, flags).getString("sub"))
    }

    @Test fun readFailedDeniesCreateAndPreReadIsUnknown() {
        val inputs = CreateGuardInputs(KeyState.NONE, LegacyReportState.READ_FAILED, false, false, false, false)
        assertEquals(AccountCreateGuard.MIGRATING, AccountCreateGuard.denial(inputs))
        val empty = NativeWalletVault(NativeTestWrap(), NativeTestFiles())
        assertTrue(MnemonicPreread.vaultAnswer(empty) { LegacyReportState.READ_FAILED } is MnemonicPreread.Answer.Unknown)
    }

    // migrating=false + a persisted marker + a valid copy: ok, the read is not held back by the marker (H3 / §5.3). The clear of the marker on a
    // valid copy is the existing repairFlags path, not asserted here.
    @Test fun aValidCopyAnswersOkWithAPersistedMarkerAndNoMigration() {
        val store = SealedPageRecordStore(NativeTestWrap(), NativeTestFiles(), "$eoa:default")
        val profiles = org.json.JSONArray().put(JSONObject().put("keyID", eoa).put("address", eoa).put("privateKeyArmor", DerivedAccount.KEY))
        store.write(JSONObject().put("rev", 1).put("schemaVersion", 2).put("profiles", profiles))
        val flags = RecordingFlags(LegacyReportState.ABSENT, marker = true)
        val r = read(ShellRecordAccount.Ready(store, eoa, nativeKeyPresent = true, pointedKeyPresent = true), null, flags)
        assertEquals("ok", r.getString("code"))
    }

    // R2A5 (valid copy): a valid native copy clears a persisted marker (repairFlags on the valid path), and answers ok.
    @Test fun aValidCopyClearsAPersistedMarker() {
        val store = SealedPageRecordStore(NativeTestWrap(), NativeTestFiles(), "$eoa:default")
        val profiles = org.json.JSONArray().put(JSONObject().put("keyID", eoa).put("address", eoa).put("privateKeyArmor", DerivedAccount.KEY))
        store.write(JSONObject().put("rev", 1).put("schemaVersion", 2).put("profiles", profiles))
        val flags = RecordingFlags(LegacyReportState.ABSENT, marker = true)
        val r = read(ShellRecordAccount.Ready(store, eoa, nativeKeyPresent = true, pointedKeyPresent = true), null, flags)
        assertEquals("ok", r.getString("code"))
        assertTrue("the persisted marker is cleared", flags.clears.get() >= 1)
    }

    // FOUND with a valid native copy: ok (the copy answers before the report; the import is the shell's and is covered there).
    @Test fun foundWithAValidCopyAnswersOk() {
        val store = SealedPageRecordStore(NativeTestWrap(), NativeTestFiles(), "$eoa:default")
        val profiles = org.json.JSONArray().put(JSONObject().put("keyID", eoa).put("address", eoa).put("privateKeyArmor", DerivedAccount.KEY))
        store.write(JSONObject().put("rev", 1).put("schemaVersion", 2).put("profiles", profiles))
        val flags = RecordingFlags(LegacyReportState.FOUND)
        val r = read(ShellRecordAccount.Ready(store, eoa, nativeKeyPresent = true, pointedKeyPresent = true), ImportOutcome.DONE, flags)
        assertEquals("ok", r.getString("code"))
    }
}
