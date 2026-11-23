package network.conet.chat.nativekey

import network.conet.chat.passcode.PasscodeRecordStore
import network.conet.chat.passcode.PasscodeWriteState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

/** The native passcode records under the silent cleanup: exact owner by name; the new account, unknown names and the directory itself are kept. */
class AccountCleanupPasscodeTest {
    @get:Rule
    val tmp = TemporaryFolder()

    private val newEoa = "0x1111111111111111111111111111111111111111"
    private val oldEoa = "0x2222222222222222222222222222222222222222"
    private val newKey = "$newEoa:default"

    @Test
    fun theOldAccountsRecordsGoAndTheNewAndUnknownStay() {
        val pass = tmp.newFolder("native_passcode_v1")
        File(pass, newEoa).writeText("new-record")
        File(pass, oldEoa).writeText("old-record")
        File(pass, oldEoa + PasscodeRecordStore.NEW_SUFFIX).apply { writeText("old-temp"); setLastModified(0L) }
        File(pass, "unknown-file").writeText("unattributed")
        val state = AndroidVaultFiles(tmp.newFolder("cleanup-state"))
        val confirmation = CleanupConfirmation(state)
        confirmation.record(newKey, 1L)

        val out = AccountCleanupRun(
            journal = CleanupJournal(state),
            confirmation = confirmation,
            adapters = listOf(PasscodeDirCleanup(pass) { listOf(oldEoa) }),
        ).run(listOf("accountKey", "idempotencyKey"), newEoa, "idem-pass", false, newKey, true, ReadBackCheck.Verdict.PASS)

        assertEquals(AccountCleanupOld.OK, out.code)
        assertFalse("the old record is removed", File(pass, oldEoa).exists())
        assertFalse("the old temp is removed", File(pass, oldEoa + PasscodeRecordStore.NEW_SUFFIX).exists())
        assertEquals("new-record", File(pass, newEoa).readText())
        assertEquals("unattributed", File(pass, "unknown-file").readText())
        assertTrue("the directory itself is kept", pass.isDirectory)
        assertEquals(1, out.retainedUnattributed)
    }

    @org.junit.Before
    fun provedStart() {
        // The process start is proved for these tests: files with modification time 0 are older than it; the fresh ones are not.
        PasscodeWriteState.startProvider = { 1_000L }
    }

    @org.junit.After
    fun restoreStart() {
        PasscodeWriteState.startProvider = { null }
    }

    private fun runForTemp(pass: File, confirmedNew: Boolean = true): AccountCleanupOld.Outcome {
        val state = AndroidVaultFiles(tmp.newFolder("cleanup-state-new"))
        val confirmation = CleanupConfirmation(state)
        if (confirmedNew) confirmation.record(newKey, 1L)
        return AccountCleanupRun(
            journal = CleanupJournal(state),
            confirmation = confirmation,
            adapters = listOf(PasscodeDirCleanup(pass) { listOf(oldEoa) }),
        ).run(listOf("accountKey", "idempotencyKey"), newEoa, "idem-new-${System.nanoTime()}", false, newKey, true, ReadBackCheck.Verdict.PASS)
    }

    /** v207 227: a <eoa>.new older than this process is removable. */
    @Test
    fun aTempFileOlderThanThisProcessIsRemoved() {
        val pass = tmp.newFolder("native_passcode_v1")
        val temp = File(pass, oldEoa + PasscodeRecordStore.NEW_SUFFIX).apply { writeText("old-temp"); setLastModified(0L) }
        val out = runForTemp(pass)
        assertEquals(AccountCleanupOld.OK, out.code)
        assertFalse("the old-process temp is removed", temp.exists())
    }

    /** v207 227: a fresh <eoa>.new with a passcode write in progress in this process is kept and counted as unattributed. */
    @Test
    fun aTempFileWithAWriteInProgressIsDeferredNotUnattributed() {
        val pass = tmp.newFolder("native_passcode_v1")
        val temp = File(pass, oldEoa + PasscodeRecordStore.NEW_SUFFIX).apply { writeText("writing"); setLastModified(System.currentTimeMillis()) }
        PasscodeWriteState.begin(oldEoa)
        try {
            val out = runForTemp(pass)
            assertTrue("the in-progress temp is kept", temp.exists())
            assertEquals("deferred, not success", AccountCleanupOld.CLEAR_INCOMPLETE, out.code)
            assertTrue(out.cleanupPending)
            assertEquals("not counted as unattributed (v209 229.2)", 0, out.retainedUnattributed)
        } finally {
            PasscodeWriteState.end(oldEoa)
        }
    }

    /** v207 227: a fresh <eoa>.new written by this process is kept even with no write in progress. */
    @Test
    fun aFreshTempWrittenByThisProcessIsDeferredWhenNoWriteIsInProgress() {
        val pass = tmp.newFolder("native_passcode_v1")
        val temp = File(pass, oldEoa + PasscodeRecordStore.NEW_SUFFIX).apply { writeText("fresh"); setLastModified(System.currentTimeMillis()) }
        val out = runForTemp(pass)
        assertTrue("the fresh temp is kept", temp.exists())
        assertEquals(AccountCleanupOld.CLEAR_INCOMPLETE, out.code)
        assertTrue(out.cleanupPending)
        assertEquals(0, out.retainedUnattributed)
    }

    /** A start that cannot be proved keeps every .new (v207 227). */
    @Test
    fun withAnUnprovenStartEveryTempIsKept() {
        PasscodeWriteState.startProvider = { null }
        val pass = tmp.newFolder("native_passcode_v1")
        val temp = File(pass, oldEoa + PasscodeRecordStore.NEW_SUFFIX).apply { writeText("old-temp"); setLastModified(0L) }
        val out = runForTemp(pass)
        assertTrue("the temp is kept when the start is unproven", temp.exists())
        assertEquals(AccountCleanupOld.CLEAR_INCOMPLETE, out.code)
        assertTrue(out.cleanupPending)
    }

    /** A removal that fails on the .new file: the run answers clear_incomplete with cleanupPending true and does not report success. */
    @Test
    fun aFailedTempRemovalIsClearIncomplete() {
        PasscodeWriteState.startProvider = { 1_000L }
        val pass = tmp.newFolder("native_passcode_v1")
        File(pass, oldEoa + PasscodeRecordStore.NEW_SUFFIX).apply { writeText("old-temp"); setLastModified(0L) }
        val state = AndroidVaultFiles(tmp.newFolder("cleanup-state-fail"))
        val confirmation = CleanupConfirmation(state)
        confirmation.record(newKey, 1L)
        val failing = object : CleanupAdapter {
            private val inner = PasscodeDirCleanup(pass) { listOf(oldEoa) }
            override fun scan(newAccountKey: String) = inner.scan(newAccountKey)
            override fun remove(item: AccountCleanupOld.Item): Boolean = false
        }
        val out = AccountCleanupRun(CleanupJournal(state), confirmation, listOf(failing)).run(
            listOf("accountKey", "idempotencyKey"), newEoa, "idem-fail", false, newKey, true, ReadBackCheck.Verdict.PASS,
        )
        assertEquals(AccountCleanupOld.CLEAR_INCOMPLETE, out.code)
        assertTrue(out.cleanupPending)
    }

    /** A write that starts after the scan and before the removal keeps the .new; the item fails, never a success. */
    @Test
    fun aWriteStartingAfterTheScanKeepsTheTemp() {
        val pass = tmp.newFolder("native_passcode_v1")
        val temp = File(pass, oldEoa + PasscodeRecordStore.NEW_SUFFIX).apply { writeText("old-temp"); setLastModified(0L) }
        val adapter = PasscodeDirCleanup(pass) { listOf(oldEoa) }
        val item = adapter.scan(newKey).items.first { it.name.endsWith(PasscodeRecordStore.NEW_SUFFIX) }
        PasscodeWriteState.begin(oldEoa)
        try {
            assertFalse("the removal is refused while the write is in progress", adapter.remove(item))
            assertTrue("the temp is kept", temp.exists())
        } finally {
            PasscodeWriteState.end(oldEoa)
        }
        assertTrue("once the write has ended, the stale temp can be removed", adapter.remove(item))
        assertFalse(temp.exists())
    }
}
