package network.conet.chat.nativekey

import network.conet.chat.ChatHistoryFileNames
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

/**
 * accountCleanupOld enabled (v196/v3): the page's confirmation command writes the marker on a passing read-back; the run
 * then deletes only exact-owner items of a provably old account, under CleanupJournal. Cases: continuation across a restart, the new account's data is never touched,
 * and a read-back mismatch deletes nothing.
 */
class AccountCleanupEnabledTest {
    @get:Rule
    val tmp = TemporaryFolder()

    private val newEoa = "0x1111111111111111111111111111111111111111"
    private val oldEoa = "0x2222222222222222222222222222222222222222"
    private val newKey = "$newEoa:default"

    private fun history(): File {
        val h = tmp.newFolder("conet-chat")
        File(h, ChatHistoryFileNames.localName(newEoa)).writeText("new-local")
        File(h, ChatHistoryFileNames.pendingName(newEoa)).writeText("new-pending")
        File(h, ChatHistoryFileNames.localName(oldEoa)).writeText("old-local")
        File(h, ChatHistoryFileNames.pendingName(oldEoa)).writeText("old-pending")
        return h
    }

    /** A removal that fails for the pending history file (the item cannot be removed in this run). */
    private class FailPending(private val inner: CleanupAdapter) : CleanupAdapter {
        override fun scan(newAccountKey: String) = inner.scan(newAccountKey)
        override fun remove(item: AccountCleanupOld.Item): Boolean =
            if (item.name.contains(ChatHistoryFileNames.PENDING_PREFIX)) false else inner.remove(item)
    }

    /** Across a restart: the first run answers clear_incomplete with cleanupPending; a new process (new file objects over the same folder) completes it. */
    @Test
    fun aRunCompletesAcrossARestartFromTheJournal() {
        val h = history()
        val stateDir = tmp.newFolder("cleanup-state-restart")
        val state1 = AndroidVaultFiles(stateDir)
        val conf1 = CleanupConfirmation(state1)
        assertEquals(AutoConfirmation.Result.RECORDED, AutoConfirmation.onPageConfirm(conf1, newEoa, newEoa, newEoa, 1L))
        val inner = HistoryDirCleanup(h) { listOf(oldEoa) }
        val first = AccountCleanupRun(CleanupJournal(state1), conf1, listOf(FailPending(inner))).run(
            listOf("accountKey", "idempotencyKey"), newEoa, "idem-restart", false, newKey, true, ReadBackCheck.Verdict.PASS,
        )
        assertEquals(AccountCleanupOld.CLEAR_INCOMPLETE, first.code)
        assertTrue(first.cleanupPending)
        assertFalse("the local old file is gone in the first run", File(h, ChatHistoryFileNames.localName(oldEoa)).exists())
        assertTrue("the pending old file remains", File(h, ChatHistoryFileNames.pendingName(oldEoa)).exists())

        // A new process: new objects over the same folder.
        val state2 = AndroidVaultFiles(stateDir)
        val second = AccountCleanupRun(CleanupJournal(state2), CleanupConfirmation(state2), listOf(inner)).run(
            listOf("accountKey", "idempotencyKey"), newEoa, "idem-restart", false, newKey, true, ReadBackCheck.Verdict.PASS,
        )
        assertEquals(AccountCleanupOld.OK, second.code)
        assertFalse(File(h, ChatHistoryFileNames.pendingName(oldEoa)).exists())
    }

    /** The new account's own history and an unattributed name are never touched by a successful cleanup. */
    @Test
    fun theNewAccountsDataIsNeverTouched() {
        val h = history()
        File(h, "chat-local-v1-ZZZZZZZZZZZZZZZZZZZZZZ.sqlite").writeText("unknown")
        val state = AndroidVaultFiles(tmp.newFolder("cleanup-state-scope"))
        val conf = CleanupConfirmation(state)
        AutoConfirmation.onPageConfirm(conf, newEoa, newEoa, newEoa, 2L)
        val out = AccountCleanupRun(CleanupJournal(state), conf, listOf(HistoryDirCleanup(h) { listOf(oldEoa) })).run(
            listOf("accountKey", "idempotencyKey"), newEoa, "idem-scope", false, newKey, true, ReadBackCheck.Verdict.PASS,
        )
        assertEquals(AccountCleanupOld.OK, out.code)
        assertTrue(File(h, ChatHistoryFileNames.localName(newEoa)).exists())
        assertTrue(File(h, ChatHistoryFileNames.pendingName(newEoa)).exists())
        assertEquals("unknown", File(h, "chat-local-v1-ZZZZZZZZZZZZZZZZZZZZZZ.sqlite").readText())
        assertEquals(1, out.retainedUnattributed)
    }

    /** A read-back mismatch is account_mismatch and deletes nothing, even with a passing-looking marker from a different account. */
    @Test
    fun aReadBackMismatchDeletesNothing() {
        val h = history()
        val before = h.listFiles().orEmpty().associate { it.name to it.readText() }
        val state = AndroidVaultFiles(tmp.newFolder("cleanup-state-mismatch"))
        val conf = CleanupConfirmation(state)
        val verdict = ReadBackCheck.verdict(newEoa, newEoa, oldEoa)
        assertEquals(ReadBackCheck.Verdict.MISMATCH, verdict)
        val out = AccountCleanupRun(CleanupJournal(state), conf, listOf(HistoryDirCleanup(h) { listOf(oldEoa) })).run(
            listOf("accountKey", "idempotencyKey"), newEoa, "idem-mm", false, newKey, true, verdict,
        )
        assertEquals(AccountCleanupOld.ACCOUNT_MISMATCH, out.code)
        assertEquals(before, h.listFiles().orEmpty().associate { it.name to it.readText() })
    }
}
