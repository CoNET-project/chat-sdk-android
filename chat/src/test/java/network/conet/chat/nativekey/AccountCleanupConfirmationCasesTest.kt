package network.conet.chat.nativekey

import network.conet.chat.ChatHistoryFileNames
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

/**
 * v185 §205 cases, rewritten for the silent cleanup (v193 §213, v195 §215): the confirmation is the page's automatic command after recovery, sent only when the read-back passes. Recovery success, read-back
 * consistency, reaching the home page and skipping are not confirmation: each keeps the original data. The page's automatic writer is not wired yet,
 * so each case is run with no confirmation recorded, and the run must answer not_confirmed and delete nothing.
 */
class AccountCleanupConfirmationCasesTest {
    @get:Rule
    val tmp = TemporaryFolder()

    private val newEoa = "0x1111111111111111111111111111111111111111"
    private val oldEoa = "0x2222222222222222222222222222222222222222"
    private val newKey = "$newEoa:default"

    private lateinit var history: File
    private lateinit var confirmation: CleanupConfirmation

    @Before
    fun setUp() {
        history = tmp.newFolder("conet-chat")
        val state = AndroidVaultFiles(tmp.newFolder("cleanup-state"))
        confirmation = CleanupConfirmation(state)
        File(history, ChatHistoryFileNames.localName(newEoa)).writeText("new-local")
        File(history, ChatHistoryFileNames.localName(oldEoa)).writeText("old-local")
        File(history, ChatHistoryFileNames.pendingName(oldEoa)).writeText("old-pending")
    }

    private fun snapshot(): Map<String, String> = history.listFiles().orEmpty().associate { it.name to it.readText() }

    /** Runs the cleanup with the given read-back outcome. Nothing records a confirmation here: the automatic writer is not wired. */
    private fun runCase(readBack: Boolean): AccountCleanupOld.Outcome {
        val state = AndroidVaultFiles(tmp.newFolder("cleanup-state-run"))
        val run = AccountCleanupRun(
            journal = CleanupJournal(state),
            confirmation = CleanupConfirmation(state),
            adapters = listOf(HistoryDirCleanup(history) { listOf(oldEoa) }),
        )
        return run.run(
            payloadFields = listOf("accountKey", "idempotencyKey"),
            accountKey = oldEoa + ":default",
            idempotencyKey = "idem-case",
            gateNotReady = false,
            newAccountKey = newKey,
            newAccountReadable = readBack,
        )
    }

    /** Recovery succeeded and the read-back is consistent, but no confirmation command has arrived: no deletion. */
    @Test
    fun recoveryAloneDoesNotConfirmAndKeepsEverything() {
        val before = snapshot()
        val out = runCase(readBack = true)
        assertEquals(AccountCleanupOld.NOT_CONFIRMED, out.code)
        assertEquals(before, snapshot())
        assertFalse(confirmation.confirmedFor(newKey))
    }

    /** The read-back is consistent after a restore, but no confirmation command has arrived: the read-back alone is not confirmation. */
    @Test
    fun readBackAloneDoesNotConfirmAndKeepsEverything() {
        val before = snapshot()
        val out = runCase(readBack = true)
        assertEquals(AccountCleanupOld.NOT_CONFIRMED, out.code)
        assertEquals(before, snapshot())
    }

    /** No confirmation command: nothing is deleted, even when the new account is readable. */
    @Test
    fun withoutTheTapNothingIsDeleted() {
        val before = snapshot()
        val out = runCase(readBack = true)
        assertEquals(AccountCleanupOld.NOT_CONFIRMED, out.code)
        assertEquals(before, snapshot())
    }

    /** Skipping the cleanup keeps the original data: the same answer, nothing removed. */
    @Test
    fun skippingTheCleanupKeepsTheOriginalData() {
        val before = snapshot()
        val out = runCase(readBack = false)
        assertFalse(out.cleanupPending)
        assertEquals(before, snapshot())
    }

    /**
     * Read-back modelled with [ReadBackCheck] (v191: accountKey is the bare page-derived address). The new account is readable only when the read-back passes.
     * A mismatch (the native re-read is another account), and an unreadable native side, are both not readable, so the run answers not_available and
     * deletes nothing. Read-back alone never confirms.
     */
    private fun readBackCase(pageEoa: String?, nativeEoa: String?): AccountCleanupOld.Outcome {
        val verdict = ReadBackCheck.verdict(oldEoa, pageEoa, nativeEoa)
        val readable = verdict == ReadBackCheck.Verdict.PASS
        val state = AndroidVaultFiles(tmp.newFolder("cleanup-state-rb"))
        val run = AccountCleanupRun(
            journal = CleanupJournal(state),
            confirmation = CleanupConfirmation(state),
            adapters = listOf(HistoryDirCleanup(history) { listOf(oldEoa) }),
        )
        return run.run(
            payloadFields = listOf("accountKey", "idempotencyKey"),
            accountKey = oldEoa,
            idempotencyKey = "idem-rb",
            gateNotReady = false,
            newAccountKey = newKey,
            newAccountReadable = readable,
            readBack = verdict,
        )
    }

    /** Both readable and different: the native re-read is another account. Answers account_mismatch, deletes nothing. */
    @Test
    fun readBackMismatchAnswersAccountMismatchAndDeletesNothing() {
        val before = snapshot()
        val out = readBackCase(pageEoa = oldEoa, nativeEoa = newEoa)
        assertEquals(AccountCleanupOld.ACCOUNT_MISMATCH, out.code)
        assertEquals(before, snapshot())
    }

    /** Native side unreadable: no native address to compare. Answers not_ready, deletes nothing. */
    @Test
    fun nativeUnreadableAnswersNotReadyAndDeletesNothing() {
        val before = snapshot()
        val out = readBackCase(pageEoa = oldEoa, nativeEoa = null)
        assertEquals(AccountCleanupOld.NOT_READY, out.code)
        assertEquals(before, snapshot())
    }

    /** A page address that is absent (unreadable on the page) is not a pass either. Answers not_ready, deletes nothing. */
    @Test
    fun pageUnreadableAnswersNotReadyAndDeletesNothing() {
        val before = snapshot()
        val out = readBackCase(pageEoa = null, nativeEoa = oldEoa)
        assertEquals(AccountCleanupOld.NOT_READY, out.code)
        assertEquals(before, snapshot())
    }

    /** Read-back passes but no confirmation command has been received from the page. Answers not_confirmed, deletes nothing (v193 213, v195 215). */
    @Test
    fun aPassingReadBackWithoutTheConfirmationCommandAnswersNotConfirmed() {
        val before = snapshot()
        val out = readBackCase(pageEoa = oldEoa, nativeEoa = oldEoa)
        assertEquals(AccountCleanupOld.NOT_CONFIRMED, out.code)
        assertEquals(before, snapshot())
    }

    /** v191: the wire accountKey is the bare address; the account part is compared, so a bare address with a different account is account_mismatch. */
    @Test
    fun aBareAddressAccountKeyIsComparedByItsAccount() {
        val state = AndroidVaultFiles(tmp.newFolder("cleanup-state-bare"))
        // The preflight checks the confirmation before the account, so a confirmation is recorded for the new account here (test-only writer).
        CleanupConfirmation(state).record(newKey, 1L)
        val run = AccountCleanupRun(
            journal = CleanupJournal(state),
            confirmation = CleanupConfirmation(state),
            adapters = listOf(HistoryDirCleanup(history) { listOf(oldEoa) }),
        )
        val mismatch = run.run(listOf("accountKey", "idempotencyKey"), oldEoa, "idem-bare", false, newKey, true)
        assertEquals(AccountCleanupOld.ACCOUNT_MISMATCH, mismatch.code)
    }
}
