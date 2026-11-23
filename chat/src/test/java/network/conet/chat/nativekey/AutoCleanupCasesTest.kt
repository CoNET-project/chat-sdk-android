package network.conet.chat.nativekey

import network.conet.chat.ChatHistoryFileNames
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

/**
 * Silent cleanup (v195 215): no user action. The page's automatic confirmation writes the marker only when the read-back passes; the cleanup then
 * removes only the old accounts' items with exact owners. Nothing here is a candidate: the deletion path stays disabled until passes and the owner releases it.
 */
class AutoCleanupCasesTest {
    @get:Rule
    val tmp = TemporaryFolder()

    private val newEoa = "0x1111111111111111111111111111111111111111"
    private val oldEoa = "0x2222222222222222222222222222222222222222"
    private val newKey = "$newEoa:default"

    private lateinit var history: File
    private lateinit var state: VaultFiles
    private lateinit var confirmation: CleanupConfirmation

    @Before
    fun setUp() {
        history = tmp.newFolder("conet-chat")
        state = AndroidVaultFiles(tmp.newFolder("cleanup-state"))
        confirmation = CleanupConfirmation(state)
        File(history, ChatHistoryFileNames.localName(newEoa)).writeText("new-local")
        File(history, ChatHistoryFileNames.pendingName(newEoa)).writeText("new-pending")
        File(history, ChatHistoryFileNames.localName(oldEoa)).writeText("old-local")
        File(history, ChatHistoryFileNames.pendingName(oldEoa)).writeText("old-pending")
    }

    private fun snapshot(): Map<String, String> = history.listFiles().orEmpty().associate { it.name to it.readText() }

    private fun run(readBack: ReadBackCheck.Verdict, idem: String = "idem-auto"): AccountCleanupOld.Outcome = AccountCleanupRun(
        journal = CleanupJournal(state),
        confirmation = confirmation,
        adapters = listOf(HistoryDirCleanup(history) { listOf(oldEoa) }),
    ).run(
        payloadFields = listOf("accountKey", "idempotencyKey"),
        accountKey = newEoa,
        idempotencyKey = idem,
        gateNotReady = false,
        newAccountKey = newKey,
        newAccountReadable = readBack == ReadBackCheck.Verdict.PASS,
        readBack = readBack,
    )

    /** Recovery succeeded and the read-back passes: the page confirms, the marker is written, the old account is cleaned, the new one is kept. */
    @Test
    fun successfulRecoveryWithAPassingReadBackCleansTheOldAndKeepsTheNew() {
        val rec = AutoConfirmation.onPageConfirm(confirmation, newEoa, newEoa, newEoa, 1L)
        assertEquals(AutoConfirmation.Result.RECORDED, rec)
        val before = snapshot()
        val out = run(ReadBackCheck.Verdict.PASS)
        assertEquals(AccountCleanupOld.OK, out.code)
        assertFalse(File(history, ChatHistoryFileNames.localName(oldEoa)).exists())
        assertFalse(File(history, ChatHistoryFileNames.pendingName(oldEoa)).exists())
        assertEquals(before[ChatHistoryFileNames.localName(newEoa)], File(history, ChatHistoryFileNames.localName(newEoa)).readText())
        assertEquals(before[ChatHistoryFileNames.pendingName(newEoa)], File(history, ChatHistoryFileNames.pendingName(newEoa)).readText())
    }

    /** Recovery failed: the page does not confirm, nothing is written, nothing is cleaned. */
    @Test
    fun aFailedRecoveryWritesNothingAndCleansNothing() {
        val before = snapshot()
        val out = run(ReadBackCheck.Verdict.UNREADABLE)
        assertEquals(AccountCleanupOld.NOT_READY, out.code)
        assertEquals(before, snapshot())
    }

    /** Recovery not finished (no confirmation from the page): the marker is absent, so the answer is not_confirmed and nothing is removed. */
    @Test
    fun anUnfinishedRecoveryWithoutTheConfirmationCleansNothing() {
        val before = snapshot()
        val out = run(ReadBackCheck.Verdict.PASS)
        assertEquals(AccountCleanupOld.NOT_CONFIRMED, out.code)
        assertEquals(before, snapshot())
    }

    /** The read-back fails (native side unreadable): the page's confirmation is not recorded, so the cleanup cleans nothing. */
    @Test
    fun aFailedReadBackWritesNothingAndCleansNothing() {
        assertEquals(AutoConfirmation.Result.NOT_RECORDED, AutoConfirmation.onPageConfirm(confirmation, newEoa, newEoa, null, 2L))
        val before = snapshot()
        val out = run(ReadBackCheck.Verdict.UNREADABLE)
        assertEquals(AccountCleanupOld.NOT_READY, out.code)
        assertEquals(before, snapshot())
    }

    /** The addresses differ (native re-read is another account): nothing is written and the answer is account_mismatch; nothing is cleaned. */
    @Test
    fun anAddressMismatchWritesNothingAndCleansNothing() {
        assertEquals(AutoConfirmation.Result.NOT_RECORDED, AutoConfirmation.onPageConfirm(confirmation, newEoa, newEoa, oldEoa, 3L))
        val before = snapshot()
        val out = run(ReadBackCheck.Verdict.MISMATCH)
        assertEquals(AccountCleanupOld.ACCOUNT_MISMATCH, out.code)
        assertEquals(before, snapshot())
    }

    /** A repeated callback with the same idempotencyKey: the second run finds the old items gone, removes nothing else, and keeps the new account. */
    @Test
    fun aRepeatedCallbackDoesNotDeleteWrongly() {
        assertEquals(AutoConfirmation.Result.RECORDED, AutoConfirmation.onPageConfirm(confirmation, newEoa, newEoa, newEoa, 4L))
        assertEquals(AccountCleanupOld.OK, run(ReadBackCheck.Verdict.PASS, "idem-dup").code)
        val afterFirst = snapshot()
        AutoConfirmation.onPageConfirm(confirmation, newEoa, newEoa, newEoa, 5L)
        val second = run(ReadBackCheck.Verdict.PASS, "idem-dup")
        assertTrue("the second run does not fail", second.code == AccountCleanupOld.OK || second.code == AccountCleanupOld.NOT_CONFIRMED)
        assertEquals(afterFirst, snapshot())
    }

    /** The new account's wallet-side history and an unattributed file are kept even after a successful cleanup. */
    @Test
    fun theNewAccountAndUnattributedItemsAreKept() {
        File(history, "chat-local-v1-AAAAAAAAAAAAAAAAAAAAAA.sqlite").writeText("unattributed")
        assertEquals(AutoConfirmation.Result.RECORDED, AutoConfirmation.onPageConfirm(confirmation, newEoa, newEoa, newEoa, 6L))
        val out = run(ReadBackCheck.Verdict.PASS)
        assertEquals(AccountCleanupOld.OK, out.code)
        assertEquals("unattributed", File(history, "chat-local-v1-AAAAAAAAAAAAAAAAAAAAAA.sqlite").readText())
        assertTrue(File(history, ChatHistoryFileNames.localName(newEoa)).exists())
        assertEquals(1, out.retainedUnattributed)
    }

    /** v193 213.5 #8 (CU-06 gate): a locked or not-ready gate answers not_ready (never clear_incomplete) and deletes nothing. */
    @Test
    fun aLockedOrNotReadyGateAnswersNotReadyAndDeletesNothing() {
        AutoConfirmation.onPageConfirm(confirmation, newEoa, newEoa, newEoa, 7L)
        val before = snapshot()
        val out = AccountCleanupRun(
            journal = CleanupJournal(state),
            confirmation = confirmation,
            adapters = listOf(HistoryDirCleanup(history) { listOf(oldEoa) }),
        ).run(
            payloadFields = listOf("accountKey", "idempotencyKey"),
            accountKey = newEoa,
            idempotencyKey = "idem-gate",
            gateNotReady = true,
            newAccountKey = newKey,
            newAccountReadable = true,
            readBack = ReadBackCheck.Verdict.PASS,
        )
        assertEquals(AccountCleanupOld.NOT_READY, out.code)
        assertFalse(out.cleanupPending)
        assertEquals(before, snapshot())
    }
}
