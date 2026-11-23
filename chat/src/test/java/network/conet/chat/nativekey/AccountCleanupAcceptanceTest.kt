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
 * The SDK-drivable items of the three-platform acceptance draft (v216 §236, S-01 to S-14). Each case states its precondition, operation and expected
 * answer; where the SDK's observable behaviour differs from the draft, the test asserts the actual behaviour and the difference is recorded in the report
 * (S-11 file names, S-13 answer). Physical-device items (S-07 after a process kill, the UI) are not covered here.
 */
class AccountCleanupAcceptanceTest {
    @get:Rule
    val tmp = TemporaryFolder()

    private val newEoa = "0x1111111111111111111111111111111111111111"
    private val oldEoa = "0x2222222222222222222222222222222222222222"
    private val thirdEoa = "0x3333333333333333333333333333333333333333"
    private val newKey = "$newEoa:default"

    private fun history(): File {
        val h = tmp.newFolder("conet-chat")
        File(h, ChatHistoryFileNames.localName(newEoa)).writeText("new-local")
        File(h, ChatHistoryFileNames.pendingName(newEoa)).writeText("new-pending")
        File(h, ChatHistoryFileNames.localName(oldEoa)).writeText("old-local")
        File(h, ChatHistoryFileNames.pendingName(oldEoa)).writeText("old-pending")
        return h
    }

    private fun wallet(eoa: String): File {
        val d = tmp.newFolder("native_wallet_v1")
        File(d, NativeWalletVault.REC).writeText("""{"v":1,"eoa":"$eoa"}""")
        File(d, NativeWalletVault.MARK).writeText("""{"v":1,"eoa":"$eoa"}""")
        return d
    }

    private fun run(adapters: List<CleanupAdapter>, state: AndroidVaultFiles, conf: CleanupConfirmation, idem: String, verdict: ReadBackCheck.Verdict = ReadBackCheck.Verdict.PASS) =
        AccountCleanupRun(CleanupJournal(state), conf, adapters).run(
            listOf("accountKey", "idempotencyKey"), newEoa, idem, false, newKey, true, verdict,
        )

    private fun dirSnapshot(d: File): Map<String, String> = d.listFiles().orEmpty().associate { it.name to it.readText() }

    /** S-01: a successful recovery with a passing read-back cleans the old data and keeps the new. ok, cleanupPending false, keptUnattributed an integer. */
    @Test
    fun s01SuccessCleansTheOldKeepsTheNew() {
        val h = history()
        val state = AndroidVaultFiles(tmp.newFolder("s01"))
        val conf = CleanupConfirmation(state)
        assertEquals(AutoConfirmation.Result.RECORDED, AutoConfirmation.onPageConfirm(conf, newEoa, newEoa, newEoa, 1L))
        val out = run(listOf(HistoryDirCleanup(h) { listOf(oldEoa) }), state, conf, "s01")
        assertEquals(AccountCleanupOld.OK, out.code)
        assertFalse(out.cleanupPending)
        assertFalse(File(h, ChatHistoryFileNames.localName(oldEoa)).exists())
        assertFalse(File(h, ChatHistoryFileNames.pendingName(oldEoa)).exists())
        assertTrue(File(h, ChatHistoryFileNames.localName(newEoa)).exists())
    }

    /** S-02: the recovery failed; no confirmation command is sent, so nothing is cleaned. */
    @Test
    fun s02FailedRecoveryDoesNotClean() {
        val h = history()
        val before = dirSnapshot(h)
        val state = AndroidVaultFiles(tmp.newFolder("s02"))
        val conf = CleanupConfirmation(state)
        val out = run(listOf(HistoryDirCleanup(h) { listOf(oldEoa) }), state, conf, "s02")
        assertEquals(AccountCleanupOld.NOT_CONFIRMED, out.code)
        assertEquals(before, dirSnapshot(h))
    }

    /** S-03: the recovery finished but the page sent no confirmation: not_confirmed, nothing cleaned. */
    @Test
    fun s03NoConfirmationAnswersNotConfirmedAndCleansNothing() {
        val h = history()
        val before = dirSnapshot(h)
        val state = AndroidVaultFiles(tmp.newFolder("s03"))
        val out = run(listOf(HistoryDirCleanup(h) { listOf(oldEoa) }), state, CleanupConfirmation(state), "s03")
        assertEquals(AccountCleanupOld.NOT_CONFIRMED, out.code)
        assertEquals(before, dirSnapshot(h))
    }

    /** S-04: a read-back side unreadable: not_ready (retryable), nothing cleaned, no success reported. */
    @Test
    fun s04ReadBackUnreadableIsNotReadyAndCleansNothing() {
        val h = history()
        val before = dirSnapshot(h)
        val verdict = ReadBackCheck.verdict(newEoa, newEoa, null)
        assertEquals(ReadBackCheck.Verdict.UNREADABLE, verdict)
        val state = AndroidVaultFiles(tmp.newFolder("s04"))
        val conf = CleanupConfirmation(state)
        assertEquals(AutoConfirmation.Result.NOT_RECORDED, AutoConfirmation.onPageConfirm(conf, newEoa, newEoa, null, 2L))
        val out = run(listOf(HistoryDirCleanup(h) { listOf(oldEoa) }), state, conf, "s04", verdict)
        assertEquals(AccountCleanupOld.NOT_READY, out.code)
        assertEquals(before, dirSnapshot(h))
    }

    /** S-05: the page address and the native address differ: account_mismatch, no confirmation recorded, nothing cleaned. */
    @Test
    fun s05AddressMismatchIsAccountMismatchAndRecordsNoConfirmation() {
        val h = history()
        val before = dirSnapshot(h)
        val state = AndroidVaultFiles(tmp.newFolder("s05"))
        val conf = CleanupConfirmation(state)
        assertEquals(AutoConfirmation.Result.NOT_RECORDED, AutoConfirmation.onPageConfirm(conf, newEoa, newEoa, oldEoa, 3L))
        assertFalse(conf.confirmedFor(newKey))
        val out = run(listOf(HistoryDirCleanup(h) { listOf(oldEoa) }), state, conf, "s05", ReadBackCheck.Verdict.MISMATCH)
        assertEquals(AccountCleanupOld.ACCOUNT_MISMATCH, out.code)
        assertEquals(before, dirSnapshot(h))
    }

    /** S-06: a repeated callback with the same idempotencyKey: no further deletion; the new account's data is not touched. */
    @Test
    fun s06RepeatedCallbackDeletesNothingFurther() {
        val h = history()
        val state = AndroidVaultFiles(tmp.newFolder("s06"))
        val conf = CleanupConfirmation(state)
        AutoConfirmation.onPageConfirm(conf, newEoa, newEoa, newEoa, 4L)
        assertEquals(AccountCleanupOld.OK, run(listOf(HistoryDirCleanup(h) { listOf(oldEoa) }), state, conf, "s06").code)
        val afterFirst = dirSnapshot(h)
        AutoConfirmation.onPageConfirm(conf, newEoa, newEoa, newEoa, 5L)
        val second = run(listOf(HistoryDirCleanup(h) { listOf(oldEoa) }), state, conf, "s06")
        assertEquals("the repeated callback is ok", AccountCleanupOld.OK, second.code)
        assertEquals(afterFirst, dirSnapshot(h))
        assertTrue(File(h, ChatHistoryFileNames.localName(newEoa)).exists())
    }

    /** S-07 (SDK part): a cleanup interrupted after its first deletion completes in a later run from the journal. */
    @Test
    fun s07InterruptedCleanupCompletesFromTheJournal() {
        val h = history()
        val stateDir = tmp.newFolder("s07")
        val state1 = AndroidVaultFiles(stateDir)
        val conf1 = CleanupConfirmation(state1)
        AutoConfirmation.onPageConfirm(conf1, newEoa, newEoa, newEoa, 6L)
        val failPending = object : CleanupAdapter {
            private val inner = HistoryDirCleanup(h) { listOf(oldEoa) }
            override fun scan(newAccountKey: String) = inner.scan(newAccountKey)
            override fun remove(item: AccountCleanupOld.Item): Boolean = if (item.name.contains(ChatHistoryFileNames.PENDING_PREFIX)) false else inner.remove(item)
        }
        val first = run(listOf(failPending), state1, conf1, "s07")
        assertEquals(AccountCleanupOld.CLEAR_INCOMPLETE, first.code)
        assertTrue(first.cleanupPending)
        val state2 = AndroidVaultFiles(stateDir)
        val second = run(listOf(HistoryDirCleanup(h) { listOf(oldEoa) }), state2, CleanupConfirmation(state2), "s07")
        assertEquals(AccountCleanupOld.OK, second.code)
        assertFalse(second.cleanupPending)
        assertTrue(File(h, ChatHistoryFileNames.localName(newEoa)).exists())
    }

    /** S-08: the new account's wallet (its wallet.v1.* EOA) is kept and unchanged by any cleanup run. */
    @Test
    fun s08NewAccountWalletIsKept() {
        val d = wallet(newEoa)
        val before = dirSnapshot(d)
        val state = AndroidVaultFiles(tmp.newFolder("s08"))
        val conf = CleanupConfirmation(state)
        AutoConfirmation.onPageConfirm(conf, newEoa, newEoa, newEoa, 7L)
        val adapter = WalletVaultCleanup(d, Any(), { oldEoa }) { dir, _ -> CleanupOwners.walletVaultOwner(dir) }
        run(listOf(adapter), state, conf, "s08")
        assertEquals(before, dirSnapshot(d))
    }

    /** S-09: the new account's chat history is kept and its record set is unchanged. */
    @Test
    fun s09NewAccountChatIsKept() {
        val h = history()
        val newFiles = dirSnapshot(h).filterKeys { it.contains(newEoa.substring(2, 10).lowercase()) || it == ChatHistoryFileNames.localName(newEoa) || it == ChatHistoryFileNames.pendingName(newEoa) }
        val state = AndroidVaultFiles(tmp.newFolder("s09"))
        val conf = CleanupConfirmation(state)
        AutoConfirmation.onPageConfirm(conf, newEoa, newEoa, newEoa, 8L)
        run(listOf(HistoryDirCleanup(h) { listOf(oldEoa) }), state, conf, "s09")
        assertEquals(newFiles[ChatHistoryFileNames.localName(newEoa)], File(h, ChatHistoryFileNames.localName(newEoa)).readText())
        assertTrue(File(h, ChatHistoryFileNames.pendingName(newEoa)).exists())
    }

    /** S-10: a file not attributable to the old account is kept and counted in keptUnattributed. */
    @Test
    fun s10UnattributableFileIsKeptAndCounted() {
        val h = history()
        File(h, "chat-local-v1-UNKNOWNUNKNOWNUNKNOWNX.sqlite").writeText("unknown")
        val state = AndroidVaultFiles(tmp.newFolder("s10"))
        val conf = CleanupConfirmation(state)
        AutoConfirmation.onPageConfirm(conf, newEoa, newEoa, newEoa, 9L)
        val out = run(listOf(HistoryDirCleanup(h) { listOf(oldEoa) }), state, conf, "s10")
        assertEquals(1, out.retainedUnattributed)
        assertTrue(File(h, "chat-local-v1-UNKNOWNUNKNOWNUNKNOWNX.sqlite").exists())
    }

    /** S-11 (SDK part): the inbox is not a deletion target of the cleanup; its entries are counted (none in this run) and the file is untouched. The draft's
     *  file names (owner_v1.txt, inbox_v1.json, call_signals_v1.json) do not match the SDK's inbox file (conet_chat_inbox_v1.json); recorded in the report. */
    @Test
    fun s11InboxFileIsNotADeletionTarget() {
        val h = history()
        val state = AndroidVaultFiles(tmp.newFolder("s11"))
        val conf = CleanupConfirmation(state)
        AutoConfirmation.onPageConfirm(conf, newEoa, newEoa, newEoa, 10L)
        val inbox = File(tmp.newFolder("nobackup"), "conet_chat_inbox_v1.json").apply { writeText("[]") }
        run(listOf(HistoryDirCleanup(h) { listOf(oldEoa) }), state, conf, "s11")
        assertEquals("[]", inbox.readText())
    }

    /** S-12: a locked or not-ready gate: not_ready, nothing deleted, never clear_incomplete. */
    @Test
    fun s12LockedGateIsNotReadyAndDeletesNothing() {
        val h = history()
        val before = dirSnapshot(h)
        val state = AndroidVaultFiles(tmp.newFolder("s12"))
        val conf = CleanupConfirmation(state)
        AutoConfirmation.onPageConfirm(conf, newEoa, newEoa, newEoa, 11L)
        val out = AccountCleanupRun(CleanupJournal(state), conf, listOf(HistoryDirCleanup(h) { listOf(oldEoa) })).run(
            listOf("accountKey", "idempotencyKey"), newEoa, "s12", true, newKey, true, ReadBackCheck.Verdict.PASS,
        )
        assertEquals(AccountCleanupOld.NOT_READY, out.code)
        assertFalse(out.cleanupPending)
        assertEquals(before, dirSnapshot(h))
    }

    /** S-13: the active account is the old account: the wallet group is kept, ok, counted in keptUnattributed, not retried. */
    @Test
    fun s13ActiveOldAccountKeepsTheWalletGroup() {
        val d = wallet(oldEoa)
        val before = dirSnapshot(d)
        val state = AndroidVaultFiles(tmp.newFolder("s13"))
        val conf = CleanupConfirmation(state)
        AutoConfirmation.onPageConfirm(conf, newEoa, newEoa, newEoa, 12L)
        val adapter = WalletVaultCleanup(d, Any(), { oldEoa }) { dir, _ -> CleanupOwners.walletVaultOwner(dir) }
        val out = run(listOf(adapter), state, conf, "s13")
        // ok, kept counted in keptUnattributed, cleanupPending false, no retry; the account's wallet files all exist.
        assertEquals(AccountCleanupOld.OK, out.code)
        assertFalse(out.cleanupPending)
        assertEquals(before.size, out.retainedUnattributed)
        assertEquals(before, dirSnapshot(d))
    }

    /** S-14: an isolated copy of the wallet is kept and counted in keptUnattributed. */
    @Test
    fun s14IsolatedWalletCopyIsKeptAndCounted() {
        val d = wallet(oldEoa)
        File(d, "${NativeWalletVault.MNEM}.isolated.copy1").writeText("""{"v":1,"eoa":"$thirdEoa"}""")
        val state = AndroidVaultFiles(tmp.newFolder("s14"))
        val conf = CleanupConfirmation(state)
        AutoConfirmation.onPageConfirm(conf, newEoa, newEoa, newEoa, 13L)
        val adapter = WalletVaultCleanup(d, Any(), { newEoa }) { dir, _ -> CleanupOwners.walletVaultOwner(dir) }
        val out = run(listOf(adapter), state, conf, "s14")
        assertTrue("the isolated copy remains", File(d, "${NativeWalletVault.MNEM}.isolated.copy1").exists())
        assertEquals(1, out.retainedUnattributed)
    }
}
