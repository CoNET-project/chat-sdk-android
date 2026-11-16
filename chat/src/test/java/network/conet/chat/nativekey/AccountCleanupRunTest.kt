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
 * `accountCleanupOld` (25.52Y.91, CU-01 to CU-08) through the run that the bridge calls, with the real platform file store in a temporary
 * directory. Nothing touches a device or real data. The adapters here are the history directory only; the other stores are not enumerated yet,
 * so a production run cannot finish (see [UnenumeratedStore]).
 */
class AccountCleanupRunTest {
    @get:Rule
    val tmp = TemporaryFolder()

    private val newEoa = "0x1111111111111111111111111111111111111111"
    private val oldEoa = "0x2222222222222222222222222222222222222222"
    private val oldEoa2 = "0x3333333333333333333333333333333333333333"
    private val newKey = "$newEoa:default"
    private val oldKey = "$oldEoa:default"

    private lateinit var history: File
    private lateinit var stateFiles: VaultFiles
    private lateinit var journal: CleanupJournal
    private lateinit var confirmation: CleanupConfirmation

    private fun setUp() {
        history = tmp.newFolder("conet-chat")
        val state = AndroidVaultFiles(tmp.newFolder("cleanup-state"))
        stateFiles = state
        journal = CleanupJournal(state)
        confirmation = CleanupConfirmation(state)
        File(history, ChatHistoryFileNames.localName(newEoa)).writeText("new-local")
        File(history, ChatHistoryFileNames.pendingName(newEoa)).writeText("new-pending")
        File(history, ChatHistoryFileNames.localName(oldEoa)).writeText("old-local")
        File(history, ChatHistoryFileNames.localName(oldEoa) + "-wal").writeText("old-wal")
        File(history, ChatHistoryFileNames.pendingName(oldEoa)).writeText("old-pending")
        File(history, ChatHistoryFileNames.localName(oldEoa2)).writeText("old2-local")
    }

    private fun oldFiles(): List<String> = listOf(
        ChatHistoryFileNames.localName(oldEoa),
        ChatHistoryFileNames.localName(oldEoa) + "-wal",
        ChatHistoryFileNames.pendingName(oldEoa),
        ChatHistoryFileNames.localName(oldEoa2),
    )

    private fun newFiles(): List<String> = listOf(ChatHistoryFileNames.localName(newEoa), ChatHistoryFileNames.pendingName(newEoa))

    private fun snapshot(): Map<String, String> = history.listFiles().orEmpty().associate { it.name to it.readText() }

    private fun runWith(
        adapters: List<CleanupAdapter> = listOf(HistoryDirCleanup(history)),
        fields: List<String> = listOf("accountKey", "idempotencyKey"),
        accountKey: String? = newKey,
        idem: String? = "idem-1",
        gateNotReady: Boolean = false,
        newAccountKey: String? = newKey,
        readable: Boolean = true,
    ): AccountCleanupOld.Outcome = AccountCleanupRun(journal, confirmation, adapters).run(
        payloadFields = fields,
        accountKey = accountKey,
        idempotencyKey = idem,
        gateNotReady = gateNotReady,
        newAccountKey = newAccountKey,
        newAccountReadable = readable,
    )

    /** Removes a name of the given owner only when [fails] says so, as a removal that does not take effect. */
    private class FailingRemoval(private val inner: CleanupAdapter, private val fails: (AccountCleanupOld.Item) -> Boolean) : CleanupAdapter {
        override fun scan(newAccountKey: String): AccountCleanupOld.Scan = inner.scan(newAccountKey)

        override fun remove(item: AccountCleanupOld.Item): Boolean = if (fails(item)) false else inner.remove(item)
    }

    /** CU-01: confirmed, every old item removed, the new account's items kept, the journal and the confirmation cleared. */
    @Test
    fun cu01SucceedsDeletesTheOldStoresAndKeepsTheNewAccount() {
        setUp()
        confirmation.record(newKey, 1L)
        val before = snapshot()

        val out = runWith()

        assertEquals(AccountCleanupOld.OK, out.code)
        assertFalse(out.cleanupPending)
        for (name in oldFiles()) assertFalse("$name is removed", File(history, name).exists())
        for (name in newFiles()) assertEquals("$name is kept unchanged", before[name], File(history, name).readText())
        assertFalse("the journal is cleared", stateFiles.exists(CleanupJournal.NAME))
        assertFalse("the confirmation is consumed", confirmation.confirmedFor(newKey))
    }

    /** CU-02: a confirmation carried by the page is refused, nothing is deleted. */
    @Test
    fun cu02ConfirmationInThePayloadIsRefusedAndDeletesNothing() {
        setUp()
        confirmation.record(newKey, 1L)
        val before = snapshot()

        val out = runWith(fields = listOf("accountKey", "idempotencyKey", "userConfirmed"))

        assertEquals(AccountCleanupOld.CONFIRMATION_NOT_NATIVE, out.code)
        assertEquals(before, snapshot())
    }

    /** CU-03: no native confirmation, nothing is deleted. */
    @Test
    fun cu03WithoutNativeConfirmationNothingIsDeleted() {
        setUp()
        val before = snapshot()

        val out = runWith()

        assertEquals(AccountCleanupOld.NOT_CONFIRMED, out.code)
        assertEquals(before, snapshot())
    }

    /** CU-04: the new account is not readable, nothing is deleted. */
    @Test
    fun cu04NewAccountUnreadableIsNotAvailableAndDeletesNothing() {
        setUp()
        confirmation.record(newKey, 1L)
        val before = snapshot()

        val out = runWith(readable = false)

        assertEquals(AccountCleanupOld.NOT_AVAILABLE, out.code)
        assertEquals(before, snapshot())
    }

    /** CU-05: the payload's accountKey is not the native new account, nothing is deleted. */
    @Test
    fun cu05AccountKeyMismatchDeletesNothing() {
        setUp()
        confirmation.record(newKey, 1L)
        val before = snapshot()

        val out = runWith(accountKey = oldKey)

        assertEquals(AccountCleanupOld.ACCOUNT_MISMATCH, out.code)
        assertEquals(before, snapshot())
    }

    /** CU-06: the storage is locked (the gate), nothing is deleted. */
    @Test
    fun cu06LockedGateIsNotReadyAndDeletesNothing() {
        setUp()
        confirmation.record(newKey, 1L)
        val before = snapshot()

        val out = runWith(gateNotReady = true)

        assertEquals(AccountCleanupOld.NOT_READY, out.code)
        assertEquals(before, snapshot())
    }

    /** CU-07: one removal does not take effect: clear_incomplete, the others are removed, the journal and the confirmation stay. */
    @Test
    fun cu07PartialFailureIsClearIncompleteAndResumable() {
        setUp()
        confirmation.record(newKey, 1L)
        val stuck = ChatHistoryFileNames.localName(oldEoa2)
        val adapters = listOf(FailingRemoval(HistoryDirCleanup(history)) { it.name.endsWith(stuck) })

        val out = runWith(adapters = adapters)

        assertEquals(AccountCleanupOld.CLEAR_INCOMPLETE, out.code)
        assertTrue(out.cleanupPending)
        assertTrue("the failed item stays", File(history, stuck).exists())
        assertFalse("the others are removed", File(history, ChatHistoryFileNames.localName(oldEoa)).exists())
        assertTrue("the journal stays for a resume", stateFiles.exists(CleanupJournal.NAME))
        assertTrue("the confirmation stays for a resume", confirmation.confirmedFor(newKey))
    }

    /** CU-08: the same idempotencyKey finishes only what is left; nothing already removed is handled again. */
    @Test
    fun cu08ResumeWithTheSameKeyRemovesOnlyTheRest() {
        setUp()
        confirmation.record(newKey, 1L)
        val stuck = ChatHistoryFileNames.localName(oldEoa2)
        runWith(adapters = listOf(FailingRemoval(HistoryDirCleanup(history)) { it.name.endsWith(stuck) }))
        val remainingBefore = snapshot()

        val out = runWith(idem = "idem-1")

        assertEquals(AccountCleanupOld.OK, out.code)
        assertFalse(out.cleanupPending)
        assertEquals("only the item left is deleted", listOf("history:$stuck"), out.deleted)
        assertFalse(File(history, stuck).exists())
        assertEquals(remainingBefore.keys - stuck, snapshot().keys)
        assertFalse("the journal is cleared", stateFiles.exists(CleanupJournal.NAME))
    }

    /** After the cleanup the new account's data is intact and usable: its files are unchanged, and a repeat of the cleanup removes nothing. */
    @Test
    fun theNewAccountIsCompleteAfterTheAdapterDeletion() {
        setUp()
        confirmation.record(newKey, 1L)
        val before = snapshot()
        assertEquals(AccountCleanupOld.OK, runWith().code)

        for (name in newFiles()) assertEquals(before[name], File(history, name).readText())
        confirmation.record(newKey, 2L)
        val again = runWith(idem = "idem-2")

        assertEquals(AccountCleanupOld.OK, again.code)
        assertTrue("nothing is removed again", again.deleted.isEmpty())
        for (name in newFiles()) assertTrue(File(history, name).exists())
    }

    /**
     * Y.100: a name with no owner is kept, is not a failure and does not block ok. The known old items are removed and the result is ok.
     */
    @Test
    fun anItemOfUnknownOwnerIsKeptAndDoesNotBlockOk() {
        setUp()
        confirmation.record(newKey, 1L)
        File(history, "stray.dat").writeText("unknown")

        val out = runWith()

        assertEquals(AccountCleanupOld.OK, out.code)
        assertFalse(out.cleanupPending)
        assertEquals("unknown", File(history, "stray.dat").readText())
        assertFalse(File(history, ChatHistoryFileNames.localName(oldEoa)).exists())
    }

    /** A store that cannot be enumerated makes the scan incomplete: clear_incomplete, and the known old items may still go. */
    @Test
    fun anIncompleteScanIsClearIncomplete() {
        setUp()
        confirmation.record(newKey, 1L)

        val out = runWith(adapters = listOf(HistoryDirCleanup(history), UnenumeratedStore("page copies")))

        assertEquals(AccountCleanupOld.CLEAR_INCOMPLETE, out.code)
        assertTrue(out.cleanupPending)
        assertTrue(File(history, ChatHistoryFileNames.localName(newEoa)).exists())
    }

    /** An unreadable journal stops the run before any removal. */
    @Test
    fun anUnreadableJournalDeletesNothing() {
        setUp()
        confirmation.record(newKey, 1L)
        stateFiles.write(CleanupJournal.NAME, "not json".toByteArray(Charsets.UTF_8))
        val before = snapshot()

        val out = runWith()

        assertEquals(AccountCleanupOld.CLEAR_INCOMPLETE, out.code)
        assertTrue(out.cleanupPending)
        assertEquals(before, snapshot())
    }

    /** An unreadable confirmation record is not a confirmation: not_confirmed, nothing is deleted. */
    @Test
    fun anUnreadableConfirmationIsNotAConfirmation() {
        setUp()
        stateFiles.write(CleanupConfirmation.NAME, "garbage".toByteArray(Charsets.UTF_8))
        val before = snapshot()

        val out = runWith()

        assertEquals(AccountCleanupOld.NOT_CONFIRMED, out.code)
        assertEquals(before, snapshot())
    }

    /** The owner of a history name is decided by the name alone: the same EOA in another letter case has the same names. */
    @Test
    fun theHistoryNamesDependOnlyOnTheLowerCaseEoa() {
        assertEquals(ChatHistoryFileNames.localName(oldEoa), ChatHistoryFileNames.localName(oldEoa.uppercase().replaceFirst("0X", "0x")))
        assertEquals(ChatHistoryFileNames.pendingName(oldEoa), ChatHistoryFileNames.pendingName(oldEoa.uppercase().replaceFirst("0X", "0x")))
        assertFalse(ChatHistoryFileNames.localName(oldEoa) == ChatHistoryFileNames.localName(newEoa))
    }
}
