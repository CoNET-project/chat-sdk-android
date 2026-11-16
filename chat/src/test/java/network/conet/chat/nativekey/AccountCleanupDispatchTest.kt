package network.conet.chat.nativekey

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.IOException

/**
 * The `accountCleanupOld` dispatch entry (Y.103 第 2 条, 25.52Y.91 第 6 项). The module cannot be built on the JVM, so the entry is driven with an
 * injected [CleanupRun]: the test builds the same [AccountCleanupRun] the module builds, over recording adapters in a temporary directory. The
 * proof is that the entry reaches that run, and that the run's answer comes back as the ack's code. No device data and no key.
 */
class AccountCleanupDispatchTest {
    @get:Rule
    val tmp = TemporaryFolder()

    private val newKey = "0x1111111111111111111111111111111111111111:default"
    private val oldKey = "0x2222222222222222222222222222222222222222:default"

    /** Records the scans and the removals of the old account's item and of the inbox, as the store adapters do. */
    private class Recording(private val items: List<AccountCleanupOld.Item>) : CleanupAdapter {
        var scans = 0
        val removed = mutableListOf<String>()

        override fun scan(newAccountKey: String): AccountCleanupOld.Scan {
            scans++
            return AccountCleanupOld.Scan(items, complete = true)
        }

        override fun remove(item: AccountCleanupOld.Item): Boolean {
            removed += item.name
            return true
        }
    }

    private fun realRun(confirmed: Boolean, adapters: List<CleanupAdapter>): AccountCleanupRun {
        val state = AndroidVaultFiles(tmp.root.resolve("state").apply { mkdirs() })
        val confirmation = CleanupConfirmation(state)
        if (confirmed) confirmation.record(newKey, 1L)
        return AccountCleanupRun(CleanupJournal(state), confirmation, adapters)
    }

    private fun runner(run: AccountCleanupRun): CleanupRun = { fields, accountKey, idem, newAccount, readable ->
        run.run(
            payloadFields = fields,
            accountKey = accountKey,
            idempotencyKey = idem,
            gateNotReady = false,
            newAccountKey = newAccount,
            newAccountReadable = readable,
        )
    }

    private fun body(vararg extra: Pair<String, String>): JSONObject {
        val b = JSONObject().put("type", "accountCleanupOld").put("reqId", "r1").put("accountKey", newKey).put("idempotencyKey", "i1")
        for ((k, v) in extra) b.put(k, v)
        return b
    }

    private fun oldItem() = AccountCleanupOld.Item("history:old", oldKey)

    private fun inboxItems(n: Int) = (0 until n).map { AccountCleanupOld.Item("inbox:$it", null) }

    @Test
    fun theEntryRunsTheSameRunAndReturnsItsCodeAsTheAck() {
        val adapter = Recording(listOf(oldItem()) + inboxItems(2))
        val run = realRun(confirmed = true, adapters = listOf(adapter))

        val ack = AccountCleanupDispatch.handle(
            reqId = "r1",
            body = body(),
            nativeNewAccount = { newKey },
            runFor = { runner(run) },
        )

        assertEquals("the run scanned the adapter", 1, adapter.scans)
        assertEquals("the old item was removed by that run", listOf("history:old"), adapter.removed)
        assertEquals("ack", ack.getString("type"))
        assertEquals("r1", ack.getString("reqId"))
        assertTrue(ack.getBoolean("ok"))
        assertFalse(ack.getJSONObject("result").getBoolean("cleanupPending"))
        assertEquals("the two inbox entries are retained and counted", 2, ack.getJSONObject("result").getInt("retainedUnattributed"))
    }

    @Test
    fun aPayloadConfirmationFromTheEntryIsRefusedByTheSameRunAndNothingIsRemoved() {
        val adapter = Recording(listOf(oldItem()))
        val run = realRun(confirmed = true, adapters = listOf(adapter))

        val ack = AccountCleanupDispatch.handle(
            reqId = "r2",
            body = body("userConfirmed" to "true"),
            nativeNewAccount = { newKey },
            runFor = { runner(run) },
        )

        assertFalse(ack.getBoolean("ok"))
        assertEquals("confirmation_not_native", ack.getString("error"))
        assertTrue("the refusal happens before any scan", adapter.removed.isEmpty())
    }

    @Test
    fun aNewAccountThatIsNotReadableFromTheEntryIsNotAvailable() {
        val adapter = Recording(listOf(oldItem()))
        val run = realRun(confirmed = true, adapters = listOf(adapter))

        val ack = AccountCleanupDispatch.handle(
            reqId = "r3",
            body = body(),
            nativeNewAccount = { null },
            runFor = { runner(run) },
        )

        assertEquals("not_available", ack.getString("error"))
        assertTrue(adapter.removed.isEmpty())
    }

    @Test
    fun aMissingContextIsNotReadyAndRunsNothing() {
        val ack = AccountCleanupDispatch.handle(
            reqId = "r4",
            body = body(),
            nativeNewAccount = { newKey },
            runFor = { null },
        )

        assertFalse(ack.getBoolean("ok"))
        assertEquals("not_ready", ack.getString("error"))
    }

    @Test
    fun aRunThatThrowsIsClearIncompleteWithCleanupPendingAndNeverOk() {
        val ack = AccountCleanupDispatch.handle(
            reqId = "r5",
            body = body(),
            nativeNewAccount = { newKey },
            runFor = { { _, _, _, _, _ -> throw IOException("store unreadable") } },
        )

        assertFalse(ack.getBoolean("ok"))
        assertEquals("clear_incomplete", ack.getString("error"))
        assertTrue(ack.getJSONObject("result").getBoolean("cleanupPending"))
    }

    @Test
    fun aNativeAccountThatThrowsIsTreatedAsNotReadable() {
        val adapter = Recording(listOf(oldItem()))
        val run = realRun(confirmed = true, adapters = listOf(adapter))

        val ack = AccountCleanupDispatch.handle(
            reqId = "r6",
            body = body(),
            nativeNewAccount = { throw IOException("vault unreadable") },
            runFor = { runner(run) },
        )

        assertEquals("not_available", ack.getString("error"))
        assertTrue(adapter.removed.isEmpty())
    }

    /** A run that cannot be built and throws is still exactly one answer for the reqId: clear_incomplete with cleanupPending, never ok. */
    @Test
    fun aRunBuilderThatThrowsStillAnswersTheReqIdOnce() {
        val ack = AccountCleanupDispatch.handle(
            reqId = "r7",
            body = body(),
            nativeNewAccount = { newKey },
            runFor = { throw IOException("store cannot be opened") },
        )

        assertEquals("r7", ack.getString("reqId"))
        assertFalse(ack.getBoolean("ok"))
        assertEquals("clear_incomplete", ack.getString("error"))
        assertTrue(ack.getJSONObject("result").getBoolean("cleanupPending"))
    }
}
