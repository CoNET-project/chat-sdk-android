package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * rc2.2-qa item 7 (25.52Y.91, vectors CU-01 to CU-08). Pure decisions in memory: no file, no directory, no device is touched.
 */
class AccountCleanupOldTest {
    private val newKey = "eoa-new:default"
    private val oldKey = "eoa-old:default"
    private val oldNames = listOf("oldWallet", "oldPgp", "oldCopy", "oldChat", "oldMigrationResidue")

    private fun store(): List<AccountCleanupOld.Item> =
        oldNames.map { AccountCleanupOld.Item(it, oldKey) } +
            listOf(AccountCleanupOld.Item("newWallet", newKey), AccountCleanupOld.Item("newChat", newKey))

    /** One call, as the bridge would make it: input check, preflight, then execution (only when the preflight passes). */
    private fun call(
        fields: List<String> = listOf("accountKey", "idempotencyKey"),
        gateNotReady: Boolean = false,
        readable: Boolean = true,
        confirmed: Boolean = true,
        match: Boolean = true,
        items: List<AccountCleanupOld.Item> = store(),
        failName: String? = null,
        done: MutableSet<String> = mutableSetOf(),
        touched: MutableList<String> = mutableListOf(),
    ): AccountCleanupOld.Outcome {
        AccountCleanupOld.refuseInput(fields, newKey, "k1")?.let { return AccountCleanupOld.Outcome(it, emptyList(), emptyList(), false) }
        AccountCleanupOld.preflight(gateNotReady, readable, confirmed, match)?.let {
            return AccountCleanupOld.Outcome(it, emptyList(), emptyList(), false)
        }
        return AccountCleanupOld.execute(newKey, items, done) {
            touched += it.name
            it.name != failName
        }
    }

    /** CU-01: success. The old storage is removed, the new account and its new data are kept. */
    @Test
    fun cu01SuccessRemovesOldAndKeepsNew() {
        val touched = mutableListOf<String>()
        val r = call(touched = touched)
        assertEquals(AccountCleanupOld.OK, r.code)
        assertEquals(oldNames, r.deleted)
        assertEquals(listOf("newWallet", "newChat"), r.kept)
        assertFalse(r.cleanupPending)
        assertFalse("the new account's items are never handed to remove", touched.any { it.startsWith("new") })
    }

    /** CU-02: a page-supplied confirmation field is refused: confirmation_not_native, nothing removed. */
    @Test
    fun cu02PageConfirmationIsRefused() {
        val r = call(fields = listOf("accountKey", "idempotencyKey", "userConfirmed"))
        assertEquals(AccountCleanupOld.CONFIRMATION_NOT_NATIVE, r.code)
        assertTrue(r.deleted.isEmpty())
    }

    /** CU-03: the native confirmation has not been completed: not_confirmed, nothing removed. */
    @Test
    fun cu03NotConfirmedNativelyRemovesNothing() {
        val r = call(confirmed = false)
        assertEquals(AccountCleanupOld.NOT_CONFIRMED, r.code)
        assertTrue(r.deleted.isEmpty())
    }

    /** CU-04: the new account is not established or not readable: not_available, nothing removed. */
    @Test
    fun cu04NewAccountUnreadableRemovesNothing() {
        val r = call(readable = false)
        assertEquals(AccountCleanupOld.NOT_AVAILABLE, r.code)
        assertTrue(r.deleted.isEmpty())
    }

    /** CU-05: the accountKey in the payload is not the native new account: account_mismatch, nothing removed. */
    @Test
    fun cu05AccountKeyMismatchRemovesNothing() {
        val r = call(match = false)
        assertEquals(AccountCleanupOld.ACCOUNT_MISMATCH, r.code)
        assertTrue(r.deleted.isEmpty())
    }

    /** CU-06: the store is locked or derived-locked: not_ready, nothing removed. */
    @Test
    fun cu06LockedStoreRemovesNothing() {
        val r = call(gateNotReady = true)
        assertEquals(AccountCleanupOld.NOT_READY, r.code)
        assertTrue(r.deleted.isEmpty())
    }

    /** CU-07: one item fails. It is kept, the others are removed and stay removed, and the result is clear_incomplete with a resume pending. */
    @Test
    fun cu07PartialFailureIsResumable() {
        val done = mutableSetOf<String>()
        val r = call(failName = "oldCopy", done = done)
        assertEquals(AccountCleanupOld.CLEAR_INCOMPLETE, r.code)
        assertEquals(listOf("oldWallet", "oldPgp", "oldChat", "oldMigrationResidue"), r.deleted)
        assertEquals(listOf("newWallet", "newChat"), r.kept)
        assertTrue(r.cleanupPending)
        assertEquals("the removed names are recorded for the resume", setOf("oldWallet", "oldPgp", "oldChat", "oldMigrationResidue"), done)
    }

    /** CU-08: the same idempotencyKey again finishes the rest only. Removed items are not handled again, and the result is ok. */
    @Test
    fun cu08IdempotentResumeFinishesTheRest() {
        val done = mutableSetOf("oldWallet", "oldPgp", "oldChat", "oldMigrationResidue")
        val remaining = listOf(
            AccountCleanupOld.Item("oldCopy", oldKey),
            AccountCleanupOld.Item("newWallet", newKey),
            AccountCleanupOld.Item("newChat", newKey),
        )
        val r = call(items = remaining, done = done)
        assertEquals(AccountCleanupOld.OK, r.code)
        assertEquals(listOf("oldCopy"), r.deleted)
        assertEquals(listOf("newWallet", "newChat"), r.kept)
        assertFalse(r.cleanupPending)
    }

    /** Key material in the payload is refused before anything is read (25.52Y.91 第 3 項). */
    @Test
    fun keyMaterialInThePayloadIsRefused() {
        val r = call(fields = listOf("accountKey", "idempotencyKey", "mnemonic"))
        assertEquals(AccountCleanupOld.KEY_REFUSED, r.code)
        assertTrue(r.deleted.isEmpty())
    }

    /** An unknown payload field, or a missing key, is bad_request. */
    @Test
    fun badShapeIsBadRequest() {
        assertEquals(AccountCleanupOld.BAD_REQUEST, call(fields = listOf("accountKey", "idempotencyKey", "extra")).code)
        assertEquals(AccountCleanupOld.BAD_REQUEST, AccountCleanupOld.refuseInput(listOf("accountKey"), newKey, null))
    }
}
