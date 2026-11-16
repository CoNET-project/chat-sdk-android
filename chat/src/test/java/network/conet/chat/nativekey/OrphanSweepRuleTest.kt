package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * rc2.2-qa item 2 (25.52Y.85 第 6 条): the start-up orphan sweep removes migration records only as the continuation of an interrupted clear
 * (clear_pending set), and only of the account that clear involves. The decision is [OrphanSweepRule]; the module reads the inputs.
 */
class OrphanSweepRuleTest {
    private val a = "0x" + "a".repeat(40)
    private val b = "0x" + "b".repeat(40)

    /** Without clear_pending nothing is swept, even with a residue of an account and no account active. */
    @Test
    fun withoutClearPendingNothingIsSwept() {
        assertTrue(OrphanSweepRule.accountsToRemove(clearPending = false, involved = a, live = null, accounts = listOf(a, b)).isEmpty())
        assertTrue(OrphanSweepRule.accountsToRemove(clearPending = false, involved = null, live = null, accounts = listOf(a)).isEmpty())
    }

    /** With clear_pending, only the account the clear involves is a candidate; the other account's residue stays. */
    @Test
    fun withClearPendingOnlyTheClearedAccountIsSwept() {
        assertEquals(listOf(a), OrphanSweepRule.accountsToRemove(clearPending = true, involved = a, live = null, accounts = listOf(a, b)))
        assertEquals(listOf(a), OrphanSweepRule.accountsToRemove(clearPending = true, involved = a.uppercase().replace("0X", "0x"), live = null, accounts = listOf(a, b)))
    }

    /** A new account (live) is never a candidate. When live is the cleared account, nothing is removed (fail closed). With no involved account, nothing. */
    @Test
    fun aNewAccountIsNotAffectedByAnInterruptedClear() {
        assertEquals(listOf(a), OrphanSweepRule.accountsToRemove(clearPending = true, involved = a, live = b, accounts = listOf(a, b)))
        assertTrue(OrphanSweepRule.accountsToRemove(clearPending = true, involved = a, live = a, accounts = listOf(a, b)).isEmpty())
        assertTrue(OrphanSweepRule.accountsToRemove(clearPending = true, involved = null, live = b, accounts = listOf(a, b)).isEmpty())
    }
}
