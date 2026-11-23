package network.conet.chat.nativekey

import network.conet.chat.passcode.PasscodeWriteState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

/**
 * The wallet vault (`wallet.v1.*`) under the cleanup (v212 232.5, v213 233, v214 234). Only the five exact names are deletable; each removal takes the vault
 * monitor, refuses while the old account is active, and re-reads the owner under the monitor. Isolated copies are retained as unattributed.
 */
class AccountCleanupWalletVaultTest {
    @get:Rule
    val tmp = TemporaryFolder()

    private val newEoa = "0x1111111111111111111111111111111111111111"
    private val oldEoa = "0x2222222222222222222222222222222222222222"
    private val thirdEoa = "0x3333333333333333333333333333333333333333"
    private val newKey = "$newEoa:default"

    private fun envelope(eoa: String) = """{"v":1,"eoa":"$eoa"}"""

    private fun adapter(dir: File, active: String? = newEoa): WalletVaultCleanup =
        WalletVaultCleanup(dir, Any(), { active }) { d, _ -> CleanupOwners.walletVaultOwner(d) }

    private fun run(dir: File, state: AndroidVaultFiles, confirmation: CleanupConfirmation, adapter: CleanupAdapter, idem: String): AccountCleanupOld.Outcome =
        AccountCleanupRun(CleanupJournal(state), confirmation, listOf(adapter)).run(
            listOf("accountKey", "idempotencyKey"), newEoa, idem, false, newKey, true, ReadBackCheck.Verdict.PASS,
        )

    @Test
    fun aStableOldVaultIsRemovedUnderTheMonitor() {
        val dir = tmp.newFolder("native_wallet_v1")
        val rec = File(dir, NativeWalletVault.REC).apply { writeText(envelope(oldEoa)) }
        val a = adapter(dir)
        val item = a.scan(newKey).items.first { it.name.endsWith(NativeWalletVault.REC) }
        assertTrue("the owner is unchanged and the old account is not active, so the vault is removed", a.remove(item))
        assertFalse(rec.exists())
    }

    /** v212 232.5: a new generation writes the same wallet.v1.rec between the scan and the removal: the vault is kept and the item fails. */
    @Test
    fun aNewGenerationWrittenAfterTheScanKeepsTheVault() {
        val dir = tmp.newFolder("native_wallet_v1")
        val rec = File(dir, NativeWalletVault.REC).apply { writeText(envelope(oldEoa)) }
        val a = adapter(dir)
        val item = a.scan(newKey).items.first { it.name.endsWith(NativeWalletVault.REC) }
        rec.writeText(envelope(newEoa))
        assertFalse(a.remove(item))
        assertEquals(envelope(newEoa), rec.readText())
    }

    /** An owner that cannot be read keeps the vault. */
    @Test
    fun anUnreadableOwnerKeepsTheVault() {
        val dir = tmp.newFolder("native_wallet_v1")
        val rec = File(dir, NativeWalletVault.REC).apply { writeText(envelope(oldEoa)) }
        val a = WalletVaultCleanup(dir, Any(), { newEoa }) { _, _ -> OwnerRead.Unreadable }
        val item = AccountCleanupOld.Item(name = "file:wallet:${NativeWalletVault.REC}", accountKey = "$oldEoa:default")
        assertFalse(a.remove(item))
        assertTrue(rec.exists())
    }

    /** v214 234.3: when the active account is the old account, the whole wallet group is kept (each removal refuses). */
    @Test
    fun whileTheOldAccountIsActiveTheWalletGroupIsKept() {
        val dir = tmp.newFolder("native_wallet_v1")
        File(dir, NativeWalletVault.REC).writeText(envelope(oldEoa))
        val a = adapter(dir, active = oldEoa)
        val item = a.scan(newKey).items.first { it.name.endsWith(NativeWalletVault.REC) }
        assertFalse("the active old account keeps its group", a.remove(item))
        assertTrue(File(dir, NativeWalletVault.REC).exists())
    }

    /** v214 234.1: an isolated copy (wallet.v1.*.isolated.<x>) belonging to a third account is retained, unattributed, and never removed. */
    @Test
    fun anIsolatedCopyOfAThirdAccountIsRetainedAndCountedUnattributed() {
        val dir = tmp.newFolder("native_wallet_v1")
        val rec = File(dir, NativeWalletVault.REC).apply { writeText(envelope(oldEoa)) }
        val isolated = File(dir, "${NativeWalletVault.REC}.isolated.x1").apply { writeText(envelope(thirdEoa)) }
        val state = AndroidVaultFiles(tmp.newFolder("cleanup-state-iso"))
        val confirmation = CleanupConfirmation(state)
        confirmation.record(newKey, 1L)
        val out = run(dir, state, confirmation, adapter(dir), "idem-iso")
        assertEquals(AccountCleanupOld.OK, out.code)
        assertFalse("the old vault is removed", rec.exists())
        assertTrue("the third account's isolated copy is kept", isolated.exists())
        assertEquals(1, out.retainedUnattributed)
    }

    /** v214 234.2: a partial removal answers clear_incomplete with cleanupPending; a later run completes it, and it is not reported as success before that. */
    @Test
    fun aPartialRemovalIsClearIncompleteThenCompletedByALaterRun() {
        val dir = tmp.newFolder("native_wallet_v1")
        val rec = File(dir, NativeWalletVault.REC).apply { writeText(envelope(oldEoa)) }
        val ok = File(dir, NativeWalletVault.MARK).apply { writeText(envelope(oldEoa)) }
        val state = AndroidVaultFiles(tmp.newFolder("cleanup-state-partial"))
        val confirmation = CleanupConfirmation(state)
        confirmation.record(newKey, 1L)
        val inner = adapter(dir)
        val failingRec = object : CleanupAdapter {
            override fun scan(newAccountKey: String) = inner.scan(newAccountKey)
            override fun remove(item: AccountCleanupOld.Item): Boolean = if (item.name.endsWith(NativeWalletVault.REC)) false else inner.remove(item)
        }
        val first = run(dir, state, confirmation, failingRec, "idem-partial")
        assertEquals(AccountCleanupOld.CLEAR_INCOMPLETE, first.code)
        assertTrue(first.cleanupPending)
        assertFalse("the removable item is gone", ok.exists())
        assertTrue("the failed item remains for a later run", rec.exists())

        val second = run(dir, state, confirmation, inner, "idem-partial")
        assertEquals(AccountCleanupOld.OK, second.code)
        assertFalse(rec.exists())
    }

    @Test
    fun theDeletionSetOnlyHasTheFiveExactNames() {
        val dir = tmp.newFolder("native_wallet_v1")
        File(dir, "wallet.v1.other").writeText(envelope(oldEoa))
        val items = adapter(dir).scan(newKey).items
        assertTrue("a non-exact wallet.v1 name is never a deletable item", items.none { it.accountKey != null && it.name.endsWith("wallet.v1.other") })
        assertFalse(adapter(dir).remove(AccountCleanupOld.Item(name = "file:wallet:wallet.v1.other", accountKey = "$oldEoa:default")))
    }
}
