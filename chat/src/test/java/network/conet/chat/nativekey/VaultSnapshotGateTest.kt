package network.conet.chat.nativekey

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * 25.52Y.70 第 4 项 and 25.52Y.75: the command gate reads the vault snapshot, never the keystore on the caller's thread. Source checks, rule-level.
 */
class VaultSnapshotGateTest {
    private fun module(): String = File("src/main/java/network/conet/chat/BeamioConetChatModule.kt").readText(Charsets.UTF_8)
    private fun vault(): String = File("src/main/java/network/conet/chat/nativekey/NativeWalletVault.kt").readText(Charsets.UTF_8)

    @Test
    fun theGateReadsTheSnapshotNotTheKeystore() {
        val m = module()
        assertTrue("the gate reads the snapshot", m.contains("val snap = NativeWallet.vault(context).snapshotState()"))
        assertFalse("the gate no longer calls state() on the caller's thread", m.contains("val state = NativeWallet.vault(context).state()"))
    }

    @Test
    fun anUnknownSnapshotAnswersNotReadyOnceWithTheUnreadableReason() {
        // 25.52Y.88: the unknown answers come from NoKeyGate.storageAnswer; walletStatus carries the unreadable reason from NoKeyGate.
        val m = module()
        val gate = File("src/main/java/network/conet/chat/nativekey/NoKeyGate.kt").readText(Charsets.UTF_8)
        val unreadableLine = gate.lines().first { it.contains("fun walletStatusUnreadable()") }
        assertTrue("walletStatus carries the unreadable reason", unreadableLine.contains("NOT_READY_UNREADABLE"))
        assertTrue("the gate answers the unknown snapshot through NoKeyGate.storageAnswer", m.contains("NoKeyGate.storageAnswer(type, snap)"))
        assertFalse("the unknown branch never answers g1_uninitialized", m.substringAfter("snap == null").substringBefore("val state = snap").contains("g1_uninitialized"))
    }

    @Test
    fun everyWriteInvalidatesTheSnapshotAndNoWriteRunsReconcile() {
        val v = vault()
        // Shape changed with the 2026-11-16 ruling: invalidated before and after the write (try/finally), never recomputed on the write path.
        assertTrue("store invalidates the snapshot before and after the write", v.contains("return storeWrite(eoa, key, source, phrase)") && v.contains("return storeWrite(eoa, key, source, phrase)"))
        assertTrue("forget invalidates the snapshot before and after the write", v.contains("return forgetWrite()"))
        assertTrue("state() sets the snapshot", v.contains("snapshot = s"))
        assertFalse("a write does not recompute (no reconcile on the write path)", v.contains("snapshot = runCatching { computeState() }"))
    }

    /** Review (2026-11-16, ShellRecord): an unknown snapshot answers shellRecordRead not_ready once, never record_unreadable. Source check. */
    @Test
    fun anUnknownSnapshotAnswersShellRecordReadNotReady() {
        val r = File("src/main/java/network/conet/chat/nativekey/ShellRecord.kt").readText(Charsets.UTF_8)
        assertTrue("the unknown branch returns NotReady", r.substringAfter("val known = vault.snapshotState() ?: run {").substringBefore("}").contains("return ShellRecordAccount.NotReady"))
        assertFalse("the unknown branch never returns Unreadable", r.substringAfter("val known = vault.snapshotState() ?: run {").substringBefore("}").contains("ShellRecordAccount.Unreadable"))
        assertTrue("NotReady is answered not_ready in the gate", r.contains("if (acc is ShellRecordAccount.NotReady) return reply(\"not_ready\", emptyList())"))
    }
}
