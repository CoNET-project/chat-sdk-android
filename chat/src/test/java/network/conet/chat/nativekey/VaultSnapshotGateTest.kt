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
        val m = module()
        assertTrue("walletStatus carries unreadable", m.contains("put(\"notReadyReason\", \"unreadable\")"))
        assertFalse("the unknown branch never answers g1_uninitialized", m.contains("g1_uninitialized\")") && m.substringAfter("snap == null").substringBefore("val state = snap").contains("g1_uninitialized"))
    }

    @Test
    fun everyWriteRecomputesTheSnapshotUnderTheLock() {
        val v = vault()
        assertTrue("store recomputes the snapshot", v.contains("snapshot = runCatching { computeState() }.getOrNull()"))
        assertTrue("forget recomputes the snapshot", v.contains("private fun forgetWrite()"))
        assertTrue("state() sets the snapshot", v.contains("snapshot = s"))
    }
}
