package network.conet.chat.nativekey

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/** The trigger of the K_pgp upgrade (PM ruling): only when the keychain is unlocked, and once per process. */
class KpgpUpgradeTriggerTest {
    @Before
    fun reset() = KpgpUpgradeTrigger.resetForTests()

    @Test
    fun aLockedOrAbsentKeychainDoesNotRun() {
        assertFalse(KpgpUpgradeTrigger.claim(null))
        assertFalse(KpgpUpgradeTrigger.claim(NativeWalletVault.State.NoKey))
        assertFalse(KpgpUpgradeTrigger.claim(NativeWalletVault.State.Locked("unreadable")))
    }

    @Test
    fun anUnlockedKeychainRunsOnceInTheProcess() {
        val ready = NativeWalletVault.State.Ready("0x" + "ab".repeat(20))
        assertTrue(KpgpUpgradeTrigger.claim(ready))
        assertFalse(KpgpUpgradeTrigger.claim(ready))
    }

    @Test
    fun aLockThenUnlockRunsAfterTheUnlock() {
        assertFalse(KpgpUpgradeTrigger.claim(NativeWalletVault.State.Locked("marker_missing")))
        assertTrue(KpgpUpgradeTrigger.claim(NativeWalletVault.State.Ready("0x" + "ab".repeat(20))))
    }
}
