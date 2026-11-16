package network.conet.chat.nativekey

import java.util.concurrent.atomic.AtomicBoolean

/**
 * When the K_pgp upgrade runs (PM ruling): after the account exists and the keychain is readable (unlocked), once per process, asynchronously. A locked
 * keychain never runs it; it runs after the unlock. The page is not blocked and the wallet is not affected by the result.
 */
internal object KpgpUpgradeTrigger {
    private val ran = AtomicBoolean(false)

    /** True when the upgrade should start now: the vault is Ready (unlocked) and the upgrade has not run in this process. Claims the run. */
    fun claim(vault: NativeWalletVault.State?): Boolean {
        if (vault !is NativeWalletVault.State.Ready) return false
        return ran.compareAndSet(false, true)
    }

    /** Tests only: forgets the claim. */
    internal fun resetForTests() {
        ran.set(false)
    }
}
