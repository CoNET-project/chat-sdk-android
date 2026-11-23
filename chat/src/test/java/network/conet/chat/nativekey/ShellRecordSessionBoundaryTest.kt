package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The shellRecord session gate at the account boundary (2026-11-22): the session counts as ready only for the vault's own Ready
 * account. Synthetic accounts. Covers a Ready vault with another account (not_ready kept), a Locked vault (not_ready kept), an unreadable vault
 * (not_ready kept), and the same account (ready).
 */
class ShellRecordSessionBoundaryTest {

    private val eoa = "0xd49251e1e9f4d4d5bac808861fa4ce23053c986f"
    private val other = "0x2222222222222222222222222222222222222222"

    /** Positive: the same account as the vault's Ready account is ready (the session counts). */
    @Test
    fun theSameReadyAccountIsReady() {
        assertTrue(ShellRecordAccounts.sessionReadyFor(NativeWalletVault.State.Ready(eoa), MnemonicSetStore.Current.Absent, eoa))
        assertTrue(ShellRecordAccounts.sessionReadyFor(NativeWalletVault.State.Ready(eoa), MnemonicSetStore.Current.Absent, eoa.uppercase().replace("0X", "0x")))
    }

    /** Negative: a Ready vault with another account is not ready for this session (the store-adopted session of another account does not count). */
    @Test
    fun aReadyVaultWithAnotherAccountIsNotReady() {
        assertFalse(ShellRecordAccounts.sessionReadyFor(NativeWalletVault.State.Ready(eoa), MnemonicSetStore.Current.Absent, other))
    }

    /** Negative: a Locked vault has no Ready account, so it is not ready, whatever the session holds. */
    @Test
    fun aLockedVaultIsNotReady() {
        assertFalse(ShellRecordAccounts.sessionReadyFor(NativeWalletVault.State.Locked("unreadable"), MnemonicSetStore.Current.Absent, eoa))
        assertFalse(ShellRecordAccounts.sessionReadyFor(NativeWalletVault.State.Locked(NativeWalletVault.PASSCODE_REQUIRED), MnemonicSetStore.Current.Absent, eoa))
    }

    /** Negative: no session at all is not ready. */
    @Test
    fun noSessionIsNotReady() {
        assertFalse(ShellRecordAccounts.sessionReadyFor(NativeWalletVault.State.Ready(eoa), MnemonicSetStore.Current.Absent, null))
    }

    /** Negative (resolve, with the gate on): a Ready vault with another account answers NotReady before any store is opened. */
    @Test
    fun resolveAnswersNotReadyForAReadyVaultWithAnotherAccount() {
        val acc = ShellRecordAccounts.resolve(
            vault = NativeWalletVault.State.Ready(eoa),
            sessionReady = ShellRecordAccounts.sessionReadyFor(NativeWalletVault.State.Ready(eoa), MnemonicSetStore.Current.Absent, other),
            sessionGate = true,
            bound = null,
            copyNames = { emptyList() },
            storeOf = { throw IllegalStateException("no store may be opened here") },
        )
        assertTrue(acc is ShellRecordAccount.NotReady)
    }

    /** Negative (resolve, with the gate on): a Locked vault answers NotReady before any store is opened. */
    @Test
    fun resolveAnswersNotReadyForALockedVault() {
        val acc = ShellRecordAccounts.resolve(
            vault = NativeWalletVault.State.Locked("unreadable"),
            sessionReady = ShellRecordAccounts.sessionReadyFor(NativeWalletVault.State.Locked("unreadable"), MnemonicSetStore.Current.Absent, eoa),
            sessionGate = true,
            bound = null,
            copyNames = { emptyList() },
            storeOf = { throw IllegalStateException("no store may be opened here") },
        )
        assertTrue(acc is ShellRecordAccount.NotReady)
        assertEquals(false, ShellRecordAccounts.sessionReadyFor(NativeWalletVault.State.Locked("unreadable"), MnemonicSetStore.Current.Absent, eoa))
    }
}
