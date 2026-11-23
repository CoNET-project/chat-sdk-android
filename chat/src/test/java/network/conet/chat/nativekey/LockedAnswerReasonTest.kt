package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * a vault state that cannot run a command answers not_ready with an honest reason, never "locked", and never reports an
 * unreadable state as a missing record. Positive and negative examples of [NoKeyGate.lockedReasonOf] and [NoKeyGate.notReadyResult].
 */
class LockedAnswerReasonTest {

    /** Positive: a passcode-protected record without a passcode is passcode_not_provided, retryable. */
    @Test
    fun aPasscodeRecordWithoutAPasscodeIsPasscodeNotProvidedAndRetryable() {
        val state = NativeWalletVault.State.Locked(NativeWalletVault.PASSCODE_REQUIRED)
        val reason = NoKeyGate.lockedReasonOf(state)
        assertEquals("passcode_not_provided", reason)
        val result = NoKeyGate.notReadyResult(reason)
        assertEquals("passcode_not_provided", result.getString("reason"))
        assertTrue(result.getBoolean("retryable"))
    }

    /** Positive: a read or keystore failure is unreadable (unknown), retryable, never a missing record. */
    @Test
    fun aReadFailureIsUnreadableAndNeverMissing() {
        val state = NativeWalletVault.State.Locked("unreadable")
        val reason = NoKeyGate.lockedReasonOf(state)
        assertEquals(NoKeyGate.NOT_READY_UNREADABLE, reason)
        assertTrue(NoKeyGate.notReadyResult(reason).getBoolean("retryable"))
    }

    /** Positive: an unfinished rollback is unknown too (the existing reason is kept, not replaced by a missing answer). */
    @Test
    fun aRollbackPendingKeepsTheUnreadableReason() {
        val state = NativeWalletVault.State.Locked("rollback_pending")
        assertEquals(NoKeyGate.NOT_READY_UNREADABLE, NoKeyGate.lockedReasonOf(state))
    }

    /** Negative: the answer is never "locked" and never "no_key" for a passcode-protected record. */
    @Test
    fun theAnswerIsNeverLockedOrNoKey() {
        val reasons = listOf(
            NoKeyGate.lockedReasonOf(NativeWalletVault.State.Locked(NativeWalletVault.PASSCODE_REQUIRED)),
            NoKeyGate.lockedReasonOf(NativeWalletVault.State.Locked("unreadable")),
        )
        for (r in reasons) {
            assertFalse(r == "locked")
            assertFalse(r == NoKeyGate.NO_KEY)
        }
    }

    /** Negative: a passcode-protected record is never reported as an absent (missing) record. */
    @Test
    fun aPasscodeRecordIsNotReportedAsMissing() {
        val reason = NoKeyGate.lockedReasonOf(NativeWalletVault.State.Locked(NativeWalletVault.PASSCODE_REQUIRED))
        assertFalse(reason == "record_missing")
        assertFalse(reason == NoKeyGate.NOT_READY_KEY_ONLY)
    }

    /** Positive (2026-11-22): one code for a passcode-protected record on every path, the command path and the walletStatus path. */
    @Test
    fun theCommandPathAndTheWalletStatusPathShareOneCode() {
        val locked = NativeWalletVault.State.Locked(NativeWalletVault.PASSCODE_REQUIRED)
        assertEquals("passcode_not_provided", NoKeyGate.lockedReasonOf(locked))
        assertEquals("passcode_not_provided", NoKeyGate.notReadyReasonOf(locked))
        assertEquals("passcode_not_provided", NoKeyGate.NOT_READY_PASSCODE_REQUIRED)
    }

    /** Negative: the result always names a reason; a bare not_ready without a reason is not produced here. */
    @Test
    fun theResultAlwaysCarriesAReasonAndRetryable() {
        val result = NoKeyGate.notReadyResult(NoKeyGate.NOT_READY_UNREADABLE)
        assertTrue(result.has("reason"))
        assertTrue(result.has("retryable"))
    }
}
