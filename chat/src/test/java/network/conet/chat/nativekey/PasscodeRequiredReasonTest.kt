package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

/** A Locked(passcode_required) state is waiting for the UI, not unreadable. Synthetic values only. */
class PasscodeRequiredReasonTest {
    private val locked = NativeWalletVault.State.Locked(NativeWalletVault.PASSCODE_REQUIRED)

    @Test
    fun theReasonIsThePasscodeRequiredOne() {
        assertEquals("passcode_not_provided", NativeWalletVault.PASSCODE_REQUIRED)
        assertEquals("passcode_not_provided", NoKeyGate.NOT_READY_PASSCODE_REQUIRED)
    }

    @Test
    fun beforeTheSessionItIsNotReadyWithThePasscodeReason() {
        assertEquals(NoKeyGate.Gate.G1, NoKeyGate.gateOf(locked, sessionReady = false))
        assertEquals("passcode_not_provided", NoKeyGate.notReadyReasonOf(locked))
        val answer = NoKeyGate.walletStatusFor(NoKeyGate.Gate.G1, locked)
        assertEquals("not_ready", answer.getString("status"))
        assertEquals("passcode_not_provided", answer.getString("notReadyReason"))
    }

    @Test
    fun inTheSessionItAnswersLockedWithTheSameReasonNotNoKey() {
        assertEquals(NoKeyGate.Gate.G2, NoKeyGate.gateOf(locked, sessionReady = true))
        val answer = NoKeyGate.walletStatusFor(NoKeyGate.Gate.G2, locked)
        assertEquals("locked", answer.getString("status"))
        assertEquals("passcode_not_provided", answer.getString("notReadyReason"))
        assertFalse(answer.optString("status") == NoKeyGate.NO_KEY)
    }

    @Test
    fun otherLockedReasonsKeepTheirMapping() {
        val unreadable = NativeWalletVault.State.Locked("unreadable")
        assertEquals("unreadable", NoKeyGate.notReadyReasonOf(unreadable))
    }
}
