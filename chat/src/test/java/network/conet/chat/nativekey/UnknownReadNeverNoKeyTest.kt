package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Test

/**
 * Negative: an unknown read of the stored wallet (a storage lock, an unreadable record, a damaged marker, a pending rollback, a missing
 * record behind a marker) must never answer walletStatus `no_key`, and must never make the gate G0. The page stays on a retryable
 * not_ready (25.52Y.75, 25.26.4c). Pure gate functions only; the module adoption guard is covered by LegacyAdoptionAsyncTest.
 */
class UnknownReadNeverNoKeyTest {
    private val unknownReasons = listOf("unreadable", "marker_mismatch", "rollback_pending", "record_missing", NativeWalletVault.DISCARD_PENDING)

    @Test
    fun noUnknownLockedStateIsG0OrNoKey() {
        for (reason in unknownReasons) {
            val state = NativeWalletVault.State.Locked(reason)
            for (sessionReady in listOf(false, true)) {
                val gate = NoKeyGate.walletStatusGate(state, sessionReady, keyOnly = false)
                assertNotEquals("reason $reason (session $sessionReady) is never G0", NoKeyGate.Gate.G0, gate)
                val answer = NoKeyGate.walletStatusFor(gate, state)
                assertFalse("reason $reason never answers no_key", answer.optString("status") == NoKeyGate.NO_KEY)
            }
        }
    }

    @Test
    fun anUnknownLockedStateBeforeTheSessionIsNotReadyWithAReason() {
        for (reason in unknownReasons) {
            val answer = NoKeyGate.walletStatusFor(NoKeyGate.Gate.G1, NativeWalletVault.State.Locked(reason))
            assertEquals("reason $reason answers not_ready", NoKeyGate.NOT_READY, answer.getString("status"))
            assertEquals("reason $reason carries an unreadable reason", NoKeyGate.NOT_READY_UNREADABLE, answer.getString("notReadyReason"))
        }
    }

    @Test
    fun aMissingSnapshotIsNotReadyNeverNoKey() {
        // A null snapshot is the unknown answer of storageAnswer (SpecE4Test pins the walletStatus name); it never reaches the G0 branch.
        assertEquals(NoKeyGate.StorageAnswer.WALLET_STATUS_NOT_READY, NoKeyGate.storageAnswer("walletStatus", null))
    }
}
