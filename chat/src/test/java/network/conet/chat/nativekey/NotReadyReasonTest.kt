package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

/**
 * `notReadyReason` on the walletStatus `not_ready` answer (spec §25.52Y.39 第 9、10 项; PM R1841). G0, G2 and a locked
 * G2 carry no reason. The G1 answer carries `g1_uninitialized` for a readable record and `unreadable` for a record that
 * cannot be read.
 */
class NotReadyReasonTest {
    private val eoa = "0xAbCdEf0000000000000000000000000000000001"

    /** G1, readable record, not initialised: g1_uninitialized. */
    @Test
    fun readableUninitialisedRecordIsG1Uninitialized() {
        val ready = NativeWalletVault.State.Ready(eoa)
        val gate = NoKeyGate.gateOf(ready, sessionReady = false)
        assertEquals(NoKeyGate.Gate.G1, gate)
        val s = NoKeyGate.walletStatusFor(gate, ready)
        assertEquals("not_ready", s.getString("status"))
        assertEquals("g1_uninitialized", s.getString("notReadyReason"))
    }

    /** G1 with a store that cannot be read: not_ready, reason unreadable (not g1_uninitialized). */
    @Test
    fun unreadableRecordIsUnreadable() {
        val locked = NativeWalletVault.State.Locked("unreadable")
        val gate = NoKeyGate.gateOf(locked, sessionReady = false)
        assertEquals(NoKeyGate.Gate.G1, gate)
        val s = NoKeyGate.walletStatusFor(gate, locked)
        assertEquals("not_ready", s.getString("status"))
        assertEquals("unreadable", s.getString("notReadyReason"))
    }

    /** r3ny (k): a damaged marker or a pending rollback is unavailable, with no reason field. */
    @Test
    fun damagedMarkerAndPendingRollbackAreUnavailable() {
        for (reason in listOf("marker_mismatch", "rollback_pending")) {
            val locked = NativeWalletVault.State.Locked(reason)
            val s = NoKeyGate.walletStatusFor(NoKeyGate.gateOf(locked, sessionReady = false), locked)
            assertEquals("$reason", "unavailable", s.getString("status"))
            assertFalse(s.has("notReadyReason"))
        }
    }

    /** r3ny (k): a key record with no marker is never locked: the wallet answers as usable (no unavailable, no not_ready). */
    @Test
    fun unmarkedKeyRecordIsNotLocked() {
        val ready = NativeWalletVault.State.Ready(eoa)
        val s = NoKeyGate.walletStatusFor(NoKeyGate.gateOf(ready, sessionReady = false), ready)
        assertEquals("not_ready", s.getString("status"))
        assertEquals("g1_uninitialized", s.getString("notReadyReason"))
    }

    /** G0 (no record): no status reason at all. */
    @Test
    fun g0CarriesNoReason() {
        val s = NoKeyGate.walletStatusFor(NoKeyGate.Gate.G0, NativeWalletVault.State.NoKey)
        assertEquals("no_key", s.getString("status"))
        assertFalse(s.has("notReadyReason"))
    }

    /** G2 unlocked and G2 locked: no reason. */
    @Test
    fun g2CarriesNoReason() {
        val ready = NativeWalletVault.State.Ready(eoa)
        val unlocked = NoKeyGate.walletStatusFor(NoKeyGate.Gate.G2, ready)
        assertEquals("unlocked", unlocked.getString("status"))
        assertFalse(unlocked.has("notReadyReason"))
        val locked = NoKeyGate.walletStatusFor(NoKeyGate.Gate.G2, NativeWalletVault.State.Locked("x"))
        assertEquals("locked", locked.getString("status"))
        assertFalse(locked.has("notReadyReason"))
    }

    /** The reason codes are the spec names. */
    @Test
    fun codesAreTheSpecNames() {
        assertEquals("g1_uninitialized", NoKeyGate.NOT_READY_G1_UNINITIALIZED)
        assertEquals("unreadable", NoKeyGate.NOT_READY_UNREADABLE)
    }
}
