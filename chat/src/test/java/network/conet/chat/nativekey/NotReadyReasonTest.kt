package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * `notReadyReason` on the walletStatus `not_ready` answer (spec §25.52Y.39 第 9、10 项). G0, G2 and a locked
 * G2 carry no reason. The G1 answer carries `g1_uninitialized` for a readable record and `unreadable` for a record that
 * cannot be read.
 */
class NotReadyReasonTest {
    private val eoa = "0xAbCdEf0000000000000000000000000000000001"

    /**
     * 25.52Y.140 第 3 項: every G1 answer carries `notReadyReason` (never absent: a missing reason is read as unreadable, and that would deadlock the
     * G1 init). A readable record gives g1_uninitialized; every other G1 state gives unreadable.
     */
    @Test
    fun everyG1AnswerCarriesItsReasonAndNothingElse() {
        val states = listOf(
            NativeWalletVault.State.Ready(eoa),
            NativeWalletVault.State.Locked("unreadable"),
            NativeWalletVault.State.Locked("marker_mismatch"),
            NativeWalletVault.State.Locked("rollback_pending"),
            NativeWalletVault.State.Locked("record_missing"),
        )
        for (st in states) {
            val gate = NoKeyGate.gateOf(st, sessionReady = false)
            assertEquals(NoKeyGate.Gate.G1, gate)
            val s = NoKeyGate.walletStatusFor(gate, st)
            assertEquals("not_ready", s.getString("status"))
            assertTrue("the reason is present for $st", s.has("notReadyReason"))
            val want = if (st is NativeWalletVault.State.Ready) "g1_uninitialized" else "unreadable"
            assertEquals("the reason for $st", want, s.getString("notReadyReason"))
        }
    }

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

    /** r3oc (k): a damaged marker, a pending rollback, and an unreadable store all answer not_ready, reason unreadable (never unavailable, locked or no_key). */
    @Test
    fun damagedMarkerAndPendingRollbackAreUnreadableNotReady() {
        for (reason in listOf("marker_mismatch", "rollback_pending", "unreadable")) {
            val locked = NativeWalletVault.State.Locked(reason)
            val s = NoKeyGate.walletStatusFor(NoKeyGate.gateOf(locked, sessionReady = false), locked)
            assertEquals(reason, "not_ready", s.getString("status"))
            assertEquals(reason, "unreadable", s.getString("notReadyReason"))
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
