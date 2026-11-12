package network.conet.chat.nativekey

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * `walletStatus` and `passcodeStatus` by gate (table D, r3g; AND-N4, AND-N5, T-160). The account below is a synthetic
 * address; no key is involved in these answers.
 */
class NoKeyStatusTest {
    private val eoa = "0xAbCdEf0000000000000000000000000000000001"
    private val record = NativeWalletVault.State.Ready(eoa)

    @Test
    fun walletStatusG2UnlockedCarriesTheAccountKey() {
        val gate = NoKeyGate.gateOf(record, sessionReady = true)
        assertEquals(NoKeyGate.Gate.G2, gate)
        val s: JSONObject = NoKeyGate.walletStatusFor(gate, record)
        assertEquals("unlocked", s.getString("status"))
        assertEquals("0xabcdef0000000000000000000000000000000001:default", s.getString("accountKey"))
    }

    @Test
    fun walletStatusG2LockedHasNoAccountKey() {
        // A locked record has no verified account, so no accountKey is given.
        val locked = NativeWalletVault.State.Locked("marker_mismatch")
        val s = NoKeyGate.walletStatusFor(NoKeyGate.gateOf(locked, sessionReady = true), locked)
        assertEquals("locked", s.getString("status"))
        assertFalse(s.has("accountKey"))
    }

    @Test
    fun walletStatusG1IsNotReadyAndNeverUnlocked() {
        // T-160: a record without a session. W1 must not report unlocked here.
        val gate = NoKeyGate.gateOf(record, sessionReady = false)
        assertEquals(NoKeyGate.Gate.G1, gate)
        val s = NoKeyGate.walletStatusFor(gate, record)
        assertEquals("not_ready", s.getString("status"))
        assertFalse(s.has("accountKey"))
    }

    @Test
    fun walletStatusG0IsNoKeyAndNothingElse() {
        val gate = NoKeyGate.gateOf(NativeWalletVault.State.NoKey, sessionReady = false)
        assertEquals(NoKeyGate.Gate.G0, gate)
        val s = NoKeyGate.walletStatusFor(gate, NativeWalletVault.State.NoKey)
        assertEquals("no_key", s.getString("status"))
        assertFalse(s.has("accountKey"))
    }

    @Test
    fun passcodeStatusHasKeyFromG1OnAndNotFromG0() {
        for (gate in listOf(NoKeyGate.Gate.G1, NoKeyGate.Gate.G2)) {
            val p = NoKeyGate.passcodeStatusFor(gate)
            assertEquals(false, p.getBoolean("set"))
            assertEquals(false, p.getBoolean("locked"))
            assertTrue(p.getBoolean("hasKey"))
        }
        val g0 = NoKeyGate.passcodeStatusFor(NoKeyGate.Gate.G0)
        assertEquals(false, g0.getBoolean("set"))
        assertEquals(false, g0.getBoolean("locked"))
        assertEquals(false, g0.getBoolean("hasKey"))
    }

    @Test
    fun g1InitChecksTheEoaAgainstTheRecord() {
        assertEquals("ok", NoKeyGate.initAnswer(eoa, eoa.lowercase()))
        assertEquals("ok", NoKeyGate.initAnswer(eoa, eoa.uppercase().replace("0X", "0x")))
        assertEquals("address_mismatch", NoKeyGate.initAnswer(eoa, "0x2222222222222222222222222222222222222222"))
        assertEquals("address_mismatch", NoKeyGate.initAnswer(eoa, null))
        assertEquals("address_mismatch", NoKeyGate.initAnswer(eoa, ""))
    }

    @Test
    fun answersByGateForAGenericName() {
        assertEquals("no_key", NoKeyGate.answerFor("deriveLocalKeys", NoKeyGate.Gate.G0))
        assertEquals("not_ready", NoKeyGate.answerFor("deriveLocalKeys", NoKeyGate.Gate.G1))
        assertEquals("dispatch", NoKeyGate.answerFor("send", NoKeyGate.Gate.G2))
        assertEquals("init", NoKeyGate.answerFor("init", NoKeyGate.Gate.G1))
        assertEquals("dispatch", NoKeyGate.answerFor("init", NoKeyGate.Gate.G2))
        assertEquals("not_supported", NoKeyGate.answerFor("walletTransferOnce", NoKeyGate.Gate.G1))
        assertEquals("allowed", NoKeyGate.answerFor("nativeRecoveryOpen", NoKeyGate.Gate.G1))
        assertEquals("status", NoKeyGate.answerFor("walletStatus", NoKeyGate.Gate.G1))
    }

    @Test
    fun accountKeyIsEoaColonWorkspaceWithDefaultWorkspace() {
        assertEquals("0xabc:default", NoKeyGate.accountKeyOf("0xABC"))
        assertEquals("0xabc:ws", NoKeyGate.accountKeyOf("0xABC", "ws"))
    }
}
