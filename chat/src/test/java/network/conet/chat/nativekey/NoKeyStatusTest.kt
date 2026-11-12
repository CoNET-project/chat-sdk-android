package network.conet.chat.nativekey

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-N4 and AND-N5 (independent verdict r3): the `walletStatus` and `passcodeStatus` answers for every vault state.
 * The account below is a synthetic address; no key is involved in these answers.
 */
class NoKeyStatusTest {
    private val eoa = "0xAbCdEf0000000000000000000000000000000001"

    @Test
    fun walletStatusUnlockedCarriesTheAccountKey() {
        val s: JSONObject = NoKeyGate.walletStatusOf(NativeWalletVault.State.Ready(eoa))
        assertEquals("unlocked", s.getString("status"))
        assertEquals("0xabcdef0000000000000000000000000000000001:default", s.getString("accountKey"))
    }

    @Test
    fun walletStatusLockedHasNoAccountKey() {
        // A locked record has no verified account, so no accountKey is given.
        val s = NoKeyGate.walletStatusOf(NativeWalletVault.State.Locked("marker_mismatch"))
        assertEquals("locked", s.getString("status"))
        assertFalse(s.has("accountKey"))
    }

    @Test
    fun walletStatusWithoutARecordIsNoKeyAndNothingElse() {
        val s = NoKeyGate.walletStatusOf(NativeWalletVault.State.NoKey)
        assertEquals("no_key", s.getString("status"))
        assertFalse(s.has("accountKey"))
    }

    @Test
    fun passcodeStatusReportsTheRecordWithoutAPasscodeLayer() {
        for (state in listOf(NativeWalletVault.State.Ready(eoa), NativeWalletVault.State.Locked("unreadable"))) {
            val p = NoKeyGate.passcodeStatusOf(state)
            assertEquals(false, p.getBoolean("set"))
            assertEquals(false, p.getBoolean("locked"))
            assertTrue(p.getBoolean("hasKey"))
        }
    }

    @Test
    fun passcodeStatusWithoutARecordReportsNoKey() {
        val p = NoKeyGate.passcodeStatusOf(NativeWalletVault.State.NoKey)
        assertEquals(false, p.getBoolean("set"))
        assertEquals(false, p.getBoolean("locked"))
        assertEquals(false, p.getBoolean("hasKey"))
    }

    @Test
    fun accountKeyIsEoaColonWorkspaceWithDefaultWorkspace() {
        assertEquals("0xabc:default", NoKeyGate.accountKeyOf("0xABC"))
        assertEquals("0xabc:ws", NoKeyGate.accountKeyOf("0xABC", "ws"))
    }
}
