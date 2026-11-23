package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * The G2 flag behind `BeamioConetChatModule.isNativeSessionReady()` (spec 25.26.4c). The shell uses it to tell G1
 * (`not_ready`) from G2. The module sets it only after a successful init and clears it on destroy, clear and session
 * replacement. These tests cover the flag and the gate decision that reads it.
 */
class NativeSessionStateTest {
    private val eoa = "0x39581c72b8c7d0de85ff22cf3ae178ae813957aa"
    private val record = NativeWalletVault.State.Ready(eoa)

    @Before
    fun startWithoutASession() {
        NativeSessionState.reset()
    }

    @Test
    fun theFlagStartsFalseAndFollowsMarkAndReset() {
        assertFalse(NativeSessionState.isReady())
        NativeSessionState.markReady("0x39581c72b8c7d0de85ff22cf3ae178ae813957aa")
        assertTrue(NativeSessionState.isReady())
        NativeSessionState.reset()
        assertFalse(NativeSessionState.isReady())
    }

    @Test
    fun theGateIsG1WithARecordAndNoInitAndG2AfterInit() {
        // With a record and no successful init: G1, so every name except init answers not_ready.
        assertEquals(NoKeyGate.Gate.G1, NoKeyGate.gateOf(record, NativeSessionState.isReady()))
        assertEquals("not_ready", NoKeyGate.answerFor("deriveLocalKeys", NoKeyGate.gateOf(record, NativeSessionState.isReady())))
        NativeSessionState.markReady("0x39581c72b8c7d0de85ff22cf3ae178ae813957aa")
        assertEquals(NoKeyGate.Gate.G2, NoKeyGate.gateOf(record, NativeSessionState.isReady()))
        assertEquals("dispatch", NoKeyGate.answerFor("send", NoKeyGate.gateOf(record, NativeSessionState.isReady())))
    }

    @Test
    fun aSessionClearedAfterInitIsG1AgainWhileTheRecordStays() {
        NativeSessionState.markReady("0x39581c72b8c7d0de85ff22cf3ae178ae813957aa")
        NativeSessionState.reset()
        // G2 -> G1 on destroy or clear (25.26.4c): the record is still there.
        assertEquals(NoKeyGate.Gate.G1, NoKeyGate.gateOf(record, NativeSessionState.isReady()))
    }

    @Test
    fun withoutARecordTheGateIsG0RegardlessOfTheFlag() {
        NativeSessionState.markReady("0x39581c72b8c7d0de85ff22cf3ae178ae813957aa")
        assertEquals(NoKeyGate.Gate.G0, NoKeyGate.gateOf(NativeWalletVault.State.NoKey, NativeSessionState.isReady()))
    }
}
