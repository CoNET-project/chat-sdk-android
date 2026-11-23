package network.conet.chat

import network.conet.chat.nativekey.NativeSessionState
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * The public native calls the shell uses in process (2026-11-20, qa.7). nativeIdentityCheck and uiLockState are also bridge commands (table-T v3)
 * and share one implementation with them. The callId registration functions are not bridge commands. The answers follow v45 §50 and v42 §46.
 */
class PublicNativeCallsTest {
    private val eoa = "0x39581c72b8c7d0de85ff22cf3ae178ae813957aa"
    private val other = "0x0cf9000000000000000000000000000000002022"
    private val callId = "call-public-0001"

    @Before
    fun setUp() {
        NativeSessionState.reset()
    }

    @After
    fun tearDown() {
        NativeSessionState.reset()
        BeamioConetChatModule.incomingCallUnbind(callId)
    }

    /** The registration is native-only; the identity check and the UI lock are bridge commands as table-T v3 says. */
    @Test
    fun theBridgeRegistrationMatchesTheSpec() {
        assertTrue(network.conet.chat.BridgeCommandTable.isRegistered("nativeIdentityCheck"))
        assertTrue(network.conet.chat.BridgeCommandTable.isRegistered("uiLockState"))
        assertFalse(network.conet.chat.BridgeCommandTable.isRegistered("incomingCallBind"))
        assertFalse(network.conet.chat.BridgeCommandTable.isRegistered("incomingCallUnbind"))
        assertFalse(network.conet.chat.BridgeCommandTable.isRegistered("incomingCallAuthorizeAnswer"))
    }

    @Test
    fun nativeIdentityCheckIsLockedWhenTheNativeSessionIsLocked() {
        val r = BeamioConetChatModule.nativeIdentityCheck(eoa)
        assertFalse(r.getBoolean("ok"))
        assertEquals("locked", r.getString("error"))
    }

    @Test
    fun nativeIdentityCheckMatchesTheUnlockedAccountCaseInsensitively() {
        NativeSessionState.markReady(eoa)
        val same = BeamioConetChatModule.nativeIdentityCheck(eoa.uppercase().replace("0X", "0x"))
        assertTrue(same.getBoolean("ok"))
        assertTrue(same.getBoolean("match"))
        val diff = BeamioConetChatModule.nativeIdentityCheck(other)
        assertTrue(diff.getBoolean("ok"))
        assertFalse(diff.getBoolean("match"))
    }

    @Test
    fun nativeIdentityCheckRefusesAMalformedEoa() {
        NativeSessionState.markReady(eoa)
        val r = BeamioConetChatModule.nativeIdentityCheck("0x12")
        assertFalse(r.getBoolean("ok"))
        assertEquals("bad_request", r.getString("error"))
    }

    /** Positive and negative examples: a UI-lock report is accepted and changes no answer; the native session alone decides. */
    @Test
    fun uiLockReportsChangeNothingInTheSdk() {
        NativeSessionState.markReady(eoa)
        assertTrue(BeamioConetChatModule.incomingCallBind(callId, eoa))
        BeamioConetChatModule.uiLockState(locked = true)
        assertTrue("a UI lock does not clear the native session", NativeSessionState.isReadyFor(eoa))
        assertEquals("allow", BeamioConetChatModule.incomingCallAuthorizeAnswer(callId, eoa))
        BeamioConetChatModule.uiLockState(locked = false)
        assertEquals("allow", BeamioConetChatModule.incomingCallAuthorizeAnswer(callId, eoa))
    }

    /** Negative examples: a native session that is not loaded asks the UI to unlock; an unbound call is deny; a store fault is never allowed. */
    @Test
    fun theCallRegistrationAuthorizesOnlyFromTheNativeSession() {
        assertTrue(BeamioConetChatModule.incomingCallBind(callId, eoa))
        assertEquals("needs_unlock", BeamioConetChatModule.incomingCallAuthorizeAnswer(callId, eoa))
        NativeSessionState.markReady(eoa)
        assertEquals("allow", BeamioConetChatModule.incomingCallAuthorizeAnswer(callId, eoa))
        BeamioConetChatModule.incomingCallUnbind(callId)
        assertEquals("deny", BeamioConetChatModule.incomingCallAuthorizeAnswer(callId, eoa))
    }
}
