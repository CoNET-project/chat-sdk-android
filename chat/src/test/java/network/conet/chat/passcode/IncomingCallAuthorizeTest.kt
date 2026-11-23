package network.conet.chat.passcode

import network.conet.chat.nativekey.NativeSessionState
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * The shell's pre-signing decision, after : the SDK reads only the native session. The passcode and the UI
 * lock belong to the UI and are not read here. `incomingCallAuthorizeAnswer` returns allow when the registration is still the named call, the current
 * account is the registered eoa, the generation still equals gen0 and the native session is loaded. A session that is not loaded is needs_unlock.
 * An unreadable reading (a storage or keystore fault) is deny, never hidden.
 */
class IncomingCallAuthorizeTest {
    private val eoa = "0x39581c72b8c7d0de85ff22cf3ae178ae813957aa"
    private val other = "0x0cf9000000000000000000000000000000002022"

    /** A fixed native reading; null means unreadable. */
    private class FixedSession(private val native: Boolean?) : PasscodeSessionSource {
        override fun nativeUnlocked(account: String): Boolean? = native
    }

    private class ThrowingSession : PasscodeSessionSource {
        override fun nativeUnlocked(account: String): Boolean? = throw IllegalStateException("injected read fault")
    }

    private fun registry(session: PasscodeSessionSource, gen: SessionGeneration = SessionGeneration()) =
        IncomingCallRegistry(gen, session)

    @After
    fun tearDown() {
        NativeSessionState.reset()
    }

    // ---- positive examples ----

    @Test
    fun allowsWhenTheNativeSessionIsLoadedAndTheCallIsActiveAndGenUnchanged() {
        val calls = registry(FixedSession(native = true))
        calls.incomingCallBind("call-aaaa1111", eoa)
        assertEquals(IncomingCallRegistry.ALLOW, calls.incomingCallAuthorizeAnswer("call-aaaa1111", eoa))
    }

    @Test
    fun allowsWhenAPasscodeIsSetAndTheNativeSessionIsLoaded() {
        // Without any UI reading the passcode no longer blocks the answer: the UI owns it.
        NativeSessionState.markReady(eoa)
        val calls = IncomingCallRegistry(SessionGeneration(), NativeSessionSource)
        calls.incomingCallBind("call-aaaa1111", eoa)
        assertEquals(IncomingCallRegistry.ALLOW, calls.incomingCallAuthorizeAnswer("call-aaaa1111", eoa))
    }

    @Test
    fun allowsAgainAfterANewBindCapturesTheCurrentGeneration() {
        val gen = SessionGeneration()
        val calls = registry(FixedSession(native = true), gen)
        calls.incomingCallBind("call-aaaa1111", eoa)
        gen.advance(eoa, SessionGeneration.Reason.LOCK)
        calls.incomingCallBind("call-bbbb2222", eoa)
        assertEquals(IncomingCallRegistry.ALLOW, calls.incomingCallAuthorizeAnswer("call-bbbb2222", eoa))
    }

    // ---- the native session is not loaded: the UI runs the unlock ----

    @Test
    fun needsUnlockWhenTheNativeSessionIsNotLoaded() {
        // Cold start or a locked native session: the prompt is needs_unlock, whether or not a passcode is set.
        val calls = registry(FixedSession(native = false))
        calls.incomingCallBind("call-aaaa1111", eoa)
        assertEquals(IncomingCallRegistry.NEEDS_UNLOCK, calls.incomingCallAuthorizeAnswer("call-aaaa1111", eoa))
    }

    @Test
    fun theProductionSourceNeedsUnlockUntilTheNativeSessionIsLoaded() {
        NativeSessionState.reset()
        val calls = IncomingCallRegistry(SessionGeneration(), NativeSessionSource)
        calls.incomingCallBind("call-aaaa1111", eoa)
        assertEquals(IncomingCallRegistry.NEEDS_UNLOCK, calls.incomingCallAuthorizeAnswer("call-aaaa1111", eoa))
        NativeSessionState.markReady(eoa)
        assertEquals(IncomingCallRegistry.ALLOW, calls.incomingCallAuthorizeAnswer("call-aaaa1111", eoa))
    }

    // ---- negative examples: storage faults and the non-unlock conditions stay deny ----

    @Test
    fun deniesWhenTheNativeReadingIsUnreadable() {
        val calls = registry(FixedSession(native = null))
        calls.incomingCallBind("call-aaaa1111", eoa)
        assertEquals(IncomingCallRegistry.DENY, calls.incomingCallAuthorizeAnswer("call-aaaa1111", eoa))
    }

    @Test
    fun deniesWhenTheSourceThrows() {
        val calls = registry(ThrowingSession())
        calls.incomingCallBind("call-aaaa1111", eoa)
        assertEquals(IncomingCallRegistry.DENY, calls.incomingCallAuthorizeAnswer("call-aaaa1111", eoa))
    }

    @Test
    fun deniesEverywhereWithNoSourceAtAll() {
        val calls = IncomingCallRegistry(SessionGeneration())
        calls.incomingCallBind("call-aaaa1111", eoa)
        assertEquals(IncomingCallRegistry.DENY, calls.incomingCallAuthorizeAnswer("call-aaaa1111", eoa))
    }

    @Test
    fun aNonUnlockConditionFailingBeatsTheUnlockPrompt() {
        // The session is not loaded, but the call is not the registered one or the account differs: deny, never needs_unlock (v120 §139.2).
        val calls = registry(FixedSession(native = false))
        calls.incomingCallBind("call-aaaa1111", eoa)
        assertEquals(IncomingCallRegistry.DENY, calls.incomingCallAuthorizeAnswer("call-bbbb2222", eoa))
        assertEquals(IncomingCallRegistry.DENY, calls.incomingCallAuthorizeAnswer("call-aaaa1111", other))
    }

    @Test
    fun deniesWhenTheNamedCallIsNotTheRegisteredOne() {
        val calls = registry(FixedSession(native = true))
        calls.incomingCallBind("call-aaaa1111", eoa)
        assertEquals(IncomingCallRegistry.DENY, calls.incomingCallAuthorizeAnswer("call-bbbb2222", eoa))
    }

    @Test
    fun deniesWhenNoCallIsRegistered() {
        val calls = registry(FixedSession(native = true))
        assertEquals(IncomingCallRegistry.DENY, calls.incomingCallAuthorizeAnswer("call-aaaa1111", eoa))
    }

    @Test
    fun deniesWhenTheCurrentAccountIsNotTheRegisteredEoa() {
        val calls = registry(FixedSession(native = true))
        calls.incomingCallBind("call-aaaa1111", eoa)
        assertEquals(IncomingCallRegistry.DENY, calls.incomingCallAuthorizeAnswer("call-aaaa1111", other))
    }

    @Test
    fun deniesWhenTheGenerationHasAdvancedSinceBindEvenIfTheCallWasNotCleared() {
        val gen = SessionGeneration()
        val calls = registry(FixedSession(native = true), gen)
        calls.incomingCallBind("call-aaaa1111", eoa)
        // A session end that advances the generation without clearing the registration: gen is no longer gen0.
        gen.advance(eoa, SessionGeneration.Reason.ACCOUNT_SWITCH)
        assertEquals(IncomingCallRegistry.DENY, calls.incomingCallAuthorizeAnswer("call-aaaa1111", eoa))
    }
}
