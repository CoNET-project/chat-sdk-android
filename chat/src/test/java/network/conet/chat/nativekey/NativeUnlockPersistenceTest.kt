package network.conet.chat.nativekey

import java.io.File
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The native unlock persists until a cold start (supplement 2026-11-20). These tests pin the session state, the identity check's answers, and the
 * UI-lock path: a UI lock (page destroy) must not clear the native session, and a hot restore of the same account keeps it.
 */
class NativeUnlockPersistenceTest {
    private val eoa = "0x39581c72b8c7d0de85ff22cf3ae178ae813957aa"
    private val other = "0x0cf9000000000000000000000000000000002022"
    private val module: String by lazy { File("src/main/java/network/conet/chat/BeamioConetChatModule.kt").readText(Charsets.UTF_8) }

    @After
    fun tearDown() {
        NativeSessionState.reset()
    }

    private fun answer(json: String, nativeEoa: String?) = NativeIdentityCheck.answer(JSONObject(json), nativeEoa)

    @Test
    fun theSessionRecordsTheAccountAndMatchesCaseInsensitively() {
        assertFalse(NativeSessionState.isReady())
        NativeSessionState.markReady(eoa.uppercase().replace("0X", "0x"))
        assertTrue(NativeSessionState.isReady())
        assertEquals(eoa, NativeSessionState.readyEoa())
        assertTrue(NativeSessionState.isReadyFor(eoa))
        assertFalse(NativeSessionState.isReadyFor(other))
        NativeSessionState.reset()
        assertFalse(NativeSessionState.isReady())
        assertEquals(null, NativeSessionState.readyEoa())
    }

    @Test
    fun anIdentityCheckWhileLockedAnswersLocked() {
        val a = answer("""{"type":"nativeIdentityCheck","reqId":1,"eoa":"$eoa"}""", null)
        assertEquals("locked", (a as NativeIdentityCheck.Answer.Refused).code)
    }

    @Test
    fun anIdentityCheckMatchesTheUnlockedAccountOnly() {
        val same = answer("""{"type":"nativeIdentityCheck","reqId":1,"eoa":"${eoa.uppercase().replace("0X", "0x")}"}""", eoa)
        assertTrue((same as NativeIdentityCheck.Answer.Match).match)
        val diff = answer("""{"type":"nativeIdentityCheck","reqId":2,"eoa":"$other"}""", eoa)
        assertFalse((diff as NativeIdentityCheck.Answer.Match).match)
    }

    @Test
    fun anIdentityCheckRefusesMissingMalformedOrExtraFields() {
        assertEquals("bad_request", (answer("""{"type":"nativeIdentityCheck","reqId":1}""", eoa) as NativeIdentityCheck.Answer.Refused).code)
        assertEquals("bad_request", (answer("""{"type":"nativeIdentityCheck","reqId":1,"eoa":"0x12"}""", eoa) as NativeIdentityCheck.Answer.Refused).code)
        // No secret may cross the bridge: a phrase or key field is refused as an extra field.
        val withPhrase = """{"type":"nativeIdentityCheck","reqId":1,"eoa":"$eoa","phrase":"abandon"}"""
        assertEquals("bad_request", (answer(withPhrase, eoa) as NativeIdentityCheck.Answer.Refused).code)
    }

    @Test
    fun aUiLockDoesNotClearTheNativeSessionInTheModule() {
        // The page destroy (UI lock) must not reset the native session: the reset lives only in identity clear (finishClearIdentity) and in the
        // account-change branch of the new session. Source guard, because the module needs an Android Context to run.
        val destroy = module.substringAfter("    private fun destroy() {").substringBefore("\n    }\n")
        // Any call that clears or locks the native session, its signer or its vault snapshot is forbidden in the UI-lock path.
        val forbidden = listOf(
            "NativeSessionState.reset(", "NativeSessionState.markReady(", "clearNativeSigner(", "invalidateSnapshot(",
            "forget(", "NativeWallet.vault(", "VoiceChannelKeys.clear(", "setNativeSigner(",
            // A1: the page session, its history keys and voiceSessions stay across a UI lock.
            "session = null", "session?.destroyed = true", "history?.destroy(", "history = null", "voiceSessions.clear(",
        )
        for (name in forbidden) assertFalse("destroy (UI lock) must not call $name", destroy.contains(name))
    }

    @Test
    fun aNewSessionClearsTheNativeUnlockOnlyForADifferentAccount() {
        assertTrue(module.contains("nativeEoa != idEoa.lowercase()"))
    }

    /** the SDK keeps no UI-lock reading. The uiLockState handler delegates to a shared function that acts on nothing. */
    @Test
    fun theUiLockStateHandlerHasNoEffectInTheSdk() {
        val handler = module.substringAfter("    private fun uiLockStateCommand(body: JSONObject) {").substringBefore("\n    }\n")
        assertFalse("uiLockState must not call passcodeUnlockSucceeded", handler.contains("passcodeUnlockSucceeded"))
        assertTrue("the bridge handler delegates to the shared uiLockState", handler.contains("uiLockState(locked)"))
        val shared = module.substringAfter("    fun uiLockState(locked: Boolean) = Unit").substringBefore("\n")
        assertTrue("the shared uiLockState is a no-op", shared.isEmpty())
        assertFalse("the SDK holds no UI-unlock state", module.contains("UiUnlockState"))
    }

    /** The callId admission runs before any passcode check in the unlock handler (addenda 10-14, 22; notice v2). */
    @Test
    fun theUnlockAdmissionComesBeforeThePasscodeCheck() {
        val handler = module.substringAfter("    private fun passcodeUnlockAnswer(").substringBefore("\n    }\n")
        val admit = handler.indexOf("PasscodeUnlockEntry.admit(")
        val check = handler.indexOf("PasscodeCommandFlow.unlock(")
        assertTrue("the admission exists", admit > 0)
        assertTrue("the passcode check exists", check > 0)
        assertTrue("the admission comes before the passcode check", admit < check)
    }
}
