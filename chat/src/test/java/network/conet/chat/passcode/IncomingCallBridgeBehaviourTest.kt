package network.conet.chat.passcode

import android.content.Context
import android.content.ContextWrapper
import java.io.File
import network.conet.chat.BeamioConetChatModule
import network.conet.chat.MainPoster
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Behavioural negative tests (acceptance item 2): `incomingCallBind` and `incomingCallUnbind` sent through the real
 * [BeamioConetChatModule.handleCommand] entry are refused as `unknown_command`, and the shared incoming-call registry is not changed by them.
 * The module is not mocked: the entry, its pre-gate checks and the envelope run as in the app. The only stand-in is a [ContextWrapper] with a
 * temporary files directory. Android's Log and other stubs return defaults (unitTests.isReturnDefaultValues).
 *
 * Coverage limit: the test runs in the module's default state, where the test environment has no key. The name is refused before the gate, so
 * the gate state (G0, G1, G2, locked, busy) does not change the answer; that order is checked by UnknownBridgeNamesTest from the source. The
 * harness does not drive the states themselves.
 */
class IncomingCallBridgeBehaviourTest {
    private val eoa = "0x39581c72b8c7d0de85ff22cf3ae178ae813957aa"
    private val callId = "call-behaviour-1"
    private lateinit var context: Context

    /** A context whose application context is itself and whose files live in a temporary directory. */
    private class TestContext(private val dir: File) : ContextWrapper(null) {
        override fun getApplicationContext(): Context = this
        override fun getFilesDir(): File = dir
        override fun getCacheDir(): File = dir
    }

    @Before
    fun setUp() {
        val dir = kotlin.io.path.createTempDirectory("incoming-call-bridge").toFile()
        context = TestContext(dir)
        // Module answers are posted to the main thread in the app; here they run inline so they reach the caller.
        MainPoster.runner = { it.run() }
        // Start from a known registry: one active call, bound by the native API (not the bridge).
        IncomingCalls.registry.onSessionEnded(eoa, SessionGeneration.Reason.LOGOUT)
        assertTrue(IncomingCalls.registry.incomingCallBind(callId, eoa))
    }

    private fun send(body: JSONObject): List<JSONObject> {
        val out = mutableListOf<JSONObject>()
        BeamioConetChatModule.handleCommand(context, body) { out.add(it) }
        return out
    }

    private fun envelope(type: String, reqId: Any = 1) = JSONObject()
        .put("type", type)
        .put("reqId", reqId)
        .put("callId", callId)
        .put("eoa", eoa)

    @org.junit.After
    fun tearDown() {
        MainPoster.runner = null
        IncomingCalls.registry.onSessionEnded(eoa, SessionGeneration.Reason.LOGOUT)
    }

    /** The module emits `{action:"chatModuleEvent", event:{...}}`; the ack is the event with type "ack". */
    private fun answerOf(out: List<JSONObject>): JSONObject? =
        out.mapNotNull { it.optJSONObject("event") }.lastOrNull { it.optString("type") == "ack" }

    private fun assertRegistryUnchanged() {
        // The registered call still passes the SDK's own check for the same account and call.
        val check = IncomingCalls.registry.check(callId, eoa, eoa)
        assertTrue("the registration still holds the call", check is IncomingCallRegistry.CallCheck.Proceed)
    }

    @Test
    fun incomingCallBindFromThePageIsRefusedAsUnknownCommandAndRegistersNothing() {
        val other = "call-page-injected"
        val out = send(envelope("incomingCallBind").put("callId", other))
        val ack = answerOf(out) ?: error("expected an ack, got $out")
        assertEquals("unknown_command", ack.optString("error"))
        assertFalse(ack.optBoolean("ok"))
        // The page's callId was not registered: the registry still knows only the native call.
        assertTrue(IncomingCalls.registry.check(other, eoa, eoa) is IncomingCallRegistry.CallCheck.CallMismatch)
        assertRegistryUnchanged()
    }

    @Test
    fun incomingCallUnbindFromThePageIsRefusedAsUnknownCommandAndClearsNothing() {
        val out = send(envelope("incomingCallUnbind"))
        val ack = answerOf(out) ?: error("expected an ack, got $out")
        assertEquals("unknown_command", ack.optString("error"))
        assertFalse(ack.optBoolean("ok"))
        assertRegistryUnchanged()
    }

    @Test
    fun theNamesAreRefusedWithAMalformedEnvelopeToo() {
        // A malformed reqId is answered by the envelope check (bad_request, null reqId) before any name is looked at.
        val out = send(envelope("incomingCallBind", reqId = JSONObject()))
        val ack = answerOf(out) ?: error("expected an ack, got $out")
        assertEquals("bad_request", ack.optString("error"))
        assertRegistryUnchanged()
    }

    @Test
    fun theNamesWithoutAReqIdAreRefusedByTheEnvelope() {
        val body = JSONObject().put("type", "incomingCallUnbind").put("callId", callId)
        val ack = answerOf(send(body)) ?: error("expected an ack")
        assertEquals("bad_request", ack.optString("error"))
        assertRegistryUnchanged()
    }

    @Test
    fun theNamesAreRefusedOnEveryRepeatedSend() {
        repeat(3) {
            val ack = answerOf(send(envelope("incomingCallBind", reqId = it + 2))) ?: error("expected an ack")
            assertEquals("unknown_command", ack.optString("error"))
        }
        assertRegistryUnchanged()
    }
}
