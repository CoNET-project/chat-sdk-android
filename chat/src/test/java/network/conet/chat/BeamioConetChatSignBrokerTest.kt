package network.conet.chat

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * AND-B9 (independent verdict r3), S-3 and T-155: without a native key the broker never asks the page to sign.
 * Each signing request fails with `no_key` at once, and nothing is emitted to the page.
 */
class BeamioConetChatSignBrokerTest {

    @Test
    fun eip191WithoutANativeKeyFailsNotReadyAtOnce() {
        BeamioConetChatSignBroker.clearNativeSigner()
        var result: Result<String>? = null
        BeamioConetChatSignBroker.requestEip191("hello") { result = it }
        val r = result
        assertTrue("the completion must run at once, not wait for a page answer", r != null)
        assertTrue("signing must fail", r!!.isFailure)
        assertEquals("not_ready", r.exceptionOrNull()?.message)
    }

    @Test
    fun eip712WithoutANativeKeyFailsNotReadyAtOnce() {
        BeamioConetChatSignBroker.clearNativeSigner()
        var result: Result<String>? = null
        BeamioConetChatSignBroker.requestEip712(JSONObject().put("primaryType", "Probe")) { result = it }
        val r = result
        assertTrue("the completion must run at once, not wait for a page answer", r != null)
        assertTrue("signing must fail", r!!.isFailure)
        assertEquals("not_ready", r.exceptionOrNull()?.message)
    }

    @Test
    fun noSigningRequestReachesThePageWithoutANativeKey() {
        BeamioConetChatSignBroker.clearNativeSigner()
        var emitted = 0
        BeamioConetChatSignBroker.setEmit { emitted++ }
        BeamioConetChatSignBroker.requestEip191("hello") { }
        BeamioConetChatSignBroker.requestEip712(JSONObject().put("primaryType", "Probe")) { }
        BeamioConetChatSignBroker.setEmit(null)
        assertEquals("no chatModuleSignRequest may be emitted", 0, emitted)
    }

    @Test
    fun thePageSigningRequestIsGoneFromTheSource() {
        // Source guard: the page-signing request kinds and action name are not in the broker any more.
        val src = File("src/main/java/network/conet/chat/BeamioConetChatSignBroker.kt").readText()
        assertFalse(src.contains("chatModuleSignRequest"))
        assertFalse(src.contains("\"eip191\""))
        assertFalse(src.contains("\"eip712\""))
        assertFalse(src.contains("Handler("))
    }
}
