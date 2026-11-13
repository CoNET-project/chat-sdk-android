package network.conet.chat.nativekey

import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The `nativeRecoveryOpen` contract on the host object (spec 25.26.4e.2): the result goes out once, for the pending reqId,
 * and carries only the code and the public address.
 */
class NativeRecoveryHostTest {
    private val sent = mutableListOf<JSONObject>()

    @After
    fun reset() {
        NativeRecoveryHost.launcher = null
        NativeRecoveryHost.events = null
    }

    private fun listen() {
        NativeRecoveryHost.events = { sent += it }
    }

    @Test
    fun withoutAScreenNothingOpensAndNothingIsPending() {
        listen()
        assertFalse(NativeRecoveryHost.open(7))
        NativeRecoveryHost.cancel()
        assertTrue(sent.isEmpty())
    }

    @Test
    fun theResultGoesOutOnceForThePendingRequest() {
        listen()
        NativeRecoveryHost.launcher = { true }
        assertTrue(NativeRecoveryHost.open(7))
        NativeRecoveryHost.finish(RecoveryOutcome.ok("0x9858effd232b4033e47d90003d41ec34ecaeda94"))
        assertEquals(1, sent.size)
        val p = sent.single()
        assertEquals("nativeRecoveryResult", p.getString("type"))
        assertEquals(7, p.getInt("reqId"))
        assertEquals("ok", p.getString("code"))
        assertEquals("0x9858effd232b4033e47d90003d41ec34ecaeda94", p.getString("eoa"))
        // A second finish for the same request sends nothing.
        NativeRecoveryHost.finish(RecoveryOutcome.fail("record_invalid"))
        assertEquals(1, sent.size)
    }

    @Test
    fun aFailureCarriesOnlyTheCode() {
        listen()
        NativeRecoveryHost.launcher = { true }
        NativeRecoveryHost.open(9)
        NativeRecoveryHost.finish(RecoveryOutcome.fail("not_found"))
        val p = sent.single()
        assertEquals("not_found", p.getString("code"))
        assertFalse(p.has("eoa"))
        assertFalse(p.has("code_value"))
    }

    @Test
    fun aScreenThatDoesNotOpenLeavesNothingPending() {
        listen()
        NativeRecoveryHost.launcher = { false }
        assertFalse(NativeRecoveryHost.open(3))
        NativeRecoveryHost.finish(RecoveryOutcome.fail("cancelled"))
        assertTrue(sent.isEmpty())
    }

    @Test
    fun cancelSendsCancelled() {
        listen()
        NativeRecoveryHost.launcher = { true }
        NativeRecoveryHost.open(4)
        NativeRecoveryHost.cancel()
        assertEquals("cancelled", sent.single().getString("code"))
    }
}
