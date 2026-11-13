package network.conet.chat.nativekey

import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The page contract on the host object (§25.41.3, §25.42.8): `open` answers not_supported, not_available or opened; each
 * submission sends exactly one result for the page's reqId; a failure keeps the page open; `ok` ends it; closing a page
 * with no result yet sends `cancelled`.
 */
class NativeRecoveryHostTest {
    private val sent = mutableListOf<JSONObject>()

    @After
    fun reset() {
        NativeRecoveryHost.launcher = null
        NativeRecoveryHost.events = null
        NativeRecoveryHost.pageClosed()
    }

    private fun listen() {
        NativeRecoveryHost.events = { sent += it }
    }

    @Test
    fun withoutAHostTheAnswerIsNotSupported() {
        listen()
        assertEquals(NativeRecoveryHost.OpenAnswer.NOT_SUPPORTED, NativeRecoveryHost.open("r-1"))
        NativeRecoveryHost.finish(RecoveryOutcome.fail("record_invalid"))
        assertTrue(sent.isEmpty())
    }

    @Test
    fun aHostThatRefusesTheAnswerIsNotAvailable() {
        listen()
        NativeRecoveryHost.launcher = { false }
        assertEquals(NativeRecoveryHost.OpenAnswer.NOT_AVAILABLE, NativeRecoveryHost.open("r-2"))
        assertEquals(null, NativeRecoveryHost.currentReqId())
    }

    @Test
    fun aHostThatOpensTheAnswerIsOpened() {
        listen()
        NativeRecoveryHost.launcher = { true }
        assertEquals(NativeRecoveryHost.OpenAnswer.OPENED, NativeRecoveryHost.open("r-3"))
        assertEquals("r-3", NativeRecoveryHost.currentReqId())
    }

    @Test
    fun aFailureKeepsThePageOpenForARetry() {
        listen()
        NativeRecoveryHost.launcher = { true }
        NativeRecoveryHost.open("r-4")
        NativeRecoveryHost.finish(RecoveryOutcome.fail("network_error"))
        assertEquals("r-4", NativeRecoveryHost.currentReqId())
        NativeRecoveryHost.finish(RecoveryOutcome.fail("bad_pin"))
        assertEquals(listOf("network_error", "bad_pin"), sent.map { it.getString("code") })
        assertEquals(listOf("r-4", "r-4"), sent.map { it.getString("reqId") })
    }

    @Test
    fun okSendsOneResultWithThePublicAddressAndEndsThePage() {
        listen()
        NativeRecoveryHost.launcher = { true }
        NativeRecoveryHost.open("r-5")
        NativeRecoveryHost.finish(RecoveryOutcome.ok("0x9858effd232b4033e47d90003d41ec34ecaeda94"))
        val p = sent.single()
        assertEquals("nativeRecoveryResult", p.getString("type"))
        assertEquals("ok", p.getString("code"))
        assertEquals("0x9858effd232b4033e47d90003d41ec34ecaeda94", p.getString("eoa"))
        assertEquals(null, NativeRecoveryHost.currentReqId())
        // The page is gone: closing it now sends nothing.
        NativeRecoveryHost.pageClosed()
        assertEquals(1, sent.size)
    }

    @Test
    fun backoffCarriesTheSecondsAndNoPublicAddress() {
        listen()
        NativeRecoveryHost.launcher = { true }
        NativeRecoveryHost.open("r-6")
        NativeRecoveryHost.finish(RecoveryOutcome.backoff(30))
        val p = sent.single()
        assertEquals("backoff", p.getString("code"))
        assertEquals(30, p.getInt("cooldownSec"))
        assertFalse(p.has("eoa"))
    }

    @Test
    fun closingAPageWithNoResultSendsCancelled() {
        listen()
        NativeRecoveryHost.launcher = { true }
        NativeRecoveryHost.open("r-7")
        NativeRecoveryHost.pageClosed()
        assertEquals("cancelled", sent.single().getString("code"))
        assertEquals("r-7", sent.single().getString("reqId"))
    }

    @Test
    fun closingAPageAfterAFailureSendsNoCancelled() {
        listen()
        NativeRecoveryHost.launcher = { true }
        NativeRecoveryHost.open("r-8")
        NativeRecoveryHost.finish(RecoveryOutcome.fail("not_found"))
        NativeRecoveryHost.pageClosed()
        assertEquals(listOf("not_found"), sent.map { it.getString("code") })
    }
}
