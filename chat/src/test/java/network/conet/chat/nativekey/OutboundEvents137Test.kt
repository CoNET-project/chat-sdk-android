package network.conet.chat.nativekey

import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/** 25.52Y.137 第 6 項: the outbound shapes of nativeAccountCreateResult (`{type, reqId, ok, result}`) and of the not_ready event. */
class OutboundEvents137Test {
    private val eoa = "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"
    private val payloads = mutableListOf<JSONObject>()

    @Before
    fun setUp() {
        payloads.clear()
        NativeAccountCreateHost.resetForTests()
        NativeAccountCreateHost.launcher = { true }
        NativeAccountCreateHost.events = { payloads.add(it) }
    }

    @After
    fun tearDown() {
        NativeAccountCreateHost.events = null
        NativeAccountCreateHost.pageClosed()
        NativeAccountCreateHost.launcher = null
    }

    @Test
    fun okCarriesTheAccountAndCleanupPendingTrueWhileTheMarkerStays() {
        assertTrue(NativeAccountCreateHost.open("A-1"))
        NativeAccountCreateHost.finish(NativeAccountCreate.Code.OK, eoa, cleanupPending = true)
        val p = payloads.single()
        assertEquals("nativeAccountCreateResult", p.getString("type"))
        assertEquals("A-1", p.getString("reqId"))
        assertTrue(p.getBoolean("ok"))
        val r = p.getJSONObject("result")
        assertEquals("ok", r.getString("code"))
        assertEquals(eoa, r.getString("eoa"))
        assertTrue(r.getBoolean("cleanupPending"))
        assertFalse("the flat fields are gone", p.has("code") || p.has("eoa"))
    }

    @Test
    fun okWithACompletedMarkerCarriesCleanupPendingFalse() {
        assertTrue(NativeAccountCreateHost.open("A-2"))
        NativeAccountCreateHost.finish(NativeAccountCreate.Code.OK, eoa, cleanupPending = false)
        val r = payloads.single().getJSONObject("result")
        assertTrue("cleanupPending is present on ok", r.has("cleanupPending"))
        assertFalse(r.getBoolean("cleanupPending"))
    }

    @Test
    fun alreadyExistsCarriesTheAccountButNoCleanupPending() {
        assertTrue(NativeAccountCreateHost.open("A-3"))
        NativeAccountCreateHost.finish(NativeAccountCreate.Code.ALREADY_EXISTS, eoa)
        val p = payloads.single()
        assertFalse(p.getBoolean("ok"))
        val r = p.getJSONObject("result")
        assertEquals("already_exists", r.getString("code"))
        assertEquals(eoa, r.getString("eoa"))
        assertFalse(r.has("cleanupPending"))
    }

    @Test
    fun aFailureCarriesNoAccountAndNoCleanupPending() {
        assertTrue(NativeAccountCreateHost.open("A-4"))
        NativeAccountCreateHost.finish(NativeAccountCreate.Code.WRITE_FAILED, null)
        val p = payloads.single()
        assertFalse(p.getBoolean("ok"))
        val r = p.getJSONObject("result")
        assertEquals("write_failed", r.getString("code"))
        assertFalse(r.has("eoa"))
        assertFalse(r.has("cleanupPending"))
    }

    /** 25.52Y.140: not_ready is the request's own answer (the ack), never a pushed event. The page stays open and nothing is sent. */
    @Test
    fun notReadyPushesNothingAndThePageStaysOpen() {
        assertTrue(NativeAccountCreateHost.open("A-5"))
        NativeAccountCreateHost.finish(NativeAccountCreate.Code.NOT_READY, null)
        assertTrue("no event is pushed for not_ready", payloads.isEmpty())
        assertTrue("the page is still open", NativeAccountCreateHost.isPageOpen())
        // A result after it is delivered for the same request, as the only nativeAccountCreateResult.
        NativeAccountCreateHost.finish(NativeAccountCreate.Code.WRITE_FAILED, null)
        assertEquals(1, payloads.size)
        assertEquals("nativeAccountCreateResult", payloads.single().getString("type"))
        assertEquals("write_failed", payloads.single().getJSONObject("result").getString("code"))
    }

    /** 25.52Y.140: a not_ready open answers ack {ok:false, error:"not_ready"} only: no page, no result, no notReadyReason. */
    @Test
    fun notReadyOpenAnswerIsTheAckOnly() {
        val ack = NativeOpenRules.ackPayload("N-R1", NativeOpenRules.Reply(NativeOpenRules.NOT_READY))
        assertEquals("ack", ack.getString("type"))
        assertFalse(ack.getBoolean("ok"))
        assertEquals("not_ready", ack.getString("error"))
        assertFalse(ack.has("page"))
        assertFalse(ack.has("notReadyReason"))
    }

    /** 25.52Y.138 第 1 項 and 25.52Y.140: the account-create result event is nested for every result, and flat for the other types. */
    @Test
    fun theResultPayloadIsNestedForAccountCreateOnly() {
        val nested = NativeOpenRules.resultPayload("nativeAccountCreateResult", "N-35", "already_bound")
        assertEquals("nativeAccountCreateResult", nested.getString("type"))
        assertFalse(nested.getBoolean("ok"))
        assertEquals("already_bound", nested.getJSONObject("result").getString("code"))
        assertFalse(nested.has("code"))
        val flat = NativeOpenRules.resultPayload("nativeImportResult", "I-2", "write_failed")
        assertEquals("write_failed", flat.getString("code"))
        assertFalse(flat.has("result"))
    }
}
