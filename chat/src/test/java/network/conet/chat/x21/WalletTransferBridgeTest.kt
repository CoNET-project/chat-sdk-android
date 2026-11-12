package network.conet.chat.x21

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * X-21 bridge contract (spec r3b 25.6.1, batch 14): routing by `cmd.type`, `ack` shapes, public-only
 * request payloads, matching of responses, timeout, and invalid payloads. The fake store exists only here;
 * the build itself runs with [WalletTransferBridge.NativeStore.NotWired].
 */
class WalletTransferBridgeTest {
    private val eoa = "0x00000000000000000000000000000000000000aa"
    private var clock = 0L

    private class FakeStore(private val allow: Boolean = true, private val code: String? = "ok") : WalletTransferBridge.NativeStore {
        override val available: Boolean = true
        var lastBytes: ByteArray? = null
        override fun mayRequest(eoa: String, kind: String): Boolean = allow
        override fun commit(eoa: String, kind: String, bytes: ByteArray): String? {
            lastBytes = bytes.copyOf()
            return code
        }
        override fun markSwitched(requestId: String): Boolean? = true
    }

    private fun bridge(store: WalletTransferBridge.NativeStore = WalletTransferBridge.NativeStore.NotWired) =
        WalletTransferBridge(now = { clock }, store = store)

    private fun ints(n: Int, fill: Int = 7): JSONArray = JSONArray().apply { repeat(n) { put(fill) } }

    private fun once(reqId: Int, requestId: String, kind: String, bytes: JSONArray): JSONObject =
        JSONObject().put("type", "walletTransferOnce").put("reqId", reqId)
            .put("requestId", requestId).put("kind", kind).put("bytes", bytes)

    private fun types(list: List<JSONObject>): List<String> = list.map { it.getString("type") }

    @Test
    fun notWiredIssuesNoRequest() {
        val b = bridge()
        assertNull(b.issue(eoa, "eoaKey"))
        assertNull(b.issue(eoa, "pgpArmor"))
    }

    @Test
    fun unsolicitedOnceIsRejectedWithoutResult() {
        val out = bridge().onCommand(once(7, "not-issued", "eoaKey", ints(32)))
        assertEquals(listOf("ack"), types(out))
        assertEquals(7, out[0].getInt("reqId"))
        assertFalse(out[0].getBoolean("ok"))
        assertEquals("not_requested", out[0].getString("error"))
    }

    @Test
    fun statusAndSwitchedReportNoStoreWhileNotWired() {
        val b = bridge()
        val status = b.onCommand(JSONObject().put("type", "walletTransferStatus").put("reqId", 3))
        assertEquals("native_store_unavailable", status[0].getString("error"))
        val switched = b.onCommand(JSONObject().put("type", "walletTransferSwitched").put("reqId", 4).put("requestId", "x"))
        assertEquals("native_store_unavailable", switched[0].getString("error"))
        assertEquals(listOf("ack"), types(switched))
    }

    @Test
    fun commandWithoutPositiveReqIdGetsNoAck() {
        assertTrue(bridge().onCommand(JSONObject().put("type", "walletTransferStatus")).isEmpty())
        assertTrue(bridge().onCommand(once(0, "x", "eoaKey", ints(32))).isEmpty())
    }

    @Test
    fun requestPayloadCarriesPublicDataOnly() {
        val b = FakeStore().let { bridge(it) }
        val req = requireNotNull(b.issue(eoa, "eoaKey"))
        assertEquals("walletTransferRequest", req.getString("type"))
        assertEquals(setOf("type", "requestId", "kind", "eoa"), req.keys().asSequence().toSet())
        assertEquals("eoaKey", req.getString("kind"))
        assertEquals(eoa, req.getString("eoa"))
        assertTrue(Regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$").matches(req.getString("requestId")))
    }

    @Test
    fun secondRequestOfSameKindIsRefused() {
        val b = bridge(FakeStore())
        assertNotNull(b.issue(eoa, "eoaKey"))
        assertNull(b.issue(eoa, "eoaKey"))
        assertNotNull(b.issue(eoa, "pgpArmor"))
    }

    @Test
    fun matchingOnceCommitsAndReportsResult() {
        val store = FakeStore(code = "ok")
        val b = bridge(store)
        val req = requireNotNull(b.issue(eoa, "eoaKey"))
        val out = b.onCommand(once(9, req.getString("requestId"), "eoaKey", ints(32, fill = 5)))
        assertEquals(listOf("ack", "walletTransferResult"), types(out))
        assertTrue(out[0].getBoolean("ok"))
        assertEquals("ok", out[1].getString("code"))
        assertEquals(setOf("type", "requestId", "kind", "code"), out[1].keys().asSequence().toSet())
        assertEquals(32, store.lastBytes!!.size)
        assertEquals(5, store.lastBytes!![0].toInt())
        // The request ended with the response: a repeat is not matched.
        assertEquals("not_requested", b.onCommand(once(10, req.getString("requestId"), "eoaKey", ints(32)))[0].getString("error"))
    }

    @Test
    fun wrongRequestIdIsRejectedAndTheRequestStaysOpen() {
        val b = bridge(FakeStore(code = "ok"))
        val req = requireNotNull(b.issue(eoa, "eoaKey"))
        val wrong = b.onCommand(once(1, "00000000-0000-0000-0000-000000000000", "eoaKey", ints(32)))
        assertEquals("not_requested", wrong[0].getString("error"))
        assertEquals(listOf("ack"), types(wrong))
        // The real response is still accepted.
        assertEquals(listOf("ack", "walletTransferResult"), types(b.onCommand(once(2, req.getString("requestId"), "eoaKey", ints(32)))))
    }

    @Test
    fun wrongLengthEndsRequestWithInvalidPayload() {
        val b = bridge(FakeStore())
        val req = requireNotNull(b.issue(eoa, "eoaKey"))
        val out = b.onCommand(once(5, req.getString("requestId"), "eoaKey", ints(31)))
        assertEquals(listOf("ack", "walletTransferResult"), types(out))
        assertFalse(out[0].getBoolean("ok"))
        assertEquals("invalid_payload", out[0].getString("error"))
        assertEquals("invalid_payload", out[1].getString("code"))
        // Ended: a new request of the same kind is allowed again.
        assertNotNull(b.issue(eoa, "eoaKey"))
    }

    @Test
    fun outOfRangeValueIsInvalidPayload() {
        val b = bridge(FakeStore())
        val req = requireNotNull(b.issue(eoa, "eoaKey"))
        val bad = ints(32).apply { put(0, 256) }
        assertEquals("invalid_payload", b.onCommand(once(6, req.getString("requestId"), "eoaKey", bad))[1].getString("code"))
    }

    @Test
    fun timeoutEndsRequestWithoutStateChange() {
        val b = bridge(FakeStore(code = "ok"))
        clock = 0L
        val req = requireNotNull(b.issue(eoa, "eoaKey"))
        clock = 29_999L
        assertTrue(b.sweep().isEmpty())
        clock = 30_000L
        val timeout = b.sweep()
        assertEquals(listOf("walletTransferResult"), types(timeout))
        assertEquals("timeout", timeout[0].getString("code"))
        assertEquals(req.getString("requestId"), timeout[0].getString("requestId"))
        // A response after the timeout is not matched.
        assertEquals("not_requested", b.onCommand(once(8, req.getString("requestId"), "eoaKey", ints(32)))[0].getString("error"))
    }

    @Test
    fun commandsSweepTimeoutsFirst() {
        val b = bridge(FakeStore())
        clock = 0L
        assertNotNull(b.issue(eoa, "eoaKey"))
        clock = 40_000L
        val out = b.onCommand(JSONObject().put("type", "walletTransferStatus").put("reqId", 11))
        assertEquals(listOf("walletTransferResult", "ack"), types(out))
    }

    @Test
    fun storeUnavailableAfterMatchGivesAckRejectionAndNoResult() {
        val b = bridge(FakeStore(code = null))
        val req = requireNotNull(b.issue(eoa, "eoaKey"))
        val out = b.onCommand(once(12, req.getString("requestId"), "eoaKey", ints(32)))
        assertEquals(listOf("ack"), types(out))
        assertEquals("native_store_unavailable", out[0].getString("error"))
    }
}
