package network.conet.chat.nativekey

import network.conet.chat.nativekey.InitNodesGate.Verdict
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * The G1 nodes rule of `init` (spec §25.52Y.29, §25.52Y.32 §4). Each case is a real JSON payload.
 * The stored count is a lambda; it must not be read when the `nodes` key is present.
 */
class InitNodesGateTest {
    private fun verdict(json: String, stored: Int, read: () -> Unit = {}): Verdict =
        InitNodesGate.verdict(JSONObject(json)) { read(); stored }

    /** (i) key missing, the device stores nodes: the stored roster is used, ready follows. */
    @Test
    fun missingKeyWithStoredNodesProceeds() {
        assertEquals(Verdict.PROCEED, verdict("{}", stored = 4))
    }

    /** (ii) key missing, nothing stored: nodes_unavailable, no ready. */
    @Test
    fun missingKeyWithNothingStoredIsUnavailable() {
        assertEquals(Verdict.NODES_UNAVAILABLE, verdict("{}", stored = 0))
        assertEquals("nodes_unavailable", InitNodesGate.errorOf(Verdict.NODES_UNAVAILABLE))
    }

    /** (iii) `[]` with nodes stored: nodes_unavailable, no fallback to the stored roster. */
    @Test
    fun emptyArrayIsUnavailableWithNoFallback() {
        var read = false
        assertEquals(Verdict.NODES_UNAVAILABLE, verdict("{\"nodes\":[]}", stored = 5) { read = true })
        assertEquals(false, read) // the stored roster is not consulted when the key is present
        assertEquals(Verdict.NODES_UNAVAILABLE, verdict("{\"nodes\":[]}", stored = 0))
    }

    /** (iv) `null` and a string: bad_request, no fallback, even when nodes are stored. */
    @Test
    fun nullAndStringAreBadRequest() {
        assertEquals(Verdict.BAD_REQUEST, verdict("{\"nodes\":null}", stored = 5))
        assertEquals(Verdict.BAD_REQUEST, verdict("{\"nodes\":null}", stored = 0))
        assertEquals(Verdict.BAD_REQUEST, verdict("{\"nodes\":\"https://example.invalid/nodes\"}", stored = 5))
    }

    /** (iv, cont.) an object, a number and a boolean are not arrays either. */
    @Test
    fun nonArrayShapesAreBadRequest() {
        assertEquals(Verdict.BAD_REQUEST, verdict("{\"nodes\":{\"ip_addr\":\"1.2.3.4\"}}", stored = 3))
        assertEquals(Verdict.BAD_REQUEST, verdict("{\"nodes\":7}", stored = 3))
        assertEquals(Verdict.BAD_REQUEST, verdict("{\"nodes\":true}", stored = 3))
    }

    /** (v) an array whose elements are not objects: bad_request, no fallback. */
    @Test
    fun stringArrayIsBadRequest() {
        assertEquals(Verdict.BAD_REQUEST, verdict("{\"nodes\":[\"https://a\",\"https://b\"]}", stored = 5))
        assertEquals(Verdict.BAD_REQUEST, verdict("{\"nodes\":[{\"ip_addr\":\"1.2.3.4\"},\"x\"]}", stored = 5))
        assertEquals(Verdict.BAD_REQUEST, verdict("{\"nodes\":[null]}", stored = 5))
    }

    /** (vi) a valid non-empty array of NodeInfo objects: ready, the payload roster is used. */
    @Test
    fun validNodeInfoArrayProceeds() {
        val json = "{\"nodes\":[{\"region\":\"us\",\"ip_addr\":\"1.2.3.4\",\"armoredPublicKey\":\"-----BEGIN PGP PUBLIC KEY BLOCK-----\",\"nftNumber\":\"1\",\"domain\":\"si.example.invalid\"}]}"
        assertEquals(Verdict.PROCEED, verdict(json, stored = 0))
        assertNull(InitNodesGate.errorOf(Verdict.PROCEED))
    }

    @Test
    fun codesAreTheSpecNames() {
        assertEquals("nodes_unavailable", InitNodesGate.NODES_UNAVAILABLE)
        assertEquals("bad_request", InitNodesGate.BAD_REQUEST)
        assertEquals("bad_request", InitNodesGate.errorOf(Verdict.BAD_REQUEST))
    }
}
