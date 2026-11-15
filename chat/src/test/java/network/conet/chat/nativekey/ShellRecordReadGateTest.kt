package network.conet.chat.nativekey

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * The read gate of shellRecordRead on the SDK side (spec §25.52Y.41 第 4、5、6、7 项; PM R1890). The source and main frame are checked
 * by the shell before the SDK is called and again at the SDK boundary (origin_refused). A read that names a key-shaped field is refused
 * as key material, with names only. Other unknown names stay bad_request. A read never returns a value in a refusal.
 */
class ShellRecordReadGateTest {
    private val eoa = "0x9858effd232b4033e47d90003d41ec34ecaeda94"

    private fun bridge(): ShellRecordBridge {
        val files = NativeTestFiles()
        val store = SealedPageRecordStore(NativeTestWrap(), files, "$eoa:default")
        return ShellRecordBridge(
            account = { ShellRecordAccount.Ready(store, eoa) },
            migrating = { false },
            outcome = { null },
        )
    }

    private fun read(extra: Map<String, Any>): JSONObject {
        val body = JSONObject().put("type", "shellRecordRead").put("reqId", "r1")
        for ((k, v) in extra) body.put(k, v)
        return bridge().handle(ShellOrigin.EMBEDDED_PAGE, body, 64).v()
    }

    /** A key-shaped top-level name on a read is refused as key material, not as an unknown name. */
    @Test
    fun aKeyShapedNameOnAReadIsKeyOverBridgeRefused() {
        assertEquals("key_over_bridge_refused", read(mapOf("privateKeyHex" to "0x00")).getString("code"))
        assertEquals("key_over_bridge_refused", read(mapOf("mnemonicPhrase" to "abandon")).getString("code"))
    }

    /** Any other unknown name on a read stays bad_request (the rule is unchanged for it). */
    @Test
    fun anOrdinaryUnknownNameOnAReadIsBadRequest() {
        assertEquals("bad_request", read(mapOf("note" to "x")).getString("code"))
    }

    /** A source that is not the embedded page is refused before anything is read. */
    @Test
    fun aNonEmbeddedOriginIsRefused() {
        val body = JSONObject().put("type", "shellRecordRead").put("reqId", "r2")
        assertEquals("origin_refused", bridge().handle(ShellOrigin.OTHER, body, 64).v().getString("code"))
    }
}
