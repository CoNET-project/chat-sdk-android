package network.conet.chat.nativekey

import network.conet.chat.nativekey.ShellRecordAccount
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

/**
 * SRP-04 (option A): a real write fault of shellRecordWrite answers the envelope {ok:false, error:"write_failed"}, the
 * record is not written, and the page copy is not created. The write is the target write (the first-write path, store empty).
 */
class ShellRecordWriteFailedEnvelopeTest {

    private val eoa = "0xAbC0000000000000000000000000000000000001"
    private val accountKey = eoa.lowercase() + ":default"

    @Test
    fun aRealWriteFaultAnswersTheEnvelopeAndWritesNothing() {
        val files = NativeTestFiles()
        // The page copy name of this account (SealedPageRecordStore): a write to it fails.
        val recordName = "page.v1.${accountKey.substringBefore(':').removePrefix("0x")}.${accountKey.substringAfter(':')}.rec"
        files.failWrite = recordName
        val store = SealedPageRecordStore(NativeTestWrap(), files, accountKey)
        val bridge = ShellRecordBridge(
            account = { ShellRecordAccount.Ready(store, eoa.lowercase()) },
            migrating = { false },
            outcome = { ImportOutcome.ABSENT },
        )
        val write = bridge.handle(
            ShellOrigin.EMBEDDED_PAGE,
            JSONObject()
                .put("type", "shellRecordWrite")
                .put("reqId", "w1")
                // schema 1 skips the schema-2 key check, so the request reaches the target write (no wallet fields needed).
                .put("record", JSONObject().put("rev", 0).put("schemaVersion", 1)),
            200,
        )
        assertEquals(false, write.getBoolean("ok"))
        assertEquals("write_failed", write.getString("error"))
        assertEquals("the reason is top-level and from the closed set", "storage_write", write.getString("reason"))
        assertFalse("nothing is written: no record file exists", files.map.containsKey(recordName))
    }

    /** Other failures keep their shape: an origin refusal is the envelope without any reason. */
    @Test
    fun otherFailuresKeepTheirShape() {
        val bridge = ShellRecordBridge(
            account = { ShellRecordAccount.Ready(SealedPageRecordStore(NativeTestWrap(), NativeTestFiles(), accountKey), eoa.lowercase()) },
            migrating = { false },
            outcome = { ImportOutcome.ABSENT },
        )
        val refused = bridge.handle(ShellOrigin.OTHER, JSONObject().put("type", "shellRecordWrite").put("reqId", "o1").put("record", JSONObject()), 10)
        assertEquals(false, refused.getBoolean("ok"))
        assertEquals("origin_refused", refused.getString("error"))
        assertFalse("no reason is added to other failures", refused.has("reason"))
    }
}
