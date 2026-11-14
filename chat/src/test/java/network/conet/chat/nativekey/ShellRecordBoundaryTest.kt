package network.conet.chat.nativekey

import network.conet.chat.nativekey.PgpMigrationKeys.ACCOUNT
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * OR-01 to OR-03 (spec r3bx §25.52AB.5): the source is checked at the native boundary. A source that is not allowed is not processed and gets
 * no reply; an allowed request gets exactly one reply, and a bad reqId is `bad_request` with `reqId: null`.
 */
class ShellRecordBoundaryTest {
    private val doc = JSONObject(File(System.getenv("PGP_MIGRATION_VECTORS") ?: "../spec/pgp-migration-vectors.v1.json").readText(Charsets.UTF_8))

    private fun bridge(): ShellRecordBridge {
        val store = SealedPageRecordStore(NativeTestWrap(), NativeTestFiles(), "$ACCOUNT:default")
        return ShellRecordBridge(
            account = { ShellRecordAccount.Ready(store, ACCOUNT) },
            migrating = { false },
            outcome = { ImportOutcome.ABSENT },
        )
    }

    private fun request(reqId: Any?): JSONObject {
        val body = JSONObject().put("type", "shellRecordRead")
        if (reqId != null) body.put("reqId", reqId)
        return body
    }

    @Test
    fun theBoundaryMatchesTheOriginVectors() {
        val cases = doc.getJSONArray("originBoundaryCases")
        assertEquals(3, cases.length())
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            val input = c.getJSONObject("input")
            val expect = c.getJSONObject("expect")
            var calls = 0
            val b = bridge()
            val body = if (input.getBoolean("reqIdValid")) request("r1") else request("")
            val reply = answerAtBoundary(input.getBoolean("allowed"), body, 40) { bb, bytes ->
                calls++
                b.handle(ShellOrigin.EMBEDDED_PAGE, bb, bytes)
            }
            val replies = if (reply == null) 0 else 1
            assertEquals(c.getString("id"), expect.getInt("replies"), replies)
            assertEquals(c.getString("id"), expect.getBoolean("processed"), reply != null && reply.optBoolean("ok", false))
            assertEquals(c.getString("id"), if (input.getBoolean("allowed")) 1 else 0, calls)
            if (!expect.isNull("reply")) {
                val want = expect.getJSONObject("reply")
                assertEquals(c.getString("id"), want.getString("error"), reply!!.getString("error"))
                assertTrue(reply.isNull("reqId"))
                assertEquals("ack", reply.getString("type"))
            }
        }
    }

    @Test
    fun aSourceThatIsNotAllowedIsNotAnsweredAtAll() {
        // OR-01 at the boundary: the answer is not called and nothing is replied.
        var called = false
        val reply = answerAtBoundary(false, request("r1"), 40) { _, _ ->
            called = true
            JSONObject()
        }
        assertNull(reply)
        assertFalse(called)
    }

    @Test
    fun theWindowOriginIsTheAndroidAppAssetsOrigin() {
        // §25.52AA.4, §25.52AB.5: the one origin the window channel accepts.
        assertEquals("https://appassets.androidplatform.net", BeamioShellRecordImport.ALLOWED_ORIGIN)
    }
}
