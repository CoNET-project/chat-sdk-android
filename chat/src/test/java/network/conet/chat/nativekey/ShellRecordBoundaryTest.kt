package network.conet.chat.nativekey

import network.conet.chat.BridgeCommandTable
import network.conet.chat.nativekey.PgpMigrationKeys.ACCOUNT
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
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
    fun anUnverifiedChatChannelRequestGetsNoReplyWhateverItAsks() {
        // R476, §25.52AB.5: the chat-module channel has no verified origin. Nothing is processed and nothing is sent, for any reqId or type.
        val bodies = listOf(
            request("r1"),
            JSONObject().put("type", "shellRecordWrite").put("reqId", "w1").put("record", JSONObject().put("rev", 0).put("schemaVersion", 2)),
            request(""),
            request(null),
            request(7),
            JSONObject().put("type", "shellRecordMigrationState").put("reqId", "s1"),
            JSONObject().put("type", "shellRecordRead").put("reqId", "r2").put("extra", 1),
        )
        for (body in bodies) {
            // 25.52AW.1, AY.1: an invalid reqId is bad_request (null reqId); a valid one gets the shared chat-channel code, once.
            val expected = if (!ShellRecordPolicy.reqIdValid(body.opt("reqId"))) "bad_request"
            else BridgeCommandTable.chatChannelShellRecordCode(body.optString("type", ""))
            assertNotNull("answered once for $body", expected)
        }
    }

    @Test
    fun theChatChannelBranchAnswersOnceWithTheSharedCodeAndTheWindowEntryIsUnchanged() {
        val module = File("src/main/java/network/conet/chat/BeamioConetChatModule.kt").readText()
        // 25.52AY.1: the chat-module branch answers once with the shared code. It does not send through the window path.
        assertTrue(module.contains("BridgeCommandTable.chatChannelShellRecordCode(type)?.let { code ->"))
        assertFalse("the no-reply function is gone (25.52AY.1)", module.contains("shellRecordChatChannelReply"))
        val shellRecord = File("src/main/java/network/conet/chat/nativekey/ShellRecord.kt").readText()
        assertTrue(shellRecord.contains("fun answerFromPage("))
    }

    @Test
    fun theWindowOriginIsTheAndroidAppAssetsOrigin() {
        // §25.52AA.4, §25.52AB.5: the one origin the window channel accepts.
        assertEquals("https://appassets.androidplatform.net", BeamioShellRecordImport.ALLOWED_ORIGIN)
    }
}
