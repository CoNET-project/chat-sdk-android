package network.conet.chat.nativekey

import network.conet.chat.nativekey.PgpMigrationKeys.ACCOUNT
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * RP-01 to RP-08b (spec r3bx §25.52AB.4): the page adapter's reply rules. The page owns them, so the SDK runs the same rules here as a
 * reference: the vectors pin the rules, and the native side's part (exactly one ack per request) is checked by the bridge.
 */
class ShellRecordReplyTest {
    private val doc = JSONObject(File(System.getenv("PGP_MIGRATION_VECTORS") ?: "../spec/pgp-migration-vectors.v1.json").readText(Charsets.UTF_8))

    /** The adapter of §25.52AB.4: pending requests by reqId, a 10 s timeout, the first reply wins, malformed and unknown replies are ignored. */
    private class ReplyAdapter {
        private val sentAt = LinkedHashMap<String, Long>()
        val outcomes = mutableListOf<JSONObject>()

        fun send(reqId: String, now: Long) {
            sentAt[reqId] = now
        }

        fun reply(msg: JSONObject) {
            if (msg.optString("type") != "ack") return ignore("not_ack")
            val reqId = msg.opt("reqId") as? String
            if (reqId == null || !sentAt.containsKey(reqId)) return ignore("unknown_reqId")
            val ok = msg.opt("ok")
            if (ok == true) {
                if (!msg.has("result")) return ignore("malformed")
                sentAt.remove(reqId)
                outcomes += JSONObject().put("reqId", reqId).put("action", "resolve").put("result", msg.get("result"))
            } else if (ok == false) {
                val error = msg.opt("error") as? String ?: return ignore("malformed")
                sentAt.remove(reqId)
                outcomes += JSONObject().put("reqId", reqId).put("action", "reject").put("error", error)
            } else {
                ignore("malformed")
            }
        }

        fun tick(now: Long) {
            val due = sentAt.filter { now - it.value >= TIMEOUT_MS }.keys.toList()
            for (id in due) {
                sentAt.remove(id)
                outcomes += JSONObject().put("reqId", id).put("action", "reject").put("error", "timeout")
            }
        }

        private fun ignore(why: String) {
            outcomes += JSONObject().put("action", "ignore").put("why", why)
        }

        companion object {
            const val TIMEOUT_MS = 10_000L
        }
    }

    /** RP-08a, RP-08b: after a write timed out, the next write waits for a completed read (§25.52AB.4, §25.52W.3). */
    private fun mayWrite(readCompletedSinceTimeout: Boolean): String = if (readCompletedSinceTimeout) "allowed" else "blocked"

    @Test
    fun theReplyRulesMatchTheReplyVectors() {
        val cases = doc.getJSONArray("replyCases")
        assertEquals(9, cases.length())
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            val id = c.getString("id")
            if (c.has("events")) {
                val adapter = ReplyAdapter()
                val events = c.getJSONArray("events")
                for (e in 0 until events.length()) {
                    val ev = events.getJSONObject(e)
                    when (ev.getString("kind")) {
                        "send" -> adapter.send(ev.getString("reqId"), ev.getLong("t"))
                        "reply" -> adapter.reply(ev.getJSONObject("msg"))
                        "tick" -> adapter.tick(ev.getLong("t"))
                    }
                }
                val expect = c.getJSONArray("expect")
                assertEquals("$id: outcome count", expect.length(), adapter.outcomes.size)
                for (k in 0 until expect.length()) {
                    val want = expect.getJSONObject(k)
                    val got = adapter.outcomes[k]
                    for (key in want.keys()) {
                        assertEquals("$id: $key at $k", ShellRecordVectorsTest.canon(want.get(key)), ShellRecordVectorsTest.canon(got.opt(key)))
                    }
                }
            } else {
                assertEquals(id, c.getString("expect"), mayWrite(c.getBoolean("readCompletedSinceTimeout")))
            }
        }
        assertTrue(ReplyAdapter.TIMEOUT_MS == 10_000L)
    }

    @Test
    fun aTimeoutAtExactlyTenSecondsRejects() {
        val adapter = ReplyAdapter()
        adapter.send("x", 0)
        adapter.tick(9_999)
        assertTrue(adapter.outcomes.isEmpty())
        adapter.tick(10_000)
        assertEquals("timeout", adapter.outcomes.single().getString("error"))
        assertFalse(adapter.outcomes.single().has("result"))
    }
}
