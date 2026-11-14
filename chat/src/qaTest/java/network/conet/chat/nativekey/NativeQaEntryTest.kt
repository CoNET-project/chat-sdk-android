package network.conet.chat.nativekey

import network.conet.chat.identity.IdentityProvisionContract
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CopyOnWriteArrayList

/**
 * R591: the QA native entry for device evidence (A5). QA build only. The sink stands in for the module, so these run without Android. They
 * check the allowlist, the reqId, the refusal of key names at any depth, the match of the ack, the removal of key names from replies, the
 * timeout, and the restore of the web emit.
 */
class NativeQaEntryTest {
    /** Records each call. [replies] gives the outgoing objects for a call; each one goes to the emit the entry passed. */
    private class FakeSink(private val replies: (JSONObject) -> List<JSONObject>) : NativeQaHooks.Sink {
        @Volatile
        var emit: ((JSONObject) -> Unit)? = null
        val calls = CopyOnWriteArrayList<JSONObject>()

        override fun swapEmit(emit: ((JSONObject) -> Unit)?): ((JSONObject) -> Unit)? {
            val previous = this.emit
            this.emit = emit
            return previous
        }

        override fun handle(body: JSONObject, emit: (JSONObject) -> Unit) {
            calls += JSONObject(body.toString())
            replies(body).forEach { emit(it) }
        }
    }

    private val eoa = "0x" + "a1".repeat(20)
    private val answerEverything: (JSONObject) -> List<JSONObject> = { b -> listOf(ackEvent(b.optInt("reqId"))) }

    private fun ack(reqId: Int, result: JSONObject? = null): JSONObject {
        val payload = JSONObject().put("type", "ack").put("reqId", reqId).put("ok", true)
        if (result != null) payload.put("result", result)
        return payload
    }

    private fun ackEvent(reqId: Int, result: JSONObject? = null): JSONObject =
        JSONObject().put("action", "chatModuleEvent").put("event", ack(reqId, result))

    private fun body(reqId: Int? = 7): JSONObject = JSONObject().also { if (reqId != null) it.put("reqId", reqId) }

    private fun snake(name: String): String =
        name.replace(Regex("([a-z])([A-Z])")) { "${it.groupValues[1]}_${it.groupValues[2]}" }.lowercase()

    @Test
    fun theAllowlistIsTheA5SetAndAnythingElseNeverReachesTheModule() {
        // R591 list plus pgpRestoreEvaluate (read-only: evalRestore with write = false, PgpRestoreMachine.evaluate). Requested by the shell for A5.
        assertEquals(
            setOf("identityPublic", "walletStatus", "init", "provisionIdentity", "pgpRestore", "pgpRestoreEvaluate"),
            NativeQaHooks.ALLOWED_COMMANDS,
        )
        val others = listOf("send", "hello", "setRoutes", "gossipSign", "pgpSign", "clearIdentity", "nativeImportOpen", "historySign", "", "IDENTITYPUBLIC", "pgpRestore ")
        for (command in others) {
            val sink = FakeSink(answerEverything)
            val reply = NativeQaHooks.runWith(sink, command, body(), 1_000)
            assertEquals("command '$command'", "not_allowed", reply.optString("error"))
            assertTrue("no call for '$command'", sink.calls.isEmpty())
        }
    }

    @Test
    fun aMissingOrNonIntegerReqIdIsBadRequestAndNeverReachesTheModule() {
        val bad = listOf(body(null), JSONObject().put("reqId", "7"), JSONObject().put("reqId", -1), JSONObject().put("reqId", JSONObject()))
        for (b in bad) {
            val sink = FakeSink(answerEverything)
            val reply = NativeQaHooks.runWith(sink, "identityPublic", b, 1_000)
            assertEquals("bad_request", reply.optString("error"))
            assertTrue(sink.calls.isEmpty())
        }
    }

    @Test
    fun aForbiddenKeyNameAtAnyDepthIsRefusedBeforeTheModuleSeesIt() {
        for (name in IdentityProvisionContract.FORBIDDEN_KEYS) {
            for (spelling in listOf(name, name.uppercase(), name.lowercase(), snake(name))) {
                val top = body().put(spelling, "x")
                val nested = body().put("identity", JSONObject().put("eoa", eoa).put("wallet", JSONObject().put(spelling, "x")))
                val inArray = body().put("items", JSONArray().put(JSONObject().put(spelling, "x")))
                for (b in listOf(top, nested, inArray)) {
                    val sink = FakeSink(answerEverything)
                    val reply = NativeQaHooks.runWith(sink, "provisionIdentity", b, 1_000)
                    assertEquals("refused: $spelling", "key_over_bridge_refused", reply.optString("error"))
                    assertTrue("no call: $spelling", sink.calls.isEmpty())
                }
            }
        }
    }

    @Test
    fun aPublicBodyIsAcceptedAndTheCommandIsTheCallsType() {
        val sink = FakeSink(answerEverything)
        val caller = body(2).put("type", "send").put("eoa", eoa)
        val reply = NativeQaHooks.runWith(sink, "walletStatus", caller, 1_000)
        assertTrue(reply.optBoolean("ok"))
        assertEquals("walletStatus", sink.calls.single().optString("type"))
        assertEquals("the caller's body keeps its own type", "send", caller.optString("type"))
    }

    @Test
    fun onlyTheAckOfThisReqIdIsReturned() {
        val sink = FakeSink {
            listOf(
                ackEvent(99, JSONObject().put("wrong", true)),
                JSONObject().put("action", "other").put("event", ack(7)),
                JSONObject().put("action", "chatModuleEvent").put("event", JSONObject().put("type", "status").put("reqId", 7)),
                ackEvent(7, JSONObject().put("eoa", eoa).put("ready", true)),
            )
        }
        val reply = NativeQaHooks.runWith(sink, "identityPublic", body(7), 1_000)
        assertEquals(7, reply.optInt("reqId"))
        assertTrue(reply.optBoolean("ok"))
        assertEquals(eoa, reply.optJSONObject("result")?.optString("eoa"))
        assertTrue(reply.optJSONObject("result")?.optBoolean("ready") == true)
    }

    @Test
    fun keyNamesInAReplyAreRemovedAndThePublicFieldsAreKept() {
        val sink = FakeSink {
            listOf(
                ackEvent(
                    7,
                    JSONObject()
                        .put("eoa", eoa)
                        .put("privateKeyArmor", "ARMOR-SECRET")
                        .put("nested", JSONObject().put("pgpPassphrase", "PASS-SECRET").put("ok", true))
                        .put("list", JSONArray().put(JSONObject().put("mnemonic", "WORDS-SECRET").put("keep", 1))),
                ),
            )
        }
        val reply = NativeQaHooks.runWith(sink, "pgpRestore", body(7), 1_000)
        val text = reply.toString()
        for (secret in listOf("ARMOR-SECRET", "PASS-SECRET", "WORDS-SECRET", "privateKeyArmor", "pgpPassphrase", "mnemonic")) {
            assertFalse("removed: $secret", text.contains(secret))
        }
        assertEquals(eoa, reply.optJSONObject("result")?.optString("eoa"))
        assertTrue(reply.optJSONObject("result")?.optJSONObject("nested")?.optBoolean("ok") == true)
        assertEquals(1, reply.optJSONObject("result")?.optJSONArray("list")?.optJSONObject(0)?.optInt("keep"))
    }

    @Test
    fun aSilentModuleTimesOutAndTheWebEmitIsPutBack() {
        val sink = FakeSink { emptyList() }
        val before: (JSONObject) -> Unit = { }
        sink.emit = before
        val reply = NativeQaHooks.runWith(sink, "init", body(3), 50)
        assertEquals("timeout", reply.optString("error"))
        assertTrue(reply.optBoolean("qaRefusal"))
        assertTrue("the web emit is put back after a timeout", sink.emit === before)
    }

    @Test
    fun theWebEmitIsPutBackAfterAnAnsweredCall() {
        val sink = FakeSink(answerEverything)
        val before: (JSONObject) -> Unit = { }
        sink.emit = before
        NativeQaHooks.runWith(sink, "walletStatus", body(5), 1_000)
        assertTrue("the web emit is put back", sink.emit === before)
    }

    @Test
    fun anAckThatArrivesLaterFromAnotherThreadIsStillReturned() {
        val sink = object : NativeQaHooks.Sink {
            var emit: ((JSONObject) -> Unit)? = null
            override fun swapEmit(emit: ((JSONObject) -> Unit)?): ((JSONObject) -> Unit)? {
                val previous = this.emit
                this.emit = emit
                return previous
            }

            override fun handle(body: JSONObject, emit: (JSONObject) -> Unit) {
                val reqId = body.optInt("reqId")
                Thread {
                    Thread.sleep(30)
                    emit(ackEvent(reqId))
                }.start()
            }
        }
        val reply = NativeQaHooks.runWith(sink, "walletStatus", body(4), 2_000)
        assertTrue(reply.optBoolean("ok"))
        assertEquals(4, reply.optInt("reqId"))
    }

    @Test
    fun aSuccessfulInitIsAnsweredByItsReadyEvent() {
        val sink = FakeSink {
            listOf(JSONObject().put("action", "chatModuleEvent").put("event", JSONObject().put("type", "ready").put("reqId", 9)))
        }
        val reply = NativeQaHooks.runWith(sink, "init", body(9), 1_000)
        assertEquals("ready", reply.optString("type"))
        assertEquals(9, reply.optInt("reqId"))
    }

    @Test
    fun aReadyEventForAnotherReqIdIsNotTheAnswer() {
        val sink = FakeSink {
            listOf(JSONObject().put("action", "chatModuleEvent").put("event", JSONObject().put("type", "ready").put("reqId", 8)))
        }
        val reply = NativeQaHooks.runWith(sink, "init", body(9), 50)
        assertEquals("timeout", reply.optString("error"))
    }
}
