package network.conet.chat.localread

import network.conet.chat.nativekey.CanonicalJson
import network.conet.chat.nativekey.NoKeyGate
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * `historyDeleteMessage` and `historyDeleteConversation` against the real native store (spec r3by §25.52AC.2 to §25.52AC.5; DL-01 to DL-09,
 * 9 cases; T-366, T-367). Each case seeds the store from its `before` state, runs the command through [NativeHistoryDelete.ack], then checks the
 * ack and the live view. The live view is the messages that are not tombstones, per conversation: an absent conversation has no live view
 * (DL-04), while the store keeps the tombstones of what was removed.
 */
class NativeHistoryDeleteTest {
    private val master = ByteArray(32) { (it * 11 + 5).toByte() }
    private val doc = JSONObject(
        String(
            File(System.getenv("PGP_MIGRATION_VECTORS") ?: "../spec/pgp-migration-vectors.v1.json").readBytes(),
            Charsets.UTF_8,
        ),
    )

    @Test
    fun everyNativeDeleteCaseMatchesItsExpectation() {
        val failures = mutableListOf<String>()
        val cases = doc.getJSONArray("nativeDeleteCases")
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            failures += runCase(c).map { "${c.getString("id")}: $it" }
        }
        assertEquals(emptyList<String>(), failures)
    }

    @Test
    fun aDeletedMessageIsTheOnlyChangeAndTheSecondDeleteIsIdempotent() {
        val store = seeded(mapOf(CONV_A to listOf("m1" to 0, "m2" to 0)))
        assertEquals(true, deletes(store, "historyDeleteMessage", "d1", CONV_A, "m1"))
        assertEquals(1, store.stateOfSendKey(CONV_A, "m1"))
        assertEquals(0, store.stateOfSendKey(CONV_A, "m2"))
        assertEquals(false, deletes(store, "historyDeleteMessage", "d2", CONV_A, "m1"))
    }

    @Test
    fun aConversationDeleteKeepsOtherConversationsAndTheNewMessagesOfThisOne() {
        val store = seeded(mapOf(CONV_A to listOf("m1" to 0), CONV_B to listOf("m1" to 0, "m3" to 0)))
        assertEquals(true, deletes(store, "historyDeleteConversation", "c1", CONV_A))
        // A message that arrives after the conversation delete is an ordinary new message: the conversation reappears (§25.52AC.3).
        store.applyRecord(CONV_A, incoming("m9", sortTs = 900L))
        assertEquals(0, store.stateOfSendKey(CONV_A, "m9"))
        assertEquals(0, store.stateOfSendKey(CONV_B, "m3"))
        assertEquals(false, deletes(store, "historyDeleteConversation", "c2", CONV_C))
    }

    @Test
    fun aRefusedGateIsTheEnvelopeWithTheRequestsReqId() {
        val store = seeded(mapOf(CONV_A to listOf("m1" to 0)))
        val body = JSONObject().put("type", "historyDeleteMessage").put("reqId", "g1").put("convKey", CONV_A).put("messageId", "m1")
        val ack = NativeHistoryDelete.ack("historyDeleteMessage", body, NoKeyGate.NO_KEY, store)
        assertEquals(CanonicalJson.encode(JSONObject().put("type", "ack").put("reqId", "g1").put("ok", false).put("error", "no_key")), CanonicalJson.encode(ack))
        assertEquals(0, store.stateOfSendKey(CONV_A, "m1"))
    }

    @Test
    fun aClosedStoreIsNotReadyThroughTheAckAndChangesNothing() {
        // lock() is logging out. It closes the handle, so the store is closed and answers not_ready (envelope), not busy.
        val file = File.createTempFile("native-delete-closed", ".db").apply { deleteOnExit() }
        val store = seeded(mapOf(CONV_A to listOf("m1" to 0)), file)
        store.lock()
        val ack = NativeHistoryDelete.ack(
            "historyDeleteConversation",
            JSONObject().put("type", "historyDeleteConversation").put("reqId", "c1").put("convKey", CONV_A),
            null,
            store,
        )
        assertEquals(
            CanonicalJson.encode(JSONObject().put("type", "ack").put("reqId", "c1").put("ok", false).put("error", "not_ready")),
            CanonicalJson.encode(ack),
        )
        // The handle was closed; a new store on the same file restores the rows.
        val reopened = newFileStore("0xaaaa:default", file)
        assertEquals(UnlockResult.OK, reopened.unlock(master, null))
        assertEquals(0, reopened.stateOfSendKey(CONV_A, "m1"))
    }

    @Test
    fun aLockedStoreWithAnOpenHandleIsBusyThroughTheAckAndChangesNothing() {
        // markLocked keeps the handle open and loses only the key: locked, not closed, so busy.
        val file = File.createTempFile("native-delete-locked", ".db").apply { deleteOnExit() }
        val store = seeded(mapOf(CONV_A to listOf("m1" to 0)), file)
        store.markLocked("kcv_mismatch")
        assertTrue("the handle stays open", store.isOpen)
        assertEquals(false, store.isUnlocked)
        val ack = NativeHistoryDelete.ack(
            "historyDeleteConversation",
            JSONObject().put("type", "historyDeleteConversation").put("reqId", "b1").put("convKey", CONV_A),
            null,
            store,
        )
        assertEquals(
            CanonicalJson.encode(JSONObject().put("type", "ack").put("reqId", "b1").put("ok", true).put("result", JSONObject().put("code", "busy"))),
            CanonicalJson.encode(ack),
        )
        assertEquals(UnlockResult.OK, store.unlock(master, null))
        assertEquals(0, store.stateOfSendKey(CONV_A, "m1"))
    }

    @Test
    fun noStoreIsNotReadyTheEnvelope() {
        val body = JSONObject().put("type", "historyDeleteMessage").put("reqId", "n1").put("convKey", CONV_A).put("messageId", "m1")
        val ack = NativeHistoryDelete.ack("historyDeleteMessage", body, null, null)
        assertEquals(CanonicalJson.encode(JSONObject().put("type", "ack").put("reqId", "n1").put("ok", false).put("error", "not_ready")), CanonicalJson.encode(ack))
    }

    @Test
    fun aMessageIdIsOneToOneHundredAndTwentyEightVisibleCharacters() {
        assertTrue(NativeHistoryDelete.isMessageId("x".repeat(128)))
        assertFalse(NativeHistoryDelete.isMessageId("x".repeat(129)))
        assertFalse(NativeHistoryDelete.isMessageId(""))
        assertFalse(NativeHistoryDelete.isMessageId("a b"))
        assertFalse(NativeHistoryDelete.isMessageId("é"))
    }

    @Test
    fun anIntegerReqIdIsEchoedAsSent() {
        val store = seeded(mapOf(CONV_A to listOf("m1" to 0)))
        val body = JSONObject().put("type", "historyDeleteMessage").put("reqId", 7).put("convKey", CONV_A).put("messageId", "m1")
        val ack = NativeHistoryDelete.ack("historyDeleteMessage", body, null, store)
        assertEquals(7, ack.getInt("reqId"))
        assertEquals(true, ack.getJSONObject("result").getBoolean("deleted"))
    }

    @Test
    fun aHistoryRowCarriesItsSendKeyAsMessageId() {
        // §25.52AC.2: the history read rows carry messageId (= sendKey), which historyDeleteMessage takes.
        val store = seeded(mapOf(CONV_A to listOf("m7" to 0)))
        val page = store.openConversation(CONV_A, LocalViewport(390.0, 844.0, "portrait", 1.0, 1))
        assertEquals(listOf<String?>("m7"), page.items.map { it.messageId })
    }

    @Test
    fun aLockedStoreFailureIsBusyAndAClosedOneIsNotReady() {
        // §25.52AC.5: busy is for a busy store (locked). A closed store is not busy; it answers the envelope not_ready.
        val locked = NativeHistoryDelete.storeFailure("f1", IllegalStateException("locked"))
        assertEquals(
            CanonicalJson.encode(JSONObject().put("type", "ack").put("reqId", "f1").put("ok", true).put("result", JSONObject().put("code", "busy"))),
            CanonicalJson.encode(locked),
        )
        val closed = NativeHistoryDelete.storeFailure("f2", IllegalStateException("closed"))
        assertEquals(
            CanonicalJson.encode(JSONObject().put("type", "ack").put("reqId", "f2").put("ok", false).put("error", "not_ready")),
            CanonicalJson.encode(closed),
        )
    }

    private fun runCase(c: JSONObject): List<String> {
        val store = seeded(c.getJSONObject("before").getJSONObject("convs").let(::convsOf))
        val cmd = c.getJSONObject("cmd")
        val ack = NativeHistoryDelete.ack(cmd.getString("type"), JSONObject(cmd.toString()), null, store)

        val expect = c.getJSONObject("expect")
        val out = mutableListOf<String>()
        if (CanonicalJson.encode(ack) != CanonicalJson.encode(expect.getJSONObject("ack"))) {
            out += "ack ${CanonicalJson.encode(ack)} != ${CanonicalJson.encode(expect.getJSONObject("ack"))}"
        }
        out += liveViewMismatches(store, c.getJSONObject("before").getJSONObject("convs"), expect.getJSONObject("history").getJSONObject("convs"))
        return out
    }

    /** The live view (messages that are not tombstones) of every conversation in either side; an absent conversation has none. */
    private fun liveViewMismatches(store: LocalChatStore, before: JSONObject, want: JSONObject): List<String> {
        val out = mutableListOf<String>()
        val convKeys = (before.keys().asSequence() + want.keys().asSequence()).map { it.toString() }.toSortedSet()
        for (conv in convKeys) {
            val seededKeys = before.optJSONObject(conv)?.getJSONObject("msgs")?.keys()?.asSequence()?.map { it.toString() }?.toList().orEmpty()
            val wantMsgs = want.optJSONObject(conv)?.getJSONObject("msgs")
            val wantLive = wantMsgs?.keys()?.asSequence()?.map { it.toString() }?.filter { wantMsgs.getJSONObject(it).getInt("state") == 0 }
                ?.toList()?.sorted().orEmpty()
            val gotLive = seededKeys.filter { store.stateOfSendKey(conv, it) == 0 }.sorted()
            if (gotLive != wantLive) out += "live view of $conv $gotLive != $wantLive"
            // A conversation that is present in the expectation also has its tombstones checked, message by message.
            if (wantMsgs != null) {
                for (mid in wantMsgs.keys().asSequence().map { it.toString() }) {
                    val want1 = wantMsgs.getJSONObject(mid).getInt("state")
                    val got = store.stateOfSendKey(conv, mid)
                    if (got != want1) out += "state of $conv/$mid $got != $want1"
                }
            }
        }
        return out
    }

    private fun convsOf(convs: JSONObject): Map<String, List<Pair<String, Int>>> =
        convs.keys().asSequence().map { it.toString() }.associateWith { conv ->
            val msgs = convs.getJSONObject(conv).getJSONObject("msgs")
            msgs.keys().asSequence().map { it.toString() }.sorted().map { mid -> mid to msgs.getJSONObject(mid).getInt("state") }.toList()
        }

    /** A store unlocked for the test, seeded with [convs]: state 0 is a live message, state 1 a tombstone (applied, then tombstoned). */
    private fun seeded(convs: Map<String, List<Pair<String, Int>>>, file: File? = null): LocalChatStore {
        val store = if (file == null) newTestStore("0xaaaa:default") else newFileStore("0xaaaa:default", file)
        assertEquals(UnlockResult.OK, store.unlock(master, null))
        var ts = 1000L
        for ((conv, msgs) in convs) {
            for ((mid, state) in msgs) {
                store.applyRecord(conv, incoming(mid, ts++))
                if (state == 1) assertTrue(store.tombstoneMessage(conv, mid))
            }
        }
        return store
    }

    /** Runs one delete and returns its `deleted` flag. */
    private fun deletes(store: LocalChatStore, type: String, reqId: String, conv: String, mid: String? = null): Boolean {
        val body = JSONObject().put("type", type).put("reqId", reqId).put("convKey", conv)
        if (mid != null) body.put("messageId", mid)
        return NativeHistoryDelete.ack(type, body, null, store).getJSONObject("result").getBoolean("deleted")
    }

    private fun incoming(sendKey: String, sortTs: Long) = IncomingRecord(
        dir = "in",
        sortTs = sortTs,
        kind = LocalMediaKind.TEXT,
        sendId = null,
        body = "body-$sendKey",
        cid = null,
        sendKeyHint = sendKey,
    )

    companion object {
        const val CONV_A = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        const val CONV_B = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        const val CONV_C = "0xcccccccccccccccccccccccccccccccccccccccc"
    }
}
