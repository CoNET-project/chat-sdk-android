package network.conet.chat.nativekey

import network.conet.chat.nativekey.PgpMigrationKeys.ACCOUNT
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * DL-10a and DL-10b (spec r3by §25.52AC.4, T-368): a conversation entry of the page record is removed only through `shellRecordWrite`, and only
 * from a freshly read record (the same `rev`). A stale copy gets `conflict` and the store keeps its current record. The vectors place `chats` at
 * the root; the whitelist places it under `profiles[*].chats` (§25.52Q.3), so the cases run there. The copy carries `schemaVersion` 1, which
 * the write needs; the rule under test is the revision check, not the schema.
 */
class PageRecordEntryDeleteTest {
    private val files = NativeTestFiles()
    private val wrap = NativeTestWrap()
    private val store = SealedPageRecordStore(wrap, files, "$ACCOUNT:default")
    private val bridge = ShellRecordBridge(
        account = { ShellRecordAccount.Ready(store, ACCOUNT) },
        migrating = { false },
        outcome = { null },
        flags = NoDeviceFlags,
    )

    private val convA = "0x" + "a".repeat(40)
    private val convB = "0x" + "b".repeat(40)

    @Test
    fun dl10aAStaleCopyIsConflictAndTheCurrentRecordStays() {
        val current = chatsRecord(3, listOf(convA to "a", convB to "b"))
        store.write(current)
        val stale = chatsRecord(2, listOf(convA to "a", convB to "b"))

        val ack = bridge.handle(ShellOrigin.EMBEDDED_PAGE, writeOf("d10a", removeEntry(stale, convA)), 0).v()

        assertEquals("conflict", ack.getString("code"))
        assertEquals(3, ack.getInt("currentRev"))
        assertEquals(CanonicalJson.encode(current), CanonicalJson.encode(store.read()))
    }

    @Test
    fun dl10bAFreshReadRemovesOnlyTheEntryAndMovesTheRevision() {
        store.write(chatsRecord(3, listOf(convA to "a", convB to "b")))
        val fresh = bridge.handle(ShellOrigin.EMBEDDED_PAGE, JSONObject().put("type", "shellRecordRead").put("reqId", "r10b"), 0)
            .v().getJSONObject("record")
        assertEquals(3, fresh.getInt("rev"))

        val ack = bridge.handle(ShellOrigin.EMBEDDED_PAGE, writeOf("d10b", removeEntry(fresh, convA)), 0).v()

        assertEquals("ok", ack.getString("code"))
        assertEquals(4, ack.getInt("rev"))
        assertEquals(CanonicalJson.encode(chatsRecord(4, listOf(convB to "b"))), CanonicalJson.encode(store.read()))
    }

    private fun writeOf(reqId: String, record: JSONObject): JSONObject =
        JSONObject().put("type", "shellRecordWrite").put("reqId", reqId).put("record", record)

    private fun chatsRecord(rev: Int, chats: List<Pair<String, String>>): JSONObject = JSONObject()
        .put("rev", rev)
        .put("schemaVersion", 1)
        .put(
            "profiles",
            JSONArray().put(
                JSONObject().put(
                    "chats",
                    JSONArray(chats.map { (address, mail) -> JSONObject().put("address", address).put("emailAddr", mail) }),
                ),
            ),
        )

    /** The page's write: a copy of [record] without the entry for [convKey], at the copy's own `rev`. */
    private fun removeEntry(record: JSONObject, convKey: String): JSONObject {
        val out = JSONObject(record.toString())
        val profile = out.getJSONArray("profiles").getJSONObject(0)
        val chats = profile.getJSONArray("chats")
        val kept = JSONArray()
        for (i in 0 until chats.length()) {
            val chat = chats.getJSONObject(i)
            if (!chat.getString("address").equals(convKey, ignoreCase = true)) kept.put(chat)
        }
        profile.put("chats", kept)
        return out
    }
}
