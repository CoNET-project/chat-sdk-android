package network.conet.chat.nativekey

import network.conet.chat.nativekey.PgpMigrationKeys.ACCOUNT
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.File

/**
 * DL-10a and DL-10b (spec r3by §25.52AC.4), run from the vector file's `pageRecordDeleteCases` (review r3bz-r3by-r488 §2.2).
 *
 * Two runs of every case:
 *  - As written. The vector puts `chats` at the root and omits `schemaVersion`. The spec does not say what a write without `schemaVersion`
 *    gets (R553 review §2.2). The SDK refuses it with `bad_request` naming `schemaVersion`; that is a recorded deviation, pending the
 *    interface owner's ruling on both this case and the position of `chats` (§25.52Q.3 lists `profiles[*].chats`, and its table lists a root
 *    `chats`).
 *  - Mapped. `chats` is moved under `profiles[0]` and `schemaVersion` 1 is added, the position the whitelist accepts. Under this run the case
 *    must give the vector's own result: `conflict` with the current `currentRev` for a stale copy, `ok` with the next `rev` for a fresh one.
 */
class PageRecordEntryDeleteTest {
    private val doc = JSONObject(
        String(
            File(System.getenv("PGP_MIGRATION_VECTORS") ?: "../spec/pgp-migration-vectors.v1.json").readBytes(),
            Charsets.UTF_8,
        ),
    )
    private val cases: JSONArray = doc.getJSONArray("pageRecordDeleteCases")

    @Test
    fun everyCaseAsWrittenIsRefusedForItsMissingSchemaVersion() {
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            val id = c.getString("id")
            val files = NativeTestFiles()
            val wrap = NativeTestWrap()
            val store = SealedPageRecordStore(wrap, files, "$ACCOUNT:default")
            store.write(JSONObject(c.getJSONObject("rec").toString()))
            val before = CanonicalJson.encode(store.read())

            val request = literalRemoval(c.getJSONObject("rec"), c.getString("convKey"), c.getInt("writeRev"))
            val ack = bridge(store).handle(ShellOrigin.EMBEDDED_PAGE, writeOf(id, request), 0).v()

            assertEquals("$id: as written", "bad_request", ack.getString("code"))
            assertEquals("$id: as written names", listOf("schemaVersion"), namesOf(ack))
            assertEquals("$id: store unchanged", before, CanonicalJson.encode(store.read()))
        }
    }

    @Test
    fun everyCaseMappedToTheWhitelistGivesTheVectorsResult() {
        val failures = mutableListOf<String>()
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            val id = c.getString("id")
            val expect = c.getJSONObject("expect")
            val files = NativeTestFiles()
            val wrap = NativeTestWrap()
            val store = SealedPageRecordStore(wrap, files, "$ACCOUNT:default")
            store.write(mapped(c.getJSONObject("rec")))

            val request = mappedRemoval(c.getJSONObject("rec"), c.getString("convKey"), c.getInt("writeRev"))
            val ack = bridge(store).handle(ShellOrigin.EMBEDDED_PAGE, writeOf(id, request), 0).v()

            when (expect.getString("code")) {
                "conflict" -> {
                    if (ack.getString("code") != "conflict") failures += "$id: code ${ack.getString("code")}"
                    if (ack.optInt("currentRev", -1) != expect.getInt("currentRev")) failures += "$id: currentRev"
                    if (addresses(store.read()) != addresses(mapped(c.getJSONObject("rec")))) failures += "$id: store changed"
                }
                "ok" -> {
                    if (ack.getString("code") != "ok") failures += "$id: code ${ack.getString("code")}"
                    if (ack.optInt("rev", -1) != expect.getInt("rev")) failures += "$id: rev"
                    if (addresses(store.read()) != addresses(mapped(expect.getJSONObject("rec")))) failures += "$id: entries"
                }
                else -> failures += "$id: unknown expectation ${expect.getString("code")}"
            }
        }
        assertEquals(emptyList<String>(), failures)
    }

    private fun bridge(store: SealedPageRecordStore): ShellRecordBridge = ShellRecordBridge(
        account = { ShellRecordAccount.Ready(store, ACCOUNT) },
        migrating = { false },
        outcome = { null },
        flags = NoDeviceFlags,
    )

    private fun writeOf(reqId: String, record: JSONObject): JSONObject =
        JSONObject().put("type", "shellRecordWrite").put("reqId", reqId).put("record", record)

    /** The vector's record as written: `chats` at the root, no schemaVersion. */
    private fun literalRemoval(record: JSONObject, convKey: String, rev: Int): JSONObject {
        val out = JSONObject(record.toString()).put("rev", rev)
        out.put("chats", without(out.getJSONArray("chats"), convKey))
        return out
    }

    /** The mapped record: `chats` under `profiles[0]`, `schemaVersion` 1, no root `chats`. */
    private fun mapped(record: JSONObject): JSONObject {
        val chats = record.getJSONArray("chats")
        return JSONObject()
            .put("rev", record.getInt("rev"))
            .put("schemaVersion", 1)
            .put("profiles", JSONArray().put(JSONObject().put("chats", chats)))
    }

    private fun mappedRemoval(record: JSONObject, convKey: String, rev: Int): JSONObject {
        val out = mapped(record).put("rev", rev)
        out.getJSONArray("profiles").getJSONObject(0).put("chats", without(out.getJSONArray("profiles").getJSONObject(0).getJSONArray("chats"), convKey))
        return out
    }

    /** The page's write: the entries of the copy without the one for [convKey]. */
    private fun without(chats: JSONArray, convKey: String): JSONArray {
        val kept = JSONArray()
        for (i in 0 until chats.length()) {
            val chat = chats.getJSONObject(i)
            if (!chat.getString("address").equals(convKey, ignoreCase = true)) kept.put(chat)
        }
        return kept
    }

    /** The addresses of the entries of a mapped record, in order. */
    private fun addresses(record: JSONObject?): List<String> {
        val chats = record?.optJSONArray("profiles")?.optJSONObject(0)?.optJSONArray("chats") ?: return emptyList()
        return (0 until chats.length()).map { chats.getJSONObject(it).getString("address") }
    }

    private fun namesOf(ack: JSONObject): List<String> =
        ack.optJSONArray("names")?.let { a -> (0 until a.length()).map { a.getString(it) }.sorted() } ?: emptyList()
}
