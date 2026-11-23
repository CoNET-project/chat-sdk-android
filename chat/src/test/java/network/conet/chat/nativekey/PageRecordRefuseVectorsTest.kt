package network.conet.chat.nativekey

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import java.io.File
import java.security.MessageDigest

/**
 * T-263, 25.52AQ.3 (r3co), 25.52AS.4 (r3cq), 25.52BG.1 (r3de): the page-record refusal vectors PR-02, PR-02b, PR-03 and PR-04. The vector file is a
 * byte copy of the interface file (`protocol/page-record-refuse-vectors.v1.json`, sha256 49e1133c…, rebuilt in r3de with leaf-path names). It is not
 * edited here. The cases run through the shellRecordWrite bridge: the PGP path and key-shape refusals come before the whitelist, the migrating check
 * comes after both, and nothing is stored.
 */
class PageRecordRefuseVectorsTest {
    private val bytes by lazy { File("../spec/page-record-refuse-vectors.v1.json").readBytes() }
    private val doc by lazy { JSONObject(String(bytes, Charsets.UTF_8)) }
    private val account = DerivedAccount.ADDRESS

    private fun bridge(store: SealedPageRecordStore, migrating: Boolean) = ShellRecordBridge(
        account = { ShellRecordAccount.Ready(store, account) },
        migrating = { migrating },
        // A confirmed absence of the legacy store (25.52W.3): the write goes ahead when nothing else refuses it.
        outcome = { ImportOutcome.ABSENT },
    )

    private fun emptyStore() = SealedPageRecordStore(NativeTestWrap(), NativeTestFiles(), "$account:default")

    private fun strings(arr: JSONArray?): List<String> =
        arr?.let { a -> (0 until a.length()).map { a.getString(it) } } ?: emptyList()

    @Test
    fun theVectorFileIsTheInterfaceCopy() {
        val sha = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
        assertEquals("49e1133c052952157330af652a8abfb3922d3bbddd13f3ad73bd32e823629d3d", sha)
    }

    @Test
    fun theFourPageRecordRefusalCasesGiveTheirCodesLeafNamesAndStoreNothing() {
        val cases = doc.getJSONArray("cases")
        assertEquals(4, cases.length())
        val ids = (0 until cases.length()).map { cases.getJSONObject(it).getString("id") }
        assertEquals(listOf("PR-02", "PR-02b", "PR-03", "PR-04"), ids)
        var passed = 0
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            val id = c.getString("id")
            val store = emptyStore()
            val migrating = c.getJSONObject("ctx").getBoolean("migrating")
            val req = JSONObject().put("type", "shellRecordWrite").put("reqId", "pr").put("record", c.getJSONObject("req"))
            val resp = bridge(store, migrating).handle(ShellOrigin.EMBEDDED_PAGE, req, 500, nativeWrite = false)
            val result = resp.optJSONObject("result") ?: resp
            val expect = c.getJSONObject("expect")
            assertEquals("$id code", expect.getString("code"), result.optString("code"))
            assertEquals("$id names (leaf paths, 25.52BG.1)", strings(expect.getJSONArray("names")), strings(result.optJSONArray("names")))
            assertNull("$id stores nothing", store.read())
            passed++
        }
        assertEquals(4, passed)
    }
}
