package network.conet.chat.nativekey

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import java.io.File
import java.security.MessageDigest

/**
 * T-263 (25.52AQ.3, r3co) and 25.52AS.4 (r3cq): the page-record refusal vectors PR-02, PR-02b, PR-03 and PR-04. The vector file is a byte copy
 * of the interface file (`protocol/page-record-refuse-vectors.v1.json`, sha256 fbbcb077…); it is not edited here. The cases are run through the
 * shellRecordWrite bridge: the PGP path and key-shape refusals come before the whitelist, the migrating check comes after both, and nothing is stored.
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
        assertEquals("fbbcb07715483cc7288de4b8302492301db95a0fe0ac02f4e43fa922746e50c2", sha)
    }

    @Test
    fun thePageRecordRefusalCasesGiveTheirCodesNamesAndStoreNothing() {
        val cases = doc.getJSONArray("cases")
        assertEquals(4, cases.length())
        val ids = (0 until cases.length()).map { cases.getJSONObject(it).getString("id") }
        assertEquals(listOf("PR-02", "PR-02b", "PR-03", "PR-04"), ids)
        val mismatches = LinkedHashMap<String, String>()
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
            val gotNames = strings(result.optJSONArray("names"))
            val wantNames = strings(expect.getJSONArray("names"))
            val codeOk = expect.getString("code") == result.optString("code")
            val namesOk = wantNames == gotNames
            if (codeOk && namesOk) passed++ else mismatches[id] =
                "want ${expect.getString("code")} ${wantNames}, got ${result.optString("code")} ${gotNames}"
            assertNull("$id stores nothing", store.read())
        }
        println("PR vectors passed $passed of ${cases.length()}; mismatches: $mismatches")
        assertEquals("mismatches against the vectors", pendingRuling.keys, mismatches.keys)
    }

    /**
     * The cases whose answer differs from the vector, with the ruling that is needed. Empty when the code matches every vector. PR-02 is
     * recorded here, not hidden: its code matches; its names list the leaf path, and the pinned pgp-migration vectors list the same leaf.
     */
    private val pendingRuling: Map<String, String> = mapOf(
        "PR-02" to "names: the PR vector lists the forbidden prefix; the pinned pgp-migration vectors list the leaf (ruling pending)",
    )
}
