package network.conet.chat.nativekey

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

/**
 * `accountCleanupOldCases` CU-01..CU-08 of the pinned vector file (Y.100, 2026-11-16), run through the same [AccountCleanupRun] the bridge calls.
 * Each case's store items are the adapter's items; CU-07's failing removal is the item that the vector leaves in place (`oldCopy`). Temporary
 * directory only; no device data and no key.
 */
class AccountCleanupVectorsTest {
    @get:Rule
    val tmp = TemporaryFolder()

    private fun strings(arr: JSONArray?): List<String> = (0 until (arr?.length() ?: 0)).map { arr!!.getString(it) }

    @Test
    fun cu01ToCu08RunThroughTheBridgeRunWithTheirExpectations() {
        val doc = JSONObject(File("../spec/pgp-migration-vectors.v1.json").readText(Charsets.UTF_8))
        val cases = doc.getJSONArray("accountCleanupOldCases")
        assertEquals(8, cases.length())
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            val id = c.getString("id")
            val input = c.getJSONObject("input")
            val expect = c.getJSONObject("expect")
            val accountKey = input.getString("accountKey")
            val nativeKey = if (input.getBoolean("accountKeyMatch")) accountKey else "eoa-native:default"
            val items = input.getJSONArray("storeItems").let { arr ->
                (0 until arr.length()).map { arr.getJSONObject(it) }.map { AccountCleanupOld.Item(it.getString("name"), it.getString("accountKey")) }
            }
            val failing = if (id == "CU-07") setOf("oldCopy") else emptySet()
            val removed = mutableSetOf<String>()
            val adapter = object : CleanupAdapter {
                override fun scan(newAccountKey: String) = AccountCleanupOld.Scan(items, complete = true)

                override fun remove(item: AccountCleanupOld.Item): Boolean {
                    if (item.name in failing) return false
                    removed += item.name
                    return true
                }
            }
            val state = AndroidVaultFiles(tmp.root.resolve(id).apply { mkdirs() })
            val confirmation = CleanupConfirmation(state)
            if (input.getBoolean("nativeConfirmed")) confirmation.record(nativeKey, 1L)

            val out = AccountCleanupRun(CleanupJournal(state), confirmation, listOf(adapter)).run(
                payloadFields = strings(input.getJSONArray("payloadKeys")),
                accountKey = accountKey,
                idempotencyKey = "idem-$id",
                gateNotReady = input.optBoolean("storeLocked", false),
                newAccountKey = nativeKey,
                newAccountReadable = input.getBoolean("newAccountReadable"),
            )

            // CU-04 in this v1 file says not_available; it is SUPERSEDED by VECTOR-accountCleanupOld-v2/v3 (v194, v196): an unreadable new account is not_ready.
            // The v1 file itself is not changed; this assertion follows the superseding vector.
            val expectedCode = if (id == "CU-04") "not_ready" else expect.getString("code")
            assertEquals("$id: code", expectedCode, out.code)
            assertEquals("$id: deleted", strings(expect.optJSONArray("deleted")).toSet(), out.deleted.toSet())
            if (expect.has("cleanupPending")) assertEquals("$id: cleanupPending", expect.getBoolean("cleanupPending"), out.cleanupPending)
            if (expect.has("kept")) assertEquals("$id: kept", strings(expect.getJSONArray("kept")).toSet(), out.kept.toSet())
            assertTrue("$id: nothing deleted that the vector keeps", out.deleted.none { it in strings(expect.optJSONArray("kept")) })
        }
    }
}
