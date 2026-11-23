package network.conet.chat.nativekey

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.File
import java.security.MessageDigest

/**
 * shell-record-shape-and-kr04-write-vectors.v2.json (9 cases: UF-01 to UF-06, KW-01 to KW-03), driven by the same bridge driver as the AK cases
 * (ShellRecordAckVectorsTest.runAck). KW-01 also checks that no page copy was written.
 */
class ShellRecordShapeVectorsTest {
    private val file = File("../spec/shell-record-shape-and-kr04-write-vectors.v2.json")
    private val doc = JSONObject(file.readText(Charsets.UTF_8))

    @Test
    fun theFileIsTheDeliveredOne() {
        val sha = MessageDigest.getInstance("SHA-256").digest(file.readBytes()).joinToString("") { "%02x".format(it) }
        assertEquals("d5940986aee72026", sha.take(16))
        assertEquals(9, doc.getJSONArray("cases").length())
    }

    @Test
    fun everyCaseMatchesItsExpectation() {
        val driver = ShellRecordAckVectorsTest()
        val failures = mutableListOf<String>()
        val list = doc.getJSONArray("cases")
        for (i in 0 until list.length()) {
            val c = list.getJSONObject(i)
            val problems = driver.runAck(c) { store, _ ->
                // KW-01 to KW-03 with a refused write: the page copy stays unwritten.
                if (c.getString("id") in setOf("KW-01", "KW-02") && store.read() != null) listOf("page copy was written") else emptyList()
            }
            VectorResultLog.record("shapeCases", c.getString("id"), problems)
            failures += problems.map { "${c.getString("id")}: $it" }
        }
        assertEquals(emptyList<String>(), failures)
    }
}
