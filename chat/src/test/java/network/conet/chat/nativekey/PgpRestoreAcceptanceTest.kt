package network.conet.chat.nativekey

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.security.MessageDigest

/**
 * Acceptance group F (spec §25.30.8, registered r3o): every case of `pgp-restore-acceptance-vectors.v1.json` (59 cases,
 * synthetic, sha256 826603a1 pinned to SHA256-CURRENT) run against [PgpRestoreMachine] through [PgpRestoreHarness]. Each step result and
 * the final state must match the vector item by item. The same cases run on a device in `PgpRestoreAcceptanceDeviceTest`.
 */
class PgpRestoreAcceptanceTest {
    private val raw = File(System.getenv("PGP_RESTORE_VECTORS") ?: "../spec/pgp-restore-acceptance-vectors.v1.json").readBytes()
    private val doc = JSONObject(String(raw, Charsets.UTF_8))
    private val password: String = JSONObject(
        String(File("../spec/pgp-backup-compat-vectors.v1.json").readBytes(), Charsets.UTF_8),
    ).getJSONArray("positives").getJSONObject(0).getString("passwordString")

    private fun sha256Hex(b: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }

    /** A harness whose devices are fresh JVM doubles. */
    private fun harness(): PgpRestoreHarness {
        val wraps = HashMap<String, NativeTestWrap>()
        val files = HashMap<String, NativeTestFiles>()
        return PgpRestoreHarness(
            doc,
            password,
            { id -> wraps.getOrPut(id) { NativeTestWrap() } },
            { id -> files.getOrPut(id) { NativeTestFiles() } },
        )
    }

    @Test
    fun theVectorFileIsTheHashedCopy() {
        assertEquals("826603a16ec6b18a440352563fd94cb987342227d5ce62a4b101a494c82c0c68", sha256Hex(raw))
        assertEquals(59, doc.getJSONArray("cases").length())
    }

    @Test
    fun everyAcceptanceCaseMatchesItsStepResultsAndFinalState() {
        val cases = doc.getJSONArray("cases")
        val failures = mutableListOf<String>()
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            val id = c.getString("id")
            val (actualSteps, actualFinal) = harness().run(c.getJSONObject("input").getJSONArray("steps"))
            val expected = c.getJSONObject("expect")
            val expSteps = expected.getJSONArray("stepResults")
            if (expSteps.length() != actualSteps.length()) {
                failures += "$id: step count ${actualSteps.length()} != ${expSteps.length()}"
                continue
            }
            for (j in 0 until expSteps.length()) {
                val e = expSteps.getJSONObject(j)
                val a = actualSteps.getJSONObject(j)
                if (!PgpRestoreHarness.jsonEq(e, a)) failures += "$id step $j: expected $e got $a"
            }
            if (!PgpRestoreHarness.jsonEq(expected.getJSONObject("final"), actualFinal)) {
                failures += "$id final: expected ${expected.getJSONObject("final")} got $actualFinal"
            }
        }
        assertTrue("acceptance mismatches:\n" + failures.joinToString("\n"), failures.isEmpty())
    }

    @Test
    fun theWalletIsNeverWrittenByAnyCase() {
        // walletWrites is 0 in every vector final state (T-190); the machine has no wallet write path at all.
        val cases = doc.getJSONArray("cases")
        for (i in 0 until cases.length()) {
            val final = cases.getJSONObject(i).getJSONObject("expect").getJSONObject("final")
            assertEquals(0, final.getJSONObject("counters").getInt("walletWrites"))
        }
    }

    companion object {
        /** The steps of one case, by id, for other JVM tests that reuse the vector's scenarios. */
        internal fun stepsOf(doc: JSONObject, id: String): JSONArray {
            val cases: JSONArray = doc.getJSONArray("cases")
            return (0 until cases.length()).map { cases.getJSONObject(it) }.first { it.getString("id") == id }
                .getJSONObject("input").getJSONArray("steps")
        }
    }
}
