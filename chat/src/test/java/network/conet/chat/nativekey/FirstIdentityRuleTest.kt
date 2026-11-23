package network.conet.chat.nativekey

import java.io.File
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Replays the `pgpRestoreEvaluateReply` cases RE-01…RE-10 of the shared restore vector (single-RPC caliber) against
 * [FirstIdentityRule]: the `legacy` and `chain` fields, and the creation entry. The display is page-side and is not asserted here.
 */
class FirstIdentityRuleTest {
    private fun casesOf(file: String): JSONArray = JSONObject(File("../spec/$file").readText(Charsets.UTF_8))
        .getJSONObject("pgpRestoreEvaluateReply").getJSONArray("cases")

    @Test
    fun everyEvaluateCaseReplaysToItsLegacyChainAndCreationExpectation() {
        for (file in listOf("pgp-restore-acceptance-vectors.v1.json", "pgp-backup-compat-vectors.v1.json")) {
            val cases = casesOf(file)
            assertEquals("$file has the ten cases (RE-01…RE-10)", 10, cases.length())
            for (i in 0 until cases.length()) replay(cases.getJSONObject(i))
        }
    }

    private fun replay(c: JSONObject) {
        val id = c.getString("id")
        val input = c.getJSONObject("input")
        val expect = c.getJSONObject("expect")
        val state = input.optString("state", "")
        val legacy = if (input.has("legacy")) input.getString("legacy") else "unknown"
        val chainRaw = if (input.has("chainRaw")) input.getString("chainRaw") else input.optString("rpc", "")
        val chain = FirstIdentityRule.chainVerdict(chainRaw)
        if (expect.has("legacy")) assertEquals("$id legacy", expect.getString("legacy"), legacy)
        if (expect.has("chain")) assertEquals("$id chain", expect.getString("chain"), chain)
        if (expect.has("creationEntry")) {
            val open = FirstIdentityRule.creationEntryOpen(state, legacy, chain)
            assertEquals("$id creationEntry", expect.getString("creationEntry") == "open", open)
        }
    }

    @Test
    fun theLegacyMergeIsAbsentOnlyWhenBothSourcesSayNothing() {
        assertEquals("ABSENT", FirstIdentityRule.legacyVerdict(LegacyReportState.ABSENT, ""))
        assertEquals("UNREADABLE", FirstIdentityRule.legacyVerdict(LegacyReportState.NOT_REPORTED, ""))
        assertEquals("UNREADABLE", FirstIdentityRule.legacyVerdict(LegacyReportState.ABSENT, null))
        assertEquals("PRESENT", FirstIdentityRule.legacyVerdict(LegacyReportState.NOT_REPORTED, "armor"))
        assertEquals("PRESENT", FirstIdentityRule.legacyVerdict(LegacyReportState.FOUND, ""))
    }
}
