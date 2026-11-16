package network.conet.chat.nativekey

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.File

/** The K_pgp creation and upgrade rules (§25.52Y.59) against the vector group `kpgpCases` (KP-01 to KP-13). */
class KpgpPolicyVectorsTest {
    private val doc = JSONObject(File(System.getenv("PGP_MIGRATION_VECTORS") ?: "../spec/pgp-migration-vectors.v1.json").readText(Charsets.UTF_8))

    private fun strings(a: JSONArray?): List<String> = (0 until (a?.length() ?: 0)).map { a!!.getString(it) }

    @Test
    fun theKpgpGroupHasThirteenCases() {
        assertEquals(13, doc.getJSONArray("kpgpCases").length())
    }

    @Test
    fun everyKpgpCaseMatchesItsExpectation() {
        val failures = mutableListOf<String>()
        val list = doc.getJSONArray("kpgpCases")
        for (i in 0 until list.length()) {
            val c = list.getJSONObject(i)
            val id = c.getString("id")
            val inp = c.getJSONObject("input")
            val exp = c.getJSONObject("expect")
            fun b(k: String, def: Boolean) = if (inp.has(k)) inp.getBoolean(k) else def
            val input = KpgpPolicy.Input(
                kind = inp.getString("kind"),
                kPgpExists = b("kPgpExists", false),
                generateOk = b("generateOk", true),
                writeOk = b("writeOk", true),
                readbackOk = b("readbackOk", true),
                lPresent = b("lPresent", false),
                lValid = b("lValid", false),
                chainBackupPresent = b("chainBackupPresent", false),
                chainVerify = b("chainVerify", false),
                userClick = b("userClick", false),
            )
            val got = KpgpPolicy.decide(input)
            if (got.action != exp.getString("action")) failures += "$id action ${got.action}"
            if (got.writes != strings(exp.optJSONArray("writes"))) failures += "$id writes ${got.writes}"
            if (got.deletes != strings(exp.optJSONArray("deletes"))) failures += "$id deletes ${got.deletes}"
            if (got.page != exp.getString("page")) failures += "$id page ${got.page}"
            if (exp.has("rollback") && got.rollback != exp.getBoolean("rollback")) failures += "$id rollback ${got.rollback}"
            if (exp.has("registryReplace") && got.registryReplace != exp.getBoolean("registryReplace")) failures += "$id registryReplace"
        }
        assertEquals(emptyList<String>(), failures)
    }
}
