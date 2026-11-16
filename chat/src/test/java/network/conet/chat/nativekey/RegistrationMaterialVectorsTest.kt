package network.conet.chat.nativekey

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.File

/** `pgpRegistrationMaterial` (§25.52Y.61): the codes and the returned fields against `registrationMaterialCases` RM-01 to RM-15. */
class RegistrationMaterialVectorsTest {
    private val doc = JSONObject(File(System.getenv("PGP_MIGRATION_VECTORS") ?: "../spec/pgp-migration-vectors.v1.json").readText(Charsets.UTF_8))

    private fun strings(a: JSONArray?): List<String> = (0 until (a?.length() ?: 0)).map { a!!.getString(it) }

    @Test
    fun everyRegistrationCaseMatchesItsExpectation() {
        val failures = mutableListOf<String>()
        val list = doc.getJSONArray("registrationMaterialCases")
        assertEquals(15, list.length())
        for (i in 0 until list.length()) {
            val c = list.getJSONObject(i)
            val id = c.getString("id")
            val inp = c.getJSONObject("input")
            fun b(k: String, def: Boolean) = if (inp.has(k)) inp.getBoolean(k) else def
            val input = RegistrationMaterialPolicy.Input(
                payloadKeys = strings(inp.getJSONArray("payloadKeys")),
                accountMatch = b("accountMatch", true),
                unlocked = b("unlocked", true),
                storageLocked = b("storageLocked", false),
                kPgpExists = b("kPgpExists", true),
                sealOk = b("sealOk", true),
                openOk = b("openOk", true),
                keyIdMatchesStored = b("keyIdMatchesStored", true),
                signOk = b("signOk", true),
                shell = inp.optString("mode") == "shell",
                submitOk = inp.optString("submitOk", "accepted"),
            )
            val got = RegistrationMaterialPolicy.decide(input)
            val exp = c.getJSONObject("expect")
            if (got.code != exp.getString("code")) failures += "$id code ${got.code}"
            if (got.returned != strings(exp.getJSONArray("returned"))) failures += "$id returned ${got.returned}"
        }
        assertEquals(emptyList<String>(), failures)
    }
}
