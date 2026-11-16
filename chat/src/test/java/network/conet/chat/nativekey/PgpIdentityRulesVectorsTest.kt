package network.conet.chat.nativekey

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.File

/** §25.52Y.60 (PI-01 to PI-07): the user ID, the account and keyID matching, and the registry keyID, against `pgpIdCases`. */
class PgpIdentityRulesVectorsTest {
    private val doc = JSONObject(File(System.getenv("PGP_MIGRATION_VECTORS") ?: "../spec/pgp-migration-vectors.v1.json").readText(Charsets.UTF_8))

    @Test
    fun everyPgpIdCaseMatchesItsExpectation() {
        val failures = mutableListOf<String>()
        val list = doc.getJSONArray("pgpIdCases")
        assertEquals(7, list.length())
        for (i in 0 until list.length()) {
            val c = list.getJSONObject(i)
            val id = c.getString("id")
            val inp = c.getJSONObject("input")
            val exp = c.getJSONObject("expect")
            val existing = if (inp.has("existingUserIdName")) inp.getString("existingUserIdName") else ""
            val name = PgpIdentityRules.userIdName(inp.getString("eoa"), inp.getBoolean("isNewKey"), existing)
            if (name != exp.getString("userIdName")) failures += "$id userIdName $name"
            val account = PgpIdentityRules.accountMatch(inp.getString("eoa"), inp.getString("profileAccount"))
            if (account != exp.getBoolean("accountMatch")) failures += "$id accountMatch $account"
            val key = PgpIdentityRules.keyIdMatch(inp.getString("keyIdLocal"), inp.getString("keyIdRemote"))
            if (key != exp.getBoolean("keyIdMatch")) failures += "$id keyIdMatch $key"
            val reg = PgpIdentityRules.registryKeyId(inp.getString("keyIdLocal"))
            if (reg != exp.getString("registryKeyId")) failures += "$id registryKeyId $reg"
        }
        assertEquals(emptyList<String>(), failures)
    }
}
