package network.conet.chat.nativekey

import network.conet.chat.nativekey.PgpMigrationKeys.ACCOUNT
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** The QA hook's effect (§25.52AA.5): only the account's `privateKeyArmor` goes; the rest, the revision and the flags stay. QA build only. */
class NativeQaHooksTest {
    @Test
    fun theHookMakesTheRecordLackTheEoaKeyAndKeepsTheRest() {
        val files = NativeTestFiles()
        val store = SealedPageRecordStore(NativeTestWrap(), files, "$ACCOUNT:default")
        store.write(
            JSONObject()
                .put("rev", 3)
                .put("schemaVersion", 2)
                .put("mnemonicPhrase", "M")
                .put("recoveryWords", "R")
                .put("profiles", JSONArray().put(JSONObject().put("keyID", ACCOUNT).put("privateKeyArmor", "EOA").put("emailAddr", "a"))),
        )
        val flags = DeviceFlagFiles(files)
        flags.setAccountPointer()
        NativeQaHooks.dropEoaKey(store, ACCOUNT)
        val after = store.read()!!
        assertEquals(3, after.getInt("rev"))
        assertEquals("M", after.getString("mnemonicPhrase"))
        assertEquals("R", after.getString("recoveryWords"))
        val profile = after.getJSONArray("profiles").getJSONObject(0)
        assertFalse(profile.has("privateKeyArmor"))
        assertEquals("a", profile.getString("emailAddr"))
        assertTrue("the pointer stays", flags.accountPointer())
    }
}
