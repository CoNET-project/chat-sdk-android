package network.conet.chat.nativekey

import network.conet.chat.nativekey.PgpMigrationKeys.ACCOUNT
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The r3br items (spec §25.52V): a residual PGP public field is stripped on every read and left in the store (AK-21), and a native write that
 * carries a PGP public field is `bad_request` with the path names, even with `nativeWrite` (AK-22).
 */
class ShellRecordR442Test {
    private fun residualRecord(): JSONObject = JSONObject()
        .put("rev", 1)
        .put("schemaVersion", 2)
        .put("mnemonicPhrase", "M")
        .put(
            "profiles",
            JSONArray().put(
                JSONObject()
                    .put("keyID", ACCOUNT)
                    .put("privateKeyArmor", "EOA")
                    .put("chatManager", JSONObject().put("router", "r").put("pgpKey", JSONObject().put("publicKey", "P").put("keyID", "K"))),
            ),
        )
        .put("beamio", JSONObject().put("accountName", "n").put("pgpPublicKeyArmor", "PUB").put("pgpPublicKeyID", "K"))

    @Test
    fun aReadStripsTheResidualPgpPublicFieldsAndLeavesTheStoreAlone() {
        val files = NativeTestFiles()
        val store = SealedPageRecordStore(NativeTestWrap(), files, "$ACCOUNT:default")
        store.write(residualRecord())
        val bridge = ShellRecordBridge(
            account = { ShellRecordAccount.Ready(store, ACCOUNT) },
            migrating = { false },
            outcome = { ImportOutcome.DONE },
        )
        val first = bridge.handle(ShellOrigin.EMBEDDED_PAGE, JSONObject().put("type", "shellRecordRead").put("reqId", "s1"), 40).v()
        val second = bridge.handle(ShellOrigin.EMBEDDED_PAGE, JSONObject().put("type", "shellRecordRead").put("reqId", "s2"), 40).v()
        for (resp in listOf(first, second)) {
            assertEquals("ok", resp.getString("code"))
            val record = resp.getJSONObject("record")
            assertFalse(record.getJSONArray("profiles").getJSONObject(0).getJSONObject("chatManager").has("pgpKey"))
            assertFalse(record.getJSONObject("beamio").has("pgpPublicKeyArmor"))
            assertEquals("n", record.getJSONObject("beamio").getString("accountName"))
        }
        // The store keeps the residual fields: a read never rewrites the record (§25.52V.3).
        val stored = store.read()!!
        assertTrue(stored.getJSONObject("beamio").has("pgpPublicKeyArmor"))
        assertTrue(stored.getJSONArray("profiles").getJSONObject(0).getJSONObject("chatManager").has("pgpKey"))
    }

    @Test
    fun aNativeWriteWithAPgpPublicFieldIsBadRequestWithItsPaths() {
        // §25.52V.2 (AK-22): the native write does not carry PGP public material into the page record either.
        val files = NativeTestFiles()
        val store = SealedPageRecordStore(NativeTestWrap(), files, "$ACCOUNT:default")
        val bridge = ShellRecordBridge(
            account = { ShellRecordAccount.Ready(store, ACCOUNT) },
            migrating = { false },
            outcome = { ImportOutcome.ABSENT },
        )
        val record = JSONObject()
            .put("rev", 0)
            .put("schemaVersion", 2)
            .put(
                "profiles",
                JSONArray().put(
                    JSONObject()
                        .put("keyID", ACCOUNT)
                        .put("privateKeyArmor", "EOA")
                        .put("chatManager", JSONObject().put("pgpKey", JSONObject().put("publicKey", "PUB").put("keyID", "K"))),
                ),
            )
        val resp = bridge.handle(
            ShellOrigin.EMBEDDED_PAGE,
            JSONObject().put("type", "shellRecordWrite").put("reqId", "n1").put("record", record),
            200,
            nativeWrite = true,
        ).v()
        assertEquals("bad_request", resp.getString("code"))
        assertEquals(
            listOf("profiles[*].chatManager.pgpKey.keyID", "profiles[*].chatManager.pgpKey.publicKey"),
            resp.getJSONArray("names").let { a -> (0 until a.length()).map { a.getString(it) } },
        )
        assertFalse("nothing is stored", store.read() != null)
    }
}
