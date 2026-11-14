package network.conet.chat.nativekey

import network.conet.chat.nativekey.PgpMigrationKeys.ACCOUNT
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.File
import java.io.IOException

/**
 * The page-record bridge beyond the vectors: sealing and binding of the store (§25.52F.3), the read-side strip (§25.52F.4), the
 * wallet-field merge (§25.52H.2), the reqId rule (§25.28.3), the whitelist (§25.52D.8), the migration-state command, the origin, and
 * the source audits (no logging, no exportable key, no generic-bridge route).
 */
class ShellRecordTest {
    private val token = "PRIVKEY-TOKEN-7731"
    private val otherAccount = "0x3333333333333333333333333333333333333333:default"

    @Test
    fun theStoredRecordIsSealedAndNeverPlaintext() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        SealedPageRecordStore(wrap, files, "$ACCOUNT:default").write(
            JSONObject().put("rev", 1).put("schemaVersion", 2).put("mnemonic", token),
        )
        assertEquals(1, files.map.size)
        for (bytes in files.map.values) {
            assertFalse("the file must not hold the plaintext", String(bytes, Charsets.ISO_8859_1).contains(token))
        }
    }

    @Test
    fun aRecordDoesNotOpenUnderAnotherAccountKey() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        SealedPageRecordStore(wrap, files, "$ACCOUNT:default").write(JSONObject().put("rev", 1).put("schemaVersion", 2))
        val moved = files.map.values.single()
        files.write(fileNameOf(otherAccount), moved)
        try {
            SealedPageRecordStore(wrap, files, otherAccount).read()
            fail("a record sealed for one account must not open for another")
        } catch (_: IOException) {
            // expected: the AAD binds the account key
        }
    }

    @Test
    fun aFileWithAnotherFormatVersionIsUnreadable() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        val store = SealedPageRecordStore(wrap, files, "$ACCOUNT:default")
        store.write(JSONObject().put("rev", 1).put("schemaVersion", 2))
        val bytes = files.map.values.single()
        bytes[0] = 2
        try {
            store.read()
            fail("an unknown format version must not be read")
        } catch (_: IOException) {
            // expected
        }
    }

    @Test
    fun aMissingRecordIsNull() {
        assertNull(SealedPageRecordStore(NativeTestWrap(), NativeTestFiles(), "$ACCOUNT:default").read())
    }

    @Test
    fun theReadCopyLosesEveryWalletFieldAndSaysSo() {
        val record = JSONObject()
            .put("rev", 1)
            .put("schemaVersion", 2)
            .put("mnemonic", "M")
            .put("walletVault", JSONObject().put("mnemonic", "M2"))
            .put("profiles", JSONArray().put(JSONObject().put("emailAddr", "a").put("privateKeyArmor", "EOA")))
        assertTrue(ShellRecordPolicy.stripForRead(record))
        assertFalse(record.has("mnemonic"))
        assertFalse(record.has("walletVault"))
        assertFalse(record.getJSONArray("profiles").getJSONObject(0).has("privateKeyArmor"))
        assertEquals("a", record.getJSONArray("profiles").getJSONObject(0).getString("emailAddr"))

        val plain = JSONObject().put("rev", 1).put("schemaVersion", 2).put("profiles", JSONArray().put(JSONObject().put("emailAddr", "a")))
        assertFalse("nothing removed, so nothing to report", ShellRecordPolicy.stripForRead(plain))
    }

    @Test
    fun theMergeKeepsAnOmittedWalletFieldAndRefusesADifferentOne() {
        val stored = JSONObject()
            .put("rev", 1)
            .put("schemaVersion", 2)
            .put("mnemonic", "M")
            .put("profiles", JSONArray().put(JSONObject().put("emailAddr", "a").put("privateKeyArmor", "EOA")))
        val omitted = JSONObject()
            .put("rev", 1)
            .put("schemaVersion", 2)
            .put("profiles", JSONArray().put(JSONObject().put("emailAddr", "b")))
        val (merged, conflicts) = ShellRecordPolicy.mergeWallet(omitted, stored)
        assertTrue(conflicts.isEmpty())
        assertEquals("EOA", merged.getJSONArray("profiles").getJSONObject(0).getString("privateKeyArmor"))
        assertEquals("M", merged.getString("mnemonic"))

        val different = JSONObject()
            .put("rev", 1)
            .put("schemaVersion", 2)
            .put("mnemonic", "OTHER")
            .put("profiles", JSONArray().put(JSONObject().put("emailAddr", "b").put("privateKeyArmor", "EOA")))
        assertEquals(listOf("mnemonic"), ShellRecordPolicy.mergeWallet(different, stored).second)
    }

    @Test
    fun theReqIdRuleAcceptsOnlyTheSpecifiedForms() {
        assertTrue(ShellRecordPolicy.reqIdValid("abc"))
        assertTrue(ShellRecordPolicy.reqIdValid("x".repeat(64)))
        assertTrue(ShellRecordPolicy.reqIdValid(0))
        assertTrue(ShellRecordPolicy.reqIdValid(9007199254740991L))
        assertFalse(ShellRecordPolicy.reqIdValid(""))
        assertFalse(ShellRecordPolicy.reqIdValid("x".repeat(65)))
        assertFalse(ShellRecordPolicy.reqIdValid("é"))
        assertFalse(ShellRecordPolicy.reqIdValid(-1))
        assertFalse(ShellRecordPolicy.reqIdValid(9007199254740992L))
        assertFalse(ShellRecordPolicy.reqIdValid(1.5))
        assertFalse(ShellRecordPolicy.reqIdValid(null))
    }

    @Test
    fun theWhitelistNamesOnlyTheUnknownPaths() {
        val record = JSONObject()
            .put("rev", 0)
            .put("schemaVersion", 1)
            .put("extra", 1)
            .put(
                "profiles",
                JSONArray().put(
                    JSONObject()
                        .put("emailAddr", "a")
                        .put("foo", 1)
                        .put("chatManager", JSONObject().put("router", "r").put("pgpKey", JSONObject().put("keyID", "K").put("x", 1))),
                ),
            )
        assertEquals(
            listOf("extra", "profiles[*].chatManager.pgpKey.x", "profiles[*].foo"),
            ShellRecordPolicy.whitelistViolations(record),
        )
    }

    @Test
    fun aPgpHeaderRefusesWithoutNames() {
        val record = JSONObject().put("rev", 0).put("schemaVersion", 1)
            .put("profiles", JSONArray().put(JSONObject().put("data", "x -----BEGIN PGP PRIVATE KEY BLOCK-----")))
        val refusal = ShellRecordPolicy.preWriteRefusal(record)
        assertEquals("pgp_private_in_payload", refusal?.first)
        assertTrue(refusal?.second?.isEmpty() == true)
    }

    @Test
    fun theMigrationStateCommandAnswersAndRefusesExtraFields() {
        val bridge = ShellRecordBridge(
            account = { ShellRecordAccount.Refused("no_key") },
            migrating = { false },
            migrationState = { "pending" },
        )
        val ok = bridge.handle(ShellOrigin.EMBEDDED_PAGE, JSONObject().put("type", "shellRecordMigrationState").put("reqId", "s1"), 40)
        assertEquals("ok", ok.getString("code"))
        assertEquals("pending", ok.getString("state"))
        val extra = bridge.handle(
            ShellOrigin.EMBEDDED_PAGE,
            JSONObject().put("type", "shellRecordMigrationState").put("reqId", "s2").put("eoa", "0x1"),
            60,
        )
        assertEquals("bad_request", extra.getString("code"))
        assertEquals(listOf("eoa"), extra.getJSONArray("names").toList())
    }

    @Test
    fun aWalletWithoutAKeyAnswersAnErrorNotAnAbsence() {
        val bridge = ShellRecordBridge(
            account = { ShellRecordAccount.Refused("no_key") },
            migrating = { false },
            migrationState = { "none" },
        )
        val read = bridge.handle(ShellOrigin.EMBEDDED_PAGE, JSONObject().put("type", "shellRecordRead").put("reqId", "r1"), 40)
        assertEquals("error", read.getString("code"))
        assertEquals("no_key", read.getString("sub"))
    }

    @Test
    fun aMigrationInProgressAnswersMigratingAndNoRecord() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        val store = SealedPageRecordStore(wrap, files, "$ACCOUNT:default")
        store.write(JSONObject().put("rev", 1).put("schemaVersion", 2))
        val bridge = ShellRecordBridge(account = { ShellRecordAccount.Ready(store) }, migrating = { true }, migrationState = { "none" })
        val resp = bridge.handle(ShellOrigin.EMBEDDED_PAGE, JSONObject().put("type", "shellRecordRead").put("reqId", "r1"), 40)
        assertEquals("migrating", resp.getString("code"))
        assertFalse(resp.has("record"))
    }

    @Test
    fun theBridgeHasNoLoggingPlaintextFallbackOrExportableKey() {
        val text = File("src/main/java/network/conet/chat/nativekey/ShellRecord.kt").readText()
        for (word in listOf("Log.", "println", "getSharedPreferences", "setKeyExportable", "EncryptedSharedPreferences")) {
            assertFalse("ShellRecord.kt must not contain $word", text.contains(word))
        }
        assertTrue("the Keystore key is randomized and non-exportable", text.contains("setRandomizedEncryptionRequired(true)"))
        assertTrue("the page store lives in the no-backup directory", text.contains("noBackupFilesDir"))
    }

    @Test
    fun theGenericBridgeRefusesTheShellRecordCommands() {
        val module = File("src/main/java/network/conet/chat/BeamioConetChatModule.kt").readText()
        assertTrue(module.contains("type.startsWith(\"shellRecord\")"))
        assertFalse("the generic bridge never sends the page record", module.contains("BeamioShellRecordImport.handle("))
    }

    private fun fileNameOf(accountKey: String): String {
        val bare = accountKey.substringBefore(':').removePrefix("0x")
        return "page.v1.$bare.${accountKey.substringAfter(':')}.rec"
    }

    private fun JSONArray.toList(): List<String> = (0 until length()).map { getString(it) }
}
