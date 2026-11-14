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
 * The page-record bridge beyond the vectors: sealing and binding of the store (§25.52F.3), the read-side PGP strip (§25.52I.2), the
 * wallet-field merge (§25.52H.2), the reqId rule (§25.28.3), the whitelist (§25.52D.8, §25.52I.3, §25.52J.2), the answers that depend on
 * the import state (§25.52K.4), the migration-state command, the origin, and the source audits (no logging, no exportable key, no
 * generic-bridge route).
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
    fun theReadCopyKeepsTheWalletFieldsAndLosesEveryPgpField() {
        // §25.52I.2: W fields go to the page; PGP fields never do, and an emptied chatManager goes with them.
        val record = JSONObject()
            .put("rev", 1)
            .put("schemaVersion", 2)
            .put("mnemonic", "M")
            .put("pgpPassphrase", "")
            .put(
                "profiles",
                JSONArray().put(
                    JSONObject()
                        .put("emailAddr", "a")
                        .put("privateKeyArmor", "EOA")
                        .put("pgpKey", JSONObject().put("privateKey", "PGPY"))
                        .put("chatManager", JSONObject().put("pgpKey", JSONObject().put("privateKey", "PGPX").put("publicKey", "PUB"))),
                ),
            )
        ShellRecordPolicy.stripPgpForRead(record)
        assertEquals("M", record.getString("mnemonic"))
        assertFalse(record.has("pgpPassphrase"))
        val profile = record.getJSONArray("profiles").getJSONObject(0)
        assertEquals("EOA", profile.getString("privateKeyArmor"))
        assertFalse(profile.has("pgpKey"))
        assertFalse("an emptied chatManager is removed", profile.has("chatManager"))
    }

    @Test
    fun aReadCarriesNoRedactionFlag() {
        // §25.52I.2: walletFieldsRedacted is for the old compatible page only, which this build never produces.
        val store = SealedPageRecordStore(NativeTestWrap(), NativeTestFiles(), "$ACCOUNT:default")
        store.write(JSONObject().put("rev", 1).put("schemaVersion", 1).put("profiles", JSONArray().put(JSONObject().put("emailAddr", "a"))))
        val bridge = ShellRecordBridge(
            account = { ShellRecordAccount.Ready(store) },
            migrating = { false },
            migrationState = { "none" },
            outcome = { ImportOutcome.DONE },
        )
        val resp = bridge.handle(ShellOrigin.EMBEDDED_PAGE, JSONObject().put("type", "shellRecordRead").put("reqId", "r9"), 40)
        assertEquals("ok", resp.getString("code"))
        assertFalse(resp.has("walletFieldsRedacted"))
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
    fun theWhitelistNamesOnlyTheUnknownPathsAndEveryPgpPublicField() {
        // §25.52I.3: the PGP public fields are not whitelisted. The W paths are, and they pass the whitelist.
        val record = JSONObject()
            .put("rev", 0)
            .put("schemaVersion", 2)
            .put("extra", 1)
            .put("mnemonic", "M")
            .put(
                "profiles",
                JSONArray().put(
                    JSONObject()
                        .put("emailAddr", "a")
                        .put("privateKeyArmor", "EOA")
                        .put("foo", 1)
                        .put("chatManager", JSONObject().put("router", "r").put("pgpKey", JSONObject().put("keyID", "K").put("x", 1))),
                ),
            )
        assertEquals(
            listOf("extra", "profiles[*].chatManager.pgpKey.keyID", "profiles[*].chatManager.pgpKey.x", "profiles[*].foo"),
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
            account = { ShellRecordAccount.Unknown },
            migrating = { false },
            migrationState = { "pending" },
            outcome = { ImportOutcome.ABSENT },
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
    fun noCopyAnswersAbsentOnlyWhenTheLegacyStoreIsConfirmedAbsent() {
        // §25.52K.4: before the import has run the answer is migrating; a confirmed absence answers absent; anything else is an error.
        fun read(outcome: ImportOutcome?): String = ShellRecordBridge(
            account = { ShellRecordAccount.Unknown },
            migrating = { false },
            migrationState = { "none" },
            outcome = { outcome },
        ).handle(ShellOrigin.EMBEDDED_PAGE, JSONObject().put("type", "shellRecordRead").put("reqId", "r1"), 40).getString("code")

        assertEquals("migrating", read(null))
        assertEquals("absent", read(ImportOutcome.ABSENT))
        val unreadable = ShellRecordBridge(
            account = { ShellRecordAccount.Unknown },
            migrating = { false },
            migrationState = { "none" },
            outcome = { ImportOutcome.LEGACY_UNREADABLE },
        ).handle(ShellOrigin.EMBEDDED_PAGE, JSONObject().put("type", "shellRecordRead").put("reqId", "r2"), 40)
        assertEquals("error", unreadable.getString("code"))
        assertEquals("legacy_store_unreadable", unreadable.getString("sub"))
        val notDone = ShellRecordBridge(
            account = { ShellRecordAccount.Unknown },
            migrating = { false },
            migrationState = { "none" },
            outcome = { ImportOutcome.NOT_DONE },
        ).handle(ShellOrigin.EMBEDDED_PAGE, JSONObject().put("type", "shellRecordRead").put("reqId", "r3"), 40)
        assertEquals("import_not_done", notDone.getString("sub"))
    }

    @Test
    fun aLockedVaultAnswersAnErrorNotAnAbsence() {
        val bridge = ShellRecordBridge(
            account = { ShellRecordAccount.Locked },
            migrating = { false },
            migrationState = { "none" },
            outcome = { ImportOutcome.ABSENT },
        )
        val read = bridge.handle(ShellOrigin.EMBEDDED_PAGE, JSONObject().put("type", "shellRecordRead").put("reqId", "r1"), 40)
        assertEquals("error", read.getString("code"))
        assertEquals("locked", read.getString("sub"))
    }

    @Test
    fun aMigrationInProgressAnswersMigratingAndNoRecord() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        val store = SealedPageRecordStore(wrap, files, "$ACCOUNT:default")
        store.write(JSONObject().put("rev", 1).put("schemaVersion", 2))
        val bridge = ShellRecordBridge(
            account = { ShellRecordAccount.Ready(store) },
            migrating = { true },
            migrationState = { "none" },
            outcome = { ImportOutcome.DONE },
        )
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

    @Test
    fun theImportIsTheOnlyPathThatMakesAFirstCopyFromTheLegacyRecord() {
        // §25.52K.5: no new wallet is made. The bridge never creates a copy by itself on a legacy failure, and the flow writes once, on success.
        val text = File("src/main/java/network/conet/chat/nativekey/ShellRecord.kt").readText()
        val bridgeStart = text.indexOf("internal class ShellRecordBridge(")
        val flowStart = text.indexOf("internal class ShellImportFlow(")
        assertTrue(bridgeStart > 0 && flowStart > 0)
        val bridgeText = text.substring(bridgeStart, text.indexOf("internal object ShellRecordState"))
        assertFalse("the bridge never runs the import", bridgeText.contains("ShellImportFlow("))
        assertTrue(text.substring(flowStart).contains("store.write(json)"))
    }

    private fun fileNameOf(accountKey: String): String {
        val bare = accountKey.substringBefore(':').removePrefix("0x")
        return "page.v1.$bare.${accountKey.substringAfter(':')}.rec"
    }

    private fun JSONArray.toList(): List<String> = (0 until length()).map { getString(it) }
}
