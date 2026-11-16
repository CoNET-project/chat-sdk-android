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
            JSONObject().put("rev", 1).put("schemaVersion", 2).put("mnemonicPhrase", token),
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
            .put("mnemonicPhrase", "M")
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
        assertEquals("M", record.getString("mnemonicPhrase"))
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
            account = { ShellRecordAccount.Ready(store, ACCOUNT) },
            migrating = { false },
            outcome = { ImportOutcome.DONE },
        )
        val resp = bridge.handle(ShellOrigin.EMBEDDED_PAGE, JSONObject().put("type", "shellRecordRead").put("reqId", "r9"), 40)
        assertEquals("ok", resp.v().getString("code"))
        assertFalse(resp.v().has("walletFieldsRedacted"))
    }

    @Test
    fun theMergeKeepsAnOmittedWalletFieldAndRefusesADifferentOne() {
        val stored = JSONObject()
            .put("rev", 1)
            .put("schemaVersion", 2)
            .put("mnemonicPhrase", "M")
            .put("profiles", JSONArray().put(JSONObject().put("keyID", ACCOUNT).put("emailAddr", "a").put("privateKeyArmor", "EOA")))
        val omitted = JSONObject()
            .put("rev", 1)
            .put("schemaVersion", 2)
            .put("profiles", JSONArray().put(JSONObject().put("keyID", ACCOUNT).put("emailAddr", "b")))
        val (merged, conflicts) = ShellRecordPolicy.mergeWallet(omitted, stored, ACCOUNT)
        assertTrue(conflicts.isEmpty())
        assertEquals("EOA", merged.getJSONArray("profiles").getJSONObject(0).getString("privateKeyArmor"))
        assertEquals("M", merged.getString("mnemonicPhrase"))

        val different = JSONObject()
            .put("rev", 1)
            .put("schemaVersion", 2)
            .put("mnemonicPhrase", "OTHER")
            .put("profiles", JSONArray().put(JSONObject().put("keyID", ACCOUNT).put("emailAddr", "b").put("privateKeyArmor", "EOA")))
        assertEquals(listOf("mnemonicPhrase"), ShellRecordPolicy.mergeWallet(different, stored, ACCOUNT).names)
    }

    @Test
    fun theWalletSlotFollowsTheAccountKeyNotThePosition() {
        // §25.52H.3 (R404 #3): the W slot is the profile whose keyID is the account, wherever it sits in the array.
        val other = "0x4444444444444444444444444444444444444444"
        val stored = JSONObject()
            .put("rev", 1)
            .put("schemaVersion", 2)
            .put(
                "profiles",
                JSONArray()
                    .put(JSONObject().put("keyID", other).put("emailAddr", "x"))
                    .put(JSONObject().put("keyID", ACCOUNT).put("privateKeyArmor", "ACCOUNT-KEY")),
            )
        // The page lists the account first, without its W field.
        val page = JSONObject()
            .put("rev", 1)
            .put("schemaVersion", 2)
            .put(
                "profiles",
                JSONArray()
                    .put(JSONObject().put("keyID", ACCOUNT).put("emailAddr", "a"))
                    .put(JSONObject().put("keyID", other).put("emailAddr", "x")),
            )
        val (merged, conflicts) = ShellRecordPolicy.mergeWallet(page, stored, ACCOUNT)
        assertTrue(conflicts.isEmpty())
        val profiles = merged.getJSONArray("profiles")
        assertEquals("ACCOUNT-KEY", profiles.getJSONObject(0).getString("privateKeyArmor"))
        assertFalse(profiles.getJSONObject(1).has("privateKeyArmor"))
    }

    @Test
    fun aMissingOrAmbiguousAccountSlotIsAConflictNotAGuess() {
        val other = "0x4444444444444444444444444444444444444444"
        val stored = JSONObject()
            .put("rev", 1)
            .put("schemaVersion", 2)
            .put("profiles", JSONArray().put(JSONObject().put("keyID", other).put("privateKeyArmor", "OTHER-KEY")))
        // The stored W field has no account slot, and the page carries none either: a conflict, nothing is written.
        val page = JSONObject()
            .put("rev", 1)
            .put("schemaVersion", 2)
            .put("profiles", JSONArray().put(JSONObject().put("keyID", "0x5555555555555555555555555555555555555555")))
        assertEquals(listOf("profiles[*].privateKeyArmor"), ShellRecordPolicy.mergeWallet(page, stored, ACCOUNT).names)

        // Two profiles claim the account: no slot is chosen among them.
        val twice = JSONObject()
            .put("rev", 1)
            .put("schemaVersion", 2)
            .put(
                "profiles",
                JSONArray()
                    .put(JSONObject().put("keyID", ACCOUNT).put("privateKeyArmor", "A"))
                    .put(JSONObject().put("keyID", ACCOUNT).put("privateKeyArmor", "B")),
            )
        assertEquals(listOf("profiles[*].privateKeyArmor"), ShellRecordPolicy.mergeWallet(twice, twice, ACCOUNT).names)
    }

    @Test
    fun aReadKeepsTheWalletFieldsForThePage() {
        // §25.52I.2 (R404 #1): a read carries the W fields, and it never carries walletFieldsRedacted.
        val resp = readBridge(storedWalletStore()).handle(
            ShellOrigin.EMBEDDED_PAGE,
            JSONObject().put("type", "shellRecordRead").put("reqId", "rw1"),
            40,
        )
        assertEquals("ok", resp.v().getString("code"))
        assertFalse(resp.v().has("walletFieldsRedacted"))
        val record = resp.v().getJSONObject("record")
        assertEquals("M", record.getString("mnemonicPhrase"))
        assertEquals("ACCOUNT-KEY", record.getJSONArray("profiles").getJSONObject(0).getString("privateKeyArmor"))
    }

    @Test
    fun aReadDeletesThePgpPublicFieldsAndKeepsTheRouter() {
        // §25.52I.2 (R404 #2): the read copy loses the PGP public fields; the whitelisted router stays.
        val store = SealedPageRecordStore(NativeTestWrap(), NativeTestFiles(), "$ACCOUNT:default")
        store.write(
            JSONObject()
                .put("rev", 1)
                .put("schemaVersion", 2)
                .put(
                    "profiles",
                    JSONArray().put(
                        JSONObject()
                            .put("keyID", ACCOUNT)
                            .put("privateKeyArmor", "ACCOUNT-KEY")
                            .put(
                                "chatManager",
                                JSONObject()
                                    .put("router", "ROUTER")
                                    .put("pgpKey", JSONObject().put("publicKey", "PUBLIC-BLOCK").put("keyID", "PGP-KID")),
                            ),
                    ),
                ),
        )
        val resp = readBridge(store).handle(ShellOrigin.EMBEDDED_PAGE, JSONObject().put("type", "shellRecordRead").put("reqId", "rp1"), 40)
        assertEquals("ok", resp.v().getString("code"))
        val profile = resp.v().getJSONObject("record").getJSONArray("profiles").getJSONObject(0)
        assertEquals("ACCOUNT-KEY", profile.getString("privateKeyArmor"))
        val chatManager = profile.getJSONObject("chatManager")
        assertEquals("ROUTER", chatManager.getString("router"))
        assertFalse(chatManager.has("pgpKey"))
        assertFalse(resp.toString().contains("PUBLIC-BLOCK"))
    }

    @Test
    fun aWritePgpPublicFieldIsBadRequestAndNamesItsPaths() {
        // §25.52I.3 (R404 #2): the PGP public fields are not whitelisted. A write that carries them is refused with the paths named.
        val record = JSONObject()
            .put("rev", 1)
            .put("schemaVersion", 2)
            .put(
                "profiles",
                JSONArray().put(
                    JSONObject()
                        .put("keyID", ACCOUNT)
                        .put("chatManager", JSONObject().put("pgpKey", JSONObject().put("publicKey", "PUB").put("keyID", "K"))),
                ),
            )
        val resp = writeBridge(storedWalletStore()).handle(
            ShellOrigin.EMBEDDED_PAGE,
            JSONObject().put("type", "shellRecordWrite").put("reqId", "wp1").put("record", record),
            200,
        )
        assertEquals("bad_request", resp.v().getString("code"))
        assertEquals(
            listOf("profiles[*].chatManager.pgpKey.keyID", "profiles[*].chatManager.pgpKey.publicKey"),
            resp.v().getJSONArray("names").toList(),
        )
    }

    @Test
    fun theWhitelistMatchesExactPathsOnly() {
        // R412 (d): a name that only looks like a whitelisted one is a violation.
        val record = JSONObject()
            .put("rev", 0)
            .put("schemaVersion", 2)
            .put("mnemonicX", "M")
            .put(
                "profiles",
                JSONArray().put(
                    JSONObject()
                        .put("keyID", ACCOUNT)
                        .put("privateKeyArmorX", "K")
                        .put("chatManager", JSONObject().put("routerX", "R")),
                ),
            )
        assertEquals(
            listOf("mnemonicX", "profiles[*].chatManager.routerX", "profiles[*].privateKeyArmorX"),
            ShellRecordPolicy.whitelistViolations(record),
        )
    }

    @Test
    fun aStoredWalletCopyRefusesOlderOrSchemaLessWrites() {
        // §25.52F.5, R412 (c): a stored copy that holds W fields takes only schema 2 writes. Schema 1 and a missing schemaVersion are refused,
        // and the refusal names the stored W paths.
        val store = storedWalletStore()
        for (schema in listOf<Any?>(1, null)) {
            val record = JSONObject()
                .put("rev", 1)
                .put("profiles", JSONArray().put(JSONObject().put("keyID", ACCOUNT).put("emailAddr", "b")))
            if (schema != null) record.put("schemaVersion", schema)
            val resp = writeBridge(store).handle(
                ShellOrigin.EMBEDDED_PAGE,
                JSONObject().put("type", "shellRecordWrite").put("reqId", "wr$schema").put("record", record),
                200,
            )
            assertEquals("wallet_copy_not_approved", resp.v().getString("code"))
            assertEquals(listOf("mnemonicPhrase", "profiles[*].privateKeyArmor"), resp.v().getJSONArray("names").toList())
        }
        assertEquals(1, store.read()!!.getInt("rev"))
    }

    @Test
    fun aSchemaTwoWriteKeepsTheStoredWalletFieldWhenThePageOmitsIt() {
        val store = storedWalletStore()
        val record = JSONObject()
            .put("rev", 1)
            .put("schemaVersion", 2)
            .put("profiles", JSONArray().put(JSONObject().put("keyID", ACCOUNT).put("emailAddr", "b")))
        val resp = writeBridge(store).handle(
            ShellOrigin.EMBEDDED_PAGE,
            JSONObject().put("type", "shellRecordWrite").put("reqId", "w2").put("record", record),
            200,
        )
        assertEquals("ok", resp.v().getString("code"))
        assertEquals(2, resp.v().getInt("rev"))
        val stored = store.read()!!
        assertEquals("M", stored.getString("mnemonicPhrase"))
        val profile = stored.getJSONArray("profiles").getJSONObject(0)
        assertEquals("ACCOUNT-KEY", profile.getString("privateKeyArmor"))
        assertEquals("b", profile.getString("emailAddr"))
    }

    @Test
    fun anOlderSchemaIsAcceptedWhileTheStoredCopyHoldsNoWalletField() {
        val store = SealedPageRecordStore(NativeTestWrap(), NativeTestFiles(), "$ACCOUNT:default")
        store.write(
            JSONObject()
                .put("rev", 1)
                .put("schemaVersion", 1)
                .put("profiles", JSONArray().put(JSONObject().put("keyID", ACCOUNT).put("emailAddr", "a"))),
        )
        val record = JSONObject()
            .put("rev", 1)
            .put("schemaVersion", 1)
            .put("profiles", JSONArray().put(JSONObject().put("keyID", ACCOUNT).put("emailAddr", "b")))
        val resp = writeBridge(store).handle(
            ShellOrigin.EMBEDDED_PAGE,
            JSONObject().put("type", "shellRecordWrite").put("reqId", "w3").put("record", record),
            200,
        )
        assertEquals("ok", resp.v().getString("code"))
        assertEquals(2, resp.v().getInt("rev"))
    }

    @Test
    fun theStoreBindsTheAccountKeyAndTheVersionByteAsAad() {
        // R412 (a): the AAD is the account key in lower case plus one version byte; the file begins with that version byte.
        val wrap = CapturingWrap()
        val files = NativeTestFiles()
        SealedPageRecordStore(wrap, files, "$ACCOUNT:default").write(JSONObject().put("rev", 1).put("schemaVersion", 2))
        assertArrayEquals("$ACCOUNT:default".toByteArray(Charsets.UTF_8) + byteArrayOf(1), wrap.sealAads.single())
        assertEquals(1, files.map.values.single()[0].toInt())
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
            .put("mnemonicPhrase", "M")
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
    fun anUnknownTopLevelActionOnTheWindowChannelIsTheEnvelopeLevelUnknownCommand() {
        // 25.52AU.1, BU.1 (r3dt): any unknown top-level action is ok false, error unknown_command, once, with no result. A missing or invalid reqId is
        // bad_request first (25.52AW.1, the envelope comes before the action).
        val bridge = ShellRecordBridge(
            account = { ShellRecordAccount.Unknown },
            migrating = { false },
            outcome = { ImportOutcome.ABSENT },
        )
        val named = bridge.handle(ShellOrigin.EMBEDDED_PAGE, JSONObject().put("type", "zzUnknownAction").put("reqId", "u1"), 40)
        assertEquals(false, named.getBoolean("ok"))
        assertEquals("unknown_command", named.getString("error"))
        assertFalse(named.has("result"))
        val noId = bridge.handle(ShellOrigin.EMBEDDED_PAGE, JSONObject().put("type", "zzUnknownAction"), 40)
        assertTrue(noId.isNull("reqId"))
        assertEquals("bad_request", noId.getString("error"))
    }

    @Test
    fun theMigrationStateIsNotAPageCommand() {
        // §25.52L.6 (D7): the page cannot ask for the migration state. The bridge refuses the command; the native query is separate.
        val bridge = ShellRecordBridge(
            account = { ShellRecordAccount.Unknown },
            migrating = { false },
            outcome = { ImportOutcome.ABSENT },
        )
        val refused = bridge.handle(
            ShellOrigin.EMBEDDED_PAGE,
            JSONObject().put("type", "shellRecordMigrationState").put("reqId", "s1"),
            40,
        )
        // 25.52AW.1, AU.1, BU.1 (R709): an unknown shellRecord* name on the window channel is the envelope-level answer: ok false, error
        // unknown_command, no result, the reqId echoed, once. (It was bad_request before r3cu; a result.code form before r3du.)
        assertEquals(false, refused.getBoolean("ok"))
        assertEquals("unknown_command", refused.getString("error"))
        assertEquals("s1", refused.getString("reqId"))
        assertTrue("no result on the envelope-level answer", !refused.has("result"))
        val other = bridge.handle(
            ShellOrigin.EMBEDDED_PAGE,
            JSONObject().put("type", "shellRecordZzUnknown").put("reqId", 990000061),
            40,
        )
        assertEquals("unknown_command", other.getString("error"))
        assertEquals(990000061, other.getInt("reqId"))
        assertTrue(!other.has("result"))
        val text = File("src/main/java/network/conet/chat/nativekey/ShellRecord.kt").readText()
        assertTrue(text.contains("fun migrationState(context: Context): String"))
    }

    @Test
    fun noCopyAnswersAbsentOnlyWhenTheLegacyStoreIsConfirmedAbsent() {
        // §25.52K.4: before the import has run the answer is migrating; a confirmed absence answers absent; anything else is an error.
        fun read(outcome: ImportOutcome?): String = ShellRecordBridge(
            account = { ShellRecordAccount.Unknown },
            migrating = { false },
            outcome = { outcome },
        ).handle(ShellOrigin.EMBEDDED_PAGE, JSONObject().put("type", "shellRecordRead").put("reqId", "r1"), 40).v().getString("code")

        assertEquals("migrating", read(null))
        assertEquals("absent", read(ImportOutcome.ABSENT))
        val unreadable = ShellRecordBridge(
            account = { ShellRecordAccount.Unknown },
            migrating = { false },
            outcome = { ImportOutcome.LEGACY_UNREADABLE },
        ).handle(ShellOrigin.EMBEDDED_PAGE, JSONObject().put("type", "shellRecordRead").put("reqId", "r2"), 40)
        // §25.52U.6 (r3rz): an unreadable legacy store answers migrating, not error(legacy_store_unreadable).
        assertEquals("migrating", unreadable.v().getString("code"))
        val notDone = ShellRecordBridge(
            account = { ShellRecordAccount.Unknown },
            migrating = { false },
            outcome = { ImportOutcome.NOT_DONE },
        ).handle(ShellOrigin.EMBEDDED_PAGE, JSONObject().put("type", "shellRecordRead").put("reqId", "r3"), 40)
        assertEquals("import_not_done", notDone.v().getString("sub"))
    }

    @Test
    fun aLockedStoreOnAWriteIsWriteFailedOnce() {
        // 25.52CH.1 (r3eg): a write on a locked store is ok:true with write_failed, once, with the reqId as sent.
        val bridge = ShellRecordBridge(
            account = { ShellRecordAccount.Locked },
            migrating = { false },
            outcome = { ImportOutcome.ABSENT },
        )
        val record = JSONObject().put("rev", 1).put("schemaVersion", 1)
        val write = bridge.handle(ShellOrigin.EMBEDDED_PAGE, JSONObject().put("type", "shellRecordWrite").put("reqId", "w1").put("record", record), 60)
        assertEquals(true, write.getBoolean("ok"))
        assertEquals("write_failed", write.getJSONObject("result").getString("code"))
        assertEquals("w1", write.getString("reqId"))
    }

    @Test
    fun aStorageExceptionIsTheFallbackOnceForReadAndWrite() {
        // 25.52CF.1 (r3ef): a read that throws gives error with sub record_unreadable; a write that throws gives write_failed. Both are ok:true,
        // once, with the reqId as sent, and no record content.
        val files = object : VaultFiles {
            override fun read(name: String): ByteArray? = throw IllegalStateException("simulated storage fault")
            override fun write(name: String, bytes: ByteArray) = throw IllegalStateException("simulated storage fault")
            override fun delete(name: String) = throw IllegalStateException("simulated storage fault")
        }
        val store = SealedPageRecordStore(NativeTestWrap(), files, "${DerivedAccount.ADDRESS}:default")
        val bridge = ShellRecordBridge(
            account = { ShellRecordAccount.Ready(store, DerivedAccount.ADDRESS) },
            migrating = { false },
            outcome = { ImportOutcome.ABSENT },
        )
        val read = bridge.handle(ShellOrigin.EMBEDDED_PAGE, JSONObject().put("type", "shellRecordRead").put("reqId", "f1"), 40)
        assertEquals(true, read.getBoolean("ok"))
        assertEquals("error", read.getJSONObject("result").getString("code"))
        assertEquals("record_unreadable", read.getJSONObject("result").getString("sub"))
        assertEquals("f1", read.getString("reqId"))
        val record = JSONObject().put("rev", 1).put("schemaVersion", 1)
        val write = bridge.handle(ShellOrigin.EMBEDDED_PAGE, JSONObject().put("type", "shellRecordWrite").put("reqId", "f2").put("record", record), 60)
        assertEquals(true, write.getBoolean("ok"))
        assertEquals("write_failed", write.getJSONObject("result").getString("code"))
        assertEquals("f2", write.getString("reqId"))
    }

    @Test
    fun aLockedVaultAnswersAnErrorNotAnAbsence() {
        val bridge = ShellRecordBridge(
            account = { ShellRecordAccount.Locked },
            migrating = { false },
            outcome = { ImportOutcome.ABSENT },
        )
        val read = bridge.handle(ShellOrigin.EMBEDDED_PAGE, JSONObject().put("type", "shellRecordRead").put("reqId", "r1"), 40)
        assertEquals("error", read.v().getString("code"))
        assertEquals("storage_locked", read.v().getString("sub"))
    }

    @Test
    fun aMigrationInProgressAnswersMigratingAndNoRecord() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        val store = SealedPageRecordStore(wrap, files, "$ACCOUNT:default")
        store.write(JSONObject().put("rev", 1).put("schemaVersion", 2))
        val bridge = ShellRecordBridge(
            account = { ShellRecordAccount.Ready(store, ACCOUNT) },
            migrating = { true },
            outcome = { ImportOutcome.DONE },
        )
        val resp = bridge.handle(ShellOrigin.EMBEDDED_PAGE, JSONObject().put("type", "shellRecordRead").put("reqId", "r1"), 40)
        assertEquals("migrating", resp.v().getString("code"))
        assertFalse(resp.v().has("record"))
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
        assertTrue(module.contains("BridgeCommandTable.chatChannelShellRecordCode(type)"))
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

    /** A sealed copy holding the W fields of [ACCOUNT]: the mnemonic and the account profile's private key. */
    private fun storedWalletStore(): SealedPageRecordStore {
        val store = SealedPageRecordStore(NativeTestWrap(), NativeTestFiles(), "$ACCOUNT:default")
        store.write(
            JSONObject()
                .put("rev", 1)
                .put("schemaVersion", 2)
                .put("mnemonicPhrase", "M")
                .put(
                    "profiles",
                    JSONArray().put(JSONObject().put("keyID", ACCOUNT).put("emailAddr", "a").put("privateKeyArmor", "ACCOUNT-KEY")),
                ),
        )
        return store
    }

    private fun readBridge(store: SealedPageRecordStore) = ShellRecordBridge(
        account = { ShellRecordAccount.Ready(store, ACCOUNT) },
        migrating = { false },
        outcome = { ImportOutcome.DONE },
    )

    private fun writeBridge(store: SealedPageRecordStore) = readBridge(store)

    /** Records the AAD of every seal, and delegates the sealing to the test wrap. */
    private class CapturingWrap : KeyWrap {
        private val inner = NativeTestWrap()
        val sealAads = mutableListOf<ByteArray>()

        override fun seal(aad: ByteArray, plain: ByteArray): ByteArray {
            sealAads += aad
            return inner.seal(aad, plain)
        }

        override fun open(aad: ByteArray, sealed: ByteArray): ByteArray? = inner.open(aad, sealed)

        override fun deleteKey() = inner.deleteKey()
    }

    private fun fileNameOf(accountKey: String): String {
        val bare = accountKey.substringBefore(':').removePrefix("0x")
        return "page.v1.$bare.${accountKey.substringAfter(':')}.rec"
    }

    private fun JSONArray.toList(): List<String> = (0 until length()).map { getString(it) }
}
