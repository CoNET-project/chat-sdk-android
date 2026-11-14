package network.conet.chat.nativekey

import network.conet.chat.nativekey.PgpMigrationKeys.ACCOUNT
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.atomic.AtomicReference

/**
 * The r3bs and R444 items: an account that is not a canonical EOA is `account_mismatch` and fails closed (not `import_not_done`, which is only
 * for a found legacy record); the write guard holds writes until a read has completed (§25.52W.3); a marker or a pointer without a record
 * holds writes; and the residual PGP public positions the Android reader lists are stripped on read (§25.52V.3).
 */
class ShellRecordR445Test {
    private fun v(resp: JSONObject) = resp.v()

    private fun writeReq(reqId: String, rev: Int = 0): JSONObject = JSONObject()
        .put("type", "shellRecordWrite")
        .put("reqId", reqId)
        .put("record", JSONObject().put("rev", rev).put("schemaVersion", 2).put("profiles", JSONArray().put(JSONObject().put("keyID", ACCOUNT).put("privateKeyArmor", "EOA"))))

    private fun bridge(store: SealedPageRecordStore, outcome: ImportOutcome?, flags: DeviceFlags = NoDeviceFlags) = ShellRecordBridge(
        account = { ShellRecordAccount.Ready(store, ACCOUNT) },
        migrating = { false },
        outcome = { outcome },
        flags = flags,
    )

    // ---- R444 item 1: an invalid account is account_mismatch, fail closed ----

    @Test
    fun anInvalidAccountIsAccountMismatchAndNeverImportNotDone() {
        val files = NativeTestFiles()
        val store = SealedPageRecordStore(NativeTestWrap(), files, "$ACCOUNT:default")
        val outcome = AtomicReference<ImportOutcome?>(null)
        var stored = false
        val flow = ShellImportFlow(
            storeFor = { store },
            addressOf = { null },
            pgpStep = { _, _ -> },
            outcome = outcome,
        )
        val code = flow.run("0xnot-an-address", LegacyWalletRecord.Found("{}".toByteArray()), null)
        assertEquals(ShellImportCode.ACCOUNT_MISMATCH, code)
        assertEquals("account_mismatch", code.wire)
        assertEquals(ImportOutcome.ACCOUNT_MISMATCH, outcome.get())
        assertNull("the legacy store is not read and nothing is stored", store.read())
        stored = store.read() != null
        assertFalse(stored)

        // The read answers account_mismatch (fail closed), and the write waits (migrating).
        val read = bridge(store, outcome.get()).handle(ShellOrigin.EMBEDDED_PAGE, JSONObject().put("type", "shellRecordRead").put("reqId", "i1"), 40)
        assertEquals("account_mismatch", v(read).getString("sub"))
        val write = bridge(store, outcome.get()).handle(ShellOrigin.EMBEDDED_PAGE, writeReq("i2"), 200)
        assertEquals("migrating", v(write).getString("code"))
        assertNull(store.read())
    }

    // ---- §25.52W.3: the write guard ----

    @Test
    fun aWriteWithAMarkerIsMigratingEvenAfterAnAbsentOutcome() {
        val files = NativeTestFiles()
        val flags = DeviceFlagFiles(files)
        flags.setLegacyUnreadable()
        val store = SealedPageRecordStore(NativeTestWrap(), files, "$ACCOUNT:default")
        val resp = bridge(store, ImportOutcome.ABSENT, flags).handle(ShellOrigin.EMBEDDED_PAGE, writeReq("g1"), 200)
        assertEquals("migrating", v(resp).getString("code"))
        assertNull(store.read())
    }

    @Test
    fun aWriteWithAPointerAndNoRecordIsMigrating() {
        val files = NativeTestFiles()
        val flags = DeviceFlagFiles(files)
        flags.setAccountPointer()
        val store = SealedPageRecordStore(NativeTestWrap(), files, "$ACCOUNT:default")
        val resp = bridge(store, ImportOutcome.ABSENT, flags).handle(ShellOrigin.EMBEDDED_PAGE, writeReq("g2"), 200)
        assertEquals("migrating", v(resp).getString("code"))
    }

    @Test
    fun aWriteAfterAConfirmedAbsenceWithNoPointerOrMarkerCreatesTheRecord() {
        val files = NativeTestFiles()
        val flags = DeviceFlagFiles(files)
        val store = SealedPageRecordStore(NativeTestWrap(), files, "$ACCOUNT:default")
        val resp = bridge(store, ImportOutcome.ABSENT, flags).handle(ShellOrigin.EMBEDDED_PAGE, writeReq("g3"), 200)
        assertEquals("ok", v(resp).getString("code"))
        assertTrue(flags.accountPointer())
    }

    @Test
    fun aWriteWithContentRefusedStaysAContentRefusalBeforeTheGuard() {
        // §25.52W.3: the guard comes after the content checks: an invalid write is refused for its content, not as migrating.
        val files = NativeTestFiles()
        val store = SealedPageRecordStore(NativeTestWrap(), files, "$ACCOUNT:default")
        val bad = JSONObject().put("type", "shellRecordWrite").put("reqId", "g4")
            .put("record", JSONObject().put("rev", 0).put("schemaVersion", 2).put("mnemonic", "m").put("profiles", JSONArray().put(JSONObject().put("keyID", ACCOUNT))))
        val resp = bridge(store, null).handle(ShellOrigin.EMBEDDED_PAGE, bad, 200)
        assertEquals("key_shaped_content", v(resp).getString("code"))
    }

    @Test
    fun aRecordThatIsNotValidDoesNotClearTheMarker() {
        // §25.52W.6: the marker is cleared when a valid record is read. A record with another account is answered account_mismatch,
        // and the marker stays.
        val files = NativeTestFiles()
        val flags = DeviceFlagFiles(files)
        flags.setLegacyUnreadable()
        val store = SealedPageRecordStore(NativeTestWrap(), files, "$ACCOUNT:default")
        store.write(
            JSONObject().put("rev", 1).put("schemaVersion", 2).put("mnemonicPhrase", "M")
                .put("profiles", JSONArray().put(JSONObject().put("keyID", "0x4444444444444444444444444444444444444444").put("privateKeyArmor", "EOA"))),
        )
        val resp = bridge(store, ImportOutcome.LEGACY_UNREADABLE, flags).handle(ShellOrigin.EMBEDDED_PAGE, JSONObject().put("type", "shellRecordRead").put("reqId", "m1"), 40)
        assertEquals("account_mismatch", v(resp).getString("sub"))
        assertTrue("the marker stays", flags.legacyUnreadable())
        assertFalse("the pointer is not repaired for another account", flags.accountPointer())
    }

    // ---- R444 item 2 (§25.52V.3): the residual PGP public positions the Android reader lists ----

    @Test
    fun everyResidualPositionTheAndroidReaderListsIsStripped() {
        val record = JSONObject()
            .put("rev", 1)
            .put("schemaVersion", 2)
            .put("mnemonicPhrase", "M")
            .put("beamio", JSONObject().put("accountName", "n").put("pgpPublicKeyArmor", "PUB").put("pgpPublicKeyID", "K"))
            .put(
                "profiles",
                JSONArray().put(
                    JSONObject()
                        .put("keyID", ACCOUNT)
                        .put("privateKeyArmor", "EOA")
                        .put("publicKeyArmor", "EOA-PUBLIC")
                        .put("chatManager", JSONObject().put("router", "R").put("pgpKey", JSONObject().put("publicKey", "P").put("keyID", "K").put("routes", "RT")))
                        .put("pgpKey", JSONObject().put("publicKeyArmor", "PA").put("publicKeyObj", JSONObject()))
                        .put(
                            "chats",
                            JSONArray().put(
                                JSONObject()
                                    .put("address", "a")
                                    .put(
                                        "chatData",
                                        JSONObject()
                                            .put("online", true)
                                            .put("publicArmored", "PUB")
                                            .put("routePgpKeyID", "K")
                                            .put("routersArmoreds", "R")
                                            .put("privateArmored", "PRIV"),
                                    ),
                            ),
                        ),
                ),
            )
        ShellRecordPolicy.stripPgpForRead(record)
        val profile = record.getJSONArray("profiles").getJSONObject(0)
        // Removed: the chatManager PGP key with its public parts, the whole pgpKey, the beamio PGP public fields, and the chatData PGP fields.
        assertFalse(profile.getJSONObject("chatManager").has("pgpKey"))
        assertFalse(profile.has("pgpKey"))
        assertFalse(record.getJSONObject("beamio").has("pgpPublicKeyArmor"))
        assertFalse(record.getJSONObject("beamio").has("pgpPublicKeyID"))
        val chatData = profile.getJSONArray("chats").getJSONObject(0).getJSONObject("chatData")
        for (k in listOf("publicArmored", "routePgpKeyID", "routersArmoreds", "privateArmored")) assertFalse(chatData.has(k))
        // Kept: the account's EOA public key, the router, the account name, and the chat's online state.
        assertEquals("EOA-PUBLIC", profile.getString("publicKeyArmor"))
        assertEquals("R", profile.getJSONObject("chatManager").getString("router"))
        assertEquals("n", record.getJSONObject("beamio").getString("accountName"))
        assertTrue(chatData.getBoolean("online"))
        assertEquals("EOA", profile.getString("privateKeyArmor"))
    }
}
