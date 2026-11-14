package network.conet.chat.nativekey

import network.conet.chat.nativekey.PgpMigrationKeys.ACCOUNT
import network.conet.chat.nativekey.PgpMigrationKeys.WORKSPACE
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.atomic.AtomicBoolean

/**
 * The review items of R424 (spec r3bh): the key-shape scan (TR-16, TR-17), the first-run entry's own migrating mark (§25.52L.3), the
 * account slot's conditional fallback (§25.52B.6, documented), and the W field removal at the unregister (§25.52H.2 rule 5, §25.52J.3).
 */
class ShellRecordR424Test {
    private val key = PgpMigrationKeys.byLabel("A")

    // ---- key-shape scan (§25.52L.9) ----

    @Test
    fun tr16KeyShapedContentInAContainerSubtreeIsRefused() {
        val record = JSONObject()
            .put("rev", 0)
            .put("schemaVersion", 1)
            .put("profiles", JSONArray().put(JSONObject().put("keyID", ACCOUNT).put("data", JSONObject().put("privateKeyArmor", "x"))))
        val resp = bridgeWithoutAccount().handle(ShellOrigin.EMBEDDED_PAGE, write("t16", record), 200)
        assertEquals("key_shaped_content", resp.v().getString("code"))
        assertEquals(listOf("profiles[*].data.privateKeyArmor"), resp.v().getJSONArray("names").names())
    }

    @Test
    fun tr17MnemonicInAContainerSubtreeIsRefused() {
        val record = JSONObject()
            .put("rev", 0)
            .put("schemaVersion", 1)
            .put("profiles", JSONArray().put(JSONObject().put("keyID", ACCOUNT).put("data", JSONObject().put("mnemonic", "m"))))
        val resp = bridgeWithoutAccount().handle(ShellOrigin.EMBEDDED_PAGE, write("t17", record), 200)
        assertEquals("key_shaped_content", resp.v().getString("code"))
        assertEquals(listOf("profiles[*].data.mnemonic"), resp.v().getJSONArray("names").names())
    }

    // ---- account slot (§25.52B.6), with the documented fallback ----

    @Test
    fun withNoKeyIdAnywhereTheFirstProfileIsTheAccountRecord() {
        val record = JSONObject().put(
            "profiles",
            JSONArray()
                .put(JSONObject().put("emailAddr", "a").put("privateKeyArmor", "EOA"))
                .put(JSONObject().put("emailAddr", "b")),
        )
        assertEquals(0, ShellRecordPolicy.accountSlot(record, ACCOUNT))
    }

    @Test
    fun aKeyIdOnAnyProfileSwitchesTheFallbackOff() {
        // Once a keyID is present, the index is never used: an unmatched record has no slot.
        val record = JSONObject().put(
            "profiles",
            JSONArray()
                .put(JSONObject().put("emailAddr", "a"))
                .put(JSONObject().put("keyID", "0x4444444444444444444444444444444444444444")),
        )
        assertNull(ShellRecordPolicy.accountSlot(record, ACCOUNT))
    }

    // ---- the first-run entry marks the migration itself (§25.52L.3) ----

    @Test
    fun theEntryMarksMigratingWhileItRunsAndRestoresTheEarlierValue() {
        val flag = AtomicBoolean(false)
        var during = false
        markingMigration(flag) { during = flag.get() }
        assertTrue("the flag is set while the entry runs", during)
        assertFalse("and cleared after it, when nothing set it before", flag.get())
    }

    @Test
    fun aFlagTheShellAlreadySetStaysSetAfterTheEntry() {
        val flag = AtomicBoolean(true)
        markingMigration(flag) {}
        assertTrue(flag.get())
        try {
            markingMigration(flag) { throw IllegalStateException("import failed") }
        } catch (_: IllegalStateException) {
            // expected: the flag is restored on the failure path too
        }
        assertTrue(flag.get())
    }

    // ---- W field removal at the unregister (§25.52H.2 rule 5, §25.52J.3) ----

    @Test
    fun removeWalletDropsTheWalletFieldsAndKeepsTheRestOfTheCopy() {
        val record = walletRecord().put("walletVault", JSONObject().put("mnemonic", "M"))
        ShellRecordPolicy.removeWallet(record)
        assertFalse(record.has("mnemonicPhrase"))
        assertFalse("an emptied walletVault goes too", record.has("walletVault"))
        val profile = record.getJSONArray("profiles").getJSONObject(0)
        assertFalse(profile.has("privateKeyArmor"))
        assertEquals("a", profile.getString("emailAddr"))
        assertEquals(ACCOUNT, profile.getString("keyID"))
        assertTrue(ShellRecordPolicy.walletIn(record).isEmpty())
    }

    @Test
    fun theWalletCopyRemovalKeepsTheRecordAndBumpsTheRevision() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        val store = SealedPageRecordStore(wrap, files, "$ACCOUNT:default")
        store.write(walletRecord())
        val removal = PageWalletRemoval(store)
        assertTrue(removal.present())
        removal.remove()
        assertFalse(removal.present())
        val after = store.read()!!
        assertEquals(2, after.v().getInt("rev"))
        assertFalse(after.has("mnemonicPhrase"))
        assertEquals("a", after.getJSONArray("profiles").getJSONObject(0).getString("emailAddr"))
    }

    @Test
    fun anUnreadableWalletCopyIsErasedAtTheUnregister() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        val name = "page.v1.${ACCOUNT.removePrefix("0x")}.default.rec"
        files.write(name, ByteArray(40) { 7 })
        val removal = PageWalletRemoval(SealedPageRecordStore(wrap, files, "$ACCOUNT:default"))
        assertTrue("an unreadable copy counts as present", removal.present())
        removal.remove()
        assertNull(files.read(name))
    }

    @Test
    fun theUnregisterRemovesTheWalletCopyAfterTheStagedCopyAndKeepsL() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        seedStagedAndMarker(wrap, files)
        val pageStore = SealedPageRecordStore(wrap, files, "$ACCOUNT:default")
        pageStore.write(walletRecord())
        val engine = migrationEngine(
            files, wrap, legacyRecord(ACCOUNT, key.priv, key.pub), ChainAnswer.Unavailable,
            wallet = PageWalletRemoval(pageStore),
        )
        assertEquals("ok", engine.unregister().code.wire)
        assertNull(files.read(markerFileName()))
        assertNull(files.read(stagedFileName()))
        assertFalse(pageStore.read()!!.has("mnemonicPhrase"))
    }

    @Test
    fun withoutARecoverySourceNothingIsRemovedIncludingTheWalletCopy() {
        // L absent, P not readable, no chain backup: unregister_refused, and the W fields stay (§25.52C.3, §25.52J.3).
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        seedStagedAndMarker(wrap, files)
        val pageStore = SealedPageRecordStore(wrap, files, "$ACCOUNT:default")
        pageStore.write(walletRecord())
        val engine = migrationEngine(
            files, wrap, null, ChainAnswer.Absent,
            recovery = FixedRecovery(p = false, chain = false),
            wallet = PageWalletRemoval(pageStore),
        )
        assertEquals("unregister_refused", engine.unregister().code.wire)
        assertNotNull(files.read(markerFileName()))
        assertNotNull(files.read(stagedFileName()))
        assertTrue(pageStore.read()!!.has("mnemonicPhrase"))
    }

    @Test
    fun aWalletOnlyCopyIsRemovedWhenARecoverySourceExists() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        val wallet = FixedWallet(present = true)
        val engine = migrationEngine(files, wrap, legacyRecord(ACCOUNT, key.priv, key.pub), ChainAnswer.Unavailable, wallet = wallet)
        assertEquals("ok", engine.unregister().code.wire)
        assertEquals(1, wallet.removeCalls)
        assertFalse(wallet.present())
    }

    @Test
    fun aFailedWalletRemovalIsWriteFailedAndACallAgainFinishesIt() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        seedStagedAndMarker(wrap, files)
        val failing = FixedWallet(present = true, failRemove = true)
        val first = migrationEngine(
            files, wrap, legacyRecord(ACCOUNT, key.priv, key.pub), ChainAnswer.Unavailable, wallet = failing,
        ).unregister()
        assertEquals("write_failed", first.code.wire)
        // M and N went first (§25.52H.2 rule 5 order: the W fields last), so the copy is left with the W fields only.
        assertNull(files.read(markerFileName()))
        assertNull(files.read(stagedFileName()))
        assertTrue(failing.present())

        val again = FixedWallet(present = true)
        val second = migrationEngine(
            files, wrap, legacyRecord(ACCOUNT, key.priv, key.pub), ChainAnswer.Unavailable, wallet = again,
        ).unregister()
        assertEquals("ok", second.code.wire)
        assertFalse(again.present())
    }

    // ---- helpers ----

    private fun bridgeWithoutAccount() = ShellRecordBridge(
        account = { ShellRecordAccount.Unknown },
        migrating = { false },
        outcome = { ImportOutcome.ABSENT },
    )

    private fun write(reqId: String, record: JSONObject): JSONObject =
        JSONObject().put("type", "shellRecordWrite").put("reqId", reqId).put("record", record)

    private fun walletRecord(): JSONObject = JSONObject()
        .put("rev", 1)
        .put("schemaVersion", 2)
        .put("mnemonicPhrase", "M")
        .put(
            "profiles",
            JSONArray().put(JSONObject().put("keyID", ACCOUNT).put("emailAddr", "a").put("privateKeyArmor", "EOA")),
        )

    private fun seedStagedAndMarker(wrap: KeyWrap, files: VaultFiles) {
        SealedStagedStore(wrap, files, ACCOUNT, WORKSPACE).write(StagedItem(ACCOUNT, key.fp, key.priv))
        SealedMarkerStore(wrap, files, ACCOUNT, WORKSPACE).write(MarkerItem(key.fp, "legacyPwa", 1L))
    }

    private fun JSONArray.names(): List<String> = (0 until length()).map { getString(it) }
}
