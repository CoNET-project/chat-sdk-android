package network.conet.chat.nativekey

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * The R431 and R436 items on the page-record bridge (spec r3bp): the ack envelope (§25.52T.2), the absence of a fresh install and the account
 * pointer (§25.52T.3, §25.52T.4), the device-level marker (§25.52T.5, §25.52T.6), and the canonical JSON of the stored copy (§25.52M.4).
 * The ack vectors (AK-01 to AK-16) run in ShellRecordAckVectorsTest.
 */
// The record tests use a key-derived account (25.52N.9 Q1); see DerivedAccount.
private val ACCOUNT: String = DerivedAccount.ADDRESS

class ShellRecordR431Test {
    private fun store(files: NativeTestFiles = NativeTestFiles()) = SealedPageRecordStore(NativeTestWrap(), files, "$ACCOUNT:default")

    private fun bridge(outcome: ImportOutcome?, store: SealedPageRecordStore, flags: DeviceFlags = NoDeviceFlags) = ShellRecordBridge(
        account = { ShellRecordAccount.Ready(store, ACCOUNT) },
        migrating = { false },
        outcome = { outcome },
        flags = flags,
    )

    private fun read(reqId: String, b: ShellRecordBridge): JSONObject =
        b.handle(ShellOrigin.EMBEDDED_PAGE, JSONObject().put("type", "shellRecordRead").put("reqId", reqId), 40)

    private fun walletRecord(rev: Int) = JSONObject()
        .put("rev", rev)
        .put("schemaVersion", 2)
        .put("mnemonicPhrase", "M")
        .put("profiles", JSONArray().put(JSONObject().put("keyID", ACCOUNT).put("privateKeyArmor", DerivedAccount.KEY)))

    // ---- the ack envelope (§25.52T.2) ----

    @Test
    fun aProcessedAnswerIsAnAckWithItsResultCode() {
        val s = store()
        s.write(walletRecord(1))
        val ok = read("ack1", bridge(ImportOutcome.DONE, s))
        assertEquals("ack", ok.getString("type"))
        assertEquals("ack1", ok.getString("reqId"))
        assertTrue(ok.getBoolean("ok"))
        assertEquals("ok", ok.getJSONObject("result").getString("code"))
        assertFalse("the code is inside result, not at the top", ok.has("code"))
    }

    @Test
    fun aConflictIsAProcessedAckWithCurrentRev() {
        val s = store()
        s.write(walletRecord(3))
        val resp = bridge(ImportOutcome.DONE, s).handle(
            ShellOrigin.EMBEDDED_PAGE,
            JSONObject().put("type", "shellRecordWrite").put("reqId", "ack2").put("record", walletRecord(2)),
            200,
        )
        assertTrue(resp.getBoolean("ok"))
        assertEquals("conflict", resp.getJSONObject("result").getString("code"))
        assertEquals(3, resp.getJSONObject("result").getInt("currentRev"))
    }

    @Test
    fun anEnvelopeRefusalIsAnAckWithAnErrorAndNoResult() {
        val resp = bridge(ImportOutcome.ABSENT, store()).handle(ShellOrigin.OTHER, JSONObject().put("type", "shellRecordRead").put("reqId", "ack3"), 40)
        assertFalse(resp.getBoolean("ok"))
        assertEquals("origin_refused", resp.getString("error"))
        assertFalse(resp.has("result"))
    }

    @Test
    fun anInvalidReqIdIsEchoedAsNull() {
        val resp = bridge(ImportOutcome.ABSENT, store()).handle(ShellOrigin.EMBEDDED_PAGE, JSONObject().put("type", "shellRecordRead").put("reqId", ""), 40)
        assertFalse(resp.getBoolean("ok"))
        assertEquals("bad_request", resp.getString("error"))
        assertTrue(resp.isNull("reqId"))
    }

    @Test
    fun aMissingEoaKeyIsAnAckResultWithNeedsNativeRecovery() {
        val s = store()
        s.write(JSONObject().put("rev", 1).put("schemaVersion", 2).put("profiles", JSONArray().put(JSONObject().put("keyID", ACCOUNT))))
        val resp = read("ack4", bridge(ImportOutcome.DONE, s))
        assertTrue(resp.getBoolean("ok"))
        assertEquals("error", resp.getJSONObject("result").getString("code"))
        assertEquals("needs_native_recovery", resp.getJSONObject("result").getString("sub"))
    }

    // ---- absence, the pointer and the marker (§25.52T.3 to §25.52T.6) ----

    @Test
    fun aFreshInstallWithNoLegacyStoreAnswersAbsent() {
        val resp = read("fresh1", bridge(ImportOutcome.ABSENT, store()))
        assertEquals("absent", resp.v().getString("code"))
    }

    @Test
    fun anAccountPointerNeverAnswersAbsent() {
        // §25.52T.4: the device has established an account, but the record is missing: error, never absent.
        val files = NativeTestFiles()
        DeviceFlagFiles(files).setAccountPointer()
        val resp = read("ptr1", bridge(ImportOutcome.ABSENT, store(files), DeviceFlagFiles(files)))
        assertEquals("error", resp.v().getString("code"))
        assertEquals("account_record_missing", resp.v().getString("sub"))
    }

    @Test
    fun aMarkerIsClearedByAConfirmedAbsenceAndThenTheReadIsAbsent() {
        // §25.52T.5, §25.52T.6 (AK-05): the marker is set, the legacy store is confirmed absent: absent, and the marker is cleared.
        val files = NativeTestFiles()
        val flags = DeviceFlagFiles(files)
        flags.setLegacyUnreadable()
        assertEquals("absent", read("mark1", bridge(ImportOutcome.ABSENT, store(files), flags)).v().getString("code"))
        assertFalse(flags.legacyUnreadable())
    }

    @Test
    fun aMarkerWithoutAReReadAnswersMigratingNotAbsence() {
        // §25.52T.6 (AK-07), §25.52U.6 (r3rz): the marker is set and the legacy store was not read again in this process: migrating, never absent.
        val files = NativeTestFiles()
        DeviceFlagFiles(files).setLegacyUnreadable()
        val resp = read("mark2", bridge(null, store(files), DeviceFlagFiles(files)))
        assertEquals("migrating", resp.v().getString("code"))
    }

    @Test
    fun aWriteWithTheMarkerAndNoRecordIsMigratingNotAFirstWrite() {
        // §25.52T.5 (AK-15): the first write does not happen while the marker is set and the record is missing.
        val files = NativeTestFiles()
        val flags = DeviceFlagFiles(files)
        flags.setLegacyUnreadable()
        val resp = bridge(ImportOutcome.LEGACY_UNREADABLE, store(files), flags).handle(
            ShellOrigin.EMBEDDED_PAGE,
            JSONObject().put("type", "shellRecordWrite").put("reqId", "mark3").put("record", JSONObject().put("rev", 0).put("schemaVersion", 1)),
            200,
        )
        assertEquals("migrating", resp.getJSONObject("result").getString("code"))
        assertNull(files.read("page.v1.${ACCOUNT.removePrefix("0x")}.default.rec"))
    }

    @Test
    fun theImportSetsAndClearsTheFlagsAsTheTableSays() {
        val files = NativeTestFiles()
        val flags = DeviceFlagFiles(files)
        assertFalse(flags.accountPointer())
        applyImportMarker(flags, ShellImportCode.LEGACY_UNREADABLE)
        assertTrue(flags.legacyUnreadable())
        applyImportMarker(flags, ShellImportCode.IMPORT_FAILED)
        assertTrue("a failed import keeps the marker", flags.legacyUnreadable())
        applyImportMarker(flags, ShellImportCode.IMPORT_OK)
        assertTrue(flags.accountPointer())
        assertFalse("a successful import clears the marker", flags.legacyUnreadable())
        applyImportMarker(flags, ShellImportCode.LEGACY_UNREADABLE)
        assertFalse("an unreadable legacy store does not set the marker once the pointer exists", flags.legacyUnreadable())
    }

    @Test
    fun aFirstSuccessfulNativeWriteSetsTheAccountPointer() {
        val files = NativeTestFiles()
        val flags = DeviceFlagFiles(files)
        val resp = bridge(ImportOutcome.ABSENT, store(files), flags).handle(
            ShellOrigin.EMBEDDED_PAGE,
            JSONObject().put("type", "shellRecordWrite").put("reqId", "ptr2").put("record", walletRecord(0)),
            200,
        )
        assertEquals("ok", resp.getJSONObject("result").getString("code"))
        assertTrue(flags.accountPointer())
    }

    // ---- canonical JSON (§25.52M.4, CJ-01, CJ-02) ----

    @Test
    fun theCanonicalJsonMatchesTheVectors() {
        val vectors = JSONObject(File(System.getenv("PGP_MIGRATION_VECTORS") ?: "../spec/pgp-migration-vectors.v1.json").readText(Charsets.UTF_8))
        val cases = vectors.getJSONArray("canonicalCases")
        assertEquals(2, cases.length())
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            assertEquals(c.getString("id"), c.getString("expect"), CanonicalJson.encode(JSONObject(c.getJSONObject("input").toString())))
        }
    }
}
