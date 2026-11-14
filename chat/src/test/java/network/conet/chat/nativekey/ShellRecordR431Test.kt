package network.conet.chat.nativekey

import network.conet.chat.nativekey.PgpMigrationKeys.ACCOUNT
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * The R431 items on the page-record bridge (spec r3bo): the ack envelope (§25.28.3), the absence of a fresh install and the device-level marker
 * of an unreadable legacy store (§25.52K.4), and the canonical JSON of the stored copy (§25.52M.4, CJ-01, CJ-02).
 */
class ShellRecordR431Test {
    private fun bridge(outcome: ImportOutcome?, store: SealedPageRecordStore? = null, marker: Boolean = false) = ShellRecordBridge(
        account = { if (store == null) ShellRecordAccount.Unknown else ShellRecordAccount.Ready(store, ACCOUNT) },
        migrating = { false },
        outcome = { outcome },
        legacyMarker = { marker },
    )

    private fun read(reqId: String, b: ShellRecordBridge): JSONObject =
        b.handle(ShellOrigin.EMBEDDED_PAGE, JSONObject().put("type", "shellRecordRead").put("reqId", reqId), 40)

    // ---- the ack envelope ----

    @Test
    fun aProcessedAnswerIsAnAckWithItsResultCode() {
        val store = SealedPageRecordStore(NativeTestWrap(), NativeTestFiles(), "$ACCOUNT:default")
        store.write(JSONObject().put("rev", 1).put("schemaVersion", 2).put("mnemonicPhrase", "M").put("profiles", JSONArray().put(JSONObject().put("keyID", ACCOUNT).put("privateKeyArmor", "EOA"))))
        val ok = read("ack1", bridge(ImportOutcome.DONE, store))
        assertEquals("ack", ok.getString("type"))
        assertEquals("ack1", ok.getString("reqId"))
        assertTrue(ok.getBoolean("ok"))
        assertEquals("ok", ok.getJSONObject("result").getString("code"))
        assertFalse("the code is inside result, not at the top", ok.has("code"))
    }

    @Test
    fun aConflictIsAProcessedAckWithCurrentRev() {
        val store = SealedPageRecordStore(NativeTestWrap(), NativeTestFiles(), "$ACCOUNT:default")
        store.write(JSONObject().put("rev", 3).put("schemaVersion", 2).put("mnemonicPhrase", "M").put("profiles", JSONArray().put(JSONObject().put("keyID", ACCOUNT).put("privateKeyArmor", "EOA"))))
        val resp = bridge(ImportOutcome.DONE, store).handle(
            ShellOrigin.EMBEDDED_PAGE,
            JSONObject().put("type", "shellRecordWrite").put("reqId", "ack2").put("record", JSONObject().put("rev", 2).put("schemaVersion", 2).put("profiles", JSONArray().put(JSONObject().put("keyID", ACCOUNT).put("privateKeyArmor", "EOA")))),
            200,
        )
        assertTrue(resp.getBoolean("ok"))
        assertEquals("conflict", resp.getJSONObject("result").getString("code"))
        assertEquals(3, resp.getJSONObject("result").getInt("currentRev"))
    }

    @Test
    fun aRefusalIsAnAckWithAnErrorAndNoResult() {
        val resp = bridge(ImportOutcome.ABSENT).handle(
            ShellOrigin.OTHER,
            JSONObject().put("type", "shellRecordRead").put("reqId", "ack3"),
            40,
        )
        assertEquals("ack", resp.getString("type"))
        assertFalse(resp.getBoolean("ok"))
        assertEquals("origin_refused", resp.getString("error"))
        assertFalse(resp.has("result"))
    }

    @Test
    fun anInvalidReqIdIsEchoedAsNull() {
        val resp = bridge(ImportOutcome.ABSENT).handle(ShellOrigin.EMBEDDED_PAGE, JSONObject().put("type", "shellRecordRead").put("reqId", ""), 40)
        assertFalse(resp.getBoolean("ok"))
        assertEquals("bad_request", resp.getString("error"))
        assertTrue(resp.isNull("reqId"))
    }

    @Test
    fun aMissingNeedsNativeRecoveryIsAnErrorAck() {
        val store = SealedPageRecordStore(NativeTestWrap(), NativeTestFiles(), "$ACCOUNT:default")
        store.write(JSONObject().put("rev", 1).put("schemaVersion", 2).put("profiles", JSONArray().put(JSONObject().put("keyID", ACCOUNT))))
        val resp = read("ack4", bridge(ImportOutcome.DONE, store))
        assertFalse(resp.getBoolean("ok"))
        assertEquals("needs_native_recovery", resp.getString("error"))
    }

    // ---- fresh install and the device marker (§25.52K.4) ----

    @Test
    fun aFreshInstallWithNoLegacyStoreAnswersAbsent() {
        // The shell reports the legacy store as absent (importFirstRun with Absent): no copy, no marker, the bridge answers absent.
        val resp = read("fresh1", bridge(ImportOutcome.ABSENT))
        assertEquals("absent", resp.v().getString("code"))
    }

    @Test
    fun aDeviceMarkerAnswersErrorNotAbsence() {
        // Once the legacy store was unreadable, read answers error even when the process outcome says absent.
        val resp = read("mark1", bridge(ImportOutcome.ABSENT, marker = true))
        assertFalse(resp.getBoolean("ok"))
        assertEquals("legacy_store_unreadable", resp.getString("error"))
        val write = bridge(ImportOutcome.ABSENT, marker = true).handle(
            ShellOrigin.EMBEDDED_PAGE,
            JSONObject().put("type", "shellRecordWrite").put("reqId", "mark2").put("record", JSONObject().put("rev", 0).put("schemaVersion", 2).put("profiles", JSONArray())),
            200,
        )
        assertEquals("legacy_store_unreadable", write.getString("error"))
    }

    @Test
    fun theMarkerIsSetByAnUnreadableImportAndClearedByASuccessfulOne() {
        val files = NativeTestFiles()
        val marker = LegacyUnreadableMarker(files)
        assertFalse(marker.present())
        applyImportMarker(marker, ShellImportCode.LEGACY_UNREADABLE)
        assertTrue(marker.present())
        applyImportMarker(marker, ShellImportCode.ABSENT)
        assertTrue("a confirmed absence does not clear it", marker.present())
        applyImportMarker(marker, ShellImportCode.IMPORT_FAILED)
        assertTrue(marker.present())
        applyImportMarker(marker, ShellImportCode.IMPORT_OK)
        assertFalse(marker.present())
        applyImportMarker(marker, ShellImportCode.LEGACY_UNREADABLE)
        applyImportMarker(marker, ShellImportCode.EXISTS)
        assertNull(files.read(LegacyUnreadableMarker.NAME))
    }

    // ---- canonical JSON (§25.52M.4, CJ-01, CJ-02) ----

    @Test
    fun theCanonicalJsonMatchesTheVectors() {
        val vectors = JSONObject(File(System.getenv("PGP_MIGRATION_VECTORS") ?: "../spec/pgp-migration-vectors.v1.json").readText(Charsets.UTF_8))
        val cases = vectors.getJSONArray("canonicalCases")
        assertEquals(2, cases.length())
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            val got = CanonicalJson.encode(JSONObject(c.getJSONObject("input").toString()))
            assertEquals(c.getString("id"), c.getString("expect"), got)
        }
    }
}
