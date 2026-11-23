package network.conet.chat.nativekey

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.security.MessageDigest

/**
 * §25.52Y.151 (第 2、6 项), §25.52Y.153 and §25.52Y.154 (PNK-09 更正): vectors `spec/page-copy-nokey-vectors.v1.json` (pinned sha256
 * 4972aa8c…, PNK-01 to PNK-10), shared by Android, iOS and PWA. The SDK runs the cases that are SDK-side: PNK-06 to PNK-09 (shellRecordRead under
 * the native gate). PNK-01 to PNK-05 are the page's walletEoaAddress mapping (PWA side).
 */
class PageCopyNoKeyVectorsTest {
    private val path = "../spec/page-copy-nokey-vectors.v1.json"
    private val doc: JSONObject by lazy { JSONObject(File(path).readText(Charsets.UTF_8)) }
    private val account = DerivedAccount.ADDRESS

    private fun case(id: String): JSONObject {
        val arr = doc.getJSONArray("cases")
        for (i in 0 until arr.length()) if (arr.getJSONObject(i).getString("id") == id) return arr.getJSONObject(i)
        throw AssertionError("no vector $id")
    }

    @Test
    fun theVectorFileIsThePinnedCopyWithTenCases() {
        val sha = MessageDigest.getInstance("SHA-256").digest(File(path).readBytes()).joinToString("") { "%02x".format(it) }
        assertEquals("4972aa8c156d630c9e00c9b320eb65bb6c1c5f159c955df8cc284e1fee9d3d93", sha)
        val ids = (0 until doc.getJSONArray("cases").length()).map { doc.getJSONArray("cases").getJSONObject(it).getString("id") }
        assertEquals((1..10).map { "PNK-%02d".format(it) }, ids.sorted())
    }

    /** The page copy the case names: each W field is present as the vector gives it; `keyID` is the account; other names carry a plain value. */
    private fun copyOf(fields: JSONArray, schema2: Boolean = true): JSONObject {
        val rec = JSONObject().put("rev", 1)
        if (schema2) rec.put("schemaVersion", 2)
        val profile = JSONObject()
        for (i in 0 until fields.length()) {
            when (val f = fields.getString(i)) {
                "privateKeyArmor" -> profile.put("privateKeyArmor", DerivedAccount.KEY)
                "keyID" -> profile.put("keyID", account)
                "mnemonicPhrase", "recoveryWords" -> rec.put(f, "synthetic words for the vector")
                else -> rec.put(f, "value")
            }
        }
        if (profile.length() > 0) rec.put("profiles", JSONArray().put(profile))
        return rec
    }

    /** The vector's schemaVersion (§25.52Y.156 第 3 项): absent means the record is schema 2. */
    private fun schema2Of(c: JSONObject): Boolean = c.getJSONObject("input").optInt("schemaVersion", 2) == 2

    /** The raw ack of one shellRecordRead. */
    private fun readWith(fields: JSONArray, walletState: String, schema2: Boolean = true): JSONObject {
        val store = SealedPageRecordStore(NativeTestWrap(), NativeTestFiles(), "$account:default")
        store.write(copyOf(fields, schema2))
        val bridge = ShellRecordBridge(
            account = { if (walletState == "G1") ShellRecordAccount.NotReady else ShellRecordAccount.Ready(store, account) },
            migrating = { false },
            outcome = { ImportOutcome.ABSENT },
            nativeNoKey = { walletState == "G0" },
        )
        val req = JSONObject().put("type", "shellRecordRead").put("reqId", "p1")
        return bridge.handle(ShellOrigin.EMBEDDED_PAGE, req, 200)
    }

    /** The result code of an ack: `result.code` when ok, otherwise the envelope `error`. */
    private fun codeOf(ack: JSONObject): String =
        if (ack.optBoolean("ok", false)) ack.getJSONObject("result").getString("code") else ack.getString("error")

    private fun recordOf(ack: JSONObject): JSONObject? = ack.optJSONObject("result")?.optJSONObject("record")

    private fun pageProfileHasArmor(record: JSONObject?): Boolean =
        record?.optJSONArray("profiles")?.let { p -> (0 until p.length()).any { p.getJSONObject(it).has("privateKeyArmor") } } == true

    /** PNK-06: native G0, the copy holds the three W fields: they are redacted; the other fields are returned. */
    @Test fun pnk06G0RedactsTheThreeWalletFieldsAndKeepsTheRest() {
        val c = case("PNK-06")
        val fields = c.getJSONObject("input").getJSONArray("copyFields")
        val ack = readWith(fields, c.getJSONObject("input").getString("walletState"))
        assertEquals("ok", codeOf(ack))
        val rec = recordOf(ack)!!
        assertFalse("privateKeyArmor redacted", pageProfileHasArmor(rec))
        assertFalse("mnemonicPhrase redacted", rec.has("mnemonicPhrase"))
        assertFalse("recoveryWords redacted", rec.has("recoveryWords"))
        assertTrue("keyID kept", rec.getJSONArray("profiles").getJSONObject(0).has("keyID"))
        assertTrue("workspace kept", rec.has("workspace"))
    }

    /** PNK-07 (§25.52Y.156): native G0, schema 2 copy with no key: the answer is needs_native_recovery, no field returned. */
    @Test fun pnk07G0Schema2WithoutKeyAnswersNeedsRecovery() {
        val c = case("PNK-07")
        val exp = c.getJSONObject("expect")
        assertEquals("error", exp.getString("code"))
        assertEquals("needs_native_recovery", exp.getString("sub"))
        val fields = c.getJSONObject("input").getJSONArray("copyFields")
        val ack = readWith(fields, c.getJSONObject("input").getString("walletState"), schema2 = schema2Of(c))
        assertEquals("error", codeOf(ack))
        assertEquals("needs_native_recovery", ack.getJSONObject("result").getString("sub"))
        assertNull(recordOf(ack))
    }

    /** PNK-10 (§25.52Y.156 第 3 項): native G0, a non-schema-2 copy with only non-W fields: returned as stored. */
    @Test fun pnk10G0NonSchema2WithoutWalletFieldsReturnsTheCopy() {
        val c = case("PNK-10")
        val fields = c.getJSONObject("input").getJSONArray("copyFields")
        val ack = readWith(fields, c.getJSONObject("input").getString("walletState"), schema2 = schema2Of(c))
        assertEquals("ok", codeOf(ack))
        val rec = recordOf(ack)!!
        assertEquals("value", rec.getString("workspace"))
        assertEquals(account, rec.getJSONArray("profiles").getJSONObject(0).getString("keyID"))
    }

    /** PNK-08: native G2 (holds the key): the W fields are returned as Y.41 gives them. */
    @Test fun pnk08G2DoesNotRedact() {
        val c = case("PNK-08")
        val fields = c.getJSONObject("input").getJSONArray("copyFields")
        val ack = readWith(fields, c.getJSONObject("input").getString("walletState"))
        assertEquals("ok", codeOf(ack))
        val rec = recordOf(ack)!!
        assertTrue("privateKeyArmor returned", pageProfileHasArmor(rec))
        assertTrue("mnemonicPhrase returned", rec.has("mnemonicPhrase"))
    }

    /** PNK-09 (§25.52Y.154 更正): native G1: shellRecordRead answers not_ready with no field returned; no key material reaches the page. */
    @Test fun pnk09G1AnswersNotReadyWithoutFields() {
        val c = case("PNK-09")
        val exp = c.getJSONObject("expect")
        assertEquals("not_ready", exp.getString("code"))
        assertEquals(0, exp.getJSONArray("fieldsReturned").length())
        val fields = c.getJSONObject("input").getJSONArray("copyFields")
        val ack = readWith(fields, c.getJSONObject("input").getString("walletState"))
        assertEquals("not_ready", codeOf(ack))
        assertNull(recordOf(ack))
        assertFalse("no armor in the reply", ack.toString().contains(DerivedAccount.KEY.removePrefix("0x")))
    }

    /**
     * E9.11.33 r2-amend6 §5.2 (G-LR-1..G-LR-5), replacing the earlier one-file allow-list. The report is read only through
     * LegacyStoreReport.readReport (the one reader), by the three permitted users, and never by the state, walletStatus or walletEoaAddress paths.
     * Writes, the clear path and name-level enumeration are exempt. The read counter is in LegacyReportReaderTest.
     */
    private fun sources(): List<Pair<String, String>> {
        val root = File("src/main/java")
        return root.walkTopDown().filter { it.isFile && it.extension == "kt" }
            .map { it.relativeTo(root).path to it.readText() }.toList()
    }

    /** G-LR-1 and G-LR-3: no source reads the report file directly, except the one reader in IdentityClear.kt. */
    @Test fun gLr1And3NoDirectReadOfTheReportOutsideTheReader() {
        val direct = sources().filter { (_, text) ->
            Regex("""read\(\s*(ClearFlagFiles\.)?LEGACY_REPORT\s*\)""").containsMatchIn(text)
        }.map { it.first }
        assertEquals(listOf("network/conet/chat/nativekey/IdentityClear.kt"), direct)
    }

    /** G-LR-2: the reader is used by exactly the three permitted users (the shellRecordRead legacy answers, the pre-read, the create guard). */
    @Test fun gLr2TheReaderHasThreePermittedUsers() {
        val users = sources().filter { (_, text) -> text.contains("LegacyStoreReport.readReport") || text.contains("readReportIn") }
            .map { it.first }.toSet()
        assertEquals(
            setOf(
                "network/conet/chat/nativekey/IdentityClear.kt",
                "network/conet/chat/nativekey/ShellRecord.kt",
                "network/conet/chat/BeamioConetChatModule.kt",
                "network/conet/chat/nativekey/AccountCreateGuard.kt",
            ),
            users,
        )
    }

    /** G-LR-5: state(), walletStatus and walletEoaAddress have no access to the report (zero references in their sources). */
    @Test fun gLr5TheStateAndWalletPathsDoNotTouchTheReport() {
        val zeroAccess = setOf("network/conet/chat/nativekey/NativeWalletVault.kt", "network/conet/chat/nativekey/NoKeyGate.kt", "network/conet/chat/nativekey/WalletCredential.kt")
        val touched = sources().filter { it.first in zeroAccess }
            .filter { (_, text) -> text.contains("LegacyStoreReport") || text.contains("LEGACY_REPORT") || text.contains("legacy_report") }
            .map { it.first }
        assertEquals(emptyList<String>(), touched)
    }

    /** The report file name occurs only where the reader, the write, and the clear path name it (the name table of the clear path is exempt). */
    @Test fun theReportNameOnlyAppearsInTheReaderWriteAndClearPath() {
        val files = sources().filter { (_, text) -> text.contains("LEGACY_REPORT") || text.contains("legacy_report") }.map { it.first }.toSet()
        assertEquals(
            setOf("network/conet/chat/nativekey/IdentityClear.kt", "network/conet/chat/BeamioConetChatModule.kt"),
            files,
        )
    }
}
