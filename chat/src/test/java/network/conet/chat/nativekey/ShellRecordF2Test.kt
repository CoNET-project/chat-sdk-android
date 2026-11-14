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
 * A4 F2 conditions (R588, the review seat's addendum): the PGP header is checked in canonical form on the write, the read and the import, and
 * the W-class values are type-checked (25.52O.3, iOS f8cf2bc). A residual PGP header fails the read and the import closed. The key-form and
 * derived-address check (25.52N.9 Q1) is not in this file: it conflicts with the synthetic placeholder values of the vectors, and is open.
 */
class ShellRecordF2Test {
    /** A PGP private header in the forms a page or a legacy record could hold: case, spacing and punctuation vary. */
    private val pgpVariants = listOf(
        "-----BEGIN PGP PRIVATE KEY BLOCK-----",
        "-----begin pgp private key block-----",
        "x BEGIN  PGP\tPRIVATE KEY",
        "BEGIN-PGP-PRIVATE-KEY",
    )

    private fun bridge(store: SealedPageRecordStore) = ShellRecordBridge(
        account = { ShellRecordAccount.Ready(store, ACCOUNT) },
        migrating = { false },
        outcome = { ImportOutcome.DONE },
    )

    private fun writeReq(record: JSONObject): JSONObject = JSONObject()
        .put("type", "shellRecordWrite")
        .put("reqId", "w1")
        .put("record", record)

    private fun readReq(): JSONObject = JSONObject().put("type", "shellRecordRead").put("reqId", "r1")

    /** The `result` of an ack, or the ack itself when it is an envelope refusal. */
    private fun resultOf(resp: JSONObject): JSONObject = resp.optJSONObject("result") ?: resp

    private fun storeWithRecord(record: JSONObject): SealedPageRecordStore {
        val store = SealedPageRecordStore(NativeTestWrap(), NativeTestFiles(), "$ACCOUNT:default")
        store.write(record)
        return store
    }

    private fun schema2(vararg profileFields: Pair<String, Any>): JSONObject {
        val profile = JSONObject().put("keyID", ACCOUNT)
        for ((k, v) in profileFields) profile.put(k, v)
        return JSONObject().put("rev", 0).put("schemaVersion", 2).put("profiles", JSONArray().put(profile))
    }

    // ---- the canonical PGP header on the write (F2 condition 3) ----

    @Test
    fun theCanonicalPgpHeaderIsRefusedOnTheWriteWhateverItsCaseAndSpacing() {
        for (variant in pgpVariants) {
            val record = JSONObject().put("rev", 0).put("schemaVersion", 2).put("profiles", JSONArray().put(JSONObject().put("data", variant)))
            val refusal = ShellRecordPolicy.preWriteRefusal(record)
            assertEquals("refused: $variant", "pgp_private_in_payload", refusal?.first)
        }
    }

    @Test
    fun aPublicKeyBlockIsNotAPrivateHeader() {
        val record = JSONObject().put("data", "-----BEGIN PGP PUBLIC KEY BLOCK-----")
        assertFalse(ShellRecordPolicy.hasPgpHeader(record))
    }

    // ---- the read fails closed on a residual header (F2 condition 2) ----

    @Test
    fun aResidualPgpHeaderAtAnUnstrippedPathFailsTheReadAndIsNotReturned() {
        for (variant in pgpVariants) {
            val store = storeWithRecord(schema2("data" to variant).put("mnemonicPhrase", "M"))
            val resp = bridge(store).handle(ShellOrigin.EMBEDDED_PAGE, readReq(), 100)
            assertEquals("code for: $variant", "error", resultOf(resp).optString("code"))
            assertEquals("sub for: $variant", "record_unreadable", resultOf(resp).optString("sub"))
            assertFalse("the record is not in the reply: $variant", resp.toString().contains("BEGIN") || resp.toString().contains("begin"))
            assertFalse("no record field: $variant", resultOf(resp).has("record"))
        }
    }

    @Test
    fun aRecordWithoutAPgpHeaderIsReadAsBefore() {
        val store = storeWithRecord(schema2("emailAddr" to "a", "privateKeyArmor" to "0x" + "11".repeat(32)).put("mnemonicPhrase", "M"))
        val resp = bridge(store).handle(ShellOrigin.EMBEDDED_PAGE, readReq(), 100)
        assertEquals("ok", resultOf(resp).optString("code"))
        assertTrue(resultOf(resp).has("record"))
    }

    // ---- the import fails closed on a residual header (F2 condition 1) ----

    @Test
    fun aLegacyRecordWithAResidualPgpHeaderIsNotImportedAndLeavesTheStoreUntouched() {
        for (variant in pgpVariants) {
            val legacy = JSONObject()
                .put("rev", 0)
                .put("mnemonicPhrase", "M")
                .put("profiles", JSONArray().put(JSONObject().put("keyID", ACCOUNT).put("privateKeyArmor", "0x" + "11".repeat(32)).put("data", variant)))
            val store = SealedPageRecordStore(NativeTestWrap(), NativeTestFiles(), "$ACCOUNT:default")
            val outcome = AtomicReference<ImportOutcome?>(null)
            val flow = ShellImportFlow(
                storeFor = { store },
                addressOf = { null },
                pgpStep = { _, _ -> },
                outcome = outcome,
            )
            val code = flow.run(ACCOUNT, LegacyWalletRecord.Found(legacy.toString().toByteArray(Charsets.UTF_8)), null)
            assertEquals("refused: $variant", ShellImportCode.IMPORT_FAILED, code)
            assertEquals("outcome for: $variant", ImportOutcome.NOT_DONE, outcome.get())
            assertNull("the store is untouched: $variant", store.read())
        }
    }

    // ---- the W-class type check (25.52O.3, iOS f8cf2bc) ----

    private val wrapper: JSONObject = JSONObject()
        .put("ct", "c3ludGhldGlj")
        .put("eoa", ACCOUNT)
        .put("iv", "aXY=")
        .put("kdf", "scrypt")
        .put("mode", "aes-256-gcm")
        .put("salt", "c2FsdA==")
        .put("v", 1)

    @Test
    fun aWrapperObjectInMnemonicPhraseIsBadRequestNamingThePath() {
        val store = SealedPageRecordStore(NativeTestWrap(), NativeTestFiles(), "$ACCOUNT:default")
        val record = schema2("emailAddr" to "a").put("mnemonicPhrase", wrapper)
        val resp = bridge(store).handle(ShellOrigin.EMBEDDED_PAGE, writeReq(record), 500)
        assertEquals("bad_request", resultOf(resp).optString("code"))
        assertEquals(listOf("mnemonicPhrase"), resultOf(resp).optJSONArray("names")?.let { a -> (0 until a.length()).map { a.getString(it) } })
        assertNull("nothing is stored", store.read())
    }

    @Test
    fun aNonStringRecoveryWordsIsBadRequestNamingThePath() {
        val store = SealedPageRecordStore(NativeTestWrap(), NativeTestFiles(), "$ACCOUNT:default")
        val record = schema2("emailAddr" to "a").put("recoveryWords", JSONArray().put("w1"))
        val resp = bridge(store).handle(ShellOrigin.EMBEDDED_PAGE, writeReq(record), 500)
        assertEquals("bad_request", resultOf(resp).optString("code"))
        assertEquals("recoveryWords", resultOf(resp).optJSONArray("names")?.getString(0))
    }

    @Test
    fun aWrapperInAProfilePrivateKeyArmorIsBadRequestNamingThePath() {
        val record = schema2("emailAddr" to "a", "privateKeyArmor" to wrapper)
        assertEquals(listOf("profiles[*].privateKeyArmor"), ShellRecordPolicy.walletTypeRefusal(record))
    }

    @Test
    fun aStringOrANullInTheWalletValuesPassesTheTypeCheck() {
        val strings = schema2("emailAddr" to "a", "privateKeyArmor" to "0xabc").put("mnemonicPhrase", "M").put("recoveryWords", "R")
        assertTrue(ShellRecordPolicy.walletTypeRefusal(strings).isEmpty())
        val nulls = schema2("emailAddr" to "a").also { it.optJSONArray("profiles")!!.getJSONObject(0).put("privateKeyArmor", JSONObject.NULL) }
            .put("mnemonicPhrase", JSONObject.NULL)
        assertTrue("a null is the page's deletion, judged by the merge", ShellRecordPolicy.walletTypeRefusal(nulls).isEmpty())
    }

    // ---- the address parse accepts only hex digits ----

    @Test
    fun theAddressParseAcceptsOnlyHexDigits() {
        assertNull("a sign is not a digit", ShellRecordPolicy.addressOfArmor("0x-" + "1".repeat(63)))
        assertNull("a short key", ShellRecordPolicy.addressOfArmor("0x" + "1".repeat(63)))
        val address = ShellRecordPolicy.addressOfArmor("0x" + "11".repeat(32))
        assertTrue("a valid key derives an address", address != null && address.matches(Regex("0x[0-9a-f]{40}")))
    }
}
