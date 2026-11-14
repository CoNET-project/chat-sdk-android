package network.conet.chat.nativekey

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import java.util.concurrent.atomic.AtomicReference

/**
 * 25.52BB.3 (r3cz, PM R673): on the first import, a legacy private key is normalized before the write check. The stored form is "0x" plus 64
 * lower-case hex digits. A key that cannot be normalized is import_failed. After normalization, a key that derives another address is
 * address_mismatch. Nothing is stored unless the import succeeds. The page write path is unchanged (its non-canonical form is still bad_request).
 */
class ShellRecordFirstImportNormalizationTest {
    private val account = DerivedAccount.ADDRESS

    /** Runs the first import of a legacy page record whose profile for [account] carries [armor]. Returns the code, the outcome and the store. */
    private fun importWith(armor: String): Triple<ShellImportCode, ImportOutcome?, SealedPageRecordStore> {
        val legacy = JSONObject()
            .put("rev", 0)
            .put("mnemonicPhrase", "M")
            .put("profiles", JSONArray().put(JSONObject().put("keyID", account).put("privateKeyArmor", armor)))
        val store = SealedPageRecordStore(NativeTestWrap(), NativeTestFiles(), "$account:default")
        val outcome = AtomicReference<ImportOutcome?>(null)
        val flow = ShellImportFlow(
            storeFor = { store },
            addressOf = { armor -> ShellRecordPolicy.addressOfArmor(armor) },
            pgpStep = { _, _ -> },
            outcome = outcome,
        )
        val code = flow.run(account, LegacyWalletRecord.Found(legacy.toString().toByteArray(Charsets.UTF_8)), null)
        return Triple(code, outcome.get(), store)
    }

    @Test
    fun aKeyWithoutThe0xPrefixIsNormalizedAndImported() {
        val bare = DerivedAccount.KEY.removePrefix("0x")
        val (code, outcome, store) = importWith(bare)
        assertEquals(ShellImportCode.IMPORT_OK, code)
        assertEquals(ImportOutcome.DONE, outcome)
        // The stored key is the canonical form, not the legacy form.
        val stored = store.read() ?: error("the import stored the record")
        assertEquals(DerivedAccount.KEY, stored.optJSONArray("profiles")!!.getJSONObject(0).getString("privateKeyArmor"))
    }

    @Test
    fun anUpperCaseKeyWithAnUpperCasePrefixIsNormalizedToLowerCase() {
        val upper = "0X" + DerivedAccount.KEY.removePrefix("0x").uppercase()
        val (code, _, store) = importWith(upper)
        assertEquals(ShellImportCode.IMPORT_OK, code)
        val stored = store.read() ?: error("the import stored the record")
        assertEquals(DerivedAccount.KEY, stored.optJSONArray("profiles")!!.getJSONObject(0).getString("privateKeyArmor"))
    }

    @Test
    fun aValueThatIsNotSixtyFourHexDigitsIsImportFailedNotAddressMismatch() {
        val (code, outcome, store) = importWith("not-a-key")
        assertEquals(ShellImportCode.IMPORT_FAILED, code)
        assertEquals(ImportOutcome.NOT_DONE, outcome)
        assertNull("nothing is stored", store.read())
    }

    @Test
    fun aNormalizedKeyThatDerivesAnotherAddressIsAddressMismatchAndNothingIsStored() {
        val otherWithoutPrefix = DerivedAccount.KEY2.removePrefix("0x")
        val (code, outcome, store) = importWith(otherWithoutPrefix)
        assertEquals(ShellImportCode.ADDRESS_MISMATCH, code)
        assertEquals(ImportOutcome.NOT_DONE, outcome)
        assertNull("the legacy store is kept, nothing is stored", store.read())
    }

    @Test
    fun theNormalizerAcceptsOnlySixtyFourHexDigits() {
        val hex = "ab".repeat(32)
        assertEquals("0x" + hex, ShellRecordPolicy.normalizeLegacyKey(hex))
        assertEquals("0x" + hex, ShellRecordPolicy.normalizeLegacyKey("0x" + hex))
        assertEquals("0x" + hex, ShellRecordPolicy.normalizeLegacyKey("0X" + hex.uppercase()))
        assertNull(ShellRecordPolicy.normalizeLegacyKey("ab".repeat(31)))
        assertNull(ShellRecordPolicy.normalizeLegacyKey("ab".repeat(33)))
        assertNull(ShellRecordPolicy.normalizeLegacyKey("zz".repeat(32)))
    }
}
