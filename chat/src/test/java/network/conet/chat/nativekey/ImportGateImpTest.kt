package network.conet.chat.nativekey

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import java.util.concurrent.atomic.AtomicReference

/**
 * v229 IMP-01/02: the legacy import path copies a record only for an account that holds a valid phrase.
 * A key-only legacy record is not parsed, not derived and not written; creation may continue (absent, append only). Driven through the production
 * [ShellImportFlow.run] with the production gate shape.
 */
class ImportGateImpTest {
    private val account = DerivedAccount.ADDRESS

    private class Run(val code: ShellImportCode, val outcome: ImportOutcome?, val store: SealedPageRecordStore, val derivations: Int)

    private fun runImport(validPhraseOf: (String) -> String?): Run {
        val legacy = JSONObject()
            .put("rev", 0)
            .put("mnemonicPhrase", "M")
            .put("profiles", JSONArray().put(JSONObject().put("keyID", account).put("privateKeyArmor", DerivedAccount.KEY)))
        val store = SealedPageRecordStore(NativeTestWrap(), NativeTestFiles(), "$account:default")
        val outcome = AtomicReference<ImportOutcome?>(null)
        var derivations = 0
        val flow = ShellImportFlow(
            storeFor = { store },
            addressOf = { armor -> derivations++; ShellRecordPolicy.addressOfArmor(armor) },
            pgpStep = { _, _ -> },
            outcome = outcome,
            validPhraseOf = validPhraseOf,
        )
        val code = flow.run(account, LegacyWalletRecord.Found(legacy.toString().toByteArray(Charsets.UTF_8)), null)
        return Run(code, outcome.get(), store, derivations)
    }

    /** IMP-01: the legacy record is key-only (no valid phrase for the account): not derived, not written; absent, so creation may continue. */
    @Test
    fun imp01LegacyKeyOnlyIsNotDerivedNotWrittenAndAllowsCreation() {
        val r = runImport(validPhraseOf = { null })
        assertEquals(ShellImportCode.ABSENT, r.code)
        assertEquals(ImportOutcome.ABSENT, r.outcome)
        assertEquals("the key is never derived", 0, r.derivations)
        assertNull("no page copy is written", r.store.read())
    }

    /** IMP-02: the legacy record belongs to an account with a valid phrase: copied as before. */
    @Test
    fun imp02LegacyWithAValidPhraseIsCopied() {
        val r = runImport(validPhraseOf = { account })
        assertEquals(ShellImportCode.IMPORT_OK, r.code)
        assertEquals(ImportOutcome.DONE, r.outcome)
        assertEquals(account, r.store.read()!!.getJSONArray("profiles").getJSONObject(0).getString("keyID"))
    }

    /** A valid phrase for another account does not authorise the legacy copy of this account. */
    @Test
    fun aPhraseForAnotherAccountDoesNotAuthoriseTheLegacyCopy() {
        val r = runImport(validPhraseOf = { "0x0000000000000000000000000000000000000001" })
        assertEquals(ShellImportCode.ABSENT, r.code)
        assertEquals("the key is never derived", 0, r.derivations)
        assertNull(r.store.read())
    }
}
