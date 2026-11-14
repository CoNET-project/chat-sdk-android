package network.conet.chat.nativekey

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * 25.52N.9 Q1 (the account's own profile: form and derived address, bad_request) and 25.52AG.2 (r3ch, r3cj: a profile of another account that carries
 * `privateKeyArmor`, null included, is a conflict with reason `w_account_unmatched`; native writes too). Synthetic keys from [DerivedAccount].
 */
class ShellRecordAccountMismatchTest {
    private val account = DerivedAccount.ADDRESS
    private val other = DerivedAccount.ADDRESS2

    private fun bridge(store: SealedPageRecordStore) = ShellRecordBridge(
        account = { ShellRecordAccount.Ready(store, account) },
        migrating = { false },
        // A confirmed absence of the legacy store: the first write goes ahead (25.52W.3). Nothing else is gated.
        outcome = { ImportOutcome.ABSENT },
    )

    private fun write(store: SealedPageRecordStore, profiles: JSONArray, nativeWrite: Boolean = false): JSONObject {
        val record = JSONObject().put("rev", 0).put("schemaVersion", 2).put("profiles", profiles)
        val req = JSONObject().put("type", "shellRecordWrite").put("reqId", "m1").put("record", record)
        return bridge(store).handle(ShellOrigin.EMBEDDED_PAGE, req, 500, nativeWrite = nativeWrite)
    }

    private fun resultOf(resp: JSONObject): JSONObject = resp.optJSONObject("result") ?: resp

    private fun names(resp: JSONObject): List<String> =
        resultOf(resp).optJSONArray("names")?.let { a -> (0 until a.length()).map { a.getString(it) } } ?: emptyList()

    private fun emptyStore() = SealedPageRecordStore(NativeTestWrap(), NativeTestFiles(), "$account:default")

    private fun profile(keyId: String, armor: Any?): JSONObject = JSONObject().put("keyID", keyId).also {
        if (armor != null) it.put("privateKeyArmor", armor)
    }

    @Test
    fun aProfileOfAnotherAccountWithAKeyIsAConflictAndNothingIsStored() {
        val store = emptyStore()
        val resp = write(store, JSONArray().put(profile(account, DerivedAccount.KEY)).put(profile(other, DerivedAccount.KEY2)))
        assertEquals("conflict", resultOf(resp).optString("code"))
        assertEquals("w_account_unmatched", resultOf(resp).optString("reason"))
        assertEquals(listOf("profiles[*].privateKeyArmor"), names(resp))
        assertNull("nothing is stored", store.read())
    }

    @Test
    fun aNullArmorOnAnotherAccountsProfileIsAlsoAConflict() {
        // 25.52AG.2 as the owner reads "carries" (r3ch): the key is present, so a null value still counts.
        val store = emptyStore()
        val resp = write(store, JSONArray().put(profile(account, DerivedAccount.KEY)).put(profile(other, JSONObject.NULL)))
        assertEquals("conflict", resultOf(resp).optString("code"))
        assertEquals("w_account_unmatched", resultOf(resp).optString("reason"))
        assertNull(store.read())
    }

    @Test
    fun aNativeWriteDoesNotExemptTheAccountMismatch() {
        val store = emptyStore()
        val resp = write(store, JSONArray().put(profile(account, DerivedAccount.KEY)).put(profile(other, DerivedAccount.KEY2)), nativeWrite = true)
        assertEquals("conflict", resultOf(resp).optString("code"))
        assertEquals("w_account_unmatched", resultOf(resp).optString("reason"))
        assertNull(store.read())
    }

    @Test
    fun aNonCanonicalKeyOnTheAccountsOwnProfileIsBadRequestNamingThePath() {
        val store = emptyStore()
        // Upper-case hex (not the canonical lower case). The fixture key is digits only, so its upper case would be the same: use letters.
        val upper = "0x" + "AB".repeat(32)
        val resp = write(store, JSONArray().put(profile(account, upper)))
        assertEquals("bad_request", resultOf(resp).optString("code"))
        assertEquals(listOf("profiles[*].privateKeyArmor"), names(resp))
        assertNull(store.read())
    }

    @Test
    fun aDerivationMismatchOnTheAccountsOwnProfileIsBadRequestNamingThePath() {
        val store = emptyStore()
        val resp = write(store, JSONArray().put(profile(account, DerivedAccount.KEY2)))
        assertEquals("bad_request", resultOf(resp).optString("code"))
        assertEquals(listOf("profiles[*].privateKeyArmor"), names(resp))
        assertNull(store.read())
    }

    @Test
    fun theAccountsOwnValidKeyIsAccepted() {
        val store = emptyStore()
        val resp = write(store, JSONArray().put(profile(account, DerivedAccount.KEY)))
        assertEquals("ok", resultOf(resp).optString("code"))
    }

    @Test
    fun aNativeReplacementThatDoesNotDeriveTheAccountIsBadRequestAndNothingIsStored() {
        // 25.52AO.2 (r3cm, R645 a): the derivation check covers native writes too. A native create or recovery whose key does not derive the account
        // is bad_request naming the path, and the store is unchanged.
        val store = emptyStore()
        val resp = write(store, JSONArray().put(profile(account, DerivedAccount.KEY2)), nativeWrite = true)
        assertEquals("bad_request", resultOf(resp).optString("code"))
        assertEquals(listOf("profiles[*].privateKeyArmor"), names(resp))
        assertNull(store.read())
    }

    @Test
    fun aNativeReplacementThatDerivesTheAccountIsAccepted() {
        val store = emptyStore()
        val resp = write(store, JSONArray().put(profile(account, DerivedAccount.KEY)), nativeWrite = true)
        assertEquals("ok", resultOf(resp).optString("code"))
    }
}
