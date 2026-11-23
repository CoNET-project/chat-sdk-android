package network.conet.chat.nativekey

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * r2.5.11 57 (vectors RM-01..04; RM-05..07 belong to the PWA start-up reducer, not to this SDK).
 * RM-01: pointer set, no record, native key valid: shellRecordRead is error / account_record_missing (not migrating, not ok).
 * RM-02: pointer set, a record with the matching profile but no privateKeyArmor: needs_native_recovery.
 * RM-03: walletStatus with the pointer set and a readable key, no session: not_ready with g1_uninitialized.
 * RM-04: nativeState valid for PHRASE_ONLY: covered by po01 in R249VectorsTest (nativeStateLabel is "valid").
 */
class ShellRecordRM57Test {
    private val eoa = DerivedAccount.ADDRESS

    /** A device that has established an account: the pointer is set, nothing else. */
    private object PointerSetFlags : DeviceFlags {
        override fun accountPointer(): Boolean = true
        override fun setAccountPointer() = Unit
        override fun accountAddress(): String? = null
        override fun setAccountAddress(eoa: String) = Unit
        override fun legacyUnreadable(): Boolean = false
        override fun setLegacyUnreadable() = Unit
        override fun clearLegacyUnreadable() = Unit
    }

    private fun bridge(store: SealedPageRecordStore, nativeKey: Boolean) = ShellRecordBridge(
        account = { ShellRecordAccount.Ready(store, eoa, nativeKeyPresent = nativeKey, pointedKeyPresent = nativeKey) },
        migrating = { false },
        outcome = { ImportOutcome.ABSENT },
        flags = PointerSetFlags,
    )

    private fun read(store: SealedPageRecordStore, nativeKey: Boolean): JSONObject {
        val req = JSONObject().put("type", "shellRecordRead").put("reqId", "rm")
        return bridge(store, nativeKey).handle(ShellOrigin.EMBEDDED_PAGE, req, 500, nativeWrite = false)
    }

    private fun resultOf(resp: JSONObject): JSONObject = resp.optJSONObject("result") ?: resp

    /** RM-01 (57(1), §25.52U.6 第 1 行): the native key is valid, the record is missing, the pointer is set: account_record_missing. */
    @Test
    fun rm01PointerSetNoRecordWithAValidNativeKeyIsAccountRecordMissing() {
        val store = SealedPageRecordStore(NativeTestWrap(), NativeTestFiles(), "$eoa:default")
        val r = resultOf(read(store, nativeKey = true))
        assertEquals("error", r.getString("code"))
        assertEquals("account_record_missing", r.getString("sub"))
    }

    /** RM-02 (57(1), §25.52U.4): the record is present, the matching profile has no privateKeyArmor: needs_native_recovery. */
    @Test
    fun rm02AMatchingProfileWithoutPrivateKeyArmorNeedsNativeRecovery() {
        val store = SealedPageRecordStore(NativeTestWrap(), NativeTestFiles(), "$eoa:default")
        val profiles = JSONArray().put(JSONObject().put("keyID", eoa).put("address", eoa))
        val record = JSONObject().put("rev", 1).put("schemaVersion", 2).put("profiles", profiles)
        store.write(record)
        val r = resultOf(read(store, nativeKey = true))
        assertEquals("error", r.getString("code"))
        assertEquals("needs_native_recovery", r.getString("sub"))
        assertEquals("needs_native_recovery", ShellRecordPolicy.accountJudgement(record, eoa))
    }

    /** RM-03 (57(2), §25.52Y.161 第 1 项 (2)): walletStatus with a readable key and no session: not_ready with g1_uninitialized. */
    @Test
    fun rm03WalletStatusWithAPointerResidueIsNotReadyG1Uninitialized() {
        val status = NoKeyGate.walletStatusFor(NoKeyGate.Gate.G1, NativeWalletVault.State.Ready(eoa))
        assertEquals("not_ready", status.getString("status"))
        assertEquals("g1_uninitialized", status.getString("notReadyReason"))
    }

    /** The RM-01 reply names only the fixed code and sub; nothing in it is a key or a phrase. */
    @Test
    fun theRmReplyCarriesNoKeyMaterial() {
        val store = SealedPageRecordStore(NativeTestWrap(), NativeTestFiles(), "$eoa:default")
        val text = read(store, nativeKey = true).toString()
        assertTrue("no 64-hex value", !Regex("[0-9a-fA-F]{64}").containsMatchIn(text))
    }
}
