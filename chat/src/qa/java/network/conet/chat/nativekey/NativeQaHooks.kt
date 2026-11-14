package network.conet.chat.nativekey

import android.content.Context

/**
 * QA-only tool (spec r3bw §25.52AA.5, HK-01 to HK-03). It is compiled only into the QA build (`-PchatQaHooks`), never into the production
 * AAR, and it is reachable from no bridge: no page message, no `window.BeamioShellRecord`, no chat-module command. Only the native test
 * target calls it. Its one effect makes the state "the record has no EOA private key" (needs_native_recovery, AK-20) for the account.
 */
object NativeQaHooks {
    /** Removes `privateKeyArmor` from the profile of [eoa] and keeps the rest of the record, its revision, and the device flags. */
    fun dropEoaKeyOfAccount(context: Context, eoa: String) {
        val account = eoa.lowercase()
        val store = BeamioShellRecordImport.storeFor(context.applicationContext, account)
        dropEoaKey(store, account)
    }

    /** The record change of [dropEoaKeyOfAccount], on a store (no Context), so the behaviour test can run without Android. */
    internal fun dropEoaKey(store: SealedPageRecordStore, account: String) {
        val record = store.read() ?: return
        val profiles = record.optJSONArray("profiles") ?: return
        for (i in 0 until profiles.length()) {
            val profile = profiles.optJSONObject(i) ?: continue
            if (profile.optString("keyID", "").equals(account, ignoreCase = true)) profile.remove("privateKeyArmor")
        }
        store.write(record)
    }
}
