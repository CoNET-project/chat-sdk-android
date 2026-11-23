package network.conet.chat.nativekey

import org.json.JSONObject

/**
 * The account the two-state store names, as the status commands report it (store-primary rule, 2026-11-22: the store is the source of the
 * account after a page sync, and the vault is no longer written). `walletStatus`, `passcodeStatus` and `walletEoaAddress` ask it first; only
 * when the store holds nothing ([View.None]) does the vault answer as before.
 *
 *  - a plain set: the account exists and needs no passcode;
 *  - a v3 set: the account exists and needs the passcode until this session is unlocked for its EOA (`passcode_not_provided`);
 *  - a store that cannot be read: unknown, `not_ready` (never `no_key`: no account is not what was read).
 *
 * Pure: the store's current set and the session's ready EOA come in as arguments; nothing is read or written here.
 */
internal object StoreAccountView {

    sealed class View {
        /** The store holds no set (confirmed absent, or cleared): the vault decides. */
        object None : View()
        class Plain(val eoa: String) : View()
        class V3(val eoa: String, val unlocked: Boolean) : View()
        object Unknown : View()
    }

    fun of(current: MnemonicSetStore.Current, readyEoa: String?): View = when (current) {
        MnemonicSetStore.Current.Absent -> View.None
        is MnemonicSetStore.Current.Unknown -> View.Unknown
        is MnemonicSetStore.Current.Found -> when (current.kind) {
            MnemonicSetStore.Kind.PLAIN -> View.Plain(current.eoa.lowercase())
            MnemonicSetStore.Kind.V3 -> View.V3(current.eoa.lowercase(), readyEoa != null && readyEoa.equals(current.eoa, ignoreCase = true))
        }
    }

    /** True when the session is ready for the account the view names (a plain set needs no passcode; a v3 set needs the unlock). */
    private fun ready(view: View, readyEoa: String?): Boolean = when (view) {
        is View.Plain -> readyEoa != null && readyEoa.equals(view.eoa, ignoreCase = true)
        is View.V3 -> view.unlocked
        else -> false
    }

    /**
     * `walletStatus`, or null when the vault decides. Ready for the account: `unlocked` with its `accountKey`. A plain set not yet initialised:
     * `not_ready` with `g1_uninitialized` (the page reads it as has). A v3 set not unlocked: `not_ready` with `passcode_not_provided`. Unknown:
     * `not_ready` with `unreadable`.
     */
    fun walletStatus(view: View, readyEoa: String?): JSONObject? = when (view) {
        View.None -> null
        View.Unknown -> NoKeyGate.walletStatusUnreadable()
        is View.Plain, is View.V3 -> {
            val eoa = if (view is View.Plain) view.eoa else (view as View.V3).eoa
            if (ready(view, readyEoa)) {
                JSONObject().put("status", "unlocked").put("accountKey", NoKeyGate.accountKeyOf(eoa))
            } else {
                val reason = if (view is View.V3) NoKeyGate.NOT_READY_PASSCODE_REQUIRED else NoKeyGate.NOT_READY_G1_UNINITIALIZED
                JSONObject().put("status", NoKeyGate.NOT_READY).put("notReadyReason", reason)
            }
        }
    }

    /**
     * `passcodeStatus` (set, locked, hasKey, nativeLocked), or null when the vault decides. The shape is the one the G1 and G2 answers have
     * (`set` and `locked` false: the SDK keeps no UI reading), `hasKey` true for a plain or v3 set, and `nativeLocked` a boolean: false only while
     * the session is ready for the account. Unknown is the unknown answer (`hasKey` true, `walletState` `not_ready`) and locked.
     */
    fun passcodeStatus(view: View, readyEoa: String?): JSONObject? = when (view) {
        View.None -> null
        View.Unknown -> NoKeyGate.passcodeStatusUnknown().put("nativeLocked", true)
        is View.Plain, is View.V3 ->
            JSONObject().put("set", false).put("locked", false).put("hasKey", true).put("nativeLocked", !ready(view, readyEoa))
    }

    /**
     * `walletEoaAddress` (the address only), or null when the vault decides. A plain set: the address its phrase derives, checked against the
     * set's EOA (a phrase that does not derive it is `unavailable`). A v3 set: the address only while the session holds the key of that account;
     * otherwise `not_ready` (the envelope's address is not verified without the passcode). Unknown: `not_ready`.
     */
    fun eoaAddress(current: MnemonicSetStore.Current, readyEoa: String?): WalletCredential.Answer? {
        return when (val view = of(current, readyEoa)) {
            View.None -> null
            View.Unknown -> WalletCredential.Answer.Refused(NoKeyGate.NOT_READY)
            is View.Plain -> {
                val key = StoreKeyAdapter.plainKey(current) ?: return WalletCredential.Answer.Refused(WalletCredential.UNAVAILABLE)
                try {
                    val derived = WalletAddress.fromPrivateKey(key)?.lowercase()
                    if (derived == null || derived != view.eoa) WalletCredential.Answer.Refused(WalletCredential.UNAVAILABLE)
                    else WalletCredential.Answer.Ok(JSONObject().put("eoa", view.eoa))
                } finally {
                    key.fill(0)
                }
            }
            is View.V3 -> {
                if (!view.unlocked) return WalletCredential.Answer.Refused(NoKeyGate.NOT_READY)
                val key = StoreKeyAdapter.sessionKey(current) ?: return WalletCredential.Answer.Refused(NoKeyGate.NOT_READY)
                try {
                    val derived = WalletAddress.fromPrivateKey(key)?.lowercase()
                    if (derived == null || derived != view.eoa) WalletCredential.Answer.Refused(WalletCredential.UNAVAILABLE)
                    else WalletCredential.Answer.Ok(JSONObject().put("eoa", view.eoa))
                } finally {
                    key.fill(0)
                }
            }
        }
    }
}
