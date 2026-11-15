package network.conet.chat.nativekey

import org.json.JSONObject

/**
 * The SDK side of the `walletCredential` answer (spec §25.52Y.38 第 3 项 (d), (e), (e'), (f); §25.52Y.42 第 5 项).
 *
 * The answer is the recovery phrase of an account that has one stored (kind: mnemonic). An account with no stored
 * phrase (a key-only import, or a device from before §25.52Y.42) answers `unavailable`: the key is never returned in its place
 * (§25.52Y.42 第 5 项). The legacy `eoa_key` answer (§25.52Y.38 第 3 项 (b)) is not built here; it waits for PM ruling Q1.
 *
 * This is not registered on the bridge. The shell trust gate (§25.52Y.38 第 2 项) and the capability bit `wallet.credential.v1` must be
 * in place first; until then the bridge answers `unknown_command` for this name, as before.
 */
object WalletCredential {
    const val NO_KEY = "no_key"
    const val UNAVAILABLE = "unavailable"
    const val KIND_MNEMONIC = "mnemonic"

    sealed class Answer {
        /** The `result` of an ok ack. It holds the account address, the kind, and the phrase in the output field (never a key). */
        class Ok(val result: JSONObject) : Answer()

        /** An error code. The caller answers `ok: false` with this code and does not fall back to another source. */
        class Refused(val code: String) : Answer()
    }

    /** Decides the answer for [gate]. G1 and G2 may ask (§25.52Y.38 第 3 项 (d)); G0 is `no_key`. The phrase is never logged. */
    fun answer(vault: NativeWalletVault, gate: NoKeyGate.Gate): Answer {
        if (gate == NoKeyGate.Gate.G0) return Answer.Refused(NO_KEY)
        val state = vault.state()
        if (state !is NativeWalletVault.State.Ready) return Answer.Refused(UNAVAILABLE)
        val read = vault.mnemonicOf()
        if (read !is NativeWalletVault.MnemonicRead.Stored) return Answer.Refused(UNAVAILABLE)
        // mnemonicOf has already checked that the phrase derives the record's key and address (§25.52Y.38 第 3 项 (f)).
        if (read.eoa != state.eoa) return Answer.Refused(UNAVAILABLE)
        val result = JSONObject()
            .put("eoa", state.eoa)
            .put("credentialKind", KIND_MNEMONIC)
            .put("mnemonic", read.phrase)
        return Answer.Ok(result)
    }
}
