package network.conet.chat.nativekey

import org.json.JSONObject

/**
 * The SDK side of the wallet answers (spec §25.52Y.38 第 3 项; §25.52Y.42 第 5 项, r3nu; PM R1866, R1870).
 *
 * `walletCredential`:
 *  - an account with a stored recovery phrase answers the phrase (kind: mnemonic; no key field);
 *  - a key-only account (a legacy device, or one whose page copy was cleared) answers its EOA private key (`credentialKind = "eoa_key"`;
 *    no phrase field). The key is derived back to the record's address first; a mismatch or an unreadable record answers `unavailable`;
 *  - a phrase account whose phrase cannot be read answers `unavailable`, never the key.
 *
 * `walletEoaAddress` answers only the address, derived from the stored key, checked against the record (spec §25.52Y.42 第 5 项 (c)).
 * The two answers do not replace each other: the key appears only in the `walletCredential` `eoa_key` answer.
 *
 * Neither is registered on the bridge. The shell trust gate (§25.52Y.38 第 2 项) and the capability bit `wallet.credential.v1` come first.
 */
object WalletCredential {
    const val NO_KEY = "no_key"
    const val UNAVAILABLE = "unavailable"
    const val KIND_MNEMONIC = "mnemonic"
    const val KIND_EOA_KEY = "eoa_key"

    sealed class Answer {
        /** The `result` of an ok ack. */
        class Ok(val result: JSONObject) : Answer()

        /** An error code. The caller answers `ok: false` with this code and does not fall back to another source. */
        class Refused(val code: String) : Answer()
    }

    /** `walletCredential` for [gate]. G1 and G2 may ask (§25.52Y.42 第 5 项 (d)); G0 is `no_key`. Nothing is logged. */
    fun answer(vault: NativeWalletVault, gate: NoKeyGate.Gate): Answer {
        if (gate == NoKeyGate.Gate.G0) return Answer.Refused(NO_KEY)
        val state = vault.state()
        if (state !is NativeWalletVault.State.Ready) return Answer.Refused(UNAVAILABLE)
        return when (val read = vault.mnemonicOf()) {
            // mnemonicOf has already checked that the phrase derives the record's key and address (§25.52Y.38 第 3 项 (f)).
            is NativeWalletVault.MnemonicRead.Stored ->
                if (read.eoa != state.eoa) Answer.Refused(UNAVAILABLE)
                else Answer.Ok(
                    JSONObject().put("eoa", state.eoa).put("credentialKind", KIND_MNEMONIC)
                        .put("mnemonic", read.phrase),
                )
            is NativeWalletVault.MnemonicRead.Missing -> eoaKeyAnswer(vault, state.eoa)
            is NativeWalletVault.MnemonicRead.Unavailable -> Answer.Refused(UNAVAILABLE)
        }
    }

    /** `walletEoaAddress` for [gate]: the address only (G1 and G2, §25.52Y.42 第 5 項 (d)); G0 is `no_key`. */
    fun eoaAddress(vault: NativeWalletVault, gate: NoKeyGate.Gate): Answer {
        if (gate == NoKeyGate.Gate.G0) return Answer.Refused(NO_KEY)
        val state = vault.state()
        if (state !is NativeWalletVault.State.Ready) return Answer.Refused(UNAVAILABLE)
        val key = vault.unlock() ?: return Answer.Refused(UNAVAILABLE)
        try {
            if (WalletAddress.fromPrivateKey(key) != state.eoa) return Answer.Refused(UNAVAILABLE)
        } finally {
            key.fill(0)
        }
        return Answer.Ok(JSONObject().put("eoa", state.eoa))
    }

    /** The compatibility answer for a key-only account (spec §25.52Y.42 第 5 项 (b)). The key is returned only after it derives [eoa]. */
    private fun eoaKeyAnswer(vault: NativeWalletVault, eoa: String): Answer {
        val key = vault.unlock() ?: return Answer.Refused(UNAVAILABLE)
        try {
            if (WalletAddress.fromPrivateKey(key) != eoa) return Answer.Refused(UNAVAILABLE)
            val hex = "0x" + key.joinToString("") { "%02x".format(it) }
            return Answer.Ok(JSONObject().put("eoa", eoa).put("credentialKind", KIND_EOA_KEY).put("eoaPrivateKey", hex))
        } finally {
            key.fill(0)
        }
    }
}
