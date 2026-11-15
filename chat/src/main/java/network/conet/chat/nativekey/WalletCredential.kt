package network.conet.chat.nativekey

import org.json.JSONObject

/**
 * The SDK side of the wallet answers (spec §25.52Y.38 第 3 项; §25.52Y.42 第 5 项, r3nu; PM R1866, R1870).
 *
 * `walletCredential`:
 *  - an account with a stored recovery phrase answers the phrase (kind: mnemonic; no key field);
 *  - a key-only account (a legacy device, or one whose page copy was cleared) answers `unavailable` (W-L5, PM R1895). No private key is
 *    returned on any path;
 *  - a phrase account whose phrase cannot be read answers `unavailable`, never the key.
 *
 * `walletEoaAddress` answers only the address, derived from the stored key, checked against the record (spec §25.52Y.42 第 5 项 (c)).
 *
 * Neither is registered on the bridge. The shell trust gate (§25.52Y.38 第 2 项) and the capability bit `wallet.credential.v1` come first.
 */
object WalletCredential {
    const val NO_KEY = "no_key"
    const val UNAVAILABLE = "unavailable"
    const val KIND_MNEMONIC = "mnemonic"

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
            // W-L5 (spec 25.52Y.42 第 8 项 (8e), PM R1895): a key-only account answers unavailable. No key is returned on any path.
            is NativeWalletVault.MnemonicRead.Missing -> Answer.Refused(UNAVAILABLE)
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
}

/**
 * The window-channel answer of `walletEoaAddress` (spec §25.52Y.42 第 5 项 (c), (d); r3ny 第 9 项; PM R1907). It is registered on the window
 * channel only, behind the same boundary as shellRecord: the source and the main frame are checked first, and a refused source is answered
 * origin_refused without the vault being read. The chat channel does not carry this name (its table is unchanged).
 */
internal object WalletEoaAddressBridge {
    const val NAME = "walletEoaAddress"

    /** The origin decision (spec r3ny 第 9 项 (a)): the allowed embedded origin, in the main frame. */
    fun originAllowed(sourceOrigin: String?, isMainFrame: Boolean): Boolean =
        isMainFrame && sourceOrigin == BeamioShellRecordImport.ALLOWED_ORIGIN

    fun answerFromPage(context: android.content.Context, sourceOrigin: String?, isMainFrame: Boolean, body: org.json.JSONObject): org.json.JSONObject =
        answer(originAllowed(sourceOrigin, isMainFrame), body) {
            val vault = NativeWallet.vault(context)
            vault to NoKeyGate.gateOf(vault.state(), NativeSessionState.isReady())
        }

    /** The pure core. [current] is called only for an allowed origin and a well-formed request. */
    internal fun answer(
        originAllowed: Boolean,
        body: org.json.JSONObject,
        current: () -> Pair<NativeWalletVault, NoKeyGate.Gate>,
    ): org.json.JSONObject {
        if (!originAllowed) return originRefused(body)
        val rawId = body.opt("reqId")
        val echo: Any = if (ShellRecordPolicy.reqIdValid(rawId)) rawId!! else org.json.JSONObject.NULL
        if (!ShellRecordPolicy.reqIdValid(rawId)) return fail(echo, "bad_request")
        if (body.optString("type", "") != NAME) return fail(echo, "unknown_command")
        if (ShellRecordPolicy.keysOf(body).any { it != "type" && it != "reqId" }) return fail(echo, "bad_request")
        val (vault, gate) = current()
        return when (val a = WalletCredential.eoaAddress(vault, gate)) {
            is WalletCredential.Answer.Ok ->
                org.json.JSONObject().put("type", "ack").put("reqId", echo).put("ok", true).put("result", a.result)
            is WalletCredential.Answer.Refused -> fail(echo, a.code)
        }
    }

    private fun fail(echo: Any, code: String): org.json.JSONObject =
        org.json.JSONObject().put("type", "ack").put("reqId", echo).put("ok", false).put("error", code)
}
