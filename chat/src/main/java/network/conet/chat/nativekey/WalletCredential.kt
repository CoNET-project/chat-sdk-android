package network.conet.chat.nativekey

import network.conet.chat.BuildConfig
import org.json.JSONObject

/**
 * The SDK side of the wallet answers (spec §25.52Y.38 第 3 项; §25.52Y.42 第 5 项, r3nu).
 *
 * `walletCredential`:
 *  - an account with a stored recovery phrase answers the phrase (kind: mnemonic; no key field);
 *  - a key-only account (a legacy device, or one whose page copy was cleared) answers `unavailable` (W-L5). No private key is
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
            // W-L5 (spec 25.52Y.42 第 8 项 (8e)): a key-only account answers unavailable. No key is returned on any path.
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
 * The window-channel answer of `walletEoaAddress` (spec §25.52Y.42 第 5 项 (c), (d); r3ny 第 9 项). It is registered on the window
 * channel only, behind the same boundary as shellRecord: the source and the main frame are checked first, and a refused source is answered
 * origin_refused without the vault being read. The chat channel does not carry this name (its table is unchanged).
 */
internal object WalletEoaAddressBridge {
    const val NAME = "walletEoaAddress"

    /** The origin decision (spec r3ny 第 9 项 (a)): the allowed embedded origin, in the main frame. */
    fun originAllowed(sourceOrigin: String?, isMainFrame: Boolean): Boolean =
        isMainFrame && sourceOrigin == BeamioShellRecordImport.ALLOWED_ORIGIN

    /** The pure core. [current] is called only for an allowed origin and a well-formed request. */
    internal fun answer(
        originAllowed: Boolean,
        body: org.json.JSONObject,
        /** The account the two-state store names (store-primary rule): an answer, or null when the store holds none and the vault decides. */
        store: (() -> WalletCredential.Answer?)? = null,
        current: () -> Pair<NativeWalletVault, NoKeyGate.Gate>,
    ): org.json.JSONObject {
        if (!originAllowed) return originRefused(body)
        val rawId = body.opt("reqId")
        val echo: Any = if (ShellRecordPolicy.reqIdValid(rawId)) rawId!! else org.json.JSONObject.NULL
        if (!ShellRecordPolicy.reqIdValid(rawId)) return fail(echo, "bad_request")
        if (body.optString("type", "") != NAME) return fail(echo, "unknown_command")
        if (ShellRecordPolicy.keysOf(body).any { it != "type" && it != "reqId" }) return fail(echo, "bad_request")
        // The store first (store-primary rule, 2026-11-22). A store that cannot be answered is unknown: not_ready, never an exception.
        if (store != null) {
            val fromStore = try {
                store()
            } catch (_: Exception) {
                return fail(echo, "not_ready")
            }
            if (fromStore != null) {
                return when (fromStore) {
                    is WalletCredential.Answer.Ok -> org.json.JSONObject().put("type", "ack").put("reqId", echo).put("ok", true).put("result", fromStore.result)
                    is WalletCredential.Answer.Refused -> fail(echo, fromStore.code)
                }
            }
        }
        // An unreadable vault is unknown: not_ready, one ack for this reqId (25.52Y.84, Y.104 第 3 条), never an exception out of the bridge.
        val (vault, gate) = try {
            current()
        } catch (_: Exception) {
            return fail(echo, "not_ready")
        }
        val a = try {
            WalletCredential.eoaAddress(vault, gate)
        } catch (_: Exception) {
            return fail(echo, "not_ready")
        }
        return when (a) {
            is WalletCredential.Answer.Ok ->
                org.json.JSONObject().put("type", "ack").put("reqId", echo).put("ok", true).put("result", a.result)
            is WalletCredential.Answer.Refused -> fail(echo, a.code)
        }
    }

    private fun fail(echo: Any, code: String): org.json.JSONObject =
        org.json.JSONObject().put("type", "ack").put("reqId", echo).put("ok", false).put("error", code)
}

/**
 * The window-channel `walletCredential` (spec 25.52Y.38 第 2 项 (e), 第 3 项, 第 4 项, 第 6 项 (b); 25.52Y.44).
 *
 * Order: the request shape (reqId); the SDK's own declaration (the bit is declared only in a QA build) answers `not_trusted` before anything
 * is read; a key-named field is `key_over_bridge_refused` (names only); the shape of the request; then the gate, the state, and the answer.
 * The answer carries the recovery phrase and a hardware-wrapped `blob` for the shell's storage. Unseal (`mode: "unseal"` with `blob`) returns
 * the phrase again after checking the blob's AAD against the account. A key-only account answers `unavailable` (W-L5). PGP never leaves the SDK.
 */
internal object WalletCredentialBridge {
    const val NAME = "walletCredential"
    const val NOT_TRUSTED = "not_trusted"
    const val KEY_REFUSED = "key_over_bridge_refused"

    /** The SDK's own declaration (spec 25.52Y.38 第 2 项 (e)): true only in a QA build. */
    fun sdkDeclares(qaBuild: Boolean = BuildConfig.WALLET_CREDENTIAL_QA): Boolean = qaBuild

    /** A name that carries key material (spec 25.52O.2): the key-shaped names and the eoa private key. */
    fun isKeyMaterialName(name: String): Boolean = ShellRecordPolicy.isKeyShaped(name) || name == "eoaPrivateKey"

    /** The answer. [current] is called only after the declaration, the reqId and the shape are checked. */
    fun answer(declared: Boolean, body: JSONObject, current: () -> Pair<NativeWalletVault, NoKeyGate.Gate>): JSONObject {
        val rawId = body.opt("reqId")
        val echo: Any = if (ShellRecordPolicy.reqIdValid(rawId)) rawId!! else JSONObject.NULL
        if (!ShellRecordPolicy.reqIdValid(rawId)) return fail(echo, "bad_request")
        if (!declared) return fail(echo, NOT_TRUSTED)
        val names = ShellRecordPolicy.keysOf(body)
        if (names.any { isKeyMaterialName(it) }) return fail(echo, KEY_REFUSED)
        if (names.any { it !in setOf("type", "reqId", "mode", "blob") }) return fail(echo, "bad_request")
        val mode = body.opt("mode")
        val blob = body.opt("blob")
        if (mode != null && mode != "unseal") return fail(echo, "bad_request")
        if ((mode == "unseal") != (blob != null)) return fail(echo, "bad_request")
        if (blob != null && blob !is String) return fail(echo, "bad_request")
        // An unreadable vault or store is unknown: not_ready, one answer for this reqId (25.52Y.84), never an exception out of the bridge.
        return try {
            val (vault, gate) = current()
            if (gate == NoKeyGate.Gate.G0) return fail(echo, WalletCredential.NO_KEY)
            val state = vault.state()
            if (state !is NativeWalletVault.State.Ready) return fail(echo, WalletCredential.UNAVAILABLE)
            if (mode == "unseal") unseal(echo, vault, state.eoa, blob as String) else obtain(echo, vault, state.eoa)
        } catch (_: Exception) {
            fail(echo, "not_ready")
        }
    }

    private fun obtain(echo: Any, vault: NativeWalletVault, eoa: String): JSONObject {
        val read = vault.mnemonicOf()
        if (read !is NativeWalletVault.MnemonicRead.Stored || read.eoa != eoa) return fail(echo, WalletCredential.UNAVAILABLE)
        val blob = vault.sealBlob(eoa, read.phrase.toByteArray(Charsets.UTF_8)) ?: return fail(echo, WalletCredential.UNAVAILABLE)
        return ok(echo, JSONObject().put("eoa", eoa).put("credentialKind", WalletCredential.KIND_MNEMONIC)
            .put("mnemonic", read.phrase).put("blob", blob))
    }

    private fun unseal(echo: Any, vault: NativeWalletVault, eoa: String, blob: String): JSONObject {
        val phrase = vault.openBlob(eoa, blob) ?: return fail(echo, WalletCredential.UNAVAILABLE)
        val key = MnemonicDerivation.deriveKey(phrase) ?: return fail(echo, WalletCredential.UNAVAILABLE)
        val derived = try {
            WalletAddress.fromPrivateKey(key)
        } finally {
            key.fill(0)
        }
        if (derived != eoa) return fail(echo, WalletCredential.UNAVAILABLE)
        return ok(echo, JSONObject().put("eoa", eoa).put("credentialKind", WalletCredential.KIND_MNEMONIC).put("mnemonic", phrase))
    }

    private fun ok(echo: Any, result: JSONObject): JSONObject =
        JSONObject().put("type", "ack").put("reqId", echo).put("ok", true).put("result", result)

    private fun fail(echo: Any, code: String): JSONObject =
        JSONObject().put("type", "ack").put("reqId", echo).put("ok", false).put("error", code)
}
