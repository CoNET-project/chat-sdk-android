package network.conet.chat.nativekey

import network.conet.chat.ConetChatCryptoUtil
import org.json.JSONObject

/**
 * Native wallet commands that answer from the vault, and the native import flow (spec 25.25).
 *
 * The import input is typed only in the native import page. The PWA never sends a key: it can only send
 * `nativeImportOpen`, which asks the host to show that page. Nothing here logs the input or the key.
 */
object NativeWalletCommands {
    /** Largest message `pgpSign` will take (decoded bytes). */
    const val PGP_SIGN_MAX_BYTES = 65_536

    /**
     * C4 `pgpSign` (spec 25.22.2): a document signature by the vault's PGP key. The page sends the purpose and the
     * message (base64), and gets back the armored signature only. The purpose must be in [registry]. Until the interface
     * owner lists the purposes, every call answers `purpose_not_registered`. Certification signatures are refused.
     * Errors: `bad_request` (message missing or not base64), `too_long`, `no_pgp_key`, `pgp_locked`,
     * `purpose_not_registered`, `sig_type_not_allowed`, `bad_passphrase`, `sign_failed`.
     */
    internal fun pgpSign(
        vault: NativePgpVault,
        purposeId: String,
        messageBase64: String?,
        sigType: Int,
        registry: Set<String> = NativePgpVault.REGISTERED_PURPOSES,
    ): NativeOutcome {
        // 25.52CI.1 (r3eh): the lock is judged before the parameters (the message, the signature type, the purpose).
        if (vault.locked()) return NativeOutcome("pgp_locked")
        val message = messageBase64?.let { runCatching { ConetChatCryptoUtil.base64Decode(it) }.getOrNull() }
            ?: return NativeOutcome("bad_request")
        if (message.size > PGP_SIGN_MAX_BYTES) return NativeOutcome("too_long")
        val out = vault.sign(purposeId, sigType, message, registry)
        return if (out.ok) NativeOutcome("ok", value = out.value) else NativeOutcome(out.code)
    }

    /** N0 `walletAddress`: no signature, only the account's EOA. `no_key` and `locked` carry no data. */
    fun walletAddress(vault: NativeWalletVault): NativeOutcome =
        when (val st = vault.state()) {
            is NativeWalletVault.State.NoKey -> NativeOutcome("no_key")
            is NativeWalletVault.State.Locked -> NativeOutcome("locked")
            is NativeWalletVault.State.Ready -> NativeOutcome("ok", address = st.eoa)
        }
}

/**
 * Result codes of the native import (spec 25.25.2, 25.26.3). The page that typed them is removed (r2.3 41); the codes stay for the
 * internal import and its page-result mapping.
 */
object NativeImport {
    enum class Code(val wire: String) {
        OK("ok"),
        INVALID_FORMAT("invalid_format"),
        INVALID_KEY("invalid_key"),
        INVALID_MNEMONIC("invalid_mnemonic"),
        ADDRESS_MISMATCH("address_mismatch"),
        ALREADY_EXISTS("already_exists"),
        WRITE_FAILED("write_failed"),
        READBACK_FAILED("readback_failed"),
        ROLLBACK_PENDING("rollback_pending"),
        CANCELLED("cancelled"),
        /** Not decided: the wrap is unconfirmed (25.52Y.136 第 7 項). Retryable; the answer carries notReadyReason unreadable. */
        NOT_READY("not_ready"),
    }

    /**
     * Recovery-path import (spec r2.3 41(3)): only the two recovery paths call this, after they decrypt. No page or bridge command reaches it.
     * Mnemonic mode (spec 25.26.3). The phrase is checked and derived in memory (25.26.1). Only the derived 32-byte
     * key reaches the vault; the phrase is not stored, logged or returned. An invalid phrase is `invalid_mnemonic`
     * and writes nothing. After validation, the expected-address, write and readback rules are the key mode's.
     */
    internal fun importRecoveryPhrase(raw: String, expectedEoa: String?, vault: NativeWalletVault): Result =
        submitPhrase(raw, expectedEoa, vault, cancelled = false)

    private fun submitPhrase(raw: String, expectedEoa: String?, vault: NativeWalletVault, cancelled: Boolean): Result {
        if (cancelled) return Result(Code.CANCELLED)
        val key = MnemonicDerivation.deriveKey(raw) ?: return Result(Code.INVALID_MNEMONIC)
        try {
            val eoa = WalletAddress.fromPrivateKey(key) ?: return Result(Code.INVALID_KEY)
            // spec §25.52Y.42: the phrase is stored, sealed, in the same write as the key (new imports only).
            val phrase = MnemonicDerivation.canonicalPhrase(raw) ?: return Result(Code.INVALID_MNEMONIC)
            return importDerived(eoa, key, expectedEoa, vault, phrase = phrase)
        } finally {
            key.fill(0)
        }
    }

    private fun importDerived(
        eoa: String,
        key: ByteArray,
        expectedEoa: String?,
        vault: NativeWalletVault,
        phrase: String? = null,
    ): Result {
        if (expectedEoa != null && !expectedEoa.equals(eoa, ignoreCase = true)) {
            return Result(Code.ADDRESS_MISMATCH)
        }
        val imported = if (phrase == null) vault.importKey(eoa, key) else vault.importMnemonicKey(eoa, key, phrase)
        return when (imported) {
            NativeWalletVault.Import.OK -> Result(Code.OK, eoa)
            NativeWalletVault.Import.OK_CLEANUP_PENDING -> Result(Code.OK, eoa, cleanupPending = true)
            NativeWalletVault.Import.ALREADY_PRESENT, NativeWalletVault.Import.RECORD_EXISTS ->
                Result(Code.ALREADY_EXISTS, vault.publicEoaIfReadable())
            NativeWalletVault.Import.ADDRESS_MISMATCH -> Result(Code.ADDRESS_MISMATCH)
            // wrap_key_missing (25.52Y.124): nothing was written; reported as a failed write until a wire code is defined.
            NativeWalletVault.Import.STORE_FAILED -> Result(Code.WRITE_FAILED)
            // Not decided: nothing was written; not_ready with notReadyReason unreadable (25.52Y.136 第 7 項).
            NativeWalletVault.Import.WRAP_KEY_MISSING -> Result(Code.NOT_READY)
            NativeWalletVault.Import.READBACK_FAILED -> Result(Code.READBACK_FAILED)
            // Only the sync path (requireOpenable) produces it: a failed write on this path.
            NativeWalletVault.Import.OLD_COPY_UNVERIFIED -> Result(Code.WRITE_FAILED)
            // v2 §三: the sync path only; a failed write (the old names are restored).
            NativeWalletVault.Import.SEALING_FAILED -> Result(Code.WRITE_FAILED)
            NativeWalletVault.Import.ROLLBACK_PENDING -> Result(Code.ROLLBACK_PENDING)
            NativeWalletVault.Import.BAD_KEY, NativeWalletVault.Import.BAD_EOA -> Result(Code.INVALID_KEY)
        }
    }

    class Result(val code: Code, val eoa: String? = null, val cleanupPending: Boolean = false)
}
