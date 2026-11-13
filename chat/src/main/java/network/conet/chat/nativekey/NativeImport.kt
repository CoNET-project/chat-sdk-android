package network.conet.chat.nativekey

import network.conet.chat.ConetChatCryptoUtil
import java.math.BigInteger

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
 * The host shows the native import page when the PWA sends `nativeImportOpen`. The page belongs to the
 * app shell. Until the shell sets [launcher], the command is answered `not_available`.
 */
object NativeImportHost {
    @Volatile
    var launcher: (() -> Boolean)? = null

    /** `true` when the page was opened. */
    fun open(): Boolean = launcher?.invoke() == true
}

/**
 * Import typed in the native page: a secp256k1 private key (spec 25.25.2) or a BIP-39 phrase (spec 25.26.3).
 * Both end in the same vault write, readback and rollback (25.25.3).
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
        CANCELLED("cancelled"),
    }

    class Result(val code: Code, val eoa: String? = null)

    private val N: BigInteger = org.bouncycastle.asn1.sec.SECNamedCurves.getByName("secp256k1").n
    private val ASCII_WHITESPACE = charArrayOf(' ', '\t', '\n', '\r', '\u000B', '\u000C')

    /**
     * @param raw the text in the input box. Leading and trailing ASCII whitespace is removed; the rest must be
     *   64 hex digits, with an optional `0x` or `0X` prefix.
     * @param expectedEoa the account the import was started for, when there is one. A derived address that
     *   differs is refused.
     * @param cancelled the user backed out: nothing is written and no message is shown.
     */
    fun submit(raw: String, expectedEoa: String?, vault: NativeWalletVault, cancelled: Boolean = false): Result {
        if (cancelled) return Result(Code.CANCELLED)
        val trimmed = raw.trim { it in ASCII_WHITESPACE }
        val hex = if (trimmed.startsWith("0x") || trimmed.startsWith("0X")) trimmed.substring(2) else trimmed
        if (hex.length != 64 || !hex.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) {
            return Result(Code.INVALID_FORMAT)
        }
        val key = ByteArray(32) { i -> hex.substring(i * 2, i * 2 + 2).toInt(16).toByte() }
        try {
            val k = BigInteger(1, key)
            if (k.signum() <= 0 || k >= N) return Result(Code.INVALID_KEY)
            val eoa = WalletAddress.fromPrivateKey(key) ?: return Result(Code.INVALID_KEY)
            return importDerived(eoa, key, expectedEoa, vault)
        } finally {
            key.fill(0)
        }
    }

    /**
     * Mnemonic mode (spec 25.26.3). The phrase is checked and derived in memory (25.26.1). Only the derived 32-byte
     * key reaches the vault; the phrase is not stored, logged or returned. An invalid phrase is `invalid_mnemonic`
     * and writes nothing. After validation, the expected-address, write and readback rules are the key mode's.
     */
    fun submitMnemonic(raw: String, expectedEoa: String?, vault: NativeWalletVault, cancelled: Boolean = false): Result {
        if (cancelled) return Result(Code.CANCELLED)
        val key = MnemonicDerivation.deriveKey(raw) ?: return Result(Code.INVALID_MNEMONIC)
        try {
            val eoa = WalletAddress.fromPrivateKey(key) ?: return Result(Code.INVALID_KEY)
            return importDerived(eoa, key, expectedEoa, vault)
        } finally {
            key.fill(0)
        }
    }

    private fun importDerived(eoa: String, key: ByteArray, expectedEoa: String?, vault: NativeWalletVault): Result {
        if (expectedEoa != null && !expectedEoa.equals(eoa, ignoreCase = true)) {
            return Result(Code.ADDRESS_MISMATCH)
        }
        return when (vault.importKey(eoa, key)) {
            NativeWalletVault.Import.OK -> Result(Code.OK, eoa)
            NativeWalletVault.Import.ALREADY_PRESENT, NativeWalletVault.Import.RECORD_EXISTS ->
                Result(Code.ALREADY_EXISTS)
            NativeWalletVault.Import.ADDRESS_MISMATCH -> Result(Code.ADDRESS_MISMATCH)
            NativeWalletVault.Import.STORE_FAILED -> Result(Code.WRITE_FAILED)
            NativeWalletVault.Import.READBACK_FAILED -> Result(Code.READBACK_FAILED)
            NativeWalletVault.Import.BAD_KEY, NativeWalletVault.Import.BAD_EOA -> Result(Code.INVALID_KEY)
        }
    }
}
