package network.conet.chat.nativekey

import network.conet.chat.ConetChatCryptoUtil
import org.json.JSONObject
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
 * The host shows the native import page when the PWA sends `nativeImportOpen`. The page belongs to the
 * app shell. Until the shell sets [launcher], the command is answered `not_supported` (spec r3x, N-06).
 */
object NativeImportHost {
    @Volatile
    var launcher: (() -> Boolean)? = null

    /** Set by the module, so the results go out through the chat module event envelope (§25.52X.4). */
    @Volatile
    internal var events: ((JSONObject) -> Unit)? = null

    @Volatile
    private var pageReqId: Any? = null

    /**
     * `nativeImportOpen`: opens the shell's page for [reqId]. `true` when the page is open. A launcher that throws counts as refused.
     * The page's result follows as `nativeImportResult` for this reqId (see [finish]).
     */
    internal fun open(reqId: Any): Boolean {
        pageReqId = reqId
        val opened = try {
            launcher?.invoke() == true
        } catch (_: Exception) {
            false
        }
        if (!opened) pageReqId = null
        return opened
    }

    /**
     * One submission's result, for the open page (§25.52X.4). Every submission sends exactly one `nativeImportResult`. `eoa` is carried only
     * by `ok` and `already_exists`, and only when the address was derived and persisted (the vault gives it only then). `ok`,
     * `already_exists` and `cancelled` end the page; any other result keeps it open for a retry. Nothing is sent when no page is open.
     */
    internal fun finish(result: NativeImport.Result) {
        val id = pageReqId ?: return
        val payload = JSONObject()
            .put("type", "nativeImportResult")
            .put("reqId", id)
            .put("code", eventCode(result.code))
        if (result.code == NativeImport.Code.OK || result.code == NativeImport.Code.ALREADY_EXISTS) {
            result.eoa?.let { payload.put("eoa", it) }
        }
        events?.invoke(payload)
        if (result.code in TERMINAL) pageReqId = null
    }

    private val TERMINAL = setOf(NativeImport.Code.OK, NativeImport.Code.ALREADY_EXISTS, NativeImport.Code.CANCELLED)

    /**
     * The wire `code` of `nativeImportResult`, exactly the five codes of 25.52Y.95 第 2 条 (mapping: 25.52Y.97 第 2 条). The internal codes are
     * not on the wire. `invalid_format`, `invalid_key` and `invalid_mnemonic` (input not valid, nothing written) are `bad_request`;
     * `address_mismatch`, `write_failed`, `readback_failed` and `rollback_pending` are `import_failed`. `ok`, `already_exists` and `cancelled`
     * keep their names. A `rollback_pending` is never `ok` and never `already_exists`.
     */
    internal fun eventCode(code: NativeImport.Code): String = when (code) {
        NativeImport.Code.OK -> "ok"
        NativeImport.Code.ALREADY_EXISTS -> "already_exists"
        NativeImport.Code.CANCELLED -> "cancelled"
        NativeImport.Code.INVALID_FORMAT,
        NativeImport.Code.INVALID_KEY,
        NativeImport.Code.INVALID_MNEMONIC,
        -> "bad_request"
        NativeImport.Code.ADDRESS_MISMATCH,
        NativeImport.Code.WRITE_FAILED,
        NativeImport.Code.READBACK_FAILED,
        NativeImport.Code.ROLLBACK_PENDING,
        -> "import_failed"
    }

    /** The `reqId` of the open import page, if any. */
    internal fun currentReqId(): Any? = pageReqId
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
        ROLLBACK_PENDING("rollback_pending"),
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
    fun submit(raw: String, expectedEoa: String?, vault: NativeWalletVault, cancelled: Boolean = false): Result =
        submitInput(raw, expectedEoa, vault, cancelled).also { NativeImportHost.finish(it) }

    private fun submitInput(raw: String, expectedEoa: String?, vault: NativeWalletVault, cancelled: Boolean): Result {
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
    fun submitMnemonic(raw: String, expectedEoa: String?, vault: NativeWalletVault, cancelled: Boolean = false): Result =
        submitPhrase(raw, expectedEoa, vault, cancelled).also { NativeImportHost.finish(it) }

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
            NativeWalletVault.Import.ALREADY_PRESENT, NativeWalletVault.Import.RECORD_EXISTS ->
                Result(Code.ALREADY_EXISTS, vault.publicEoaIfReadable())
            NativeWalletVault.Import.ADDRESS_MISMATCH -> Result(Code.ADDRESS_MISMATCH)
            NativeWalletVault.Import.STORE_FAILED -> Result(Code.WRITE_FAILED)
            NativeWalletVault.Import.READBACK_FAILED -> Result(Code.READBACK_FAILED)
            NativeWalletVault.Import.ROLLBACK_PENDING -> Result(Code.ROLLBACK_PENDING)
            NativeWalletVault.Import.BAD_KEY, NativeWalletVault.Import.BAD_EOA -> Result(Code.INVALID_KEY)
        }
    }
}
