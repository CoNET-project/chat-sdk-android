package network.conet.chat.nativekey

import network.conet.chat.ConetChatCryptoUtil
import org.json.JSONArray
import org.json.JSONObject
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets

/** The result of path A (spec 25.26.4e.2). [eoa] is set only for `ok`. The result carries no recovery code, phrase or key. */
class RecoveryOutcome private constructor(val code: String, val eoa: String?) {
    companion object {
        internal fun ok(eoa: String) = RecoveryOutcome("ok", eoa)
        internal fun fail(code: String) = RecoveryOutcome(code, null)
    }
}

/** Reads the record stored under an index (25.26.4e.3 step 3). Returns null when the registry has none. */
internal fun interface RecordSource {
    fun recordFor(indexHash: ByteArray): Result<String?>
}

/**
 * The account registry read (25.26.4e.3 step 3). Read-only: `eth_call` of `getBase64ByNameHash(bytes32)` on the registry.
 * The address and endpoint are configuration. Their owner confirmation is pending: 25.26.4e does not state them, and the
 * values here are the PWA's live ones (`CONET_ACCOUNT_REGISTRY`, `CONET_RPC_URL`).
 */
internal object AccountRegistryRead {
    class Config(val registry: String, val rpcUrl: String, val chainId: Long)

    /** Set by the shell before use if the owner changes the values. */
    @Volatile
    var config: Config = Config(
        registry = "0xfFDc8d2021A41F4638Cb3eCf58B5155383EE9f6d",
        rpcUrl = "https://publicrpc.conet.network",
        chainId = 224422L,
    )

    const val SIG = "getBase64ByNameHash(bytes32)"

    /** The base64 record for [indexHash] (32 bytes), or null when there is none. A failure is `Result.failure`. */
    fun getBase64ByNameHash(rpc: AddressPgpRead.Rpc, cfg: Config, indexHash: ByteArray): Result<String?> = runCatching {
        require(indexHash.size == 32)
        val data = AddressPgpRead.selector(SIG) + indexHash.joinToString("") { "%02x".format(it) }
        val call = JSONObject().put("to", cfg.registry).put("data", data)
        val hex = rpc.call("eth_call", JSONArray().put(call).put("latest")) as? String
            ?: error("no result")
        AddressPgpRead.decodeString(hex) ?: error("undecodable")
    }.fold(
        onSuccess = { Result.success(it.ifEmpty { null }) },
        onFailure = { Result.failure(IllegalStateException("network_error")) },
    )
}

/** Path A (spec 25.26.4e.3). Pure apart from the vault and the record source passed in. */
internal object RecoveryRestore {
    fun run(recoveryCode: ByteArray, vault: NativeWalletVault, source: RecordSource): RecoveryOutcome {
        // Step 2: format.
        if (!RecoveryCode.isValid(recoveryCode)) return RecoveryOutcome.fail("invalid_format")
        // Step 3: the record under keccak256 of the code's UTF-8 bytes (what createRecover registered).
        val index = ConetChatCryptoUtil.keccak256(recoveryCode)
        val lookup = source.recordFor(index)
        if (lookup.isFailure) return RecoveryOutcome.fail("network_error")
        val record = lookup.getOrNull() ?: return RecoveryOutcome.fail("not_found")
        val parsed = RecoveryRecord.parse(record) ?: return RecoveryOutcome.fail("record_invalid")
        // Step 4: decrypt with the code as the password (the recovery page uses an empty PIN, 25.26.4d fact 2).
        val phrase = RecoveryRecord.decryptMnemonic(parsed.stored, parsed.imgBase64, recoveryCode)
            ?: return RecoveryOutcome.fail("record_invalid")
        try {
            // Step 5: the phrase must be UTF-8 and a valid BIP-39 phrase.
            val text = try {
                StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(phrase)).toString()
            } catch (_: Exception) {
                return RecoveryOutcome.fail("record_invalid")
            }
            // Step 6: derive m/44'/60'/0'/0/0, then refuse to overwrite an existing native record.
            val key = MnemonicDerivation.deriveKey(text) ?: return RecoveryOutcome.fail("record_invalid")
            try {
                val eoa = WalletAddress.fromPrivateKey(key) ?: return RecoveryOutcome.fail("record_invalid")
                if (vault.state() !is NativeWalletVault.State.NoKey) return RecoveryOutcome.fail("already_exists")
                // Step 7: write and read back. importKey rolls back on failure.
                return when (vault.importKey(eoa, key)) {
                    NativeWalletVault.Import.OK -> RecoveryOutcome.ok(eoa)
                    NativeWalletVault.Import.ALREADY_PRESENT, NativeWalletVault.Import.RECORD_EXISTS ->
                        RecoveryOutcome.fail("already_exists")
                    NativeWalletVault.Import.STORE_FAILED -> RecoveryOutcome.fail("write_failed")
                    NativeWalletVault.Import.READBACK_FAILED -> RecoveryOutcome.fail("readback_failed")
                    NativeWalletVault.Import.ADDRESS_MISMATCH, NativeWalletVault.Import.BAD_KEY,
                    NativeWalletVault.Import.BAD_EOA -> RecoveryOutcome.fail("record_invalid")
                }
            } finally {
                key.fill(0)
            }
        } finally {
            phrase.fill(0)
        }
    }
}
