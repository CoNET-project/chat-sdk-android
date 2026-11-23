package network.conet.chat.nativekey

import network.conet.chat.ConetChatCryptoUtil
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import kotlin.math.ceil

/**
 * The result of one submission (§25.42.8). [eoa] is set only for `ok`; [cooldownSec] only for `backoff`. A result carries no
 * code, password, phrase, key or record.
 */
class RecoveryOutcome private constructor(val code: String, val eoa: String?, val cooldownSec: Int?) {
    companion object {
        internal fun ok(eoa: String) = RecoveryOutcome("ok", eoa, null)
        internal fun fail(code: String) = RecoveryOutcome(code, null, null)

        /** `already_exists` with the public EOA of the device's key (25.52X.4). [eoa] is null when it cannot be read: no EOA is carried. */
        internal fun existing(eoa: String?) = RecoveryOutcome("already_exists", eoa, null)
        internal fun backoff(seconds: Int) = RecoveryOutcome("backoff", null, seconds)
    }
}

/** The clock the backoff uses. Injected, so the vectors can advance it. */
internal fun interface RecoveryClock {
    fun nowMs(): Long
}

/** The device-local failure record of path B (§25.42.7). Survives a restart. Holds counts and times only. */
internal interface RecoveryFailureStore {
    fun failures(): Int
    fun lastFailureAtMs(): Long
    fun save(failures: Int, atMs: Long)
    fun clear()
}

/** The cooldown table of §25.42.7, the same as §25.17.6. */
internal object RecoveryBackoff {
    /** Seconds of cooldown after [failures] consecutive failures. None up to 4. */
    fun cooldownSeconds(failures: Int): Int = when {
        failures <= 4 -> 0
        failures == 5 -> 30
        failures == 6 -> 60
        failures == 7 -> 300
        failures == 8 -> 900
        else -> 3600
    }

    /** The seconds left in the cooldown at [nowMs], rounded up. Zero when there is none. */
    fun remainingSeconds(store: RecoveryFailureStore, nowMs: Long): Int {
        val failures = store.failures()
        val total = cooldownSeconds(failures)
        if (total == 0) return 0
        val elapsedMs = nowMs - store.lastFailureAtMs()
        val leftMs = total * 1000L - elapsedMs
        return if (leftMs <= 0L) 0 else ceil(leftMs / 1000.0).toInt()
    }
}

/** Reads the record of a registry (§25.42.5 steps 4, 4.1). Returns null when there is no record. Throws when unreachable. */
internal interface RecoveryRegistryReader {
    fun byNameHash(indexHash: ByteArray): String?
    fun byAccountName(name: String): String?
}

/** The production reader: the endpoints of [AccountRegistryRead], over HTTPS JSON-RPC. */
internal class EndpointRegistryReader(
    private val rpcFor: (RegistryEndpoint) -> AddressPgpRead.Rpc,
) : RecoveryRegistryReader {
    override fun byNameHash(indexHash: ByteArray): String? =
        AccountRegistryRead.readAgreed(AccountRegistryRead.current, rpcFor, AccountRegistryRead.callDataByNameHash(indexHash))

    override fun byAccountName(name: String): String? =
        AccountRegistryRead.readAgreed(AccountRegistryRead.current, rpcFor, AccountRegistryRead.callDataByAccountName(name))
}

/**
 * The recovery engine (§25.42.5), both paths. The steps run in the spec's order. The engine knows nothing of the page
 * or the bridge: the host passes the secret in and reads the outcome back. Secrets are passed as arrays and zeroed by
 * the caller; nothing here logs input or record content.
 */
internal class RecoveryEngine(
    private val vault: NativeWalletVault,
    private val registry: RecoveryRegistryReader,
    private val failures: RecoveryFailureStore,
    private val clock: RecoveryClock,
    /** The Argon2id step. Production uses [RecoveryRecord.argon2idKey]; a test replaces it to count the calls (§25.47.9). */
    private val kdf: (ByteArray, RecoveryRecord.Stored) -> ByteArray = { p, s -> RecoveryRecord.argon2idKey(p, s) },
) {
    /** Path A (§25.42.5, recovery code). Steps 1 to 12. */
    fun restoreWithCode(rawCode: ByteArray): RecoveryOutcome {
        // Step 1: the gate. A key on the device answers already_exists before anything is read.
        if (hasKey()) return RecoveryOutcome.existing(vault.publicEoaIfReadable())
        // Step 2: the shape of the code.
        val code = RecoveryCode.normalize(rawCode) ?: return RecoveryOutcome.fail("invalid_format")
        try {
            // Step 3: the registry key is keccak256 of the code's UTF-8 bytes (the solidityPacked string).
            val index = ConetChatCryptoUtil.keccak256(code)
            // Step 4: one read. Unreachable is network_error; no record is not_found.
            val record = try {
                registry.byNameHash(index)
            } catch (_: Exception) {
                return RecoveryOutcome.fail("network_error")
            } ?: return RecoveryOutcome.fail("not_found")
            // Steps 5 to 12. Path A: a failed decrypt is record_invalid, and path A never counts.
            return openAndStore(record, code, countsWrongPassword = false)
        } finally {
            code.fill(0)
        }
    }

    /** Path B (§25.42.5, account name and password). Steps 1 to 12. The password is a char array the caller clears. */
    fun restoreWithAccountPassword(rawName: String, password: CharArray): RecoveryOutcome {
        // Step 1: the gate.
        if (hasKey()) return RecoveryOutcome.existing(vault.publicEoaIfReadable())
        // Step 2: the name is trimmed; the password must be present.
        val name = rawName.trim { it == ' ' || it in '\t'..'\r' }
        if (name.isEmpty() || password.isEmpty()) return RecoveryOutcome.fail("invalid_format")
        // Cooldown (§25.42.7): no read and no decrypt while it lasts.
        val wait = RecoveryBackoff.remainingSeconds(failures, clock.nowMs())
        if (wait > 0) return RecoveryOutcome.backoff(wait)
        // Step 4: the current registry only. The pre-migration registry is deprecated (r3jz): path B does not query it, so
        // no legacy_record is produced and a name with no current record is not_found, whatever the old registry holds (B-06, B-12).
        val record = try {
            registry.byAccountName(name)
        } catch (_: Exception) {
            return RecoveryOutcome.fail("network_error")
        } ?: return RecoveryOutcome.fail("not_found")
        val pw = StandardCharsets.UTF_8.encode(java.nio.CharBuffer.wrap(password))
        val passwordBytes = ByteArray(pw.remaining())
        pw.get(passwordBytes)
        // The encoder's own buffer holds the password too: clear it as well as our copy.
        if (pw.hasArray()) pw.array().fill(0)
        try {
            return openAndStore(record, passwordBytes, countsWrongPassword = true)
        } finally {
            passwordBytes.fill(0)
        }
    }

    /** Steps 5 to 12, shared by both paths. [password] is the UTF-8 password (the code for path A). */
    private fun openAndStore(record: String, password: ByteArray, countsWrongPassword: Boolean): RecoveryOutcome {
        // Step 5: the record shape.
        val parsed = RecoveryRecord.parse(record) ?: return RecoveryOutcome.fail("record_invalid")
        // Step 6: the decrypt.
        val opened = RecoveryRecord.open(parsed.stored, parsed.imgBase64, password, kdf)
        val phrase = when (opened) {
            is RecoveryRecord.Opened.Ok -> opened.phrase
            is RecoveryRecord.Opened.Malformed -> return RecoveryOutcome.fail("record_invalid")
            is RecoveryRecord.Opened.WrongPassword -> {
                if (!countsWrongPassword) return RecoveryOutcome.fail("record_invalid")
                failures.save(failures.failures() + 1, clock.nowMs())
                return RecoveryOutcome.fail("bad_pin")
            }
        }
        try {
            // Step 7: the phrase is UTF-8 and a valid BIP-39 phrase (§25.26.1).
            val text = try {
                StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(phrase)).toString()
            } catch (_: Exception) {
                return RecoveryOutcome.fail("record_invalid")
            }
            // D1 (r2.3 41(3), review R2): the recovered object is the phrase. The phrase import derives the EOA at m/44'/60'/0'/0/0 and writes the
            // phrase with its key (importRecoveryPhrase, internal to the two recovery paths). A key-only write is not a recovery.
            // Step 9: check the native record again before the write.
            if (hasKey()) return RecoveryOutcome.existing(vault.publicEoaIfReadable())
            // Step 10: write, read back, roll back (importMnemonicKey, §25.25.3).
            val r = NativeImport.importRecoveryPhrase(text, null, vault)
            return when (r.code) {
                NativeImport.Code.OK -> {
                    failures.clear()
                    RecoveryOutcome.ok(checkNotNull(r.eoa))
                }
                NativeImport.Code.ALREADY_EXISTS -> RecoveryOutcome.existing(vault.publicEoaIfReadable())
                NativeImport.Code.WRITE_FAILED -> RecoveryOutcome.fail("write_failed")
                NativeImport.Code.READBACK_FAILED -> RecoveryOutcome.fail("readback_failed")
                NativeImport.Code.ROLLBACK_PENDING -> RecoveryOutcome.fail("rollback_pending")
                // An unconfirmed wrap is not_ready, unreadable: retryable, never a write failure (25.52Y.136 第 7 項).
                NativeImport.Code.NOT_READY -> RecoveryOutcome.fail("not_ready")
                NativeImport.Code.INVALID_MNEMONIC, NativeImport.Code.INVALID_KEY, NativeImport.Code.INVALID_FORMAT,
                NativeImport.Code.ADDRESS_MISMATCH, NativeImport.Code.CANCELLED,
                -> RecoveryOutcome.fail("record_invalid")
            }
        } finally {
            phrase.fill(0)
        }
    }

    /**
     * hasKey (25.52Y.136 第 11 項, §25.25.4 表 D): false only with no key record (G0), a confirmed wrap loss (25.52Y.122 第 1 項), or the residue
     * shape (25.52Y.127). A locked or unknown record that exists is a key.
     */
    private fun hasKey(): Boolean = hasKeyOf(vault.state())
}

/**
 * hasKey (25.52Y.136 第 11 項, §25.25.4 表 D, and the vector values of 25.52Y.137 第 5 項): false only with no key record (G0), a confirmed wrap loss
 * (25.52Y.122 第 1 項), or the residue shape (25.52Y.127). A locked or unknown record that exists is a key; a state whose record cannot be decided is
 * not asserted (the vector null).
 */
internal fun hasKeyOf(state: NativeWalletVault.State): Boolean = state !is NativeWalletVault.State.NoKey
