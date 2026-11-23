package network.conet.chat.passcode

import network.conet.chat.nativekey.MnemonicDerivation
import network.conet.chat.nativekey.VaultFiles
import network.conet.chat.nativekey.WalletAddress

/**
 * The passcodeProvision and passcodeUnlock flows (frozen shell passcode protocol v1, §3.1 and §3.2), with the store and the vault files passed in, so
 * the rules are tested without Android. The bridge handlers read the context and the native state, then call these.
 *
 * Counting: none. The native side never counts a wrong passcode and never returns `backoff` (protocol §5.3). A wrong passcode does not change the
 * native session. Key material: the phrase bytes and derived keys are zeroed as soon as they are no longer needed.
 */
internal object PasscodeCommandFlow {
    const val BAD_REQUEST = "bad_request"
    const val EOA_MISMATCH = "eoa_mismatch"
    const val WEAK_PASSCODE = "weak_passcode"
    const val WRITE_FAILED = "write_failed"
    const val READBACK_MISMATCH = "readback_mismatch"
    const val NO_RECORD = "no_record"
    const val RECORD_INVALID = "record_invalid"
    const val WRONG_PASSCODE = "wrong_passcode"

    private val EOA_RE = Regex("^0x[0-9a-f]{40}$")

    sealed class Provision {
        /** The record is written, read back and opened: [verifiedAddress] is derived from the read-back record. */
        class Set(val eoa: String, val verifiedAddress: String) : Provision()
        class Fail(val code: String) : Provision()
    }

    sealed class Unlock {
        /** The record opened and its phrase derives to the requested account. The caller owns [phrase] and zeroes it. */
        class Unlocked(val eoa: String, val phrase: ByteArray) : Unlock()
        class Fail(val code: String) : Unlock()
    }

    /** The lower-case address a phrase derives to, or null. The derived key is zeroed before returning. */
    fun addressOf(phrase: String): String? {
        val key = MnemonicDerivation.deriveKey(phrase) ?: return null
        return try {
            WalletAddress.fromPrivateKey(key)?.lowercase()
        } finally {
            key.fill(0)
        }
    }

    /**
     * §3.1. [pointerEoa] is the native account pointer, null when none. [files] is the passcode directory, used to see whether another account
     * already has a record (never overwritten).
     */
    fun provision(
        phrase: String,
        passcode: String,
        eoa: String,
        store: PasscodeRecordStore,
        pointerEoa: String?,
        files: VaultFiles,
    ): Provision {
        val request = eoa.lowercase()
        if (!EOA_RE.matches(request) || phrase.isEmpty() || passcode.isEmpty()) return Provision.Fail(BAD_REQUEST)
        // The native side checks the derivation: the phrase must produce the requested account.
        val derived = addressOf(phrase) ?: return Provision.Fail(EOA_MISMATCH)
        if (derived != request) return Provision.Fail(EOA_MISMATCH)
        if (PasscodePolicy.reject(passcode) != null) return Provision.Fail(WEAK_PASSCODE)
        val hasOwn = store.read(request) !is PasscodeRecordStore.Read.Absent
        val hasOther = files.names().any { it != request && EOA_RE.matches(it) && !it.endsWith(".staging") }
        (PasscodeDecisions.provision(request, pointerEoa, hasOwn, hasOther) as? PasscodeDecisions.Provision.Refused)
            ?.let { return Provision.Fail(it.code) }
        val inner = phrase.toByteArray(Charsets.UTF_8)
        val write = try {
            store.writeVerified(request, passcode, inner)
        } finally {
            inner.fill(0)
        }
        when (write) {
            PasscodeRecordStore.Write.WRITE_FAILED -> return Provision.Fail(WRITE_FAILED)
            PasscodeRecordStore.Write.READBACK_MISMATCH -> return Provision.Fail(READBACK_MISMATCH)
            PasscodeRecordStore.Write.OK -> Unit
        }
        // The verified address comes from the stored record, read back and opened, not from the request.
        val back = store.unlock(request, passcode) ?: return Provision.Fail(READBACK_MISMATCH)
        val backPhrase = String(back, Charsets.UTF_8)
        back.fill(0)
        val verified = addressOf(backPhrase) ?: return Provision.Fail(READBACK_MISMATCH)
        if (verified != request) return Provision.Fail(READBACK_MISMATCH)
        return Provision.Set(request, verified)
    }

    /**
     * §3.2 (the passcode check only; the callId admission runs first, in PasscodeUnlockEntry). A missing record is no_record; an unreadable one is
     * record_invalid; a passcode that does not open it is wrong_passcode, never counted.
     */
    fun unlock(eoa: String, passcode: String, store: PasscodeRecordStore): Unlock {
        val request = eoa.lowercase()
        if (!EOA_RE.matches(request) || passcode.isEmpty()) return Unlock.Fail(BAD_REQUEST)
        when (store.read(request)) {
            is PasscodeRecordStore.Read.Absent -> return Unlock.Fail(NO_RECORD)
            is PasscodeRecordStore.Read.Invalid -> return Unlock.Fail(RECORD_INVALID)
            is PasscodeRecordStore.Read.Record -> Unit
        }
        val opened = store.unlock(request, passcode)
        val code = PasscodeDecisions.unlock(if (opened != null) PasscodeDecisions.Opened.OPENED else PasscodeDecisions.Opened.WRONG_PASSCODE)
        if (code != null) return Unlock.Fail(code)
        val phrase = opened ?: return Unlock.Fail(WRONG_PASSCODE)
        // The opened phrase must derive to the requested account; otherwise the record is invalid for it (fail closed).
        val derived = addressOf(String(phrase, Charsets.UTF_8))
        if (derived != request) {
            phrase.fill(0)
            return Unlock.Fail(RECORD_INVALID)
        }
        return Unlock.Unlocked(request, phrase)
    }
}
