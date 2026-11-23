package network.conet.chat.passcode

/**
 * Wire codes of the frozen shell passcode protocol v1 (PROTOCOL-shell-passcode-v1-FROZEN-2026-11-20, sections 3–4).
 * Each value is the exact string on the wire; a new code must be added here and to the frozen table, never renamed.
 */
object PasscodeCodes {
    const val EOA_MISMATCH = "eoa_mismatch"
    const val ADDRESS_MISMATCH = "address_mismatch"
    const val WEAK_PASSCODE = "weak_passcode"
    const val ALREADY_SET = "already_set"
    const val OTHER_ACCOUNT_PRESENT = "other_account_present"
    const val NOT_SET = "not_set"
    const val WRONG_PASSCODE = "wrong_passcode"
    const val BACKOFF = "backoff"
    const val NO_RECORD = "no_record"
    const val RECORD_INVALID = "record_invalid"
    const val NOT_READY = "not_ready"
    const val WRITE_FAILED = "write_failed"
    const val READBACK_MISMATCH = "readback_mismatch"
    const val NO_REQUEST = "no_request"
    const val PASSCODE_REQUIRED = "passcode_not_provided"
    const val LOCKED = "locked"

    /** Reasons of `write_failed`. */
    const val REASON_READBACK_MISMATCH = "readback_mismatch"
    const val REASON_OTHER_ACCOUNT_PRESENT = "other_account_present"

    /** `notReadyReason` value for an encrypted mnemonic that waits for the UI to hand over the passcode (2026-11-20). */
    const val NOT_READY_REASON_PASSCODE_REQUIRED = "passcode_not_provided"
}
