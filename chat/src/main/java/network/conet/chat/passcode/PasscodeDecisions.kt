package network.conet.chat.passcode

/**
 * The decision rules of the passcode commands (frozen shell passcode protocol v1, sections 3.1–3.4). Pure: the caller reads the state and
 * passes the facts in; the answer code is returned. No counting happens here (protocol 3.2: the native side counts nothing).
 */
object PasscodeDecisions {
    /** Outcome of a provision check: [Proceed] means the write may start. */
    sealed class Provision {
        object Proceed : Provision()
        class Refused(val code: String) : Provision()
    }

    /**
     * Section 3.1. [pointerEoa] is the native account pointer (null when none); [hasOwnRecord] means a passcode record for this account
     * exists; [hasOtherRecord] means a passcode record for another account exists (never overwritten).
     */
    fun provision(requestEoa: String, pointerEoa: String?, hasOwnRecord: Boolean, hasOtherRecord: Boolean): Provision {
        if (!isCanonicalEoa(requestEoa)) return Provision.Refused("bad_request")
        if (pointerEoa != null && pointerEoa.lowercase() != requestEoa.lowercase()) return Provision.Refused(PasscodeCodes.EOA_MISMATCH)
        if (hasOwnRecord) return Provision.Refused(PasscodeCodes.ALREADY_SET)
        if (hasOtherRecord) return Provision.Refused(PasscodeCodes.OTHER_ACCOUNT_PRESENT)
        return Provision.Proceed
    }

    /** What the native store found when it tried to open the record for an unlock (section 3.2). */
    enum class Opened { OPENED, WRONG_PASSCODE, ABSENT, INVALID }

    /** Section 3.2: the answer code of an unlock. A wrong passcode is answered, never counted. Null means unlocked. */
    fun unlock(opened: Opened): String? = when (opened) {
        Opened.OPENED -> null
        Opened.WRONG_PASSCODE -> PasscodeCodes.WRONG_PASSCODE
        Opened.ABSENT -> PasscodeCodes.NO_RECORD
        Opened.INVALID -> PasscodeCodes.RECORD_INVALID
    }

    /**
     * Section 3.3: the cause of a `nativeRepairRequest`, or null when no request is sent. [uiUnlocked] is true when the page's UI unlock for the
     * same account has succeeded in this session (section 6).
     */
    fun repairCause(unlockCode: String?, uiUnlocked: Boolean, opened: Opened): String? {
        if (unlockCode == null) return null
        return when (opened) {
            Opened.ABSENT -> "no_record"
            Opened.INVALID -> "record_invalid"
            Opened.WRONG_PASSCODE -> if (uiUnlocked) "passcode_mismatch" else "unlock_failed"
            Opened.OPENED -> null
        }
    }

    /** Section 3.4: a repair provide is accepted only for an unexpired request for the same account (`requestReqId` must match). */
    fun repairProvide(requestMatches: Boolean, expired: Boolean, sameAccount: Boolean): String? = when {
        !requestMatches || expired || !sameAccount -> PasscodeCodes.NO_REQUEST
        else -> null
    }

    private fun isCanonicalEoa(eoa: String): Boolean = Regex("^0x[0-9a-fA-F]{40}$").matches(eoa)
}
