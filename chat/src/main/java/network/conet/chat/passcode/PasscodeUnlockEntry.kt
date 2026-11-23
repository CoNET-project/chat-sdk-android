package network.conet.chat.passcode

import org.json.JSONObject

/**
 * The entry of `passcodeUnlock` (addenda 10 to 14). This is the skeleton: it admits or refuses a request, and passes an admitted request on.
 * The unlock itself belongs to the passcode batch. Order of checks:
 *  1. field allowlist: only `eoa`, `passcode` and the optional `callId` are allowed; anything else is `bad_request` (house rule, as NativeOpenRules);
 *  2. format: `eoa` is a canonical address, `callId` (when present) is a short opaque token, `passcode` is a non-empty string, `eoa` and `passcode` are required;
 *  3. call check (before any passcode check): see [IncomingCallRegistry.check];
 *  4. the passcode is passed on, untouched, for verification.
 *
 * A callId that is malformed, has no registration, or does not match: before the table takes effect ([CALL_TABLE_IN_EFFECT] false) it answers
 * `bad_request`; afterwards `call_mismatch`. Neither ends the call, consumes the callId, or leads to a passcode check.
 * `account_mismatch` is non-terminal too.
 */
internal object PasscodeUnlockEntry {
    /** The allowlist of `passcodeUnlock` fields. Must match the SDK allowedFields and the shell whitelist exactly. */
    val ALLOWED_FIELDS: Set<String> = setOf("eoa", "passcode", "callId")

    const val BAD_REQUEST = "bad_request"
    const val CALL_MISMATCH = "call_mismatch"
    const val ACCOUNT_MISMATCH = "account_mismatch"

    /**
     * True: the code table takes effect (notice v2). A callId that does not match the registered call, or has none, answers
     * `call_mismatch`, non-terminal. A malformed callId answers `bad_request`. Changing this is a revision, not a local edit.
     */
    const val CALL_TABLE_IN_EFFECT = true

    private val EOA_RE = Regex("^0x[0-9a-f]{40}$")
    private val CALL_ID_RE = Regex("^[A-Za-z0-9_-]{8,128}$")

    sealed class Admission {
        /** The request is not run. [endsCall] says whether the incoming call ends with it. */
        class Refused(val code: String, val endsCall: Boolean) : Admission()

        /**
         * The request is passed on. [pendingCallCancelled] is true when a call is registered but the request named none: the unlock runs and the call
         * ends as cancelled. [gen0] is the generation captured at bind, when the request named the registered call.
         */
        class Pass(
            val eoa: String,
            val passcode: String,
            val callId: String?,
            val pendingCallCancelled: Boolean,
            val gen0: Long?,
        ) : Admission()
    }

    /**
     * The answer to a callId that is malformed, unregistered or not the registered call (addenda 21, 22 §一, 23 §一; notice v2). Before the table
     * takes effect it is `bad_request`; afterwards `call_mismatch`. Neither ends the call, consumes the callId, or leads to a passcode check.
     */
    private fun callMismatchAnswer(callTableInEffect: Boolean): Admission.Refused =
        Admission.Refused(if (callTableInEffect) CALL_MISMATCH else BAD_REQUEST, endsCall = false)

    fun isEoa(value: String): Boolean = EOA_RE.matches(value.lowercase())

    fun isCallId(value: String): Boolean = CALL_ID_RE.matches(value)

    /**
     * Admits or refuses one `passcodeUnlock` request. [currentAccount] is the native session account. [callTableInEffect] defaults to
     * [CALL_TABLE_IN_EFFECT]; the parameter exists so both sides of the can be tested.
     */
    fun admit(
        fields: JSONObject,
        currentAccount: String,
        calls: IncomingCallRegistry,
        callTableInEffect: Boolean = CALL_TABLE_IN_EFFECT,
    ): Admission {
        if (fields.keys().asSequence().any { it !in ALLOWED_FIELDS }) return Admission.Refused(BAD_REQUEST, endsCall = false)
        val eoa = fields.opt("eoa") as? String ?: return Admission.Refused(BAD_REQUEST, endsCall = false)
        val passcode = fields.opt("passcode") as? String ?: return Admission.Refused(BAD_REQUEST, endsCall = false)
        if (!isEoa(eoa) || passcode.isEmpty()) return Admission.Refused(BAD_REQUEST, endsCall = false)
        val callId: String? = if (fields.has("callId")) {
            val raw = fields.opt("callId") as? String
            // A malformed callId is refused like any other callId that does not name the registered call: bad_request before the table takes
            // effect, call_mismatch afterwards (addenda 21 §二 and 23 §一; notice v2 §二.3).
            if (raw == null || !isCallId(raw)) return callMismatchAnswer(callTableInEffect)
            raw
        } else {
            null
        }
        return when (val check = calls.check(callId, eoa, currentAccount)) {
            is IncomingCallRegistry.CallCheck.CallMismatch -> callMismatchAnswer(callTableInEffect)
            is IncomingCallRegistry.CallCheck.AccountMismatch ->
                Admission.Refused(ACCOUNT_MISMATCH, endsCall = false)
            is IncomingCallRegistry.CallCheck.CancelsCall ->
                Admission.Pass(eoa, passcode, callId = null, pendingCallCancelled = true, gen0 = null)
            is IncomingCallRegistry.CallCheck.Proceed ->
                Admission.Pass(eoa, passcode, callId, pendingCallCancelled = false, gen0 = check.gen0)
            is IncomingCallRegistry.CallCheck.NoPendingCall ->
                Admission.Pass(eoa, passcode, callId = null, pendingCallCancelled = false, gen0 = null)
        }
    }
}
