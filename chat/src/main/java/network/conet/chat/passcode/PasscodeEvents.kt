package network.conet.chat.passcode

import org.json.JSONObject

/**
 * Native-to-page events of the passcode protocol (frozen v1, sections 3.2, 3.3, 3.4). The SDK builds the payloads and hands them to an
 * outlet; the shell delivers them to the trusted main frame over the same trust check as the requests (option (a)).
 * The SDK does not decide who receives them.
 */
object PasscodeEvents {
    /** Causes of `nativeRepairRequest` (section 3.3). Backoff, eoa mismatch, bad request and not_ready are never a cause. */
    val REPAIR_CAUSES: Set<String> = setOf("unlock_failed", "no_record", "passcode_mismatch", "record_invalid")

    /** The outlet the shell provides. The SDK calls [emit] with a finished payload; the outlet never changes it. */
    fun interface Outlet {
        fun emit(payload: JSONObject)
    }

    fun nativeRepairRequest(reqId: Long, eoa: String, cause: String): JSONObject {
        require(cause in REPAIR_CAUSES) { "unknown repair cause" }
        return JSONObject().put("type", "nativeRepairRequest").put("reqId", reqId).put("eoa", eoa.lowercase()).put("cause", cause)
    }

    fun passcodeState(set: Boolean, locked: Boolean): JSONObject =
        JSONObject().put("type", "passcodeState").put("set", set).put("locked", locked)

    fun nativeRepairResult(reqId: Long, ok: Boolean, code: String): JSONObject =
        JSONObject().put("type", "nativeRepairResult").put("reqId", reqId).put("ok", ok).put("code", code)
}
