package network.conet.chat.nativekey

import org.json.JSONObject

/**
 * One answer per request. A command that escapes with an exception still owes its request exactly one answer: the module
 * answers `not_ready` when no answer was decided yet for that reqId. A command without a reqId owes none.
 */
internal object CommandAnswerGuard {

    /** The key of a request id as it travels in a payload; null for an absent or JSON-null id. */
    fun keyOf(reqId: Any?): String? = reqId?.takeIf { it != JSONObject.NULL }?.toString()

    /** Records that [reqId] is being answered. True only the first time for that id; false when there is no id. */
    fun firstAnswer(answered: MutableSet<String>, reqId: Any?): Boolean {
        val key = keyOf(reqId) ?: return false
        return answered.add(key)
    }
}
