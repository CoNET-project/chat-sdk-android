package network.conet.chat.localread

import network.conet.chat.nativekey.ShellRecordPolicy
import network.conet.chat.nativekey.shellAck
import org.json.JSONArray
import org.json.JSONObject

/**
 * `historyDeleteMessage` and `historyDeleteConversation` (spec r3by §25.52AC.2 to §25.52AC.5). The answer is built here, from the request and the
 * native history store. The module only sends it, so each request gets exactly one ack (§25.52AB.4). The page record is not written (§25.52AC.6).
 */
object NativeHistoryDelete {
    const val MESSAGE = "historyDeleteMessage"
    const val CONVERSATION = "historyDeleteConversation"

    /** `convKey`: `0x` and 40 lower-case hex digits (§25.52AC.2, §12.3). */
    private val CONV_KEY = Regex("0x[0-9a-f]{40}")

    /**
     * The ack of one request, in the spec's order: the reqId first (an invalid one is an envelope refusal with a null reqId), then the gate
     * ([refusal]: `no_key` for G0 or `not_ready` for G1, or null to go on), then the content (`bad_request` with the path names), then the store.
     * A store that is locked or closed is `busy` and nothing changes.
     */
    fun ack(type: String, body: JSONObject, refusal: String?, store: LocalChatStore?): JSONObject {
        val rawId = body.opt("reqId")
        if (!ShellRecordPolicy.reqIdValid(rawId)) return shellAck(JSONObject.NULL, "bad_request", emptyList())
        val reqId: Any = rawId!!
        if (refusal != null) return JSONObject().put("type", "ack").put("reqId", reqId).put("ok", false).put("error", refusal)

        val convKey = body.opt("convKey") as? String
        val messageId = body.opt("messageId") as? String
        // Path names in UTF-8 order (§25.52AC.5): "convKey" sorts before "messageId".
        val names = mutableListOf<String>()
        if (convKey == null || !CONV_KEY.matches(convKey)) names += "convKey"
        if (type == MESSAGE && (messageId == null || !isMessageId(messageId))) names += "messageId"
        if (names.isNotEmpty()) return shellAck(reqId, "bad_request", listOf("names" to JSONArray(names)))

        val history = store ?: return JSONObject().put("type", "ack").put("reqId", reqId).put("ok", false).put("error", "not_ready")
        if (!history.isUnlocked) return shellAck(reqId, "busy", emptyList())
        return try {
            val deleted = if (type == MESSAGE) {
                history.tombstoneMessage(convKey!!, messageId!!)
            } else {
                history.tombstoneConversation(convKey!!)
            }
            shellAck(reqId, "ok", listOf("deleted" to deleted))
        } catch (e: IllegalStateException) {
            storeFailure(reqId, e)
        }
    }

    /**
     * The answer for a store that failed inside the call (§25.52AC.5). `locked` (the key is gone) is busy: nothing changed, and a retry can
     * succeed. Anything else, `closed` included, is not busy, because the store cannot answer now and busy is defined only for a busy store.
     * Those answer with the envelope `not_ready`.
     */
    internal fun storeFailure(reqId: Any, e: IllegalStateException): JSONObject =
        if (e.message == "locked") {
            shellAck(reqId, "busy", emptyList())
        } else {
            JSONObject().put("type", "ack").put("reqId", reqId).put("ok", false).put("error", "not_ready")
        }

    /** `messageId` (the sendKey, §25.52AC.2): 1 to 128 visible ASCII characters. */
    fun isMessageId(value: String): Boolean = value.length in 1..128 && value.all { it.code in 0x21..0x7E }
}
