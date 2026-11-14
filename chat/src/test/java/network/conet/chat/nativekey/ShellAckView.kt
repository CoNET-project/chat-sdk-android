package network.conet.chat.nativekey

import org.json.JSONObject

/** The codes that an ack carries as its `error` value and that the vectors name as `error` with a `sub` (§25.52D.6, §25.52S.3). */
private val ACK_SUB_CODES = setOf(
    "locked", "record_unreadable", "storage_locked", "legacy_store_unreadable", "import_not_done", "needs_native_recovery", "no_key",
)

/**
 * The vectors' vocabulary of a page-record answer, read from its ack (§25.28.3, R431): `code` and `sub` for an error, the `result` fields
 * otherwise, and `reqId`. Any object that is not an ack is returned as it is.
 */
internal fun JSONObject.v(): JSONObject {
    if (optString("type") != "ack") return this
    val out = JSONObject().put("reqId", opt("reqId"))
    if (optBoolean("ok")) {
        val result = getJSONObject("result")
        for (k in result.keys()) out.put(k, result.get(k))
    } else {
        val error = getString("error")
        if (error in ACK_SUB_CODES) out.put("code", "error").put("sub", error) else out.put("code", error)
    }
    return out
}
