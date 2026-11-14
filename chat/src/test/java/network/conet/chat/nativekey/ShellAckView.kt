package network.conet.chat.nativekey

import org.json.JSONObject

/**
 * The vectors' vocabulary of a page-record answer, read from its ack (§25.28.3, §25.52T.2): for `ok: true` the `result` fields (the outcome
 * is `result.code`, an error carries `sub` in `result`), and `reqId`. For `ok: false` the `code` is the `error` value. Any object that is not
 * an ack is returned as it is.
 */
internal fun JSONObject.v(): JSONObject {
    if (optString("type") != "ack") return this
    val out = JSONObject().put("reqId", opt("reqId"))
    if (optBoolean("ok")) {
        val result = getJSONObject("result")
        for (k in result.keys()) out.put(k, result.get(k))
    } else {
        out.put("code", getString("error"))
    }
    return out
}
