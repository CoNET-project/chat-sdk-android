package network.conet.chat

import org.json.JSONObject

/**
 * Decides whether a `postResult` message answers a host call. Only a JSON object with `ok` or `error` answers; any other
 * message (for example the `{}` that Chromium 124 returns from `evaluateJavascript` for an async IIFE) keeps the call
 * waiting for its real answer or its timeout. Free of Android types so the JVM tests can drive it.
 */
internal object BridgeResultRule {
    fun isAnswer(json: String): Boolean {
        val text = json.trim()
        if (!text.startsWith("{")) return false
        val obj = try {
            JSONObject(text)
        } catch (_: Exception) {
            return false
        }
        return obj.has("ok") || obj.has("error")
    }
}
