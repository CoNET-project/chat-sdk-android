package network.conet.chat

import org.json.JSONArray
import org.json.JSONObject

/**
 * Call control carried as an ordinary Chat message (the peer's mailbox copy of
 * `voice_end_v1` / `voice_call_timeout_v1`). The module recognises it and hands
 * it to the shell's call layer ([BeamioConetChatModule.callControlObserver]);
 * iOS uses the same rules.
 */
object BeamioConetChatCallControl {
    data class Signal(val type: String, val callId: String, val sessionId: String)

    private val TYPES = setOf("voice_end_v1", "voice_call_timeout_v1")

    /** The call-control signal inside a decrypted Chat line, or null. */
    fun parse(line: String): Signal? {
        if (TYPES.none { line.contains(it) } && !looksBase64Text(line)) return null
        return walk(line, 0)
    }

    private fun looksBase64Text(line: String): Boolean {
        val obj = runCatching { JSONObject(line) }.getOrNull() ?: return true
        val text = obj.optString("text")
        return text.isNotEmpty() && !text.trim().startsWith("{")
    }

    private fun parseAny(s: String): Any? {
        val t = s.trim()
        if (t.startsWith("{")) return runCatching { JSONObject(t) }.getOrNull()
        if (t.startsWith("[")) return runCatching { JSONArray(t) }.getOrNull()
        val decoded = runCatching {
            String(android.util.Base64.decode(t.replace(Regex("\\s+"), ""), android.util.Base64.DEFAULT), Charsets.UTF_8)
        }.getOrNull()?.trim() ?: return null
        return if (decoded.startsWith("{")) runCatching { JSONObject(decoded) }.getOrNull() else null
    }

    private fun walk(value: Any?, depth: Int): Signal? {
        if (depth >= 8 || value == null) return null
        when (value) {
            is String -> return walk(parseAny(value), depth + 1)
            is JSONArray -> for (i in 0 until value.length()) walk(value.opt(i), depth + 1)?.let { return it }
            is JSONObject -> {
                val type = value.optString("type")
                if (type in TYPES) {
                    val callId = value.optString("callId").trim()
                    val sessionId = value.optString("sessionId").trim()
                    return if (callId.isEmpty() && sessionId.isEmpty()) null else Signal(type, callId, sessionId)
                }
                (value.opt("text") as? String)?.let { walk(it, depth + 1)?.let { hit -> return hit } }
                val keys = value.keys()
                while (keys.hasNext()) {
                    val k = keys.next()
                    if (k == "text") continue
                    val v = value.opt(k)
                    if (v is JSONObject || v is JSONArray) walk(v, depth + 1)?.let { return it }
                }
            }
        }
        return null
    }
}
