package network.conet.chat

import org.json.JSONArray
import org.json.JSONObject

/**
 * Call-signal classification per the spec's `src/call-signal.ts` (shared
 * vectors `callSignal`), for protocol v1 `event:callSignal` (P3). Kept apart
 * from [BeamioConetChatCallControl], which the module still uses for the shell's
 * call layer; aligning the two is left to whoever owns call control.
 */
object BeamioConetChatCallSignal {
    /** [kind]: `offer` | `accept` | `reject` | `end` | `timeout` | `ringing`. */
    data class Signal(
        val kind: String,
        val type: String,
        val callId: String,
        val sessionId: String,
        /** `voice_call_reject_v1` only: `busy` when `reason == "busy"`, else `declined`. */
        val rejectReason: String? = null,
        /** The signal object exactly as found (its own fields, for example `callerSignature` and `from`), as compact JSON. Null only when not known. */
        val signalJson: String? = null,
    )

    val KINDS: Map<String, String> = mapOf(
        "voice_call_offer_v1" to "offer",
        "voice_call_accept_v1" to "accept",
        "voice_call_reject_v1" to "reject",
        "voice_end_v1" to "end",
        "voice_call_timeout_v1" to "timeout",
        // Wake receipt: the callee's device is ringing (callee → caller mailbox, NoPush).
        "voice_call_ringing_v1" to "ringing",
    )

    private const val MAX_DEPTH = 8
    private val BASE64 = Regex("^[A-Za-z0-9+/]+={0,2}$")

    /** The call signal inside a decrypted Chat line, or null. */
    fun classify(line: String): Signal? = walk(line, 0)

    private fun parseJson(text: String): Any? {
        val t = text.trim()
        if (t.startsWith("{")) return runCatching { JSONObject(t) }.getOrNull()
        if (t.startsWith("[")) return runCatching { JSONArray(t) }.getOrNull()
        return null
    }

    /** Padded standard base64 only (whitespace removed), decoding to UTF-8. Pure Kotlin (JVM-testable). */
    private fun decodeBase64Utf8(text: String): String? {
        val compact = text.filter { !it.isWhitespace() }
        if (compact.isEmpty() || compact.length % 4 != 0 || !BASE64.matches(compact)) return null
        val bytes = runCatching { ConetChatCryptoUtil.base64Decode(compact) }.getOrNull() ?: return null
        val decoder = Charsets.UTF_8.newDecoder()
        return runCatching { decoder.decode(java.nio.ByteBuffer.wrap(bytes)).toString() }.getOrNull()
    }

    private fun parseString(raw: String): Any? {
        val t = raw.trim()
        if (t.startsWith("{") || t.startsWith("[")) return parseJson(t)
        return decodeBase64Utf8(t)?.let { parseJson(it) }
    }

    private fun trimmed(v: Any?): String = (v as? String)?.trim().orEmpty()

    private fun walk(value: Any?, depth: Int): Signal? {
        if (depth >= MAX_DEPTH || value == null) return null
        when (value) {
            is String -> return parseString(value)?.let { walk(it, depth + 1) }
            is JSONArray -> {
                for (i in 0 until value.length()) walk(value.opt(i), depth + 1)?.let { return it }
                return null
            }
            is JSONObject -> {
                val type = value.opt("type") as? String
                val kind = type?.let { KINDS[it] }
                if (type != null && kind != null) {
                    val callId = trimmed(value.opt("callId"))
                    val sessionId = trimmed(value.opt("sessionId"))
                    if (callId.isEmpty() && sessionId.isEmpty()) return null
                    val rejectReason = if (type == "voice_call_reject_v1") {
                        if (value.optString("reason") == "busy") "busy" else "declined"
                    } else {
                        null
                    }
                    return Signal(kind, type, callId, sessionId, rejectReason, signalJson = value.toString())
                }
                (value.opt("text") as? String)?.let { walk(it, depth + 1)?.let { hit -> return hit } }
                val keys = value.keys()
                while (keys.hasNext()) {
                    val k = keys.next()
                    if (k == "text") continue
                    val v = value.opt(k)
                    if (v is JSONObject || v is JSONArray) walk(v, depth + 1)?.let { return it }
                }
                return null
            }
            else -> return null
        }
    }
}
