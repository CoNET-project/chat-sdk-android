package network.conet.chat

import org.json.JSONObject
import java.util.concurrent.ConcurrentHashMap

/** One answer from the host WebView, as its `postResult` message reports it. */
internal data class JsJsonResult(
    val ok: Boolean,
    val armor: String = "",
    val text: String = "",
    val armorHash: String = "",
    val error: String = "",
    val value: String = "",
)

/**
 * Parses one `postResult` message. Null means the message is not an answer (not a JSON object, or it has
 * neither `ok` nor `error`): the call keeps waiting for its real answer or its timeout.
 */
internal fun parseBridgeResult(json: String): JsJsonResult? {
    val text = json.trim()
    if (!text.startsWith("{")) return null
    val obj = try {
        JSONObject(text)
    } catch (_: Exception) {
        return null
    }
    if (!obj.has("ok") && !obj.has("error")) return null
    return JsJsonResult(
        ok = obj.optBoolean("ok", false),
        armor = obj.optString("armor", ""),
        text = obj.optString("text", ""),
        armorHash = obj.optString("armorHash", ""),
        error = obj.optString("error", ""),
        value = obj.optString("value", ""),
    )
}

/**
 * Routing for host WebView calls, free of Android types so the JVM tests can drive it.
 *
 * A call completes in exactly one of two ways: its `postResult` message ([onBridgeMessage]), or its timeout
 * ([expire]: [onTimeout] runs first, then the call completes with `js_bridge_timeout`). Request ids are unique,
 * so a second answer for an id is ignored.
 *
 * The `evaluateJavascript` return value is never a completion. On Chromium 124 an async IIFE returns `{}`
 * there; completing from that path reported `encrypt_fail` while the real answer was still on its way.
 */
internal class JsResultRouter(
    private val timeoutMs: Long,
    /** Runs [task] after [delayMs] in the caller's thread model and returns a function that cancels it. */
    private val schedule: (delayMs: Long, task: () -> Unit) -> (() -> Unit),
    private val onTimeout: (requestId: String) -> Unit,
) {
    private class Pending(val callback: (JsJsonResult) -> Unit, val cancelTimer: () -> Unit)

    private val pending = ConcurrentHashMap<String, Pending>()

    fun register(requestId: String, callback: (JsJsonResult) -> Unit) {
        val cancel = schedule(timeoutMs) { expire(requestId) }
        pending.put(requestId, Pending(callback, cancel))?.cancelTimer?.invoke()
    }

    fun pendingIds(): List<String> = pending.keys.toList()

    /** The `postResult` channel. Returns false when the message was not an answer and was ignored. */
    fun onBridgeMessage(requestId: String, json: String): Boolean {
        val parsed = parseBridgeResult(json) ?: return false
        return complete(requestId, parsed)
    }

    /** Completes the call if it is still pending. A late or repeated answer returns false. */
    fun complete(requestId: String, result: JsJsonResult): Boolean {
        val p = pending.remove(requestId) ?: return false
        p.cancelTimer()
        try {
            p.callback(result)
        } catch (_: Exception) {
        }
        return true
    }

    private fun expire(requestId: String) {
        val p = pending.remove(requestId) ?: return
        onTimeout(requestId)
        try {
            p.callback(JsJsonResult(ok = false, error = "js_bridge_timeout"))
        } catch (_: Exception) {
        }
    }
}

/**
 * Entry-route wrap decisions, free of Android types. A wrap yields the outer armor the entry node expects, or a
 * failure. Nothing falls back to the unwrapped inner armor.
 */
internal object EntryWrapPolicy {
    /** Why the wrap cannot be attempted at all, or null when it can. */
    fun preflight(innerArmor: String, entryPublicArmor: String): String? = when {
        !innerArmor.contains("BEGIN PGP MESSAGE") -> "not_pgp_armor"
        !entryPublicArmor.contains("BEGIN PGP PUBLIC KEY") -> "no_entry_key"
        else -> null
    }

    /** Maps the host's answer for one wrap to the caller's result. */
    fun outcome(parsed: JsJsonResult, innerArmor: String): Result<String> = when {
        !parsed.ok -> Result.failure(IllegalStateException(parsed.error.ifBlank { "wrap_fail" }))
        !parsed.armor.contains("BEGIN PGP MESSAGE") -> Result.failure(IllegalStateException("wrap_no_armor"))
        parsed.armor == innerArmor -> Result.failure(IllegalStateException("wrap_unchanged"))
        else -> Result.success(parsed.armor)
    }
}
