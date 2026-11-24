package network.conet.chat.nativekey

import network.conet.chat.BuildConfig
import org.json.JSONObject
import java.util.concurrent.ConcurrentHashMap

/** One status of the first identity: a state, and optionally a reason, an attempt and a retry delay. */
internal class FirstIdentityStatus(val state: String, val reason: String? = null, val attempt: Int? = null, val retryAfterMs: Long? = null)

/**
 * The `firstIdentityStatus` event (SDK to page): `{type, state, reason?, attempt?, retryAfterMs?}`, those keys only. State is one of registering, registered,
 * retry_later, identity_pending, failed. No key, armor, fingerprint, signature, tag or password is ever in it. A terminal state (registered, failed) is not
 * overwritten later in the same process. Enabled only in a QA build (`-PchatIdentityStateEventsQa=true`); a production build emits nothing, and the QA
 * capability name `identity.first.status.v1` is declared only there.
 */
internal object FirstIdentityEvents {
    const val TYPE = "firstIdentityStatus"
    const val CAPABILITY = "identity.first.status.v1"

    val STATES: Set<String> = setOf("registering", "registered", "retry_later", "identity_pending", "failed")

    /** The reasons the text lists; any other value is not sent. */
    val REASONS: Set<String> = setOf("no_record_confirmed", "read_unavailable", "submit_5xx", "submit_4xx", "conflict_other_key", "readback_timeout")

    /** The sink the module installs (its event channel). Null until installed. */
    @Volatile
    internal var sink: ((JSONObject) -> Unit)? = null

    @Volatile
    internal var enabled: Boolean = BuildConfig.IDENTITY_STATE_EVENTS_QA

    private val terminal: MutableSet<String> = ConcurrentHashMap.newKeySet()

    /** The event body of [status]: the whitelist keys only. */
    fun body(status: FirstIdentityStatus): JSONObject {
        val out = JSONObject().put("type", TYPE).put("state", status.state)
        status.reason?.takeIf { it in REASONS }?.let { out.put("reason", it) }
        status.attempt?.takeIf { it >= 1 }?.let { out.put("attempt", it) }
        if (status.state == "retry_later") status.retryAfterMs?.takeIf { it >= 0 }?.let { out.put("retryAfterMs", it) }
        return out
    }

    /** Sends [status] for [account] (the account only keys the terminal latch; it is never sent). */
    fun emit(account: String, status: FirstIdentityStatus) {
        if (!enabled || status.state !in STATES) return
        val out = sink ?: return
        val key = account.lowercase()
        if (key in terminal) return
        if (status.state == "registered" || status.state == "failed") terminal.add(key)
        out(body(status))
    }

    internal fun resetForTests() {
        terminal.clear()
    }
}
