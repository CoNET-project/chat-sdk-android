package network.conet.chat.nativekey

import org.json.JSONObject

/**
 * `nativeIdentityCheck {eoa}` (supplement 2026-11-20, §2.6): when the UI unlocks again and the native session is already unlocked, the native side
 * checks, on this device only, whether the page's EOA is the EOA of the unlocked native phrase. No phrase, key or derived secret crosses the bridge:
 * the request carries only the public EOA.
 *
 * Answers: `match` true or false when the native session is unlocked; `locked` when it is locked (no check is made); `bad_request` for a missing,
 * malformed or extra field. The comparison is case-insensitive on the lower-case form.
 */
internal object NativeIdentityCheck {
    const val NAME = "nativeIdentityCheck"

    /** The allowed fields, with the envelope fields `type` and `reqId`. Must match the SDK allowedFields and the shell whitelist exactly. */
    val ALLOWED_FIELDS: Set<String> = setOf("type", "reqId", "eoa")

    /** The native session is locked: no check is made (v43 §47.2, v42 §45.3). */
    const val LOCKED = "locked"
    const val BAD_REQUEST = "bad_request"

    private val EOA_RE = Regex("^0x[0-9a-f]{40}$")

    sealed class Answer {
        class Match(val match: Boolean) : Answer()
        class Refused(val code: String) : Answer()
    }

    /** [nativeEoa] is the lower-case EOA the native session is unlocked for, or null when it is locked. */
    fun answer(body: JSONObject, nativeEoa: String?): Answer {
        if (body.keys().asSequence().any { it !in ALLOWED_FIELDS }) return Answer.Refused(BAD_REQUEST)
        val requested = body.opt("eoa") as? String ?: return Answer.Refused(BAD_REQUEST)
        val normalized = requested.lowercase()
        if (!EOA_RE.matches(normalized)) return Answer.Refused(BAD_REQUEST)
        if (nativeEoa == null) return Answer.Refused(LOCKED)
        return Answer.Match(normalized == nativeEoa.lowercase())
    }
}
