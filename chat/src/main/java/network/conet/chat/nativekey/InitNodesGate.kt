package network.conet.chat.nativekey

import org.json.JSONArray
import org.json.JSONObject

/**
 * The nodes rule of the G1 identity-only `init` (spec §25.52Y.29, §25.52Y.32; PM R1841, R1854).
 *
 * - `nodes` key missing: the stored roster on this device is used and `ready` follows; with none stored, `nodes_unavailable`.
 * - `nodes` is an empty array `[]`: `nodes_unavailable`, with no fallback to the stored roster, and no `ready`.
 * - `nodes` present but not an array (`null`, a string, an object, a number, a boolean): `bad_request`, no fallback, no `ready`.
 * - `nodes` is an array with an element that is not an object: `bad_request`, no fallback, no `ready`.
 * - `nodes` is a non-empty array of objects: the roster comes from the payload and `ready` follows.
 *
 * This rule applies to G1 only. The G2 `init` is unchanged (§25.52GJ). The EOA checks run before this rule. The function
 * reads no state itself: the stored count is taken through the caller's lambda, and only when the key is absent.
 */
object InitNodesGate {
    const val NODES_UNAVAILABLE = "nodes_unavailable"
    const val BAD_REQUEST = "bad_request"

    enum class Verdict { PROCEED, NODES_UNAVAILABLE, BAD_REQUEST }

    /** The verdict for the payload's `nodes` field. [storedNodeCount] is read only when the key is absent. */
    fun verdict(payload: JSONObject, storedNodeCount: () -> Int): Verdict {
        if (!payload.has("nodes")) {
            return if (storedNodeCount() == 0) Verdict.NODES_UNAVAILABLE else Verdict.PROCEED
        }
        val raw = payload.opt("nodes")
        if (raw !is JSONArray) return Verdict.BAD_REQUEST
        for (i in 0 until raw.length()) {
            if (raw.opt(i) !is JSONObject) return Verdict.BAD_REQUEST
        }
        return if (raw.length() == 0) Verdict.NODES_UNAVAILABLE else Verdict.PROCEED
    }

    /** The error code the module answers for a verdict that refuses; null for [Verdict.PROCEED]. */
    fun errorOf(verdict: Verdict): String? = when (verdict) {
        Verdict.PROCEED -> null
        Verdict.NODES_UNAVAILABLE -> NODES_UNAVAILABLE
        Verdict.BAD_REQUEST -> BAD_REQUEST
    }
}
