package network.conet.chat.nativekey

import org.json.JSONObject

/**
 * The request fields of a signing command, checked before any signature (spec 25.52FX.1, FY.1, FU.1; gossip-sign R-1 to R-10).
 * `inboundGeneration` must be a non-negative integer when present. A new page (init declares deferAck: true) must send it on an
 * envelope or a group. An old page may omit it, but a wrong type is still refused. `sendId`, when present, must be a non-empty string.
 * Returns the refusal code (`bad_request`), or null when the request is well formed. Nothing is signed on a refusal.
 */
internal object SignRequestRule {
    fun check(kind: String, request: JSONObject, pageDeferAck: Boolean): String? {
        if (request.has("sendId")) {
            val sendId = request.opt("sendId")
            if (sendId !is String || sendId.isEmpty()) return "bad_request"
        }
        val present = request.has("inboundGeneration") && request.opt("inboundGeneration") != JSONObject.NULL
        if (present) {
            val generation = request.opt("inboundGeneration")
            val wellFormed = (generation is Int && generation >= 0) || (generation is Long && generation >= 0)
            return if (wellFormed) null else "bad_request"
        }
        return if (pageDeferAck && (kind == "envelope" || kind == "group")) "bad_request" else null
    }
}
