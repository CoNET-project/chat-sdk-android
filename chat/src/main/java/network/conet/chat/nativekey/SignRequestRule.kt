package network.conet.chat.nativekey

import network.conet.chat.BeamioConetChatProtocol
import org.json.JSONObject

/**
 * The request fields of a signing command, checked before any signature (gossip-sign vectors R-1 to R-13).
 *
 * `inboundGeneration`, when the field is present at all, must be a non-negative integer by value ([BridgeInteger]: 0..2^53−1, a double such as 5.0 is
 * accepted, a boolean, a string, a fraction, a negative number, an out-of-range number or an explicit null is `bad_request`), for every page and every shell.
 *
 * When it is absent, it is required only if BOTH hold: the page's init declared deferAck, and THIS SDK declares `inbound.generation.v1`
 * ([BeamioConetChatProtocol.declaresInboundGeneration]: the one source). The requirement presupposes a generation to send, which a shell that
 * announces none cannot give a page. Without the declaration the field may be omitted (the page then sends none: it does so for any shell that does not
 * declare the capability), so the SDK never enforces what it does not provide.
 *
 * This build does not implement the inbound generation (it does not declare `inbound.generation.v1` and does not bind a request to an inbound generation).
 * After an account switch or an identity clear a request of an old generation is therefore not refused.
 *
 * `sendId`, when present, must be a non-empty string. Returns the refusal code (`bad_request`), or null when the request is well formed.
 * Nothing is signed on a refusal.
 */
internal object SignRequestRule {
    fun check(
        kind: String,
        request: JSONObject,
        pageDeferAck: Boolean,
        shellDeclaresGeneration: Boolean = BeamioConetChatProtocol.declaresInboundGeneration(),
    ): String? {
        if (request.has("sendId")) {
            val sendId = request.opt("sendId")
            if (sendId !is String || sendId.isEmpty()) return "bad_request"
        }
        if (request.has("inboundGeneration")) {
            // Present means appeared, an explicit null included: its type is wrong, as it is on iOS.
            return if (BridgeInteger.nonNegativeSafe(request.opt("inboundGeneration")) != null) null else "bad_request"
        }
        return if (shellDeclaresGeneration && pageDeferAck && (kind == "envelope" || kind == "group")) "bad_request" else null
    }
}
