package network.conet.chat

import org.json.JSONObject

/**
 * The gate for call-control signals delivered to the shell (2026-11-20; protocol v54 §61, v68 §75). The shell cannot see the envelope, so the SDK
 * delivers a control signal only when every check passes:
 *  1. the message is an envelope (an outer object with `signMessage` and `from`), not a bare signal;
 *  2. the signer recovered from the outer signature over the envelope text equals the envelope `from` (lower case);
 *  3. the inner signal object carries a `from`, and it equals the envelope `from`;
 *  4. the signal is one of accept, reject, end, timeout, ringing (an offer is handled by the offer path, not here);
 *  5. the message is new: a copy already delivered (same armor hash) is refused as a replay.
 * Anything that fails is dropped, with no delivery and no state change. History and cached copies never reach this gate: the redelivery paths return
 * earlier in the inbound handler.
 */
internal object CallControlGate {
    /** The control kinds the shell may act on (classify's kinds, minus offer). */
    val KINDS: Set<String> = setOf("accept", "reject", "end", "timeout", "ringing")

    private val EOA_RE = Regex("^0x[0-9a-f]{40}$")

    sealed class Verdict {
        /** [type] is the raw wire type, [from] the verified envelope sender (lower case). */
        class Deliver(val type: String, val callId: String, val sessionId: String, val from: String) : Verdict()
        class Drop(val reason: String) : Verdict()
    }

    /** Remembers the armor hashes already delivered: a bounded set in insertion order. */
    class ReplayGuard(private val capacity: Int = 512) {
        private val seen = LinkedHashSet<String>()

        /** True when [key] is new (and is now remembered); false for a replay. */
        @Synchronized
        fun admit(key: String): Boolean {
            if (seen.contains(key)) return false
            seen.add(key)
            if (seen.size > capacity) seen.iterator().let { it.next(); it.remove() }
            return true
        }
    }

    /**
     * [recoveredSigner] is the EIP-191 signer recovered from the outer signature over the envelope text, or null when unverified. [armorHash]
     * identifies the copy (empty when unknown: then the replay check cannot apply, and the message is refused).
     */
    fun admit(plaintext: String, recoveredSigner: String?, armorHash: String, replays: ReplayGuard): Verdict {
        val outer = runCatching { JSONObject(plaintext) }.getOrNull() ?: return Verdict.Drop("not_envelope")
        if (!outer.has("signMessage") || !outer.has("text")) return Verdict.Drop("not_envelope")
        val outerFrom = outer.optString("from", "").trim().lowercase()
        if (!EOA_RE.matches(outerFrom)) return Verdict.Drop("no_envelope_from")
        val signer = recoveredSigner?.trim()?.lowercase()
        if (signer.isNullOrEmpty()) return Verdict.Drop("unverified")
        if (signer != outerFrom) return Verdict.Drop("signer_mismatch")
        // Only the signed text is read for the signal. classify also walks the envelope's other object fields, which the outer signature does not cover:
        // a control object placed there must never be taken as the signal.
        val signedText = outer.optString("text", "")
        val sig = BeamioConetChatCallSignal.classify(signedText) ?: return Verdict.Drop("not_control")
        if (sig.kind !in KINDS) return Verdict.Drop("not_control_kind")
        val inner = runCatching { JSONObject(sig.signalJson ?: "") }.getOrNull() ?: return Verdict.Drop("no_inner_signal")
        val innerFrom = inner.optString("from", "").trim().lowercase()
        if (innerFrom.isEmpty()) return Verdict.Drop("no_inner_from")
        if (innerFrom != outerFrom) return Verdict.Drop("inner_from_mismatch")
        if (armorHash.isEmpty()) return Verdict.Drop("no_copy_identity")
        if (!replays.admit(armorHash)) return Verdict.Drop("replay")
        return Verdict.Deliver(sig.type, sig.callId, sig.sessionId, outerFrom)
    }
}
