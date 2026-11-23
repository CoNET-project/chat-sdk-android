package network.conet.chat

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The call-control gate (2026-11-20): a control signal reaches the shell only when the outer signer equals the envelope from, the inner from equals
 * it too, the kind is a control kind, and the copy is new. Each refusal is tested; a refused message is never delivered.
 */
class CallControlGateTest {
    private val a = "0x39581c72b8c7d0de85ff22cf3ae178ae813957aa"
    private val b = "0x0cf9000000000000000000000000000000002022"

    private fun inner(type: String, from: String?, callId: String = "call-ctl-00000001", sessionId: String = "sess-0001"): String {
        val o = JSONObject().put("type", type).put("callId", callId).put("sessionId", sessionId)
        if (from != null) o.put("from", from)
        return o.toString()
    }

    /** An envelope: the outer from and signature around the inner text, as the sender builds it. */
    private fun envelope(innerText: String, outerFrom: String?, sign: String = "0xsig"): String {
        val o = JSONObject().put("timestamp", 1763600000000L).put("text", innerText).put("signMessage", sign)
        if (outerFrom != null) o.put("from", outerFrom)
        return o.toString()
    }

    private val guard = CallControlGate.ReplayGuard()

    @Test
    fun aVerifiedEndSignalIsDeliveredWithItsSender() {
        val plain = envelope(inner("voice_end_v1", a), a)
        val v = CallControlGate.admit(plain, a, "hash-1", guard)
        assertTrue(v is CallControlGate.Verdict.Deliver)
        v as CallControlGate.Verdict.Deliver
        assertEquals("voice_end_v1", v.type)
        assertEquals("call-ctl-00000001", v.callId)
        assertEquals("sess-0001", v.sessionId)
        assertEquals(a, v.from)
    }

    @Test
    fun theOtherControlKindsAreDelivered() {
        for (type in listOf("voice_call_accept_v1", "voice_call_reject_v1", "voice_call_timeout_v1", "voice_call_ringing_v1")) {
            val v = CallControlGate.admit(envelope(inner(type, a), a), a, "hash-$type", guard)
            assertTrue("$type is delivered", v is CallControlGate.Verdict.Deliver)
        }
    }

    @Test
    fun aForgedOuterSignerIsDropped() {
        // The envelope says it is from A, but the signature recovers B.
        val v = CallControlGate.admit(envelope(inner("voice_end_v1", a), a), b, "hash-forged", guard)
        assertEquals("signer_mismatch", (v as CallControlGate.Verdict.Drop).reason)
    }

    @Test
    fun anUnverifiedSignatureIsDropped() {
        val v = CallControlGate.admit(envelope(inner("voice_end_v1", a), a), null, "hash-unverified", guard)
        assertEquals("unverified", (v as CallControlGate.Verdict.Drop).reason)
    }

    @Test
    fun anInnerFromDifferentFromTheEnvelopeIsDropped() {
        val v = CallControlGate.admit(envelope(inner("voice_end_v1", b), a), a, "hash-mismatch", guard)
        assertEquals("inner_from_mismatch", (v as CallControlGate.Verdict.Drop).reason)
    }

    @Test
    fun aMissingInnerFromIsDroppedSilently() {
        val v = CallControlGate.admit(envelope(inner("voice_end_v1", null), a), a, "hash-nofrom", guard)
        assertEquals("no_inner_from", (v as CallControlGate.Verdict.Drop).reason)
    }

    @Test
    fun aMissingEnvelopeFromIsDropped() {
        val v = CallControlGate.admit(envelope(inner("voice_end_v1", a), null), a, "hash-noouter", guard)
        assertEquals("no_envelope_from", (v as CallControlGate.Verdict.Drop).reason)
    }

    @Test
    fun aBareSignalIsNotAnEnvelopeAndIsDropped() {
        // History and cached copies are bare objects with no outer signature: never delivered as control.
        val v = CallControlGate.admit(inner("voice_end_v1", a), a, "hash-bare", guard)
        assertEquals("not_envelope", (v as CallControlGate.Verdict.Drop).reason)
    }

    @Test
    fun anOfferIsNotDeliveredByThisGate() {
        val v = CallControlGate.admit(envelope(inner("voice_call_offer_v1", a), a), a, "hash-offer", guard)
        assertEquals("not_control_kind", (v as CallControlGate.Verdict.Drop).reason)
    }

    @Test
    fun aReplayedCopyIsDroppedTheSecondTime() {
        val plain = envelope(inner("voice_end_v1", a), a)
        assertTrue(CallControlGate.admit(plain, a, "hash-replay", guard) is CallControlGate.Verdict.Deliver)
        val again = CallControlGate.admit(plain, a, "hash-replay", guard)
        assertEquals("replay", (again as CallControlGate.Verdict.Drop).reason)
    }

    @Test
    fun aCopyWithNoIdentityIsDropped() {
        val v = CallControlGate.admit(envelope(inner("voice_end_v1", a), a), a, "", guard)
        assertEquals("no_copy_identity", (v as CallControlGate.Verdict.Drop).reason)
    }

    @Test
    fun theSignerMatchesWhateverCaseTheRecoveryReturns() {
        val mixed = "0x" + a.removePrefix("0x").uppercase()
        assertTrue(CallControlGate.admit(envelope(inner("voice_end_v1", a), a), mixed, "hash-case", guard) is CallControlGate.Verdict.Deliver)
    }

    /** A control object outside the signed text is not the signal: the outer signature does not cover it. */
    @Test
    fun aControlObjectOutsideTheSignedTextIsNotDelivered() {
        val unsigned = JSONObject().put("timestamp", 1763600000000L).put("text", "hello, not a control signal")
            .put("signMessage", "0xsig").put("from", a)
            .put("extra", JSONObject(inner("voice_end_v1", a)))
        val v = CallControlGate.admit(unsigned.toString(), a, "hash-outside", guard)
        assertEquals("not_control", (v as CallControlGate.Verdict.Drop).reason)
    }

    /** A signal inside the signed text is delivered even when an unsigned sibling holds a different control object. */
    @Test
    fun theSignedTextIsTheOnlySourceOfTheSignal() {
        val signedInner = inner("voice_call_reject_v1", a, callId = "call-signed-0001")
        val unsigned = JSONObject().put("timestamp", 1763600000000L).put("text", signedInner)
            .put("signMessage", "0xsig").put("from", a)
            .put("extra", JSONObject(inner("voice_end_v1", a, callId = "call-decoy-0001")))
        val v = CallControlGate.admit(unsigned.toString(), a, "hash-signed-only", guard)
        assertTrue(v is CallControlGate.Verdict.Deliver)
        v as CallControlGate.Verdict.Deliver
        assertEquals("voice_call_reject_v1", v.type)
        assertEquals("call-signed-0001", v.callId)
    }

    @Test
    fun theReplayGuardIsBoundedAndForgetsTheOldest() {
        val small = CallControlGate.ReplayGuard(capacity = 2)
        assertTrue(small.admit("x"))
        assertTrue(small.admit("y"))
        assertTrue(small.admit("z"))
        assertTrue("the oldest was forgotten", small.admit("x"))
        assertEquals(false, small.admit("z"))
    }
}
