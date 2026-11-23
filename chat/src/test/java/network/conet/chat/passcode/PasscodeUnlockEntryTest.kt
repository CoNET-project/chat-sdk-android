package network.conet.chat.passcode

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * The skeleton of passcodeUnlock (addenda 10 to 14): the field allowlist, format checks, the call check before any passcode check, and the rule
 * that call_mismatch and account_mismatch do not consume the call. The unlock itself is not part of this batch.
 */
class PasscodeUnlockEntryTest {
    private val eoa = "0x39581c72b8c7d0de85ff22cf3ae178ae813957aa"
    private val other = "0x0cf9000000000000000000000000000000002022"
    private val gen = SessionGeneration()
    private val calls = IncomingCallRegistry(gen)

    private fun req(vararg pairs: Pair<String, Any>): JSONObject {
        val o = JSONObject()
        for ((k, v) in pairs) o.put(k, v)
        return o
    }

    private fun refused(a: PasscodeUnlockEntry.Admission): PasscodeUnlockEntry.Admission.Refused {
        return a as? PasscodeUnlockEntry.Admission.Refused ?: fail("expected a refusal, got $a") as PasscodeUnlockEntry.Admission.Refused
    }

    private fun passed(a: PasscodeUnlockEntry.Admission): PasscodeUnlockEntry.Admission.Pass {
        return a as? PasscodeUnlockEntry.Admission.Pass ?: fail("expected a pass, got $a") as PasscodeUnlockEntry.Admission.Pass
    }

    @Test
    fun theAllowlistIsExactlyEoaPasscodeAndCallId() {
        assertEquals(setOf("eoa", "passcode", "callId"), PasscodeUnlockEntry.ALLOWED_FIELDS)
    }

    @Test
    fun anUnlistedFieldIsRefusedAndNeverPassedOn() {
        val a = PasscodeUnlockEntry.admit(req("eoa" to eoa, "passcode" to "12345678", "extra" to 1), eoa, calls)
        assertEquals("bad_request", refused(a).code)
    }

    @Test
    fun missingOrMalformedFieldsAreBadRequest() {
        assertEquals("bad_request", refused(PasscodeUnlockEntry.admit(req("passcode" to "x"), eoa, calls)).code)
        assertEquals("bad_request", refused(PasscodeUnlockEntry.admit(req("eoa" to eoa), eoa, calls)).code)
        assertEquals("bad_request", refused(PasscodeUnlockEntry.admit(req("eoa" to "0x12", "passcode" to "x"), eoa, calls)).code)
        assertEquals("bad_request", refused(PasscodeUnlockEntry.admit(req("eoa" to eoa, "passcode" to ""), eoa, calls)).code)
        assertEquals("bad_request", refused(PasscodeUnlockEntry.admit(req("eoa" to eoa, "passcode" to 123), eoa, calls)).code)
    }

    @Test
    fun aMalformedCallIdIsBadRequestBeforeTheTableTakesEffect() {
        val r = refused(PasscodeUnlockEntry.admit(req("eoa" to eoa, "passcode" to "x", "callId" to "bad id!"), eoa, calls, callTableInEffect = false))
        assertEquals("bad_request", r.code)
        assertFalse("the call is not ended", r.endsCall)
    }

    @Test
    fun aMalformedCallIdIsCallMismatchOnceTheTableTakesEffect() {
        val r = refused(PasscodeUnlockEntry.admit(req("eoa" to eoa, "passcode" to "x", "callId" to "bad id!"), eoa, calls, callTableInEffect = true))
        assertEquals("call_mismatch", r.code)
        assertFalse(r.endsCall)
    }

    /** F-40: the account is judged first, so a wrong eoa and a wrong callId together answer account_mismatch. */
    @Test
    fun anEoaAndCallIdBothWrongAnswerAccountMismatchFirst() {
        calls.incomingCallBind("call-aaaa1111", eoa)
        val r = refused(PasscodeUnlockEntry.admit(req("eoa" to other, "passcode" to "12345678", "callId" to "call-cccc9999"), eoa, calls))
        assertEquals("account_mismatch", r.code)
        assertFalse(r.endsCall)
    }

    @Test
    fun aCurrentAccountMismatchWithAWrongCallIdAnswersAccountMismatchFirst() {
        calls.incomingCallBind("call-aaaa1111", eoa)
        val r = refused(PasscodeUnlockEntry.admit(req("eoa" to eoa, "passcode" to "12345678", "callId" to "call-cccc9999"), other, calls))
        assertEquals("account_mismatch", r.code)
    }

    @Test
    fun withNoCallAndNoRegistrationTheUnlockIsOrdinary() {
        val p = passed(PasscodeUnlockEntry.admit(req("eoa" to eoa, "passcode" to "12345678"), eoa, calls))
        assertFalse(p.pendingCallCancelled)
        assertNull(p.callId)
        assertNull(p.gen0)
    }

    @Test
    fun withARegisteredCallButNoCallIdTheCallEndsAsCancelled() {
        calls.incomingCallBind("call-aaaa1111", eoa)
        val p = passed(PasscodeUnlockEntry.admit(req("eoa" to eoa, "passcode" to "12345678"), eoa, calls))
        assertTrue(p.pendingCallCancelled)
    }

    @Test
    fun aMatchingCallPassesWithTheCapturedGeneration() {
        calls.incomingCallBind("call-aaaa1111", eoa)
        val p = passed(PasscodeUnlockEntry.admit(req("eoa" to eoa, "passcode" to "12345678", "callId" to "call-aaaa1111"), eoa, calls))
        assertEquals("call-aaaa1111", p.callId)
        assertEquals(0L, p.gen0)
        assertFalse(p.pendingCallCancelled)
    }

    @Test
    fun aCallIdWithNoRegistrationIsBadRequestBeforeTheTableTakesEffect() {
        val r = refused(PasscodeUnlockEntry.admit(req("eoa" to eoa, "passcode" to "12345678", "callId" to "call-aaaa1111"), eoa, calls, callTableInEffect = false))
        assertEquals("bad_request", r.code)
        assertFalse("a refusal does not end the call", r.endsCall)
    }

    @Test
    fun aCallIdWithNoRegistrationIsCallMismatchOnceTheTableTakesEffectAndIsNotTerminal() {
        val r = refused(PasscodeUnlockEntry.admit(req("eoa" to eoa, "passcode" to "12345678", "callId" to "call-aaaa1111"), eoa, calls, callTableInEffect = true))
        assertEquals("call_mismatch", r.code)
        assertFalse("call_mismatch is not terminal", r.endsCall)
    }

    @Test
    fun aDifferentCallIdIsRefusedAndTheRegisteredCallIsNotConsumed() {
        calls.incomingCallBind("call-aaaa1111", eoa)
        val r = refused(PasscodeUnlockEntry.admit(req("eoa" to eoa, "passcode" to "12345678", "callId" to "call-bbbb2222"), eoa, calls))
        assertEquals("call_mismatch", r.code)
        assertFalse(r.endsCall)
        // The registration still holds call-1: a matching request now passes.
        val p = passed(PasscodeUnlockEntry.admit(req("eoa" to eoa, "passcode" to "12345678", "callId" to "call-aaaa1111"), eoa, calls))
        assertEquals("call-aaaa1111", p.callId)
    }

    @Test
    fun aRequestEoaDifferentFromTheRegisteredOneIsAccountMismatchAndKeepsTheCall() {
        calls.incomingCallBind("call-aaaa1111", eoa)
        val r = refused(PasscodeUnlockEntry.admit(req("eoa" to other, "passcode" to "12345678", "callId" to "call-aaaa1111"), eoa, calls))
        assertEquals("account_mismatch", r.code)
        assertFalse("the call is not ended by an account mismatch", r.endsCall)
        assertEquals("call-aaaa1111", (PasscodeUnlockEntry.admit(req("eoa" to eoa, "passcode" to "12345678", "callId" to "call-aaaa1111"), eoa, calls) as PasscodeUnlockEntry.Admission.Pass).callId)
    }

    @Test
    fun aCurrentAccountDifferentFromTheRegisteredOneIsAccountMismatch() {
        calls.incomingCallBind("call-aaaa1111", eoa)
        val r = refused(PasscodeUnlockEntry.admit(req("eoa" to eoa, "passcode" to "12345678", "callId" to "call-aaaa1111"), other, calls))
        assertEquals("account_mismatch", r.code)
    }

    @Test
    fun unbindRemovesTheCallOnlyWhenItIsTheRegisteredOne() {
        calls.incomingCallBind("call-aaaa1111", eoa)
        calls.incomingCallUnbind("call-dddd0000")
        assertTrue(calls.check("call-aaaa1111", eoa, eoa) is IncomingCallRegistry.CallCheck.Proceed)
        calls.incomingCallUnbind("call-aaaa1111")
        assertEquals("call_mismatch", refused(PasscodeUnlockEntry.admit(req("eoa" to eoa, "passcode" to "12345678", "callId" to "call-aaaa1111"), eoa, calls)).code)
    }

    @Test
    fun aSessionEndAdvancesTheGenerationAndClearsTheCall() {
        calls.incomingCallBind("call-aaaa1111", eoa)
        val before = gen.current(eoa)
        assertEquals(before + 1, calls.onSessionEnded(eoa, SessionGeneration.Reason.LOCK))
        assertEquals(
            "call_mismatch",
            refused(PasscodeUnlockEntry.admit(req("eoa" to eoa, "passcode" to "12345678", "callId" to "call-aaaa1111"), eoa, calls)).code,
        )
    }

    @Test
    fun aNewBindAfterASessionEndCapturesTheNewGeneration() {
        calls.incomingCallBind("call-aaaa1111", eoa)
        calls.onSessionEnded(eoa, SessionGeneration.Reason.LOGOUT)
        calls.incomingCallBind("call-bbbb2222", eoa)
        val p = passed(PasscodeUnlockEntry.admit(req("eoa" to eoa, "passcode" to "12345678", "callId" to "call-bbbb2222"), eoa, calls))
        assertEquals(1L, p.gen0)
    }

    @Test
    fun bindRefusesMalformedValues() {
        assertFalse(calls.incomingCallBind("bad id!", eoa))
        assertFalse(calls.incomingCallBind("call-aaaa1111", "0x12"))
        assertEquals("no call is registered", "call_mismatch", refused(PasscodeUnlockEntry.admit(req("eoa" to eoa, "passcode" to "12345678", "callId" to "call-aaaa1111"), eoa, calls)).code)
    }

    /** Notice v2: the account is judged first, so with no registered call a request for another account is account_mismatch, not call_mismatch. */
    @Test
    fun anEoaOtherThanTheCurrentAccountIsAccountMismatchEvenWithNoRegistration() {
        val r = refused(PasscodeUnlockEntry.admit(req("eoa" to other, "passcode" to "12345678", "callId" to "call-aaaa1111"), eoa, calls))
        assertEquals("account_mismatch", r.code)
        assertFalse(r.endsCall)
    }
}
