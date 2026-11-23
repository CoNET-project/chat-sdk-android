package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** The read-back check (v182 §202): both sides must equal the account; a missing or unreadable side is never a pass. Native side is a test stand-in. */
class ReadBackCheckTest {
    private val acc = "0x1111111111111111111111111111111111111111"
    private val other = "0x2222222222222222222222222222222222222222"
    private val key = "$acc:default"

    @Test
    fun bothSidesEqualTheAccountPasses() {
        assertTrue(ReadBackCheck.passes(key, acc, acc))
    }

    @Test
    fun aPageAddressForAnotherAccountFails() {
        assertFalse(ReadBackCheck.passes(key, other, acc))
    }

    @Test
    fun aNativeAddressForAnotherAccountFails() {
        assertFalse(ReadBackCheck.passes(key, acc, other))
    }

    /** PWA: an unreadable page address is sent as an absent field, which is not a pass. */
    @Test
    fun aMissingPageAddressIsNotAPass() {
        assertFalse(ReadBackCheck.passes(key, null, acc))
    }

    @Test
    fun aMissingNativeAddressIsNotAPass() {
        assertFalse(ReadBackCheck.passes(key, acc, null))
    }

    @Test
    fun aMalformedAddressIsNotAPass() {
        assertFalse(ReadBackCheck.passes(key, "0xZZ", acc))
        // The page sends lower-case only: an upper-case address is not the same form, so it is not a pass.
        val mixed = "0xabcdef0123456789abcdef0123456789abcdef01"
        val upper = "0x" + mixed.drop(2).uppercase()
        assertFalse(ReadBackCheck.passes("$mixed:default", upper, mixed))
    }

    @Test
    fun aMissingAccountKeyIsNotAPass() {
        assertFalse(ReadBackCheck.passes(null, acc, acc))
    }

    /** PWA and SDK log only the first 6 and last 4 characters. */
    @Test
    fun theLogFormIsTheFirstSixAndLastFour() {
        assertEquals("0x1111…1111", ReadBackCheck.logForm(acc))
    }

    /** Negative: the page-derived address differs from the payload accountKey: MISMATCH, never PASS. */
    @Test
    fun aPageAddressDifferentFromThePayloadAccountKeyIsAMismatch() {
        assertEquals(ReadBackCheck.Verdict.MISMATCH, ReadBackCheck.verdict(acc, other, acc))
    }

    /** Negative: the native address differs from the payload accountKey: MISMATCH. */
    @Test
    fun aNativeAddressDifferentFromThePayloadAccountKeyIsAMismatch() {
        assertEquals(ReadBackCheck.Verdict.MISMATCH, ReadBackCheck.verdict(acc, acc, other))
    }

    /** Positive: the payload, the page and the native address agree: PASS. */
    @Test
    fun allThreeAgreeIsPass() {
        assertEquals(ReadBackCheck.Verdict.PASS, ReadBackCheck.verdict(acc, acc, acc))
    }
}
