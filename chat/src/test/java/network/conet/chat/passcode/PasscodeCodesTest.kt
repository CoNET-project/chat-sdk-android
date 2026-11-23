package network.conet.chat.passcode

import org.junit.Assert.assertEquals
import org.junit.Test

/** The wire strings are the frozen protocol's (sections 3–4). A rename would break the page. */
class PasscodeCodesTest {
    @Test
    fun theWireStringsAreTheFrozenOnes() {
        assertEquals("eoa_mismatch", PasscodeCodes.EOA_MISMATCH)
        assertEquals("address_mismatch", PasscodeCodes.ADDRESS_MISMATCH)
        assertEquals("already_set", PasscodeCodes.ALREADY_SET)
        assertEquals("other_account_present", PasscodeCodes.OTHER_ACCOUNT_PRESENT)
        assertEquals("passcode_not_provided", PasscodeCodes.PASSCODE_REQUIRED)
        assertEquals("passcode_not_provided", PasscodeCodes.NOT_READY_REASON_PASSCODE_REQUIRED)
        assertEquals("readback_mismatch", PasscodeCodes.READBACK_MISMATCH)
        assertEquals("no_request", PasscodeCodes.NO_REQUEST)
        assertEquals("write_failed", PasscodeCodes.WRITE_FAILED)
        assertEquals("backoff", PasscodeCodes.BACKOFF)
    }
}
