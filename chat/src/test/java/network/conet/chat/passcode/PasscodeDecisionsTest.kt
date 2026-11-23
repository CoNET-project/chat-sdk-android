package network.conet.chat.passcode

import network.conet.chat.passcode.PasscodeDecisions.Opened
import network.conet.chat.passcode.PasscodeDecisions.Provision
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Decision table of the frozen passcode commands (sections 3.1–3.4). Synthetic addresses only. */
class PasscodeDecisionsTest {
    private val a = "0x1111111111111111111111111111111111111111"
    private val b = "0x2222222222222222222222222222222222222222"

    @Test
    fun provisionProceedsOnlyForAnEmptyAccount() {
        assertTrue(PasscodeDecisions.provision(a, null, hasOwnRecord = false, hasOtherRecord = false) is Provision.Proceed)
        assertTrue(PasscodeDecisions.provision(a, a.uppercase().replace("0X", "0x"), false, false) is Provision.Proceed)
    }

    @Test
    fun provisionRefusesAMismatchedPointerAndAMalformedEoa() {
        assertEquals("eoa_mismatch", (PasscodeDecisions.provision(a, b, false, false) as Provision.Refused).code)
        assertEquals("bad_request", (PasscodeDecisions.provision("0xabc", null, false, false) as Provision.Refused).code)
    }

    @Test
    fun provisionNeverOverwritesAnExistingRecord() {
        assertEquals("already_set", (PasscodeDecisions.provision(a, a, hasOwnRecord = true, hasOtherRecord = false) as Provision.Refused).code)
        assertEquals("other_account_present", (PasscodeDecisions.provision(a, null, hasOwnRecord = false, hasOtherRecord = true) as Provision.Refused).code)
    }

    @Test
    fun unlockAnswersEachOutcomeAndCountsNothing() {
        assertNull(PasscodeDecisions.unlock(Opened.OPENED))
        assertEquals("wrong_passcode", PasscodeDecisions.unlock(Opened.WRONG_PASSCODE))
        assertEquals("no_record", PasscodeDecisions.unlock(Opened.ABSENT))
        assertEquals("record_invalid", PasscodeDecisions.unlock(Opened.INVALID))
    }

    @Test
    fun repairIsRequestedOnlyForTheFrozenCauses() {
        assertNull(PasscodeDecisions.repairCause(null, uiUnlocked = true, opened = Opened.OPENED))
        assertEquals("no_record", PasscodeDecisions.repairCause("no_record", false, Opened.ABSENT))
        assertEquals("record_invalid", PasscodeDecisions.repairCause("record_invalid", false, Opened.INVALID))
        assertEquals("passcode_mismatch", PasscodeDecisions.repairCause("wrong_passcode", uiUnlocked = true, opened = Opened.WRONG_PASSCODE))
        assertEquals("unlock_failed", PasscodeDecisions.repairCause("wrong_passcode", uiUnlocked = false, opened = Opened.WRONG_PASSCODE))
    }

    @Test
    fun repairProvideNeedsAMatchingUnexpiredSameAccountRequest() {
        assertNull(PasscodeDecisions.repairProvide(requestMatches = true, expired = false, sameAccount = true))
        assertEquals("no_request", PasscodeDecisions.repairProvide(requestMatches = false, expired = false, sameAccount = true))
        assertEquals("no_request", PasscodeDecisions.repairProvide(requestMatches = true, expired = true, sameAccount = true))
        assertEquals("no_request", PasscodeDecisions.repairProvide(requestMatches = true, expired = false, sameAccount = false))
    }
}
