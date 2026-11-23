package network.conet.chat.passcode

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Test

/** Payload shapes of the frozen events. Synthetic values only. */
class PasscodeEventsTest {
    private val eoa = "0x1111111111111111111111111111111111111111"

    @Test
    fun nativeRepairRequestHasTheFrozenFieldsAndLowerCaseEoa() {
        val p = PasscodeEvents.nativeRepairRequest(7_500_000_000_001L, eoa.uppercase().replace("0X", "0x"), "unlock_failed")
        assertEquals("nativeRepairRequest", p.getString("type"))
        assertEquals(7_500_000_000_001L, p.getLong("reqId"))
        assertEquals(eoa, p.getString("eoa"))
        assertEquals("unlock_failed", p.getString("cause"))
    }

    @Test
    fun onlyTheFourFrozenCausesAreAccepted() {
        for (cause in listOf("unlock_failed", "no_record", "passcode_mismatch", "record_invalid")) {
            PasscodeEvents.nativeRepairRequest(7_500_000_000_001L, eoa, cause)
        }
        assertThrows(IllegalArgumentException::class.java) { PasscodeEvents.nativeRepairRequest(1L, eoa, "backoff") }
        assertThrows(IllegalArgumentException::class.java) { PasscodeEvents.nativeRepairRequest(1L, eoa, "not_ready") }
    }

    @Test
    fun passcodeStateCarriesSetAndLocked() {
        val p = PasscodeEvents.passcodeState(set = true, locked = false)
        assertEquals("passcodeState", p.getString("type"))
        assertEquals(true, p.getBoolean("set"))
        assertEquals(false, p.getBoolean("locked"))
        assertFalse(p.has("passcode"))
    }

    @Test
    fun nativeRepairResultCarriesTheCode() {
        val p = PasscodeEvents.nativeRepairResult(7_500_000_000_001L, ok = false, code = "address_mismatch")
        assertEquals("nativeRepairResult", p.getString("type"))
        assertEquals("address_mismatch", p.getString("code"))
        assertEquals(false, p.getBoolean("ok"))
    }
}
