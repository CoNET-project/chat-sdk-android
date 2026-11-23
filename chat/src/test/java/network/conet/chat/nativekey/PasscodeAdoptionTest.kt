package network.conet.chat.nativekey

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 0.2.28 follow-up (2026-11-20): passcodeStatus under G0 during the legacy adoption. While the adoption is in flight or unsettled the
 * answer is unknown (hasKey true, walletState not_ready), never hasKey:false (the page would read it as "confirmed none"). Once the
 * adoption has settled, G0 answers hasKey:false. G1 and G2 are not affected.
 */
class PasscodeAdoptionTest {
    private val module: String by lazy {
        File("src/main/java/network/conet/chat/BeamioConetChatModule.kt").readText(Charsets.UTF_8)
    }

    @Test
    fun whileTheAdoptionIsInFlightG0IsUnknownNotNone() {
        val r = NoKeyGate.passcodeStatusWhileAdopting(NoKeyGate.Gate.G0, adoptionSettled = false, adoptionInFlight = true)
        assertEquals("not_ready", r.getString("walletState"))
        assertTrue("hasKey stays true (unknown, never a confirmed none)", r.getBoolean("hasKey"))
    }

    @Test
    fun whileTheAdoptionIsUnsettledG0IsUnknownNotNone() {
        val r = NoKeyGate.passcodeStatusWhileAdopting(NoKeyGate.Gate.G0, adoptionSettled = false, adoptionInFlight = false)
        assertEquals("not_ready", r.getString("walletState"))
        assertTrue("never hasKey:false while unsettled", r.getBoolean("hasKey"))
    }

    @Test
    fun onceSettledG0AnswersHasKeyFalse() {
        val r = NoKeyGate.passcodeStatusWhileAdopting(NoKeyGate.Gate.G0, adoptionSettled = true, adoptionInFlight = false)
        assertFalse(r.getBoolean("hasKey"))
        assertFalse("no walletState once settled", r.has("walletState"))
        assertEquals(false, r.getBoolean("set"))
        assertEquals(false, r.getBoolean("locked"))
    }

    @Test
    fun g1AndG2AreNotAffectedByTheAdoption() {
        for (gate in listOf(NoKeyGate.Gate.G1, NoKeyGate.Gate.G2)) {
            val r = NoKeyGate.passcodeStatusWhileAdopting(gate, adoptionSettled = false, adoptionInFlight = true)
            assertTrue("hasKey true for $gate", r.getBoolean("hasKey"))
            assertFalse("no walletState for $gate", r.has("walletState"))
        }
    }

    @Test
    fun theModuleAnswersPasscodeStatusThroughTheGuard() {
        val route = module.substringAfter("NoKeyGate.Route.PASSCODE_STATUS -> {").substringBefore("when (NoKeyGate.answerFor(type, commandGate))")
        assertTrue("the guard function is the answer", route.contains("NoKeyGate.passcodeStatusWhileAdopting("))
        assertTrue("the adoption flags are read", route.contains("isLegacyWalletAdoptionSettled()") && route.contains("isLegacyWalletAdoptionInFlight()"))
        assertFalse("no direct hasKey:false answer on this route", route.contains("NoKeyGate.passcodeStatusFor(gate)"))
    }
}
