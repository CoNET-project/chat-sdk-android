package network.conet.chat.passcode

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The session generation (gen; 2026-11-20): per account, in memory, only increasing, advanced by lock, logout and
 * account switch, and by nothing else. The reason is a closed set, so unlock, passcode change and passcode disable cannot advance it.
 */
class SessionGenerationTest {
    private val a = "0x39581c72b8c7d0de85ff22cf3ae178ae813957aa"
    private val b = "0x0cf9000000000000000000000000000000002022"

    @Test
    fun startsAtZeroForEveryAccount() {
        val gen = SessionGeneration()
        assertEquals(0L, gen.current(a))
        assertEquals(0L, gen.current(b))
    }

    @Test
    fun eachEndingOfASessionAdvancesByOne() {
        val gen = SessionGeneration()
        assertEquals(1L, gen.advance(a, SessionGeneration.Reason.LOCK))
        assertEquals(2L, gen.advance(a, SessionGeneration.Reason.LOGOUT))
        assertEquals(3L, gen.advance(a, SessionGeneration.Reason.ACCOUNT_SWITCH))
        assertEquals(3L, gen.current(a))
    }

    @Test
    fun aCapturedGenerationNoLongerMatchesAfterTheSessionEnds() {
        val gen = SessionGeneration()
        val gen0 = gen.current(a) // captured when the call is answered
        gen.advance(a, SessionGeneration.Reason.LOCK)
        assertTrue("the captured generation no longer matches", gen0 != gen.current(a))
    }

    @Test
    fun accountsAreCountedSeparately() {
        val gen = SessionGeneration()
        gen.advance(a, SessionGeneration.Reason.LOCK)
        gen.advance(a, SessionGeneration.Reason.LOCK)
        assertEquals(2L, gen.current(a))
        assertEquals("the other account is untouched", 0L, gen.current(b))
    }

    @Test
    fun theAccountKeyIsCaseInsensitive() {
        val gen = SessionGeneration()
        gen.advance(a.uppercase().replace("0X", "0x"), SessionGeneration.Reason.LOGOUT)
        assertEquals(1L, gen.current(a))
    }

    @Test
    fun itNeverDecreasesOverManyEndings() {
        val gen = SessionGeneration()
        var last = 0L
        val reasons = SessionGeneration.Reason.values()
        for (i in 0 until 500) {
            val next = gen.advance(a, reasons[i % reasons.size])
            assertTrue("strictly increasing at step $i", next > last)
            last = next
        }
        assertEquals(500L, gen.current(a))
    }
}
