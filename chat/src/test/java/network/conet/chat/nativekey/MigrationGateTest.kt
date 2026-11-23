package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Hotfix (S25 ANR): a legacy adoption runs once per process when definitive, and a read fault is retried only after a delay. */
class MigrationGateTest {
    private class Clock(var t: Long = 1_000L) { fun now(): Long = t }

    @Test fun commandsAfterAnAdoptionNeverOpenTheKeystoreAgain() {
        val clock = Clock()
        val gate = MigrationGate(now = clock::now)
        var attempts = 0
        repeat(200) {
            gate.run { attempts++; MigrationGate.Outcome.RESOLVED_ADOPTED }
        }
        assertEquals("one attempt for 200 commands", 1, attempts)
        assertTrue(gate.isResolved())
    }

    @Test fun aDefinitiveNothingIsRememberedToo() {
        val clock = Clock()
        val gate = MigrationGate(now = clock::now)
        var attempts = 0
        repeat(50) { gate.run { attempts++; MigrationGate.Outcome.RESOLVED_NOTHING } }
        assertEquals(1, attempts)
    }

    @Test fun anUnknownResultIsRetriedOnlyAfterTheDelay() {
        val clock = Clock()
        val gate = MigrationGate(now = clock::now, retryMillis = 30_000L)
        var attempts = 0
        // 100 commands within the window: one attempt
        repeat(100) { gate.run { attempts++; MigrationGate.Outcome.UNKNOWN } }
        assertEquals(1, attempts)
        clock.t += 29_999L
        gate.run { attempts++; MigrationGate.Outcome.UNKNOWN }
        assertEquals("still inside the window", 1, attempts)
        clock.t += 1L
        assertFalse(gate.run { attempts++; MigrationGate.Outcome.UNKNOWN })
        assertEquals("retried once the window has passed", 2, attempts)
    }

    @Test fun anUnknownThatBecomesDefinitiveStopsTheRetries() {
        val clock = Clock()
        val gate = MigrationGate(now = clock::now, retryMillis = 1_000L)
        var attempts = 0
        gate.run { attempts++; MigrationGate.Outcome.UNKNOWN }
        clock.t += 1_000L
        assertTrue(gate.run { attempts++; MigrationGate.Outcome.RESOLVED_ADOPTED })
        repeat(20) { clock.t += 5_000L; gate.run { attempts++; MigrationGate.Outcome.UNKNOWN } }
        assertEquals("no attempt after the adoption", 2, attempts)
    }

    @Test fun anAttemptThatThrowsIsUnknownAndRateLimited() {
        val clock = Clock()
        val gate = MigrationGate(now = clock::now, retryMillis = 10_000L)
        var attempts = 0
        repeat(30) { gate.run { attempts++; throw IllegalStateException("keystore") } }
        assertEquals(1, attempts)
        assertFalse(gate.isResolved())
    }
}
