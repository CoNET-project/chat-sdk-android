package network.conet.chat

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ListenPolicyTest {
    @Test
    fun retryBacksOffExponentiallyUpTo30s() {
        val mid = 0.5 // no jitter
        assertEquals(2_000L, BeamioListenPolicy.retryDelayMs(1, mid))
        assertEquals(4_000L, BeamioListenPolicy.retryDelayMs(2, mid))
        assertEquals(8_000L, BeamioListenPolicy.retryDelayMs(3, mid))
        assertEquals(16_000L, BeamioListenPolicy.retryDelayMs(4, mid))
        assertEquals(30_000L, BeamioListenPolicy.retryDelayMs(5, mid))
        assertEquals(30_000L, BeamioListenPolicy.retryDelayMs(50, mid))
        // Zero or negative counts are treated as the first failure.
        assertEquals(2_000L, BeamioListenPolicy.retryDelayMs(0, mid))
    }

    @Test
    fun jitterStaysWithin20PercentAndUnderTheCap() {
        for (n in 1..10) {
            val lo = BeamioListenPolicy.retryDelayMs(n, 0.0)
            val hi = BeamioListenPolicy.retryDelayMs(n, 0.999)
            val mid = BeamioListenPolicy.retryDelayMs(n, 0.5)
            assertTrue(lo <= mid && mid <= hi)
            assertTrue(lo >= (mid * 0.8).toLong())
            assertTrue(hi <= BeamioListenPolicy.RETRY_MAX_MS)
        }
        // Twelve seconds of fixed retries is gone: after 4 failures the wait is ≥ 12.8 s.
        assertTrue(BeamioListenPolicy.retryDelayMs(4, 0.0) > 12_000L)
    }

    @Test
    fun pauseAppliesOnlyInTheBackgroundWithoutACall() {
        // Background, no call: pause.
        assertTrue(BeamioListenPolicy.pauseApplies(lifecycleKnown = true, inForeground = false, callInProgress = false))
        // Ringing / dialing / in a call: keep.
        assertFalse(BeamioListenPolicy.pauseApplies(lifecycleKnown = true, inForeground = false, callInProgress = true))
        // Foreground: keep.
        assertFalse(BeamioListenPolicy.pauseApplies(lifecycleKnown = true, inForeground = true, callInProgress = false))
        // A shell that never reports the app state: the page's pause applies as before.
        assertTrue(BeamioListenPolicy.pauseApplies(lifecycleKnown = false, inForeground = true, callInProgress = false))
    }

    @Test
    fun pageResumeDoesNotReopenInTheBackground() {
        assertFalse(BeamioListenPolicy.pageResumeApplies(lifecycleKnown = true, inForeground = false, callInProgress = false))
        assertTrue(BeamioListenPolicy.pageResumeApplies(lifecycleKnown = true, inForeground = false, callInProgress = true))
        assertTrue(BeamioListenPolicy.pageResumeApplies(lifecycleKnown = true, inForeground = true, callInProgress = false))
        assertTrue(BeamioListenPolicy.pageResumeApplies(lifecycleKnown = false, inForeground = false, callInProgress = false))
    }
}
