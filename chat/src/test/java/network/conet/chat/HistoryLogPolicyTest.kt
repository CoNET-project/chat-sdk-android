package network.conet.chat

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class HistoryLogPolicyTest {
    @Test
    fun routineLinesStayNative() {
        assertFalse(HistoryLogPolicy.reachesPage("info"))
        assertFalse(HistoryLogPolicy.reachesPage("debug"))
        assertFalse(HistoryLogPolicy.reachesPage(""))
    }

    @Test
    fun problemsStillReachThePage() {
        assertTrue(HistoryLogPolicy.reachesPage("warn"))
        assertTrue(HistoryLogPolicy.reachesPage("WARN"))
        assertTrue(HistoryLogPolicy.reachesPage("warning"))
        assertTrue(HistoryLogPolicy.reachesPage("error"))
    }
}
