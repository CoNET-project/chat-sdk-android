package network.conet.chat

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class HistoryLogPolicyTest {
    @Test
    fun routineLinesStayNative() {
        assertFalse(HistoryLogPolicy.reachesPage("info", "[history] synced records=1626 localOnly=1"))
        assertFalse(HistoryLogPolicy.reachesPage("info", "[history] pointer updated records=1627 index=0x39…de77"))
        assertFalse(HistoryLogPolicy.reachesPage("info", "[history] head adopted records=1626 previous=1626 requeued=0 pending=1"))
        assertFalse(HistoryLogPolicy.reachesPage("info", "[history] batch written entries=3 records=1629 index=0x01"))
        assertFalse(HistoryLogPolicy.reachesPage("debug", "[history] load peer=all records=10 tail=10 older=0"))
        assertFalse(HistoryLogPolicy.reachesPage("info", "[history] readiness check"))
    }

    @Test
    fun problemsStillReachThePage() {
        assertTrue(HistoryLogPolicy.reachesPage("warn", "[history] storageFragment HTTP 500"))
        assertTrue(HistoryLogPolicy.reachesPage("WARN", "x"))
        assertTrue(HistoryLogPolicy.reachesPage("warning", "x"))
        assertTrue(HistoryLogPolicy.reachesPage("error", "x"))
    }

    /** The page waits for `[history] ready` (info) before any history call (nativeConetChatTransport). */
    @Test
    fun lifecycleLinesThePageReadsStillReachIt() {
        assertTrue(HistoryLogPolicy.reachesPage("info", "[history] ready genesis=0x12…ab pending=0"))
        assertTrue(HistoryLogPolicy.reachesPage("info", "[history] prepare failed: timeout"))
        assertTrue(HistoryLogPolicy.reachesPage("info", "[history] domain sign failed"))
        assertTrue(HistoryLogPolicy.reachesPage("info", "[history] hkdf failed"))
    }
}
