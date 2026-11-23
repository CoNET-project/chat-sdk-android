package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Test

/** The snapshot refresh backoff: 1 s, 2 s, 4 s, …, capped at 30 s; cleared by one success. Rule-level. */
class VaultSnapshotBackoffTest {
    @Test
    fun noFailureNoBackoff() {
        assertEquals(0L, VaultSnapshotRefresh.backoffMs(0))
    }

    @Test
    fun doublesFromOneSecond() {
        assertEquals(1_000L, VaultSnapshotRefresh.backoffMs(1))
        assertEquals(2_000L, VaultSnapshotRefresh.backoffMs(2))
        assertEquals(4_000L, VaultSnapshotRefresh.backoffMs(3))
        assertEquals(8_000L, VaultSnapshotRefresh.backoffMs(4))
        assertEquals(16_000L, VaultSnapshotRefresh.backoffMs(5))
    }

    @Test
    fun cappedAtThirtySeconds() {
        assertEquals(30_000L, VaultSnapshotRefresh.backoffMs(6))
        assertEquals(30_000L, VaultSnapshotRefresh.backoffMs(7))
        assertEquals(30_000L, VaultSnapshotRefresh.backoffMs(100))
    }
}
