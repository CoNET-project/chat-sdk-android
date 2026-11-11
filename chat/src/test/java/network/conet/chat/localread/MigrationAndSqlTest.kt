package network.conet.chat.localread

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/** spec r3a 7.1 (schema, key-range SQL text) and 11.1 / 11.3 (migration state machine). Pure JVM. */
class MigrationAndSqlTest {
    private val m = MigrationMachine

    @Test
    fun pwaPathReachesSwitchedThenPurged() {
        var s = MigrationState.NONE
        s = m.next(s, MigrationEvent.START)
        s = m.next(s, MigrationEvent.ROWS_IMPORTED)
        s = m.next(s, MigrationEvent.VERIFY_FAILED)
        assertEquals(MigrationState.RUNNING, s)
        s = m.next(s, MigrationEvent.VERIFIED)
        assertEquals(MigrationState.COMPLETE, s)
        assertFalse(m.canSwitchUi(s, readbackPassed = false))
        assertTrue(m.canSwitchUi(s, readbackPassed = true))
        s = m.next(s, MigrationEvent.READBACK_OK)
        s = m.next(s, MigrationEvent.SWITCH_UI)
        assertFalse(m.canPurge(MigrationState.COMPLETE))
        assertTrue(m.canPurge(s))
        s = m.next(s, MigrationEvent.PURGE)
        assertEquals(MigrationState.PURGED, s)
    }

    @Test
    fun readbackFailureRollsBackToRunningNeverToNone() {
        assertEquals(MigrationState.RUNNING, m.next(MigrationState.COMPLETE, MigrationEvent.READBACK_FAILED))
    }

    @Test
    fun androidFirstFullSyncGoesStraightToComplete() {
        assertEquals(MigrationState.COMPLETE, m.next(MigrationState.NONE, MigrationEvent.FIRST_FULL_SYNC))
    }

    @Test
    fun illegalTransitionsThrow() {
        assertIllegal { m.next(MigrationState.NONE, MigrationEvent.PURGE) }
        assertIllegal { m.next(MigrationState.RUNNING, MigrationEvent.SWITCH_UI) }
        assertIllegal { m.next(MigrationState.COMPLETE, MigrationEvent.PURGE) }
        assertIllegal { m.next(MigrationState.PURGED, MigrationEvent.START) }
    }

    @Test
    fun pageSqlHasKeyRangeAndBoundedLimit() {
        val first = SqlSchema.pageSql(hasCursor = false)
        assertTrue(first.contains("WHERE conv_blind = ? ORDER BY sort_ts DESC, stable_id DESC LIMIT ?"))
        assertEquals(2, SqlSchema.pageArgCount(false))
        val after = SqlSchema.pageSql(hasCursor = true)
        assertTrue(after.contains("(sort_ts < ? OR (sort_ts = ? AND stable_id < ?))"))
        assertEquals(5, SqlSchema.pageArgCount(true))
        assertTrue(SqlSchema.MAX_PAGE_ROWS >= 80)
    }

    @Test
    fun noPlaintextIdentityColumnsInSchema() {
        val msg = SqlSchema.DDL.first { it.contains("CREATE TABLE IF NOT EXISTS msg") }
        for (forbidden in listOf("send_id", "preview", "conv_key", "kind", "dir", "ts_prov")) {
            assertFalse("plaintext column $forbidden", msg.contains(" $forbidden "))
        }
        assertTrue(msg.contains("PRIMARY KEY (conv_blind, sort_ts, stable_id)"))
        assertEquals(7, SqlSchema.DDL.size)
    }

    private fun assertIllegal(block: () -> Unit) {
        try {
            block()
            fail("expected IllegalMigrationTransition")
        } catch (_: IllegalMigrationTransition) {
        }
    }
}
