package network.conet.chat.nativekey

import network.conet.chat.nativekey.PgpMigrationKeys.ACCOUNT
import network.conet.chat.nativekey.PgpMigrationKeys.WORKSPACE
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException

/**
 * VaultFiles whose removal of a name for which [fails] is true does not take effect: it throws, as a failed platform removal does.
 * Other names behave as [inner]. Used only with the in-memory test files.
 */
internal class DeleteFailsFor(private val inner: VaultFiles, private val fails: (String) -> Boolean) : VaultFiles {
    override fun read(name: String): ByteArray? = inner.read(name)

    override fun write(name: String, bytes: ByteArray) = inner.write(name, bytes)

    override fun delete(name: String) {
        if (fails(name)) throw IOException("cannot remove")
        inner.delete(name)
    }
}

/**
 * 25.52Y.84 (coordinator, 2026-11-16): a removal in the PGP migration that does not take effect is never a silent success. Each site below
 * has one test. The names are the store suffixes: `.n` (staged), `.m` (marker), `.last` (last code).
 */
class PgpDeleteFailureTest {
    private val wrap = NativeTestWrap()
    private val legacyA = legacyRecord(ACCOUNT, PgpMigrationKeys.a.priv, PgpMigrationKeys.a.pub)

    private fun endsWith(suffix: String): (String) -> Boolean = { it.endsWith(suffix) }

    /** Unregister, the marker removal (verifies the site at the marker removal in unregisterRun). */
    @Test
    fun unregisterMarkerRemovalThatFailsIsClearIncompleteAndTheMarkerStays() {
        val base = NativeTestFiles()
        SealedMarkerStore(wrap, base, ACCOUNT, WORKSPACE).write(MarkerItem(PgpMigrationKeys.a.fp, "legacyPwa", 1L))
        val files = DeleteFailsFor(base, endsWith(".m"))

        val result = migrationEngine(files, wrap, legacyA, ChainAnswer.Absent).unregister()

        assertEquals(MigrationCode.CLEAR_INCOMPLETE, result.code)
        assertTrue("the marker is still there", base.map.keys.any { it.endsWith(".m") })
    }

    /** Unregister, the staged removal (the site at the staged removal in unregisterRun). */
    @Test
    fun unregisterStagedRemovalThatFailsIsClearIncompleteAndTheStagedItemStays() {
        val base = NativeTestFiles()
        SealedStagedStore(wrap, base, ACCOUNT, WORKSPACE).write(StagedItem(ACCOUNT, PgpMigrationKeys.a.fp, PgpMigrationKeys.a.priv))
        val files = DeleteFailsFor(base, endsWith(".n"))

        val result = migrationEngine(files, wrap, legacyA, ChainAnswer.Absent).unregister()

        assertEquals(MigrationCode.CLEAR_INCOMPLETE, result.code)
        assertTrue("the staged item is still there", base.map.keys.any { it.endsWith(".n") })
    }

    /** Unregister with only the last code present (the site at the first branch of unregisterRun). */
    @Test
    fun unregisterLastCodeRemovalThatFailsIsClearIncompleteAndTheCodeStays() {
        val base = NativeTestFiles()
        FileLastCodeStore(base, ACCOUNT, WORKSPACE).write("fingerprint_mismatch")
        val files = DeleteFailsFor(base, endsWith(".last"))

        val result = migrationEngine(files, wrap, null, ChainAnswer.Absent).unregister()

        assertEquals(MigrationCode.CLEAR_INCOMPLETE, result.code)
        assertTrue("the last code is still there", base.map.keys.any { it.endsWith(".last") })
    }

    /**
     * The rollback of our own staged write on a rejected verification (the site in verifyStaged's reject): when that removal does not take
     * effect the write is still there, so the run reports write_failed and never the reject code as if the rollback were done.
     */
    @Test
    fun aRejectWhoseStagedRollbackFailsIsWriteFailedAndTheStagedWriteStays() {
        val base = NativeTestFiles()
        val files = DeleteFailsFor(base, endsWith(".n"))

        val result = migrationEngine(
            files,
            wrap,
            legacyA,
            ChainAnswer.Found(PgpMigrationKeys.a.fp),
            MigrationFaults(challengeOnReread = true),
        ).run()

        assertEquals(MigrationCode.WRITE_FAILED, result.code)
        assertTrue("the staged write is still there", base.map.keys.any { it.endsWith(".n") })
    }
}
