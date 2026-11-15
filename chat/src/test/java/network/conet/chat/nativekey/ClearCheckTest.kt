package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The identity clear's recovery check and removal of the migration records (spec 25.52PY.8 (1a), (1c), (3); PY.12).
 * The check removes nothing; the removal is run only after clear_pending is set. Reuses the migration fixtures.
 */
class ClearCheckTest {
    private val a = PgpMigrationKeys.a
    private val account = PgpMigrationKeys.ACCOUNT
    private val workspace = PgpMigrationKeys.WORKSPACE
    private val legacyA = legacyRecord(account, a.priv, a.pub)

    private fun seedRecords(files: NativeTestFiles, wrap: NativeTestWrap) {
        SealedStagedStore(wrap, files, account, workspace).write(StagedItem(account, a.fp, a.priv))
        SealedMarkerStore(wrap, files, account, workspace).write(MarkerItem(a.fp, "legacyPwa", 1L))
    }

    @Test
    fun checkRefusesWithoutARecoverySourceAndRemovesNothing() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        seedRecords(files, wrap)
        val result = migrationEngine(files, wrap, null, ChainAnswer.Absent, recovery = FixedRecovery(p = false, chain = false))
            .clearCheck(pgpRecordPresent = false)
        assertEquals(MigrationCode.UNREGISTER_REFUSED, result.code)
        assertNotNull("the staged record stays", files.read(stagedFileName()))
        assertNotNull("the marker stays", files.read(markerFileName()))
    }

    @Test
    fun checkPassesWithLegacyAsTheRecoverySourceAndStillRemovesNothing() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        seedRecords(files, wrap)
        val result = migrationEngine(files, wrap, legacyA, ChainAnswer.Absent).clearCheck(pgpRecordPresent = false)
        assertEquals(MigrationCode.OK, result.code)
        assertNotNull(files.read(stagedFileName()))
        assertNotNull(files.read(markerFileName()))
    }

    @Test
    fun aNativePgpRecordNeedsARecoverySourceEvenWithoutMigrationRecords() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        val refused = migrationEngine(files, wrap, null, ChainAnswer.Absent, recovery = FixedRecovery(p = false, chain = false))
            .clearCheck(pgpRecordPresent = true)
        assertEquals("(1c): the PGP record is present and no source exists", MigrationCode.UNREGISTER_REFUSED, refused.code)

        val passed = migrationEngine(files, wrap, legacyA, ChainAnswer.Absent).clearCheck(pgpRecordPresent = true)
        assertEquals("(1c) passes with L present", MigrationCode.OK, passed.code)
    }

    @Test
    fun withNothingToCheckTheCheckPasses() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        val result = migrationEngine(files, wrap, null, ChainAnswer.Absent, recovery = FixedRecovery(p = false, chain = false))
            .clearCheck(pgpRecordPresent = false)
        assertEquals(MigrationCode.OK, result.code)
    }

    @Test
    fun eraseRemovesTheStagedRecordTheMarkerAndTheLastCode() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        seedRecords(files, wrap)
        FileLastCodeStore(files, account, workspace).write("fingerprint_mismatch")
        val engine = migrationEngine(files, wrap, legacyA, ChainAnswer.Absent)
        assertTrue("the erase reports success", engine.clearErase())
        assertNull(files.read(stagedFileName()))
        assertNull(files.read(markerFileName()))
        assertNull(files.read(lastCodeFileName()))
    }
}
