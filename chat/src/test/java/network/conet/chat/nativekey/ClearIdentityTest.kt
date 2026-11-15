package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The identity clear (spec 25.52PY.8, PY.9, PY.10, PY.12; r3qr). Each step is a fake that records its call, so the order, the
 * failure rule and the redo are checked without the platform. The flags live in a [NativeTestFiles] that survives a "restart".
 */
class ClearIdentityTest {
    private class Steps(val files: NativeTestFiles) {
        val log = mutableListOf<String>()
        var holds: Boolean? = true
        var wallet = true
        var inbox = true
        var legacy = true
        var pointer = true
        var migrationOk = true
        var pgpPresent = false
        var pgpSource = true

        fun build(): IdentityClear = IdentityClear(
            flags = ClearFlagFiles(files),
            migrationCheck = { migrationOk },
            pgpRecordPresent = { pgpPresent },
            pgpSourceAvailable = {
                log += "pgpSource"
                pgpSource
            },
            holdsWallet = {
                log += "holds"
                holds
            },
            eraseWallet = {
                log += "wallet:pending=${files.map.containsKey(ClearFlagFiles.CLEAR_PENDING)}"
                wallet
            },
            eraseInbox = {
                log += "inbox"
                inbox
            },
            reportLegacyAbsent = {
                log += "legacy"
                legacy
            },
            clearPointer = {
                log += "pointer"
                pointer
            },
        )
    }

    private fun confirmBackup(files: NativeTestFiles) {
        files.map[ClearFlagFiles.BACKUP_CONFIRMED] = byteArrayOf(1)
    }

    @Test
    fun withoutWalletTheStepsRunInOrderAndOkIsLast() {
        val files = NativeTestFiles()
        val s = Steps(files).apply { holds = false }
        assertEquals(IdentityClearCode.OK, s.build().clear())
        assertEquals(listOf("holds", "wallet:pending=true", "inbox", "legacy", "pointer"), s.log)
        assertFalse("clear_pending is cleared as the last step", files.map.containsKey(ClearFlagFiles.CLEAR_PENDING))
    }

    @Test
    fun walletWithoutBackupConfirmationIsRefusedAndNothingIsDeleted() {
        val files = NativeTestFiles()
        val s = Steps(files).apply { holds = true }
        assertEquals(IdentityClearCode.UNREGISTER_REFUSED, s.build().clear())
        assertEquals(listOf("holds"), s.log)
        assertFalse(files.map.containsKey(ClearFlagFiles.CLEAR_PENDING))
    }

    @Test
    fun walletWithBackupConfirmationRunsTheSteps() {
        val files = NativeTestFiles()
        confirmBackup(files)
        val s = Steps(files).apply { holds = true }
        assertEquals(IdentityClearCode.OK, s.build().clear())
        assertEquals(listOf("holds", "wallet:pending=true", "inbox", "legacy", "pointer"), s.log)
    }

    @Test
    fun unreadableStorageIsRefusedBecauseNoWalletCanBeRuledOut() {
        val files = NativeTestFiles()
        confirmBackup(files)
        val s = Steps(files).apply { holds = null }
        assertEquals(IdentityClearCode.UNREGISTER_REFUSED, s.build().clear())
        assertEquals(listOf("holds"), s.log)
    }

    @Test
    fun aDamagedBackupFlagCountsAsNotConfirmed() {
        val files = NativeTestFiles()
        files.map[ClearFlagFiles.BACKUP_CONFIRMED] = byteArrayOf(2)
        val s = Steps(files).apply { holds = true }
        assertEquals(IdentityClearCode.UNREGISTER_REFUSED, s.build().clear())
    }

    @Test
    fun aWalletEraseFailureIsIncompleteAndTheInboxIsStillAttempted() {
        val files = NativeTestFiles()
        val s = Steps(files).apply { holds = false; wallet = false }
        assertEquals(IdentityClearCode.CLEAR_INCOMPLETE, s.build().clear())
        assertEquals(listOf("holds", "wallet:pending=true", "inbox"), s.log)
        assertTrue("clear_pending kept", files.map.containsKey(ClearFlagFiles.CLEAR_PENDING))
    }

    @Test
    fun anInboxFailureIsIncompleteAndKeepsThePointer() {
        val files = NativeTestFiles()
        val s = Steps(files).apply { holds = false; inbox = false }
        assertEquals(IdentityClearCode.CLEAR_INCOMPLETE, s.build().clear())
        assertFalse("the pointer step is not reached", s.log.contains("pointer"))
        assertTrue(files.map.containsKey(ClearFlagFiles.CLEAR_PENDING))
    }

    @Test
    fun aLegacyReportFailureIsIncompleteAndTheMarkerStays() {
        val files = NativeTestFiles()
        val s = Steps(files).apply { holds = false; legacy = false }
        assertEquals(IdentityClearCode.CLEAR_INCOMPLETE, s.build().clear())
        assertFalse(s.log.contains("pointer"))
        assertTrue(files.map.containsKey(ClearFlagFiles.CLEAR_PENDING))
    }

    @Test
    fun aPointerFailureIsIncompleteAndTheMarkerStays() {
        val files = NativeTestFiles()
        val s = Steps(files).apply { holds = false; pointer = false }
        assertEquals(IdentityClearCode.CLEAR_INCOMPLETE, s.build().clear())
        assertTrue(files.map.containsKey(ClearFlagFiles.CLEAR_PENDING))
    }

    @Test
    fun aFailedClearOfTheMarkerIsIncomplete() {
        val files = NativeTestFiles()
        files.failDelete = ClearFlagFiles.CLEAR_PENDING
        val s = Steps(files).apply { holds = false }
        assertEquals(IdentityClearCode.CLEAR_INCOMPLETE, s.build().clear())
    }

    @Test
    fun aMarkerThatCannotBeSetStopsBeforeAnyDeletion() {
        val files = NativeTestFiles()
        files.failWrite = ClearFlagFiles.CLEAR_PENDING
        val s = Steps(files).apply { holds = false }
        assertEquals(IdentityClearCode.CLEAR_INCOMPLETE, s.build().clear())
        assertEquals(listOf("holds"), s.log)
    }

    @Test
    fun aRedoAfterAnIncompleteClearCompletesAndReleasesTheMarker() {
        val files = NativeTestFiles()
        val s = Steps(files).apply { holds = false; wallet = false }
        assertEquals(IdentityClearCode.CLEAR_INCOMPLETE, s.build().clear())
        s.wallet = true
        s.log.clear()
        assertEquals(IdentityClearCode.OK, s.build().redoIfInterrupted())
        assertEquals(listOf("holds", "wallet:pending=true", "inbox", "legacy", "pointer"), s.log)
        assertFalse(files.map.containsKey(ClearFlagFiles.CLEAR_PENDING))
    }

    @Test
    fun theMarkerSurvivesARestart() {
        val files = NativeTestFiles()
        val s = Steps(files).apply { holds = false; pointer = false }
        assertEquals(IdentityClearCode.CLEAR_INCOMPLETE, s.build().clear())
        assertTrue("a new process sees the marker", ClearFlagFiles(files).clearPending())
    }

    @Test
    fun aRestartRedoRunsOnlyWhenTheMarkerIsSetAndNoWalletIsHeld() {
        val files = NativeTestFiles()
        files.map[ClearFlagFiles.CLEAR_PENDING] = byteArrayOf(1)
        val held = Steps(files).apply { holds = true }
        assertNull(held.build().redoIfInterrupted())
        assertTrue("nothing is erased while a wallet is held", held.log == listOf("holds"))

        val none = Steps(files).apply { holds = false }
        assertEquals(IdentityClearCode.OK, none.build().redoIfInterrupted())
        assertFalse(files.map.containsKey(ClearFlagFiles.CLEAR_PENDING))
    }

    @Test
    fun noMarkerMeansNoRedo() {
        val files = NativeTestFiles()
        val s = Steps(files).apply { holds = false }
        assertNull(s.build().redoIfInterrupted())
        assertTrue("with no marker nothing is read or erased", s.log.isEmpty())
    }

    @Test
    fun theRecoveryBackupFlagSetsReadsAndClears() {
        val files = NativeTestFiles()
        val flags = ClearFlagFiles(files)
        assertFalse(flags.recoveryBackupConfirmed())
        assertTrue(flags.setRecoveryBackupConfirmed())
        assertTrue(flags.recoveryBackupConfirmed())
        assertTrue(flags.clearRecoveryBackupConfirmed())
        assertFalse(flags.recoveryBackupConfirmed())
    }

    @Test
    fun theLegacyReportIsWrittenAsAFlagFileAndIsNotTheUnreadableMarker() {
        val files = NativeTestFiles()
        assertTrue(ClearFlagFiles(files).writeLegacyReportAbsent())
        assertEquals("absent", String(files.map[ClearFlagFiles.LEGACY_REPORT]!!, Charsets.UTF_8))
        assertFalse("the unreadable marker is not set", files.map.containsKey("legacy_store_unreadable.v1"))
    }

    @Test
    fun eraseCheckedReportsAFileThatCannotBeRemoved() {
        val files = NativeTestFiles()
        files.map["x"] = byteArrayOf(1)
        files.failDelete = "x"
        assertFalse(eraseChecked(files, "x"))
        files.failDelete = null
        assertTrue(eraseChecked(files, "x"))
        assertTrue("an absent file is gone", eraseChecked(files, "x"))
    }

    @Test
    fun aMigrationRefusalChangesNothing() {
        val files = NativeTestFiles()
        val s = Steps(files).apply { holds = false; migrationOk = false }
        assertEquals(IdentityClearCode.UNREGISTER_REFUSED, s.build().clear())
        assertTrue("a migration refusal is decided before any step is recorded", s.log.isEmpty())
        assertFalse(files.map.containsKey(ClearFlagFiles.CLEAR_PENDING))
    }

    @Test
    fun aNativePgpRecordWithoutARecoverySourceRefusesBeforeAnyWrite() {
        val files = NativeTestFiles()
        val s = Steps(files).apply { holds = false; pgpPresent = true; pgpSource = false }
        assertEquals(IdentityClearCode.UNREGISTER_REFUSED, s.build().clear())
        assertEquals("(1c) is checked before clear_pending, and nothing is erased", listOf("holds", "pgpSource"), s.log)
        assertFalse(files.map.containsKey(ClearFlagFiles.CLEAR_PENDING))
    }

    @Test
    fun aNativePgpRecordWithARecoverySourceProceedsToTheErase() {
        val files = NativeTestFiles()
        val s = Steps(files).apply { holds = false; pgpPresent = true; pgpSource = true }
        assertEquals(IdentityClearCode.OK, s.build().clear())
        assertTrue(s.log.contains("wallet:pending=true"))
    }

    @Test
    fun withoutAPgpRecordTheSourceCheckIsSkipped() {
        val files = NativeTestFiles()
        val s = Steps(files).apply { holds = false; pgpPresent = false; pgpSource = false }
        assertEquals(IdentityClearCode.OK, s.build().clear())
        assertFalse("no PGP record, so (1c) is not evaluated", s.log.contains("pgpSource"))
    }

    @Test
    fun aMigrationRecordNameGivesItsAccountOnlyForTheThreeRecordKinds() {
        val hex = "a".repeat(40)
        assertEquals("0x$hex", migrationAccountOfName("pgp.v1.mig.$hex.default.n"))
        assertEquals("0x$hex", migrationAccountOfName("pgp.v1.mig.$hex.default.m"))
        assertEquals("0x$hex", migrationAccountOfName("pgp.v1.mig.$hex.default.last"))
        assertNull("a short address is not a record", migrationAccountOfName("pgp.v1.mig.abc.default.n"))
        assertNull("the native PGP record is not a migration record", migrationAccountOfName("pgp.v1.a1b2.rec"))
        assertNull("wallet files are not migration records", migrationAccountOfName("wallet.v1.rec"))
    }

    @Test
    fun theOrphanSweepRunsOnlyWhenAnInterruptedClearIsMarked() {
        val absent = NativeTestFiles()
        assertFalse("no marker, no sweep", orphanSweepMayRun(ClearFlagFiles(absent)))

        val marked = NativeTestFiles()
        marked.map[ClearFlagFiles.CLEAR_PENDING] = byteArrayOf(1)
        assertTrue("an interrupted clear is marked", orphanSweepMayRun(ClearFlagFiles(marked)))

        val unreadable = object : VaultFiles {
            override fun read(name: String): ByteArray? = throw java.io.IOException("unreadable")
            override fun write(name: String, bytes: ByteArray) = Unit
            override fun delete(name: String) = Unit
        }
        assertFalse("an unreadable marker counts as not set", orphanSweepMayRun(ClearFlagFiles(unreadable)))
    }
}
