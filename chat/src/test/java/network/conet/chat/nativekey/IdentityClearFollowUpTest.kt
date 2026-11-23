package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Follow-up of and: the identity_cleared markers are written by the redo before
 * clear_pending is consumed (a failure answers clear_incomplete and keeps the clear pending); an unconfirmed backup answers unregister_refused with the
 * reason backup_unconfirmed and writes nothing; the create guard allows a create when the identity_cleared state holds a found (kept) legacy copy, and
 * only then.
 */
class IdentityClearFollowUpTest {

    private fun clearer(files: NativeTestFiles, holds: Boolean, backup: Boolean, markCleared: () -> Boolean): IdentityClear = IdentityClear(
        flags = ClearFlagFiles(files),
        backupConfirmed = { backup },
        migrationCheck = { true },
        pgpRecordPresent = { false },
        pgpSourceAvailable = { true },
        holdsWallet = { holds },
        eraseWallet = { true },
        eraseInbox = { true },
        reportLegacyAbsent = { true },
        clearPointer = { true },
        markCleared = markCleared,
    )

    /** Positive (reason): a held wallet without the backup confirmed is refused with backup_unconfirmed, and nothing is written. */
    @Test
    fun anUnconfirmedBackupRefusesWithTheReasonAndWritesNothing() {
        val files = NativeTestFiles()
        val ic = clearer(files, holds = true, backup = false) { error("the marker must not be written on a refusal") }
        assertEquals(IdentityClearCode.UNREGISTER_REFUSED, ic.clear())
        assertEquals(ClearFlagFiles.REASON_BACKUP_UNCONFIRMED, ic.refusalReason)
        assertTrue("nothing is written on a refusal", files.map.isEmpty())
    }

    /** Negative (blocker 1): a marker write that fails answers clear_incomplete and keeps clear_pending; the redo writes the marker and completes. */
    @Test
    fun aFailedMarkerWriteKeepsTheClearPendingAndTheRedoCompletes() {
        val files = NativeTestFiles()
        var markerOk = false
        var attempts = 0
        val ic = clearer(files, holds = false, backup = true) { attempts++; markerOk }
        assertEquals("a failed marker write is not ok", IdentityClearCode.CLEAR_INCOMPLETE, ic.clear())
        assertTrue("clear_pending stays set", ClearFlagFiles(files).clearPendingState() == true)
        markerOk = true
        assertEquals("the redo writes the marker and completes", IdentityClearCode.OK, ic.redoIfInterrupted())
        assertEquals("the marker was attempted on each redo", 2, attempts)
        assertFalse("clear_pending is consumed after the marker", ClearFlagFiles(files).clearPendingState() == true)
    }

    /** Positive (blocker 2): after an identity clear the kept legacy copy (found) does not block a create; the same found does block without the marker. */
    @Test
    fun aKeptLegacyCopyDoesNotBlockACreateOnlyAfterTheIdentityClear() {
        val cleared = CreateGuardInputs(
            key = KeyState.NONE, legacyReport = LegacyReportState.FOUND, legacyUnreadable = false,
            pointer = false, pageCopy = false, migrating = false, identityCleared = true,
        )
        assertNull("the create is allowed after the identity clear", AccountCreateGuard.denial(cleared))
        val notCleared = cleared.copy(identityCleared = false)
        assertEquals("without the marker the found copy keeps the existing refusal", AccountCreateGuard.MIGRATING, AccountCreateGuard.denial(notCleared))
    }

    /** Negative: an unreadable legacy report is never allowed, even after the identity clear. */
    @Test
    fun anUnreadableLegacyReportStillBlocksACreate() {
        val inputs = CreateGuardInputs(
            key = KeyState.NONE, legacyReport = LegacyReportState.UNREADABLE, legacyUnreadable = false,
            pointer = false, pageCopy = false, migrating = false, identityCleared = true,
        )
        assertEquals(AccountCreateGuard.MIGRATING, AccountCreateGuard.denial(inputs))
    }
}
