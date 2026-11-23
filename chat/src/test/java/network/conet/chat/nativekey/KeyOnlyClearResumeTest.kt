package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The key-only precheck, the resume gate and the owner of clear_pending (2026-11-22).
 * Synthetic EOAs only.
 */
class KeyOnlyClearResumeTest {

    private val x = "0x" + "a".repeat(40)
    private val y = "0x" + "b".repeat(40)

    /** The precheck refuses a key-only account unless its own marker names it. Any other owner, absent or unknown marker still refuses. */
    @Test
    fun theKeyOnlyPrecheckRefusesUnlessTheMarkerNamesTheCurrentAccount() {
        assertTrue("no marker: refused", keyOnlyClearRefused(true, PendingOwner.Absent, x))
        assertTrue("unknown marker: refused", keyOnlyClearRefused(true, PendingOwner.Unknown, x))
        assertTrue("marker of another account: refused", keyOnlyClearRefused(true, PendingOwner.Owned(y), x))
        assertTrue("no-account marker: refused", keyOnlyClearRefused(true, PendingOwner.NoAccount, x))
        assertFalse("its own marker: the redo path is reached", keyOnlyClearRefused(true, PendingOwner.Owned(x), x))
        assertFalse("its own marker, upper case: the redo path is reached", keyOnlyClearRefused(true, PendingOwner.Owned(x), x.uppercase().replaceFirst("0X", "0x")))
        assertFalse("not key-only: never refused here", keyOnlyClearRefused(false, PendingOwner.Absent, x))
        assertFalse("not key-only, unknown marker: never refused here", keyOnlyClearRefused(false, PendingOwner.Unknown, null))
    }

    /** The gate resumes only the account the marker names; with no current account (G0) an account or no-account marker resumes. */
    @Test
    fun theGateResumesOnlyTheNamedAccount() {
        assertTrue(clearResumable(PendingOwner.Owned(x), x))
        assertFalse("another account does not resume X's clear", clearResumable(PendingOwner.Owned(x), y))
        assertFalse("G0 (no current account) does not resume an account marker", clearResumable(PendingOwner.Owned(x), null))
        assertTrue("G0 resumes a no-account marker", clearResumable(PendingOwner.NoAccount, null))
        assertFalse("a no-account marker is not resumed by an account", clearResumable(PendingOwner.NoAccount, x))
        assertFalse("an unknown marker never resumes", clearResumable(PendingOwner.Unknown, x))
        assertFalse("an unknown marker never resumes with no account", clearResumable(PendingOwner.Unknown, null))
        assertFalse("no marker never resumes", clearResumable(PendingOwner.Absent, x))
    }

    private fun clearer(files: NativeTestFiles, holds: Boolean, backup: Boolean, current: String?, markCleared: () -> Boolean = { true }): IdentityClear =
        IdentityClear(
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
            currentEoa = current,
        )

    /**
     * G0 (no current account) with an account marker: no resume at the gate, and the clear (which records the current account, none here) refuses
     * with clear_incomplete. Nothing is deleted or written.
     */
    @Test
    fun g0WithAnAccountMarkerDoesNotResumeAndDeletesNothing() {
        val files = NativeTestFiles()
        assertTrue(ClearFlagFiles(files).setClearPending(x))
        val before = files.map.toMap()
        assertFalse(clearResumable(ClearFlagFiles(files).clearPendingOwner(), null))
        var wrote = false
        val ic = IdentityClear(
            flags = ClearFlagFiles(files),
            backupConfirmed = { true },
            holdsWallet = { false },
            eraseWallet = { wrote = true; true },
            eraseInbox = { wrote = true; true },
            reportLegacyAbsent = { wrote = true; true },
            clearPointer = { wrote = true; true },
            currentEoa = null,
        )
        assertEquals(IdentityClearCode.CLEAR_INCOMPLETE, ic.clear())
        assertFalse("nothing is deleted or written", wrote)
        assertEquals(before, files.map.toMap())
    }

    @Test
    fun theMarkerRecordsItsOwnerAndReadsItBack() {
        val files = NativeTestFiles()
        assertTrue(ClearFlagFiles(files).setClearPending(x))
        assertEquals(PendingOwner.Owned(x), ClearFlagFiles(files).clearPendingOwner())
        assertTrue(ClearFlagFiles(files).setClearPending(null))
        assertEquals(PendingOwner.NoAccount, ClearFlagFiles(files).clearPendingOwner())
        assertFalse("a malformed owner is not written", ClearFlagFiles(files).setClearPending("not-an-eoa"))
    }

    /** A marker written before the owner was recorded (`1`) is unknown: it resumes nothing and nothing is deleted. */
    @Test
    fun aLegacyMarkerIsUnknownAndDeletesNothing() {
        val files = NativeTestFiles()
        files.map[ClearFlagFiles.CLEAR_PENDING] = "1".toByteArray(Charsets.UTF_8)
        val before = files.map.toMap()
        assertEquals(PendingOwner.Unknown, ClearFlagFiles(files).clearPendingOwner())
        assertEquals(IdentityClearCode.CLEAR_INCOMPLETE, clearer(files, holds = false, backup = true, current = x).redoIfInterrupted())
        assertEquals(IdentityClearCode.CLEAR_INCOMPLETE, clearer(files, holds = false, backup = true, current = x).clear())
        assertEquals("nothing is written or deleted for an unknown marker", before, files.map.toMap())
    }

    /** The marker of account X blocks account Y's clear: Y's own checks run first, and no byte of the device changes. */
    @Test
    fun anotherAccountCannotClearOverTheMarkerOfX() {
        val files = NativeTestFiles()
        assertTrue(ClearFlagFiles(files).setClearPending(x))
        val before = files.map.toMap()
        var markerWritten = false
        val forY = clearer(files, holds = false, backup = true, current = y) { markerWritten = true; true }
        assertEquals(IdentityClearCode.CLEAR_INCOMPLETE, forY.clear())
        assertFalse("no identity_cleared marker is written for Y", markerWritten)
        assertEquals("X's marker and the device are unchanged", before, files.map.toMap())
        assertEquals(PendingOwner.Owned(x), ClearFlagFiles(files).clearPendingOwner())
    }

    /** Y's own checks still refuse first: an unconfirmed backup of a held wallet is refused with its reason, and nothing changes. */
    @Test
    fun anotherAccountStillMeetsItsOwnChecksFirst() {
        val files = NativeTestFiles()
        assertTrue(ClearFlagFiles(files).setClearPending(x))
        val before = files.map.toMap()
        val forY = clearer(files, holds = true, backup = false, current = y)
        assertEquals(IdentityClearCode.UNREGISTER_REFUSED, forY.clear())
        assertEquals(ClearFlagFiles.REASON_BACKUP_UNCONFIRMED, forY.refusalReason)
        assertEquals(before, files.map.toMap())
    }

    /** X's redo clears X's interrupted clear and consumes its own marker; the redo is the one named by the marker. */
    @Test
    fun theNamedAccountRedoCompletesAndConsumesItsMarker() {
        val files = NativeTestFiles()
        assertTrue(ClearFlagFiles(files).setClearPending(x))
        val ic = clearer(files, holds = false, backup = true, current = x)
        assertEquals(IdentityClearCode.OK, ic.redoIfInterrupted())
        assertEquals(PendingOwner.Absent, ClearFlagFiles(files).clearPendingOwner())
    }

    /**
     * The same account, with the wallet still held and the backup confirmed before the clear started: clear() runs the full checks again and
     * completes; the marker is rewritten with the same owner and then consumed.
     */
    @Test
    fun theSameAccountResumeWithTheConfirmedBackupCompletes() {
        val files = NativeTestFiles()
        assertTrue(ClearFlagFiles(files).setClearPending(x))
        var markerWritten = false
        val ic = clearer(files, holds = true, backup = true, current = x) { markerWritten = true; true }
        assertEquals(IdentityClearCode.OK, ic.clear())
        assertTrue("the markers are written by the redo", markerWritten)
        assertEquals(PendingOwner.Absent, ClearFlagFiles(files).clearPendingOwner())
    }

    /** An interrupted clear with the wallet still held is not redone at start-up (the block stays). */
    @Test
    fun aHeldWalletKeepsTheRedoBlocked() {
        val files = NativeTestFiles()
        assertTrue(ClearFlagFiles(files).setClearPending(x))
        val before = files.map.toMap()
        assertEquals(IdentityClearCode.CLEAR_INCOMPLETE, clearer(files, holds = true, backup = true, current = x).redoIfInterrupted())
        assertEquals(before, files.map.toMap())
    }
}
