package network.conet.chat.nativekey

import network.conet.chat.nativekey.NativeWalletVault.PublishedWalletCopy
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException

/**
 * Forensics : the clear_pending marker itself cannot be read (not its owner: the read throws). What the product answers, and whether anything is
 * written or deleted, in each path. The marker read failure is [PendingOwner.Unknown] (clearPendingOwner catches every read exception).
 * The allowed set of the coming vector GB-05c is {clear_incomplete, not_ready, unregister_refused without a reason}.
 */
class ClearPendingMarkerUnreadableTest {
    private val x = "0x" + "a".repeat(40)

    /** A file set whose clear_pending read throws, and which counts every write and delete (of any name). */
    private class Faulty(val inner: NativeTestFiles = NativeTestFiles()) : VaultFiles by inner {
        var writes = 0
        var deletes = 0
        override fun read(name: String): ByteArray? = if (name == ClearFlagFiles.CLEAR_PENDING) throw IOException("read fault") else inner.read(name)
        override fun exists(name: String): Boolean = if (name == ClearFlagFiles.CLEAR_PENDING) throw IOException("read fault") else inner.exists(name)
        override fun write(name: String, bytes: ByteArray) { writes++; inner.write(name, bytes) }
        override fun delete(name: String) { deletes++; inner.delete(name) }
    }

    private class Counter { var erased = 0 }

    private fun clearer(files: VaultFiles, c: Counter, holds: Boolean, backup: Boolean, current: String?) = IdentityClear(
        flags = ClearFlagFiles(files),
        backupConfirmed = { backup },
        holdsWallet = { holds },
        eraseWallet = { c.erased++; true },
        eraseInbox = { c.erased++; true },
        reportLegacyAbsent = { c.erased++; true },
        clearPointer = { c.erased++; true },
        currentEoa = current,
    )

    @Test
    fun theUnreadableMarkerIsUnknown() {
        assertEquals(PendingOwner.Unknown, ClearFlagFiles(Faulty()).clearPendingOwner())
        assertFalse("the strict marker read is not 'set'", ClearFlagFiles(Faulty()).clearPendingStrict())
        assertFalse(clearResumable(PendingOwner.Unknown, null))
        assertFalse(clearResumable(PendingOwner.Unknown, x))
    }

    /** G0, manual clearIdentity: clear_incomplete, ahead of the key-only precheck (even with the published copy kept); nothing written or deleted. */
    @Test
    fun g0ManualAnswersClearIncompleteAndTouchesNothing() {
        for (copy in PublishedWalletCopy.values()) {
            val f = Faulty()
            val owner = ClearFlagFiles(f).clearPendingOwner()
            val pre = clearPrecheck(g2 = false, g0 = true, owner = owner, currentEoa = null, keyOnly = copy != PublishedWalletCopy.Absent,
                identityClearedStrict = ClearFlagFiles(f).identityClearedStrict(), vaultNoKey = true, copy = copy)
            assertEquals("copy $copy", ClearPrecheck.INCOMPLETE, pre)
            assertEquals(0, f.writes)
            assertEquals(0, f.deletes)
        }
    }

    /** Cold start and the retry at a command's gate: redoIfInterrupted answers clear_incomplete, erases nothing, writes nothing. */
    @Test
    fun theColdStartRedoAnswersClearIncompleteAndTouchesNothing() {
        val f = Faulty()
        val c = Counter()
        assertEquals(IdentityClearCode.CLEAR_INCOMPLETE, clearer(f, c, holds = false, backup = true, current = null).redoIfInterrupted())
        assertEquals(0, c.erased)
        assertEquals(0, f.writes)
        assertEquals(0, f.deletes)
    }

    /** With a current account (G2), the handler: the refusals run first; with them passed, the unknown marker answers clear_incomplete and nothing is written. */
    @Test
    fun aCurrentAccountHandlerAnswersClearIncompleteOnceItsOwnChecksPass() {
        val f = Faulty()
        val c = Counter()
        assertEquals(IdentityClearCode.CLEAR_INCOMPLETE, clearer(f, c, holds = true, backup = true, current = x).clear())
        assertEquals(0, c.erased)
        assertEquals("no marker or flag is written", 0, f.writes)
        assertEquals(0, f.deletes)
    }

    /** The account's own refusals still come first: an unconfirmed backup is unregister_refused with its reason (not part of the marker read). */
    @Test
    fun theAccountsOwnRefusalsAreNotHiddenByTheUnknownMarker() {
        val f = Faulty()
        val c = Counter()
        val ic = clearer(f, c, holds = true, backup = false, current = x)
        assertEquals(IdentityClearCode.UNREGISTER_REFUSED, ic.clear())
        assertEquals(ClearFlagFiles.REASON_BACKUP_UNCONFIRMED, ic.refusalReason)
        assertEquals(0, c.erased)
        assertEquals(0, f.writes)
        assertEquals(0, f.deletes)
    }

    /** A key-only current account with an unknown marker: the key-only refusal stands (the Unknown marker is not the account's own marker). */
    @Test
    fun aKeyOnlyCurrentAccountIsStillRefusedWithTheUnknownMarker() {
        val f = Faulty()
        val owner = ClearFlagFiles(f).clearPendingOwner()
        assertEquals(ClearPrecheck.REFUSED_KEY_ONLY,
            clearPrecheck(g2 = true, g0 = false, owner = owner, currentEoa = x, keyOnly = true, identityClearedStrict = false, vaultNoKey = false, copy = PublishedWalletCopy.Present))
        assertEquals(0, f.writes)
        assertEquals(0, f.deletes)
    }

    /** The orphan sweep and the redo scope rule never treat an unreadable marker as safe. */
    @Test
    fun theScopeRuleNeverCallsAnUnknownMarkerSafe() {
        assertEquals(false, redoScopeSafe(PendingOwner.Unknown, emptyList(), MnemonicSetStore.Current.Absent, PointerRead.None))
        assertTrue(!orphanSweepMayRun(ClearFlagFiles(Faulty())))
    }
}
