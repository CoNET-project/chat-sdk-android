package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * G0 plan B (owner): the automatic finish of an interrupted clear (cold start, and the retry at a command's gate) runs only for the recorded
 * account X, with every read successful and no other account's entry in the scope of the erase. Anything else deletes and writes nothing and keeps
 * the marker. Synthetic EOAs only. The six examples of item 6 are the first six tests.
 */
class G0PlanBRedoTest {
    private val x = "0x" + "a".repeat(40)
    private val y = "0x" + "b".repeat(40)
    private fun bare(e: String) = e.removePrefix("0x")
    private fun xPgp() = listOf("pgp.v1.${bare(x)}.rec", "pgp.v1.${bare(x)}.ok")
    private fun yPgp() = listOf("pgp.v1.${bare(y)}.rec")
    private fun set(eoa: String) = MnemonicSetStore.Current.Found(eoa, MnemonicSetStore.Kind.PLAIN, "synthetic")

    private class Counter { var erased = 0 }

    /** The redo over the pure scope rule, as the module wires it. */
    private fun redoer(
        files: NativeTestFiles,
        counter: Counter,
        holds: Boolean? = false,
        pgp: List<String> = emptyList(),
        current: MnemonicSetStore.Current = MnemonicSetStore.Current.Absent,
        pointer: PointerRead = PointerRead.None,
    ) = IdentityClear(
        flags = ClearFlagFiles(files),
        holdsWallet = { holds },
        eraseWallet = { counter.erased++; true },
        eraseInbox = { counter.erased++; true },
        reportLegacyAbsent = { counter.erased++; true },
        clearPointer = { counter.erased++; true },
        redoSafe = { owner -> redoScopeSafe(owner, pgp, current, pointer) },
    )

    private fun pending(owner: String?): NativeTestFiles = NativeTestFiles().also { assertTrue(ClearFlagFiles(it).setClearPending(owner)) }

    /** 1. G0 + Owned X, manual clearIdentity: clear_incomplete, nothing deleted or written. */
    @Test
    fun g0ManualClearOfAnOwnedMarkerAnswersClearIncompleteAndDeletesNothing() {
        val files = pending(x)
        val before = files.map.toMap()
        assertFalse(clearResumable(ClearFlagFiles(files).clearPendingOwner(), null))
        val c = Counter()
        val ic = IdentityClear(
            flags = ClearFlagFiles(files), backupConfirmed = { true }, holdsWallet = { false },
            eraseWallet = { c.erased++; true }, eraseInbox = { c.erased++; true }, reportLegacyAbsent = { c.erased++; true },
            clearPointer = { c.erased++; true }, currentEoa = null,
        )
        assertEquals(IdentityClearCode.CLEAR_INCOMPLETE, ic.clear())
        assertEquals(0, c.erased)
        assertEquals(before, files.map.toMap())
    }

    /** 2. Cold start + Owned X + no other account's entry + every read successful: the clear is finished and the marker removed. */
    @Test
    fun coldStartFinishesTheRecordedAccountsClear() {
        val files = pending(x)
        val c = Counter()
        // X's own pgp records, X's set and X's pointer are all inside X's scope.
        val r = redoer(files, c, pgp = xPgp(), current = set(x), pointer = PointerRead.At(x)).redoIfInterrupted()
        assertEquals(IdentityClearCode.OK, r)
        assertTrue("the steps ran", c.erased > 0)
        assertEquals("the marker is consumed", PendingOwner.Absent, ClearFlagFiles(files).clearPendingOwner())
    }

    /** 3. Cold start + Owned X + another account's entry (pgp record, set, pointer): nothing is deleted, the marker stays. */
    @Test
    fun coldStartWithAnotherAccountsEntryDeletesNothing() {
        val cases = mapOf(
            "pgp of Y" to Triple(yPgp(), MnemonicSetStore.Current.Absent, PointerRead.None),
            "pgp of X and Y" to Triple(xPgp() + yPgp(), MnemonicSetStore.Current.Absent, PointerRead.None),
            "set of Y" to Triple(emptyList<String>(), set(y), PointerRead.None),
            "pointer at Y" to Triple(emptyList<String>(), MnemonicSetStore.Current.Absent, PointerRead.At(y)),
            "unattributable pgp file" to Triple(listOf("pgp.v1.disabled.${bare(y)}.pending"), MnemonicSetStore.Current.Absent, PointerRead.None),
        )
        for ((label, scope) in cases) {
            val files = pending(x)
            val before = files.map.toMap()
            val c = Counter()
            val r = redoer(files, c, pgp = scope.first, current = scope.second, pointer = scope.third).redoIfInterrupted()
            assertEquals(label, IdentityClearCode.CLEAR_INCOMPLETE, r)
            assertEquals("$label: nothing erased", 0, c.erased)
            assertEquals("$label: marker and files unchanged", before, files.map.toMap())
        }
    }

    /** 4. Cold start + any read failure: nothing is deleted, the marker stays (retried at the next start). */
    @Test
    fun coldStartWithAnyReadFailureDeletesNothing() {
        val files = pending(x)
        val before = files.map.toMap()
        val checks = listOf(
            "holds unknown" to { c: Counter -> redoer(files, c, holds = null) },
            "set unknown" to { c: Counter -> redoer(files, c, current = MnemonicSetStore.Current.Unknown("read")) },
            "pointer unreadable" to { c: Counter -> redoer(files, c, pointer = PointerRead.Unreadable) },
        )
        for ((label, build) in checks) {
            val c = Counter()
            assertEquals(label, IdentityClearCode.CLEAR_INCOMPLETE, build(c).redoIfInterrupted())
            assertEquals("$label: nothing erased", 0, c.erased)
            assertEquals("$label: unchanged", before, files.map.toMap())
        }
        // A scope reader that throws is a failed read as well.
        val c = Counter()
        val throwing = IdentityClear(
            flags = ClearFlagFiles(files), holdsWallet = { false },
            eraseWallet = { c.erased++; true }, eraseInbox = { c.erased++; true }, reportLegacyAbsent = { c.erased++; true }, clearPointer = { c.erased++; true },
            redoSafe = { throw java.io.IOException("read fault") },
        )
        assertEquals(IdentityClearCode.CLEAR_INCOMPLETE, throwing.redoIfInterrupted())
        assertEquals(0, c.erased)
        assertEquals(before, files.map.toMap())
    }

    /** 5. Unknown marker (and an absent one): never finished, nothing deleted. */
    @Test
    fun anUnknownMarkerDeletesNothing() {
        val files = NativeTestFiles()
        files.map[ClearFlagFiles.CLEAR_PENDING] = "1".toByteArray(Charsets.UTF_8)
        val before = files.map.toMap()
        val c = Counter()
        assertEquals(IdentityClearCode.CLEAR_INCOMPLETE, redoer(files, c).redoIfInterrupted())
        assertEquals(0, c.erased)
        assertEquals(before, files.map.toMap())
        assertEquals("the rule itself never calls an unknown marker safe", false, redoScopeSafe(PendingOwner.Unknown, emptyList(), MnemonicSetStore.Current.Absent, PointerRead.None))
        assertEquals(false, redoScopeSafe(PendingOwner.Absent, emptyList(), MnemonicSetStore.Current.Absent, PointerRead.None))
    }

    /** 6. Current account = X: the gate resumes (the existing path), and the clear completes. */
    @Test
    fun theCurrentAccountEqualToXResumes() {
        val files = pending(x)
        assertTrue(clearResumable(ClearFlagFiles(files).clearPendingOwner(), x))
        val c = Counter()
        val ic = IdentityClear(
            flags = ClearFlagFiles(files), backupConfirmed = { true }, holdsWallet = { false },
            eraseWallet = { c.erased++; true }, eraseInbox = { c.erased++; true }, reportLegacyAbsent = { c.erased++; true },
            clearPointer = { c.erased++; true }, currentEoa = x,
        )
        assertEquals(IdentityClearCode.OK, ic.clear())
        assertTrue(c.erased > 0)
        assertEquals(PendingOwner.Absent, ClearFlagFiles(files).clearPendingOwner())
    }

    /** A no-account marker is finished only when nothing of any account is in scope. */
    @Test
    fun aNoAccountMarkerIsFinishedOnlyWhenNothingIsInScope() {
        val files = pending(null)
        assertEquals(IdentityClearCode.OK, redoer(files, Counter()).redoIfInterrupted())
        for ((label, scope) in mapOf(
            "pgp" to Triple(xPgp(), MnemonicSetStore.Current.Absent, PointerRead.None),
            "set" to Triple(emptyList<String>(), set(x), PointerRead.None),
            "pointer" to Triple(emptyList<String>(), MnemonicSetStore.Current.Absent, PointerRead.At(x)),
        )) {
            val f = pending(null)
            val before = f.map.toMap()
            val c = Counter()
            assertEquals(label, IdentityClearCode.CLEAR_INCOMPLETE, redoer(f, c, pgp = scope.first, current = scope.second, pointer = scope.third).redoIfInterrupted())
            assertEquals(0, c.erased)
            assertEquals(before, f.map.toMap())
        }
    }

    /** The module wires the scope rule into the redo, and the redo's flag erase is limited to the recorded account. */
    @Test
    fun theModuleWiresTheScopeRule() {
        val module = File("src/main/java/network/conet/chat/BeamioConetChatModule.kt").readText(Charsets.UTF_8)
        assertTrue(module.contains("redoSafe = { owner -> redoScopeSafeFor(ctx, owner, page) }"))
        assertTrue(module.contains("(flags.clearPendingOwner() as? PendingOwner.Owned)?.eoa"))
    }
}
