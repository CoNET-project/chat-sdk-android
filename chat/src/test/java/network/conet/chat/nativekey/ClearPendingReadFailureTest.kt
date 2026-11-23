package network.conet.chat.nativekey

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException

/**
 * Review finding, with the coordinator's : an unreadable clear_pending starts no redo and deletes nothing. It is
 * unknown, not "no pending clear": nothing is written or consumed, the block stays (clear_incomplete), and the next successful read resumes the
 * clear. Test directories are in memory; no device or real directory is touched.
 */
class ClearPendingReadFailureTest {
    /** Wraps [inner] and makes the read of [failName] throw, as a damaged or unreadable store would. Every other call passes through. */
    private class ReadFailsFor(private val inner: NativeTestFiles, private val failName: String) : VaultFiles {
        var deletes = 0
        override fun read(name: String): ByteArray? {
            if (name == failName) throw IOException("clear_pending unreadable")
            return inner.read(name)
        }

        override fun write(name: String, bytes: ByteArray) = inner.write(name, bytes)

        override fun delete(name: String) {
            deletes++
            inner.delete(name)
        }
    }

    private fun clearWith(flags: ClearFlagFiles, redoCalls: IntArray): IdentityClear = IdentityClear(
        flags = flags,
        holdsWallet = { redoCalls[0]++; false },
        eraseWallet = { redoCalls[0]++; true },
        eraseInbox = { true },
        reportLegacyAbsent = { true },
        clearPointer = { true },
    )

    /** The marker cannot be read: the redo does not run, no file is deleted, and the answer is "nothing interrupted" (null). */
    @Test
    fun unreadableClearPendingNeverStartsTheRedoAndDeletesNothing() {
        val inner = NativeTestFiles()
        inner.map[ClearFlagFiles.CLEAR_PENDING] = ownedMarker()
        inner.map["wallet.v1.rec"] = byteArrayOf(7, 7)
        inner.map["wallet.v1.mark"] = byteArrayOf(8)
        val before = inner.map.mapValues { it.value.copyOf() }
        val files = ReadFailsFor(inner, ClearFlagFiles.CLEAR_PENDING)
        val calls = IntArray(1)

        val result = clearWith(ClearFlagFiles(files), calls).redoIfInterrupted()

        assertEquals("an unreadable marker is unknown: the block stays, it is not reported as no pending clear", IdentityClearCode.CLEAR_INCOMPLETE, result)
        assertEquals("the redo did not touch the wallet", 0, calls[0])
        assertEquals("no delete was issued", 0, files.deletes)
        assertEquals("no name removed", before.keys, inner.map.keys)
        for ((name, bytes) in before) assertArrayEquals("$name unchanged", bytes, inner.map[name])
    }

    /** Control: the same store with a readable marker does run the redo (so the test above is not vacuous). */
    @Test
    fun readableClearPendingRunsTheRedo() {
        val inner = NativeTestFiles()
        inner.map[ClearFlagFiles.CLEAR_PENDING] = ownedMarker()
        val calls = IntArray(1)

        val result = clearWith(ClearFlagFiles(inner), calls).redoIfInterrupted()

        assertEquals("the redo ran", true, calls[0] > 0)
        assertEquals("the redo completed", "ok", result)
    }

    /** Fails only the first read of [failName]; later reads, writes and deletes pass through to [inner]. */
    private class FailsOnceFor(private val inner: NativeTestFiles, private val failName: String) : VaultFiles {
        private var failed = false
        override fun read(name: String): ByteArray? {
            if (name == failName && !failed) {
                failed = true
                throw IOException("transient")
            }
            return inner.read(name)
        }

        override fun write(name: String, bytes: ByteArray) = inner.write(name, bytes)

        override fun delete(name: String) = inner.delete(name)
    }

    /**
     * Rule (coordinator, rc2.2-qa): one failed read leaves the pending clear unknown. The next read that succeeds finds the marker and resumes the
     * user's clear, and only the account that clear involves is swept. Nothing is written by the failure, and the marker is cleared last.
     */
    @Test
    fun aFailedReadThenASuccessfulReadStillResumesAndClearsOnlyThatAccount() {
        val inner = NativeTestFiles()
        val involved = "0x" + "a".repeat(40)
        val other = "0x" + "b".repeat(40)
        inner.map[ClearFlagFiles.CLEAR_PENDING] = ownedMarker()
        val before = inner.map.mapValues { it.value.copyOf() }
        val files = FailsOnceFor(inner, ClearFlagFiles.CLEAR_PENDING)
        val calls = IntArray(1)

        val first = clearWith(ClearFlagFiles(files), calls).redoIfInterrupted()

        assertEquals("the failed read is unknown: the block stays", IdentityClearCode.CLEAR_INCOMPLETE, first)
        assertEquals("the redo did not run on the failed read", 0, calls[0])
        assertEquals("the failed read wrote and removed nothing", before.keys, inner.map.keys)
        assertArrayEquals("the pending marker is not consumed", ownedMarker(), inner.map[ClearFlagFiles.CLEAR_PENDING])

        val second = clearWith(ClearFlagFiles(files), calls).redoIfInterrupted()

        assertEquals("the next successful read resumes the clear", IdentityClearCode.OK, second)
        assertTrue("the redo ran on the resumed clear", calls[0] > 0)
        assertFalse("the marker is cleared last", inner.map.containsKey(ClearFlagFiles.CLEAR_PENDING))
        assertEquals(
            "only the involved account is swept (25.52Y.85 第 6 条)",
            listOf(involved),
            OrphanSweepRule.accountsToRemove(clearPending = true, involved = involved, live = null, accounts = listOf(involved, other)),
        )
    }

    /** A clear_pending that names its owner. The legacy single byte is unknown and resumes nothing. */
    private fun ownedMarker(): ByteArray = ("0x" + "c".repeat(40)).toByteArray(Charsets.UTF_8)
}
