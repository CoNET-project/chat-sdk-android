package network.conet.chat.nativekey

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import java.io.IOException

/**
 * Review finding (76706f6d on ced0bfc): a read of clear_pending that fails must not start the redo, and nothing may be deleted. The redo
 * runs only on a strict read that finds the marker. Test directories are in memory; no device or real directory is touched.
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
        inner.map[ClearFlagFiles.CLEAR_PENDING] = byteArrayOf(1)
        inner.map["wallet.v1.rec"] = byteArrayOf(7, 7)
        inner.map["wallet.v1.mark"] = byteArrayOf(8)
        val before = inner.map.mapValues { it.value.copyOf() }
        val files = ReadFailsFor(inner, ClearFlagFiles.CLEAR_PENDING)
        val calls = IntArray(1)

        val result = clearWith(ClearFlagFiles(files), calls).redoIfInterrupted()

        assertNull("an unreadable marker is not a pending clear", result)
        assertEquals("the redo did not touch the wallet", 0, calls[0])
        assertEquals("no delete was issued", 0, files.deletes)
        assertEquals("no name removed", before.keys, inner.map.keys)
        for ((name, bytes) in before) assertArrayEquals("$name unchanged", bytes, inner.map[name])
    }

    /** Control: the same store with a readable marker does run the redo (so the test above is not vacuous). */
    @Test
    fun readableClearPendingRunsTheRedo() {
        val inner = NativeTestFiles()
        inner.map[ClearFlagFiles.CLEAR_PENDING] = byteArrayOf(1)
        val calls = IntArray(1)

        val result = clearWith(ClearFlagFiles(inner), calls).redoIfInterrupted()

        assertEquals("the redo ran", true, calls[0] > 0)
        assertEquals("the redo completed", "ok", result)
    }
}
