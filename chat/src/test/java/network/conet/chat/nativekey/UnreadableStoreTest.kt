package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException

/**
 * Unreadable stores on the paths that decide a restore, a clear and the backup gate (25.52Y.84, 25.52Y.104 第 3 条). A store that cannot be read is
 * unknown: the restore never generates a key on it, the backup flag is not confirmed (the clear refuses), and a missing or unreadable pending metadata
 * is never taken for "no pending".
 */
class UnreadableStoreTest {
    private val account = "0x2222222222222222222222222222222222222222"

    /** A store whose read of one name fails, as a store that cannot be read does. */
    private class ReadFailsFor(private val inner: VaultFiles, private val failName: String) : VaultFiles {
        override fun read(name: String): ByteArray? = if (name == failName) throw IOException("store unreadable") else inner.read(name)

        override fun write(name: String, bytes: ByteArray) = inner.write(name, bytes)

        override fun delete(name: String) = inner.delete(name)
    }

    @Test
    fun anAbsentPendingMetadataIsNoPending() {
        val device = PgpRestoreDevice("d", account, NativeTestWrap(), NativeTestFiles())
        assertNull(device.pendingMeta())
    }

    /** A pending metadata that is present but cannot be parsed is unknown: it throws, and no key is generated on it (25.52Y.84). */
    @Test
    fun anUnparseablePendingMetadataIsUnknownNotNoPending() {
        val files = NativeTestFiles()
        files.map[NativePgpVault.pendingMetaName(account)] = "not json".toByteArray(Charsets.UTF_8)
        val device = PgpRestoreDevice("d", account, NativeTestWrap(), files)
        assertThrows(IOException::class.java) { device.pendingMeta() }
    }

    /** A pending metadata whose read fails throws: the caller does not see "no pending". */
    @Test
    fun aPendingMetadataReadThatFailsThrows() {
        val files = ReadFailsFor(NativeTestFiles(), NativePgpVault.pendingMetaName(account))
        val device = PgpRestoreDevice("d", account, NativeTestWrap(), files)
        assertThrows(IOException::class.java) { device.pendingMeta() }
    }

    /** The completed idempotency key that cannot be read throws, so a repeated request is not taken as a first one. */
    @Test
    fun aCompletedIdemReadThatFailsThrows() {
        val files = ReadFailsFor(NativeTestFiles(), NativePgpVault.completedName(account))
        val device = PgpRestoreDevice("d", account, NativeTestWrap(), files)
        assertThrows(IOException::class.java) { device.completedIdem() }
    }

    /** The recovery-backup flag that cannot be read is not confirmed: the clear refuses on it (fail closed). */
    @Test
    fun aBackupFlagThatCannotBeReadIsNotConfirmed() {
        val flags = ClearFlagFiles(ReadFailsFor(NativeTestFiles(), ClearFlagFiles.backupFlagName(account)))
        assertFalse(flags.recoveryBackupConfirmed(account))
    }

    /** A flag that is absent is not confirmed either; the write of a flag that completes is confirmed on read-back. */
    @Test
    fun aBackupFlagIsConfirmedOnlyWhenReadBack() {
        val files = NativeTestFiles()
        val flags = ClearFlagFiles(files)
        assertFalse(flags.recoveryBackupConfirmed(account))
        assertTrue(flags.setRecoveryBackupConfirmed(account))
        assertTrue(flags.recoveryBackupConfirmed(account))
        assertEquals(1, files.map.size)
    }
}
