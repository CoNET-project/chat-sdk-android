package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The chain-backup source of the K_pgp upgrade. Every case here is a failure or an absent source: none reaches the key checks, so none writes.
 * The verified path needs a real OpenPGP backup and the approved crypto; it is not in this file (the migration vectors cover the pipeline).
 */
class ChainBackupRestoreTest {
    private class FakeChain(
        private val readable: Boolean = true,
        private val record: PgpIdentity? = null,
        private val backup: String = "",
    ) : PgpRestoreChain {
        override fun chainReadable(): Boolean = readable
        override fun backupReadable(): Boolean = readable
        override fun version(): Long = 0L
        override fun identity(): PgpIdentity? = record
        override fun backupText(): String = backup
        override fun write(identity: PgpIdentity, backupText: String) = throw IllegalStateException("not in this test")
    }

    private val id = PgpIdentity("0011AABB", "0000000000000001")
    private val eoa = "0x" + "a".repeat(40)

    private fun restore(chain: PgpRestoreChain, pw: String? = "0x" + "11".repeat(32), approved: Boolean = false): ChainBackupRestore.Result =
        ChainBackupRestore.restore(eoa, chain, { pw }, NativeMigrationCrypto(approved))

    @Test
    fun noBackupIsNoSource() {
        assertEquals(ChainBackupRestore.Result.NoSource, restore(FakeChain(record = id, backup = "")))
    }

    @Test
    fun unreadableChainIsUnverifiedNotNoSource() {
        assertEquals(ChainBackupRestore.Result.Unverified, restore(FakeChain(readable = false, record = id, backup = "AAAA")))
    }

    @Test
    fun backupWithoutRecordIsUnverified() {
        assertEquals(ChainBackupRestore.Result.Unverified, restore(FakeChain(record = null, backup = "AAAA")))
    }

    @Test
    fun lockedWalletIsUnverified() {
        assertEquals(ChainBackupRestore.Result.Unverified, restore(FakeChain(record = id, backup = "AAAA"), pw = null))
    }

    @Test
    fun undecryptableBackupIsUnverified() {
        // Not valid base64 of an AES-GCM blob: no key is derived from it.
        assertEquals(ChainBackupRestore.Result.Unverified, restore(FakeChain(record = id, backup = "not-a-backup!")))
    }

    @Test
    fun withoutOpenPgpApprovalNothingVerifies() {
        // The challenge needs the approved OpenPGP functions (PgpMigrationPolicy.OPENPGP_APPROVED is false on Android).
        assertTrue(!PgpMigrationPolicy.OPENPGP_APPROVED)
        assertTrue(!NativeMigrationCrypto().approved())
    }
}
