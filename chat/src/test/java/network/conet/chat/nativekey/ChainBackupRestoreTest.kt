package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The chain-backup candidate of the recovery. It only yields a candidate or a reason: whether the key is the registered one is the gate's decision
 * ([RecoveryChallengeGate], tested in `RecoveryChallengeGateTest`), and nothing here writes.
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
    private val forms: () -> List<String>? = { listOf("0x" + "11".repeat(32)) }

    @Test
    fun noBackupIsNoBackup() {
        assertEquals(ChainBackupRestore.Candidate.NoBackup, ChainBackupRestore.candidate(FakeChain(record = id, backup = ""), forms))
    }

    @Test
    fun unreadableChainIsUnreadableNotNoBackup() {
        assertEquals(ChainBackupRestore.Candidate.Unreadable, ChainBackupRestore.candidate(FakeChain(readable = false, record = id, backup = "AAAA"), forms))
    }

    @Test
    fun lockedWalletIsUnreadable() {
        assertEquals(ChainBackupRestore.Candidate.Unreadable, ChainBackupRestore.candidate(FakeChain(record = id, backup = "AAAA")) { null })
    }

    @Test
    fun undecryptableBackupIsUndecryptable() {
        // Not valid base64 of an AES-GCM blob: no key is derived from it.
        assertEquals(ChainBackupRestore.Candidate.Undecryptable, ChainBackupRestore.candidate(FakeChain(record = id, backup = "not-a-backup!"), forms))
    }

    @Test
    fun theGlobalOpenPgpFlagStaysFalse() {
        // The recovery gate does not read it; the migration and the first-run import still do.
        assertTrue(!PgpMigrationPolicy.OPENPGP_APPROVED)
        assertTrue(!NativeMigrationCrypto().approved())
    }
}
