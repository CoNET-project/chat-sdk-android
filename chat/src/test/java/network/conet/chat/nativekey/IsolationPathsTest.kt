package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The three paths that used to erase bytes of a record now keep them: each moved byte string is still held under an isolated name after the path
 * runs (standing constraint: no stored bytes are deleted), and the restore logic is unchanged. Also: the pre-read settles nothing.
 */
class IsolationPathsTest {
    private val phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    private val wrap = NativeTestWrap()

    private fun key() = checkNotNull(MnemonicDerivation.deriveKey(phrase))
    private fun eoa() = checkNotNull(WalletAddress.fromPrivateKey(key()))
    private fun digest(b: ByteArray) = java.security.MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }
    private fun isolatedDigests(files: NativeTestFiles, name: String) =
        files.map.filterKeys { it.startsWith("$name.isolated.") }.values.map { digest(it) }.toSet()

    /** Path 3 (write failure): the store write of a key record fails at MARK; the written REC is kept, isolated, not erased. */
    @Test fun writeFailureKeepsTheWrittenRecordIsolated() {
        val files = NativeTestFiles()
        files.failWrite = NativeWalletVault.MARK
        val code = NativeWalletVault(wrap, files).importKey(eoa(), key())
        assertFalse("the write failed: $code", code == NativeWalletVault.Import.OK)
        assertTrue("no fixed record is left", files.map[NativeWalletVault.REC] == null)
        assertTrue("the written record is kept under an isolated name", isolatedDigests(files, NativeWalletVault.REC).isNotEmpty())
    }

    /** The helper of path 3 and of the account-create rollback: every record written is kept, the bytes are the same. */
    @Test fun isolateWrittenRecordsKeepsEveryByteString() {
        val files = NativeTestFiles()
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importKey(eoa(), key()))
        val before = files.map.filterKeys { it != NativeWalletVault.AUDIT }.values.map { digest(it) }.toSet()
        assertTrue(NativeWalletVault(wrap, files).isolateWrittenRecords(mnemonicPlanned = true))
        assertTrue("no fixed record is left", files.map[NativeWalletVault.REC] == null && files.map[NativeWalletVault.COMMIT] == null)
        val after = files.map.filterKeys { it != NativeWalletVault.AUDIT }.values.map { digest(it) }.toSet()
        assertTrue("every byte string is still held", before.all { it in after })
    }

    /** Path 1 (manifest rollback of an aborted import, settleForWrite): the record and the marker it created are kept isolated, then the intent goes. */
    @Test fun manifestRollbackKeepsTheCreatedRecordsIsolated() {
        val files = NativeTestFiles()
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importKey(eoa(), key()))
        val rec = files.map[NativeWalletVault.REC]!!.copyOf()
        val mark = files.map[NativeWalletVault.MARK]!!.copyOf()
        files.map.remove(NativeWalletVault.COMMIT)
        files.map[NativeWalletVault.INTENT] = NativeWalletVault(wrap, files).encodeIntent(eoa(), mnemonicPlanned = false, created = listOf(NativeWalletVault.REC, NativeWalletVault.MARK))
        assertTrue(NativeWalletVault(wrap, files).settleForWrite())
        assertFalse("intent removed", files.map.containsKey(NativeWalletVault.INTENT))
        assertTrue("the record is kept isolated", isolatedDigests(files, NativeWalletVault.REC).contains(digest(rec)))
        assertTrue("the marker is kept isolated", isolatedDigests(files, NativeWalletVault.MARK).contains(digest(mark)))
        assertTrue(String(files.map.getValue(NativeWalletVault.AUDIT), Charsets.UTF_8).contains("pending_import_rollback"))
    }

    /** The pre-read settles nothing: a pending marker stays, and every byte string stays. */
    @Test fun thePreReadSettlesNothing() {
        val files = NativeTestFiles()
        NativeWalletVault(wrap, files).importKey(eoa(), key())
        files.map[NativeWalletVault.PENDING] = """{"v":1,"utc":"2026-11-17T00:00:00Z","eoa":"${eoa()}","items":[],"newRecordSha":null,"preWriteAliasAbsent":false}""".toByteArray()
        val before = files.map.mapValues { digest(it.value) }
        MnemonicPreread.vaultAnswerOrUnknown(NativeWalletVault(wrap, files))
        assertTrue("the pending marker is not settled by the pre-read", files.map.containsKey(NativeWalletVault.PENDING))
        assertEquals(before, files.map.mapValues { digest(it.value) })
    }
}
