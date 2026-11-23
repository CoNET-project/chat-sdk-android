package network.conet.chat.nativekey

import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.io.IOException

/**
 * C-1 evidence on a real file system (item 3(a)-(c)): [AndroidVaultFiles] over a JVM temporary directory, with the
 * fault points of the write path injected by [FaultFiles]. Only the key wrap is a test double ([NativeTestWrap]), because the Android
 * keystore does not run on the JVM. The device run (C-1 to C-5) is still required and is not claimed here.
 */
class PwaSyncRealFileTest {
    @get:Rule
    val tmp = TemporaryFolder()

    private val pwaPhrase = "legal winner thank year wave sausage worth useful legal winner thank yellow"
    private val nativePhrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    private lateinit var dir: File
    private lateinit var wrap: NativeTestWrap

    @Before
    fun setUp() {
        dir = tmp.newFolder("vault")
        wrap = NativeTestWrap()
        MnemonicPreread.resetForTests()
    }

    @After
    fun tearDown() = MnemonicPreread.resetForTests()

    private fun keyOf(p: String): ByteArray = checkNotNull(MnemonicDerivation.deriveKey(p))
    private fun eoaOf(k: ByteArray): String = checkNotNull(WalletAddress.fromPrivateKey(k))

    private fun vaultOver(files: VaultFiles) = NativeWalletVault(wrap, files)

    /** A native account with [nativePhrase] written to the real directory. */
    private fun seeded(): NativeWalletVault {
        val v = vaultOver(AndroidVaultFiles(dir))
        val k = keyOf(nativePhrase)
        assertEquals(NativeWalletVault.Import.OK, v.importMnemonicKey(eoaOf(k), k, nativePhrase))
        return v
    }

    private val AUDIT = setOf("wallet.isolation.audit")

    private fun snapshot(): Map<String, ByteArray> =
        dir.listFiles()!!.filter { it.isFile }.associate { it.name to it.readBytes() }

    private fun isolatedOldRecord(old: ByteArray): Boolean =
        dir.listFiles()!!.filter { it.isFile }.any { it.readBytes().contentEquals(old) }

    /** LG-R24 on real artifacts: no file of the vault holds a phrase in plain text or a 64-hex private key (the record is sealed). */
    private fun assertNoKeyMaterialOnDisk() {
        val forbidden = listOf(pwaPhrase, nativePhrase, "abandon abandon abandon")
        val keyHex = listOf(nativePhrase, pwaPhrase).map { p -> keyOf(p).joinToString("") { "%02x".format(it) } }
        for (f in dir.listFiles()!!.filter { it.isFile }) {
            val text = String(f.readBytes(), Charsets.ISO_8859_1)
            for (p in forbidden) assertFalse("${f.name} carries a phrase", text.contains(p))
            for (h in keyHex) assertFalse("${f.name} carries a private key", text.contains(h))
        }
    }

    @Test
    fun sr02OnRealFilesWritesIsolatesReadsBackAndLeavesNoPlaintext() {
        val v = seeded()
        val oldRec = AndroidVaultFiles(dir).read(NativeWalletVault.REC)!!
        val k = keyOf(pwaPhrase)
        assertEquals(NativeWalletVault.SyncOutcome.UPDATED, v.syncPhrase(eoaOf(k), k, pwaPhrase))
        val read = vaultOver(AndroidVaultFiles(dir)).mnemonicOf()
        assertEquals(pwaPhrase, (read as NativeWalletVault.MnemonicRead.Stored).phrase)
        assertTrue("old record isolated on disk", isolatedOldRecord(oldRec))
        assertNoKeyMaterialOnDisk()
    }

    @Test
    fun sr08OnRealFilesFailedWriteKeepsBytesAndTheAccountUsable() {
        val v = seeded()
        val before = snapshot()
        val files = FaultFiles(AndroidVaultFiles(dir)).apply { failWrite.add(NativeWalletVault.REC) }
        val k = keyOf(pwaPhrase)
        val outcome = vaultOver(files).syncPhrase(eoaOf(k), k, pwaPhrase)
        assertEquals("a failed write is reported as a failure", NativeWalletVault.SyncOutcome.WRITE_FAILED, outcome)
        val after = snapshot()
        // The isolation audit is a new file by design (25.52Y.128); every vault name keeps its bytes.
        // E9 keep: the failed write's own record is moved to an isolated name, not erased; the names that were there are still there.
        assertTrue("every name from before is still there", before.keys.all { it in after.keys })
        assertTrue("the extra names are isolated copies", (after.keys - AUDIT - before.keys).all { it.contains(".isolated.") })
        before.forEach { (n, b) -> assertArrayEquals("$n bytes unchanged", b, after[n]) }
        // R1: the account stays usable and is read through an independent read.
        val read = vaultOver(AndroidVaultFiles(dir)).mnemonicOf()
        assertEquals(nativePhrase, (read as NativeWalletVault.MnemonicRead.Stored).phrase)
        assertNoKeyMaterialOnDisk()
        assertTrue("the account is ready again", v.state() is NativeWalletVault.State.Ready)
    }

    @Test
    fun aFailedReadbackIsReportedAndTheAccountStaysUsable() {
        seeded()
        val before = snapshot()
        // The first read of the new record after it is written returns other bytes: the readback cannot confirm it.
        val files = FaultFiles(AndroidVaultFiles(dir)).apply { corruptReadAfterWrite.add(NativeWalletVault.REC) }
        val k = keyOf(pwaPhrase)
        val outcome = vaultOver(files).syncPhrase(eoaOf(k), k, pwaPhrase)
        assertEquals(NativeWalletVault.SyncOutcome.READBACK_FAILED, outcome)
        val after = snapshot()
        before.forEach { (n, b) -> assertArrayEquals("$n bytes unchanged", b, after[n]) }
        assertEquals(nativePhrase, (vaultOver(AndroidVaultFiles(dir)).mnemonicOf() as NativeWalletVault.MnemonicRead.Stored).phrase)
    }

    /** ROLLBACK_PENDING: the write fails and the restore cannot rename the old names back. Nothing is deleted; the state is unknown. */
    @Test
    fun aRollbackThatCannotBeConfirmedKeepsEverythingAndIsUnknown() {
        seeded()
        val oldRec = AndroidVaultFiles(dir).read(NativeWalletVault.REC)!!
        val files = FaultFiles(AndroidVaultFiles(dir)).apply {
            failWrite.add(NativeWalletVault.REC)
            failRenameTo.add(NativeWalletVault.REC)
        }
        val k = keyOf(pwaPhrase)
        val outcome = vaultOver(files).syncPhrase(eoaOf(k), k, pwaPhrase)
        assertEquals(NativeWalletVault.SyncOutcome.ROLLBACK_PENDING, outcome)
        assertTrue("old record kept on disk (isolated, not deleted)", isolatedOldRecord(oldRec))
        // A restart (a new vault instance, no memory) does not treat the state as usable.
        assertTrue("not a success on restart", vaultOver(AndroidVaultFiles(dir)).mnemonicOf() !is NativeWalletVault.MnemonicRead.Stored)
    }

    /**
     * PHRASE_ONLY (E5, 2026-11-17; SO-26 pending E5.1): no key record, a readable phrase. pwaWalletSync is write_failed / internal_state:
     * nothing is sealed, renamed or cleaned, and the residue is unchanged (the former B1 expectation of an idempotent answer or a write is withdrawn).
     */
    @Test
    fun phraseOnlyPwaWalletSyncChangesNothingAndIsNotReady() {
        seeded()
        AndroidVaultFiles(dir).delete(NativeWalletVault.REC) // the key record is gone; the phrase record stays
        val v = vaultOver(AndroidVaultFiles(dir))
        val state = v.state()
        assertTrue("phrase-only state: $state", state is NativeWalletVault.State.Locked && state.reason == NativeWalletVault.PHRASE_ONLY)
        val before = AndroidVaultFiles(dir).names().sorted()
        val native = keyOf(nativePhrase)
        assertEquals(NativeWalletVault.SyncOutcome.NOT_READY, v.syncPhrase(eoaOf(native), native, nativePhrase))
        val pwa = keyOf(pwaPhrase)
        assertEquals(NativeWalletVault.SyncOutcome.NOT_READY, v.syncPhrase(eoaOf(pwa), pwa, pwaPhrase))
        assertEquals(before, AndroidVaultFiles(dir).names().sorted())
        assertTrue(vaultOver(AndroidVaultFiles(dir)).state() is NativeWalletVault.State.Locked)
    }

    /** A process that stops in the middle: the failed write left isolated names, and a fresh instance must not delete or report them as usable. */
    @Test
    fun aRestartAfterAnInterruptedWriteDeletesNothingAndDoesNotReportSuccess() {
        seeded()
        val files = FaultFiles(AndroidVaultFiles(dir)).apply {
            failWrite.add(NativeWalletVault.MNEM)
            failRenameTo.add(NativeWalletVault.REC)
        }
        val k = keyOf(pwaPhrase)
        vaultOver(files).syncPhrase(eoaOf(k), k, pwaPhrase)
        val names = dir.listFiles()!!.map { it.name }.toSet()
        assertTrue("some record remains on disk", names.isNotEmpty())
        val restarted = vaultOver(AndroidVaultFiles(dir))
        assertTrue("a restarted instance does not report the new phrase as stored",
            restarted.mnemonicOf() !is NativeWalletVault.MnemonicRead.Stored || (restarted.mnemonicOf() as NativeWalletVault.MnemonicRead.Stored).phrase == nativePhrase)
    }

    /** B2 (r2.4.8): the empty shell (PWA holds a phrase, the native store has nothing) accepts the sync, writes, reads back, answers ok. */
    @Test
    fun anEmptyShellAcceptsTheSyncWritesReadsBackAndAnswersOk() {
        val v = vaultOver(AndroidVaultFiles(dir))
        assertTrue("starts with no key", v.state() is NativeWalletVault.State.NoKey)
        MnemonicPreread.accept(1L)
        val k = keyOf(pwaPhrase)
        val outcome = v.syncPhrase(eoaOf(k), k, pwaPhrase)
        assertEquals(NativeWalletVault.SyncOutcome.UPDATED, outcome)
        assertEquals("ok", NativeSyncAck.codeOf(outcome))
        val fresh = vaultOver(AndroidVaultFiles(dir))
        assertEquals(pwaPhrase, (fresh.mnemonicOf() as NativeWalletVault.MnemonicRead.Stored).phrase)
        val answer = MnemonicPreread.vaultAnswerOrUnknown(fresh)
        assertEquals(eoaOf(k), (answer as MnemonicPreread.Answer.Valid).eoa)
        assertNoKeyMaterialOnDisk()
    }

    /** B2 (r2.4.8): an untrusted request is refused before anything is read or written; the directory stays empty. */
    @Test
    fun anUntrustedRequestWritesNothing() {
        val body = org.json.JSONObject().put("phrase", pwaPhrase).put("seq", 1)
        assertEquals("untrusted_source", NativeSyncAck.admit(body))
        assertTrue("nothing written", dir.listFiles()!!.isEmpty())
    }

    /** B3 (r2.4.8): a failed write is re-read and the definitive answer is published under the current sequence (not stuck at unknown). */
    @Test
    fun aFailedWriteIsRereadAndPublishesADefinitiveAnswer() {
        seeded()
        assertTrue(MnemonicPreread.accept(3L))
        val files = FaultFiles(AndroidVaultFiles(dir)).apply { failWrite.add(NativeWalletVault.REC) }
        val k = keyOf(pwaPhrase)
        val vault = vaultOver(files)
        val outcome = vault.syncPhrase(eoaOf(k), k, pwaPhrase)
        assertEquals("write_failed", NativeSyncAck.codeOf(outcome))
        MnemonicPreread.publishAfterSync(3L, MnemonicPreread.vaultAnswerOrUnknown(vaultOver(AndroidVaultFiles(dir))))
        val published = MnemonicPreread.answer()
        assertTrue("definitive, not unknown: $published", published is MnemonicPreread.Answer.Valid)
        assertEquals(nativePhrase, (published as MnemonicPreread.Answer.Valid).phrase)
    }
}

/** A directory with injected faults at the write path: a write to a name in [failWrite] throws; a rename into a name in [failRenameTo] throws. */
internal class FaultFiles(private val inner: VaultFiles) : VaultFiles {
    val failWrite = mutableSetOf<String>()
    val failRenameTo = mutableSetOf<String>()
    /** The next read of a name written after this is armed returns other bytes once (a readback that cannot confirm the write). */
    val corruptReadAfterWrite = mutableSetOf<String>()
    private val armed = mutableSetOf<String>()

    override fun read(name: String): ByteArray? {
        val bytes = inner.read(name)
        if (name in armed && bytes != null) {
            armed.remove(name)
            return ByteArray(bytes.size) { 0x5A }
        }
        return bytes
    }
    override fun write(name: String, bytes: ByteArray) {
        if (name in failWrite) throw IOException("injected write failure: $name")
        inner.write(name, bytes)
        if (name in corruptReadAfterWrite) armed.add(name)
    }
    /** A delete of a name in [failDelete] throws (an interrupted removal). */
    val failDelete = mutableSetOf<String>()

    override fun delete(name: String) {
        if (name in failDelete) throw IOException("injected delete failure: $name")
        inner.delete(name)
    }
    override fun exists(name: String): Boolean = inner.exists(name)
    override fun rename(from: String, to: String) {
        if (to in failRenameTo) throw IOException("injected rename failure: $to")
        inner.rename(from, to)
    }
    override fun names(): List<String> = inner.names()
}