package network.conet.chat.nativekey

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * `pwaWalletSync` (r2.4.2 42(1), 43(2), 43(3)); vectors SR-02, SR-03, SR-08, SR-10, SR-13-style no-delete, and the write path of C-1.
 * The vault is the real [NativeWalletVault] over the in-memory file double ([NativeTestFiles]); this is not device storage.
 * Device storage (C-1 on a real store) is not run here.
 */
class PwaWalletSyncTest {
    private val pwaPhrase = "legal winner thank year wave sausage worth useful legal winner thank yellow"
    private val nativePhrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

    private fun keyOf(phrase: String): ByteArray = checkNotNull(MnemonicDerivation.deriveKey(phrase))
    private fun eoaOf(key: ByteArray): String = checkNotNull(WalletAddress.fromPrivateKey(key))

    /** A native account holding [nativePhrase] (the SR-02 starting point). */
    private fun nativeWithOwnPhrase(wrap: NativeTestWrap, files: NativeTestFiles): NativeWalletVault {
        val vault = NativeWalletVault(wrap, files)
        val key = keyOf(nativePhrase)
        assertEquals(NativeWalletVault.Import.OK, vault.importMnemonicKey(eoaOf(key), key, nativePhrase))
        return vault
    }

    @Test
    fun sr03_theSamePhraseIsIdempotentAndWritesNothing() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        val vault = nativeWithOwnPhrase(wrap, files)
        val before = files.map.mapValues { it.value.copyOf() }
        val key = keyOf(nativePhrase)

        assertEquals(NativeWalletVault.SyncOutcome.IDEMPOTENT, vault.syncPhrase(eoaOf(key), key, nativePhrase))
        assertEquals(before.keys, files.map.keys)
        before.forEach { (name, bytes) -> assertArrayEquals("$name unchanged", bytes, files.map[name]) }
    }

    @Test
    fun sr02_aDifferentPhraseIsWrittenIsolatedReadBackAndBecomesTheAccount() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        val vault = nativeWithOwnPhrase(wrap, files)
        val oldRec = files.map[NativeWalletVault.REC]!!.copyOf()
        val key = keyOf(pwaPhrase)
        val eoa = eoaOf(key)

        assertEquals(NativeWalletVault.SyncOutcome.UPDATED, vault.syncPhrase(eoa, key, pwaPhrase))

        // The new phrase is read back from the stored record (independent of the write's own values) and derives the new EOA.
        val read = vault.mnemonicOf()
        assertTrue("read back as the PWA phrase", read is NativeWalletVault.MnemonicRead.Stored)
        read as NativeWalletVault.MnemonicRead.Stored
        assertEquals(eoa, read.eoa)
        assertEquals(pwaPhrase, read.phrase)
        // The old record is isolated, not overwritten in place (43(3)): its bytes are still in the directory.
        assertTrue("old record kept", files.map.values.any { it.contentEquals(oldRec) })
    }

    @Test
    fun sr08_aWriteFailureKeepsTheOldBytesAndReportsFailure() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        val vault = nativeWithOwnPhrase(wrap, files)
        val rec = files.map[NativeWalletVault.REC]!!.copyOf()
        val mnem = files.map[NativeWalletVault.MNEM]!!.copyOf()
        files.failWrite = NativeWalletVault.REC
        val key = keyOf(pwaPhrase)

        val outcome = vault.syncPhrase(eoaOf(key), key, pwaPhrase)

        assertEquals("reported as write_failed (R1, review)", NativeWalletVault.SyncOutcome.WRITE_FAILED, outcome)
        assertArrayEquals("record restored", rec, files.map[NativeWalletVault.REC])
        assertArrayEquals("phrase record restored", mnem, files.map[NativeWalletVault.MNEM])
        // R1: the account that was usable before stays usable; the confirmation is an independent read of the old bytes.
        assertEquals(nativePhrase, (vault.mnemonicOf() as NativeWalletVault.MnemonicRead.Stored).phrase)
    }

    @Test
    fun sr10_anUnknownStateWritesNothingAndDeletesNothing() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        val vault = nativeWithOwnPhrase(wrap, files)
        val before = files.map.mapValues { it.value.copyOf() }
        wrap.deleteKey() // the wrapping key is gone: the record is present but cannot be read (unknown)
        val key = keyOf(pwaPhrase)

        assertEquals(NativeWalletVault.SyncOutcome.NOT_READY, vault.syncPhrase(eoaOf(key), key, pwaPhrase))
        assertEquals(before.keys, files.map.keys)
        before.forEach { (name, bytes) -> assertArrayEquals("$name unchanged", bytes, files.map[name]) }
    }

    @Test
    fun anInvalidPhraseOrAMismatchedKeyWritesNothing() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        val vault = NativeWalletVault(wrap, files)
        val key = keyOf(pwaPhrase)
        assertEquals(NativeWalletVault.SyncOutcome.BAD_INPUT, vault.syncPhrase(eoaOf(key), key, "not a phrase"))
        assertEquals(NativeWalletVault.SyncOutcome.BAD_INPUT, vault.syncPhrase(eoaOf(keyOf(nativePhrase)), key, pwaPhrase))
        assertTrue("nothing written", files.map.isEmpty())
    }

    /** LG-R24 (r2.4.2 42(6)): a log line never carries a phrase or a key; the sync logs the outcome name only. */
    @Test
    fun theOutcomeLogLineCarriesNoKeyMaterial() {
        val line = "pwaWalletSync outcome=${NativeWalletVault.SyncOutcome.UPDATED.name}"
        assertTrue(!Regex("([a-z]+ ){11}[a-z]+").containsMatchIn(line))
        assertTrue(!Regex("0x[0-9a-fA-F]{64}").containsMatchIn(line))
    }

    /** A transient failure: the write fails, the old names are back; the next request (a new sequence) proceeds once the store is writable. */
    @Test
    fun aTransientFailureThenARetryWithANewSequenceSucceeds() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        val vault = nativeWithOwnPhrase(wrap, files)
        val rec = files.map[NativeWalletVault.REC]!!.copyOf()
        val key = keyOf(pwaPhrase)
        val eoa = eoaOf(key)
        files.failWrite = NativeWalletVault.REC
        assertTrue(MnemonicPreread.accept(1L))
        assertTrue(vault.syncPhrase(eoa, key, pwaPhrase) != NativeWalletVault.SyncOutcome.UPDATED)
        assertArrayEquals("old record kept after the failure", rec, files.map[NativeWalletVault.REC])
        files.failWrite = null
        assertTrue("retry carries a newer sequence", MnemonicPreread.accept(2L))
        val retry = vault.syncPhrase(eoa, key, pwaPhrase)
        assertEquals("the retry is written and read back", NativeWalletVault.SyncOutcome.UPDATED, retry)
        val read = vault.mnemonicOf()
        assertEquals(pwaPhrase, (read as NativeWalletVault.MnemonicRead.Stored).phrase)
    }
}
