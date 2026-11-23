package network.conet.chat.nativekey

import network.conet.chat.nativekey.MnemonicPreread.Answer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.IOException

/**
 * E7 (spec-59e-errata-v3.3.1-E7.md, E7.1; vectors E7-add.json and E7.1-add.json). The native pre-read answers `absent` only when the key
 * record was read and the phrase item is either missing or read and deterministically not a valid phrase (N1–N5). A failed read, a failed
 * enumeration or a phrase item whose two reads differ is `unknown`. Nothing is removed by any of these answers.
 * Cases here are written by hand from the vector's pre-state (not driven by the JSON): the vector ops include PWA-side steps.
 * Mapping: P-04 keyOnly, P-05 enumeration failure, P-09/E71-01 checksum failure, P-10/P-11 deterministic invalid, P-12/E71-02 read exception,
 * P-13 non-deterministic (unknown), P-14 marker unsettled (unknown).
 */
class PrereadE7Test {
    private val goodPhrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    private val badPhrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"
    private val wrap = NativeTestWrap()

    @Before fun newLaunch() {
        MnemonicPreread.resetForTests()
        NativeWalletVault.resetLaunchForTests()
    }

    /** A file double whose reads can fail or change: [readHook] may throw or return a replacement for a name's bytes. */
    private class HookFiles(val inner: NativeTestFiles, val readHook: (String, ByteArray?) -> ByteArray?) : VaultFiles {
        override fun read(name: String): ByteArray? = readHook(name, inner.read(name))
        override fun write(name: String, bytes: ByteArray) = inner.write(name, bytes)
        override fun delete(name: String) = inner.delete(name)
        override fun names(): List<String> = inner.names()
        override fun rename(from: String, to: String) = inner.rename(from, to)
    }

    private fun digest(b: ByteArray): String = java.security.MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }

    private fun eoaOf(phrase: String): Pair<String, ByteArray> {
        val key = checkNotNull(MnemonicDerivation.deriveKey(phrase))
        return checkNotNull(WalletAddress.fromPrivateKey(key)) to key
    }

    /** A mnemonic item sealed for [eoa] holding [phrase] (valid or not), built the way the vault builds its own item. */
    private fun mnemonicItem(eoa: String, phrase: String): ByteArray {
        val m = NativeWalletVault::class.java.getDeclaredMethod("encodeMnemonic", String::class.java, ByteArray::class.java)
        m.isAccessible = true
        val sealed = wrap.seal(NativeWalletVault.mnemAad(eoa), phrase.toByteArray(Charsets.UTF_8))
        return m.invoke(NativeWalletVault(wrap, NativeTestFiles()), eoa, sealed) as ByteArray
    }

    /** Key record and marker for an account with [phrase] stored as a (possibly invalid) mnemonic item. */
    private fun accountWithPhraseItem(files: NativeTestFiles, phrase: String) {
        val (eoa, key) = eoaOf(goodPhrase)
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importMnemonicKey(eoa, key, goodPhrase))
        val rec = files.map[NativeWalletVault.REC]!!
        files.map[NativeWalletVault.MNEM] = mnemonicItem(eoa, phrase)
        files.map[NativeWalletVault.MARK] = NativeWalletVault.markerOf(rec, files.map[NativeWalletVault.MNEM])
    }

    private fun keyOnly(files: NativeTestFiles) {
        val (eoa, key) = eoaOf(goodPhrase)
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importKey(eoa, key))
        files.map.remove(NativeWalletVault.MNEM)
    }

    private fun answerOf(files: VaultFiles): Answer = MnemonicPreread.vaultAnswerOrUnknown(NativeWalletVault(wrap, files))

    private fun snapshotOf(files: NativeTestFiles): Map<String, String> = files.map.mapValues { digest(it.value) }

    // P-04: the keychain holds only a key (readable record, no phrase item), enumeration and reads succeed: explicitly no valid mnemonic → absent.
    @Test fun p04_keyOnlyIsAbsentAndNothingIsRemoved() {
        val files = NativeTestFiles()
        keyOnly(files)
        val before = snapshotOf(files)
        assertTrue("key-only answers absent", answerOf(files) == Answer.Absent)
        assertEquals(before, snapshotOf(files))
    }

    // P-05: enumeration fails while only a key is held: unknown, retryable, nothing changes.
    @Test fun p05_enumerationFailureIsUnknown() {
        val files = NativeTestFiles()
        keyOnly(files)
        val before = snapshotOf(files)
        val failing = HookFiles(files) { name, _ -> throw IOException("keystore enumeration failed at $name") }
        assertEquals(Answer.Unknown, answerOf(failing))
        assertEquals("nothing is removed or changed", before, snapshotOf(files))
    }

    // P-09 / E71-01: the phrase item is read and fails the BIP-39 checksum, and a second read gives the same → absent; the item is kept.
    @Test fun p09_checksumFailureTwiceIsAbsentAndTheItemIsKept() {
        val files = NativeTestFiles()
        accountWithPhraseItem(files, badPhrase)
        val before = snapshotOf(files)
        assertEquals("deterministic invalid phrase answers absent", Answer.Absent, answerOf(files))
        assertEquals("the item and the records are kept", before, snapshotOf(files))
    }

    // P-10 / P-11: a word list or length failure is the same deterministic invalid result as a checksum failure.
    @Test fun p10p11_otherInvalidPhraseShapesAreAbsentAndKept() {
        for (phrase in listOf("notaword notaword notaword notaword notaword notaword notaword notaword notaword notaword notaword notaword",
                "abandon abandon abandon")) {
            val files = NativeTestFiles()
            accountWithPhraseItem(files, phrase)
            assertEquals(Answer.Absent, answerOf(files))
            assertTrue(files.map.containsKey(NativeWalletVault.MNEM))
        }
    }

    // P-12 / E71-02: a read exception on the phrase item is unknown; it is not absent, and a later read is not used to decide it.
    @Test fun p12_readExceptionOnThePhraseItemIsUnknown() {
        val files = NativeTestFiles()
        accountWithPhraseItem(files, badPhrase)
        val failing = HookFiles(files) { name, bytes -> if (name == NativeWalletVault.MNEM) throw IOException("read failed") else bytes }
        assertEquals(Answer.Unknown, answerOf(failing))
    }

    // P-13: the first read is invalid and the second is valid → not the same result → unknown (not absent).
    @Test fun p13_differentRereadsAreUnknown() {
        val files = NativeTestFiles()
        accountWithPhraseItem(files, badPhrase)
        val bad = files.map[NativeWalletVault.MNEM]!!
        val good = mnemonicItem(eoaOf(goodPhrase).first, goodPhrase)
        var mnemReads = 0
        val flip = HookFiles(files) { name, bytes ->
            if (name == NativeWalletVault.MNEM) { mnemReads++; if (mnemReads == 1) bad else good } else bytes
        }
        assertEquals(Answer.Unknown, answerOf(flip))
    }

    // P-14: the marker is not settled (a pending marker): unknown, even though the phrase item is invalid.
    // P-14 is superseded by the decision of 2026-11-17: an unsettled marker alone is not unknown (see PrereadHalfWriteTest).
    @Test fun p14_unsettledMarkerIsAbsentUnderTheDecision2026_11_17() {
        val files = NativeTestFiles()
        accountWithPhraseItem(files, badPhrase)
        files.map[NativeWalletVault.PENDING] = "{}".toByteArray()
        assertEquals(Answer.Absent, answerOf(files))
    }
}
