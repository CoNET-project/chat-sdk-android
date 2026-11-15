package network.conet.chat.nativekey

import network.conet.chat.nativekey.NativeWalletVault.Import
import network.conet.chat.nativekey.NativeWalletVault.MnemonicRead
import network.conet.chat.nativekey.NativeWalletVault.State
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The sealed recovery phrase (spec §25.52Y.42) and the walletCredential answer (§25.52Y.38 第 3 项). The phrase is the public BIP-39
 * test vector of mnemonic-derivation-vectors MI-1 (eoa 0x9858…); it is not a real wallet. Upgrade cases U-A1 and U-A2 (§25.52Y.40 第 5 项).
 */
class NativeMnemonicStoreTest {
    private val phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    private val eoa = "0x9858effd232b4033e47d90003d41ec34ecaeda94"

    private fun keyOf(p: String): ByteArray = MnemonicDerivation.deriveKey(p)!!

    private fun vault(wrap: NativeTestWrap, files: NativeTestFiles) = NativeWalletVault(wrap, files)

    /** A phrase import stores a sealed copy; the marker covers both records; the phrase reads back as stored. */
    @Test
    fun phraseImportStoresTheSealedPhraseUnderTheMarker() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        val v = vault(wrap, files)
        assertEquals(Import.OK, v.importMnemonicKey(eoa, keyOf(phrase), phrase))
        assertTrue(files.map.containsKey(NativeWalletVault.MNEM))
        assertTrue(files.map.containsKey(NativeWalletVault.REC))
        assertEquals(State.Ready(eoa).eoa, (v.state() as State.Ready).eoa)
        val read = v.mnemonicOf()
        assertTrue(read is MnemonicRead.Stored)
        assertEquals(phrase, (read as MnemonicRead.Stored).phrase)
        assertEquals(eoa, read.eoa)
    }

    /** The phrase itself is never in any stored file: the sealed copy is ciphertext. */
    @Test
    fun phraseIsNeverStoredInTheClear() {
        val files = NativeTestFiles()
        vault(NativeTestWrap(), files).importMnemonicKey(eoa, keyOf(phrase), phrase)
        val needle = phrase.toByteArray(Charsets.UTF_8)
        for ((name, stored) in files.map) {
            assertFalse("$name holds the phrase in the clear", String(stored, Charsets.ISO_8859_1).contains(String(needle, Charsets.ISO_8859_1)))
        }
    }

    /** U-A1: a key-only import (no phrase) writes no phrase record, and its marker is the record digest as before. */
    @Test
    fun keyOnlyImportWritesNoPhraseRecord() {
        val files = NativeTestFiles()
        val v = vault(NativeTestWrap(), files)
        assertEquals(Import.OK, v.importKey(eoa, keyOf(phrase)))
        assertFalse(files.map.containsKey(NativeWalletVault.MNEM))
        assertTrue(v.state() is State.Ready)
        assertTrue(v.mnemonicOf() is MnemonicRead.Missing)
    }

    /** A wrong phrase for the key is refused before anything is written. */
    @Test
    fun phraseThatDoesNotDeriveTheKeyStoresNothing() {
        val files = NativeTestFiles()
        val other = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
        assertEquals(Import.BAD_KEY, vault(NativeTestWrap(), files).importMnemonicKey(eoa, keyOf(phrase), other))
        assertTrue(files.map.isEmpty())
    }

    /** A failed phrase-record write rolls the whole import back: no record, no phrase, no marker. */
    @Test
    fun failedPhraseWriteRollsBackTheWholeImport() {
        val files = NativeTestFiles().apply { failWrite = NativeWalletVault.MNEM }
        val v = vault(NativeTestWrap(), files)
        assertEquals(Import.STORE_FAILED, v.importMnemonicKey(eoa, keyOf(phrase), phrase))
        assertTrue(files.map.isEmpty())
        assertTrue(v.state() is State.NoKey)
    }

    /** A failed marker write also leaves nothing behind (the marker is the last step). */
    @Test
    fun failedMarkerWriteRollsBackTheWholeImport() {
        val files = NativeTestFiles().apply { failWrite = NativeWalletVault.MARK }
        val v = vault(NativeTestWrap(), files)
        assertEquals(Import.STORE_FAILED, v.importMnemonicKey(eoa, keyOf(phrase), phrase))
        assertTrue(files.map.isEmpty())
    }

    /** A readback that does not confirm the key removes everything the call wrote. */
    @Test
    fun readbackFailureRollsBackTheWholeImport() {
        val files = NativeTestFiles()
        val wrap = NativeTestWrap().apply { openOverride = { ByteArray(32) { 7 } } }
        val v = vault(wrap, files)
        assertEquals(Import.READBACK_FAILED, v.importMnemonicKey(eoa, keyOf(phrase), phrase))
        assertTrue(files.map.isEmpty())
    }

    /** A phrase record that is replaced after the import breaks the marker: the vault is locked and the phrase is unavailable. */
    @Test
    fun tamperedPhraseRecordLocksTheVault() {
        val files = NativeTestFiles()
        val wrap = NativeTestWrap()
        val v = vault(wrap, files)
        assertEquals(Import.OK, v.importMnemonicKey(eoa, keyOf(phrase), phrase))
        val other = NativeTestFiles()
        vault(wrap, other).importMnemonicKey(eoa, keyOf(phrase), phrase)
        files.map[NativeWalletVault.MNEM] = other.map[NativeWalletVault.MNEM]!!.copyOf()
        val s = v.state()
        assertTrue(s is State.Locked)
        assertEquals("marker_mismatch", (s as State.Locked).reason)
        assertTrue(v.mnemonicOf() is MnemonicRead.Unavailable)
    }

    /** A phrase record with no key record is an orphan: state() removes it. */
    @Test
    fun orphanPhraseRecordIsRemoved() {
        val files = NativeTestFiles()
        files.map[NativeWalletVault.MNEM] = "{\"record\":1}".toByteArray(Charsets.UTF_8)
        assertTrue(vault(NativeTestWrap(), files).state() is State.NoKey)
        assertFalse(files.map.containsKey(NativeWalletVault.MNEM))
    }

    /** forget() removes the phrase record with the key record. */
    @Test
    fun forgetRemovesThePhraseRecord() {
        val files = NativeTestFiles()
        val v = vault(NativeTestWrap(), files)
        v.importMnemonicKey(eoa, keyOf(phrase), phrase)
        v.forget()
        assertTrue(files.map.isEmpty())
    }

    /** walletCredential: G1 and G2 with a stored phrase answer the mnemonic; G0 is no_key. */
    @Test
    fun walletCredentialAnswersTheStoredPhraseInG1AndG2() {
        val v = vault(NativeTestWrap(), NativeTestFiles())
        v.importMnemonicKey(eoa, keyOf(phrase), phrase)
        for (gate in listOf(NoKeyGate.Gate.G1, NoKeyGate.Gate.G2)) {
            val a = WalletCredential.answer(v, gate)
            assertTrue("$gate", a is WalletCredential.Answer.Ok)
            val r = (a as WalletCredential.Answer.Ok).result
            assertEquals("mnemonic", r.getString("credentialKind"))
            assertEquals(phrase, r.getString("mnemonic"))
            assertEquals(eoa, r.getString("eoa"))
            assertFalse(r.has("eoaPrivateKey"))
        }
        assertEquals("no_key", (WalletCredential.answer(v, NoKeyGate.Gate.G0) as WalletCredential.Answer.Refused).code)
    }

    /** walletCredential with no stored phrase (U-A1 device, or a 32-byte key device): unavailable, never the key. */
    @Test
    fun walletCredentialWithoutPhraseIsUnavailableNotTheKey() {
        val v = vault(NativeTestWrap(), NativeTestFiles())
        v.importKey(eoa, keyOf(phrase))
        val a = WalletCredential.answer(v, NoKeyGate.Gate.G1)
        assertEquals("unavailable", (a as WalletCredential.Answer.Refused).code)
    }

    /** walletCredential with an unreadable record answers unavailable (retryable), not no_key. */
    @Test
    fun walletCredentialOnAnUnreadableRecordIsUnavailable() {
        val files = NativeTestFiles()
        val wrap = NativeTestWrap()
        val v = vault(wrap, files)
        v.importMnemonicKey(eoa, keyOf(phrase), phrase)
        wrap.openOverride = { ByteArray(32) { 9 } }
        val a = WalletCredential.answer(v, NoKeyGate.Gate.G2)
        assertEquals("unavailable", (a as WalletCredential.Answer.Refused).code)
    }

    /** The marker of a record without a phrase is unchanged from before this rule (existing devices keep their marker). */
    @Test
    fun markerWithoutPhraseIsTheRecordDigestAsBefore() {
        val files = NativeTestFiles()
        val v = vault(NativeTestWrap(), files)
        v.importKey(eoa, keyOf(phrase))
        val rec = files.map[NativeWalletVault.REC]!!
        assertArrayEquals(NativeWalletVault.markerOf(rec, null), files.map[NativeWalletVault.MARK])
        assertNull(files.map[NativeWalletVault.MNEM])
    }
}
