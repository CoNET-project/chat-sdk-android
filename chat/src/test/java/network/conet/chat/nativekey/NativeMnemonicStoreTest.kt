package network.conet.chat.nativekey

import network.conet.chat.nativekey.NativeWalletVault.Import
import network.conet.chat.nativekey.NativeWalletVault.MnemonicRead
import network.conet.chat.nativekey.NativeWalletVault.State
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
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

    /** A phrase record with no key record and no intent is existing data: it is kept and the account is locked (spec §25.52Y.42 第 4 項 (d)). */
    @Test
    fun orphanPhraseRecordWithoutIntentIsKept() {
        val files = NativeTestFiles()
        files.map[NativeWalletVault.MNEM] = "{\"record\":1}".toByteArray(Charsets.UTF_8)
        val s = vault(NativeTestWrap(), files).state()
        assertEquals("record_missing", (s as State.Locked).reason)
        assertTrue(files.map.containsKey(NativeWalletVault.MNEM))
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

    /** walletCredential with a phrase that cannot be read: unavailable, and the key is not given in its place (spec 25.52Y.42 第 5 项). */
    @Test
    fun unreadablePhraseIsUnavailableNotTheKey() {
        val files = NativeTestFiles()
        val v = vault(NativeTestWrap(), files)
        v.importMnemonicKey(eoa, keyOf(phrase), phrase)
        files.map[NativeWalletVault.MNEM] = "{\"record\":1,\"eoa\":\"$eoa\",\"sealed\":\"00\"}".toByteArray(Charsets.UTF_8)
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

    /**
     * Upgrade keeps the wallet (PM R1865; spec 25.52Y.40 第 5 项 U-A1, U-A2): the files written before this change (a key record and its
     * marker) are read by the new code byte for byte unchanged, the address is the same, and no phrase is generated.
     */
    @Test
    fun upgradeOfAKeyOnlyWalletLeavesFilesAndAddressUnchanged() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        // The pre-change device: key record and marker only.
        assertEquals(Import.OK, vault(wrap, files).importKey(eoa, keyOf(phrase)))
        val before = files.map.mapValues { it.value.copyOf() }
        // The upgraded app opens the same files (a new vault over the same store).
        val upgraded = vault(wrap, files)
        val s = upgraded.state()
        assertEquals(eoa, (s as State.Ready).eoa)
        assertTrue(upgraded.mnemonicOf() is MnemonicRead.Missing)
        assertEquals("eoa_key", (WalletCredential.answer(upgraded, NoKeyGate.Gate.G1) as WalletCredential.Answer.Ok).result.getString("credentialKind"))
        assertEquals(before.keys, files.map.keys)
        for ((name, bytes) in before) assertArrayEquals("$name changed on upgrade", bytes, files.map[name])
    }

    /** U-A2: a phrase-imported wallet keeps its phrase and address across a restart (a new vault over the same files). */
    @Test
    fun phraseWalletSurvivesARestartWithTheSameAddress() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        assertEquals(Import.OK, vault(wrap, files).importMnemonicKey(eoa, keyOf(phrase), phrase))
        val before = files.map.mapValues { it.value.copyOf() }
        val restarted = vault(wrap, files)
        assertEquals(eoa, (restarted.state() as State.Ready).eoa)
        val read = restarted.mnemonicOf() as MnemonicRead.Stored
        assertEquals(phrase, read.phrase)
        assertEquals(eoa, read.eoa)
        for ((name, bytes) in before) assertArrayEquals("$name changed on restart", bytes, files.map[name])
    }

    /** U-A14: a key-only account answers walletCredential with eoaPrivateKey, no phrase field; the key derives the record's address. */
    @Test
    fun keyOnlyAccountAnswersTheKeyWithoutAPhrase() {
        val v = vault(NativeTestWrap(), NativeTestFiles())
        v.importKey(eoa, keyOf(phrase))
        val r = (WalletCredential.answer(v, NoKeyGate.Gate.G1) as WalletCredential.Answer.Ok).result
        assertEquals("eoa_key", r.getString("credentialKind"))
        assertFalse(r.has("mnemonic"))
        val hex = r.getString("eoaPrivateKey")
        assertTrue(hex.startsWith("0x") && hex.length == 66)
        val back = hex.substring(2).chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        assertEquals(eoa, WalletAddress.fromPrivateKey(back))
        assertEquals(eoa, r.getString("eoa"))
        // G2 gets the same answer.
        assertTrue(WalletCredential.answer(v, NoKeyGate.Gate.G2) is WalletCredential.Answer.Ok)
    }

    /** U-A15: walletEoaAddress answers only the address, in G1 and G2; G0 is no_key; it never carries the key. */
    @Test
    fun walletEoaAddressAnswersOnlyTheAddress() {
        val v = vault(NativeTestWrap(), NativeTestFiles())
        v.importKey(eoa, keyOf(phrase))
        for (gate in listOf(NoKeyGate.Gate.G1, NoKeyGate.Gate.G2)) {
            val r = (WalletCredential.eoaAddress(v, gate) as WalletCredential.Answer.Ok).result
            assertEquals(eoa, r.getString("eoa"))
            assertEquals(1, r.length())
        }
        assertEquals("no_key", (WalletCredential.eoaAddress(v, NoKeyGate.Gate.G0) as WalletCredential.Answer.Refused).code)
    }

    /** U-A16: a 32-byte-key device whose page copy was cleared: walletCredential and walletEoaAddress give the same address. */
    @Test
    fun clearedKeyOnlyDeviceGivesTheSameAddressOnBothPaths() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        vault(wrap, files).importKey(eoa, keyOf(phrase))
        val restarted = vault(wrap, files)
        val cred = (WalletCredential.answer(restarted, NoKeyGate.Gate.G1) as WalletCredential.Answer.Ok).result
        val addr = (WalletCredential.eoaAddress(restarted, NoKeyGate.Gate.G1) as WalletCredential.Answer.Ok).result
        assertEquals(cred.getString("eoa"), addr.getString("eoa"))
    }

    /**
     * U-A17 (PM R1878): a key record with no marker and no intent is a wallet from before the marker rule. It is usable as it is:
     * the record opens and its address matches. Nothing is deleted or written, and the file bytes do not change.
     */
    @Test
    fun existingRecordWithoutMarkerOrIntentIsUsableAndKeptThroughEveryPath() {
        val files = NativeTestFiles()
        val wrap = NativeTestWrap()
        vault(wrap, files).importKey(eoa, keyOf(phrase))
        files.map.remove(NativeWalletVault.MARK)
        files.map.remove(NativeWalletVault.COMMIT)
        val before = files.map.mapValues { it.value.copyOf() }
        val v = vault(wrap, files)
        assertEquals(eoa, (v.state() as State.Ready).eoa)
        assertArrayEquals(keyOf(phrase), v.unlock())
        assertTrue(v.mnemonicOf() is MnemonicRead.Missing)
        assertEquals("eoa_key", (WalletCredential.answer(v, NoKeyGate.Gate.G1) as WalletCredential.Answer.Ok).result.getString("credentialKind"))
        assertEquals(eoa, (WalletCredential.eoaAddress(v, NoKeyGate.Gate.G1) as WalletCredential.Answer.Ok).result.getString("eoa"))
        assertEquals(before.keys, files.map.keys)
        for ((name, bytes) in before) assertArrayEquals("$name changed", bytes, files.map[name])
    }

    /** An unreadable intent deletes nothing and reports rollback_pending. */
    @Test
    fun unreadableIntentDeletesNothingAndReportsPending() {
        val files = NativeTestFiles()
        val wrap = NativeTestWrap()
        vault(wrap, files).importKey(eoa, keyOf(phrase))
        files.map[NativeWalletVault.INTENT] = "garbage".toByteArray(Charsets.UTF_8)
        val before = files.map.mapValues { it.value.copyOf() }
        assertEquals("rollback_pending", (vault(wrap, files).state() as State.Locked).reason)
        for ((name, bytes) in before) assertArrayEquals("$name changed", bytes, files.map[name])
    }

    /** A committed import whose intent removal did not happen (a crash after the commit record): the account is usable and the next start removes the intent. */
    @Test
    fun committedImportWithALeftoverIntentStaysUsable() {
        val files = NativeTestFiles().apply { crashAfterWrite = NativeWalletVault.COMMIT }
        val wrap = NativeTestWrap()
        assertThrows(NativeTestCrash::class.java) { vault(wrap, files).importMnemonicKey(eoa, keyOf(phrase), phrase) }
        files.crashAfterWrite = null
        assertTrue(files.map.containsKey(NativeWalletVault.INTENT))
        val v = vault(wrap, files)
        assertEquals(eoa, (v.state() as State.Ready).eoa)
        assertFalse(files.map.containsKey(NativeWalletVault.INTENT))
        assertTrue(v.mnemonicOf() is MnemonicRead.Stored)
    }

    /** A crash after the key record leaves an intent and an uncommitted record: the next start rolls it back and the account is free to import again. */
    @Test
    fun uncommittedImportIsRolledBackOnTheNextStart() {
        val files = NativeTestFiles().apply { crashAfterWrite = NativeWalletVault.REC }
        val wrap = NativeTestWrap()
        assertThrows(NativeTestCrash::class.java) { vault(wrap, files).importMnemonicKey(eoa, keyOf(phrase), phrase) }
        files.crashAfterWrite = null
        assertTrue(files.map.containsKey(NativeWalletVault.INTENT))
        val v = vault(wrap, files)
        assertTrue(v.state() is State.NoKey)
        assertFalse(files.map.containsKey(NativeWalletVault.REC))
        assertFalse(files.map.containsKey(NativeWalletVault.INTENT))
        assertEquals(Import.OK, v.importMnemonicKey(eoa, keyOf(phrase), phrase))
    }

    /**
     * Native create (PM R1872, spec 25.52Y.42 第 2 (b) 项, r3nz 第 2 项): the account is made from the phrase its entropy spells. The phrase
     * derives the account's EOA m/44'/60'/0'/0/0 (so the stored phrase restores the key); the phrase is sealed; the result holds only the address.
     */
    @Test
    fun createSealsThePhraseAndTheDerivedAddressIsTheReturnedAccount() {
        for (seed in 0 until 6) {
            val entropy = ByteArray(16) { (it * 7 + seed * 31 + 3).toByte() }
            val files = NativeTestFiles()
            val v = vault(NativeTestWrap(), files)
            val r = NativeAccountCreate.create(v, entropy.copyOf())
            assertEquals("seed $seed", NativeAccountCreate.Code.OK, r.code)
            val eoaOut = r.eoa!!
            val phrase = NativeAccountCreate.phraseOf(entropy)
            assertEquals("seed $seed: 12 words", 12, phrase.split(" ").size)
            // The phrase derives the address that was created and recorded.
            val derived = MnemonicDerivation.deriveKey(phrase)!!
            assertEquals("seed $seed: phrase derives the recorded EOA", eoaOut, WalletAddress.fromPrivateKey(derived))
            derived.fill(0)
            // The phrase is sealed, not stored in the clear, and reads back as the recorded account's phrase.
            assertTrue("seed $seed: phrase record stored", files.map.containsKey(NativeWalletVault.MNEM))
            val read = v.mnemonicOf()
            assertTrue("seed $seed: phrase readable", read is MnemonicRead.Stored)
            assertEquals(phrase, (read as MnemonicRead.Stored).phrase)
            assertEquals(eoaOut, read.eoa)
            // The result carries only the address: no phrase, no key.
            assertFalse("seed $seed: result has no phrase", r.toString().contains(phrase))
            for ((name, stored) in files.map) {
                assertFalse("seed $seed: $name holds the phrase in the clear",
                    String(stored, Charsets.ISO_8859_1).contains(phrase))
            }
        }
    }

    /** T-IU3 (r3nz, §25.52Y.42 第 13 项): an intent envelope that cannot be parsed deletes nothing, reports rollback_pending, and the slot is unavailable. */
    @Test
    fun unparseableIntentEnvelopeDeletesNothingAndIsUnreadable() {
        val files = NativeTestFiles()
        val wrap = NativeTestWrap()
        vault(wrap, files).importKey(eoa, keyOf(phrase))
        files.map.remove(NativeWalletVault.COMMIT)
        files.map[NativeWalletVault.INTENT] = "{not an envelope".toByteArray(Charsets.UTF_8)
        val before = files.map.mapValues { it.value.copyOf() }
        val v = vault(wrap, files)
        assertEquals("rollback_pending", (v.state() as State.Locked).reason)
        assertTrue(v.mnemonicOf() is MnemonicRead.Unavailable)
        assertEquals("not_ready", NoKeyGate.walletStatusFor(NoKeyGate.gateOf(v.state(), false), v.state()).getString("status"))
        assertEquals("unreadable", NoKeyGate.walletStatusFor(NoKeyGate.gateOf(v.state(), false), v.state()).getString("notReadyReason"))
        assertEquals(before.keys, files.map.keys)
        for ((name, bytes) in before) assertArrayEquals("$name changed", bytes, files.map[name])
    }

    /** T-IU4 (r3nz): a valid intent whose commit envelope cannot be opened is treated as uncommitted: rollback_pending, unavailable, nothing deleted. */
    @Test
    fun intentWithAnUnopenableCommitIsUncommittedAndNothingIsDeleted() {
        val files = NativeTestFiles().apply { crashAfterWrite = NativeWalletVault.COMMIT }
        val wrap = NativeTestWrap()
        assertThrows(NativeTestCrash::class.java) { vault(wrap, files).importMnemonicKey(eoa, keyOf(phrase), phrase) }
        files.crashAfterWrite = null
        // The commit file is there but its sealed body does not open (tampered).
        files.map[NativeWalletVault.COMMIT] = "{\"v\":1,\"kind\":\"commit\",\"eoa\":\"$eoa\",\"sealed\":\"00\"}".toByteArray(Charsets.UTF_8)
        assertTrue(files.map.containsKey(NativeWalletVault.INTENT))
        val before = files.map.mapValues { it.value.copyOf() }
        val v = vault(wrap, files)
        assertEquals("rollback_pending", (v.state() as State.Locked).reason)
        assertEquals("not_ready", NoKeyGate.walletStatusFor(NoKeyGate.gateOf(v.state(), false), v.state()).getString("status"))
        assertEquals("unreadable", NoKeyGate.walletStatusFor(NoKeyGate.gateOf(v.state(), false), v.state()).getString("notReadyReason"))
        assertTrue(v.mnemonicOf() is MnemonicRead.Unavailable)
        assertEquals(before.keys, files.map.keys)
        for ((name, bytes) in before) assertArrayEquals("$name changed", bytes, files.map[name])
    }

    /**
     * T-IU6 (r3nz): an existing key record with no marker, no intent and no commit is usable, and nothing is changed. The intent-pending
     * case above locks the whole vault (one account per vault), so this case is checked on its own; a combined case needs a ruling.
     */
    @Test
    fun existingUnmarkedKeyRecordIsUsableWithNoIntentAndNoCommit() {
        val files = NativeTestFiles()
        val wrap = NativeTestWrap()
        vault(wrap, files).importKey(eoa, keyOf(phrase))
        files.map.remove(NativeWalletVault.MARK)
        files.map.remove(NativeWalletVault.COMMIT)
        val before = files.map.mapValues { it.value.copyOf() }
        val v = vault(wrap, files)
        assertEquals(eoa, (v.state() as State.Ready).eoa)
        assertEquals("not_ready", NoKeyGate.walletStatusFor(NoKeyGate.gateOf(v.state(), false), v.state()).getString("status"))
        for ((name, bytes) in before) assertArrayEquals("$name changed", bytes, files.map[name])
    }
}
