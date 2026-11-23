package network.conet.chat.nativekey

import network.conet.chat.ConetChatCryptoUtil
import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Overwrite guard (fixes 1 and A): a native record is replaced only when the old key record and the old
 * phrase both open under the old account, and the phrase derives that account. Otherwise nothing moves and the answer is NOT_READY.
 */
class OverwriteVerifiedCopyTest {
    private val phraseA = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    private val phraseB = "legal winner thank year wave sausage worth useful legal winner thank yellow"
    private val phraseC = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"

    private fun keyOf(p: String) = checkNotNull(MnemonicDerivation.deriveKey(p))
    private fun eoaOf(k: ByteArray) = checkNotNull(WalletAddress.fromPrivateKey(k))

    /** A native record holding account A with its phrase. */
    private fun vaultOfA(wrap: KeyWrap, files: NativeTestFiles): String {
        val key = keyOf(phraseA)
        val eoa = eoaOf(key)
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importMnemonicKey(eoa, key, phraseA))
        return eoa
    }

    @Test
    fun aPhraseOfAnotherAccountUnderTheEnvelopeOfAIsRefusedAndNothingMoves() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        val eoaA = vaultOfA(wrap, files)
        // The phrase envelope names A, but its sealed phrase is B's (sealed under A's AAD, so it opens).
        val mnem = JSONObject(String(files.map[NativeWalletVault.MNEM]!!, Charsets.UTF_8))
        mnem.put("sealed", ConetChatCryptoUtil.toHex(wrap.seal(NativeWalletVault.mnemAad(eoaA), phraseB.toByteArray(Charsets.UTF_8))))
        files.map[NativeWalletVault.MNEM] = mnem.toString().toByteArray(Charsets.UTF_8)
        // The marker covers the phrase bytes; recompute it so only the derivation check can refuse the copy.
        files.map[NativeWalletVault.MARK] = NativeWalletVault.markerOf(files.map[NativeWalletVault.REC]!!, files.map[NativeWalletVault.MNEM])
        val vault = NativeWalletVault(wrap, files)
        assertTrue("the vault reads as ready before the overwrite", vault.state() is NativeWalletVault.State.Ready)
        val before = files.map.mapValues { it.value.copyOf() }
        val keyC = keyOf(phraseC)
        assertEquals(NativeWalletVault.SyncOutcome.OLD_COPY_UNVERIFIED, vault.syncPhrase(eoaOf(keyC), keyC, phraseC))
        assertEquals(before.keys, files.map.keys)
        before.forEach { (name, bytes) -> assertArrayEquals("$name unchanged", bytes, files.map[name]) }
    }

    /**
     * The distinction the project rule needs: an absent phrase file (a key-only account, overwritten) is not an unreadable one. A phrase file that
     * is present but does not open refuses the overwrite and nothing moves.
     */
    @Test
    fun aPresentButUnreadablePhraseIsRefusedWhileAnAbsentOneIsOverwritten() {
        // The wrap key is present (a known wrap): the unreadable copy is then an unverifiable old copy, not an unknown wrap.
        val wrap = object : KeyWrap by NativeTestWrap() {
            override fun presence(): WrapKeyPresence = WrapKeyPresence.PRESENT
        }
        val files = NativeTestFiles()
        vaultOfA(wrap, files)
        val mnem = JSONObject(String(files.map[NativeWalletVault.MNEM]!!, Charsets.UTF_8))
        mnem.put("sealed", "00")
        files.map[NativeWalletVault.MNEM] = mnem.toString().toByteArray(Charsets.UTF_8)
        files.map[NativeWalletVault.MARK] = NativeWalletVault.markerOf(files.map[NativeWalletVault.REC]!!, files.map[NativeWalletVault.MNEM])
        val before = files.map.mapValues { it.value.copyOf() }
        val keyC = keyOf(phraseC)
        val stateBefore = NativeWalletVault(wrap, files).state()
        assertEquals("present but unreadable: refused (state ${(stateBefore as? NativeWalletVault.State.Locked)?.reason ?: stateBefore})", NativeWalletVault.SyncOutcome.OLD_COPY_UNVERIFIED,
            NativeWalletVault(wrap, files).syncPhrase(eoaOf(keyC), keyC, phraseC))
        before.forEach { (name, bytes) -> assertArrayEquals("$name unchanged", bytes, files.map[name]) }
        // The same record with the phrase file absent (a key-only account): overwritten, the old copy kept.
        files.map.remove(NativeWalletVault.MNEM)
        files.map.remove(NativeWalletVault.MARK)
        files.map[NativeWalletVault.MARK] = NativeWalletVault.markerOf(files.map[NativeWalletVault.REC]!!, null)
        val oldRecBytes = files.map[NativeWalletVault.REC]!!.copyOf()
        assertEquals("absent: overwritten", NativeWalletVault.SyncOutcome.UPDATED,
            NativeWalletVault(wrap, files).syncPhrase(eoaOf(keyC), keyC, phraseC))
        // The old copy is kept under an isolated name, byte for byte (read back, same address, then the swap).
        val kept = files.map.keys.filter { it.startsWith("${NativeWalletVault.REC}.isolated.") }
        assertEquals("the old record is kept isolated", 1, kept.size)
        assertArrayEquals("kept bytes are the old record", oldRecBytes, files.map[kept.single()])
    }

    @Test
    fun aKeyRecordThatDoesNotOpenIsNotOverwrittenEvenWhenTheWrapKeyIsConfirmedAbsent() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        vaultOfA(wrap, files)
        // The key record is damaged: it no longer opens under the wrap key.
        files.map[NativeWalletVault.REC] = JSONObject(String(files.map[NativeWalletVault.REC]!!, Charsets.UTF_8))
            .put("sealed", "00").toString().toByteArray(Charsets.UTF_8)
        val before = files.map.mapValues { it.value.copyOf() }
        val keyC = keyOf(phraseC)
        val answer = NativeWalletVault(wrap, files).syncPhrase(eoaOf(keyC), keyC, phraseC)
        assertTrue("refused, not overwritten: $answer", answer != NativeWalletVault.SyncOutcome.UPDATED)
        before.forEach { (name, bytes) -> assertArrayEquals("$name unchanged", bytes, files.map[name]) }
    }

    @Test
    fun aVerifiedCopyOfAIsStillOverwrittenByAnotherAccountAndKeptIsolated() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        val eoaA = vaultOfA(wrap, files)
        val keyB = keyOf(phraseB)
        val eoaB = eoaOf(keyB)
        assertEquals(NativeWalletVault.SyncOutcome.UPDATED, NativeWalletVault(wrap, files).syncPhrase(eoaB, keyB, phraseB))
        val isolated = files.map.keys.filter { it.startsWith("${NativeWalletVault.REC}.isolated.") }
        assertEquals("the old record is kept under an isolated name", 1, isolated.size)
        val kept = JSONObject(String(files.map[isolated.single()]!!, Charsets.UTF_8))
        assertEquals("the kept record still names A", eoaA, kept.getString("eoa"))
        assertEquals("the new record names B", eoaB, JSONObject(String(files.map[NativeWalletVault.REC]!!, Charsets.UTF_8)).getString("eoa"))
    }

    /** account_address.v1 (project rule 2026-11-18): a present flag that names another account refuses the overwrite; a missing one does not. */
    @Test
    fun anAccountAddressThatDoesNotMatchTheRecordRefusesTheOverwrite() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        val eoaA = vaultOfA(wrap, files)
        val keyC = keyOf(phraseC)
        val eoaB = eoaOf(keyOf(phraseB))
        val before = files.map.mapValues { it.value.copyOf() }
        val vault = NativeWalletVault(wrap, files)
        assertEquals("flag names B, the record is A: refused", NativeWalletVault.SyncOutcome.OLD_COPY_UNVERIFIED,
            vault.syncPhrase(eoaOf(keyC), keyC, phraseC) { eoaB })
        before.forEach { (name, bytes) -> assertArrayEquals("$name unchanged", bytes, files.map[name]) }
        assertEquals("flag unreadable: refused", NativeWalletVault.SyncOutcome.OLD_COPY_UNVERIFIED,
            vault.syncPhrase(eoaOf(keyC), keyC, phraseC) { throw IllegalStateException("unreadable") })
        before.forEach { (name, bytes) -> assertArrayEquals("$name unchanged", bytes, files.map[name]) }
        assertEquals("flag missing is not a reason to refuse", NativeWalletVault.SyncOutcome.UPDATED,
            vault.syncPhrase(eoaOf(keyC), keyC, phraseC) { null })
        // A fresh vault of A again, with the flag naming A: overwritten.
        val files2 = NativeTestFiles()
        assertEquals(eoaA, vaultOfA(wrap, files2))
        assertEquals("flag names A: overwritten", NativeWalletVault.SyncOutcome.UPDATED,
            NativeWalletVault(wrap, files2).syncPhrase(eoaOf(keyC), keyC, phraseC) { eoaA })
    }
}
