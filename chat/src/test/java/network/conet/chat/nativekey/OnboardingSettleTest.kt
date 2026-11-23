package network.conet.chat.nativekey

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Project 2026-11-18 (G2 onboarding): a key-only residue of an unfinished first write answers absent, and onboarding writes a new account only
 * after the pending write is settled. A settle that does not finish refuses the write and overwrites nothing. Real write paths only.
 */
class OnboardingSettleTest {
    private val phraseA = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    private val phraseB = "legal winner thank year wave sausage worth useful legal winner thank yellow"
    private fun keyOf(p: String) = checkNotNull(MnemonicDerivation.deriveKey(p))
    private fun eoaOf(p: String) = checkNotNull(WalletAddress.fromPrivateKey(keyOf(p)))
    private val wrap = NativeTestWrap()

    /** An unfinished first write of A's key (the key record is written, the intent stays): the residue of an interrupted onboarding. */
    private fun unfinishedFirstWriteOfA(files: NativeTestFiles) {
        files.crashAfterWrite = NativeWalletVault.REC
        try {
            NativeWalletVault(wrap, files).importKey(eoaOf(phraseA), keyOf(phraseA))
        } catch (_: NativeTestCrash) {
        }
        files.crashAfterWrite = null
    }

    @Test fun aSettledResidueLetsOnboardingWriteTheNewAccount() {
        val files = NativeTestFiles()
        unfinishedFirstWriteOfA(files)
        val result = NativeWalletVault(wrap, files).importMnemonicKey(eoaOf(phraseB), keyOf(phraseB), phraseB)
        assertEquals("the residue is settled, then the new account is written: $result", NativeWalletVault.Import.OK, result)
    }

    @Test fun anUnfinishedSettleRefusesTheOnboardingWriteAndOverwritesNothing() {
        val files = NativeTestFiles()
        unfinishedFirstWriteOfA(files)
        val before = files.map.mapValues { it.value.copyOf() }
        // Every rename fails: the residue cannot be rolled back, so the settle does not finish.
        files.failRename = { true }
        val result = NativeWalletVault(wrap, files).importMnemonicKey(eoaOf(phraseB), keyOf(phraseB), phraseB)
        // The existing path refuses: the unfinished intent makes the state Locked, and a Locked state refuses the write (RECORD_EXISTS). Not OK.
        assertTrue("refused, not written: $result", result != NativeWalletVault.Import.OK)
        assertEquals("the existing refusal of a locked state", NativeWalletVault.Import.RECORD_EXISTS, result)
        before.forEach { (name, bytes) -> assertArrayEquals("$name unchanged", bytes, files.map[name]) }
    }

    /**
     * A partial settle: the first rename of the residue succeeds, then the next one fails (as after a crash in the middle of the
     * settle). The onboarding write is refused, nothing is overwritten, and every byte string is still held (fixed or isolated).
     */
    @Test fun aPartialSettleRefusesTheOnboardingWriteAndKeepsEveryByteString() {
        val files = NativeTestFiles()
        // An unfinished first write of A with two records written (the key record and the phrase), then a crash: the residue has two fixed names.
        files.crashAfterWrite = NativeWalletVault.MNEM
        try {
            NativeWalletVault(wrap, files).importMnemonicKey(eoaOf(phraseA), keyOf(phraseA), phraseA)
        } catch (_: NativeTestCrash) {
        }
        files.crashAfterWrite = null
        assertTrue("two fixed records are the residue", files.map.containsKey(NativeWalletVault.REC) && files.map.containsKey(NativeWalletVault.MNEM))
        val before = files.map.values.map { java.security.MessageDigest.getInstance("SHA-256").digest(it).toList() }.sortedBy { it.toString() }
        // The first rename succeeds, every later rename fails: the settle stops after one move.
        var renames = 0
        files.failRename = { renames++ >= 1 }
        val result = NativeWalletVault(wrap, files).importMnemonicKey(eoaOf(phraseB), keyOf(phraseB), phraseB)
        // Observed: one move succeeded and the settle stopped there (the second move was not attempted or failed; only one rename call was made).
        assertEquals("exactly one move was attempted", 1, renames)
        assertTrue("the first move is on disk as an isolated copy", files.map.keys.any { it.contains(".isolated.") })
        assertTrue("refused, not written: $result", result != NativeWalletVault.Import.OK)
        // Nothing is overwritten: each byte string that existed is still held under some name.
        val after = files.map.values.map { java.security.MessageDigest.getInstance("SHA-256").digest(it).toList() }
        assertTrue("every byte string is still held", before.all { it in after })
        // The fixed key record, if present, is still the first account's record (never the new account's).
        files.map[NativeWalletVault.REC]?.let { rec ->
            assertEquals("the fixed record is not the new account", eoaOf(phraseA), org.json.JSONObject(String(rec, Charsets.UTF_8)).getString("eoa"))
        }
    }
}
