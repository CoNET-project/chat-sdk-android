package network.conet.chat.nativekey

import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Sealing, read-back and retention of the old native record during a PWA sync. Synthetic accounts only:
 * the phrases are the BIP-39 test vectors used by PwaWalletSyncTest, and the wrap and the files are the test doubles.
 *
 * Rules under test:
 *  - the old record is isolated, never removed; after a successful write its isolated copies are listed as retained;
 *  - a copy that opened before the isolation and does not open after it is a failed seal: nothing is written, the old names
 *    are restored, and the caller gets a retryable failure;
 *  - a failed write restores the old data; the same call can then be retried and succeeds;
 *  - the same phrase is idempotent and writes nothing (no retained list is created);
 *  - a restart (a new instance on the same files) sees the same state.
 */
class SealRetainTest {
    private val oldPhrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    private val newPhrase = "legal winner thank year wave sausage worth useful legal winner thank yellow"
    private val thirdPhrase = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"

    private fun keyOf(phrase: String): ByteArray = checkNotNull(MnemonicDerivation.deriveKey(phrase))
    private fun eoaOf(key: ByteArray): String = checkNotNull(WalletAddress.fromPrivateKey(key))

    private fun nativeWithOldPhrase(wrap: NativeTestWrap, files: NativeTestFiles): NativeWalletVault {
        val vault = NativeWalletVault(wrap, files)
        val key = keyOf(oldPhrase)
        assertEquals(NativeWalletVault.Import.OK, vault.importMnemonicKey(eoaOf(key), key, oldPhrase))
        return vault
    }

    /** Wraps the files so that the hook runs right after a rename (used to fail the seal or the write at a chosen point). */
    private class HookedFiles(val inner: NativeTestFiles, val afterRename: (from: String, to: String) -> Unit) : VaultFiles {
        override fun read(name: String): ByteArray? = inner.read(name)
        override fun write(name: String, bytes: ByteArray) = inner.write(name, bytes)
        override fun delete(name: String) = inner.delete(name)
        override fun names(): List<String> = inner.names()
        override fun rename(from: String, to: String) {
            inner.rename(from, to)
            afterRename(from, to)
        }
    }

    private fun retainedNames(vault: NativeWalletVault): List<String> = vault.isolationRetained().map { it.first }

    @Test
    fun aSuccessfulSyncKeepsTheOldRecordIsolatedAndListsItAsRetained() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        val vault = nativeWithOldPhrase(wrap, files)
        val oldRec = files.map[NativeWalletVault.REC]!!.copyOf()
        val key = keyOf(newPhrase)

        assertEquals(NativeWalletVault.SyncOutcome.UPDATED, vault.syncPhrase(eoaOf(key), key, newPhrase))

        val retained = vault.isolationRetained()
        assertEquals(listOf(NativeWalletVault.REC), retained.map { it.first } .filter { it == NativeWalletVault.REC })
        val iso = retained.single { it.first == NativeWalletVault.REC }.second
        assertArrayEquals("the isolated copy is the old record, byte for byte", oldRec, files.map[iso])
        assertTrue("the marker file is written", files.map.containsKey(NativeWalletVault.RETAINED))
        assertFalse("the pending marker is cleared on success", files.map.containsKey(NativeWalletVault.PENDING))
    }

    @Test
    fun theIsolatedCopiesAndTheAuditAreNeverRemovedAutomatically() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        val vault = nativeWithOldPhrase(wrap, files)
        val first = keyOf(newPhrase)
        assertEquals(NativeWalletVault.SyncOutcome.UPDATED, vault.syncPhrase(eoaOf(first), first, newPhrase))
        val firstIso = vault.isolationRetained().single { it.first == NativeWalletVault.REC }.second

        val second = keyOf(thirdPhrase)
        assertEquals(NativeWalletVault.SyncOutcome.UPDATED, vault.syncPhrase(eoaOf(second), second, thirdPhrase))

        assertTrue("the first isolated copy is still there", files.map.containsKey(firstIso))
        assertEquals("both sets are listed", 2, vault.isolationRetained().count { it.first == NativeWalletVault.REC })
        assertTrue("the audit is kept", files.map.containsKey(NativeWalletVault.AUDIT))
        assertTrue("the audit records the isolations", String(files.map.getValue(NativeWalletVault.AUDIT)).contains("isolated_for_new_slot"))
    }

    @Test
    fun aRestartSeesTheSameStateAndTheRetainedList() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        val vault = nativeWithOldPhrase(wrap, files)
        val key = keyOf(newPhrase)
        assertEquals(NativeWalletVault.SyncOutcome.UPDATED, vault.syncPhrase(eoaOf(key), key, newPhrase))

        val restarted = NativeWalletVault(wrap, files)
        assertTrue("the account is ready", restarted.state() is NativeWalletVault.State.Ready)
        val read = restarted.mnemonicOf()
        assertTrue(read is NativeWalletVault.MnemonicRead.Stored)
        assertEquals(newPhrase, (read as NativeWalletVault.MnemonicRead.Stored).phrase)
        assertEquals(retainedNames(vault), retainedNames(restarted))
    }

    @Test
    fun aCopyThatDoesNotOpenAfterTheIsolationFailsTheSealAndKeepsTheOldData() {
        val wrap = NativeTestWrap()
        val inner = NativeTestFiles()
        val vault0 = nativeWithOldPhrase(wrap, inner)
        val oldRec = inner.map[NativeWalletVault.REC]!!.copyOf()
        val oldMnem = inner.map[NativeWalletVault.MNEM]?.copyOf()
        // The wrap key changes right after the old record is isolated: the isolated copy opened before, and does not open now.
        val hooked = HookedFiles(inner) { from, _ ->
            if (from == NativeWalletVault.REC) wrap.deleteKey()
        }
        val vault = NativeWalletVault(wrap, hooked)
        val key = keyOf(newPhrase)

        val outcome = vault.syncPhrase(eoaOf(key), key, newPhrase)
        assertEquals("a refused seal is a failed seal", NativeWalletVault.SyncOutcome.SEALING_FAILED, outcome)
        assertArrayEquals("the old record is restored at its name", oldRec, inner.map[NativeWalletVault.REC])
        if (oldMnem != null) assertArrayEquals("the old phrase is restored at its name", oldMnem, inner.map[NativeWalletVault.MNEM])
        assertTrue("nothing is listed as retained", vault.isolationRetained().isEmpty())
        assertNotNull("the vault instance is still usable for reads", vault0)
    }

    @Test
    fun aFailedWriteRestoresTheOldDataAndTheSameSyncCanBeRetried() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        val vault = nativeWithOldPhrase(wrap, files)
        val oldRec = files.map[NativeWalletVault.REC]!!.copyOf()
        val key = keyOf(newPhrase)

        files.failWrite = NativeWalletVault.REC
        val failed = vault.syncPhrase(eoaOf(key), key, newPhrase)
        assertTrue("a failed write is not an update: $failed", failed != NativeWalletVault.SyncOutcome.UPDATED)
        assertArrayEquals("the old record is back at its name", oldRec, files.map[NativeWalletVault.REC])

        files.failWrite = null
        assertEquals(NativeWalletVault.SyncOutcome.UPDATED, vault.syncPhrase(eoaOf(key), key, newPhrase))
        assertEquals(newPhrase, (vault.mnemonicOf() as NativeWalletVault.MnemonicRead.Stored).phrase)
    }

    @Test
    fun theSamePhraseIsIdempotentAndCreatesNoRetainedList() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        val vault = nativeWithOldPhrase(wrap, files)
        val before = files.map.keys.toSet()
        val key = keyOf(oldPhrase)

        assertEquals(NativeWalletVault.SyncOutcome.IDEMPOTENT, vault.syncPhrase(eoaOf(key), key, oldPhrase))
        assertEquals(before, files.map.keys)
        assertTrue(vault.isolationRetained().isEmpty())
        assertFalse(files.map.containsKey(NativeWalletVault.RETAINED))
    }
}
