package network.conet.chat.nativekey

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Synthetic cases SO-01..SO-17 of the v2 decided text (spec-59e-synthetic-vectors.v2.json, sha256 5dc22e1b…). Accounts are the
 * synthetic test phrases; the wrap and the files are the test doubles. SO-15 (explicit empty) runs on the discard path and is
 * covered by its own vectors; SO-16 (explicit clear) is pending a and is skipped.
 */
class SpecV2SealTest {
    private val oldPhrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    private val newPhrase = "legal winner thank year wave sausage worth useful legal winner thank yellow"
    private val thirdPhrase = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"

    private fun keyOf(phrase: String): ByteArray = checkNotNull(MnemonicDerivation.deriveKey(phrase))
    private fun eoaOf(key: ByteArray): String = checkNotNull(WalletAddress.fromPrivateKey(key))

    private fun oldAccount(wrap: NativeTestWrap, files: VaultFiles): NativeWalletVault {
        val vault = NativeWalletVault(wrap, files)
        val key = keyOf(oldPhrase)
        assertEquals(NativeWalletVault.Import.OK, vault.importMnemonicKey(eoaOf(key), key, oldPhrase))
        return vault
    }

    private fun isolatedOf(files: NativeTestFiles, name: String): List<String> =
        files.map.keys.filter { it.startsWith("$name.isolated.") }

    /** A file double whose hooks run after a rename, after a write, or on a read (to inject the chosen fault). */
    private class Faulty(val inner: NativeTestFiles) : VaultFiles {
        var afterRename: ((String, String) -> Unit)? = null
        var afterWrite: ((String) -> Unit)? = null
        var corruptReadOnce: String? = null

        override fun read(name: String): ByteArray? {
            if (corruptReadOnce == name) {
                corruptReadOnce = null
                return "garbage".toByteArray()
            }
            return inner.read(name)
        }
        override fun write(name: String, bytes: ByteArray) {
            inner.write(name, bytes)
            afterWrite?.invoke(name)
        }
        override fun delete(name: String) = inner.delete(name)
        override fun names(): List<String> = inner.names()
        override fun rename(from: String, to: String) {
            inner.rename(from, to)
            afterRename?.invoke(from, to)
        }
    }

    private fun snapshot(files: NativeTestFiles): Map<String, String> =
        files.map.mapValues { (_, b) -> digest(b) }

    private fun digest(b: ByteArray): String = java.security.MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }

    // SO-01: success: the old copy is kept, the new record is in place, the intent is cleared, retained is written with its fields.
    @Test fun so01_success() {
        val wrap = NativeTestWrap(); val files = NativeTestFiles()
        val vault = oldAccount(wrap, files)
        val oldRec = files.map[NativeWalletVault.REC]!!.copyOf()
        val key = keyOf(newPhrase)
        assertEquals(NativeWalletVault.SyncOutcome.UPDATED, vault.syncPhrase(eoaOf(key), key, newPhrase))
        val iso = isolatedOf(files, NativeWalletVault.REC)
        assertEquals(1, iso.size)
        assertArrayEquals(oldRec, files.map[iso.single()])
        assertFalse(files.map.containsKey(NativeWalletVault.PENDING))
        val retained = JSONObjectOf(files.map.getValue(NativeWalletVault.RETAINED))
        // v3.1 §七 (SO-23): exactly these fields; nothing sensitive.
        assertEquals(setOf("oldEoa", "time", "auditRef", "isolatedNames", "oldSha"), retained.keys().asSequence().toSet())
        assertEquals(iso.single(), retained.getJSONArray("isolatedNames").getString(0))
        assertTrue(String(files.map.getValue(NativeWalletVault.AUDIT)).contains("isolated_for_new_slot"))
    }

    // SO-02: a copy whose bytes differ from the old digest after the seal: the old names are restored, nothing is written.
    @Test fun so02_sealReadbackDigestMismatchRestoresWithoutWriting() {
        val wrap = NativeTestWrap(); val inner = NativeTestFiles()
        val vault0 = oldAccount(wrap, inner)
        val oldRec = inner.map[NativeWalletVault.REC]!!.copyOf()
        val faulty = Faulty(inner)
        // The read-back of the copy returns other bytes once (the stored copy itself is intact): the seal does not verify.
        faulty.afterRename = { from, to -> if (from == NativeWalletVault.REC) faulty.corruptReadOnce = to }
        val vault = NativeWalletVault(wrap, faulty)
        val key = keyOf(newPhrase)
        assertEquals(NativeWalletVault.SyncOutcome.SEALING_FAILED, vault.syncPhrase(eoaOf(key), key, newPhrase))
        assertArrayEquals("the old record is back at its name", oldRec, inner.map[NativeWalletVault.REC])
        assertTrue("no isolated copy is left", isolatedOf(inner, NativeWalletVault.REC).isEmpty())
        assertFalse("the intent marker is cleared", inner.map.containsKey(NativeWalletVault.PENDING))
        assertNotNull(vault0)
    }

    // SO-03: the old account does not open from its copy after the seal (the wrap key changed): restored, retryable.
    @Test fun so03_copyDoesNotOpenToTheOldAccountRestores() {
        val wrap = NativeTestWrap(); val files = NativeTestFiles()
        oldAccount(wrap, files)
        val oldRec = files.map[NativeWalletVault.REC]!!.copyOf()
        val faulty = Faulty(files)
        faulty.afterRename = { from, _ -> if (from == NativeWalletVault.REC) wrap.deleteKey() }
        val vault = NativeWalletVault(wrap, faulty)
        val key = keyOf(newPhrase)
        assertEquals(NativeWalletVault.SyncOutcome.SEALING_FAILED, vault.syncPhrase(eoaOf(key), key, newPhrase))
        assertArrayEquals(oldRec, files.map[NativeWalletVault.REC])
        assertTrue(isolatedOf(files, NativeWalletVault.REC).isEmpty())
    }

    // SO-04: the write of the new value fails with the fixed name empty: the copy is renamed back, bytes unchanged.
    @Test fun so04_writeFailureRestoresTheCopy() {
        val wrap = NativeTestWrap(); val files = NativeTestFiles()
        oldAccount(wrap, files)
        val oldRec = files.map[NativeWalletVault.REC]!!.copyOf()
        files.failWrite = NativeWalletVault.REC
        val key = keyOf(newPhrase)
        assertEquals(NativeWalletVault.SyncOutcome.WRITE_FAILED, NativeWalletVault(wrap, files).syncPhrase(eoaOf(key), key, newPhrase))
        assertArrayEquals(oldRec, files.map[NativeWalletVault.REC])
        assertTrue(isolatedOf(files, NativeWalletVault.REC).isEmpty())
        assertFalse(files.map.containsKey(NativeWalletVault.PENDING))
    }

    // SO-05: a write fails with the fixed name non-empty and the restore cannot complete: both kept, unknown, nothing deleted.
    @Test fun so05_partialWriteKeepsBothAndIsUnknown() {
        val wrap = NativeTestWrap(); val files = NativeTestFiles()
        oldAccount(wrap, files)
        val key = keyOf(newPhrase)
        files.failWrite = NativeWalletVault.COMMIT
        files.failRename = { it.contains(".isolated.") }
        val outcome = NativeWalletVault(wrap, files).syncPhrase(eoaOf(key), key, newPhrase)
        assertTrue("not an update: $outcome", outcome != NativeWalletVault.SyncOutcome.UPDATED)
        // The isolated copies are kept: the sealed old record and the partial new record that the failed write moved (kept, not erased).
        assertEquals("the isolated copies are kept", 2, isolatedOf(files, NativeWalletVault.REC).size)
        assertTrue(files.map.containsKey(NativeWalletVault.PENDING))
    }

    // SO-06: the read-back after the write does not match, fixed name non-empty: both kept, unknown.
    @Test fun so06_readbackMismatchFixedNameNonEmptyKeepsBoth() {
        val wrap = NativeTestWrap(); val inner = NativeTestFiles()
        oldAccount(wrap, inner)
        val faulty = Faulty(inner)
        faulty.afterWrite = { name -> if (name == NativeWalletVault.REC) faulty.corruptReadOnce = NativeWalletVault.REC }
        // The rollback cannot remove the new record (its removal fails): the fixed name stays non-empty, so both are kept, unknown.
        // The first move of REC is the isolation of the old record (it succeeds); the second is the kept move of the new record in the rollback (it fails).
        var recMoves = 0
        inner.failRename = { if (it == NativeWalletVault.REC) { recMoves++; recMoves >= 2 } else false }
        val vault = NativeWalletVault(wrap, faulty)
        val key = keyOf(newPhrase)
        val outcome = vault.syncPhrase(eoaOf(key), key, newPhrase)
        assertTrue("not an update: $outcome", outcome != NativeWalletVault.SyncOutcome.UPDATED)
        assertEquals(1, isolatedOf(inner, NativeWalletVault.REC).size)
        assertTrue("the new record stays under its name", inner.map.containsKey(NativeWalletVault.REC))
        assertTrue(inner.map.containsKey(NativeWalletVault.PENDING))
    }

    // SO-07: the read-back does not match with the fixed name empty: the copy is renamed back.
    @Test fun so07_readbackMismatchFixedNameEmptyRestores() {
        val wrap = NativeTestWrap(); val inner = NativeTestFiles()
        oldAccount(wrap, inner)
        val oldRec = inner.map[NativeWalletVault.REC]!!.copyOf()
        val faulty = Faulty(inner)
        faulty.afterWrite = { name -> if (name == NativeWalletVault.REC) inner.map.remove(NativeWalletVault.REC) }
        val key = keyOf(newPhrase)
        assertEquals(NativeWalletVault.SyncOutcome.READBACK_FAILED, NativeWalletVault(wrap, faulty).syncPhrase(eoaOf(key), key, newPhrase))
        assertArrayEquals(oldRec, inner.map[NativeWalletVault.REC])
        assertTrue(isolatedOf(inner, NativeWalletVault.REC).isEmpty())
    }

    // SO-08: interrupted after the seal, before the new write: startup recovery renames the copy back.
    @Test fun so08_interruptionAfterTheSealRecoversAtStartup() {
        val wrap = NativeTestWrap(); val inner = NativeTestFiles()
        oldAccount(wrap, inner)
        val oldRec = inner.map[NativeWalletVault.REC]!!.copyOf()
        val faulty = Faulty(inner)
        // The process stops after the last old name has moved: every fixed name is empty, every copy holds its old bytes.
        val last = listOf(NativeWalletVault.REC, NativeWalletVault.MNEM, NativeWalletVault.MARK, NativeWalletVault.COMMIT).last { inner.map.containsKey(it) }
        faulty.afterRename = { from, _ -> if (from == last) throw NativeTestCrash() }
        val key = keyOf(newPhrase)
        try {
            NativeWalletVault(wrap, faulty).syncPhrase(eoaOf(key), key, newPhrase)
        } catch (_: NativeTestCrash) {
        }
        assertTrue(inner.map.containsKey(NativeWalletVault.PENDING))
        assertTrue(NativeWalletVault(wrap, inner).settleForWrite())
        assertArrayEquals(oldRec, inner.map[NativeWalletVault.REC])
        assertTrue(isolatedOf(inner, NativeWalletVault.REC).isEmpty())
        assertFalse(inner.map.containsKey(NativeWalletVault.PENDING))
    }

    // SO-09: interrupted after the new record is written, before its digest is recorded: startup rolls forward and keeps the copy.
    @Test fun so09_interruptionAfterTheWriteRollsForwardAndKeepsTheCopy() {
        val wrap = NativeTestWrap(); val inner = NativeTestFiles()
        oldAccount(wrap, inner)
        val key = keyOf(newPhrase)
        // The process stops after the new record and its phrase are written, before the digest is recorded.
        inner.crashAfterWrite = NativeWalletVault.MNEM
        try {
            NativeWalletVault(wrap, inner).syncPhrase(eoaOf(key), key, newPhrase)
        } catch (_: NativeTestCrash) {
        }
        inner.crashAfterWrite = null
        assertTrue(NativeWalletVault(wrap, inner).settleForWrite())
        assertEquals(1, isolatedOf(inner, NativeWalletVault.REC).size)
        assertFalse(inner.map.containsKey(NativeWalletVault.PENDING))
        assertTrue(inner.map.containsKey(NativeWalletVault.RETAINED))
        assertEquals(eoaOf(key), (NativeWalletVault(wrap, inner).mnemonicOf() as NativeWalletVault.MnemonicRead.Stored).eoa)
    }

    // SO-10: interrupted; the copy's bytes no longer match the old digest and the fixed name is empty: both kept, unknown.
    @Test fun so10_interruptionWithAChangedCopyKeepsBothAndIsUnknown() {
        val wrap = NativeTestWrap(); val inner = NativeTestFiles()
        oldAccount(wrap, inner)
        val faulty = Faulty(inner)
        faulty.afterRename = { from, to -> if (from == NativeWalletVault.REC) { inner.map[to] = "changed".toByteArray(); throw NativeTestCrash() } }
        val key = keyOf(newPhrase)
        try {
            NativeWalletVault(wrap, faulty).syncPhrase(eoaOf(key), key, newPhrase)
        } catch (_: NativeTestCrash) {
        }
        val vault = NativeWalletVault(wrap, inner)
        assertFalse(vault.settleForWrite())
        assertEquals("unknown", vault.readStateLabel())
        assertEquals(1, isolatedOf(inner, NativeWalletVault.REC).size)
        assertTrue(inner.map.containsKey(NativeWalletVault.PENDING))
    }

    // SO-11: while the intent marker stands the read is unknown, and three reads change no file.
    @Test fun so11_unknownReadsChangeNothing() {
        val wrap = NativeTestWrap(); val files = NativeTestFiles()
        oldAccount(wrap, files)
        files.map[NativeWalletVault.PENDING] = """{"v":1,"eoa":"${eoaOf(keyOf(newPhrase))}","items":[],"preWriteAliasAbsent":false}""".toByteArray()
        val before = snapshot(files)
        val vault = NativeWalletVault(wrap, files)
        repeat(3) { assertEquals("unknown", vault.readStateLabel()) }
        assertEquals(before, snapshot(files))
    }

    // SO-12: after success the state is retained, not unknown, and reads change no file.
    @Test fun so12_retainedAfterSuccessAndReadsChangeNothing() {
        val wrap = NativeTestWrap(); val files = NativeTestFiles()
        val vault = oldAccount(wrap, files)
        val key = keyOf(newPhrase)
        assertEquals(NativeWalletVault.SyncOutcome.UPDATED, vault.syncPhrase(eoaOf(key), key, newPhrase))
        val before = snapshot(files)
        repeat(3) { assertEquals("retained", NativeWalletVault(wrap, files).readStateLabel()) }
        assertEquals(before, snapshot(files))
    }

    // SO-13: the same account and the same phrase: idempotent, no seal, no audit row, nothing written.
    @Test fun so13_sameAccountIsIdempotent() {
        val wrap = NativeTestWrap(); val files = NativeTestFiles()
        val vault = oldAccount(wrap, files)
        val before = snapshot(files)
        val key = keyOf(oldPhrase)
        assertEquals(NativeWalletVault.SyncOutcome.IDEMPOTENT, vault.syncPhrase(eoaOf(key), key, oldPhrase))
        assertEquals(before, snapshot(files))
    }

    // SO-14: the phrase does not derive the PWA EOA: refused as bad input, no seal, no intent marker.
    @Test fun so14_mismatchedEoaIsRefusedWithoutAnyChange() {
        val wrap = NativeTestWrap(); val files = NativeTestFiles()
        val vault = oldAccount(wrap, files)
        val before = snapshot(files)
        val key = keyOf(newPhrase)
        val otherEoa = eoaOf(keyOf(thirdPhrase))
        assertEquals(NativeWalletVault.SyncOutcome.BAD_INPUT, vault.syncPhrase(otherEoa, key, newPhrase))
        assertEquals(before, snapshot(files))
        assertFalse(files.map.containsKey(NativeWalletVault.PENDING))
    }

    // SO-15 (v2 vectors, decided: 明确空沿既有规格，原生旧记录不变): the PWA's explicit empty with a native account that is valid (phrase present)
    // does not drop, overwrite or isolate anything; no audit row, no intent, nothing removed. The private-only drop (33(5)) is a different case
    // (a key record with no phrase) and is not claimed here.
    @Test fun so15_explicitEmptyWithAValidAccountChangesNothing() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        val key = keyOf(oldPhrase)
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importMnemonicKey(eoaOf(key), key, oldPhrase))
        val vault = NativeWalletVault(wrap, files)
        val before = snapshot(files)
        assertEquals("valid", vault.nativeStateLabel())
        assertEquals(NativeWalletVault.DiscardOutcome.NOT_DROPPED, vault.discardPrivateOnly(true, vault.nativeStateLabel()))
        assertEquals(before, snapshot(files))
        assertFalse(files.map.containsKey(NativeWalletVault.AUDIT))
        assertFalse(files.map.containsKey(NativeWalletVault.INTENT))
        assertEquals("ok", vault.readStateLabel())
    }

    // SO-16: explicit user clear is pending a (v2 §七 (b)); skipped, nothing removes an isolated copy in this code.
    @Test fun so16_explicitClearIsSkippedPendingTheRuling() {
        org.junit.Assume.assumeTrue("pending (v2 §七 b)", false)
    }

    // SO-17: no automatic path removes an isolated copy: read, same-account write, and restart leave it in place.
    @Test fun so17_noAutomaticPathRemovesTheCopy() {
        val wrap = NativeTestWrap(); val files = NativeTestFiles()
        val vault = oldAccount(wrap, files)
        val key = keyOf(newPhrase)
        assertEquals(NativeWalletVault.SyncOutcome.UPDATED, vault.syncPhrase(eoaOf(key), key, newPhrase))
        val iso = isolatedOf(files, NativeWalletVault.REC).single()
        assertEquals(NativeWalletVault.SyncOutcome.IDEMPOTENT, vault.syncPhrase(eoaOf(key), key, newPhrase))
        NativeWalletVault(wrap, files).readStateLabel()
        assertTrue(NativeWalletVault(wrap, files).settleForWrite())
        assertNotNull(files.map[iso])
        assertNull(files.map[iso + ".gone"])
    }

    private fun JSONObjectOf(bytes: ByteArray) = org.json.JSONObject(String(bytes, Charsets.UTF_8))
}
