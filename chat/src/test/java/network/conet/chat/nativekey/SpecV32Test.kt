package network.conet.chat.nativekey

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.IOException

/**
 * Synthetic cases of v3.2 that are not in SpecV2SealTest / SpecV3SealTest: SO-22C, SO-22D (unknown: enumeration failed, keystore
 * transiently unavailable), SO-24 (the wire reasons), SO-25 (the window: the new record is written, the phrase is not, no digest recorded).
 * Source: spec-59e-synthetic-vectors.v3.2-add.json (sha256 5e99fae3…), text spec-59e-revision-text-v3.2-decided.md (sha256 7c963df2…).
 */
class SpecV32Test {
    private val oldPhrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    private val newPhrase = "legal winner thank year wave sausage worth useful legal winner thank yellow"

    @Before fun newLaunch() {
        NativeWalletVault.resetLaunchForTests()
    }

    private fun keyOf(phrase: String): ByteArray = checkNotNull(MnemonicDerivation.deriveKey(phrase))
    private fun eoaOf(key: ByteArray): String = checkNotNull(WalletAddress.fromPrivateKey(key))

    private class VaultWrap(val inner: NativeTestWrap) : KeyWrap {
        var presenceValue: WrapKeyPresence = WrapKeyPresence.UNKNOWN
        override fun seal(aad: ByteArray, plain: ByteArray): ByteArray = inner.seal(aad, plain)
        override fun open(aad: ByteArray, sealed: ByteArray): ByteArray? = inner.open(aad, sealed)
        override fun deleteKey(): Boolean = inner.deleteKey()
        override fun presence(): WrapKeyPresence = presenceValue
    }

    private fun oldAccount(wrap: VaultWrap, files: VaultFiles): NativeWalletVault {
        val vault = NativeWalletVault(wrap, files)
        val key = keyOf(oldPhrase)
        assertEquals(NativeWalletVault.Import.OK, vault.importMnemonicKey(eoaOf(key), key, oldPhrase))
        return vault
    }

    private fun isolatedOf(files: NativeTestFiles, name: String): List<String> = files.map.keys.filter { it.startsWith("$name.isolated.") }
    private fun digest(b: ByteArray): String = java.security.MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }
    private fun snapshot(files: NativeTestFiles): Map<String, String> = files.map.mapValues { (_, b) -> digest(b) }

    /** Makes every read of the wrap fail, as a transient keystore failure would. */
    private class FlakyFiles(val inner: NativeTestFiles) : VaultFiles {
        var failReads = false
        override fun read(name: String): ByteArray? = if (failReads) throw IOException("keystore transiently unavailable") else inner.read(name)
        override fun write(name: String, bytes: ByteArray) = inner.write(name, bytes)
        override fun delete(name: String) = inner.delete(name)
        override fun names(): List<String> = inner.names()
        override fun rename(from: String, to: String) = inner.rename(from, to)
    }

    // SO-22C: the keystore enumeration failed (presence unknown) and the old record does not open: not a confirmed loss, nothing written.
    @Test fun so22C_enumerationFailureIsUnknownAndNothingIsWritten() {
        val wrap = VaultWrap(NativeTestWrap()); val files = NativeTestFiles()
        oldAccount(wrap, files)
        wrap.inner.deleteKey()
        wrap.presenceValue = WrapKeyPresence.UNKNOWN
        val before = snapshot(files)
        val key = keyOf(newPhrase)
        assertEquals(NativeWalletVault.SyncOutcome.NOT_READY, NativeWalletVault(wrap, files).syncPhrase(eoaOf(key), key, newPhrase))
        assertEquals(before, snapshot(files))
        assertFalse(files.map.containsKey(NativeWalletVault.PENDING))
    }

    // SO-22D: the keystore is transiently unavailable (reads throw): unknown, nothing moves, retryable.
    @Test fun so22D_transientKeystoreFailureIsUnknownAndRetryable() {
        val wrap = VaultWrap(NativeTestWrap()); val inner = NativeTestFiles()
        oldAccount(wrap, inner)
        val before = snapshot(inner)
        val flaky = FlakyFiles(inner)
        flaky.failReads = true
        val key = keyOf(newPhrase)
        assertEquals(NativeWalletVault.SyncOutcome.NOT_READY, NativeWalletVault(wrap, flaky).syncPhrase(eoaOf(key), key, newPhrase))
        assertEquals(before, snapshot(inner))
        flaky.failReads = false
        assertEquals(NativeWalletVault.SyncOutcome.UPDATED, NativeWalletVault(wrap, flaky).syncPhrase(eoaOf(key), key, newPhrase))
    }

    // SO-24: every failure answer on the wire has write_failed with one of the two words; the proposed words are not on the wire.
    @Test fun so24_wireReasonsAreTheTwoWordsOnly() {
        // rollback_pending and old_copy_unverified are write_failed reasons now; the forbidden words are the rest.
        val forbidden = setOf("sealing_failed", "readback_mismatch", "unknown_loss", "not_settled", "readback_failed")
        for (o in NativeWalletVault.SyncOutcome.values()) {
            val a = NativeSyncAck.answerOf(o)
            if (a.code == NativeSyncAck.WRITE_FAILED) {
                assertTrue("$o reason ${a.reason}", a.reason in setOf("internal_state", "storage_write", "rollback_pending", "old_copy_unverified"))
                assertFalse("$o reason ${a.reason}", a.reason in forbidden)
            }
        }
        assertEquals("write_failed", NativeSyncAck.answerOf(NativeWalletVault.SyncOutcome.READBACK_FAILED).code)
        assertEquals("internal_state", NativeSyncAck.answerOf(NativeWalletVault.SyncOutcome.READBACK_FAILED).reason)
    }

    /** A file double that can corrupt the phrase on its restore write (a failed per-entry restore), while [corruptMnem] is set. */
    private class CorruptingFiles(val inner: NativeTestFiles) : VaultFiles {
        var corruptMnem = false
        override fun read(name: String): ByteArray? = inner.read(name)
        override fun write(name: String, bytes: ByteArray) {
            inner.write(name, bytes)
            if (corruptMnem && name == NativeWalletVault.MNEM) inner.map[NativeWalletVault.MNEM] = "corrupt".toByteArray()
        }
        override fun delete(name: String) = inner.delete(name)
        override fun names(): List<String> = inner.names()
        override fun rename(from: String, to: String) = inner.rename(from, to)
    }

    /** Leaves the window: REC written, phrase not written, no digest recorded (the process stops right after the record write). */
    private fun stopInWindow(wrap: VaultWrap, files: NativeTestFiles): ByteArray {
        val oldRec = files.map[NativeWalletVault.REC]!!.copyOf()
        val key = keyOf(newPhrase)
        files.crashAfterWrite = NativeWalletVault.REC
        try {
            NativeWalletVault(wrap, files).syncPhrase(eoaOf(key), key, newPhrase)
        } catch (_: NativeTestCrash) {
        }
        files.crashAfterWrite = null
        return oldRec
    }

    private fun assertOldAccountInPlace(wrap: VaultWrap, files: NativeTestFiles, oldRec: ByteArray, oldMnem: ByteArray, oldMark: ByteArray, oldCommit: ByteArray) {
        assertArrayEquals(oldRec, files.map[NativeWalletVault.REC])
        assertArrayEquals(oldMnem, files.map[NativeWalletVault.MNEM])
        assertArrayEquals(oldMark, files.map[NativeWalletVault.MARK])
        assertArrayEquals(oldCommit, files.map[NativeWalletVault.COMMIT])
        assertFalse(files.map.containsKey(NativeWalletVault.PENDING))
        assertEquals("ok", NativeWalletVault(wrap, files).readStateLabel())
    }

    // SO-25: REC written, phrase not written. Restarted: the partial new record is isolated; every entry is restored by digest and read back.
    @Test fun so25_windowRestoresEveryEntryAndKeepsTheOldAccount() {
        val wrap = VaultWrap(NativeTestWrap()); val files = NativeTestFiles()
        oldAccount(wrap, files)
        val oldMnem = files.map[NativeWalletVault.MNEM]!!.copyOf()
        val oldMark = files.map[NativeWalletVault.MARK]!!.copyOf()
        val oldCommit = files.map[NativeWalletVault.COMMIT]!!.copyOf()
        val oldEoa = (NativeWalletVault(wrap, files).mnemonicOf() as NativeWalletVault.MnemonicRead.Stored).eoa
        val oldRec = stopInWindow(wrap, files)
        assertFalse("the phrase was not written", files.map.containsKey(NativeWalletVault.MNEM) && files.map.getValue(NativeWalletVault.MNEM).contentEquals(newPhrase.toByteArray()))
        val restarted = NativeWalletVault(wrap, files)
        assertTrue(restarted.settleForWrite())
        assertOldAccountInPlace(wrap, files, oldRec, oldMnem, oldMark, oldCommit)
        assertEquals("the partial new record and the sealed old record are both kept", 2, isolatedOf(files, NativeWalletVault.REC).size)
        // The old record opens to the EOA it named (the same as before the move).
        assertEquals(oldEoa, (restarted.mnemonicOf() as NativeWalletVault.MnemonicRead.Stored).eoa)
        // One audit row per restored entry.
        assertEquals(4, String(files.map.getValue(NativeWalletVault.AUDIT)).lines().count { it.contains("restored_from_sealed_copy") })
        // The write can be retried from the old account.
        val key = keyOf(newPhrase)
        assertEquals(NativeWalletVault.SyncOutcome.UPDATED, restarted.syncPhrase(eoaOf(key), key, newPhrase))
    }

    // SO-25b: interrupted after REC and MNEM were restored: the next launch resumes from the start and reaches the same final state.
    @Test fun so25b_interruptionDuringTheWindowResumesToTheSameState() {
        val wrap = VaultWrap(NativeTestWrap()); val files = NativeTestFiles()
        oldAccount(wrap, files)
        val oldMnem = files.map[NativeWalletVault.MNEM]!!.copyOf()
        val oldMark = files.map[NativeWalletVault.MARK]!!.copyOf()
        val oldCommit = files.map[NativeWalletVault.COMMIT]!!.copyOf()
        val oldRec = stopInWindow(wrap, files)
        files.crashAfterWrite = NativeWalletVault.MNEM
        try {
            NativeWalletVault(wrap, files).settleForWrite()
        } catch (_: NativeTestCrash) {
        }
        files.crashAfterWrite = null
        NativeWalletVault.resetLaunchForTests()
        assertTrue(NativeWalletVault(wrap, files).settleForWrite())
        assertOldAccountInPlace(wrap, files, oldRec, oldMnem, oldMark, oldCommit)
        assertEquals(2, isolatedOf(files, NativeWalletVault.REC).size)
    }

    // SO-25c: a restore fails: everything is kept, rollback_pending; one automatic resume per launch; a user retry runs it again.
    @Test fun so25c_failedWindowRestoreKeepsEverythingAndResumesOncePerLaunch() {
        val wrap = VaultWrap(NativeTestWrap()); val inner = NativeTestFiles()
        oldAccount(wrap, inner)
        val oldMnem = inner.map[NativeWalletVault.MNEM]!!.copyOf()
        val oldMark = inner.map[NativeWalletVault.MARK]!!.copyOf()
        val oldCommit = inner.map[NativeWalletVault.COMMIT]!!.copyOf()
        val oldRec = stopInWindow(wrap, inner)
        val files = CorruptingFiles(inner)
        files.corruptMnem = true
        // Launch 1: the automatic resume fails; a second call in the same launch does not try again.
        NativeWalletVault.resetLaunchForTests()
        assertFalse(NativeWalletVault(wrap, files).settleForWrite())
        assertFalse(NativeWalletVault(wrap, files).settleForWrite())
        assertTrue(inner.map.containsKey(NativeWalletVault.PENDING))
        assertEquals(1, String(inner.map.getValue(NativeWalletVault.AUDIT)).lines().count { it.contains("window_restore_failed") })
        assertEquals("nothing deleted: the sealed copies and the partial new record stay", 2, isolatedOf(inner, NativeWalletVault.REC).size)
        // Launch 2: again one attempt, again a failure, no loop.
        NativeWalletVault.resetLaunchForTests()
        assertFalse(NativeWalletVault(wrap, files).settleForWrite())
        assertTrue(inner.map.containsKey(NativeWalletVault.PENDING))
        // The fault clears; a user retry through the existing entry runs the resume again and succeeds.
        files.corruptMnem = false
        assertTrue(NativeWalletVault(wrap, files).retryPendingByUser())
        assertOldAccountInPlace(wrap, inner, oldRec, oldMnem, oldMark, oldCommit)
    }

    // SO-22E: a marker that does not match: unknown, nothing written, retryable.
    @Test fun so22E_markerMismatchIsUnknownAndNothingIsWritten() {
        val wrap = VaultWrap(NativeTestWrap()); val files = NativeTestFiles()
        oldAccount(wrap, files)
        files.map[NativeWalletVault.MARK] = "wrong-marker".toByteArray()
        val before = snapshot(files)
        val key = keyOf(newPhrase)
        assertEquals(NativeWalletVault.SyncOutcome.NOT_READY, NativeWalletVault(wrap, files).syncPhrase(eoaOf(key), key, newPhrase))
        assertEquals(before, snapshot(files))
        assertFalse(files.map.containsKey(NativeWalletVault.PENDING))
        assertTrue(isolatedOf(files, NativeWalletVault.REC).isEmpty())
    }

    // SO-22F: a keystore error that is not "item not found": not a confirmed loss; unknown, nothing written.
    @Test fun so22F_otherKeystoreErrorIsUnknownAndNothingIsWritten() {
        val inner = NativeTestWrap(); val files = NativeTestFiles()
        val wrap = VaultWrap(inner)
        oldAccount(wrap, files)
        val before = snapshot(files)
        // The wrap now throws on every open (an error that is not a missing alias), and the presence is not confirmed.
        val erroring = object : KeyWrap {
            override fun seal(aad: ByteArray, plain: ByteArray): ByteArray = inner.seal(aad, plain)
            override fun open(aad: ByteArray, sealed: ByteArray): ByteArray? = throw IllegalStateException("errSecInteractionNotAllowed")
            override fun deleteKey(): Boolean = true
            override fun presence(): WrapKeyPresence = WrapKeyPresence.UNKNOWN
        }
        val key = keyOf(newPhrase)
        assertEquals(NativeWalletVault.SyncOutcome.NOT_READY, NativeWalletVault(erroring, files).syncPhrase(eoaOf(key), key, newPhrase))
        assertEquals(before, snapshot(files))
        assertFalse(files.map.containsKey(NativeWalletVault.PENDING))
    }

    // SO-25d (E2-1, completeness review): a fixed name that holds something other than the old bytes (an unverified restore) is kept
    // under an isolated name before the sealed copy is restored there; nothing is overwritten.
    @Test fun so25d_existingContentUnderAFixedNameIsKeptBeforeTheRestore() {
        val wrap = VaultWrap(NativeTestWrap()); val files = NativeTestFiles()
        oldAccount(wrap, files)
        val oldMnem = files.map[NativeWalletVault.MNEM]!!.copyOf()
        val oldMark = files.map[NativeWalletVault.MARK]!!.copyOf()
        val oldCommit = files.map[NativeWalletVault.COMMIT]!!.copyOf()
        val oldRec = stopInWindow(wrap, files)
        // An earlier unverified restore left other bytes under the phrase's fixed name.
        val junk = "unverified-restore".toByteArray()
        files.map[NativeWalletVault.MNEM] = junk
        assertTrue(NativeWalletVault(wrap, files).settleForWrite())
        assertOldAccountInPlace(wrap, files, oldRec, oldMnem, oldMark, oldCommit)
        // The junk is kept (isolated, audited), not overwritten; the sealed copy of the phrase stays too (two isolated names).
        val kept = isolatedOf(files, NativeWalletVault.MNEM)
        assertEquals(2, kept.size)
        assertTrue("the junk is among the kept names", kept.any { files.map[it]!!.contentEquals(junk) })
        assertTrue(String(files.map.getValue(NativeWalletVault.AUDIT)).contains("preserved_before_restore"))
    }

    // SO-25e (E2-1): when the content under a fixed name cannot be kept, the restore does not overwrite it: everything stays, rollback_pending.
    @Test fun so25e_unkeepableContentIsNotOverwritten() {
        val wrap = VaultWrap(NativeTestWrap()); val files = NativeTestFiles()
        oldAccount(wrap, files)
        stopInWindow(wrap, files)
        val junk = "unverified-restore".toByteArray()
        files.map[NativeWalletVault.MNEM] = junk
        files.failRename = { it == NativeWalletVault.MNEM }
        val before = files.map.filterKeys { it != NativeWalletVault.AUDIT }.mapValues { digest(it.value) }
        assertFalse(NativeWalletVault(wrap, files).settleForWrite())
        assertArrayEquals(junk, files.map[NativeWalletVault.MNEM])
        // Nothing is lost: every earlier file is still there, under its name or as a kept (isolated) copy with the same bytes.
        for ((name, sha) in before) {
            val kept = files.map[name]?.let { digest(it) } == sha || files.map.values.any { digest(it) == sha }
            assertTrue("$name is kept", kept)
        }
        assertTrue(files.map.containsKey(NativeWalletVault.PENDING))
    }

    // Independent review (E2-1 split), item 1: the rename succeeds but the audit row cannot be written. The file stays under its
    // isolated name without an audit row (the current behaviour, stated in the handoff); nothing is deleted, the marker stays, and
    // the next launch resumes the window from the same shape.
    @Test fun so25f_auditFailureAfterTheRenameKeepsTheFileIsolatedAndResumesLater() {
        val wrap = VaultWrap(NativeTestWrap()); val files = NativeTestFiles()
        oldAccount(wrap, files)
        val oldMnem = files.map[NativeWalletVault.MNEM]!!.copyOf()
        val oldMark = files.map[NativeWalletVault.MARK]!!.copyOf()
        val oldCommit = files.map[NativeWalletVault.COMMIT]!!.copyOf()
        val oldRec = stopInWindow(wrap, files)
        files.failWrite = NativeWalletVault.AUDIT
        assertFalse(NativeWalletVault(wrap, files).settleForWrite())
        assertTrue("the partial new record is isolated", isolatedOf(files, NativeWalletVault.REC).size >= 2)
        assertTrue(files.map.containsKey(NativeWalletVault.PENDING))
        val audit = files.map[NativeWalletVault.AUDIT]?.let { String(it, Charsets.UTF_8) } ?: ""
        assertFalse("no audit row was written for the isolation", audit.contains("partial_new_isolated"))
        // The fault clears: the next launch resumes from the same shape and reaches the old account in place.
        files.failWrite = null
        NativeWalletVault.resetLaunchForTests()
        assertTrue(NativeWalletVault(wrap, files).settleForWrite())
        assertOldAccountInPlace(wrap, files, oldRec, oldMnem, oldMark, oldCommit)
    }

    // ---- E2 附加 (E2-addendum.1, spec-59e-synthetic-vectors.v3.3.1-E2-addendum.1.json, sha256 09ff42c8…): SO-25d, SO-25e, SO-25f ----

    /**
     * The staged shape of the vector: the fixed REC name holds GARBAGE bytes; the sealed copy of the old REC is isolated; MNEM and COMMIT
     * are absent; the fixed MARK holds its old bytes; the intent marker is pending with no newRecordSha (items: REC and MARK).
     */
    private fun stageGarbageUnderRec(wrap: VaultWrap, files: NativeTestFiles): ByteArray {
        oldAccount(wrap, files)
        val oldRec = files.map[NativeWalletVault.REC]!!.copyOf()
        val oldMark = files.map[NativeWalletVault.MARK]!!.copyOf()
        val isoRec = "${NativeWalletVault.REC}.isolated.20261117T000000Z.aaaaaaaa"
        val isoMark = "${NativeWalletVault.MARK}.isolated.20261117T000000Z.bbbbbbbb"
        files.map.remove(NativeWalletVault.MNEM)
        files.map.remove(NativeWalletVault.COMMIT)
        files.map.remove(NativeWalletVault.INTENT)
        files.map[isoRec] = oldRec
        files.map[NativeWalletVault.REC] = "GARBAGE_BYTES".toByteArray()
        val eoa = eoaOf(keyOf(oldPhrase))
        files.map[NativeWalletVault.PENDING] = org.json.JSONObject().put("v", 1).put("utc", "2026-11-17T00:00:00Z").put("eoa", eoa)
            .put("preWriteAliasAbsent", false).put("newRecordSha", org.json.JSONObject.NULL)
            .put("items", org.json.JSONArray()
                .put(org.json.JSONObject().put("name", NativeWalletVault.REC).put("isolated", isoRec).put("oldSha", digest(oldRec)))
                .put(org.json.JSONObject().put("name", NativeWalletVault.MARK).put("isolated", isoMark).put("oldSha", digest(oldMark))))
            .toString().toByteArray(Charsets.UTF_8)
        return oldRec
    }

    // SO-25d (E2 附加 A1): the garbage under REC is renamed to an isolated name and kept, then the old REC is restored from its sealed copy.
    @Test fun so25d_garbageUnderTheFixedNameIsKeptThenTheOldBytesAreRestored() {
        val wrap = VaultWrap(NativeTestWrap()); val files = NativeTestFiles()
        val oldRec = stageGarbageUnderRec(wrap, files)
        assertTrue(NativeWalletVault(wrap, files).settleForWrite())
        assertArrayEquals(oldRec, files.map[NativeWalletVault.REC])
        assertEquals("the sealed copy and the garbage are both kept", 2, isolatedOf(files, NativeWalletVault.REC).size)
        assertTrue("the garbage is kept", isolatedOf(files, NativeWalletVault.REC).any { files.map[it]!!.contentEquals("GARBAGE_BYTES".toByteArray()) })
        assertFalse(files.map.containsKey(NativeWalletVault.PENDING))
        val audit = String(files.map.getValue(NativeWalletVault.AUDIT), Charsets.UTF_8)
        assertTrue(audit.contains("preserved_before_restore") || audit.contains("partial_new_isolated"))
        assertTrue(audit.contains("restored_from_sealed_copy"))
        assertEquals("ok", NativeWalletVault(wrap, files).readStateLabel())
    }

    // SO-25e (E2 附加 A2): the rename of the garbage fails: nothing is overwritten, everything is kept, rollback_pending.
    @Test fun so25e_aFailedRenameOverwritesNothingAndStaysRollbackPending() {
        val wrap = VaultWrap(NativeTestWrap()); val files = NativeTestFiles()
        stageGarbageUnderRec(wrap, files)
        files.failRename = { it == NativeWalletVault.REC }
        val before = files.map.mapValues { it.value.copyOf() }
        assertFalse(NativeWalletVault(wrap, files).settleForWrite())
        assertArrayEquals("GARBAGE_BYTES".toByteArray(), files.map[NativeWalletVault.REC])
        before.forEach { (name, bytes) -> assertTrue("$name is kept", bytes.contentEquals(files.map[name])) }
        assertTrue(files.map.containsKey(NativeWalletVault.PENDING))
    }

    // SO-25f (E2 附加 A3): the rename succeeds and the audit row cannot be written: no rollback of the rename, nothing deleted;
    // the next launch backfills the missing row (matched by digest) and continues with SO-25d's steps.
    @Test fun so25f_auditFailureAfterRenameIsBackfilledOnTheNextLaunch() {
        val wrap = VaultWrap(NativeTestWrap()); val files = NativeTestFiles()
        val oldRec = stageGarbageUnderRec(wrap, files)
        files.failWrite = NativeWalletVault.AUDIT
        assertFalse(NativeWalletVault(wrap, files).settleForWrite())
        assertFalse("the rename is not rolled back", files.map.containsKey(NativeWalletVault.REC) && files.map[NativeWalletVault.REC]!!.contentEquals("GARBAGE_BYTES".toByteArray()))
        assertFalse("the fixed REC name is empty", files.map.containsKey(NativeWalletVault.REC))
        assertTrue("the garbage stays isolated", isolatedOf(files, NativeWalletVault.REC).any { files.map[it]!!.contentEquals("GARBAGE_BYTES".toByteArray()) })
        assertTrue(files.map.containsKey(NativeWalletVault.PENDING))
        // Next launch: the fault cleared; the row is backfilled (by digest), then the resume completes.
        files.failWrite = null
        NativeWalletVault.resetLaunchForTests()
        assertTrue(NativeWalletVault(wrap, files).settleForWrite())
        assertArrayEquals(oldRec, files.map[NativeWalletVault.REC])
        val audit = String(files.map.getValue(NativeWalletVault.AUDIT), Charsets.UTF_8)
        assertTrue("the missing row is backfilled", audit.contains("audit_backfilled"))
        assertFalse(files.map.containsKey(NativeWalletVault.PENDING))
    }

    // SO-25f, the backfill fails again: everything is kept, rollback_pending; a user retry then completes.
    @Test fun so25f2_backfillFailureKeepsEverythingUntilTheUserRetries() {
        val wrap = VaultWrap(NativeTestWrap()); val files = NativeTestFiles()
        val oldRec = stageGarbageUnderRec(wrap, files)
        files.failWrite = NativeWalletVault.AUDIT
        assertFalse(NativeWalletVault(wrap, files).settleForWrite())
        NativeWalletVault.resetLaunchForTests()
        assertFalse(NativeWalletVault(wrap, files).settleForWrite())
        assertTrue("nothing deleted", isolatedOf(files, NativeWalletVault.REC).any { files.map[it]!!.contentEquals("GARBAGE_BYTES".toByteArray()) })
        assertTrue(files.map.containsKey(NativeWalletVault.PENDING))
        files.failWrite = null
        assertTrue(NativeWalletVault(wrap, files).retryPendingByUser())
        assertArrayEquals(oldRec, files.map[NativeWalletVault.REC])
    }

    // ---- 半写中断 (WK-style crash at each write point) and an interruption during the resume ----

    // Interrupted after the write of each restored entry (REC, MNEM, MARK, COMMIT): the next launch resumes and the old account is in place.
    @Test fun h1_interruptedAtEachRestoreWriteResumesToTheOldAccount() {
        for (name in listOf(NativeWalletVault.REC, NativeWalletVault.MNEM, NativeWalletVault.MARK, NativeWalletVault.COMMIT)) {
            val wrap = VaultWrap(NativeTestWrap()); val files = NativeTestFiles()
            oldAccount(wrap, files)
            val oldMnem = files.map[NativeWalletVault.MNEM]!!.copyOf()
            val oldMark = files.map[NativeWalletVault.MARK]!!.copyOf()
            val oldCommit = files.map[NativeWalletVault.COMMIT]!!.copyOf()
            val oldRec = stopInWindow(wrap, files)
            files.crashAfterWrite = name
            NativeWalletVault.resetLaunchForTests()
            try {
                NativeWalletVault(wrap, files).settleForWrite()
            } catch (_: NativeTestCrash) {
            }
            files.crashAfterWrite = null
            NativeWalletVault.resetLaunchForTests()
            assertTrue("interrupted at $name", NativeWalletVault(wrap, files).settleForWrite())
            assertOldAccountInPlace(wrap, files, oldRec, oldMnem, oldMark, oldCommit)
        }
    }

    // Interrupted during the resume, then again in the next resume: the third launch reaches the same final state.
    @Test fun h2_interruptedAgainDuringTheResumeStillReachesTheOldAccount() {
        val wrap = VaultWrap(NativeTestWrap()); val files = NativeTestFiles()
        oldAccount(wrap, files)
        val oldMnem = files.map[NativeWalletVault.MNEM]!!.copyOf()
        val oldMark = files.map[NativeWalletVault.MARK]!!.copyOf()
        val oldCommit = files.map[NativeWalletVault.COMMIT]!!.copyOf()
        val oldRec = stopInWindow(wrap, files)
        for (name in listOf(NativeWalletVault.MNEM, NativeWalletVault.COMMIT)) {
            files.crashAfterWrite = name
            NativeWalletVault.resetLaunchForTests()
            try {
                NativeWalletVault(wrap, files).settleForWrite()
            } catch (_: NativeTestCrash) {
            }
        }
        files.crashAfterWrite = null
        NativeWalletVault.resetLaunchForTests()
        assertTrue(NativeWalletVault(wrap, files).settleForWrite())
        assertOldAccountInPlace(wrap, files, oldRec, oldMnem, oldMark, oldCommit)
    }
}
