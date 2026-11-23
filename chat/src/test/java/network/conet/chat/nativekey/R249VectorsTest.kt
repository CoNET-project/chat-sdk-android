package network.conet.chat.nativekey

import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

/**
 * The r2.4.9 vectors of the sync path, one test per row: LC-01..09 (lifecycle route and the main path), AC-07..10 (answer mapping and
 * bad_request), RP-01..03 (re-read and epoch), DR and AU (narrow discard with audit), NS (nativeState values).
 * Real files for the write path ([AndroidVaultFiles] over a JVM temporary directory, with [FaultFiles]); the key wrap is a test double.
 * The command glue in [BeamioConetChatModule] runs on a device only (C-1 to C-5); its decisions are the functions these tests call.
 */
class R249VectorsTest {
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
        PwaEmptySignal.resetForTests()
    }

    @After
    fun tearDown() {
        MnemonicPreread.resetForTests()
        PwaEmptySignal.resetForTests()
    }

    private fun keyOf(p: String): ByteArray = checkNotNull(MnemonicDerivation.deriveKey(p))
    private fun eoaOf(k: ByteArray): String = checkNotNull(WalletAddress.fromPrivateKey(k))
    private fun vault(files: VaultFiles = AndroidVaultFiles(dir)) = NativeWalletVault(wrap, files)
    private fun body(phrase: String, seq: Any = 1, trusted: Boolean = true): JSONObject =
        JSONObject().put("phrase", phrase).put("seq", seq).also { if (trusted) it.put("trustedOrigin", true) }

    // LC-01 .. LC-09

    @Test
    fun lc01EmptyShellWithTheTrustedSyncWritesReadsBackAndAnswersOk() {
        assertEquals(NoKeyGate.Route.LIFECYCLE, NoKeyGate.route("pwaWalletSync"))
        assertNull(NativeSyncAck.admit(body(pwaPhrase)))
        assertNull(NativeSyncAck.formatError(body(pwaPhrase), pwaPhrase))
        val k = keyOf(pwaPhrase)
        assertTrue(MnemonicPreread.accept(1L))
        val outcome = vault().syncPhrase(eoaOf(k), k, pwaPhrase)
        assertEquals("ok", NativeSyncAck.codeOf(outcome))
        val fresh = vault()
        assertEquals(pwaPhrase, (fresh.mnemonicOf() as NativeWalletVault.MnemonicRead.Stored).phrase)
        assertNotNull(AndroidVaultFiles(dir).read(NativeWalletVault.REC))
    }

    @Test
    fun lc02WithoutTheTrustedOriginTheAnswerIsUntrustedAndNothingIsWritten() {
        assertEquals("untrusted_source", NativeSyncAck.admit(body(pwaPhrase, trusted = false)))
        assertTrue("nothing written", dir.listFiles()!!.isEmpty())
    }

    @Test
    fun lc03AnOldSequenceIsStaleAndNothingIsWritten() {
        assertTrue(MnemonicPreread.accept(5L))
        assertFalse(MnemonicPreread.accept(4L))
        assertTrue("nothing written", dir.listFiles()!!.isEmpty())
    }

    @Test
    fun lc04AnotherNoKeyCommandIsStillRefused() {
        assertEquals(NoKeyGate.Route.NO_KEY, NoKeyGate.route("historyFullSync"))
    }

    @Test
    fun lc05AnAllowedNoKeyCommandIsStillAllowed() {
        assertEquals(NoKeyGate.Route.WALLET_STATUS, NoKeyGate.route("walletStatus"))
    }

    /** LC-06 (r2.4.9 48(5)): with a key the path is the same lifecycle route. LC-10 and LC-11 below check the keyed conditions. */
    @Test
    fun lc06WithAKeyThePathIsTheSameLifecycleRouteBecauseTheRouteIsNameOnly() {
        assertEquals(NoKeyGate.Route.LIFECYCLE, NoKeyGate.route("pwaWalletSync"))
    }

    /** LC-10 (review 4): with a key, a request without trustedOrigin is untrusted_source and writes nothing. */
    @Test
    fun lc10WithAKeyAnUntrustedRequestIsRefusedAndWritesNothing() {
        val files = NativeTestFiles()
        val k = keyOf(nativePhrase)
        assertEquals(NativeWalletVault.Import.OK, vault(files).importMnemonicKey(eoaOf(k), k, nativePhrase))
        val before = files.map.mapValues { it.value.copyOf() }
        assertEquals("untrusted_source", NativeSyncAck.admit(body(pwaPhrase, trusted = false)))
        before.forEach { (n, b) -> assertArrayEquals("$n unchanged", b, files.map[n]) }
    }

    /** LC-11 (review 4): with a key, an old sequence is stale_seq and writes nothing. */
    @Test
    fun lc11WithAKeyAnOldSequenceIsStaleAndWritesNothing() {
        val files = NativeTestFiles()
        val k = keyOf(nativePhrase)
        assertEquals(NativeWalletVault.Import.OK, vault(files).importMnemonicKey(eoaOf(k), k, nativePhrase))
        assertTrue(MnemonicPreread.accept(9L))
        assertFalse(MnemonicPreread.accept(3L))
        assertEquals(nativePhrase, (vault(files).mnemonicOf() as NativeWalletVault.MnemonicRead.Stored).phrase)
    }

    @Test
    fun lc07TheMainPathWritesOnceAndTheReadBackEqualsThePwaBytes() {
        val k = keyOf(pwaPhrase)
        assertTrue(MnemonicPreread.accept(1L))
        val outcome = vault().syncPhrase(eoaOf(k), k, pwaPhrase)
        assertEquals("ok", NativeSyncAck.codeOf(outcome))
        MnemonicPreread.publishAfterSync(1L, MnemonicPreread.vaultAnswerOrUnknown(vault()))
        assertTrue(MnemonicPreread.answer() is MnemonicPreread.Answer.Valid)
        assertEquals(pwaPhrase, (vault().mnemonicOf() as NativeWalletVault.MnemonicRead.Stored).phrase)
    }

    @Test
    fun lc07nAFailedShellCheckLeavesTheNativeStoreUnchanged() {
        assertEquals("untrusted_source", NativeSyncAck.admit(body(pwaPhrase, trusted = false)))
        assertTrue(dir.listFiles()!!.isEmpty())
    }

    @Test
    fun lc08AnInjectedWriteFailureLeavesTheBytesAndAnswersWriteFailedWithAReason() {
        val files = FaultFiles(AndroidVaultFiles(dir)).apply { failWrite.add(NativeWalletVault.REC) }
        val k = keyOf(pwaPhrase)
        assertTrue(MnemonicPreread.accept(1L))
        val outcome = vault(files).syncPhrase(eoaOf(k), k, pwaPhrase)
        val answer = NativeSyncAck.answerOf(outcome)
        assertEquals("write_failed", answer.code)
        assertEquals("storage_write", answer.reason)
        assertNull("no record written", AndroidVaultFiles(dir).read(NativeWalletVault.REC))
    }

    @Test
    fun lc09AnAbsentPreReadAlsoMeansNoKeyAndTheSyncIsAccepted() {
        assertTrue(MnemonicPreread.vaultAnswerOrUnknown(vault()) is MnemonicPreread.Answer.Absent)
        assertEquals(NoKeyGate.Route.LIFECYCLE, NoKeyGate.route("pwaWalletSync"))
        assertNull(NativeSyncAck.admit(body(pwaPhrase)))
    }

    // AC-07 .. AC-10

    @Test
    fun ac07to09TheInternalStatesAreWriteFailedWithTheInternalStateReason() {
        for (o in listOf(NativeWalletVault.SyncOutcome.NOT_READY, NativeWalletVault.SyncOutcome.READBACK_FAILED)) {
            val a = NativeSyncAck.answerOf(o)
            assertEquals("$o", "write_failed", a.code)
            assertEquals("$o", "internal_state", a.reason)
        }
        // an unfinished rollback is rollback_pending (not internal_state).
        assertEquals("rollback_pending", NativeSyncAck.answerOf(NativeWalletVault.SyncOutcome.ROLLBACK_PENDING).reason)
    }

    /** AC-11..13 (r2.5.1 49(1)): a plain store failure is storage_write; every reason is one of the two fixed words and carries no sensitive form. */
    @Test
    fun ac11to13TheReasonsAreTheTwoFixedWordsAndOnlyAPlainStoreFailureIsStorageWrite() {
        // the vocabulary adds rollback_pending and old_copy_unverified.
        val vocab = setOf("internal_state", "storage_write", "rollback_pending", "old_copy_unverified")
        assertEquals("storage_write", NativeSyncAck.answerOf(NativeWalletVault.SyncOutcome.WRITE_FAILED).reason)
        for (o in NativeWalletVault.SyncOutcome.values()) {
            val a = NativeSyncAck.answerOf(o)
            if (a.code == NativeSyncAck.WRITE_FAILED) {
                assertTrue("$o reason ${a.reason}", a.reason in vocab)
                assertFalse("$o reason carries no key form", Regex("[0-9a-fA-F]{64}").containsMatchIn(a.reason!!))
            }
        }
    }

    @Test
    fun ac10ABadFormatIsBadRequest() {
        assertEquals("bad_request", NativeSyncAck.formatError(JSONObject().put("seq", "abc"), pwaPhrase))
        assertEquals("bad_request", NativeSyncAck.formatError(JSONObject().put("seq", "5"), pwaPhrase))
        assertEquals("bad_request", NativeSyncAck.formatError(JSONObject().put("phrase", pwaPhrase), pwaPhrase))
        assertEquals("bad_request", NativeSyncAck.formatError(body(pwaPhrase, seq = -1), pwaPhrase))
        assertEquals("bad_request", NativeSyncAck.formatError(body("not a phrase at all"), "not a phrase at all"))
        assertNull(NativeSyncAck.formatError(body(pwaPhrase, seq = 7), pwaPhrase))
    }

    // RP-01 .. RP-03

    @Test
    fun rp01AFailedWriteIsRereadAndPublishedUnderTheNewEpoch() {
        seed()
        assertTrue(MnemonicPreread.accept(1L))
        assertTrue(MnemonicPreread.accept(2L))
        val files = FaultFiles(AndroidVaultFiles(dir)).apply { failWrite.add(NativeWalletVault.REC) }
        val k = keyOf(pwaPhrase)
        assertEquals("write_failed", NativeSyncAck.codeOf(vault(files).syncPhrase(eoaOf(k), k, pwaPhrase)))
        MnemonicPreread.publishAfterSync(2L, MnemonicPreread.vaultAnswerOrUnknown(vault()))
        assertTrue("definitive, not unknown", MnemonicPreread.answer() is MnemonicPreread.Answer.Valid)
    }

    @Test
    fun rp02ALateUnknownFromAnOldEpochIsDroppedAndDoesNotOverwrite() {
        assertTrue(MnemonicPreread.accept(1L))
        assertTrue(MnemonicPreread.accept(2L))
        MnemonicPreread.publishAfterSync(2L, MnemonicPreread.Answer.Absent)
        MnemonicPreread.publishAfterSync(1L, MnemonicPreread.Answer.Unknown)
        assertTrue(MnemonicPreread.answer() is MnemonicPreread.Answer.Absent)
    }

    @Test
    fun rp03AFailedWriteWithAnEmptyNativeStoreRereadsAsAbsent() {
        assertTrue(MnemonicPreread.accept(1L))
        val files = FaultFiles(AndroidVaultFiles(dir)).apply { failWrite.add(NativeWalletVault.REC) }
        val k = keyOf(pwaPhrase)
        assertEquals("write_failed", NativeSyncAck.codeOf(vault(files).syncPhrase(eoaOf(k), k, pwaPhrase)))
        MnemonicPreread.publishAfterSync(1L, MnemonicPreread.vaultAnswerOrUnknown(vault()))
        assertTrue(MnemonicPreread.answer() is MnemonicPreread.Answer.Absent)
    }

    // NS-01 .. NS-04

    @Test
    fun nsTheNativeStateHasThreeNamedValuesAndAnyOtherIsUnknown() {
        assertEquals("valid", NativeWalletVault.nativeStateOf("valid"))
        assertEquals("explicit_empty", NativeWalletVault.nativeStateOf("explicit_empty"))
        assertEquals("unknown", NativeWalletVault.nativeStateOf("unknown"))
        assertEquals("unknown", NativeWalletVault.nativeStateOf("something_else"))
        assertEquals("unknown", NativeWalletVault.nativeStateOf(null))
    }

    // DR-01 .. DR-09, AU-01 .. AU-03: the narrow discard (r2.4.9 46(1)-(3), review: ordered intent, audit after the intent, no read side effect)

    private fun keyOnlyRecord(files: VaultFiles): VaultFiles {
        val k = keyOf(nativePhrase)
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importKey(eoaOf(k), k))
        return files
    }

    private fun intentOf(files: VaultFiles): String? = files.read(NativeWalletVault.DISCARD_INTENT)?.let { String(it, Charsets.UTF_8) }

    /** DR-10 (spec 46, r2.5.2): no failure drops both private records and keeps the mnemonic entry (see dr05 and dr01). */
    @Test
    fun dr01AKeyOnlyEntryIsKeptAndNothingIsAudited() {
        //  (no deletion on the explicit-empty path; 33(5) is not carried out): the key record stays, no audit line, no intent.
        val files = keyOnlyRecord(NativeTestFiles())
        val before = files.names().associateWith { files.read(it)!! }
        val outcome = vault(files).discardPrivateOnly(pwaExplicitEmpty = true, nativeState = "explicit_empty")
        assertEquals(NativeWalletVault.DiscardOutcome.NOT_DROPPED, outcome)
        before.forEach { (n, b) -> assertArrayEquals(n, b, files.read(n)) }
        assertEquals(before.keys, files.names().toSet())
        assertNull("no intent", intentOf(files))
        assertNull("no audit line", files.read(NativeWalletVault.DISCARD_AUDIT))
    }

    @Test
    fun dr02AnUnknownNativeStateDropsNothing() {
        val files = keyOnlyRecord(NativeTestFiles())
        assertEquals(NativeWalletVault.DiscardOutcome.NOT_DROPPED, vault(files).discardPrivateOnly(pwaExplicitEmpty = true, nativeState = "unknown"))
        assertNotNull(files.read(NativeWalletVault.REC))
    }

    @Test
    fun dr03APwaSideNotExplicitlyEmptyDropsNothing() {
        val files = keyOnlyRecord(NativeTestFiles())
        assertEquals(NativeWalletVault.DiscardOutcome.NOT_DROPPED, vault(files).discardPrivateOnly(pwaExplicitEmpty = false, nativeState = "explicit_empty"))
        assertNotNull(files.read(NativeWalletVault.REC))
    }

    /** An audit that cannot be written: nothing is dropped, and the intent is removed so no decision stays on disk. */
    @Test
    fun dr04AnAuditWriteFailureDropsNothingAndLeavesNoIntent() {
        val files = FaultFiles(keyOnlyRecord(NativeTestFiles())).apply { failWrite.add(NativeWalletVault.DISCARD_AUDIT) }
        assertEquals(NativeWalletVault.DiscardOutcome.NOT_DROPPED, vault(files).discardPrivateOnly(pwaExplicitEmpty = true, nativeState = "explicit_empty"))
        assertNotNull(files.read(NativeWalletVault.REC))
        assertNull(intentOf(files))
    }

    @Test
    fun dr05APhraseEntryIsNeverDropped() {
        val files = NativeTestFiles()
        val k = keyOf(nativePhrase)
        assertEquals(NativeWalletVault.Import.OK, vault(files).importMnemonicKey(eoaOf(k), k, nativePhrase))
        assertEquals(NativeWalletVault.DiscardOutcome.NOT_DROPPED, vault(files).discardPrivateOnly(pwaExplicitEmpty = true, nativeState = "explicit_empty"))
        assertNotNull(files.read(NativeWalletVault.REC))
    }

    /** The intent cannot be written: nothing is dropped and no intent is left. */
    @Test
    fun dr06AnIntentThatCannotBeWrittenDropsNothing() {
        val files = FaultFiles(keyOnlyRecord(NativeTestFiles())).apply { failWrite.add(NativeWalletVault.DISCARD_INTENT) }
        assertEquals(NativeWalletVault.DiscardOutcome.NOT_DROPPED, vault(files).discardPrivateOnly(pwaExplicitEmpty = true, nativeState = "explicit_empty"))
        assertNotNull(files.read(NativeWalletVault.REC))
        assertNull(intentOf(files))
    }

    /** Own numbering (not a spec vector): review 1, the intent is written, but its read-back fails. The decision is aborted at once: nothing dropped, no pending intent left. */
    @Test
    fun dr10AnIntentWhoseReadBackFailsIsAbortedAtOnceAndDropsNothing() {
        val files = FaultFiles(keyOnlyRecord(NativeTestFiles())).apply { corruptReadAfterWrite.add(NativeWalletVault.DISCARD_INTENT) }
        assertEquals(NativeWalletVault.DiscardOutcome.NOT_DROPPED, vault(files).discardPrivateOnly(pwaExplicitEmpty = true, nativeState = "explicit_empty"))
        assertNotNull("the record is kept", files.read(NativeWalletVault.REC))
        assertFalse("no pending intent left", intentOf(files) == NativeWalletVault.INTENT_PENDING)
        // A later start does not finish a decision that was reported as not dropped.
        vault(files).completeDiscardAtStartup()
        assertNotNull(files.read(NativeWalletVault.REC))
    }

    /**
     * DR-09 (spec 46, r2.5.2): a removal that fails before the second record is deleted is rolled back. The key record that was removed is
     * written back byte for byte, the audit returns to its prior bytes, the intent is removed, and the store is unchanged.
     */
    @Test
    fun dr09AMidRemovalFailureRollsBackAndTheStoreIsUnchanged() {
        val inner = keyOnlyRecord(NativeTestFiles()) as NativeTestFiles
        val before = inner.map.mapValues { it.value.copyOf() }
        val files = FaultFiles(inner).apply { failDelete.add(NativeWalletVault.COMMIT) }
        assertEquals(NativeWalletVault.DiscardOutcome.NOT_DROPPED, vault(files).discardPrivateOnly(pwaExplicitEmpty = true, nativeState = "explicit_empty"))
        files.failDelete.clear()
        assertEquals("the store is unchanged", before.keys, inner.map.keys)
        before.forEach { (n, b) -> assertArrayEquals("$n unchanged", b, inner.map[n]) }
        assertNull("no intent left", intentOf(inner))
    }

    /**
     * DR-09 (pending branch): the rollback itself cannot write the record back. The answer is PENDING, the intent stays, and the next startup
     * finishes the decision. A read has no side effect in between (the state is unknown and the intent is still there).
     */
    @Test
    fun dr11AStartupCannotClearALeftoverIntentThenRetriesAndKeepsTheRecord() {
        // The fault is on a path that still exists: the startup completion of a leftover pending intent cannot delete its intent.
        // The record stays, the intent stays, and the next startup (fault cleared) clears the intent only.
        val inner = keyOnlyRecord(NativeTestFiles())
        inner.write(NativeWalletVault.DISCARD_INTENT, NativeWalletVault.INTENT_PENDING.toByteArray(Charsets.UTF_8))
        val files = FaultFiles(inner).apply { failDelete.add(NativeWalletVault.DISCARD_INTENT) }
        vault(files).completeDiscardAtStartup()
        assertEquals(NativeWalletVault.INTENT_PENDING, intentOf(inner))
        assertNotNull(inner.read(NativeWalletVault.REC))
        assertNotNull(inner.read(NativeWalletVault.COMMIT))
        files.failDelete.clear()
        vault(files).completeDiscardAtStartup()
        assertNull(intentOf(inner))
        assertNotNull(inner.read(NativeWalletVault.REC))
        assertNotNull(inner.read(NativeWalletVault.COMMIT))
        assertNull(inner.read(NativeWalletVault.DISCARD_AUDIT))
    }

    /** dr08B: a leftover pending intent with only a key record: the startup clears the intent, removes no record, writes no audit line. */
    @Test
    fun dr08BLeftoverPendingIntentWithOnlyAKeyKeepsTheRecord() {
        val files = keyOnlyRecord(NativeTestFiles())
        files.write(NativeWalletVault.DISCARD_INTENT, NativeWalletVault.INTENT_PENDING.toByteArray(Charsets.UTF_8))
        val before = files.names().associateWith { files.read(it)!! }
        vault(files).completeDiscardAtStartup()
        assertNull(intentOf(files))
        before.filterKeys { it != NativeWalletVault.DISCARD_INTENT }.forEach { (n, b) -> assertArrayEquals(n, b, files.read(n)) }
        assertNull(files.read(NativeWalletVault.DISCARD_AUDIT))
    }

    @Test
    fun dr08APreparedLeftoverIsRemovedAtStartupWithoutDropping() {
        val files = keyOnlyRecord(NativeTestFiles())
        files.write(NativeWalletVault.DISCARD_INTENT, NativeWalletVault.INTENT_PREPARED.toByteArray(Charsets.UTF_8))
        vault(files).completeDiscardAtStartup()
        assertNull(intentOf(files))
        assertNotNull("nothing dropped", files.read(NativeWalletVault.REC))
    }

    /** Own numbering (not a spec vector): the audit is written only after the intent is confirmed; a failed intent leaves no audit line. */
    @Test
    fun dr09TheAuditIsWrittenOnlyAfterTheIntentIsConfirmed() {
        val files = FaultFiles(keyOnlyRecord(NativeTestFiles())).apply { failWrite.add(NativeWalletVault.DISCARD_INTENT) }
        vault(files).discardPrivateOnly(pwaExplicitEmpty = true, nativeState = "explicit_empty")
        assertNull("no audit line without a confirmed intent", files.read(NativeWalletVault.DISCARD_AUDIT))
    }

    private fun seed() {
        val k = keyOf(nativePhrase)
        assertEquals(NativeWalletVault.Import.OK, vault().importMnemonicKey(eoaOf(k), k, nativePhrase))
    }

    // PE-01 .. PE-07: pwaEmptySignal (r2.5.2 53): the signal ledger and the native read that goes with it

    @Test
    fun pe01OnlyExplicitEmptyIsAnEmptyPwaSide() {
        assertEquals("explicit_empty", PwaEmptySignal.stateOf("explicit_empty"))
        assertEquals("valid", PwaEmptySignal.stateOf("valid"))
        assertEquals("unknown", PwaEmptySignal.stateOf("unknown"))
        assertEquals("unknown", PwaEmptySignal.stateOf("nonsense"))
        assertEquals("unknown", PwaEmptySignal.stateOf(null))
    }

    @Test
    fun pe02AnOlderSignalOrSyncSequenceIsStale() {
        assertTrue(PwaEmptySignal.accept(5L, "explicit_empty"))
        assertFalse("an older signal is stale", PwaEmptySignal.accept(4L, "explicit_empty"))
        assertTrue(MnemonicPreread.accept(8L))
        assertFalse("a signal older than the newest sync is stale", PwaEmptySignal.accept(7L, "explicit_empty"))
        assertTrue(PwaEmptySignal.accept(9L, "unknown"))
        assertEquals("unknown", PwaEmptySignal.latestState())
    }

    @Test
    fun pe03TheNativeReadIsExplicitEmptyForAKeyOnlyRecordAndValidForAPhrase() {
        val keyOnly = keyOnlyRecord(NativeTestFiles())
        assertEquals("explicit_empty", vault(keyOnly).nativeStateLabel())
        val phrase = NativeTestFiles()
        val k = keyOf(nativePhrase)
        assertEquals(NativeWalletVault.Import.OK, vault(phrase).importMnemonicKey(eoaOf(k), k, nativePhrase))
        assertEquals("valid", vault(phrase).nativeStateLabel())
    }

    /** PE-04: the discard happens only with both sides explicit: the PWA side is explicit_empty and the native read is explicit_empty. */
    @Test
    fun pe04TheDiscardNeedsBothSidesExplicitlyEmpty() {
        val files = keyOnlyRecord(NativeTestFiles())
        assertEquals(NativeWalletVault.DiscardOutcome.NOT_DROPPED, vault(files).discardPrivateOnly(pwaExplicitEmpty = false, nativeState = vault(files).nativeStateLabel()))
        assertNotNull(files.read(NativeWalletVault.REC))
    }

    /** PE-05: both sides explicit: the key-only entry is dropped with its audit line. */
    @Test
    fun pe05BothSidesExplicitKeepTheKeyOnlyEntry() {
        // the private-only record is kept even when both sides say explicit empty.
        val files = keyOnlyRecord(NativeTestFiles())
        val outcome = vault(files).discardPrivateOnly(pwaExplicitEmpty = PwaEmptySignal.stateOf("explicit_empty") == "explicit_empty", nativeState = vault(files).nativeStateLabel())
        assertEquals(NativeWalletVault.DiscardOutcome.NOT_DROPPED, outcome)
        assertNotNull(files.read(NativeWalletVault.REC))
    }

    /** PE-06: a phrase entry is never dropped, whatever the signal says. */
    @Test
    fun pe06APhraseEntryIsNotDroppedBySignal() {
        val files = NativeTestFiles()
        val k = keyOf(nativePhrase)
        assertEquals(NativeWalletVault.Import.OK, vault(files).importMnemonicKey(eoaOf(k), k, nativePhrase))
        assertEquals(NativeWalletVault.DiscardOutcome.NOT_DROPPED, vault(files).discardPrivateOnly(pwaExplicitEmpty = true, nativeState = vault(files).nativeStateLabel()))
        assertNotNull(files.read(NativeWalletVault.REC))
    }

    /** PE-07: an unknown PWA side never drops (53(3), 53(7)). */
    @Test
    fun pe07AnUnknownPwaSideDropsNothing() {
        val files = keyOnlyRecord(NativeTestFiles())
        val pwa = PwaEmptySignal.stateOf("unknown")
        assertEquals(NativeWalletVault.DiscardOutcome.NOT_DROPPED, vault(files).discardPrivateOnly(pwaExplicitEmpty = pwa == "explicit_empty", nativeState = vault(files).nativeStateLabel()))
        assertNotNull(files.read(NativeWalletVault.REC))
    }

    // Review (a) and (b) of's follow-up: aborted marks do not lock; the startup hook re-checks the record before any removal.

    /** An aborted mark left by a failed abort is not a decision: the state is not locked by it, and a new discard is not held back. */
    @Test
    fun aa01AnAbortedMarkDoesNotLockTheStateOrHoldBackADiscard() {
        val files = keyOnlyRecord(NativeTestFiles())
        files.write(NativeWalletVault.DISCARD_INTENT, NativeWalletVault.INTENT_ABORTED.toByteArray(Charsets.UTF_8))
        val state = vault(files).state()
        assertFalse("not locked by an aborted mark", state is NativeWalletVault.State.Locked && state.reason == NativeWalletVault.DISCARD_PENDING)
        assertEquals(NativeWalletVault.DiscardOutcome.NOT_DROPPED, vault(files).discardPrivateOnly(pwaExplicitEmpty = true, nativeState = "explicit_empty"))
        assertNotNull(files.read(NativeWalletVault.REC))
    }

    /** A live decision (prepared) does lock the state until the startup hook decides it. */
    @Test
    fun aa02APreparedIntentLocksTheState() {
        val files = keyOnlyRecord(NativeTestFiles())
        files.write(NativeWalletVault.DISCARD_INTENT, NativeWalletVault.INTENT_PREPARED.toByteArray(Charsets.UTF_8))
        val state = vault(files).state()
        assertTrue("locked: $state", state is NativeWalletVault.State.Locked && state.reason == NativeWalletVault.DISCARD_PENDING)
    }

    /**
     * A pending decision whose record now holds a phrase (review b): nothing is removed, the intent goes, and an aborted audit line (count 0)
     * is written after the earlier count-1 line.
     */
    @Test
    fun aa03AStartupRecheckFindingAPhraseAbandonsTheDecisionWithAnAbortedAuditLine() {
        val files = NativeTestFiles()
        val k = keyOf(nativePhrase)
        assertEquals(NativeWalletVault.Import.OK, vault(files).importMnemonicKey(eoaOf(k), k, nativePhrase))
        val recBefore = files.read(NativeWalletVault.REC)!!.copyOf()
        files.write(NativeWalletVault.DISCARD_INTENT, NativeWalletVault.INTENT_PENDING.toByteArray(Charsets.UTF_8))
        vault(files).completeDiscardAtStartup()
        assertNull("the intent is cleared", files.read(NativeWalletVault.DISCARD_INTENT))
        assertArrayEquals("the record is kept", recBefore, files.read(NativeWalletVault.REC))
        val last = String(files.read(NativeWalletVault.DISCARD_AUDIT)!!, Charsets.UTF_8).trim().lines().last()
        val audit = JSONObject(last)
        assertEquals(0, audit.getInt("count"))
        assertEquals("privatekey", audit.getString("entryType"))
        assertEquals(nativePhrase, (vault(files).mnemonicOf() as NativeWalletVault.MnemonicRead.Stored).phrase)
    }

    /** Review 1 (9f0a100): the signal and the sync share one sequence. A sync older than the newest signal is stale. */
    @Test
    fun sq01ASyncOlderThanASignalIsStaleAndTheOtherWayRound() {
        assertTrue(PwaEmptySignal.accept(10L, "explicit_empty"))
        assertFalse("a sync older than the newest signal is stale", MnemonicPreread.accept(5L))
        assertTrue("an equal sync is current (SQ-07)", MnemonicPreread.accept(10L))
        assertTrue(MnemonicPreread.accept(11L))
        assertFalse("a signal older than the newest sync is stale", PwaEmptySignal.accept(10L, "unknown"))
        assertTrue("an equal signal is current (SQ-07)", PwaEmptySignal.accept(11L, "unknown"))
        assertTrue(PwaEmptySignal.accept(12L, "unknown"))
    }

    /** Review 1: a signal does not move the pre-read epoch; the cached pre-read survives it (only a sync voids it). */
    @Test
    fun sq02ASignalDoesNotVoidThePreRead() {
        assertTrue(MnemonicPreread.accept(3L))
        MnemonicPreread.publishAfterSync(3L, MnemonicPreread.Answer.Absent)
        assertTrue(PwaEmptySignal.accept(4L, "explicit_empty"))
        assertTrue("the pre-read is still served", MnemonicPreread.answer() is MnemonicPreread.Answer.Absent)
    }

    /** Review 2 (owner): PHRASE_ONLY is valid for the native label and for the pre-read, when the phrase reads and derives. */
    @Test
    fun po01APhraseOnlyRecordIsValidForTheLabelAndThePreRead() {
        val files = NativeTestFiles()
        val k = keyOf(nativePhrase)
        assertEquals(NativeWalletVault.Import.OK, vault(files).importMnemonicKey(eoaOf(k), k, nativePhrase))
        files.delete(NativeWalletVault.REC) // the key record is gone; the readable phrase remains
        val v = vault(files)
        val st = v.state()
        assertTrue("phrase-only: $st", st is NativeWalletVault.State.Locked && st.reason == NativeWalletVault.PHRASE_ONLY)
        assertEquals("valid", v.nativeStateLabel())
        val answer = MnemonicPreread.vaultAnswerOrUnknown(v)
        assertEquals(nativePhrase, (answer as MnemonicPreread.Answer.Valid).phrase)
    }

    /**
     * Review: REC missing but MNEM present. The startup recheck sees a phrase record, abandons the decision (aborted audit, count 0,
     * intent removed) and does not stay locked. Probe: the phrase stays readable and the state is not discard_pending on the next start.
     */
    @Test
    fun aa04APhraseRecordWithoutKeyRecordAbandonsThePendingDecisionAtStartup() {
        val files = NativeTestFiles()
        val k = keyOf(nativePhrase)
        assertEquals(NativeWalletVault.Import.OK, vault(files).importMnemonicKey(eoaOf(k), k, nativePhrase))
        files.delete(NativeWalletVault.REC)
        files.write(NativeWalletVault.DISCARD_INTENT, NativeWalletVault.INTENT_PENDING.toByteArray(Charsets.UTF_8))
        vault(files).completeDiscardAtStartup()
        assertNull("the intent is cleared, not kept", files.read(NativeWalletVault.DISCARD_INTENT))
        assertNotNull("the phrase record stays", files.read(NativeWalletVault.MNEM))
        val last = String(files.read(NativeWalletVault.DISCARD_AUDIT)!!, Charsets.UTF_8).trim().lines().last()
        assertEquals(0, JSONObject(last).getInt("count"))
        val next = vault(files)
        val state = next.state()
        assertFalse("not locked by a discard after the start", state is NativeWalletVault.State.Locked && state.reason == NativeWalletVault.DISCARD_PENDING)
        assertEquals("valid", next.nativeStateLabel())
    }

    /**
     * PV-05 (r2.5.7 46(7)): nativeMnemonicPreread without a true trustedOrigin is ok:false with untrusted_source. The answer is not read, and no
     * phrase is returned. With the marker, the answer is the pre-read (valid carries the phrase, as before).
     */
    @Test
    fun pv05AnUntrustedPreReadRequestIsRefusedBeforeAnyReadAndCarriesNoPhrase() {
        var reads = 0
        val answer = { reads++; MnemonicPreread.Answer.Valid("0x" + "1".repeat(40), nativePhrase) }
        for (body in listOf(JSONObject(), JSONObject().put("trustedOrigin", false), JSONObject().put("trustedOrigin", "true"))) {
            val p = NativeSyncAck.prereadPayload(7, body, answer)
            assertFalse(p.getBoolean("ok"))
            assertEquals("untrusted_source", p.getString("error"))
            assertFalse("no result carries a phrase", p.has("result"))
            assertFalse("no phrase anywhere in the reply", p.toString().contains(nativePhrase))
        }
        assertEquals("the pre-read is not read for an untrusted request", 0, reads)
        // r2.5.19 60(3): a trusted request also carries seq (the current one), or it is bad_request before the state.
        val trusted = NativeSyncAck.prereadPayload(7, JSONObject().put("trustedOrigin", true).put("seq", 6), answer)
        assertTrue(trusted.getBoolean("ok"))
        assertEquals("ok", trusted.getJSONObject("result").getString("code"))
        assertEquals(nativePhrase, trusted.getJSONObject("result").getString("mnemonic"))
        assertEquals(1, reads)
    }

    /**
     * AU-05 (r2.5.7 46(5), 46(8)): an aborted audit line (count 0) deletes nothing. The store bytes are unchanged, except the audit file that
     * gains exactly one count-0 line, and the intent is removed. Covers the startup re-check that finds a phrase (review b).
     */
    @Test
    fun au05AnAbortedAuditLineDeletesNothingAndTheStoreBytesAreUnchanged() {
        val files = NativeTestFiles()
        val k = keyOf(nativePhrase)
        assertEquals(NativeWalletVault.Import.OK, vault(files).importMnemonicKey(eoaOf(k), k, nativePhrase))
        files.write(NativeWalletVault.DISCARD_INTENT, NativeWalletVault.INTENT_PENDING.toByteArray(Charsets.UTF_8))
        val before = files.map.filterKeys { it != NativeWalletVault.DISCARD_INTENT && it != NativeWalletVault.DISCARD_AUDIT }.mapValues { it.value.copyOf() }
        vault(files).completeDiscardAtStartup()
        val after = files.map.filterKeys { it != NativeWalletVault.DISCARD_INTENT && it != NativeWalletVault.DISCARD_AUDIT }
        assertEquals("the same names", before.keys, after.keys)
        before.forEach { (n, b) -> assertArrayEquals("$n unchanged", b, after[n]) }
        assertNull("the intent is removed", files.read(NativeWalletVault.DISCARD_INTENT))
        val lines = String(files.read(NativeWalletVault.DISCARD_AUDIT)!!, Charsets.UTF_8).trim().lines()
        assertEquals("exactly one aborted line", 1, lines.size)
        assertEquals(0, JSONObject(lines.single()).getInt("count"))
    }

    /**
     * Review (adopted): the aborted audit line cannot be written at startup. The intent stays, nothing is removed, and the state is
     * unknown (discard_pending): not a usable account, not an empty store. The next start, with the store writable, decides it.
     */
    @Test
    fun aa06AnAbortedAuditThatCannotBeWrittenKeepsTheIntentAndTheStateUnknown() {
        val inner = NativeTestFiles()
        val k = keyOf(nativePhrase)
        assertEquals(NativeWalletVault.Import.OK, vault(inner).importMnemonicKey(eoaOf(k), k, nativePhrase))
        inner.write(NativeWalletVault.DISCARD_INTENT, NativeWalletVault.INTENT_PENDING.toByteArray(Charsets.UTF_8))
        val recBefore = inner.read(NativeWalletVault.REC)!!.copyOf()
        val mnemBefore = inner.read(NativeWalletVault.MNEM)!!.copyOf()
        val files = FaultFiles(inner).apply { failWrite.add(NativeWalletVault.DISCARD_AUDIT) }

        vault(files).completeDiscardAtStartup()

        assertEquals("pending", String(inner.read(NativeWalletVault.DISCARD_INTENT)!!, Charsets.UTF_8))
        assertArrayEquals(recBefore, inner.read(NativeWalletVault.REC))
        assertArrayEquals(mnemBefore, inner.read(NativeWalletVault.MNEM))
        val state = vault(files).state()
        assertTrue("unknown, not a usable account nor an empty store: $state",
            state is NativeWalletVault.State.Locked && state.reason == NativeWalletVault.DISCARD_PENDING)

        // The next start, with the audit writable, decides the intent and the state is no longer unknown.
        files.failWrite.clear()
        vault(files).completeDiscardAtStartup()
        assertNull(inner.read(NativeWalletVault.DISCARD_INTENT))
        assertArrayEquals(mnemBefore, inner.read(NativeWalletVault.MNEM))
        assertEquals(nativePhrase, (vault(files).mnemonicOf() as NativeWalletVault.MnemonicRead.Stored).phrase)
    }

    /**
     * r2.5.17 58(1)(e)-(g): one drop per start cycle. A repeated signal (the same sequence, equal and so current) finds no record left and drops
     * nothing more; without a signal (the PWA gave up or did not send) the native side never drops.
     */
    @Test
    fun pe08ARepeatedSignalDropsNothingMoreAndNoSignalDropsNothing() {
        val files = NativeTestFiles()
        val k = keyOf(nativePhrase)
        assertEquals(NativeWalletVault.Import.OK, vault(files).importKey(eoaOf(k), k))
        // no repeated signal and no first signal removes the private-only record; no audit line is written.
        assertEquals(NativeWalletVault.DiscardOutcome.NOT_DROPPED, vault(files).discardPrivateOnly(pwaExplicitEmpty = true, nativeState = "explicit_empty"))
        assertNotNull(files.read(NativeWalletVault.REC))
        assertNull(files.read(NativeWalletVault.DISCARD_AUDIT))
    }
}
