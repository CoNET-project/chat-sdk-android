package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.json.JSONObject

/**
 * E9 补正 1: a record move on a rollback or failure path writes its pending marker entry first, then moves, then audits; the marker goes only after the
 * audit row. A failed audit row leaves the moved bytes isolated and the marker in place; the next settle backfills the row.
 */
class AuditBackfillTest {
    private val phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    private val wrap = NativeTestWrap()
    private fun key() = checkNotNull(MnemonicDerivation.deriveKey(phrase))
    private fun eoa() = checkNotNull(WalletAddress.fromPrivateKey(key()))
    private fun digest(b: ByteArray) = java.security.MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }
    private fun isolatedCopies(files: NativeTestFiles, name: String) = files.map.filterKeys { it.startsWith("$name.isolated.") }
    private fun auditRowsFor(files: NativeTestFiles, iso: String) =
        files.map[NativeWalletVault.AUDIT]?.let { String(it, Charsets.UTF_8).lines().count { l -> l.contains("\"isolated\":\"$iso\"") } } ?: 0

    @Test fun auditFailureKeepsTheMovedBytesAndTheMarkerThenTheNextSettleBackfills() {
        val files = NativeTestFiles()
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importKey(eoa(), key()))
        val commit = files.map[NativeWalletVault.COMMIT]!!.copyOf()
        // The write's rollback moves the first record it finds (COMMIT here); the audit row write fails.
        files.failWrite = NativeWalletVault.AUDIT
        assertFalse("the audit failed", NativeWalletVault(wrap, files).isolateWrittenRecords(mnemonicPlanned = false))
        // The bytes are still held under an isolated name, and the marker still lists the move.
        val iso = isolatedCopies(files, NativeWalletVault.COMMIT).keys.single()
        assertTrue("the moved bytes are kept", files.map[iso]!!.contentEquals(commit))
        assertTrue("the marker still lists the move", files.map.containsKey(NativeWalletVault.PENDING))
        assertEquals(0, auditRowsFor(files, iso))
        // The fault clears: the next settle backfills the row and clears the marker.
        files.failWrite = null
        NativeWalletVault.resetLaunchForTests()
        NativeWalletVault(wrap, files).settleForWrite()
        assertEquals("exactly one audit row for the move", 1, auditRowsFor(files, iso))
        assertFalse("the marker is cleared after the row", files.map.containsKey(NativeWalletVault.PENDING))
        assertTrue("the moved bytes are still kept", files.map[iso]!!.contentEquals(commit))
    }

    /**
     * E9 启动钩子: a startup whose audit backfill fails keeps the marker and every byte, and the startup classification does not change (the pre-read
     * answer, the state is not a lock of this marker). The next start backfills the row and clears the marker.
     */
    @Test fun aStartupWhoseBackfillFailsKeepsTheClassificationAndTheNextStartBackfills() {
        val files = NativeTestFiles()
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importKey(eoa(), key()))
        val answerBefore = MnemonicPreread.vaultAnswerOrUnknown(NativeWalletVault(wrap, files))
        files.failWrite = NativeWalletVault.AUDIT
        assertFalse(NativeWalletVault(wrap, files).isolateWrittenRecords(mnemonicPlanned = false))
        val iso = isolatedCopies(files, NativeWalletVault.COMMIT).keys.single()
        // Startup with the audit still failing: the marker and the bytes stay; the classification is the same as before the move.
        NativeWalletVault.resetLaunchForTests()
        NativeWalletVault(wrap, files).completeDiscardAtStartup()
        assertTrue("marker kept", files.map.containsKey(NativeWalletVault.PENDING))
        assertTrue("bytes kept", files.map.containsKey(iso))
        assertEquals("the pre-read answer is unchanged", answerBefore, MnemonicPreread.vaultAnswerOrUnknown(NativeWalletVault(wrap, files)))
        // E9.1-4 consistency: the walletStatus state, the phrase verdict and the pre-read agree on the current phrase position (none here).
        assertEquals("the phrase verdict is missing, not unknown", NativeWalletVault.PhraseVerdict.MISSING, NativeWalletVault(wrap, files).phraseVerdict())
        assertEquals("walletStatus answers no_key", "no_key", NoKeyGate.walletStatusFor(NoKeyGate.Gate.G0, NativeWalletVault(wrap, files).state()).getString("status"))
        assertFalse("the state is not a lock of this marker", NativeWalletVault(wrap, files).state() is NativeWalletVault.State.Locked &&
            (NativeWalletVault(wrap, files).state() as NativeWalletVault.State.Locked).reason == "rollback_pending")
        // The next start (the fault cleared) backfills the row and clears the marker.
        files.failWrite = null
        NativeWalletVault.resetLaunchForTests()
        NativeWalletVault(wrap, files).completeDiscardAtStartup()
        assertEquals("exactly one audit row", 1, auditRowsFor(files, iso))
        assertFalse("marker cleared", files.map.containsKey(NativeWalletVault.PENDING))
    }

    /**
     * Leaves a keep-only residue: a stale copy of the record under an isolated name, listed by the marker as a "keep" entry whose audit row is still owed.
     * The fixed records stay in place, so the account itself is unchanged. [newRecordSha] (null for a settled move) is written to the marker top level.
     */
    private fun keepResidue(files: NativeTestFiles, newRecordSha: String?) {
        val rec = files.map.getValue(NativeWalletVault.REC)
        val iso = "${NativeWalletVault.REC}.isolated.20261117T000000Z.eeeeeeee"
        files.map[iso] = rec.copyOf()
        files.map[NativeWalletVault.PENDING] = JSONObject().put("v", 1).put("utc", "2026-11-17T00:00:00Z").put("eoa", eoa())
            .put("preWriteAliasAbsent", false).put("newRecordSha", newRecordSha ?: JSONObject.NULL)
            .put("items", org.json.JSONArray().put(JSONObject().put("name", NativeWalletVault.REC).put("isolated", iso)
                .put("oldSha", digest(rec)).put("kind", "keep")))
            .toString().toByteArray(Charsets.UTF_8)
    }

    /**
     * Keep-residue rule (a keep-only marker must not change the answer for a valid account). Erratum number: 编号待定（来源未找到）. E9.1-4 is
     * "walletStatus 不作启动门槛" (spec-59e-errata-v3.3.1-E9.1.md), not this rule; E9.11.22 and E9.11.24 were checked and do not state it.
     * The phrase verdict is VALID, the state is a ready account, the walletStatus is the same as for the same account with no residue,
     * and the pre-read answers the same valid phrase.
     */
    @Test fun aValidPhraseWithAKeepResidueAgreesAcrossVerdictStatusAndPreread() {
        val files = NativeTestFiles()
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importMnemonicKey(eoa(), key(), phrase))
        val control = NativeTestFiles()
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, control).importMnemonicKey(eoa(), key(), phrase))
        val controlStatus = statusOf(control)
        keepResidue(files, newRecordSha = null)
        NativeWalletVault.resetLaunchForTests()
        val v = NativeWalletVault(wrap, files)
        assertEquals("phrase verdict is valid", NativeWalletVault.PhraseVerdict.VALID, v.phraseVerdict())
        val st = v.state()
        assertTrue("the state is a ready account, not a lock: $st", st is NativeWalletVault.State.Ready)
        assertEquals("walletStatus equals the no-residue account", controlStatus, statusOf(files))
        val answer = MnemonicPreread.vaultAnswerOrUnknown(NativeWalletVault(wrap, files))
        assertTrue("pre-read answers valid: $answer", answer is MnemonicPreread.Answer.Valid)
        assertEquals("the valid answer is this account", eoa(), (answer as MnemonicPreread.Answer.Valid).eoa)
        assertEquals("the valid answer carries the phrase", phrase, answer.phrase)
    }

    /** The walletStatus of the vault in [f] (no session, so the gate is G1 for a ready account), as text. */
    private fun statusOf(f: NativeTestFiles): String {
        val v = NativeWalletVault(wrap, f)
        return NoKeyGate.walletStatusFor(NoKeyGate.gateOf(v.state(), sessionReady = false), v.state()).toString()
    }

    /**
     * Fresh-account write failure (erratum number: 编号待定（来源未找到）; not E9.1-4):
     * a marker that holds only keep entries but also a confirmed new-record digest is a write in progress.
     * It must keep blocking: the state is not Ready. The same residue with no digest does not block.
     */
    @Test fun aKeepOnlyMarkerWithANewRecordDigestDoesNotBecomeReady() {
        val files = NativeTestFiles()
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importKey(eoa(), key()))
        keepResidue(files, newRecordSha = null)
        NativeWalletVault.resetLaunchForTests()
        val settled = NativeWalletVault(wrap, files).state()
        assertTrue("keep-only marker does not block: $settled", settled is NativeWalletVault.State.Ready)
        keepResidue(files, newRecordSha = digest(ByteArray(32) { 1 }))
        NativeWalletVault.resetLaunchForTests()
        val pending = NativeWalletVault(wrap, files).state()
        assertFalse("a write in progress blocks: $pending", pending is NativeWalletVault.State.Ready)
    }

    /**
     *  (state, walletStatus and pre-read decide from one source order): a COMMIT moved by a rollback whose audit row failed,
     * with the phrase at the fixed position valid and no intent pending, is a ready account. The three answers agree and equal the no-residue account.
     */
    @Test fun aMovedCommitWithAValidPhraseIsAReadyAccountAcrossStateStatusAndPreread() {
        val files = NativeTestFiles()
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importMnemonicKey(eoa(), key(), phrase))
        val control = NativeTestFiles()
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, control).importMnemonicKey(eoa(), key(), phrase))
        val controlStatus = statusOf(control)
        files.failWrite = NativeWalletVault.AUDIT
        assertFalse(NativeWalletVault(wrap, files).isolateWrittenRecords(mnemonicPlanned = false))
        assertFalse("COMMIT is moved away", files.map.containsKey(NativeWalletVault.COMMIT))
        NativeWalletVault.resetLaunchForTests()
        val v = NativeWalletVault(wrap, files)
        val st = v.state()
        assertTrue("the state is a ready account: $st", st is NativeWalletVault.State.Ready)
        assertEquals("phrase verdict is valid", NativeWalletVault.PhraseVerdict.VALID, v.phraseVerdict())
        assertEquals("walletStatus equals the no-residue account", controlStatus, statusOf(files))
        val answer = MnemonicPreread.vaultAnswerOrUnknown(NativeWalletVault(wrap, files))
        assertTrue("pre-read answers valid: $answer", answer is MnemonicPreread.Answer.Valid)
        assertEquals("the valid answer carries the phrase", phrase, (answer as MnemonicPreread.Answer.Valid).phrase)
    }

    /** r2.5 audit order: a pending row is an intent only. A copy that has nothing but a pending row gets its own row on the next reconcile. */
    @Test fun aPendingRowAloneIsNotAuditEvidenceAndTheNextReconcileBackfillsIt() {
        val files = NativeTestFiles()
        val v = NativeWalletVault(NativeTestWrap(), files)
        assertEquals(NativeWalletVault.Import.OK, v.importKey(eoa(), key()))
        val rec = files.map[NativeWalletVault.REC]!!.copyOf()
        val iso = NativeWalletVault.REC + ".isolated.2026-11-18T00:00:00Z.abcd1234"
        files.map[iso] = rec.copyOf()
        val pending = JSONObject()
            .put("v", 1).put("name", NativeWalletVault.REC).put("isolating", iso)
            .put("reason", "isolated_for_new_slot").put("state", "pending").put("sha256", digest(rec)).put("id", "p1")
        files.map[NativeWalletVault.AUDIT] = (String(files.map[NativeWalletVault.AUDIT] ?: ByteArray(0), Charsets.UTF_8) + pending.toString() + "\n").toByteArray(Charsets.UTF_8)
        assertTrue(NativeWalletVault(NativeTestWrap(), files).reconcileOrphanAudits())
        val rows = String(files.map[NativeWalletVault.AUDIT]!!, Charsets.UTF_8).lines().filter { it.isNotBlank() }.map { JSONObject(it) }
            .filter { it.optString("isolated") == iso || it.optString("isolating") == iso }
        assertEquals("the pending row plus one backfilled row", 2, rows.size)
        assertEquals("audit_backfilled", rows.last().getString("reason"))
        assertEquals("a backfilled row is a done row", "done", rows.last().optString("state", "done"))
    }

    /** A row written before the state field existed counts as done: reconcile adds nothing for that copy. */
    @Test fun aStatelessRowIsADoneRowAndReconcileAddsNothingForIt() {
        val files = NativeTestFiles()
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(NativeTestWrap(), files).importKey(eoa(), key()))
        val rec = files.map[NativeWalletVault.REC]!!.copyOf()
        val iso = NativeWalletVault.REC + ".isolated.2026-11-18T00:00:00Z.beef0001"
        files.map[iso] = rec.copyOf()
        val legacy = JSONObject().put("v", 1).put("name", NativeWalletVault.REC).put("isolated", iso)
            .put("reason", "isolated_for_new_slot").put("sha256", digest(rec)).put("id", "l1")
        files.map[NativeWalletVault.AUDIT] = (String(files.map[NativeWalletVault.AUDIT] ?: ByteArray(0), Charsets.UTF_8) + legacy.toString() + "\n").toByteArray(Charsets.UTF_8)
        assertTrue(NativeWalletVault(NativeTestWrap(), files).reconcileOrphanAudits())
        assertEquals("only the legacy row", 1, auditRowsFor(files, iso))
    }

    /** a backfill never writes a done row from bytes that changed after the pending row recorded their digest. */
    @Test fun aBackfillAfterATamperedCopyWritesNoDoneRow() {
        val files = NativeTestFiles()
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(NativeTestWrap(), files).importKey(eoa(), key()))
        val rec = files.map[NativeWalletVault.REC]!!.copyOf()
        val iso = NativeWalletVault.REC + ".isolated.2026-11-18T00:00:00Z.cafe0001"
        // The pending row recorded the digest of the original bytes; the copy under the isolated name was changed afterwards.
        files.map[iso] = rec.copyOf().also { it[0] = (it[0].toInt() xor 0x01).toByte() }
        val pending = JSONObject().put("v", 1).put("name", NativeWalletVault.REC).put("isolating", iso)
            .put("reason", "isolated_for_new_slot").put("state", "pending").put("sha256", digest(rec)).put("id", "p2")
        files.map[NativeWalletVault.AUDIT] = (String(files.map[NativeWalletVault.AUDIT] ?: ByteArray(0), Charsets.UTF_8) + pending.toString() + "\n").toByteArray(Charsets.UTF_8)
        assertFalse("the backfill refuses", NativeWalletVault(NativeTestWrap(), files).reconcileOrphanAudits())
        val doneRows = String(files.map[NativeWalletVault.AUDIT]!!, Charsets.UTF_8).lines().filter { it.isNotBlank() }.map { JSONObject(it) }
            .filter { it.optString("isolated") == iso && it.optString("state", "done") == "done" }
        assertEquals("no done row for the changed copy", 0, doneRows.size)
    }

    /** a pending row is written under the "isolating" key, so a reader that searches the done key does not find it. */
    @Test fun aPendingRowIsNotFoundByTheDoneKeySearch() {
        val iso = NativeWalletVault.REC + ".isolated.2026-11-18T00:00:00Z.cafe0002"
        val pendingLine = JSONObject().put("v", 1).put("name", NativeWalletVault.REC).put("isolating", iso)
            .put("reason", "isolated_for_new_slot").put("state", "pending").toString()
        assertFalse("the done-key search misses it", pendingLine.contains("\"isolated\":\"$iso\""))
        assertTrue("the pending key holds it", pendingLine.contains("\"isolating\":\"$iso\""))
    }
}
