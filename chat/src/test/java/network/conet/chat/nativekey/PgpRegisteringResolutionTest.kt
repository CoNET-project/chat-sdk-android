package network.conet.chat.nativekey

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Registering-state resolution (draft r2.5.20 第 5 版, 5B). The v2 marker records the write's chain block (`writeBlock`). Every case below is
 * decided from a fresh read of the chain, the pending key's state, and the absence rule (configured; default never confirms).
 */
class PgpRegisteringResolutionTest {
    private val acceptance = JSONObject(File("../spec/pgp-restore-acceptance-vectors.v1.json").readText(Charsets.UTF_8))
    private val account = acceptance.getJSONObject("syntheticAccount").getString("address").lowercase()
    private val password = JSONObject(File("../spec/pgp-backup-compat-vectors.v1.json").readText(Charsets.UTF_8))
        .getJSONArray("positives").getJSONObject(0).getString("passwordString")

    private fun identityOf(name: String) = PgpIdentity(
        acceptance.getJSONObject("identities").getJSONObject(name).getString("fingerprint"),
        acceptance.getJSONObject("identities").getJSONObject(name).getString("subkeyKeyID"),
    )

    private fun armorOf(name: String): String = acceptance.getJSONObject("syntheticKeys").getJSONObject(name).getString("privateArmor")

    /** A chain whose writes can throw (after or before landing) and whose reads can be unknown or hidden. [version] counts landed writes only. */
    private class ScriptedChain : PgpRestoreChain {
        var id: PgpIdentity? = null
        var text: String = ""
        var version: Long = 0L
        var attempts = 0
        var throwsLeft = 0
        var persistBeforeThrow = false
        var readUnknown = false
        var hideOnRead = false
        var head: Long? = 100L

        override fun chainReadable(): Boolean = true
        override fun backupReadable(): Boolean = true
        override fun version(): Long = version
        override fun identity(): PgpIdentity? = id
        override fun backupText(): String = text
        override fun headBlock(): Long? = head
        override fun identityRead(): IdentityRead = when {
            readUnknown -> IdentityRead.Unknown
            hideOnRead -> IdentityRead.Absent
            id == null -> IdentityRead.Absent
            else -> IdentityRead.Present(id!!)
        }
        override fun write(identity: PgpIdentity, backupText: String) {
            attempts++
            if (throwsLeft > 0) {
                throwsLeft--
                if (persistBeforeThrow) {
                    id = identity
                    text = backupText
                    version++
                }
                throw IllegalStateException("chain io")
            }
            id = identity
            text = backupText
            version++
        }
    }

    private inner class Fixture {
        val files = NativeTestFiles()
        val dev = PgpRestoreDevice("A", account, NativeTestWrap(), files)
        val chain = ScriptedChain()
        var confirmAbsence = false
        val ruleCalls = mutableListOf<Long>()
        val m = PgpRestoreMachine(
            chain = chain,
            wallet = object : PgpRestoreWallet {
                override fun ready(): Boolean = true
                override fun passwordString(): String? = password
            },
            keys = object : PgpRestoreKeys {
                override fun newKey(deviceId: String): PgpNewKey = PgpNewKey(armorOf("P4"), identityOf("P4"))
            },
            ivFor = { ByteArray(12) { 1 } },
            devices = mapOf("A" to dev),
            absence = RegisteringAbsenceRule { block ->
                ruleCalls += block
                confirmAbsence
            },
        )

        /** Gets the device to a pending key (the commit can run) without writing the chain. */
        fun toPending() {
            m.restore("A")
            m.tapEntry("A")
            m.keygen("A", "idem-1", nativeConfirmed = true)
        }
    }

    @Test
    fun aWriteThatThrowsAndDidNotLandIsRetriedWithTheSameKey() {
        val f = Fixture()
        f.toPending()
        val pendingBefore = f.dev.pending.identity()
        f.chain.throwsLeft = 1
        f.m.commit("A")
        assertEquals("failed", f.dev.ui.state)
        assertEquals("write_failed", f.dev.ui.code)
        assertFalse("the marker goes: the write did not land", f.dev.registeringMarked())
        assertEquals(null, f.chain.id)
        assertEquals("the pending key is kept", "idem-1", f.dev.pendingMeta()?.idemKey)

        f.m.retryWrite("A")
        assertEquals("ok", f.dev.ui.state)
        assertEquals("retry lands", identityOf("P4").fingerprint, f.chain.id?.fingerprint)
        assertEquals("the same pending key was written", pendingBefore, f.chain.id)
        assertEquals("one landed write", 1L, f.chain.version)
        assertEquals("two attempts", 2, f.chain.attempts)
    }

    @Test
    fun retryWithoutAPendingKeyIsRefused() {
        val f = Fixture()
        val r = f.m.retryWrite("A")
        assertEquals("rejected", r.result)
        assertEquals("no_pending", r.code)
        assertEquals("nothing written", 0, f.chain.attempts)
    }

    @Test
    fun aRetryWaitsWhileTheMarkerIsUnresolved() {
        val f = Fixture()
        f.toPending()
        f.dev.markRegistering(100L)
        f.confirmAbsence = false
        val r = f.m.retryWrite("A")
        assertEquals("undetermined", r.result)
        assertEquals("pgp_write_in_progress", f.dev.ui.code)
        assertEquals("nothing written", 0, f.chain.attempts)
        assertTrue("the marker stays", f.dev.registeringMarked())
    }

    @Test
    fun aWriteThatThrowsAfterLandingCarriesOnAsOk() {
        val f = Fixture()
        f.toPending()
        f.chain.throwsLeft = 1
        f.chain.persistBeforeThrow = true
        f.m.commit("A")
        assertEquals("ok", f.dev.ui.state)
        assertFalse("the marker goes after the local write", f.dev.registeringMarked())
        assertEquals("one attempt", 1, f.chain.attempts)
        assertEquals("one landed write", 1L, f.chain.version)
    }

    @Test
    fun aWriteThatThrowsAndCannotBeReadBackStaysUndetermined() {
        val f = Fixture()
        f.toPending()
        f.chain.throwsLeft = 1
        f.chain.readUnknown = true
        f.m.commit("A")
        assertEquals("undetermined", f.dev.ui.state)
        assertEquals("pgp_write_in_progress", f.dev.ui.code)
        assertTrue("the marker stays", f.dev.registeringMarked())
        assertEquals(0L, f.chain.version)
    }

    @Test
    fun theMarkerIsV2JsonWithTheWriteBlock() {
        val f = Fixture()
        f.toPending()
        f.m.commit("A", crashAt = "after_write")
        assertEquals("the marker records the head block of the write", 100L, f.dev.registeringMark()?.writeBlock)
        assertTrue("v2 format", f.dev.registeringMark()?.v2 == true)
    }

    @Test
    fun aCrashAfterTheWriteResolvesWhenTheChainHoldsThePendingIdentity() {
        val f = Fixture()
        f.toPending()
        f.m.commit("A", crashAt = "after_write")
        val again = f.m.restore("A")
        assertFalse("resolved by the identity on the chain", f.dev.ui.code == "pgp_write_in_progress")
        assertFalse("the marker goes", f.dev.registeringMarked())
        assertEquals("ok", again.result)
    }

    @Test
    fun aReadBackAbsentAfterTheWriteIsReportedAndResolvesWhenVisible() {
        val f = Fixture()
        f.toPending()
        f.chain.hideOnRead = true
        val committed = f.m.commit("A")
        // (b) review 4: the step answer agrees with the UI state: undetermined, never ok.
        assertEquals("undetermined", committed.result)
        assertEquals("readback_failed", committed.code)
        assertEquals("undetermined", f.dev.ui.state)
        assertEquals("readback_failed", f.dev.ui.code)
        assertEquals("the marker keeps the head block of the write", 100L, f.dev.registeringMark()?.writeBlock)
        assertEquals("the pending key is kept", "idem-1", f.dev.pendingMeta()?.idemKey)

        val still = f.m.restore("A")
        assertEquals("undetermined", still.result)
        assertEquals("pgp_write_in_progress", f.dev.ui.code)

        f.chain.hideOnRead = false
        f.m.restore("A")
        assertFalse("resolved once visible", f.dev.registeringMarked())
        assertEquals("one landed write", 1L, f.chain.version)
    }

    /** Draft 5B(3): a pending key with the marker never clears by absence; with confirmed absence after writeBlock it is RETRY_READY (same key). */
    @Test
    fun invariantAMarkerIsNeverClearedByAbsenceAndConfirmedAbsenceIsRetryReady() {
        val f = Fixture()
        f.toPending()
        f.dev.markRegistering(100L)
        f.confirmAbsence = true
        val r = f.m.restore("A")
        assertEquals("retry_ready", r.result)
        assertEquals("retry_ready", f.dev.ui.state)
        assertTrue("the marker stays", f.dev.registeringMarked())
        assertEquals("the rule was asked about the writeBlock", listOf(100L), f.ruleCalls)
        assertEquals(0, f.chain.attempts)
        val second = f.m.keygen("A", "idem-2", nativeConfirmed = true)
        assertNotEquals("ok", second.result)
        assertEquals("the pending key is still the first", "idem-1", f.dev.pendingMeta()?.idemKey)
    }

    @Test
    fun aRetryReadyRetriesWithTheSameKeyAndANewWriteBlock() {
        val f = Fixture()
        f.toPending()
        val pendingBefore = f.dev.pending.identity()
        f.dev.markRegistering(100L)
        f.confirmAbsence = true
        f.chain.head = 250L
        f.m.retryWrite("A")
        assertEquals("ok", f.dev.ui.state)
        assertEquals("the same pending key was written", pendingBefore, f.chain.id)
        assertFalse("marker cleared after the local write", f.dev.registeringMarked())
    }

    /** Draft 5B 2(c): no pending key, the chain absent after the write block on both endpoints: the marker goes, with its cleared audit. */
    @Test
    fun withoutAPendingKeyAConfirmedAbsenceClearsTheMarkerWithItsAudit() {
        val f = Fixture()
        f.dev.markRegistering(100L)
        f.confirmAbsence = true
        f.m.restore("A")
        assertEquals("the rule was asked about the marker's block", listOf(100L), f.ruleCalls)
        assertFalse("cleared", f.dev.registeringMarked())
        assertFalse(f.dev.ui.code == "pgp_write_in_progress")
        val audit = String(f.files.read("pgp.restore.registering.cleared.$account")!!, Charsets.UTF_8)
        assertTrue("the cleared audit records the write block", audit.contains("writeBlock=100"))
    }

    /** Without a confirmed absence the marker stays (no pending key, no identity on the chain). */
    @Test
    fun withoutAConfirmedAbsenceAndNoPendingKeyTheMarkerStays() {
        val f = Fixture()
        f.dev.markRegistering(100L)
        f.confirmAbsence = false
        f.m.restore("A")
        assertTrue("the marker stays", f.dev.registeringMarked())
        assertEquals("pgp_write_in_progress", f.dev.ui.code)
        assertNull("no cleared audit", f.files.read("pgp.restore.registering.cleared.$account"))
    }

    @Test
    fun aMarkerWithoutABlockIsNeverRetryReadyByAbsence() {
        val f = Fixture()
        f.toPending()
        f.dev.markRegistering(null)
        f.confirmAbsence = true
        val r = f.m.restore("A")
        assertEquals("undetermined", r.result)
        assertTrue("the marker stays", f.dev.registeringMarked())
        assertTrue("the rule is not asked without a block", f.ruleCalls.isEmpty())
    }

    @Test
    fun aChainThatCannotAnswerKeepsTheMarkerWhateverTheBlock() {
        val f = Fixture()
        f.dev.markRegistering(100L)
        f.chain.readUnknown = true
        f.confirmAbsence = true
        val r = f.m.restore("A")
        assertEquals("undetermined", r.result)
        assertEquals("pgp_write_in_progress", f.dev.ui.code)
        assertTrue("unknown chain: the marker stays", f.dev.registeringMarked())
    }

    /** Draft 5B(5): a Locked pending key is pending: the marker stays, the rule is not asked. */
    @Test
    fun aLockedPendingKeyCountsAsExistingAndTheMarkerStays() {
        val f = Fixture()
        f.toPending()
        f.files.delete(NativePgpVault.markName(account, NativePgpVault.Slot.PENDING))
        assertTrue("the pending key is Locked, not NoKey", f.dev.pending.state() is NativePgpVault.State.Locked)
        f.dev.markRegistering(100L)
        f.confirmAbsence = true
        val r = f.m.restore("A")
        assertEquals("undetermined", r.result)
        assertEquals("pgp_write_in_progress", f.dev.ui.code)
        assertTrue("the marker stays", f.dev.registeringMarked())
        assertTrue("the rule is not consulted for a Locked pending key", f.ruleCalls.isEmpty())
    }

    /** Draft 5B(4): a Ready pending key and another identity on the chain: restore_failed, the marker stays, nothing is cleared. */
    @Test
    fun aPendingKeyAndAnotherIdentityOnTheChainIsRestoreFailed() {
        val f = Fixture()
        f.toPending()
        f.dev.markRegistering(100L)
        f.chain.id = identityOf("P3")
        val r = f.m.restore("A")
        assertEquals("failed:pending_differs", r.result)
        assertEquals("failed", f.dev.ui.state)
        assertEquals("pgp_pending_differs", f.dev.ui.code)
        assertTrue("the marker stays", f.dev.registeringMarked())
        assertEquals("the pending key is kept", "idem-1", f.dev.pendingMeta()?.idemKey)
    }

    /** Draft 5B(2b): another identity and no pending key: the marker is superseded and audited; the evaluation goes on. */
    @Test
    fun aSupersededMarkerWithoutAPendingKeyIsAuditedAndTheEvaluationGoesOn() {
        val f = Fixture()
        f.dev.markRegistering(100L)
        f.chain.id = identityOf("P3")
        f.m.restore("A")
        assertFalse("the marker goes", f.dev.registeringMarked())
        assertNotEquals("pgp_write_in_progress", f.dev.ui.code)
        assertEquals("pgp_backup_missing", f.dev.ui.code)
        val audit = String(f.files.read("pgp.restore.superseded.$account")!!, Charsets.UTF_8)
        assertTrue("the active side is recorded as none", audit.contains("active=none"))
        assertTrue("the chain fingerprint is audited", audit.contains(identityOf("P3").fingerprint))
        assertEquals("nothing written", 0, f.chain.attempts)
    }

    /** Draft 5B(2b): a superseded marker with an active key that differs from the chain is pgp_locked, never overwritten. */
    @Test
    fun aSupersededMarkerWithADifferentActiveKeyIsPgpLocked() {
        val f = Fixture()
        assertEquals(NativePgpVault.Put.OK, f.dev.active.put(account, armorOf("P2"), ""))
        f.dev.markRegistering(100L)
        f.chain.id = identityOf("P3")
        val r = f.m.restore("A")
        assertEquals("undetermined", r.result)
        assertEquals("pgp_locked", f.dev.ui.code)
        assertFalse("the marker goes after the audit", f.dev.registeringMarked())
        assertEquals("the active key is untouched", identityOf("P2").fingerprint, f.dev.active.identity()?.fingerprint)
        assertEquals("nothing written", 0, f.chain.attempts)
    }

    /** Draft 5B(1): a legacy marker goes only when the chain holds the pending key and the active slot already holds it. */
    @Test
    fun aLegacyMarkerGoesOnlyWhenTheChainAndTheActiveSlotHoldThePendingKey() {
        val f = Fixture()
        f.toPending()
        f.files.write("pgp.restore.registering.$account", "1".toByteArray(Charsets.UTF_8))
        f.chain.id = identityOf("P4")
        val onlyChain = f.m.restore("A")
        assertEquals("undetermined", onlyChain.result)
        assertEquals("pgp_registering_unknown_format", f.dev.ui.code)
        assertTrue("the legacy marker stays while the active slot is empty", f.dev.registeringMarked())

        assertEquals(NativePgpVault.Put.OK, f.dev.active.put(account, armorOf("P4"), ""))
        f.m.restore("A")
        assertFalse("chain and active both hold the pending key: the legacy marker goes", f.dev.registeringMarked())
    }

    private fun auditOf(f: Fixture, name: String): String? = f.files.read("$name.$account")?.let { String(it, Charsets.UTF_8) }

    /** Draft 5B 2(a): a completed registration (active written, identity on the chain) writes the resolved audit and clears pending and marker. */
    @Test
    fun aCompletedRegistrationWritesTheResolvedAuditAndClearsPendingAndMarker() {
        val f = Fixture()
        f.toPending()
        f.m.commit("A", crashAt = "after_write")
        f.m.restore("A")
        assertFalse(f.dev.registeringMarked())
        assertTrue("pending is cleared", f.dev.pending.state() is NativePgpVault.State.NoKey)
        assertTrue("active is written", f.dev.active.state() is NativePgpVault.State.Ready)
        assertTrue("the resolved audit records writeBlock 100", auditOf(f, "pgp.restore.registering.resolved")?.contains("writeBlock=100") == true)
    }

    /** A normal commit (no crash) writes the resolved audit as well. */
    @Test
    fun aNormalCommitWritesTheResolvedAudit() {
        val f = Fixture()
        f.toPending()
        f.m.commit("A")
        assertEquals("ok", f.dev.ui.state)
        assertTrue("the resolved audit is written", auditOf(f, "pgp.restore.registering.resolved")?.contains("writeBlock=100") == true)
    }

    /** Without a write (evaluation), the chain's identity with an empty active slot keeps the marker: nothing is resolved yet. */
    @Test
    fun anEvaluationWithoutTheActiveWriteKeepsTheMarkerAndWritesNoResolvedAudit() {
        val f = Fixture()
        f.toPending()
        f.m.commit("A", crashAt = "after_write")
        f.m.evaluate("A")
        assertTrue("the marker stays until the active write", f.dev.registeringMarked())
        assertNull("no resolved audit yet", auditOf(f, "pgp.restore.registering.resolved"))
        assertTrue("the pending key stays", f.dev.pending.state() is NativePgpVault.State.Ready)
    }

    /** The active slot already holds the chain's identity: the registration is resolved at once, with its audit. */
    @Test
    fun anActiveSlotThatAlreadyHoldsTheIdentityResolvesAtOnce() {
        val f = Fixture()
        f.toPending()
        f.m.commit("A", crashAt = "after_write")
        assertEquals(NativePgpVault.Put.OK, f.dev.active.put(account, armorOf("P4"), ""))
        f.m.evaluate("A")
        assertFalse(f.dev.registeringMarked())
        assertTrue(f.dev.pending.state() is NativePgpVault.State.NoKey)
        assertTrue(auditOf(f, "pgp.restore.registering.resolved") != null)
    }

    /**
     * Review v7 item 1: a failed resolved audit leaves the pending key and the marker in place, so the next evaluation completes the registration
     * and never writes a superseded audit. The audit is retried and then written.
     */
    @Test
    fun aFailedResolvedAuditKeepsThePendingKeyAndTheMarkerAndWritesNoSupersededAudit() {
        val f = Fixture()
        f.toPending()
        f.m.commit("A", crashAt = "after_write")
        assertEquals(NativePgpVault.Put.OK, f.dev.active.put(account, armorOf("P4"), ""))
        f.files.failWrite = "pgp.restore.registering.resolved.$account"
        val r = f.m.evaluate("A")
        assertEquals("undetermined", r.result)
        assertEquals("pgp_write_in_progress", f.dev.ui.code)
        assertTrue("the pending key stays", f.dev.pending.state() is NativePgpVault.State.Ready)
        assertTrue("the marker stays", f.dev.registeringMarked())
        assertNull("no superseded audit", f.files.read("pgp.restore.superseded.$account"))

        f.files.failWrite = null
        f.m.evaluate("A")
        assertFalse("the marker goes once the audit is written", f.dev.registeringMarked())
        assertTrue("the pending key goes with it", f.dev.pending.state() is NativePgpVault.State.NoKey)
        assertTrue("the resolved audit is written", auditOf(f, "pgp.restore.registering.resolved") != null)
        assertNull("still no superseded audit", f.files.read("pgp.restore.superseded.$account"))
    }

    /** The restore path's completion has the same order: the active write happens, the audit fails, the state stays; the next run completes it. */
    @Test
    fun aFailedAuditAfterARestoreWriteIsCompletedByTheNextRun() {
        val f = Fixture()
        f.toPending()
        f.m.commit("A", crashAt = "after_write")
        f.files.failWrite = "pgp.restore.registering.resolved.$account"
        val r = f.m.restore("A")
        assertEquals("undetermined", r.result)
        assertTrue("the active slot is written", f.dev.active.state() is NativePgpVault.State.Ready)
        assertTrue("the pending key stays until the audit", f.dev.pending.state() is NativePgpVault.State.Ready)
        assertTrue("the marker stays until the audit", f.dev.registeringMarked())

        f.files.failWrite = null
        f.m.restore("A")
        assertFalse(f.dev.registeringMarked())
        assertTrue(f.dev.pending.state() is NativePgpVault.State.NoKey)
        assertNull("no superseded audit", f.files.read("pgp.restore.superseded.$account"))
    }
}
