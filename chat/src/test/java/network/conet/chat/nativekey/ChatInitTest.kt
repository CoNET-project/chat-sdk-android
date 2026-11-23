package network.conet.chat.nativekey

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * `chatInit` phase 1 (draft r2.5.20 第 5 版): the rules and the G2 flow. Synthetic keys only; nothing reaches the chain or the bridge.
 */
class ChatInitTest {
    private val acceptance = JSONObject(File("../spec/pgp-restore-acceptance-vectors.v1.json").readText(Charsets.UTF_8))
    private val account = acceptance.getJSONObject("syntheticAccount").getString("address").lowercase()
    private val password = JSONObject(File("../spec/pgp-backup-compat-vectors.v1.json").readText(Charsets.UTF_8))
        .getJSONArray("positives").getJSONObject(0).getString("passwordString")

    private fun identityOf(name: String) = PgpIdentity(
        acceptance.getJSONObject("identities").getJSONObject(name).getString("fingerprint"),
        acceptance.getJSONObject("identities").getJSONObject(name).getString("subkeyKeyID"),
    )

    private fun armorOf(name: String): String = acceptance.getJSONObject("syntheticKeys").getJSONObject(name).getString("privateArmor")

    private class FlowChain : PgpRestoreChain {
        var id: PgpIdentity? = null
        var text: String = ""
        var version: Long = 0L
        var attempts = 0
        var readUnknown = false
        var head: Long? = 100L
        override fun chainReadable(): Boolean = !readUnknown
        override fun backupReadable(): Boolean = !readUnknown
        override fun version(): Long = version
        override fun identity(): PgpIdentity? = id
        override fun backupText(): String = text
        override fun headBlock(): Long? = head
        override fun identityRead(): IdentityRead = when {
            readUnknown -> IdentityRead.Unknown
            id == null -> IdentityRead.Absent
            else -> IdentityRead.Present(id!!)
        }
        override fun write(identity: PgpIdentity, backupText: String) {
            attempts++
            id = identity
            text = backupText
            version++
        }
    }

    private inner class Fixture(absenceTrue: Boolean = false) {
        val files = NativeTestFiles()
        val dev = PgpRestoreDevice("A", account, NativeTestWrap(), files)
        val chain = FlowChain()
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
            absence = RegisteringAbsenceRule { absenceTrue },
        )

        fun backupOf(name: String): String = NativePgpBackup.encryptArmor(password, armorOf(name).toByteArray(Charsets.UTF_8), ByteArray(12) { 1 })
    }

    // ---- rules -------------------------------------------------------------------------------------------------------------------------------

    @Test
    fun inputRules() {
        assertEquals(ChatInitRules.KEY_REFUSED, ChatInitRules.inputError(listOf("type", "reqId", "privateKeyArmor"), "r1", null))
        assertEquals(ChatInitRules.KEY_REFUSED, ChatInitRules.inputError(listOf("type", "reqId", "walletSignature"), "r1", null))
        assertEquals(ChatInitRules.BAD_REQUEST, ChatInitRules.inputError(listOf("type", "reqId", "eoa"), "r1", null))
        assertEquals(ChatInitRules.BAD_REQUEST, ChatInitRules.inputError(listOf("type", "reqId"), null, null))
        assertEquals(ChatInitRules.BAD_REQUEST, ChatInitRules.inputError(listOf("type", "reqId", "workspace"), "r1", "other"))
        assertNull(ChatInitRules.inputError(listOf("type", "reqId"), "r1", null))
        assertNull(ChatInitRules.inputError(listOf("type", "reqId", "workspace"), 7, "default"))
    }

    @Test
    fun gateG0AndG1ArePendingConfirmAndG2RunsTheFlow() {
        assertEquals(ChatInitRules.PENDING_CONFIRM, ChatInitRules.gateStatus(NoKeyGate.Gate.G0))
        assertEquals(ChatInitRules.PENDING_CONFIRM, ChatInitRules.gateStatus(NoKeyGate.Gate.G1))
        assertNull(ChatInitRules.gateStatus(NoKeyGate.Gate.G2))
    }

    /** Every UI state maps to a status in the closed set; `unknown` is never one (draft 第 1 节). */
    @Test
    fun everyUiStateMapsToAStatusAndUnknownNeverLeaves() {
        val closed = setOf(ChatInitRules.READY, ChatInitRules.PENDING_CONFIRM, ChatInitRules.RESTORE_FAILED, ChatInitRules.REGISTERING, ChatInitRules.ERROR)
        val states = listOf("not_evaluated", "undetermined", "blocked", "first_identity", "ok", "retry_ready", "failed", "awaiting_confirm", "unknown")
        for (s in states) for (m in listOf(true, false)) {
            val status = ChatInitRules.statusOf(s, m)
            assertTrue("$s -> $status", status in closed)
            assertFalse("$s must not leave as unknown", status == "unknown")
        }
        assertEquals(ChatInitRules.READY, ChatInitRules.statusOf("ok", true))
        assertEquals(ChatInitRules.PENDING_CONFIRM, ChatInitRules.statusOf("ok", false))
        // Draft 4.2 and the status table: retry_ready is never registering outwardly; the flow retries it.
        assertEquals(ChatInitRules.PENDING_CONFIRM, ChatInitRules.statusOf("retry_ready", false))
        assertEquals(ChatInitRules.RESTORE_FAILED, ChatInitRules.statusOf("failed", false))
        assertEquals(ChatInitRules.PENDING_CONFIRM, ChatInitRules.statusOf("undetermined", false))
    }

    /** Draft 第 1 节 白名单: the builder adds only the public names, and never a private one; `code` appears only for error. */
    @Test
    fun theResultCarriesOnlyTheWhitelistedNames() {
        val statuses = listOf(ChatInitRules.READY, ChatInitRules.PENDING_CONFIRM, ChatInitRules.RESTORE_FAILED, ChatInitRules.REGISTERING)
        for (s in statuses) {
            val p = ChatInitRules.resultPayload("r1", s, eoa = "0xABC", keyId = "K1", publicKeyArmored = "PUB")
            val keys = p.keys().asSequence().map { it.toString() }.toSet()
            assertTrue("$s keys $keys", ChatInitRules.PUBLIC_FIELDS.containsAll(keys))
            assertTrue(keys.none { it in ChatInitRules.FORBIDDEN_FIELDS })
            assertFalse("code only for error", p.has("code"))
            assertEquals("0xabc", p.getString("eoa"))
        }
        val err = ChatInitRules.resultPayload("r1", ChatInitRules.ERROR, code = "bad_request")
        assertEquals("bad_request", err.getString("code"))
        assertEquals("none", err.getString("registrationStatus"))
        assertEquals("confirmed", ChatInitRules.resultPayload("r1", ChatInitRules.READY).getString("registrationStatus"))
        assertEquals("submitted", ChatInitRules.resultPayload("r1", ChatInitRules.REGISTERING).getString("registrationStatus"))
    }

    // ---- G2 flow ----------------------------------------------------------------------------------------------------------------------------

    @Test
    fun aFirstIdentityIsPendingConfirmAndNothingIsGenerated() {
        val f = Fixture()
        val p = ChatInitFlow.run(f.m, "A", account, "r1", recoveryProtected = false, flight = ChatInitFlight())
        assertEquals(ChatInitRules.PENDING_CONFIRM, p.getString("status"))
        assertEquals(0, f.chain.attempts)
        assertEquals("first_identity", f.dev.ui.state)
        assertFalse("no pending key is created", f.dev.pending.state() is NativePgpVault.State.Ready)
    }

    @Test
    fun anUnreadableChainIsPendingConfirmNotUnknown() {
        val f = Fixture()
        f.chain.readUnknown = true
        val p = ChatInitFlow.run(f.m, "A", account, "r1", recoveryProtected = false, flight = ChatInitFlight())
        assertEquals(ChatInitRules.PENDING_CONFIRM, p.getString("status"))
        assertEquals(0, f.chain.attempts)
    }

    @Test
    fun aMatchingChainAndActiveKeyIsReadyWithTheKeyId() {
        val f = Fixture()
        f.chain.id = identityOf("P4")
        f.chain.text = f.backupOf("P4")
        assertEquals(NativePgpVault.Put.OK, f.dev.active.put(account, armorOf("P4"), ""))
        val p = ChatInitFlow.run(f.m, "A", account, "r1", recoveryProtected = false, flight = ChatInitFlight())
        assertEquals(ChatInitRules.READY, p.getString("status"))
        assertEquals(identityOf("P4").subkeyKeyId, p.getString("keyId"))
        assertEquals("confirmed", p.getString("registrationStatus"))
        assertEquals(0, f.chain.attempts)
    }

    @Test
    fun aBackupThatDoesNotDecryptIsRestoreFailed() {
        val f = Fixture()
        f.chain.id = identityOf("P4")
        f.chain.text = "not-a-backup"
        val p = ChatInitFlow.run(f.m, "A", account, "r1", recoveryProtected = false, flight = ChatInitFlight())
        assertEquals(ChatInitRules.RESTORE_FAILED, p.getString("status"))
        assertEquals(0, f.chain.attempts)
    }

    @Test
    fun aRecoveryFailureCounterIsRestoreFailedAndTheEvaluationDoesNotRun() {
        val f = Fixture()
        val p = ChatInitFlow.run(f.m, "A", account, "r1", recoveryProtected = true, flight = ChatInitFlight())
        assertEquals(ChatInitRules.RESTORE_FAILED, p.getString("status"))
        assertEquals("the evaluation did not run", "not_evaluated", f.dev.ui.state)
        assertEquals(0, f.chain.attempts)
    }

    /** Draft 4.2 (r2.5.20 第 7 版): retry_ready is retried by chatInit with the same pending key; the retry lands and the result is ready. */
    @Test
    fun aRetryReadyPendingKeyIsRetriedByTheFlowWithTheSameKey() {
        val f = Fixture(absenceTrue = true)
        f.m.restore("A")
        f.m.tapEntry("A")
        f.m.keygen("A", "idem-1", nativeConfirmed = true)
        f.dev.markRegistering(100L)
        val p = ChatInitFlow.run(f.m, "A", account, "r1", recoveryProtected = false, flight = ChatInitFlight())
        assertEquals(ChatInitRules.READY, p.getString("status"))
        assertEquals(identityOf("P4").subkeyKeyId, p.getString("keyId"))
        assertEquals("the retry wrote the chain once", 1, f.chain.attempts)
        assertEquals("the same pending identity", identityOf("P4").fingerprint, f.chain.identity()?.fingerprint)
    }

    /** Draft 5B 5: a Locked pending key is never retried; the state stays pending (pgp_write_in_progress). */
    @Test
    fun aLockedPendingKeyIsNotRetried() {
        val f = Fixture(absenceTrue = true)
        f.m.restore("A")
        f.m.tapEntry("A")
        f.m.keygen("A", "idem-1", nativeConfirmed = true)
        f.files.delete(NativePgpVault.markName(account, NativePgpVault.Slot.PENDING))
        f.dev.markRegistering(100L)
        val p = ChatInitFlow.run(f.m, "A", account, "r1", recoveryProtected = false, flight = ChatInitFlight())
        assertEquals(ChatInitRules.PENDING_CONFIRM, p.getString("status"))
        assertEquals("pgp_write_in_progress", f.dev.ui.code)
        assertEquals("no retry", 0, f.chain.attempts)
    }

    /** Draft 4.3 (r2.5.20 第 7 版): the chain holds a decryptable identity and the active slot is empty: restore writes the empty slot, then ready. */
    @Test
    fun aChainIdentityWithAnEmptyActiveSlotIsRestoredIntoTheSlotAndIsReady() {
        val f = Fixture()
        f.chain.id = identityOf("P4")
        f.chain.text = f.backupOf("P4")
        val p = ChatInitFlow.run(f.m, "A", account, "r1", recoveryProtected = false, flight = ChatInitFlight())
        assertEquals(ChatInitRules.READY, p.getString("status"))
        assertEquals(identityOf("P4").fingerprint, f.dev.active.identity()?.fingerprint)
        assertEquals("the chain is not written", 0, f.chain.attempts)
    }

    /** Draft 4.3: a restore whose active write fails is restore_failed, never an endless pending. */
    @Test
    fun aRestoreThatCannotWriteTheSlotIsRestoreFailed() {
        val f = Fixture()
        f.chain.id = identityOf("P4")
        f.chain.text = f.backupOf("P4")
        f.files.failWrite = NativePgpVault.recName(account)
        val p = ChatInitFlow.run(f.m, "A", account, "r1", recoveryProtected = false, flight = ChatInitFlight())
        assertEquals(ChatInitRules.RESTORE_FAILED, p.getString("status"))
        assertEquals("the chain is not written", 0, f.chain.attempts)
    }

    /** Single in-flight (draft 第 5 节): a second call while one runs is pending_confirm and runs nothing. */
    @Test
    fun aSecondCallWhileAFlowRunsIsPendingConfirmAndRunsNothing() {
        val f = Fixture()
        val flight = ChatInitFlight()
        assertTrue(flight.tryEnter())
        val p = ChatInitFlow.run(f.m, "A", account, "r1", recoveryProtected = false, flight = flight)
        assertEquals(ChatInitRules.PENDING_CONFIRM, p.getString("status"))
        assertEquals("the evaluation did not run", "not_evaluated", f.dev.ui.state)
        flight.exit()
        val again = ChatInitFlow.run(f.m, "A", account, "r1", recoveryProtected = false, flight = flight)
        assertEquals("first_identity was reached after release", "first_identity", f.dev.ui.state)
        assertEquals(ChatInitRules.PENDING_CONFIRM, again.getString("status"))
    }

    @Test
    fun theFlightIsReleasedWhenTheFlowEnds() {
        val f = Fixture()
        val flight = ChatInitFlight()
        ChatInitFlow.run(f.m, "A", account, "r1", recoveryProtected = true, flight = flight)
        assertTrue("released after the flow", flight.tryEnter())
        flight.exit()
    }

    /** Draft N-1 (review 5, c): the recovery protection comes from the stored failure counter, through the same flow. */
    private fun storeWith(failures: Int) = object : RecoveryFailureStore {
        override fun failures(): Int = failures
        override fun lastFailureAtMs(): Long = 0L
        override fun save(failures: Int, atMs: Long) = Unit
        override fun clear() = Unit
    }

    @Test
    fun aStoredRecoveryFailureCounterProtectsAndTheEvaluationDoesNotRun() {
        val f = Fixture()
        val p = ChatInitFlow.runWithStore(f.m, "A", account, "r1", storeWith(2), ChatInitFlight())
        assertEquals(ChatInitRules.RESTORE_FAILED, p.getString("status"))
        assertEquals("not_evaluated", f.dev.ui.state)
    }

    @Test
    fun noStoredRecoveryFailureRunsTheEvaluation() {
        val f = Fixture()
        val p = ChatInitFlow.runWithStore(f.m, "A", account, "r1", storeWith(0), ChatInitFlight())
        assertEquals(ChatInitRules.PENDING_CONFIRM, p.getString("status"))
        assertEquals("first_identity", f.dev.ui.state)
    }

    /** Review 5 (c): the in-flight guard is the process one; a flow held by another machine is seen as in flight. */
    @Test
    fun theProcessInFlightGuardIsSharedAcrossMachines() {
        val first = Fixture()
        val second = Fixture()
        assertTrue(ChatInitProcess.flight.tryEnter())
        val p = ChatInitFlow.runWithStore(second.m, "A", account, "r1", storeWith(0), ChatInitProcess.flight)
        assertEquals(ChatInitRules.PENDING_CONFIRM, p.getString("status"))
        assertEquals("not_evaluated", second.dev.ui.state)
        ChatInitProcess.flight.exit()
        assertEquals("not_evaluated", first.dev.ui.state)
    }
}
