package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * The first-identity machine is a QA build's (production builds open it only after acceptance).
 * The default build starts none of it: no generation, no submission, no K-only discard, no pending resume, no addUser payload. The
 * recovery and the reconciliation of an ACTIVE key with the same key run in every build.
 */
class FirstIdentityGateTest {
    private val ready = NativePgpVault.State.Ready("FP")
    private val noKey = NativePgpVault.State.NoKey

    private class Spy(val firstAnswer: FirstIdentityCoordinator.Result = FirstIdentityCoordinator.Result.NotApplicable()) {
        val modes = ArrayList<FirstIdentityCoordinator.Mode>()
        var baseCalls = 0
        var base: KpgpPolicy.Expect = KpgpPolicy.Expect("pgp_migration_retry", emptyList(), emptyList(), "pgp_migration_retry")
        fun run(mode: FirstIdentityCoordinator.Mode): FirstIdentityCoordinator.Result { modes += mode; return firstAnswer }
        fun base(): KpgpPolicy.Expect { baseCalls++; return base }
    }

    private fun expect(action: String) = KpgpPolicy.Expect(action, emptyList(), emptyList(), action)

    private fun go(enabled: Boolean, state: NativePgpVault.State?, spy: Spy) =
        KpgpUpgrade.orchestrate(enabled, { state }, { spy.run(it) }, { spy.base() })

    // ---- the default build ---------------------------------------------------------------------------------------------------------------

    @Test
    fun theDefaultBuildNeverStartsTheMachineForAnAccountWithNoVaultKey() {
        for (answer in listOf(
            FirstIdentityCoordinator.Result.Registered,
            FirstIdentityCoordinator.Result.RetryLater("x"),
            FirstIdentityCoordinator.Result.Conflict,
            FirstIdentityCoordinator.Result.Failed("x"),
        )) {
            val spy = Spy(answer).also { it.base = expect("upgraded_from_chain") }
            val r = go(false, noKey, spy)
            assertTrue("no coordinator run of any mode", spy.modes.isEmpty())
            assertEquals("the approved recovery decides", "upgraded_from_chain", r.action)
            assertEquals(1, spy.baseCalls)
        }
    }

    @Test
    fun theDefaultBuildStillRunsTheApprovedRecoveryForAnEmptySlot() {
        val spy = Spy().also { it.base = expect("pgp_migration_retry") }
        assertEquals("pgp_migration_retry", go(false, noKey, spy).action)
        assertEquals(1, spy.baseCalls)
        assertTrue(spy.modes.isEmpty())
    }

    @Test
    fun theDefaultBuildReconcilesAnActiveKeyInTheReconcileOnlyMode() {
        for (action in listOf("keep_existing", "upgraded_from_L", "upgraded_from_chain")) {
            val spy = Spy().also { it.base = expect(action) }
            go(false, ready, spy)
            assertEquals("$action: one run, reconcile only", listOf(FirstIdentityCoordinator.Mode.RECONCILE_ONLY), spy.modes)
        }
        // A retry of the reconcile is the same retry answer as before.
        val retry = Spy(FirstIdentityCoordinator.Result.RetryLater("network_unavailable")).also { it.base = expect("keep_existing") }
        assertEquals(KpgpUpgrade.FIRST_IDENTITY_RETRY, go(false, ready, retry).action)
        val failed = Spy(FirstIdentityCoordinator.Result.Failed("x")).also { it.base = expect("keep_existing") }
        assertEquals(KpgpUpgrade.FIRST_IDENTITY_RETRY, go(false, ready, failed).action)
        // Registered, conflict and not-applicable leave the base answer.
        for (answer in listOf(FirstIdentityCoordinator.Result.Registered, FirstIdentityCoordinator.Result.Conflict, FirstIdentityCoordinator.Result.NotApplicable())) {
            val s = Spy(answer).also { it.base = expect("keep_existing") }
            assertEquals("keep_existing", go(false, ready, s).action)
        }
    }

    @Test
    fun theDefaultBuildDoesNotReconcileWhenTheBaseAnswerIsNotSettledOrTheStateIsNotReady() {
        val unsettled = Spy().also { it.base = expect("pgp_migration_retry") }
        go(false, ready, unsettled)
        assertTrue(unsettled.modes.isEmpty())
        for (st in listOf(null, NativePgpVault.State.Locked("x"))) {
            val s = Spy().also { it.base = expect("keep_existing") }
            go(false, st, s)
            assertTrue(s.modes.isEmpty())
        }
    }

    // ---- the QA build: as before ---------------------------------------------------------------------------------------------------------

    @Test
    fun aQaBuildRunsTheFullMachineForAnAccountWithNoVaultKey() {
        val registered = Spy(FirstIdentityCoordinator.Result.Registered)
        assertEquals(KpgpUpgrade.FIRST_IDENTITY_REGISTERED, go(true, noKey, registered).action)
        assertEquals(listOf(FirstIdentityCoordinator.Mode.FULL), registered.modes)
        assertEquals("the base is not asked after a registration", 0, registered.baseCalls)
        for (answer in listOf(FirstIdentityCoordinator.Result.RetryLater("x"), FirstIdentityCoordinator.Result.Failed("x"), FirstIdentityCoordinator.Result.Conflict)) {
            val s = Spy(answer)
            val r = go(true, noKey, s)
            assertEquals(KpgpUpgrade.FIRST_IDENTITY_RETRY, r.action)
            assertTrue(r.rollback)
            assertEquals(listOf(FirstIdentityCoordinator.Mode.FULL), s.modes)
            assertEquals(0, s.baseCalls)
        }
        // A registered chain or a case that is not the machine's goes on to the recovery.
        for (answer in listOf(FirstIdentityCoordinator.Result.Recovery("registered"), FirstIdentityCoordinator.Result.NotApplicable())) {
            val s = Spy(answer).also { it.base = expect("upgraded_from_chain") }
            assertEquals("upgraded_from_chain", go(true, noKey, s).action)
            assertEquals(1, s.baseCalls)
        }
    }

    @Test
    fun aQaBuildReconcilesAnActiveKeyWithTheFullMachineAsBefore() {
        val spy = Spy().also { it.base = expect("keep_existing") }
        go(true, ready, spy)
        assertEquals(listOf(FirstIdentityCoordinator.Mode.FULL), spy.modes)
        val retry = Spy(FirstIdentityCoordinator.Result.RetryLater("x")).also { it.base = expect("upgraded_from_L") }
        assertEquals(KpgpUpgrade.FIRST_IDENTITY_RETRY, go(true, ready, retry).action)
    }

    // ---- the wiring ----------------------------------------------------------------------------------------------------------------------

    @Test
    fun theProductionSwitchIsTheQaFlagAndEveryCoordinatorRunGoesThroughTheGate() {
        val src = File("src/main/java/network/conet/chat/nativekey/KpgpUpgrade.kt").readText()
        assertTrue(src.contains("firstIdentityEnabled = network.conet.chat.BuildConfig.IDENTITY_STATE_EVENTS_QA"))
        // The only call of the production coordinator is the one inside the gated orchestration's runFirst.
        assertEquals(1, Regex("""firstIdentity\(app, eoa, store, storeAccount, nowSec, mode\)""").findAll(src).count())
        assertEquals("firstIdentity( is defined once and called once", 2, Regex("""\bfirstIdentity\(""").findAll(src).count())
        val orchestrate = src.substringAfter("internal fun orchestrate(").substringBefore("private val SETTLED_ACTIONS")
        assertTrue(orchestrate.contains("if (firstIdentityEnabled && state is NativePgpVault.State.NoKey)"))
        assertTrue(orchestrate.contains("if (firstIdentityEnabled) FirstIdentityCoordinator.Mode.FULL else FirstIdentityCoordinator.Mode.RECONCILE_ONLY"))
        // Nothing else constructs the coordinator, and the account-create command is its own QA-gated path.
        val users = File("src/main/java/network/conet/chat").walkTopDown().filter { it.extension == "kt" && it.readText().contains("FirstIdentityCoordinator(") }.map { it.name }.toSet()
        assertEquals(setOf("FirstIdentityCoordinator.kt", "KpgpUpgrade.kt"), users)
        val module = File("src/main/java/network/conet/chat/BeamioConetChatModule.kt").readText()
        assertTrue(module.contains("if (!BuildConfig.IDENTITY_STATE_EVENTS_QA) return fail(\"not_available\")"))
        // The default build's flag is off.
        val gradle = File("build.gradle.kts").readText()
        assertFalse(gradle.contains("IDENTITY_STATE_EVENTS_QA\", \"true\""))
    }
}
