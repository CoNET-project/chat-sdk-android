package network.conet.chat.nativekey

import java.io.File
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 0.2.28 (S25 ANR, 2026-11-19): the legacy wallet adoption is off the main thread, and the answer of a command that arrives while it
 * is unsettled is not_ready (a retry), never no_key (onboarding). Runtime timing is verified on the device; these tests lock the
 * ordering and the gate behaviour that the runtime depends on (source guards, the same convention as BridgeCommandTableTest).
 */
class LegacyAdoptionAsyncTest {
    private val wallet: String by lazy {
        File("src/main/java/network/conet/chat/nativekey/AndroidNativeWallet.kt").readText(Charsets.UTF_8)
    }
    private val module: String by lazy {
        File("src/main/java/network/conet/chat/BeamioConetChatModule.kt").readText(Charsets.UTF_8)
    }

    private fun body(src: String, header: String, nextHeader: String): String =
        src.substringAfter(header).substringBefore(nextHeader)

    @Test
    fun anUnknownAdoptionResultLeavesTheGateUnsettled() {
        // Behaviour: while the adoption has no definitive result, isLegacyWalletAdoptionSettled is false, so walletStatus keeps
        // answering not_ready. The gate retries only after its delay, so the keystore is not hit on every command.
        var t = 1_000L
        val gate = MigrationGate(now = { t }, retryMillis = 30_000L)
        assertFalse(gate.run { MigrationGate.Outcome.UNKNOWN })
        assertFalse("unsettled after an unknown result", gate.isResolved())
        t += 29_999L
        var attempts = 0
        gate.run { attempts++; MigrationGate.Outcome.UNKNOWN }
        assertTrue("no retry inside the window", attempts == 0)
        t += 1L
        gate.run { attempts++; MigrationGate.Outcome.RESOLVED_ADOPTED }
        assertTrue("the retry after the delay runs", attempts == 1)
        assertTrue("then settled", gate.isResolved())
    }

    @Test
    fun migrateLegacyOnTheMainThreadReturnsBeforeAnyKeystoreWork() {
        // The main-thread branch returns false and schedules the adoption; the keystore work (legacyGate.run) comes after it.
        val fn = body(wallet, "fun migrateLegacy(context: Context): Boolean {", "/** True when the once-per-process")
        val onMain = fn.indexOf("if (isMainThread())")
        val scheduled = fn.indexOf("scheduleLegacyAdoptionOffMain(app)")
        val returned = fn.indexOf("return false", scheduled)
        val keystore = fn.indexOf("legacyGate.run")
        assertTrue("main-thread branch exists", onMain > 0)
        assertTrue("the main-thread branch schedules and returns false", scheduled in onMain until returned)
        assertTrue("keystore work is after the main-thread return", returned in 0 until keystore)
    }

    @Test
    fun theOffMainWorkerRunsOnTheExecutorAndClearsTheKickInAFinally() {
        val fn = body(wallet, "private fun scheduleLegacyAdoptionOffMain(app: Context) {", "private fun refreshVaultSnapshotAfterLegacy")
        assertTrue("claimed once with the kick flag", fn.contains("legacyAdoptionKick.compareAndSet(false, true)"))
        assertTrue("runs on the startup executor", fn.contains("startupExecutor.execute"))
        assertTrue("the in-flight flag is cleared in a finally", fn.contains("} finally {") && fn.contains("legacyAdoptionKick.set(false)"))
        assertTrue("the worker does not re-enter migrateLegacy", !fn.contains("migrateLegacy("))
    }

    @Test
    fun walletStatusAnswersNotReadyWhileTheAdoptionIsUnsettledOrInFlight() {
        // The walletStatus route answers before the generic NO_KEY branch, so the adoption check must sit inside the route itself:
        // G0 during adoption -> status not_ready (reason unreadable) with a snapshot refresh; no no_key; the check comes before walletStatusFor.
        val route = body(module, "NoKeyGate.Route.WALLET_STATUS -> {", "NoKeyGate.Route.PASSCODE_STATUS -> {")
        val check = route.indexOf("statusGate == NoKeyGate.Gate.G0")
        val unsettled = route.indexOf("!NativeWallet.isLegacyWalletAdoptionSettled()")
        val inFlight = route.indexOf("NativeWallet.isLegacyWalletAdoptionInFlight()")
        val answer = route.indexOf("NoKeyGate.walletStatusFor(statusGate, state")
        assertTrue("G0 is the condition", check > 0)
        assertTrue("unsettled or in-flight both count", unsettled > 0 && inFlight > 0)
        assertTrue("the check comes before the walletStatus answer", maxOf(unsettled, inFlight) < answer)
        val notReady = route.substringAfter("statusGate == NoKeyGate.Gate.G0").substringBefore("return")
        assertTrue("answers status not_ready", notReady.contains("put(\"status\", NoKeyGate.NOT_READY)"))
        assertTrue("with reason unreadable", notReady.contains("put(\"notReadyReason\", NoKeyGate.NOT_READY_UNREADABLE)"))
        assertFalse("never no_key on this path", notReady.contains("NO_KEY"))
    }

    @Test
    fun initAnswersNotReadyNotNoKeyWhileTheAdoptionIsUnsettledOrInFlight() {
        //  (b): migrateLegacy returns false at once on the main thread, and init then reads the vault. A NoKey snapshot
        // during adoption must answer not_ready (retry), and no_key only after the adoption has settled.
        val fn = body(module, "private fun adoptNativeWallet(", "/** True when the stored PGP material cannot be read")
        val noKey = fn.substringAfter("is NativeWalletVault.State.NoKey -> {").substringBefore("is NativeWalletVault.State.Locked")
        val check = noKey.indexOf("!NativeWallet.isLegacyWalletAdoptionSettled()")
        val inFlight = noKey.indexOf("NativeWallet.isLegacyWalletAdoptionInFlight()")
        val notReady = noKey.indexOf("NoKeyGate.NOT_READY")
        val noKeyAck = noKey.indexOf("error = \"no_key\"")
        assertTrue("the adoption check is in the NoKey branch", check > 0 && inFlight > 0)
        assertTrue("not_ready is answered under the check", check in 0 until notReady)
        assertTrue("no_key comes after the check", notReady in 0 until noKeyAck)
    }

    @Test
    fun notReadyDiagnosticsNameTheCauseWithoutSecrets() {
        // Diagnostics only (no wire change): the cause is a fixed code, never a key, phrase or path. Keystore unreadable (init snapshot
        // unknown) and adoption in progress are distinguished for diagnosis.
        assertTrue(module.contains("not_ready reason=adoption_in_progress cmd=init"))
        assertTrue(module.contains("not_ready reason=adoption_in_progress cmd=walletStatus"))
        assertTrue(module.contains("not_ready reason=keystore_unreadable cmd=init"))
    }

    @Test
    fun walletStatusAnswersNoKeyOnlyAfterTheAdoptionIsSettled() {
        // The settled path keeps the answer of the spec: G0 with a settled adoption is walletStatusFor(G0) = no_key.
        val route = body(module, "NoKeyGate.Route.WALLET_STATUS -> {", "NoKeyGate.Route.PASSCODE_STATUS -> {")
        val guard = route.substringBefore("val vaultForReason")
        assertTrue("the adoption guard is the only branch that changes the G0 answer", guard.contains("statusGate == NoKeyGate.Gate.G0"))
        assertTrue("the G0 status of the spec is still walletStatusFor", route.contains("NoKeyGate.walletStatusFor(statusGate, state"))
    }
}
