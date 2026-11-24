package network.conet.chat.nativekey

import network.conet.chat.BeamioChatPgpStore
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.SecureRandom

/**
 * The passcode lock before a key is written. Where a chain read or the gate
 * takes time, the account's lock is asked again right before the write: a lock since then writes and submits nothing.
 */
class PasscodeLockChecksTest {
    private val random = SecureRandom()
    private val account = "0x" + "ab".repeat(20)
    private val own = RecKeys.generate(account, random)
    private val accountKey = ByteArray(32) { (it + 1).toByte() }
    private val canonical = NativePgpBackup.passwordString(accountKey)
    private val forms: () -> List<String>? = { NativePgpBackup.passwordForms(accountKey) }

    private class Env {
        val log = ArrayList<String>()
        val base = NativeTestFiles()
        val files = CountingFiles(base, log)
        val kBackend = CountingKBackend(log)
        val k = AccountPgpK(kBackend)
        val wrap = NativeTestWrap()
    }

    private fun backupOf(pgp: RecPgp): String =
        NativePgpBackup.encryptArmor(canonical, pgp.privateArmor.toByteArray(Charsets.UTF_8), ByteArray(12).also { random.nextBytes(it) })

    // ---- the automatic recovery ----------------------------------------------------------------------------------------------------------

    @Test
    fun theAutomaticRecoveryWritesNothingWhenTheAccountIsLockedAfterTheGate() {
        for ((state, code) in listOf(LockState.LOCKED to "passcode_not_provided", LockState.UNKNOWN to "not_ready")) {
            val e = Env()
            val out = AutoRecovery.recover(
                account, NativePgpVault(e.wrap, e.files, account), e.k, RecChain(registered = registeredOf(own, account), backup = backupOf(own)),
                null, forms, 1L, random, null, lock = { state },
            )
            assertEquals(code, out.logCode)
            assertEquals("pgp_migration_retry", out.expect.action)
            assertTrue("zero writes: ${e.log}", e.files.untouched)
            assertEquals(0, e.kBackend.puts)
        }
    }

    @Test
    fun theAutomaticRecoveryStillWritesWhenTheAccountIsUnlocked() {
        val e = Env()
        val out = AutoRecovery.recover(
            account, NativePgpVault(e.wrap, e.files, account), e.k, RecChain(registered = registeredOf(own, account), backup = backupOf(own)),
            null, forms, 1L, random, null, lock = { LockState.UNLOCKED },
        )
        assertEquals("upgraded_from_chain", out.expect.action)
        assertTrue(e.files.writes > 0)
    }

    @Test
    fun theMirrorOfAVaultKeyIntoKWritesNothingWhenLocked() {
        val e = Env()
        val vault = NativePgpVault(e.wrap, e.files, account)
        assertEquals(NativePgpVault.Put.OK, vault.put(account, own.privateArmor, ""))
        val vaultWrites = e.files.writes
        val out = AutoRecovery.mirrorVault(
            account, KpgpUpgrade.LRecord(own.privateArmor, own.identity.subkeyKeyId), e.k, RecChain(registered = registeredOf(own, account), backup = ""),
            1L, random, null, lock = { LockState.LOCKED },
        )
        assertEquals("passcode_not_provided", out.logCode)
        assertEquals("no K write", 0, e.kBackend.puts)
        assertEquals("no vault write either", vaultWrites, e.files.writes)
    }

    // ---- the page restore -----------------------------------------------------------------------------------------------------------------

    private class PageEnv {
        val log = ArrayList<String>()
        val base = NativeTestFiles()
        val files = CountingFiles(base, log)
        val wrap = NativeTestWrap()
    }

    /** A wallet that is ready for the first [readyFor] questions and locked after. [writesAtLock] records the vault writes at the first refusal. */
    private inner class FlippingWallet(val readyFor: Int, val env: PageEnv) : PgpRestoreWallet {
        var asked = 0
        var writesAtLock: Int? = null
        override fun ready(): Boolean {
            asked++
            val ok = asked <= readyFor
            if (!ok && writesAtLock == null) writesAtLock = env.files.writes
            return ok
        }
        override fun passwordString(): String? = canonical
        override fun passwordForms(): List<String>? = NativePgpBackup.passwordForms(accountKey)
    }

    private fun restoreMachine(env: PageEnv, wallet: PgpRestoreWallet) = PgpRestoreMachine(
        chain = RecChain(registered = registeredOf(own, account, source = RegisteredPgpKey.Source.SINGLE), backup = backupOf(own)),
        wallet = wallet,
        keys = object : PgpRestoreKeys { override fun newKey(deviceId: String): PgpNewKey = error("the restore never generates a key") },
        ivFor = { error("the restore never writes a backup") },
        devices = mapOf(PgpRestoreBridge.DEVICE to PgpRestoreDevice(PgpRestoreBridge.DEVICE, account, env.wrap, env.files)),
        recoveryGate = PageRecoveryGate(),
    )

    @Test
    fun aPageRestoreWritesNothingAfterTheLockWhereverTheLockComes() {
        // Unlocked all the way: the baseline writes the key and asks more than once (the start of the evaluation and right before the write).
        val baseEnv = PageEnv()
        val baseWallet = FlippingWallet(Int.MAX_VALUE, baseEnv)
        assertEquals("ok", PgpRestoreBridge.restore(restoreMachine(baseEnv, baseWallet)).getString("code"))
        assertTrue("the lock is asked again before the write (asked ${baseWallet.asked})", baseWallet.asked >= 2)
        var stopped = 0
        for (n in 0 until baseWallet.asked) {
            val env = PageEnv()
            val wallet = FlippingWallet(n, env)
            val m = restoreMachine(env, wallet)
            val result = PgpRestoreBridge.restore(m)
            assertEquals("n=$n: one cancelled, no data", "cancelled", result.getString("code"))
            assertEquals("n=$n: no other field in the cancelled result", setOf("code"), result.keys().asSequence().toSet())
            val active = m.devices.getValue(PgpRestoreBridge.DEVICE).active
            assertTrue("n=$n: a lock was seen", wallet.writesAtLock != null)
            assertEquals("n=$n: no vault write after the lock", wallet.writesAtLock, env.files.writes)
            assertTrue("n=$n: no key was activated", active.state() is NativePgpVault.State.NoKey)
            stopped++
        }
        assertEquals(baseWallet.asked, stopped)
    }

    @Test
    fun theWriteSitesOfTheRestoreMachineAskTheLockJustBeforeTheyWrite() {
        val src = File("src/main/java/network/conet/chat/nativekey/PgpRestoreMachine.kt").readText()
        // restore write, activation, keygen (before generating and before the pending write), and the old-backup write
        assertTrue(src.indexOf("if (!wallet.ready()) {\n                dev.ui = PgpRestoreUi(\"blocked\", code = \"wallet_not_ready\")\n                return \"blocked\"\n            }\n            val putResult") > 0)
        assertTrue(src.contains("if (!wallet.ready()) return false\n        if (dev.active.put("))
        assertTrue(src.contains("if (!wallet.ready()) return rejected(\"wallet_not_ready\")\n        counters.keygen++"))
        assertTrue(src.contains("if (!wallet.ready()) return\n            if (dev.old.put("))
    }

    // ---- production wiring ------------------------------------------------------------------------------------------------------------------

    @Test
    fun theProductionRunsAskTheRealLockAtEveryPoint() {
        val up = File("src/main/java/network/conet/chat/nativekey/KpgpUpgrade.kt").readText()
        assertTrue(up.contains("lockState = { lockStateOf(app, eoa, storeAccount) }"))
        assertEquals("both automatic recoveries take the lock", 2, Regex("""lock = \{ lockStateOf\(app, eoa, storeAccount\) \}""").findAll(up).count())
        // A v3 store set that is not unlocked is locked (passcode_not_provided); anything unreadable is unknown (never unlocked).
        assertTrue(up.contains("if (resolution.reason == NoKeyGate.NOT_READY_PASSCODE_REQUIRED) LockState.LOCKED else LockState.UNKNOWN"))
        assertTrue(up.contains("} catch (_: Exception) {\n        LockState.UNKNOWN"))
        // The lock is asked at several points on the module thread: it reads the snapshot, never the vault's monitor (S25 contention).
        val lockFn = up.substringAfter("internal fun lockStateOf(").substringBefore("/** The registration endpoint bases")
        assertTrue(lockFn.contains("lockStateOfVault(NativeWallet.vault(app).snapshotState(), eoa)"))
        assertFalse(lockFn.contains("vault(app).state()"))
    }

    // ---- what counts as "the material is not available" -----------------------------------------------------------------------------------

    @Test
    fun onlyAMissingPasscodePackageIsLockedAndAnythingUnreadableIsUnknown() {
        val eoa = account
        // A vault account: Ready for this account is unlocked; every other state is a storage state, unknown (never LOCKED, never a passcode reason).
        assertEquals(LockState.UNLOCKED, KpgpUpgrade.lockStateOfVault(NativeWalletVault.State.Ready(eoa), eoa))
        assertEquals(LockState.UNLOCKED, KpgpUpgrade.lockStateOfVault(NativeWalletVault.State.Ready(eoa.uppercase().replace("0X", "0x")), eoa))
        assertEquals(LockState.UNKNOWN, KpgpUpgrade.lockStateOfVault(NativeWalletVault.State.Ready("0x" + "cd".repeat(20)), eoa))
        for (reason in listOf("marker_missing", "marker_mismatch", "unreadable", "record_missing", NativeWalletVault.DISCARD_PENDING, "rollback_pending", NativeWalletVault.PHRASE_ONLY)) {
            assertEquals("Locked($reason) is a storage state", LockState.UNKNOWN, KpgpUpgrade.lockStateOfVault(NativeWalletVault.State.Locked(reason), eoa))
        }
        // The vault Locked for the passcode package is the one locked vault state (the vault's own PASSCODE_REQUIRED, "passcode_not_provided").
        assertEquals(LockState.LOCKED, KpgpUpgrade.lockStateOfVault(NativeWalletVault.State.Locked(NativeWalletVault.PASSCODE_REQUIRED), eoa))
        assertEquals(LockState.UNKNOWN, KpgpUpgrade.lockStateOfVault(NativeWalletVault.State.NoKey, eoa))
        assertEquals("no snapshot yet", LockState.UNKNOWN, KpgpUpgrade.lockStateOfVault(null, eoa))
        // A store account: resolved for this session is unlocked; the passcode package missing is the only locked; anything else is unknown.
        val resolved = StoreAwareAccount.Resolution.Account(eoa, StoreAwareAccount.Source.STORE_PLAIN)
        assertEquals(LockState.UNLOCKED, KpgpUpgrade.lockStateOfStore(resolved, eoa))
        assertEquals(LockState.UNKNOWN, KpgpUpgrade.lockStateOfStore(StoreAwareAccount.Resolution.Account("0x" + "cd".repeat(20), StoreAwareAccount.Source.STORE_PLAIN), eoa))
        assertEquals(LockState.LOCKED, KpgpUpgrade.lockStateOfStore(StoreAwareAccount.Resolution.NotReady(NoKeyGate.NOT_READY_PASSCODE_REQUIRED), eoa))
        assertEquals(LockState.UNKNOWN, KpgpUpgrade.lockStateOfStore(StoreAwareAccount.Resolution.NotReady("unreadable"), eoa))
        assertEquals(LockState.UNKNOWN, KpgpUpgrade.lockStateOfStore(StoreAwareAccount.Resolution.NoKey, eoa))
    }

    @Test
    fun noUiOrAppLockStateIsReadAnywhereInTheLockDecision() {
        val up = File("src/main/java/network/conet/chat/nativekey/KpgpUpgrade.kt").readText()
        val region = up.substringAfter("internal fun lockStateOf(").substringBefore("/** The registration endpoint bases")
        for (forbidden in listOf("uiLock", "UiLock", "NativeSessionState", "isReady(", "isReadyFor", "SessionKeyHolder", "passcodeUnlock", "appLock", "AppLock")) {
            assertFalse("the lock decision does not read $forbidden", region.contains(forbidden))
        }
        val coordinator = File("src/main/java/network/conet/chat/nativekey/FirstIdentityCoordinator.kt").readText()
        for (forbidden in listOf("uiLock", "UiLock", "NativeSessionState", "passcodeUnlock", "appLock", "AppLock")) {
            assertFalse("the coordinator does not read $forbidden", coordinator.contains(forbidden))
        }
    }
}
