package network.conet.chat.nativekey

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.File
import java.util.concurrent.CountDownLatch
import java.util.concurrent.FutureTask
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

/**
 * The S25 cold start (25 StrongBox decrypts in 150 s, the page showing "wallet not ready"): every command paid a decrypt before it was
 * dispatched, the first pgpMigrate held the chat-command queue for 36.8 s, every inbound message paid two more, and init blocked the main thread for
 * 12.5 s. These tests count the decrypts (the test wrap counts `open`) and keep the answers the same.
 */
class ColdStartOpensTest {
    private val phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    private val key = checkNotNull(MnemonicDerivation.deriveKey(phrase))
    private val eoa = checkNotNull(WalletAddress.fromPrivateKey(key)).lowercase()
    /** The module's code, without its comment lines (a comment may name what the code no longer does). */
    private val module = File("src/main/java/network/conet/chat/BeamioConetChatModule.kt").readLines().filterNot { it.trim().startsWith("//") }.joinToString("\n")

    private class Fix {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        val vault = NativeWalletVault(wrap, files)
    }

    private fun phraseAccount(): Fix = Fix().also {
        assertEquals(NativeWalletVault.Import.OK, it.vault.importMnemonicKey(eoa, key, phrase))
    }

    private fun keyOnlyAccount(): Fix = Fix().also {
        assertEquals(NativeWalletVault.Import.OK, it.vault.importKey(eoa, key))
        it.files.map.remove(NativeWalletVault.MNEM)
        it.vault.invalidateSnapshot()
    }

    @Before
    fun reset() = VaultPerf.resetForTests()

    @After
    fun restore() {
        VaultPerf.sink = { label, start, code -> DiagTiming.log(label, start, code) }
    }

    private fun <T> within(ms: Long, block: () -> T): T {
        val task = FutureTask(block)
        Thread(task).also { it.isDaemon = true }.start()
        try {
            return task.get(ms, TimeUnit.MILLISECONDS)
        } catch (e: TimeoutException) {
            throw AssertionError("blocked for more than $ms ms")
        }
    }

    // ---- C1: only clearIdentity pays for the per-account key-only criterion --------------------------------------------------------------

    @Test
    fun theKeyOnlyCriterionIsComputedOnlyInsideTheClearIdentityBlock() {
        val calls = Regex("""keyWithoutPhraseFor\(""").findAll(module).count()
        assertEquals("one call in the module", 1, calls)
        val body = module.substringAfter("private fun handleCommandInner(").substringBefore("private fun dispatch(")
        val before = body.substringBefore("if (type == \"clearIdentity\") {")
        assertFalse("not before the clearIdentity block: every command would pay it", before.contains("keyWithoutPhraseFor("))
        assertFalse(before.contains("publishedCopyState("))
        val block = body.substringAfter("if (type == \"clearIdentity\") {").substringBefore("// X-21 is retired")
        assertTrue(block.contains("keyWithoutPhraseFor("))
        assertTrue("the criterion still decides clearPrecheck", block.contains("keyOnly = keyOnlyNow"))
    }

    @Test
    fun theKeyOnlyCriterionOpensThePhraseRecordAndHelloDoesNotNeedIt() {
        // What every command used to pay: one decrypt of the phrase record (phraseItemOf).
        val f = phraseAccount()
        f.vault.state()
        val store = MnemonicSetStore(NativeTestMnemonicDir.empty())
        f.wrap.opens = 0
        assertFalse(f.vault.keyWithoutPhraseFor(eoa, store))
        assertTrue("the criterion decrypts: ${f.wrap.opens}", f.wrap.opens >= 1)
        // What a command that only reads the snapshot pays: nothing.
        f.wrap.opens = 0
        repeat(20) {
            f.vault.snapshotState()
            f.vault.snapshotWithKeyOnly()
            f.vault.snapshotKeyOnly()
            f.vault.stateIfKnown()
        }
        assertEquals(0, f.wrap.opens)
    }

    // ---- C2: the gate read for pgpMigrate and pgpDecryptInbound ---------------------------------------------------------------------------

    @Test
    fun anUnknownSnapshotIsAnswerableAtOnceEvenWhileTheMonitorIsHeld() {
        val f = phraseAccount()
        f.vault.invalidateSnapshot()
        val held = CountDownLatch(1)
        val release = CountDownLatch(1)
        val holder = Thread { synchronized(f.vault) { held.countDown(); release.await(10, TimeUnit.SECONDS) } }.also { it.isDaemon = true; it.start() }
        assertTrue(held.await(5, TimeUnit.SECONDS))
        f.wrap.opens = 0
        val read = within(2_000) { VaultGateReader.read(f.vault, sessionReady = true) }
        assertNull("no snapshot: unknown, and it did not wait for the monitor", read.state)
        assertFalse(read.keyOnly)
        assertEquals(0, f.wrap.opens)
        release.countDown()
        holder.join(5_000)
    }

    @Test
    fun beforeInitTheGateReadOpensNothingWhateverTheState() {
        // init has not run: the session is not ready, keyOnly cannot change the gate, so it is not read (it was two decrypts).
        for (f in listOf(phraseAccount(), keyOnlyAccount(), Fix())) {
            f.vault.state()
            f.wrap.opens = 0
            val read = VaultGateReader.read(f.vault, sessionReady = false)
            assertNotNull(read.state)
            assertFalse(read.keyOnly)
            assertEquals(0, f.wrap.opens)
        }
    }

    @Test
    fun afterInitTheSnapshotsKeyOnlyFlagIsVouchedForByTheRecordsAndOpensNothing() {
        val ph = phraseAccount()
        ph.vault.state()
        ph.wrap.opens = 0
        val a = VaultGateReader.read(ph.vault, sessionReady = true)
        assertTrue(a.state is NativeWalletVault.State.Ready)
        assertFalse(a.keyOnly)
        assertEquals("a phrase account: no decrypt", 0, ph.wrap.opens)
        val ko = keyOnlyAccount()
        ko.vault.state()
        ko.wrap.opens = 0
        val b = VaultGateReader.read(ko.vault, sessionReady = true)
        assertTrue(b.state is NativeWalletVault.State.Ready)
        assertTrue("a key-only account stays key-only", b.keyOnly)
        assertEquals(0, ko.wrap.opens)
    }

    @Test
    fun theGateIsTheSameAsTheLiveReadWouldGiveForEveryStateAndSession() {
        val cases = listOf(phraseAccount(), keyOnlyAccount(), Fix())
        for (f in cases) {
            f.vault.state()
            for (sessionReady in listOf(false, true)) {
                val read = VaultGateReader.read(f.vault, sessionReady)
                val live = f.vault.state()
                val liveGate = NoKeyGate.gateOf(live, sessionReady, keyOnly = f.vault.keyOnlyLive())
                val gate = NoKeyGate.gateOf(read.state!!, sessionReady, keyOnly = read.keyOnly)
                assertEquals("state=${live::class.simpleName} session=$sessionReady", liveGate, gate)
            }
        }
    }

    @Test
    fun aKeyOnlyRewriteOutsideTheVaultIsNeverTakenForAnAccount() {
        // The snapshot says phrase account; the records change outside the vault (the phrase is removed, the marker rewritten for the key-only shape).
        val f = phraseAccount()
        f.vault.state()
        val rec = f.files.map[NativeWalletVault.REC]!!
        f.files.map.remove(NativeWalletVault.MNEM)
        f.files.map[NativeWalletVault.MARK] = NativeWalletVault.markerOf(rec, null)
        assertFalse("the plain snapshot flag is stale", f.vault.snapshotKeyOnly())
        assertNull("the signature no longer matches: not vouched for", f.vault.keyOnlyIfVerified())
        assertNull("and the snapshot is dropped", f.vault.snapshotState())
        // The gate read, on a snapshot that is stale in the same way: the flag is not trusted, the live read decides.
        val g = phraseAccount()
        g.vault.state()
        val rec2 = g.files.map[NativeWalletVault.REC]!!
        g.files.map.remove(NativeWalletVault.MNEM)
        g.files.map[NativeWalletVault.MARK] = NativeWalletVault.markerOf(rec2, null)
        val read = VaultGateReader.read(g.vault, sessionReady = true)
        assertTrue("the stale snapshot still said Ready", read.state is NativeWalletVault.State.Ready)
        assertTrue("key-only by the live read", read.keyOnly)
        assertEquals("key-only never reaches G2", NoKeyGate.Gate.G1, NoKeyGate.gateOf(read.state!!, true, keyOnly = read.keyOnly))
    }

    @Test
    fun aRecordedDiscardIsStillLockedWithASnapshotAndNeverMistakenForReady() {
        val f = phraseAccount()
        f.vault.state()
        assertTrue(f.vault.stateIfKnown() is NativeWalletVault.State.Ready)
        f.files.map[NativeWalletVault.DISCARD_INTENT] = "pending".toByteArray()
        val s = f.vault.stateIfKnown()
        assertTrue("a recorded discard is unknown, as state() says: $s", s is NativeWalletVault.State.Locked)
        assertEquals(NativeWalletVault.DISCARD_PENDING, (s as NativeWalletVault.State.Locked).reason)
        // an aborted discard is not pending
        f.files.map[NativeWalletVault.DISCARD_INTENT] = NativeWalletVault.INTENT_ABORTED.toByteArray()
        assertTrue(f.vault.stateIfKnown() is NativeWalletVault.State.Ready)
    }

    @Test
    fun theSignatureCoversEveryRecordThatDecidesTheState() {
        val f = phraseAccount()
        f.vault.state()
        val base = f.vault.recordSignature()
        assertNotNull(base)
        for (name in listOf(NativeWalletVault.REC, NativeWalletVault.MARK, NativeWalletVault.MNEM, NativeWalletVault.COMMIT, NativeWalletVault.INTENT)) {
            val old = f.files.map[name]
            f.files.map[name] = (old ?: ByteArray(0)) + byteArrayOf(1)
            assertTrue("$name changes the signature", f.vault.recordSignature() != base)
            if (old == null) f.files.map.remove(name) else f.files.map[name] = old
            assertEquals("restored: the same signature", base, f.vault.recordSignature())
        }
        f.files.failRead = { true }
        assertNull("a read failure is unknown", f.vault.recordSignature())
        assertNull(f.vault.keyOnlyIfVerified())
    }

    @Test
    fun theSignatureHoldsOnlyDigestsAndIsNotLoggedOrStored() {
        val f = phraseAccount()
        val sig = f.vault.recordSignature()!!
        assertTrue("digests and separators only: $sig", Regex("^([0-9a-f]{64}|-)(\\|([0-9a-f]{64}|-)){4}$").matches(sig))
        val src = File("src/main/java/network/conet/chat/nativekey/NativeWalletVault.kt").readText()
        val ctor = src.substringAfter("class Snap internal constructor(").substringBefore(")")
        assertTrue(ctor.contains("internal val signature: String?"))
        assertFalse("never written out", src.substringAfter("fun recordSignature()").substringBefore("fun keyOnlyIfVerified").contains("files.write"))
        assertFalse(src.substringAfter("fun recordSignature()").substringBefore("fun keyOnlyIfVerified").contains("Log."))
        assertFalse(src.substringAfter("fun recordSignature()").substringBefore("fun keyOnlyIfVerified").contains("DiagTiming"))
    }

    @Test
    fun pgpMigrateAndPgpDecryptInboundUseTheGateReaderAndNoLiveRead() {
        val migrate = module.substringAfter("private fun pgpMigrateCommand(").substringBefore("private fun ").take(2500)
        val gateStart = migrate.substringBefore("when (val ack = PgpMigrationBridge.ackFor(")
        assertTrue(gateStart.contains("VaultGateReader.read("))
        assertFalse("no monitor wait", gateStart.contains(".state()"))
        assertFalse("no live key-only read", gateStart.contains("keyOnlyLive()"))
        assertTrue("an unknown snapshot asks for a refresh and is G1", gateStart.contains("scheduleSnapshotRefresh(ctx)") && gateStart.contains("NoKeyGate.Gate.G1"))
        // The refusals keep their order: the key fields and the gate are still decided by ackFor, after the (now instant) read.
        assertTrue(migrate.indexOf("VaultGateReader.read(") < migrate.indexOf("PgpMigrationBridge.ackFor("))
        val inbound = module.substringAfter("private fun handlePgpDecryptInbound(").substringBefore("/** N0 `walletAddress`")
        val gate = inbound.substringAfter("val vault = NativeWallet.vault(ctx)").substringBefore("val eoa = (state as? NativeWalletVault.State.Ready)?.eoa")
        assertTrue(gate.contains("VaultGateReader.read(vault, sessionReady)"))
        assertFalse(gate.contains("vault.state()"))
        assertFalse(gate.contains("keyOnlyLive()"))
        assertTrue("an unknown snapshot is not_ready after asking for a refresh", gate.contains("scheduleSnapshotRefresh(ctx)") && gate.contains("refuse(\"not_ready\")"))
    }

    // ---- C4: init ------------------------------------------------------------------------------------------------------------------------

    @Test
    fun initUnlocksOnceAndTheKeyOnlyCheckOpensNothingMore() {
        val f = phraseAccount()
        f.vault.state()
        f.wrap.opens = 0
        val k = f.vault.unlock()
        assertNotNull(k)
        k!!.fill(0)
        val unlockOpens = f.wrap.opens
        assertTrue("unlock opens the record: $unlockOpens", unlockOpens >= 1)
        assertFalse(f.vault.keyOnlyChecked())
        assertEquals("the key-only check adds no decrypt", unlockOpens, f.wrap.opens)
        // The old check, for the record of what it cost.
        val before = f.wrap.opens
        assertFalse(f.vault.keyOnlyLive())
        assertTrue("the live check decrypts again: ${f.wrap.opens - before}", f.wrap.opens - before >= 2)
    }

    @Test
    fun initNeverMarksAKeyOnlyAccountReady() {
        val f = keyOnlyAccount()
        f.vault.state()
        assertTrue("key-only", f.vault.keyOnlyChecked())
        // and after an outside rewrite to key-only the check is still key-only (the signature differs, the live read decides)
        val g = phraseAccount()
        g.vault.state()
        val rec = g.files.map[NativeWalletVault.REC]!!
        g.files.map.remove(NativeWalletVault.MNEM)
        g.files.map[NativeWalletVault.MARK] = NativeWalletVault.markerOf(rec, null)
        assertTrue(g.vault.keyOnlyChecked())
    }

    @Test
    fun theReadyBranchOfInitRunsOffTheMainThreadAndAnswersInEveryCase() {
        val branch = module.substringAfter("private fun adoptNativeWallet(").substringBefore("is NativeWalletVault.State.NoKey ->")
        val ready = branch.substringAfter("is NativeWalletVault.State.Ready -> {")
        assertTrue("the address check stays on the calling thread", ready.indexOf("address_mismatch") in 0 until ready.indexOf("initWorker.execute"))
        val worker = ready.substringAfter("initWorker.execute {")
        assertTrue("the Keystore part is InitUnlock", worker.contains("network.conet.chat.nativekey.InitUnlock.run("))
        assertTrue(worker.contains("markReady = { NativeSessionState.markReady(st.eoa) }"))
        assertFalse("not the live compute", worker.contains("isKeyOnlyAccount()") || worker.contains("keyOnlyLive()"))
        assertFalse("no unlock outside InitUnlock", worker.contains("vault.unlock()"))
        assertTrue("an Exception is the retryable answer", worker.contains("catch (_: Exception) {"))
        assertTrue(worker.substringAfter("catch (_: Exception) {").contains("InitUnlock.Outcome.UNREADABLE"))
        assertFalse("an Error is not swallowed into an answer", worker.contains("catch (_: Throwable)") || worker.contains("catch (e: Throwable)"))
        val unreadable = worker.substringAfter("InitUnlock.Outcome.UNREADABLE ->").substringBefore("else ->")
        assertTrue("unreadable is not_ready, never no_key", unreadable.contains("notReadyAck(reqId, NoKeyGate.NOT_READY_UNREADABLE)") && !unreadable.contains("no_key"))
        assertTrue("the rest of init goes back to the main thread", worker.contains("else -> main.post { done() }"))
        assertFalse("no unlock outside the worker in the Ready branch", ready.substringBefore("initWorker.execute").contains("vault.unlock()"))
        assertTrue(module.contains("Thread(r, \"conet-chat-init\")"))
        assertTrue("one thread: two inits stay in order", module.substringAfter("private val initWorker").substringBefore("}").contains("newSingleThreadExecutor"))
    }

    // ---- InitUnlock: every case answers, and none answers no_key --------------------------------------------------------------------------

    private open class SignerProbe {
        var set: ByteArray? = null
        var setCopy: ByteArray? = null
        var cleared = 0
        var ready = 0
        var setThrows = false
        var readyThrows = false
        var clearThrows = false
    }

    private fun runUnlock(vault: NativeWalletVault, p: SignerProbe) = InitUnlock.run(
        vault,
        setSigner = { k -> if (p.setThrows) throw IllegalStateException("signer"); p.set = k; p.setCopy = k.copyOf() },
        clearSigner = { p.cleared++; if (p.clearThrows) throw IllegalStateException("clear") },
        markReady = { if (p.readyThrows) throw IllegalStateException("ready"); p.ready++ },
    )

    @Test
    fun anAccountThatUnlocksIsReadyAndTheKeyIsZeroed() {
        val f = phraseAccount()
        f.vault.state()
        val p = SignerProbe()
        assertEquals(InitUnlock.Outcome.SESSION_READY, runUnlock(f.vault, p))
        assertEquals(1, p.ready)
        assertEquals(0, p.cleared)
        assertTrue("the signer got the account's key", p.setCopy!!.contentEquals(key))
        assertTrue("the buffer was zeroed after the hand-over", p.set!!.all { it == 0.toByte() })
    }

    @Test
    fun aKeyOnlyAccountKeepsItsSignerButIsNotMarkedReady() {
        val f = keyOnlyAccount()
        f.vault.state()
        val p = SignerProbe()
        assertEquals(InitUnlock.Outcome.KEY_ONLY, runUnlock(f.vault, p))
        assertEquals("not an account: never ready", 0, p.ready)
        assertNotNull(p.setCopy)
        assertEquals(0, p.cleared)
    }

    @Test
    fun aKeyThatCannotBeUnlockedIsUnreadableAndTheSignerIsCleared() {
        val f = Fix() // no record: unlock gives nothing
        val p = SignerProbe()
        assertEquals(InitUnlock.Outcome.UNREADABLE, runUnlock(f.vault, p))
        assertEquals(1, p.cleared)
        assertEquals(0, p.ready)
        assertNull(p.setCopy)
    }

    @Test
    fun aFaultAnywhereInTheUnlockIsAnAnswerAndNeverAMissingKey() {
        // the keystore throws while the record is opened
        val a = phraseAccount()
        a.vault.state()
        a.wrap.openOverride = { throw java.io.IOException("keystore unavailable") }
        val pa = SignerProbe()
        assertEquals(InitUnlock.Outcome.UNREADABLE, runUnlock(a.vault, pa))
        assertEquals(0, pa.ready)
        // the signer hand-over throws: the key is zeroed, the signer is cleared, the session is not ready
        val b = phraseAccount()
        b.vault.state()
        val pb = SignerProbe().also { it.setThrows = true }
        assertEquals(InitUnlock.Outcome.UNREADABLE, runUnlock(b.vault, pb))
        assertEquals(1, pb.cleared)
        assertEquals(0, pb.ready)
        // markReady throws after the signer was set: the signer must not stay for a session that is not ready
        val c = phraseAccount()
        c.vault.state()
        val pc = SignerProbe().also { it.readyThrows = true }
        assertEquals(InitUnlock.Outcome.UNREADABLE, runUnlock(c.vault, pc))
        assertEquals("the signer set before the fault is cleared", 1, pc.cleared)
        assertTrue("and its buffer was zeroed", pc.set!!.all { it == 0.toByte() })
        // a clear that throws inside the handler still ends in an answer
        val d = phraseAccount()
        d.vault.state()
        val pd = SignerProbe().also { it.setThrows = true; it.clearThrows = true }
        assertEquals(InitUnlock.Outcome.UNREADABLE, runUnlock(d.vault, pd))
    }

    @Test
    fun anErrorGetsTheSameCleanupAndIsRethrownNotSwallowed() {
        fun <T> expectError(block: () -> T): Error {
            try {
                block()
            } catch (e: Error) {
                return e
            }
            throw AssertionError("the Error was swallowed")
        }
        // the signer hand-over fails with an OutOfMemoryError
        val a = phraseAccount()
        a.vault.state()
        val pa = object : SignerProbe() {}
        val oom = OutOfMemoryError("simulated")
        val ea = expectError {
            InitUnlock.run(a.vault, setSigner = { throw oom }, clearSigner = { pa.cleared++ }, markReady = { pa.ready++ })
        }
        assertTrue("the same Error comes out", ea === oom)
        assertEquals("the signer is cleared", 1, pa.cleared)
        assertEquals("the session is not marked ready", 0, pa.ready)
        // markReady fails with an Error after the signer was set: signer cleared, key zeroed
        val b = phraseAccount()
        b.vault.state()
        val pb = SignerProbe()
        val so = StackOverflowError()
        val eb = expectError {
            InitUnlock.run(
                b.vault,
                setSigner = { k -> pb.set = k; pb.setCopy = k.copyOf() },
                clearSigner = { pb.cleared++ },
                markReady = { throw so },
            )
        }
        assertTrue(eb === so)
        assertEquals(1, pb.cleared)
        assertTrue("the key buffer was zeroed", pb.set!!.all { it == 0.toByte() })
        // the Keystore throws an Error while the record is opened
        val c = phraseAccount()
        c.vault.state()
        c.wrap.openOverride = { throw OutOfMemoryError("keystore") }
        val pc = SignerProbe()
        val ec = expectError { runUnlock(c.vault, pc) }
        assertTrue(ec is OutOfMemoryError)
        assertEquals("no signer was set, and the clearing still ran", 1, pc.cleared)
        assertEquals(0, pc.ready)
        assertNull(pc.setCopy)
        // an Error inside the cleanup does not replace the Error being handled
        val d = phraseAccount()
        d.vault.state()
        val first = OutOfMemoryError("first")
        val ed = expectError {
            InitUnlock.run(d.vault, setSigner = { throw first }, clearSigner = { throw OutOfMemoryError("second") }, markReady = { })
        }
        assertTrue("the original Error is the one rethrown", ed === first)
    }

    @Test
    fun anErrorIsRethrownByTheSourceAndTheModuleDoesNotCatchIt() {
        val src = File("src/main/java/network/conet/chat/nativekey/InitUnlock.kt").readText().lines().filterNot { it.trim().startsWith("*") || it.trim().startsWith("//") || it.trim().startsWith("/**") }.joinToString("\n")
        val errorCatch = src.substringAfter("catch (e: Throwable) {").substringBefore("} finally")
        assertTrue(errorCatch.contains("cleanup(clearSigner)") && errorCatch.contains("throw e"))
        assertTrue("the key is zeroed in a finally that every path passes", src.contains("} finally {\n            key?.fill(0)"))
    }

    @Test
    fun theUnlockPartHoldsNoSecretAndLogsNothing() {
        val src = File("src/main/java/network/conet/chat/nativekey/InitUnlock.kt").readText().lines().filterNot { it.trim().startsWith("*") || it.trim().startsWith("//") || it.trim().startsWith("/**") }.joinToString("\n")
        assertFalse(src.contains("Log.") || src.contains("DiagTiming") || src.contains("println"))
        assertFalse(src.contains("String("))
    }

    // ---- the cleanup write path invalidates the snapshot ---------------------------------------------------------------------------------

    @Test
    fun removingAnOldAccountsWalletFilesDropsTheVaultSnapshot() {
        val dir = createTempDir("vault-cleanup-")
        try {
            val owner = "0x" + "cd".repeat(20)
            val name = NativeWalletVault.MNEM
            File(dir, name).writeBytes(byteArrayOf(1, 2, 3))
            val f = phraseAccount()
            f.vault.state()
            assertNotNull(f.vault.snapshotState())
            var removedCalls = 0
            val adapter = WalletVaultCleanup(
                dir, f.vault, { "0x" + "ab".repeat(20) },
                onRemoved = { removedCalls++; f.vault.invalidateSnapshot() },
            ) { _, _ -> OwnerRead.Known("$owner:default") }
            val item = AccountCleanupOld.Item(name = "file:wallet:$name", accountKey = "$owner:default")
            assertTrue(adapter.remove(item))
            assertFalse("the file is gone", File(dir, name).exists())
            assertEquals(1, removedCalls)
            assertNull("the snapshot did not outlive the files it was computed from", f.vault.snapshotState())
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun aRefusedRemovalTouchesNothingAndStillDropsOnlyWhenItAttemptedOne() {
        val dir = createTempDir("vault-cleanup-")
        try {
            val owner = "0x" + "cd".repeat(20)
            File(dir, NativeWalletVault.MNEM).writeBytes(byteArrayOf(1))
            var calls = 0
            // The old account is the active one: the wallet group is kept, nothing attempted.
            val adapter = WalletVaultCleanup(dir, Any(), { owner }, onRemoved = { calls++ }) { _, _ -> OwnerRead.Known("$owner:default") }
            assertFalse(adapter.remove(AccountCleanupOld.Item(name = "file:wallet:${NativeWalletVault.MNEM}", accountKey = "$owner:default")))
            assertTrue(File(dir, NativeWalletVault.MNEM).exists())
            assertEquals("no attempt, no drop", 0, calls)
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun theProductionWiringPassesTheVaultsInvalidation() {
        val src = File("src/main/java/network/conet/chat/nativekey/AccountCleanupWiring.kt").readText()
        assertTrue(src.contains("onRemoved = { (vaultMonitor as? NativeWalletVault)?.invalidateSnapshot() }"))
        val stores = File("src/main/java/network/conet/chat/nativekey/AccountCleanupStores.kt").readText()
        val remove = stores.substringAfter("class WalletVaultCleanup(").substringAfter("override fun remove(").substringBefore("private companion object")
        assertTrue("the invalidation runs in a finally, inside the monitor", remove.contains("finally {\n                onRemoved()"))
        assertTrue(remove.indexOf("synchronized(vaultMonitor)") < remove.indexOf("onRemoved()"))
    }
}

/** An empty mnemonic-set directory for a store that holds nothing. */
internal object NativeTestMnemonicDir {
    fun empty(): File = createTempDir("mnem-set-").also { it.deleteOnExit() }
}
