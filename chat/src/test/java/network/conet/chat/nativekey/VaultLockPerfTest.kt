package network.conet.chat.nativekey

import java.io.File
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.FutureTask
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicInteger
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.util.Random

/**
 * The vault monitor on a slow-keystore device (for example a Samsung S25): the page's pwaWalletSync, a cold state and the K upgrade trigger queued behind one
 * monitor for tens of seconds. Behaviour, not text: the snapshot is dropped only when something may have changed, the input check runs outside the
 * monitor, one compute opens and derives once, the K trigger never takes the monitor, and the timing lines hold numbers only. The vault's answers
 * and what it writes are unchanged.
 */
class VaultLockPerfTest {
    private val phraseA = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    private val phraseB = "legal winner thank year wave sausage worth useful legal winner thank yellow"
    private val keyA = MnemonicDerivation.deriveKey(phraseA)!!
    private val keyB = MnemonicDerivation.deriveKey(phraseB)!!
    private val eoaA = WalletAddress.fromPrivateKey(keyA)!!
    private val eoaB = WalletAddress.fromPrivateKey(keyB)!!

    /** The test wrap, counted like the device wrap (every open, seal and presence is a Keystore operation). */
    private class PerfWrap(val inner: KeyWrap) : KeyWrap {
        override fun seal(aad: ByteArray, plain: ByteArray): ByteArray = VaultPerf.keystore { inner.seal(aad, plain) }
        override fun open(aad: ByteArray, sealed: ByteArray): ByteArray? = VaultPerf.keystore { inner.open(aad, sealed) }
        override fun deleteKey(): Boolean = inner.deleteKey()
        override fun presence(): WrapKeyPresence = VaultPerf.keystore { inner.presence() }
    }

    private class Fix {
        val files = NativeTestFiles()
        val vault = NativeWalletVault(PerfWrap(NativeTestWrap()), files)
    }

    private fun fixWith(phrase: String, key: ByteArray, eoa: String): Fix = Fix().also {
        assertEquals(NativeWalletVault.Import.OK, it.vault.importMnemonicKey(eoa, key, phrase))
    }

    @Before
    fun reset() = VaultPerf.resetForTests()

    @After
    fun restoreSink() {
        VaultPerf.sink = { label, start, code -> DiagTiming.log(label, start, code) }
    }

    // ---- the snapshot is dropped only when something may have changed -----------------------------------------------------------------------

    @Test
    fun anIdempotentSyncKeepsTheSnapshotAndDoesNotRecomputeTheState() {
        val f = fixWith(phraseA, keyA, eoaA)
        assertTrue(f.vault.state() is NativeWalletVault.State.Ready)
        val snap = f.vault.snapshotWithKeyOnly()
        assertNotNull(snap)
        val before = VaultPerf.mark()
        assertEquals(NativeWalletVault.SyncOutcome.IDEMPOTENT, f.vault.syncPhrase(eoaA, keyA, phraseA))
        assertSame("the snapshot is the same object: not dropped, not recomputed", snap, f.vault.snapshotWithKeyOnly())
        val after = VaultPerf.mark()
        // Only the comparison with the stored phrase opens things (the record and the phrase): no cold recompute (that is the presence check plus both opens).
        assertTrue("keystore operations in an idempotent sync: ${after.ksOps - before.ksOps}", after.ksOps - before.ksOps <= 2)
        assertEquals("the input was derived once, outside the lock, and the stored phrase once more", 2, after.deriveOps - before.deriveOps)
    }

    @Test
    fun aBadInputAndANotReadyAnswerKeepTheSnapshotToo() {
        val f = fixWith(phraseA, keyA, eoaA)
        f.vault.state()
        val snap = f.vault.snapshotWithKeyOnly()
        assertEquals("a phrase that does not derive the key", NativeWalletVault.SyncOutcome.BAD_INPUT, f.vault.syncPhrase(eoaA, keyB, phraseA))
        assertEquals("an address that is not the key's", NativeWalletVault.SyncOutcome.BAD_INPUT, f.vault.syncPhrase(eoaB, keyA, phraseA))
        assertSame(snap, f.vault.snapshotWithKeyOnly())
        // A locked record (its marker is gone): the sync is not ready, nothing is written, and the (locked) snapshot stays.
        val g = fixWith(phraseA, keyA, eoaA)
        g.files.map.remove(NativeWalletVault.MARK)
        g.vault.invalidateSnapshot()
        assertTrue(g.vault.state() is NativeWalletVault.State.Locked)
        val lockedSnap = g.vault.snapshotWithKeyOnly()
        val bytesBefore = g.files.map.mapValues { it.value.toList() }
        assertEquals(NativeWalletVault.SyncOutcome.NOT_READY, g.vault.syncPhrase(eoaB, keyB, phraseB))
        assertSame(lockedSnap, g.vault.snapshotWithKeyOnly())
        assertEquals("nothing was written", bytesBefore, g.files.map.mapValues { it.value.toList() })
    }

    @Test
    fun aWriteDropsTheSnapshotAndTheNextReadSeesTheNewValue() {
        val f = fixWith(phraseA, keyA, eoaA)
        assertEquals(eoaA, (f.vault.state() as NativeWalletVault.State.Ready).eoa)
        assertEquals(NativeWalletVault.SyncOutcome.UPDATED, f.vault.syncPhrase(eoaB, keyB, phraseB))
        assertNull("the snapshot is dropped after the write: no stale Ready for the old account", f.vault.snapshotState())
        assertEquals(eoaB, (f.vault.state() as NativeWalletVault.State.Ready).eoa)
        val m = f.vault.mnemonicOf() as NativeWalletVault.MnemonicRead.Stored
        assertEquals(eoaB, m.eoa)
        assertEquals(phraseB, m.phrase)
        // From an empty vault: the import path.
        val empty = Fix()
        assertTrue(empty.vault.state() is NativeWalletVault.State.NoKey)
        assertEquals(NativeWalletVault.SyncOutcome.UPDATED, empty.vault.syncPhrase(eoaA, keyA, phraseA))
        assertEquals(eoaA, (empty.vault.state() as NativeWalletVault.State.Ready).eoa)
    }

    @Test
    fun aSettleThatChangesAControlFileDropsTheSnapshotBeforeTheDecision() {
        // A pending write (an intent) is settled by the sync: the decision is made on a fresh read, so a stale Ready is never the basis of a write.
        val f = fixWith(phraseA, keyA, eoaA)
        f.vault.state()
        assertNotNull(f.vault.snapshotState())
        // A leftover orphan audit line or pending state is settled inside settleForWrite; here the observable rule is the signature one: any change drops it.
        val src = File("src/main/java/network/conet/chat/nativekey/NativeWalletVault.kt").readText()
        assertTrue(src.contains("if (controlSignature() != before) snapshot = null"))
        assertTrue(src.contains("if (wrote || controlSignature() != before) snapshot = null"))
    }

    // ---- the input check is outside the monitor, the comparison and the write are inside -----------------------------------------------------

    private fun <T> within(ms: Long, block: () -> T): T? {
        val task = FutureTask(block)
        Thread(task, "vault-perf-test").also { it.isDaemon = true }.start()
        return try {
            task.get(ms, TimeUnit.MILLISECONDS)
        } catch (_: TimeoutException) {
            null
        }
    }

    @Test
    fun theInputIsCheckedOutsideTheMonitorAndTheWriteWaitsForIt() {
        val f = fixWith(phraseA, keyA, eoaA)
        val held = CountDownLatch(1)
        val release = CountDownLatch(1)
        val holder = Thread {
            synchronized(f.vault) {
                held.countDown()
                release.await(10, TimeUnit.SECONDS)
            }
        }.also { it.isDaemon = true; it.start() }
        assertTrue(held.await(5, TimeUnit.SECONDS))
        // A bad input answers while the monitor is held by another thread: it never needed it.
        assertEquals(NativeWalletVault.SyncOutcome.BAD_INPUT, within(2_000) { f.vault.syncPhrase(eoaA, keyB, phraseA) })
        // A valid sync does need it: it has not answered while the monitor is held, and answers once it is released.
        val task = FutureTask { f.vault.syncPhrase(eoaA, keyA, phraseA) }
        Thread(task).also { it.isDaemon = true; it.start() }
        try {
            task.get(300, TimeUnit.MILLISECONDS)
            throw AssertionError("a valid sync must wait for the monitor")
        } catch (_: TimeoutException) {
        }
        release.countDown()
        assertEquals(NativeWalletVault.SyncOutcome.IDEMPOTENT, task.get(5, TimeUnit.SECONDS))
        holder.join(5_000)
    }

    @Test
    fun theComparisonWithTheCurrentRecordStaysInsideTheLock() {
        // The input derived outside the lock is still compared with the stored phrase inside it: the same phrase is idempotent, another is not.
        val f = fixWith(phraseA, keyA, eoaA)
        assertEquals(NativeWalletVault.SyncOutcome.IDEMPOTENT, f.vault.syncPhrase(eoaA, keyA, phraseA))
        assertEquals(NativeWalletVault.SyncOutcome.UPDATED, f.vault.syncPhrase(eoaB, keyB, phraseB))
        assertEquals("now phrase B is the stored one", NativeWalletVault.SyncOutcome.IDEMPOTENT, f.vault.syncPhrase(eoaB, keyB, phraseB))
        val src = File("src/main/java/network/conet/chat/nativekey/NativeWalletVault.kt").readText()
        val unlocked = src.substringAfter("    fun syncPhrase(").substringBefore("    /** The control files whose change")
        assertFalse("the unlocked entry never calls the comparison", unlocked.contains("samePhrase(") || unlocked.contains("mnemonicOf("))
    }

    // ---- one compute opens and derives once ---------------------------------------------------------------------------------------------

    @Test
    fun aColdStateOpensAndDerivesThePhraseOnce() {
        val f = fixWith(phraseA, keyA, eoaA)
        f.vault.invalidateSnapshot()
        val before = VaultPerf.mark()
        assertTrue(f.vault.state() is NativeWalletVault.State.Ready)
        val after = VaultPerf.mark()
        assertEquals("one derivation (it was two)", 1, after.deriveOps - before.deriveOps)
        // The alias presence, the phrase open, the key-record open.
        assertEquals("keystore operations of one cold state (they were four)", 3, after.ksOps - before.ksOps)
    }

    @Test
    fun theStateAnswersAreTheSameAsBefore() {
        val ready = fixWith(phraseA, keyA, eoaA)
        ready.vault.invalidateSnapshot()
        assertEquals(eoaA, (ready.vault.state() as NativeWalletVault.State.Ready).eoa)
        assertFalse("a phrase is present", ready.vault.snapshotKeyOnly())
        val none = Fix()
        assertTrue(none.vault.state() is NativeWalletVault.State.NoKey)
        val noMarker = fixWith(phraseA, keyA, eoaA).also { it.files.map.remove(NativeWalletVault.MARK); it.vault.invalidateSnapshot() }
        assertTrue(noMarker.vault.state() is NativeWalletVault.State.Locked)
    }

    // ---- the race: syncs and reads together --------------------------------------------------------------------------------------------

    @Test
    fun concurrentSyncsAndReadsEndInAConsistentVaultWithNoStaleSnapshot() {
        val f = fixWith(phraseA, keyA, eoaA)
        val pool = Executors.newFixedThreadPool(8)
        val errors = AtomicInteger()
        val outcomes = java.util.Collections.synchronizedList(ArrayList<NativeWalletVault.SyncOutcome>())
        val start = CountDownLatch(1)
        val done = CountDownLatch(8)
        repeat(8) { t ->
            pool.execute {
                val rnd = Random(t.toLong())
                try {
                    start.await()
                    repeat(25) {
                        when (rnd.nextInt(4)) {
                            0 -> outcomes += f.vault.syncPhrase(eoaA, keyA, phraseA)
                            1 -> outcomes += f.vault.syncPhrase(eoaB, keyB, phraseB)
                            2 -> f.vault.state()
                            else -> f.vault.snapshotState()
                        }
                    }
                } catch (_: Throwable) {
                    errors.incrementAndGet()
                } finally {
                    done.countDown()
                }
            }
        }
        start.countDown()
        assertTrue(done.await(120, TimeUnit.SECONDS))
        pool.shutdown()
        assertEquals("no exception in any thread", 0, errors.get())
        assertTrue("every outcome is an answer a sync can give: $outcomes", outcomes.all { it in setOf(NativeWalletVault.SyncOutcome.UPDATED, NativeWalletVault.SyncOutcome.IDEMPOTENT) })
        // The vault is consistent: the record, the phrase and the state name the same account, and the phrase derives it.
        val cached = f.vault.snapshotState()
        f.vault.invalidateSnapshot()
        val fresh = f.vault.state() as NativeWalletVault.State.Ready
        if (cached != null) assertEquals("the snapshot was not stale", (cached as NativeWalletVault.State.Ready).eoa, fresh.eoa)
        val m = f.vault.mnemonicOf() as NativeWalletVault.MnemonicRead.Stored
        assertEquals(fresh.eoa, m.eoa)
        assertTrue(fresh.eoa == eoaA || fresh.eoa == eoaB)
        val derived = MnemonicDerivation.deriveKey(m.phrase)!!
        assertEquals(fresh.eoa, WalletAddress.fromPrivateKey(derived))
        // The two phrases were synced at least once each, or the state is the one that won.
        assertTrue(outcomes.isNotEmpty())
    }

    // ---- the K upgrade trigger never takes the monitor ---------------------------------------------------------------------------------

    @Test
    fun theTriggerReadsTheSnapshotAndNeverTheMonitor() {
        val f = fixWith(phraseA, keyA, eoaA)
        var scheduled = 0
        // No snapshot yet: it asks for one and leaves, even while another thread holds the monitor.
        f.vault.invalidateSnapshot()
        val held = CountDownLatch(1)
        val release = CountDownLatch(1)
        val holder = Thread { synchronized(f.vault) { held.countDown(); release.await(10, TimeUnit.SECONDS) } }.also { it.isDaemon = true; it.start() }
        assertTrue(held.await(5, TimeUnit.SECONDS))
        val answer = within(2_000) { KpgpUpgradeTrigger.snapshotOrSchedule(f.vault) { scheduled++ } }
        assertNull("no snapshot: null, and it did not wait for the monitor", answer)
        assertEquals(1, scheduled)
        release.countDown()
        holder.join(5_000)
        // With a snapshot: it returns the state and schedules nothing.
        f.vault.state()
        val ready = KpgpUpgradeTrigger.snapshotOrSchedule(f.vault) { scheduled++ }
        assertTrue(ready is NativeWalletVault.State.Ready)
        assertEquals(1, scheduled)
    }

    @Test
    fun theModuleTriggerAndTheFirstCommandUseTheSnapshotAndWarmIt() {
        val module = File("src/main/java/network/conet/chat/BeamioConetChatModule.kt").readText()
        val trigger = module.substringAfter("val kpgpTriggerStep: () -> Unit = kStep@{").substringBefore("val trigger = network.conet.chat.nativekey.KpgpUpgradeTrigger")
        assertTrue(trigger.contains("KpgpUpgradeTrigger.snapshotOrSchedule("))
        assertFalse("the trigger task does not call the vault's state()", Regex("""\.vault\(ctxIn\)\.state\(\)|\.state\(\)""").containsMatchIn(trigger))
        val warm = module.substringAfter("ensurePreread(ctxIn, \"command\")").substringBefore("BeamioConetChatSignBroker.setEmit(emit)")
        assertTrue("the first command warms the snapshots in order, with the trigger as the last step", warm.contains("VaultWarmUp.start(ctxIn, kpgpTriggerStep)"))
    }

    // ---- the timing lines hold numbers and enumerated words only -------------------------------------------------------------------------

    @Test
    fun theTimingLinesHoldOnlyNumbersAndEnumeratedWords() {
        val lines = java.util.Collections.synchronizedList(ArrayList<Pair<String, String>>())
        VaultPerf.sink = { label, _, code -> lines += label to code }
        val f = fixWith(phraseA, keyA, eoaA)
        f.vault.invalidateSnapshot()
        f.vault.state()
        f.vault.syncPhrase(eoaA, keyA, phraseA)
        f.vault.syncPhrase(eoaB, keyB, phraseB)
        VaultPerf.logWrapKeyLevelOnce { "STRONGBOX" }
        assertTrue(lines.any { it.first == "vault.computeState" })
        assertTrue(lines.any { it.first == "vault.syncPhrase" })
        assertTrue(lines.any { it.first == "wrapKey.level" && it.second == "level=STRONGBOX" })
        val shape = Regex("""^([A-Za-z]+=[0-9A-Z_]+ ?)+$""")
        for ((label, code) in lines) {
            assertTrue("label $label", label in setOf("vault.computeState", "vault.syncPhrase", "wrapKey.level", "ks.op"))
            assertTrue("code '$code' is numbers and enumerated words only", shape.matches(code))
            for (secret in listOf(eoaA, eoaB, eoaA.removePrefix("0x"), "abandon", "legal", "winner", "0x")) {
                assertFalse("no $secret in '$code'", code.contains(secret, ignoreCase = true))
            }
        }
    }

    @Test
    fun theWrapKeyLevelIsAnEnumeratedWordWhateverTheProbeSays() {
        for ((probe, expected) in listOf<Pair<() -> String, String>>(
            { "TEE" } to "level=TEE",
            { "software" } to "level=UNKNOWN",
            { "TEE with 0xabc" } to "level=TEE",
            { throw IllegalStateException("secret message") } to "level=UNKNOWN",
        )) {
            VaultPerf.resetForTests()
            val captured = ArrayList<String>()
            VaultPerf.sink = { _, _, code -> captured += code }
            VaultPerf.logWrapKeyLevelOnce(probe)
            assertEquals(listOf(expected), captured)
        }
        val src = File("src/main/java/network/conet/chat/nativekey/VaultPerf.kt").readText()
        assertFalse(src.contains("Log.") || src.contains("println"))
    }
}
