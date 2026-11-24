package network.conet.chat.nativekey

import org.json.JSONObject
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
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/**
 * The public identity snapshot, the one-decrypt read, the ordered warm-up and the per-operation Keystore lines (on a StrongBox device one operation
 * is seconds long, so identityPublic must not open the record, the K trigger must open it once, and the work must be ordered).
 */
class PublicIdentitySnapshotTest {
    private val vectors = JSONObject(String(File(System.getenv("PGP_NATIVE_VECTORS") ?: "../spec/pgp-native-vectors.v1.json").readBytes(), Charsets.UTF_8))
    private fun key(id: String) = vectors.getJSONObject("keys").getJSONObject(id)
    private val eoa = SYN_EOA
    private val otherEoa = "0x" + "cd".repeat(20)

    /** The test wrap, counting every Keystore operation as the device wrap does. */
    private class CountingWrap(val inner: NativeTestWrap = NativeTestWrap()) : KeyWrap {
        val ops = AtomicInteger(0)
        override fun seal(aad: ByteArray, plain: ByteArray): ByteArray = VaultPerf.keystore(VaultPerf.Op.SEAL) { ops.incrementAndGet(); inner.seal(aad, plain) }
        override fun open(aad: ByteArray, sealed: ByteArray): ByteArray? = VaultPerf.keystore(VaultPerf.Op.OPEN) { ops.incrementAndGet(); inner.open(aad, sealed) }
        override fun deleteKey(): Boolean = inner.deleteKey()
        override fun presence(): WrapKeyPresence = VaultPerf.keystore(VaultPerf.Op.PRESENCE) { ops.incrementAndGet(); inner.presence() }
    }

    private class Fix(account: String = SYN_EOA) {
        val wrap = CountingWrap()
        val files = NativeTestFiles()
        val vault = NativePgpVault(wrap, files, account)
        /** A second handle on the same storage, as every `pgpFor` call is. */
        fun another() = NativePgpVault(wrap, files, vault.account)
    }

    @Before
    fun reset() {
        VaultPerf.resetForTests()
        PublicIdentitySnapshot.resetForTests()
        VaultPerf.sink = { _, _, _ -> }
    }

    @After
    fun restore() {
        VaultPerf.sink = { label, start, code -> DiagTiming.log(label, start, code) }
        PublicIdentitySnapshot.resetForTests()
    }

    private fun put(f: Fix, id: String = "ecc-pass") =
        f.vault.put(eoa, key(id).getString("privateArmored"), key(id).getString("passphrase"))

    // ---- one decrypt for the state, the identity and the armor ----------------------------------------------------------------------------

    @Test
    fun readOnceAnswersWhatThreeSeparateReadsAnswerWithOneDecrypt() {
        val f = Fix()
        assertEquals(NativePgpVault.Put.OK, put(f))
        val sep0 = f.wrap.inner.opens
        val st = f.vault.state() as NativePgpVault.State.Ready
        val id = f.vault.identity()
        val armor = f.vault.armorForMove()
        assertEquals("the old way opens the record three times", 3, f.wrap.inner.opens - sep0)
        val one0 = f.wrap.inner.opens
        val r = f.vault.readOnce(wantArmor = true)
        assertEquals("one decrypt", 1, f.wrap.inner.opens - one0)
        val rs = r.state as NativePgpVault.State.Ready
        assertEquals(st.fingerprint, rs.fingerprint)
        assertEquals(id, r.identity)
        assertTrue(armor!!.contentEquals(r.armor!!))
        assertNotNull(r.identity)
        armor.fill(0)
        r.armor!!.fill(0)
    }

    @Test
    fun readOnceWithoutTheArmorReturnsNoArmor() {
        val f = Fix()
        put(f)
        assertNull(f.vault.readOnce(wantArmor = false).armor)
    }

    @Test
    fun readOnceKeepsTheStatesOfTheOldChecksAndOpensNothingForThem() {
        // no record, no marker
        val a = Fix()
        a.wrap.ops.set(0)
        assertTrue(a.vault.readOnce(true).state is NativePgpVault.State.NoKey)
        assertEquals(0, a.wrap.ops.get())
        // record without marker
        val b = Fix()
        put(b)
        b.files.map.remove(NativePgpVault.markName(eoa))
        b.wrap.ops.set(0)
        assertEquals("marker_missing", (b.vault.readOnce(true).state as NativePgpVault.State.Locked).reason)
        assertEquals(0, b.wrap.ops.get())
        // marker without record
        val c = Fix()
        put(c)
        c.files.map.remove(NativePgpVault.recName(eoa))
        assertEquals("record_missing", (c.vault.readOnce(true).state as NativePgpVault.State.Locked).reason)
        // marker that does not match
        val d = Fix()
        put(d)
        d.files.map[NativePgpVault.markName(eoa)] = "00".toByteArray()
        d.wrap.ops.set(0)
        assertEquals("marker_mismatch", (d.vault.readOnce(true).state as NativePgpVault.State.Locked).reason)
        assertEquals(0, d.wrap.ops.get())
        // a record another account sealed: the AAD does not open it
        val e = Fix()
        put(e)
        val other = NativePgpVault(e.wrap, e.files, otherEoa)
        assertTrue(other.readOnce(true).state is NativePgpVault.State.NoKey)
        // nothing was deleted by any of these reads
        assertNotNull(b.files.map[NativePgpVault.recName(eoa)])
        assertNotNull(d.files.map[NativePgpVault.recName(eoa)])
    }

    @Test
    fun theSourceOfTheUpgradeReadsTheVaultOnceAndFillsTheSnapshot() {
        val src = File("src/main/java/network/conet/chat/nativekey/KpgpUpgrade.kt").readText()
        val ready = src.substringAfter("val read = pgp.readOnce(wantArmor = true)").substringBefore("is NativePgpVault.State.Locked ->")
        assertTrue(ready.contains("PublicIdentitySnapshot.store(pgp.account, read)"))
        for (call in listOf("pgp.state()", "pgp.identity()", "pgp.armorForMove()")) {
            assertFalse("fromDevice no longer calls $call", src.substringAfter("fun fromDevice(").contains(call))
        }
        assertEquals("one readOnce in the base path", 1, Regex("""readOnce\(""").findAll(src.substringAfter("private fun fromDeviceBase(")).count())
        // The state check at the start asks the snapshot first, and reads (once, filling the snapshot) only on a miss.
        val now = src.substringAfter("private fun vaultStateNow(").substringBefore("internal fun orchestrate(")
        assertTrue(now.indexOf("PublicIdentitySnapshot.lookup(") in 0 until now.indexOf("readOnce("))
        assertFalse(now.contains(".state()") && !now.contains("readOnce(wantArmor = false).also { PublicIdentitySnapshot.store(pgp.account, it) }.state"))
    }

    // ---- the snapshot --------------------------------------------------------------------------------------------------------------------

    @Test
    fun refreshOpensOnceAndLookupsOpenNothing() {
        val f = Fix()
        put(f)
        f.wrap.ops.set(0)
        assertEquals(PublicIdentitySnapshot.Kind.READY, PublicIdentitySnapshot.refresh(f.vault))
        assertEquals("the refresh is one decrypt", 1, f.wrap.ops.get())
        f.wrap.ops.set(0)
        VaultPerf.resetForTests()
        repeat(100) {
            // What identityPublic does: a handle, the file signature (plain reads), a lookup.
            val l = PublicIdentitySnapshot.lookup(eoa, f.another().fileSignature())
            assertTrue(l is PublicIdentitySnapshot.Lookup.Hit)
        }
        assertEquals("100 identityPublic reads: no Keystore operation at all", 0, f.wrap.ops.get())
        assertEquals(0, VaultPerf.mark().ksOps)
        val facts = (PublicIdentitySnapshot.lookup(eoa, f.vault.fileSignature()) as PublicIdentitySnapshot.Lookup.Hit).facts
        assertEquals(PublicIdentitySnapshot.Kind.READY, facts.kind)
        assertEquals(f.vault.identity()!!.subkeyKeyId, facts.keyId)
        assertEquals(key("ecc-pass").getString("fingerprint").uppercase(), facts.fingerprint)
    }

    @Test
    fun theSnapshotHoldsNoPrivateMaterial() {
        val f = Fix()
        put(f)
        PublicIdentitySnapshot.refresh(f.vault)
        val facts = (PublicIdentitySnapshot.lookup(eoa, f.vault.fileSignature()) as PublicIdentitySnapshot.Lookup.Hit).facts
        // By type: Facts has strings, an enum, a long and nothing else, so it has no place for bytes.
        for (field in PublicIdentitySnapshot.Facts::class.java.declaredFields) {
            assertTrue("${field.name}: ${field.type}", field.type == String::class.java || field.type == Long::class.javaPrimitiveType || field.type == PublicIdentitySnapshot.Kind::class.java)
        }
        // By content: no armor, no passphrase, no sealed bytes in any value or in its text.
        val private = key("ecc-pass").getString("privateArmored")
        val pass = key("ecc-pass").getString("passphrase")
        // The public armor is the key's public block and nothing else; it is long, so it is judged by what it is.
        val pub = facts.publicArmor!!
        assertEquals("the public block of the record's key, as the upgrade derives it", NativePgpKeyGen.publicArmorOf(key("ecc-pass").getString("privateArmored")), pub)
        assertTrue(pub.contains("BEGIN PGP PUBLIC KEY BLOCK"))
        assertFalse(pub.contains("PRIVATE KEY"))
        val values = listOfNotNull(facts.account, facts.keyId, facts.fingerprint, facts.signature)
        for (v in values) {
            assertFalse(v.contains("PRIVATE KEY"))
            assertFalse(v.contains(pass))
            assertFalse(private.contains(v) && v.length > 64)
        }
        assertFalse("only short public strings and the digest signature", listOfNotNull(facts.account, facts.keyId, facts.fingerprint).any { it.length > 70 })
        assertEquals("two sha-256 digests", 64 + 1 + 64, facts.signature.length)
        // The object's own fields hold only the map of Facts, a clock and constants.
        for (field in PublicIdentitySnapshot::class.java.declaredFields) {
            assertFalse("${field.name}", field.type == ByteArray::class.java)
        }
        // The source says the same.
        val src = File("src/main/java/network/conet/chat/nativekey/PublicIdentitySnapshot.kt").readText()
        assertFalse(src.contains("ByteArray"))
        assertFalse(src.contains("armor =") || src.contains("privateArmor"))
    }

    @Test
    fun aWriteDropsTheEntryAndTheNextLookupNeverSeesTheOldKey() {
        val f = Fix()
        put(f, "ecc-pass")
        PublicIdentitySnapshot.refresh(f.vault)
        val oldId = (PublicIdentitySnapshot.lookup(eoa, f.vault.fileSignature()) as PublicIdentitySnapshot.Lookup.Hit).facts.keyId
        // put with overwrite, as the confirmed replacement does
        assertEquals(NativePgpVault.Put.OK, f.vault.put(eoa, key("ecc-nopass").getString("privateArmored"), "", overwrite = true))
        assertTrue("after the write: a miss, never the old value", PublicIdentitySnapshot.lookup(eoa, f.vault.fileSignature()) is PublicIdentitySnapshot.Lookup.Miss)
        PublicIdentitySnapshot.refresh(f.vault)
        val newId = (PublicIdentitySnapshot.lookup(eoa, f.vault.fileSignature()) as PublicIdentitySnapshot.Lookup.Hit).facts.keyId
        assertNotNull(newId)
        assertTrue("the new key's id", newId != oldId)
    }

    @Test
    fun aRefreshThatReadBeforeAWriteAndStoredAfterItIsNeverServed() {
        val f = Fix()
        put(f, "ecc-pass")
        val stale = f.vault.readOnce(wantArmor = false)
        assertEquals(NativePgpVault.Put.OK, f.vault.put(eoa, key("ecc-nopass").getString("privateArmored"), "", overwrite = true))
        // The slow refresh finishes after the write and stores what it read before it.
        PublicIdentitySnapshot.store(eoa, stale)
        assertTrue("its file signature is the old one", PublicIdentitySnapshot.lookup(eoa, f.vault.fileSignature()) is PublicIdentitySnapshot.Lookup.Miss)
    }

    @Test
    fun aClearDropsTheEntryThroughForgetAndThroughAnyOtherDeleteToo() {
        val f = Fix()
        put(f)
        PublicIdentitySnapshot.refresh(f.vault)
        assertTrue(f.vault.forget())
        assertTrue(PublicIdentitySnapshot.lookup(eoa, f.vault.fileSignature()) is PublicIdentitySnapshot.Lookup.Miss)
        // A delete by code that never calls invalidate: the file signature catches it.
        val g = Fix()
        put(g)
        PublicIdentitySnapshot.refresh(g.vault)
        g.files.map.remove(NativePgpVault.recName(eoa))
        g.files.map.remove(NativePgpVault.markName(eoa))
        assertTrue(PublicIdentitySnapshot.lookup(eoa, g.vault.fileSignature()) is PublicIdentitySnapshot.Lookup.Miss)
        // A direct replacement of the record by other code.
        val h = Fix()
        put(h)
        PublicIdentitySnapshot.refresh(h.vault)
        val other = Fix()
        other.vault.put(eoa, key("ecc-nopass").getString("privateArmored"), "")
        h.files.map[NativePgpVault.recName(eoa)] = other.files.map[NativePgpVault.recName(eoa)]!!
        assertTrue(PublicIdentitySnapshot.lookup(eoa, h.vault.fileSignature()) is PublicIdentitySnapshot.Lookup.Miss)
        // invalidateAll, as the identity clear does.
        val i = Fix()
        put(i)
        PublicIdentitySnapshot.refresh(i.vault)
        PublicIdentitySnapshot.invalidateAll()
        assertTrue(PublicIdentitySnapshot.lookup(eoa, i.vault.fileSignature()) is PublicIdentitySnapshot.Lookup.Miss)
    }

    @Test
    fun anUnreadableFileIsNeverAHit() {
        val f = Fix()
        put(f)
        PublicIdentitySnapshot.refresh(f.vault)
        f.files.failRead = { true }
        assertNull("the signature cannot be read: unknown", f.vault.fileSignature())
        assertTrue(PublicIdentitySnapshot.lookup(eoa, f.vault.fileSignature()) is PublicIdentitySnapshot.Lookup.Miss)
    }

    @Test
    fun accountsAreKeptApartAndSwitchingNeverServesTheOtherOne() {
        val a = Fix(eoa)
        val b = Fix(otherEoa)
        put(a, "ecc-pass")
        assertEquals(NativePgpVault.Put.OK, b.vault.put(otherEoa, key("ecc-nopass").getString("privateArmored"), ""))
        PublicIdentitySnapshot.refresh(a.vault)
        // B asked: no entry of B's own, so a miss, not A's facts.
        assertTrue(PublicIdentitySnapshot.lookup(otherEoa, b.vault.fileSignature()) is PublicIdentitySnapshot.Lookup.Miss)
        PublicIdentitySnapshot.refresh(b.vault)
        val fa = (PublicIdentitySnapshot.lookup(eoa, a.vault.fileSignature()) as PublicIdentitySnapshot.Lookup.Hit).facts
        val fb = (PublicIdentitySnapshot.lookup(otherEoa, b.vault.fileSignature()) as PublicIdentitySnapshot.Lookup.Hit).facts
        assertEquals(eoa, fa.account)
        assertEquals(otherEoa, fb.account)
        assertTrue(fa.keyId != fb.keyId)
        // An A entry looked up with B's signature is not valid for B.
        assertTrue(PublicIdentitySnapshot.lookup(eoa, b.vault.fileSignature()) is PublicIdentitySnapshot.Lookup.Miss)
        // A write for B leaves A's entry alone and drops B's. (The slot is the active one.)
        assertEquals(NativePgpVault.Put.OK, b.vault.put(otherEoa, key("ecc-pass").getString("privateArmored"), key("ecc-pass").getString("passphrase"), overwrite = true))
        assertTrue(PublicIdentitySnapshot.lookup(otherEoa, b.vault.fileSignature()) is PublicIdentitySnapshot.Lookup.Miss)
    }

    @Test
    fun aWriteToAPendingSlotLeavesTheActiveEntry() {
        val f = Fix()
        put(f)
        PublicIdentitySnapshot.refresh(f.vault)
        val pending = NativePgpVault(f.wrap, f.files, eoa, NativePgpVault.Slot.PENDING)
        assertEquals(NativePgpVault.Put.OK, pending.put(eoa, key("ecc-nopass").getString("privateArmored"), ""))
        assertTrue(PublicIdentitySnapshot.lookup(eoa, f.vault.fileSignature()) is PublicIdentitySnapshot.Lookup.Hit)
    }

    @Test
    fun noKeyIsKeptWhileTheFilesStayEmptyAndDropsWhenAKeyAppears() {
        val f = Fix()
        assertEquals(PublicIdentitySnapshot.Kind.NO_KEY, PublicIdentitySnapshot.refresh(f.vault))
        val hit = PublicIdentitySnapshot.lookup(eoa, f.vault.fileSignature())
        assertEquals(PublicIdentitySnapshot.Kind.NO_KEY, (hit as PublicIdentitySnapshot.Lookup.Hit).facts.kind)
        put(f)
        assertTrue(PublicIdentitySnapshot.lookup(eoa, f.vault.fileSignature()) is PublicIdentitySnapshot.Lookup.Miss)
    }

    @Test
    fun anUnknownAnswerIsShortLivedSoATransientFailureDoesNotStick() {
        val f = Fix()
        put(f)
        f.files.map.remove(NativePgpVault.markName(eoa))
        var now = 1_000L
        PublicIdentitySnapshot.nowMs = { now }
        assertEquals(PublicIdentitySnapshot.Kind.UNKNOWN, PublicIdentitySnapshot.refresh(f.vault))
        assertTrue(PublicIdentitySnapshot.lookup(eoa, f.vault.fileSignature()) is PublicIdentitySnapshot.Lookup.Hit)
        now += PublicIdentitySnapshot.UNKNOWN_TTL_MS - 1
        assertTrue(PublicIdentitySnapshot.lookup(eoa, f.vault.fileSignature()) is PublicIdentitySnapshot.Lookup.Hit)
        now += 1
        assertTrue("after the time it is a miss and a refresh is wanted", PublicIdentitySnapshot.lookup(eoa, f.vault.fileSignature()) is PublicIdentitySnapshot.Lookup.Miss)
    }

    @Test
    fun aReadThatThrowsStoresNothing() {
        val f = Fix()
        put(f)
        f.wrap.inner.openOverride = { throw java.io.IOException("keystore unavailable") }
        assertEquals(PublicIdentitySnapshot.Kind.UNKNOWN, PublicIdentitySnapshot.refresh(f.vault))
        assertTrue(PublicIdentitySnapshot.lookup(eoa, f.vault.fileSignature()) is PublicIdentitySnapshot.Lookup.Miss)
    }

    @Test
    fun putAndForgetDropTheEntryInTheSourceToo() {
        val src = File("src/main/java/network/conet/chat/nativekey/NativePgpVault.kt").readText()
        assertTrue(src.substringAfter("fun put(").substringBefore("private fun putLocked").contains("PublicIdentitySnapshot.invalidate(account)"))
        assertTrue(src.substringAfter("fun forget()").substringBefore("/** True when this slot").contains("PublicIdentitySnapshot.invalidate(account)"))
        val module = File("src/main/java/network/conet/chat/BeamioConetChatModule.kt").readText()
        assertTrue(module.substringAfter("private fun clearIdentity(").substringBefore("private fun finishClearIdentity").contains("PublicIdentitySnapshot.invalidateAll()"))
        assertTrue(module.substringAfter("private fun finishClearIdentity(").take(300).contains("PublicIdentitySnapshot.invalidateAll()"))
    }

    // ---- the order of the warm-up ----------------------------------------------------------------------------------------------------------

    private class Manual {
        val queue = ArrayDeque<Runnable>()
        fun execute(r: Runnable) { queue.addLast(r) }
        fun drain() { while (queue.isNotEmpty()) queue.removeFirst().run() }
    }

    private fun engine(m: Manual, log: MutableList<String>, fail: Set<String> = emptySet()): VaultWarmUp.Engine {
        val steps = VaultWarmUp.Steps(
            walletSnapshot = { log += "wallet"; if ("wallet" in fail) throw IllegalStateException("x") },
            publicIdentity = { log += "identity"; if ("identity" in fail) throw IllegalStateException("x") },
        )
        return VaultWarmUp.Engine(steps) { m.execute(it) }
    }

    @Test
    fun theWarmUpRunsTheWalletThenTheIdentityThenTheTrigger() {
        val m = Manual()
        val log = ArrayList<String>()
        val e = engine(m, log)
        val trace = ArrayList<VaultWarmUp.Step>()
        e.trace = { trace += it }
        e.start { log += "k" }
        m.drain()
        assertEquals(listOf("wallet", "identity", "k"), log)
        assertEquals(listOf(VaultWarmUp.Step.WALLET_SNAPSHOT, VaultWarmUp.Step.PUBLIC_IDENTITY, VaultWarmUp.Step.K_TRIGGER), trace)
    }

    @Test
    fun theApplicationStartRunsNoTrigger() {
        val m = Manual()
        val log = ArrayList<String>()
        val e = engine(m, log)
        e.start(null)
        m.drain()
        assertEquals(listOf("wallet", "identity"), log)
    }

    @Test
    fun aFailedStepDoesNotSkipTheNextOnesAndTheTriggerStillRunsLast() {
        val m = Manual()
        val log = ArrayList<String>()
        val e = engine(m, log, fail = setOf("wallet", "identity"))
        e.start { log += "k" }
        m.drain()
        assertEquals(listOf("wallet", "identity", "k"), log)
        // and a failed trigger leaves the engine usable
        val m2 = Manual()
        val log2 = ArrayList<String>()
        val e2 = engine(m2, log2)
        e2.start { throw IllegalStateException("k failed") }
        m2.drain()
        e2.start(null)
        m2.drain()
        assertEquals(listOf("wallet", "identity", "wallet", "identity"), log2)
    }

    @Test
    fun aSecondStartWhileARunIsWaitingIsNotRepeatedButItsTriggerIsNotLost() {
        val m = Manual()
        val log = ArrayList<String>()
        val e = engine(m, log)
        e.start(null)          // Application.onCreate: queued, not yet run
        e.start { log += "k" } // the first command: the run is already waiting
        assertEquals("one run is queued", 1, m.queue.size)
        m.drain()
        assertEquals(listOf("wallet", "identity", "k"), log)
    }

    @Test
    fun aTriggerAskedForDuringTheRunAfterItsLookIsRunByAFollowUp() {
        val m = Manual()
        val log = ArrayList<String>()
        lateinit var e: VaultWarmUp.Engine
        val steps = VaultWarmUp.Steps(
            walletSnapshot = { log += "wallet" },
            // A trigger is requested while step 2 runs, before step 3 looks.
            publicIdentity = { log += "identity"; e.start { log += "k2" } },
        )
        e = VaultWarmUp.Engine(steps) { m.execute(it) }
        e.start(null)
        m.drain()
        assertEquals(listOf("wallet", "identity", "k2"), log)
        // Asked for after step 3 had looked (during the trigger itself): a second run.
        val m3 = Manual()
        val log3 = ArrayList<String>()
        lateinit var e3: VaultWarmUp.Engine
        e3 = VaultWarmUp.Engine(VaultWarmUp.Steps({ log3 += "wallet" }, { log3 += "identity" })) { m3.execute(it) }
        e3.start { log3 += "k1"; e3.start { log3 += "k2" } }
        m3.drain()
        assertEquals(listOf("wallet", "identity", "k1", "wallet", "identity", "k2"), log3)
    }

    @Test
    fun theIdentityStepReadsTheAccountOfTheWalletOrTheStoreAndSkipsTheRest() {
        val f = Fix()
        put(f)
        f.wrap.ops.set(0)
        val ready = NativeWalletVault.State.Ready(eoa)
        assertEquals(eoa, VaultWarmUp.publicIdentityStep(ready, { null }) { f.another() })
        assertEquals("one decrypt", 1, f.wrap.ops.get())
        // the second warm-up finds a valid entry and opens nothing
        f.wrap.ops.set(0)
        assertNull(VaultWarmUp.publicIdentityStep(ready, { null }) { f.another() })
        assertEquals(0, f.wrap.ops.get())
        // a vault with no record uses the store's account
        PublicIdentitySnapshot.invalidateAll()
        assertEquals(eoa, VaultWarmUp.publicIdentityStep(NativeWalletVault.State.NoKey, { eoa }) { f.another() })
        // no account: nothing is read
        PublicIdentitySnapshot.invalidateAll()
        f.wrap.ops.set(0)
        assertNull(VaultWarmUp.publicIdentityStep(NativeWalletVault.State.NoKey, { null }) { f.another() })
        assertNull(VaultWarmUp.publicIdentityStep(null, { eoa }) { f.another() })
        assertEquals(0, f.wrap.ops.get())
    }

    @Test
    fun theModuleWiresTheWarmUpAndTheApplicationEntry() {
        val module = File("src/main/java/network/conet/chat/BeamioConetChatModule.kt").readText()
        assertTrue(module.contains("fun warmUp(context: Context)"))
        assertTrue(module.substringAfter("fun warmUp(context: Context)").take(200).contains("VaultWarmUp.start(context.applicationContext)"))
        // The first command no longer starts the wallet snapshot by itself: it is step 1.
        val first = module.substringAfter("ensurePreread(ctxIn, \"command\")").substringBefore("val kpgpTriggerStep")
        assertFalse(first.contains("VaultSnapshotRefresh.schedule(ctxIn)"))
        assertTrue(Regex("""PERF_COMMANDS: Set<String> = setOf\("pwaWalletSync", "identityPublic", "nativeMnemonicPreread"\)""").containsMatchIn(module))
        assertTrue(module.contains("VaultPerf.log(\"cmd.\$type\", t0, perfMark, 0L)"))
        // The warm-up has one thread and never a lock of the vault or a wait for the caller.
        val src = File("src/main/java/network/conet/chat/nativekey/VaultWarmUp.kt").readText()
        assertFalse(src.contains("synchronized(vault") || src.contains(".get(") && src.contains("Future"))
    }

    // ---- the per-operation lines hold enumerated words and digits only ------------------------------------------------------------------

    @Test
    fun everyKeystoreOperationLogsItsKindThreadClassAndTheOthersInFlight() {
        val lines = java.util.Collections.synchronizedList(ArrayList<Pair<String, String>>())
        VaultPerf.sink = { label, _, code -> lines += label to code }
        val f = Fix()
        put(f)
        f.vault.state()
        val ops = lines.filter { it.first == "ks.op" }.map { it.second }
        assertTrue(ops.isNotEmpty())
        val shape = Regex("""^kind=(OPEN|SEAL|PRESENCE|OTHER) others=[0-9]+ cls=(MAIN|SNAPSHOT|MODULE_IO|OTHER) ok=[01]$""")
        for (c in ops) assertTrue("'$c'", shape.matches(c))
        assertTrue(ops.any { it.startsWith("kind=SEAL ") })
        assertTrue(ops.any { it.startsWith("kind=OPEN ") })
    }

    @Test
    fun anOperationSeesHowManyOthersWereAlreadyRunning() {
        val lines = java.util.Collections.synchronizedList(ArrayList<String>())
        VaultPerf.sink = { label, _, code -> if (label == "ks.op") lines += code }
        val started = CountDownLatch(1)
        val release = CountDownLatch(1)
        val first = Thread {
            VaultPerf.keystore(VaultPerf.Op.OPEN) { started.countDown(); release.await(10, TimeUnit.SECONDS) }
        }.also { it.isDaemon = true; it.start() }
        assertTrue(started.await(5, TimeUnit.SECONDS))
        val second = Thread { VaultPerf.keystore(VaultPerf.Op.SEAL) { } }.also { it.isDaemon = true; it.start() }
        second.join(5_000)
        release.countDown()
        first.join(5_000)
        assertTrue("the second operation started while one was running: $lines", lines.any { it.startsWith("kind=SEAL others=1 ") })
        assertTrue(lines.any { it.startsWith("kind=OPEN others=0 ") })
    }

    @Test
    fun aFailedOperationIsLoggedWithOkZeroAndTheErrorTextIsNotLogged() {
        val lines = ArrayList<String>()
        VaultPerf.sink = { label, _, code -> if (label == "ks.op") lines += code }
        try {
            VaultPerf.keystore(VaultPerf.Op.OPEN) { throw java.io.IOException("secret detail 0xabc") }
        } catch (_: java.io.IOException) {
        }
        assertEquals(1, lines.size)
        assertTrue(lines[0].endsWith("ok=0"))
        assertFalse(lines[0].contains("secret") || lines[0].contains("0xabc"))
    }

    @Test
    fun theThreadIsLoggedAsAClassNeverByName() {
        assertEquals(VaultPerf.ThreadClass.MAIN, VaultPerf.threadClassOf("anything", true))
        assertEquals(VaultPerf.ThreadClass.SNAPSHOT, VaultPerf.threadClassOf("conet-vault-snapshot", false))
        assertEquals(VaultPerf.ThreadClass.MODULE_IO, VaultPerf.threadClassOf("conet-chat-module", false))
        assertEquals(VaultPerf.ThreadClass.OTHER, VaultPerf.threadClassOf("pool-3-thread-1 with 0x39581c72", false))
        val src = File("src/main/java/network/conet/chat/nativekey/VaultPerf.kt").readText()
        assertFalse("the line carries the class, not the thread name", src.substringAfter("sink(\"ks.op\"").substringBefore("}").contains("Thread.currentThread().name"))
    }

    @Test
    fun theDeviceWrapMarksEachOperationWithItsKind() {
        val src = File("src/main/java/network/conet/chat/nativekey/AndroidNativeWallet.kt").readText()
        assertTrue(src.contains("VaultPerf.keystore(VaultPerf.Op.PRESENCE)"))
        assertTrue(src.contains("VaultPerf.keystore(VaultPerf.Op.SEAL)"))
        assertTrue(src.contains("VaultPerf.keystore(VaultPerf.Op.OPEN)"))
        assertFalse(Regex("""VaultPerf\.keystore \{""").containsMatchIn(src))
    }

    @Test
    fun theCommandLineHoldsDigitsOnly() {
        val lines = ArrayList<String>()
        VaultPerf.sink = { label, _, code -> if (label == "cmd.identityPublic") lines += code }
        val mark = VaultPerf.mark()
        VaultPerf.keystore(VaultPerf.Op.OPEN) { }
        VaultPerf.log("cmd.identityPublic", System.nanoTime(), mark, 0L)
        assertEquals(1, lines.size)
        assertTrue(lines[0], Regex("""^ksOps=1 ksMs=[0-9]+ deriveOps=0 deriveMs=[0-9]+ lockWaitMs=0$""").matches(lines[0]))
    }

    // ---- three points of the identityPublic answer --------------------------------------------------------------------------------------

    @Test
    fun aRestoreWriteDropsTheEntryToo() {
        // The restore machine writes the active slot through its own device (the same vault class and files).
        val f = Fix()
        val dev = PgpRestoreDevice("d", eoa, f.wrap, f.files)
        put(f)
        PublicIdentitySnapshot.refresh(f.vault)
        assertTrue(PublicIdentitySnapshot.lookup(eoa, f.vault.fileSignature()) is PublicIdentitySnapshot.Lookup.Hit)
        assertEquals(NativePgpVault.Put.OK, dev.active.put(eoa, key("ecc-nopass").getString("privateArmored"), "", overwrite = true))
        assertTrue("after a restore write: a miss", PublicIdentitySnapshot.lookup(eoa, f.vault.fileSignature()) is PublicIdentitySnapshot.Lookup.Miss)
        // And a restore into an empty slot (no key before): the NO_KEY entry is dropped.
        val g = Fix()
        PublicIdentitySnapshot.refresh(g.vault)
        assertEquals(NativePgpVault.Put.OK, PgpRestoreDevice("d", eoa, g.wrap, g.files).active.put(eoa, key("ecc-pass").getString("privateArmored"), key("ecc-pass").getString("passphrase")))
        assertTrue(PublicIdentitySnapshot.lookup(eoa, g.vault.fileSignature()) is PublicIdentitySnapshot.Lookup.Miss)
    }

    private fun sourceOf(facts: PublicIdentitySnapshot.Facts?, route: String?) = object : IdentityPublic.Source {
        override fun eoa(): String? = eoa
        override fun pgp(): IdentityPublic.PgpRecord = IdentityPublic.PgpRecord.NotRead
        override fun pgpAvailable(): Boolean = facts != null
        override fun pgpState(): IdentityPublic.PgpState? = when (facts?.kind) {
            PublicIdentitySnapshot.Kind.READY -> IdentityPublic.PgpState.READY
            PublicIdentitySnapshot.Kind.NO_KEY -> IdentityPublic.PgpState.NOT_READY
            PublicIdentitySnapshot.Kind.UNKNOWN -> IdentityPublic.PgpState.UNKNOWN
            null -> null
        }
        override fun pgpKeyId(): String? = facts?.keyId
        override fun pgpPublicArmor(): String? = facts?.publicArmor
        override fun ownRouteArmor(): String? = route
    }

    @Test
    fun theThreeItemRuleHoldsOnTheSnapshotPath() {
        val f = Fix()
        put(f)
        PublicIdentitySnapshot.refresh(f.vault)
        val facts = (PublicIdentitySnapshot.lookup(eoa, f.vault.fileSignature()) as PublicIdentitySnapshot.Lookup.Hit).facts
        val routeArmor = key("ecc-nopass").getString("publicArmored")
        fun answer(src: IdentityPublic.Source) = IdentityPublic.answer(NoKeyGate.Gate.G2, { listOf("type", "reqId") }, 1, src).result!!
        // all three: ready, with the three fields
        val full = answer(sourceOf(facts, routeArmor))
        assertTrue(full.getBoolean("pgpReady"))
        assertEquals(facts.keyId, full.getString("pgpKeyID"))
        assertEquals(facts.publicArmor, full.getString("pgpPublicKeyArmored"))
        assertEquals(routeArmor, full.getString("ownRouteArmoredPublicKey"))
        // any one missing: not ready and none of the three
        for (missing in listOf("route", "armor", "keyId")) {
            val reduced = PublicIdentitySnapshot.Facts(
                eoa, PublicIdentitySnapshot.Kind.READY,
                if (missing == "keyId") null else facts.keyId, facts.fingerprint,
                if (missing == "armor") null else facts.publicArmor,
                facts.signature, 0L,
            )
            val r = answer(sourceOf(reduced, if (missing == "route") null else routeArmor))
            assertFalse("missing $missing", r.getBoolean("pgpReady"))
            for (name in listOf("pgpKeyID", "pgpPublicKeyArmored", "ownRouteArmoredPublicKey")) assertFalse("$name with $missing missing", r.has(name))
        }
        // a private armor is never passed as the public one
        val priv = PublicIdentitySnapshot.Facts(eoa, PublicIdentitySnapshot.Kind.READY, facts.keyId, facts.fingerprint, key("ecc-pass").getString("privateArmored"), facts.signature, 0L)
        assertFalse(answer(sourceOf(priv, routeArmor)).getBoolean("pgpReady"))
        // and nothing private is in the answer
        assertFalse(full.toString().contains("PRIVATE KEY"))
        assertFalse(full.toString().contains(key("ecc-pass").getString("passphrase")))
    }

    @Test
    fun aFailedBackgroundReadIsAskedForAgainByTheNextCall() {
        VaultWarmUp.resetForTests()
        val f = Fix()
        put(f)
        val q = Manual()
        // 1: the vault cannot be built: nothing stored, the account is released.
        VaultWarmUp.warmIdentityOn({ q.execute(it) }, eoa) { throw IllegalStateException("no vault") }
        // a second ask while the first is queued is not queued again
        VaultWarmUp.warmIdentityOn({ q.execute(it) }, eoa) { throw IllegalStateException("no vault") }
        assertEquals(1, q.queue.size)
        q.drain()
        assertTrue(PublicIdentitySnapshot.lookup(eoa, f.vault.fileSignature()) is PublicIdentitySnapshot.Lookup.Miss)
        // 2: the Keystore throws during the read: nothing stored again.
        f.wrap.inner.openOverride = { throw java.io.IOException("keystore unavailable") }
        VaultWarmUp.warmIdentityOn({ q.execute(it) }, eoa) { f.another() }
        assertEquals("released after the failure: asked for again", 1, q.queue.size)
        q.drain()
        assertTrue(PublicIdentitySnapshot.lookup(eoa, f.vault.fileSignature()) is PublicIdentitySnapshot.Lookup.Miss)
        // 3: the Keystore is back: the next call reads and the lookup hits.
        f.wrap.inner.openOverride = null
        VaultWarmUp.warmIdentityOn({ q.execute(it) }, eoa) { f.another() }
        assertEquals(1, q.queue.size)
        q.drain()
        val hit = PublicIdentitySnapshot.lookup(eoa, f.vault.fileSignature())
        assertEquals(PublicIdentitySnapshot.Kind.READY, (hit as PublicIdentitySnapshot.Lookup.Hit).facts.kind)
        VaultWarmUp.resetForTests()
    }

    @Test
    fun anUnknownAnswerIsRefreshedAfterItsTimeSoThePageDoesNotStickOnIt() {
        VaultWarmUp.resetForTests()
        val f = Fix()
        put(f)
        f.files.map.remove(NativePgpVault.markName(eoa))
        var now = 10_000L
        PublicIdentitySnapshot.nowMs = { now }
        assertNull(VaultWarmUp.refreshIdentity(eoa) { f.another() }?.let { null })
        // inside the window the unknown answer is served; after it, a miss asks for a read again
        assertTrue(PublicIdentitySnapshot.lookup(eoa, f.vault.fileSignature()) is PublicIdentitySnapshot.Lookup.Hit)
        now += PublicIdentitySnapshot.UNKNOWN_TTL_MS
        assertTrue(PublicIdentitySnapshot.lookup(eoa, f.vault.fileSignature()) is PublicIdentitySnapshot.Lookup.Miss)
        // the storage is fixed; the next read gives the real answer
        put(f.also { it.files.map.clear() })
        assertEquals(eoa, VaultWarmUp.refreshIdentity(eoa) { f.another() })
        assertEquals(PublicIdentitySnapshot.Kind.READY, ((PublicIdentitySnapshot.lookup(eoa, f.vault.fileSignature())) as PublicIdentitySnapshot.Lookup.Hit).facts.kind)
        VaultWarmUp.resetForTests()
    }

    // ---- put drops the entry before it touches anything, and after it ends, even when it fails ---------------------------

    @Test
    fun aFailedPutStillDropsTheEntryEvenThoughNoFileChanged() {
        val f = Fix()
        put(f)
        PublicIdentitySnapshot.refresh(f.vault)
        val sig = f.vault.fileSignature()
        assertTrue(PublicIdentitySnapshot.lookup(eoa, sig) is PublicIdentitySnapshot.Lookup.Hit)
        f.wrap.inner.failSeal = true
        assertEquals(NativePgpVault.Put.STORE_FAILED, f.vault.put(eoa, key("ecc-nopass").getString("privateArmored"), "", overwrite = true))
        assertEquals("nothing was written, so the signature is unchanged", sig, f.vault.fileSignature())
        assertTrue("and the entry is dropped anyway: the invalidation does not depend on the signature", PublicIdentitySnapshot.lookup(eoa, sig) is PublicIdentitySnapshot.Lookup.Miss)
    }

    @Test
    fun putDropsTheEntryBeforeTheFirstWrite() {
        val f = Fix()
        put(f)
        PublicIdentitySnapshot.refresh(f.vault)
        val sig = f.vault.fileSignature()!!
        var duringFirstWrite: PublicIdentitySnapshot.Lookup? = null
        val spy = object : VaultFiles {
            override fun read(name: String): ByteArray? = f.files.read(name)
            override fun write(name: String, bytes: ByteArray) {
                if (duringFirstWrite == null) duringFirstWrite = PublicIdentitySnapshot.lookup(eoa, sig)
                f.files.write(name, bytes)
            }
            override fun delete(name: String) = f.files.delete(name)
        }
        val v = NativePgpVault(f.wrap, spy, eoa)
        assertEquals(NativePgpVault.Put.OK, v.put(eoa, key("ecc-nopass").getString("privateArmored"), "", overwrite = true))
        // At the first write the files still have the old signature, so only an invalidation before the write explains a miss here.
        assertTrue("dropped before the first write: $duringFirstWrite", duringFirstWrite is PublicIdentitySnapshot.Lookup.Miss)
    }

    @Test
    fun forgetDropsTheEntryBeforeItErasesAnything() {
        val f = Fix()
        put(f)
        PublicIdentitySnapshot.refresh(f.vault)
        val sig = f.vault.fileSignature()!!
        var duringFirstDelete: PublicIdentitySnapshot.Lookup? = null
        val spy = object : VaultFiles {
            override fun read(name: String): ByteArray? = f.files.read(name)
            override fun write(name: String, bytes: ByteArray) = f.files.write(name, bytes)
            override fun delete(name: String) {
                if (duringFirstDelete == null) duringFirstDelete = PublicIdentitySnapshot.lookup(eoa, sig)
                f.files.delete(name)
            }
        }
        assertTrue(NativePgpVault(f.wrap, spy, eoa).forget())
        assertTrue("dropped before the first erase: $duringFirstDelete", duringFirstDelete is PublicIdentitySnapshot.Lookup.Miss)
    }

    @Test
    fun theUnknownEntryLivesFiveSeconds() {
        // A short-lived UNKNOWN entry with the existing 5 s time, for a transient failure and for a mismatched record alike.
        assertEquals(5_000L, PublicIdentitySnapshot.UNKNOWN_TTL_MS)
    }
}
