package network.conet.chat

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.file.Files
import java.util.Random
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * Batched history writes + multi-device compare-and-swap (history-batch-write-design.md).
 * Offline: in-memory registry with the contract's nonce / ts / seq rules, in-memory IPFS,
 * fake signer whose EIP-712 signature binds the signed nonce and index hash.
 */
class HistoryBatchTest {
    private val owner = "0x" + "ab".repeat(20)

    /** Contract + relay + IPFS in memory. */
    class FakeWorld(private val rng: Random = Random(1)) {
        var indexHash: String? = null
        var ts = "0"
        var seq = "0"
        var nonce = 0L
        val heads = ArrayList<String>()
        val events = ArrayList<Triple<String, String, String>>()
        val fragments = HashMap<String, String>()
        var uploads = 0
        /** "v2" (default), "legacy" (403 for an unsigned upload), "rate_limited" (429, Retry-After 90 s). */
        @Volatile var server = "v2"
        val uploadBodies = ArrayList<Boolean>()
        var forbidden = 0

        private fun jiggle() {
            val r = synchronized(rng) { rng.nextInt(3) }
            if (r > 0) Thread.sleep(0, r * 100_000)
        }

        fun net(
            offline: Boolean = false,
            failIndexFetch: Boolean = false,
            loseAckAfterLanding: Boolean = false,
            serveInstead: Map<String, String> = emptyMap(),
        ) =
            object : HistoryNet {
                override fun readSnapshot(owner: String): HistorySnapshot? {
                    jiggle()
                    if (offline) return null
                    return synchronized(this@FakeWorld) { HistorySnapshot(indexHash, ts, seq, nonce.toString()) }
                }

                override fun fetchFragment(hash: String): String? {
                    jiggle()
                    if (offline) return null
                    return synchronized(this@FakeWorld) {
                        if (failIndexFetch && hash == indexHash) null else fragments[serveInstead[hash] ?: hash]
                    }
                }

                override fun uploadFragment(cipherB64: String, legacy: LegacyUploadCredential?): HistoryBatch.UploadResult {
                    jiggle()
                    if (offline) return HistoryBatch.UploadResult.Error
                    val hash = ConetChatCryptoUtil.keccakUtf8Hex(cipherB64)
                    synchronized(this@FakeWorld) {
                        uploadBodies.add(legacy != null)
                        if (server == "rate_limited") return HistoryBatch.classifyUpload(429, "{}", "90", hash, legacy != null)
                        if (server == "legacy" && legacy == null) {
                            forbidden++
                            return HistoryBatch.classifyUpload(403, "Forbidden", null, hash, false)
                        }
                        if (legacy != null && legacy.selfSign != "sig191:${legacy.owner}") return HistoryBatch.UploadResult.Error
                        fragments[hash] = cipherB64
                        uploads++
                    }
                    return HistoryBatch.classifyUpload(200, JSONObject().put("ok", true).put("hash", hash).toString(), null, hash, legacy != null)
                }

                override fun submitPointer(
                    owner: String,
                    indexHash: String,
                    ts: String,
                    seq: String,
                    nonce: String,
                    signature: String,
                ): HistoryBatch.SubmitResult {
                    jiggle()
                    if (offline) return HistoryBatch.SubmitResult.ERROR
                    val result = setPointerWithSig(indexHash, ts, seq, nonce, signature)
                    jiggle()
                    if (result == HistoryBatch.SubmitResult.OK && loseAckAfterLanding) return HistoryBatch.SubmitResult.ERROR
                    return result
                }
            }

        /** Same checks as ChatIndexRegistry.setPointerWithSig. */
        @Synchronized
        fun setPointerWithSig(hash: String, ts: String, seq: String, nonce: String, signature: String): HistoryBatch.SubmitResult {
            if (signature != "sig712:$nonce:$hash:$ts:$seq") return HistoryBatch.SubmitResult.ERROR
            if (nonce.toLong() != this.nonce) return HistoryBatch.classify(400, "Stale pointer nonce")
            if (ts.toBigInteger() < this.ts.toBigInteger() || seq.toBigInteger() < this.seq.toBigInteger()) {
                return HistoryBatch.SubmitResult.CONFLICT
            }
            indexHash = hash
            this.ts = ts
            this.seq = seq
            this.nonce += 1
            heads.add(hash)
            events.add(Triple(hash, ts, seq))
            return HistoryBatch.SubmitResult.OK
        }

        @Synchronized
        fun legacyOverwrite(hash: String, legacyTs: String) {
            indexHash = hash
            ts = legacyTs
            nonce += 1
            heads.add(hash)
        }
    }

    class FakeClock(var t: Long = 1_800_000_000_000L, private val r: () -> Double = { Math.random() }) : HistoryClock {
        override fun now(): Long = t
        override fun random(): Double = r()
        override fun sleep(ms: Long) = Unit
    }

    private val eip191Messages = java.util.Collections.synchronizedList(ArrayList<String>())

    private val signer = object : HistorySigner {
        override fun eip191(message: String): String {
            eip191Messages.add(message)
            return "sig191:$message"
        }
        override fun eip712(typedData: JSONObject): String {
            val v = typedData.getJSONObject("value")
            return "sig712:${v.getString("nonce")}:${v.getString("indexHash")}:${v.getString("ts")}:${v.getString("seq")}"
        }
    }

    private fun store(
        world: FakeWorld,
        net: HistoryNet = world.net(),
        dir: File? = null,
        clock: HistoryClock = FakeClock(),
    ): BeamioConetChatHistoryStore {
        val s = BeamioConetChatHistoryStore(
            eoa = owner,
            chainId = 224422,
            conetRpcUrl = "mem://rpc",
            ipfsBaseUrl = "mem://ipfs",
            ipfsWriteBaseUrl = null,
            apiBaseUrl = "mem://api",
            registryAddress = "0x1511Caa71081C84d8a591490D1b83879088EED72",
            log = { _, _ -> },
            storageDir = dir,
            net = net,
            clock = clock,
            signer = signer,
            autoFlush = false,
        )
        val ready = CountDownLatch(1)
        var ok = false
        s.prepare {
            ok = it
            ready.countDown()
        }
        assertTrue(ready.await(10, TimeUnit.SECONDS))
        assertTrue(ok)
        return s
    }

    private fun append(s: BeamioConetChatHistoryStore, sendId: String?, ts: Long, body: String = "body-$sendId-$ts") {
        val done = CountDownLatch(1)
        val e = JSONObject().put("peer", "0xPeer").put("dir", "out").put("ts", ts).put("body", body)
        if (sendId != null) e.put("sendId", sendId)
        s.append(e) { done.countDown() }
        assertTrue(done.await(10, TimeUnit.SECONDS))
    }

    private fun read(s: BeamioConetChatHistoryStore, query: String? = null): List<BeamioConetChatHistoryStore.Entry> {
        val done = CountDownLatch(1)
        var out: List<BeamioConetChatHistoryStore.Entry> = emptyList()
        s.read(if (query == null) null else JSONObject().put("query", query)) {
            out = it
            done.countDown()
        }
        assertTrue(done.await(30, TimeUnit.SECONDS))
        return out
    }

    /** Keys of the on-chain head as a fresh device restores it. */
    private fun headKeys(world: FakeWorld): List<String> {
        val reader = store(world)
        reader.syncNowBlocking()
        val keys = read(reader).map { it.sendId }
        reader.destroy()
        return keys
    }

    private fun pe(key: String, ts: Long) = HistoryBatch.PendingEntry(key, "0xpeer", "out", ts, key)

    // ---- pure rules ------------------------------------------------------------------

    @Test
    fun firstEntryPlansWriteTwoToFourMinutesOut() {
        val rnd = Random(5)
        repeat(50) {
            val s = HistoryBatch.PendingState()
            HistoryBatch.enqueue(s, pe("a", 1), 1_000_000, { rnd.nextDouble() }) { false }
            val d = s.dueAt!! - 1_000_000
            assertTrue("delay $d", d in 120_000 until 240_000)
        }
    }

    @Test
    fun tenthEntryPullsWriteToFiveToFortyFiveSeconds() {
        val rnd = Random(9)
        repeat(50) {
            val s = HistoryBatch.PendingState()
            for (i in 0 until HistoryBatch.MAX_ENTRIES) {
                HistoryBatch.enqueue(s, pe("k$i", i.toLong()), 1_000_000L + i, { rnd.nextDouble() }) { false }
            }
            val at10 = 1_000_000L + HistoryBatch.MAX_ENTRIES - 1
            val d = s.dueAt!! - at10
            assertTrue("delay $d", d in 5_000 until 45_000)
            val planned = s.dueAt
            HistoryBatch.enqueue(s, pe("k10", 10), at10 + 1, { rnd.nextDouble() }) { false }
            assertEquals(planned, s.dueAt)
        }
    }

    @Test
    fun duplicateAndCommittedKeysAreSkipped() {
        val s = HistoryBatch.PendingState()
        assertTrue(HistoryBatch.enqueue(s, pe("a", 1), 0, { 0.5 }) { false })
        assertFalse(HistoryBatch.enqueue(s, pe("a", 2), 0, { 0.5 }) { false })
        assertFalse(HistoryBatch.enqueue(s, pe("b", 3), 0, { 0.5 }) { it == "b" })
        assertEquals(1, s.entries.size)
    }

    @Test
    fun timeTriggerKeepsWritesTwoMinutesApart() {
        val s = HistoryBatch.PendingState()
        HistoryBatch.enqueue(s, pe("a", 1), 0, { 0.0 }) { false }
        HistoryBatch.flushSucceeded(s, setOf("a"), 500_000, { 0.0 })
        assertNull(s.dueAt)
        val t = HistoryBatch.PendingState(lastFlushAt = 600_000)
        HistoryBatch.enqueue(t, pe("c", 3), 550_000, { 0.0 }) { false }
        assertEquals(600_000 + HistoryBatch.MIN_INTERVAL_MS, t.dueAt)
    }

    @Test
    fun failureBackoffDoublesAndCaps() {
        val s = HistoryBatch.PendingState()
        HistoryBatch.enqueue(s, pe("a", 1), 0, { 0.5 }) { false }
        val delays = (0 until 8).map {
            HistoryBatch.flushFailed(s, 0, { 0.5 })
            s.dueAt!!
        }
        assertEquals(listOf(30_000L, 60_000, 120_000, 240_000, 480_000, 600_000, 600_000, 600_000), delays)
    }

    @Test
    fun overdueWriteRunsTenToSixtySecondsAfterLaunch() {
        val s = HistoryBatch.PendingState()
        HistoryBatch.enqueue(s, pe("a", 1), 0, { 0.5 }) { false }
        HistoryBatch.resume(s, 10_000_000, { 0.5 })
        assertEquals(10_035_000L, s.dueAt)
    }

    @Test
    fun pendingStateRoundTrips() {
        val s = HistoryBatch.PendingState()
        HistoryBatch.enqueue(s, pe("a", 1), 7, { 0.25 }) { false }
        val back = HistoryBatch.PendingState.fromJson(JSONObject(s.toJson().toString()))!!
        assertEquals(s.entries, back.entries)
        assertEquals(s.dueAt, back.dueAt)
        assertEquals(s.firstPendingAt, back.firstPendingAt)
        assertEquals(s.timeJitterMs, back.timeJitterMs)
    }

    @Test
    fun contentKeyMatchesTsVector() {
        // Same vector as the TS worker test (scripts/testHistoryBatch.ts).
        assertEquals(
            "h:101d8a1062ea26e0fdbfc1ed7e336f3d",
            HistoryBatch.recordKey(null, "0xPeer", "out", 1730000000000, "{\"text\":\"hi\"}"),
        )
        assertEquals("s1", HistoryBatch.recordKey("s1", "0xab", "in", 5, "x"))
    }

    @Test
    fun relayConflictClassification() {
        assertEquals(HistoryBatch.SubmitResult.OK, HistoryBatch.classify(200, ""))
        assertEquals(HistoryBatch.SubmitResult.CONFLICT, HistoryBatch.classify(400, "{\"error\":\"Stale pointer nonce\"}"))
        assertEquals(HistoryBatch.SubmitResult.CONFLICT, HistoryBatch.classify(409, ""))
        assertEquals(HistoryBatch.SubmitResult.CONFLICT, HistoryBatch.classify(400, "ChatIndexRegistry: bad nonce"))
        assertEquals(HistoryBatch.SubmitResult.ERROR, HistoryBatch.classify(403, "Invalid signature"))
        assertEquals(HistoryBatch.SubmitResult.ERROR, HistoryBatch.classify(0, ""))
    }

    // ---- store -----------------------------------------------------------------------

    @Test
    fun appendOnlyQueuesUntilFlush() {
        val world = FakeWorld()
        val s = store(world)
        append(s, "m1", 1)
        append(s, "m2", 2)
        append(s, "m2", 2)
        assertEquals(2, s.pendingCount())
        assertEquals(0, world.uploads)
        assertEquals(0, world.heads.size)
        assertEquals(BeamioConetChatHistoryStore.FlushResult.OK, s.flushNowBlocking())
        assertEquals(1, world.heads.size)
        assertEquals(listOf("m1", "m2"), headKeys(world).sorted())
        assertEquals(BeamioConetChatHistoryStore.FlushResult.EMPTY, s.flushNowBlocking())
        assertEquals(1, world.heads.size)
        s.destroy()
    }

    @Test
    fun uploadClassificationFollowsV2Spec() {
        val h = "0x" + "ab".repeat(32)
        val ok = JSONObject().put("ok", true).put("hash", h).toString()
        assertEquals(HistoryBatch.UploadResult.Ok, HistoryBatch.classifyUpload(200, ok, null, h, false))
        assertEquals(HistoryBatch.UploadResult.Error, HistoryBatch.classifyUpload(200, JSONObject().put("ok", true).put("hash", "0x" + "00".repeat(32)).toString(), null, h, false))
        assertEquals(HistoryBatch.UploadResult.Ok, HistoryBatch.classifyUpload(200, "ok", null, h, true))
        assertEquals(HistoryBatch.UploadResult.LegacyRequired, HistoryBatch.classifyUpload(403, "", null, h, false))
        assertEquals(HistoryBatch.UploadResult.Error, HistoryBatch.classifyUpload(403, "", null, h, true))
        assertEquals(HistoryBatch.UploadResult.RateLimited(12_000), HistoryBatch.classifyUpload(429, "{}", "12", h, false))
        assertEquals(HistoryBatch.UploadResult.RateLimited(3_000), HistoryBatch.classifyUpload(429, "{\"retryAfterSec\":3}", null, h, false))
        assertEquals(HistoryBatch.UploadResult.RateLimited(60_000), HistoryBatch.classifyUpload(429, "", null, h, false))
        for (code in listOf(400, 410, 413, 500)) assertEquals(HistoryBatch.UploadResult.Error, HistoryBatch.classifyUpload(code, "{}", null, h, false))
    }

    @Test
    fun v2UploadsCarryNoWalletAndNeedNoUploadSignature() {
        val world = FakeWorld()
        eip191Messages.clear()
        val s = store(world)
        append(s, "m1", 1)
        append(s, "m2", 2)
        assertEquals(BeamioConetChatHistoryStore.FlushResult.OK, s.flushNowBlocking())
        assertEquals(listOf(false, false, false), world.uploadBodies)
        // Only the history master key derivation asks the PWA to sign; no self-address signature.
        assertEquals(1, eip191Messages.size)
        assertTrue(eip191Messages[0].startsWith("beamio.chat.history.v1|"))
        s.destroy()
    }

    @Test
    fun preV2ServerGetsOne403ThenTheSignedBody() {
        val world = FakeWorld()
        world.server = "legacy"
        eip191Messages.clear()
        val s = store(world)
        append(s, "m1", 1)
        assertEquals(BeamioConetChatHistoryStore.FlushResult.OK, s.flushNowBlocking())
        append(s, "m2", 2)
        assertEquals(BeamioConetChatHistoryStore.FlushResult.OK, s.flushNowBlocking())
        assertEquals(1, world.forbidden)
        assertEquals(listOf(false, true, true, true, true), world.uploadBodies)
        assertEquals(2, eip191Messages.size)
        assertEquals(owner, eip191Messages[1])
        assertEquals(listOf("m1", "m2"), headKeys(world).sorted())
        s.destroy()
    }

    @Test
    fun rateLimitedBatchWaitsForRetryAfter() {
        val world = FakeWorld()
        world.server = "rate_limited"
        val clock = FakeClock(r = { 0.0 })
        val s = store(world, clock = clock)
        append(s, "m1", 1)
        assertEquals(BeamioConetChatHistoryStore.FlushResult.ERROR, s.flushNowBlocking())
        assertEquals(clock.t + 90_000, s.pendingDueAtBlocking())
        world.server = "v2"
        assertEquals(BeamioConetChatHistoryStore.FlushResult.OK, s.flushNowBlocking())
        s.destroy()
    }

    @Test
    fun pointerWriteKeepsOnChainTsAndSeq() {
        val world = FakeWorld()
        world.ts = "1730000000123"
        world.seq = "7"
        val s = store(world)
        append(s, "m1", 1)
        s.flushNowBlocking()
        assertEquals("1730000000123", world.events[0].second)
        assertEquals("7", world.events[0].third)
        s.destroy()
    }

    @Test
    fun queueSurvivesRestartEncrypted() {
        val world = FakeWorld()
        val dir = Files.createTempDirectory("hist").toFile()
        val clock = FakeClock(r = { 0.5 })
        val first = store(world, dir = dir, clock = clock)
        append(first, "m1", 1, "secret-body")
        append(first, null, 2, "no-send-id")
        first.destroy()
        val file = dir.listFiles()!!.single { it.name.startsWith("history-pending-") && it.name.endsWith(".bin") }
        assertFalse(file.readText().contains("secret-body"))
        clock.t += 3_600_000
        val second = store(world, dir = dir, clock = clock)
        assertEquals(2, second.pendingCount())
        assertEquals(clock.t + 35_000, second.pendingDueAtBlocking())
        assertEquals(BeamioConetChatHistoryStore.FlushResult.OK, second.flushNowBlocking())
        assertEquals(2, headKeys(world).size)
        second.destroy()
    }

    @Test
    fun lostAckAfterLandingDoesNotDuplicate() {
        val world = FakeWorld()
        val dir = Files.createTempDirectory("hist").toFile()
        val flaky = store(world, net = world.net(loseAckAfterLanding = true), dir = dir)
        append(flaky, "m1", 1)
        assertEquals(BeamioConetChatHistoryStore.FlushResult.ERROR, flaky.flushNowBlocking())
        flaky.destroy()
        val again = store(world, dir = dir)
        assertEquals(1, again.pendingCount())
        assertEquals(BeamioConetChatHistoryStore.FlushResult.EMPTY, again.flushNowBlocking())
        assertEquals(1, world.heads.size)
        assertEquals(listOf("m1"), headKeys(world))
        again.destroy()
    }

    @Test
    fun offlineBacksOffAndKeepsQueue() {
        val world = FakeWorld()
        val clock = FakeClock(r = { 0.5 })
        val s = store(world, net = world.net(offline = true), clock = clock)
        append(s, "m1", 1)
        assertEquals(BeamioConetChatHistoryStore.FlushResult.ERROR, s.flushNowBlocking())
        assertEquals(clock.t + 30_000, s.pendingDueAtBlocking())
        assertEquals(1, s.pendingCount())
        assertEquals(0, world.heads.size)
        s.destroy()
    }

    @Test
    fun unreadableHeadIsNeverOverwritten() {
        val world = FakeWorld()
        val a = store(world)
        append(a, "a1", 1)
        a.flushNowBlocking()
        val b = store(world, net = world.net(failIndexFetch = true))
        append(b, "b1", 2)
        assertEquals(BeamioConetChatHistoryStore.FlushResult.ERROR, b.flushNowBlocking())
        assertEquals(1, world.heads.size)
        assertEquals(listOf("a1"), headKeys(world))
        a.destroy()
        b.destroy()
    }

    @Test
    fun olderIndexServedUnderHeadHashIsRejected() {
        val world = FakeWorld()
        val a = store(world)
        append(a, "a1", 1)
        a.flushNowBlocking()
        val oldHead = world.indexHash!!
        append(a, "a2", 2)
        a.flushNowBlocking()
        val newHead = world.indexHash!!
        val b = store(world, net = world.net(serveInstead = mapOf(newHead to oldHead)))
        append(b, "b1", 3)
        assertEquals(BeamioConetChatHistoryStore.FlushResult.ERROR, b.flushNowBlocking())
        assertEquals(newHead, world.indexHash)
        assertEquals(listOf("a1", "a2"), headKeys(world).sorted())
        a.destroy()
        b.destroy()
    }

    @Test
    fun readIncludesWaitingEntries() {
        val world = FakeWorld()
        val s = store(world)
        append(s, "m1", 1)
        s.flushNowBlocking()
        append(s, "m2", 2, "hello world")
        assertEquals(listOf("m1", "m2"), read(s).map { it.sendId })
        assertEquals(listOf("m2"), read(s, "hello").map { it.sendId })
        s.destroy()
    }

    @Test
    fun legacyOverwriteRequeuesLostEntries() {
        val world = FakeWorld()
        val a = store(world)
        append(a, "a1", 1)
        a.flushNowBlocking()
        val firstHead = world.indexHash!!
        append(a, "a2", 2)
        a.flushNowBlocking()
        world.legacyOverwrite(firstHead, "1730000000000")
        assertEquals(listOf("a1"), headKeys(world))
        a.syncNowBlocking()
        assertEquals(1, a.pendingCount())
        assertEquals(BeamioConetChatHistoryStore.FlushResult.OK, a.flushNowBlocking())
        assertEquals(listOf("a1", "a2"), headKeys(world).sorted())
        a.destroy()
    }

    @Test
    fun concurrentDevicesLoseNothing() {
        for (seed in 1..40) {
            val rng = Random(seed.toLong())
            val world = FakeWorld(Random(seed * 31L))
            val devices = (0 until 3).map { store(world) }
            val expected = HashSet<String>()
            var ts = 1L
            for (round in 0 until 4) {
                val plans = devices.mapIndexed { d, _ ->
                    val n = rng.nextInt(4)
                    val keys = (0 until n).map { i ->
                        if (rng.nextDouble() < 0.25) "call:$round:$i" else "d$d:r$round:$i"
                    }
                    expected.addAll(keys)
                    keys.map { it to ts++ } to (rng.nextDouble() < 0.7)
                }
                val threads = devices.mapIndexed { d, s ->
                    Thread {
                        for ((k, t) in plans[d].first) append(s, k, t, "$k|from-d$d")
                        if (plans[d].second) s.flushNowBlocking()
                    }.also { it.start() }
                }
                threads.forEach { it.join(60_000) }
            }
            var pass = 0
            while (devices.any { it.pendingCount() > 0 } && pass++ < 10) {
                devices.map { s -> Thread { s.flushNowBlocking() }.also { it.start() } }.forEach { it.join(60_000) }
            }
            assertTrue("seed $seed: queues drained", devices.all { it.pendingCount() == 0 })
            val keys = headKeys(world)
            assertEquals("seed $seed: duplicates", keys.size, keys.toSet().size)
            assertEquals("seed $seed: lost entries", expected, keys.toSet())
            assertTrue("seed $seed: no client clock", world.events.all { it.second == "0" && it.third == "0" })
            devices.forEach { it.destroy() }
        }
    }

    /**
     * Samsung qa4, 2026-11-05: the queue thread was stuck (process frozen / network cut) while
     * the planned write time passed. Every append queued behind it re-armed the timer with
     * delay 0, so 4 flushes ran back to back and the backoff jumped from 30 s to 8 min in 13 ms.
     * A timer task must only write when the planned time has really come.
     */
    @Test
    fun staleTimerTasksDoNotWriteBeforeThePlannedTime() {
        val world = FakeWorld()
        val clock = FakeClock(r = { 0.0 })
        val gate = CountDownLatch(1)
        val firstRead = java.util.concurrent.atomic.AtomicBoolean(true)
        val offline = world.net(offline = true)
        val net = object : HistoryNet by offline {
            override fun readSnapshot(owner: String): HistorySnapshot? {
                if (firstRead.getAndSet(false)) gate.await(10, TimeUnit.SECONDS) else Thread.sleep(50)
                return null
            }
        }
        val failures = java.util.Collections.synchronizedList(ArrayList<String>())
        val s = BeamioConetChatHistoryStore(
            eoa = owner,
            chainId = 224422,
            conetRpcUrl = "mem://rpc",
            ipfsBaseUrl = "mem://ipfs",
            ipfsWriteBaseUrl = null,
            apiBaseUrl = "mem://api",
            registryAddress = "0x1511Caa71081C84d8a591490D1b83879088EED72",
            log = { _, msg -> if (msg.contains("batch write failed")) failures.add(msg) },
            storageDir = null,
            net = net,
            clock = clock,
            signer = signer,
            autoFlush = true,
        )
        val ready = CountDownLatch(1)
        s.prepare { ready.countDown() }
        assertTrue(ready.await(10, TimeUnit.SECONDS))
        append(s, "m1", 1) // plans the write 2 minutes out (jitter 0)
        clock.t += 200_000 // the planned time passes while ...
        val stuck = Thread { s.syncNowBlocking() }.also { it.start() } // ... the queue is stuck on a read
        Thread.sleep(200)
        // Behind it: appends with slow network work in between (as on the phone), so a timer
        // armed with delay 0 fires before the next append re-arms it.
        val queued = CountDownLatch(4)
        val readers = ArrayList<Thread>()
        for (i in 2..5) {
            s.append(JSONObject().put("peer", "0xPeer").put("dir", "out").put("ts", i).put("body", "b$i").put("sendId", "m$i")) {
                queued.countDown()
            }
            readers.add(Thread { s.syncNowBlocking() }.also { it.start() })
            Thread.sleep(50)
        }
        gate.countDown()
        assertTrue(queued.await(10, TimeUnit.SECONDS))
        stuck.join(10_000)
        readers.forEach { it.join(10_000) }
        Thread.sleep(1_000) // let every timer that was armed with delay 0 run
        assertEquals("one write attempt, then backoff: $failures", 1, failures.size)
        assertEquals(5, s.pendingCount())
        s.destroy()
    }
}
