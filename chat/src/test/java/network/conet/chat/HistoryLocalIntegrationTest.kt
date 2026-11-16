package network.conet.chat

import network.conet.chat.localread.LocalChatIds
import network.conet.chat.localread.LocalSource
import network.conet.chat.localread.LocalViewport
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.math.BigInteger
import java.security.MessageDigest
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/**
 * Integration of BeamioConetChatHistoryStore with the local read store, against a fake chain
 * (in-memory fragments and head pointer). No real network, relay, key or chat data.
 * Environment: JVM unit test on the developer host (not a device).
 */
class HistoryLocalIntegrationTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private val eoa = "0x" + "a1".repeat(20)
    private val other = "0x" + "b2".repeat(20)
    private val peer = "0x" + "c3".repeat(20)
    private val vp = LocalViewport(390.0, 844.0, "portrait", 1.0, 1)

    private class Chain {
        val frags = ConcurrentHashMap<String, String>()
        @Volatile
        var head: HistorySnapshot? = null
    }

    private class FakeNet(val chain: Chain) : HistoryNet {
        @Volatile
        var online = true
        @Volatile
        var snapGate: CountDownLatch? = null
        val snapCalls = AtomicInteger()
        val fetchCalls = AtomicInteger()
        val fetched = java.util.concurrent.CopyOnWriteArrayList<String>()

        override fun readSnapshot(owner: String): HistorySnapshot? {
            snapCalls.incrementAndGet()
            snapGate?.await(30, TimeUnit.SECONDS)
            if (!online) return null
            return chain.head ?: HistorySnapshot(null, "0", "0", "0")
        }

        override fun fetchFragment(hash: String): String? {
            fetchCalls.incrementAndGet()
            fetched.add(hash)
            return if (online) chain.frags[hash] else null
        }

        override fun uploadFragment(cipherB64: String, legacy: LegacyUploadCredential?): HistoryBatch.UploadResult {
            if (!online) return HistoryBatch.UploadResult.Error
            chain.frags[ConetChatCryptoUtil.keccakUtf8Hex(cipherB64)] = cipherB64
            return HistoryBatch.UploadResult.Ok
        }

        override fun submitPointer(
            owner: String,
            indexHash: String,
            ts: String,
            seq: String,
            nonce: String,
            signature: String,
        ): HistoryBatch.SubmitResult {
            if (!online) return HistoryBatch.SubmitResult.ERROR
            val next = BigInteger(nonce).add(BigInteger.ONE).toString()
            chain.head = HistorySnapshot(indexHash, ts, seq, next)
            return HistoryBatch.SubmitResult.OK
        }
    }

    private object FakeSigner : HistorySigner {
        private fun digest(text: String): String =
            "0x" + ConetChatCryptoUtil.toHex(MessageDigest.getInstance("SHA-256").digest(text.toByteArray(Charsets.UTF_8)))
        override fun eip191(message: String): String = digest("191|$message")
        override fun eip712(typedData: JSONObject): String = digest("712|$typedData")
    }

    private object FixedClock : HistoryClock {
        override fun now(): Long = 1_767_300_000_000L
        override fun random(): Double = 0.5
        override fun sleep(ms: Long) {}
    }

    /** Public test key from the spec vectors (not an account key). */
    private val testPrivateKey = ConetChatCryptoUtil.hexToBytes("78c08ce2d2b3fcc5674235d61587b11daebeb0bd4b44a263b827f0ba7743b0bd")!!

    private fun store(eoaAddr: String, dir: File?, net: HistoryNet): BeamioConetChatHistoryStore =
        storeWithRoot(eoaAddr, dir, net) { LocalChatIds.rootDbFromPrivateKey(testPrivateKey, eoaAddr, "default") }

    private fun storeWithRoot(eoaAddr: String, dir: File?, net: HistoryNet, root: (() -> ByteArray?)?): BeamioConetChatHistoryStore =
        BeamioConetChatHistoryStore(
            eoa = eoaAddr,
            chainId = 224422,
            conetRpcUrl = "",
            ipfsBaseUrl = "",
            ipfsWriteBaseUrl = null,
            apiBaseUrl = "",
            registryAddress = "0x1511Caa71081C84d8a591490D1b83879088EED72",
            log = { _, _ -> },
            storageDir = dir,
            sqlDbFactory = { network.conet.chat.localread.JdbcSqlDb.open(it) },
            net = net,
            clock = FixedClock,
            signer = FakeSigner,
            autoFlush = false,
            dbRootProvider = root,
        )

    private fun prepare(s: BeamioConetChatHistoryStore) {
        val latch = CountDownLatch(1)
        var ok = false
        s.prepare { ok = it; latch.countDown() }
        assertTrue(latch.await(30, TimeUnit.SECONDS))
        assertTrue("prepare", ok)
    }

    private fun append(s: BeamioConetChatHistoryStore, dir: String, ts: Long, body: String, sendId: String?) {
        val latch = CountDownLatch(1)
        val o = JSONObject().put("peer", peer).put("dir", dir).put("ts", ts).put("body", body)
        if (sendId != null) o.put("sendId", sendId)
        s.append(o) { latch.countDown() }
        assertTrue(latch.await(30, TimeUnit.SECONDS))
    }

    private fun sync(s: BeamioConetChatHistoryStore) {
        val latch = CountDownLatch(1)
        s.startFullSync { latch.countDown() }
        assertTrue(latch.await(30, TimeUnit.SECONDS))
    }

    private fun masterOf(eoaAddr: String): ByteArray =
        ConetChatCryptoUtil.keccak256(FakeSigner.eip191("beamio.chat.history.v1|224422|$eoaAddr").toByteArray(Charsets.UTF_8))

    private fun seedChat(chain: Chain) {
        val w = store(eoa, null, FakeNet(chain))
        prepare(w)
        append(w, "in", 1000L, "FIXTURE-HIST hello one", "sid-1")
        append(w, "out", 1001L, "FIXTURE-HIST hello two", null)
        append(w, "in", 1002L, "FIXTURE-HIST hello three", "sid-3")
        assertEquals(BeamioConetChatHistoryStore.FlushResult.OK, w.flushNowBlocking())
    }

    @Test
    fun syncFillsLocalStoreWithStableIdsAndReadsWork() {
        val chain = Chain()
        seedChat(chain)
        val dir = tmp.newFolder("reader")
        val r = store(eoa, dir, FakeNet(chain))
        prepare(r)
        sync(r)
        val page = r.localStore()!!.openConversation(peer, vp)
        assertEquals(3, page.items.size)
        val rDb = LocalChatIds.rootDbFromPrivateKey(testPrivateKey, eoa, "default")
        val idxKey = LocalChatIds.idxKeyFromRootDb(rDb)
        val idKey = LocalChatIds.idKeyFromRootDb(rDb)
        // spec v1.1 4.3: stable_id = base64url(HMAC(K_idx, sendKey)), 43 characters.
        assertEquals(LocalChatIds.stableIdOf(idxKey, "sid-1"), page.items[0].stableId)
        assertEquals(LocalChatIds.stableIdOf(idxKey, "sid-3"), page.items[2].stableId)
        assertEquals(43, page.items[0].stableId.length)
        // A sendId-less entry gets the derived sendKey as its sendId (spec v1.1 4.2, D10); the stable id follows it.
        val sendKey = LocalChatIds.sendKeyDerived(idKey, peer, "out", 1001L, "FIXTURE-HIST hello two")
        assertEquals(sendKey, page.items[1].sendId)
        assertEquals(LocalChatIds.stableIdOf(idxKey, sendKey), page.items[1].stableId)
        assertEquals("FIXTURE-HIST hello two", page.items[1].body)
        assertEquals("complete", r.localStore()!!.migration)
        assertEquals("idle", page.syncState)
    }

    @Test
    fun readPathNeverCallsNetworkAndWorksOffline() {
        val chain = Chain()
        seedChat(chain)
        val dir = tmp.newFolder("reads")
        val net = FakeNet(chain)
        val r = store(eoa, dir, net)
        prepare(r)
        sync(r)
        net.snapCalls.set(0)
        net.fetchCalls.set(0)
        val s = r.localStore()!!
        assertEquals(3, s.openConversation(peer, vp).items.size)
        val legacy = java.util.concurrent.LinkedBlockingQueue<Int>()
        r.read(JSONObject().put("peer", peer)) { legacy.add(it.size) }
        assertEquals(3, legacy.poll(10, TimeUnit.SECONDS))
        assertEquals("no network on read path: snapshot", 0, net.snapCalls.get())
        assertEquals("no network on read path: fragments", 0, net.fetchCalls.get())
        net.online = false
        assertEquals(3, s.openConversation(peer, vp).items.size)
    }

    @Test
    fun restartOfflineReadsFromSealedFile() {
        val chain = Chain()
        seedChat(chain)
        val dir = tmp.newFolder("restart")
        val first = store(eoa, dir, FakeNet(chain))
        prepare(first)
        sync(first)
        // Second process: nothing synced, network down.
        val offline = FakeNet(chain).apply { online = false }
        val again = store(eoa, dir, offline)
        prepare(again)
        val page = again.localStore()!!.openConversation(peer, vp)
        assertEquals(3, page.items.size)
        assertEquals(0, offline.snapCalls.get())
        assertEquals(0, offline.fetchCalls.get())
    }

    @Test
    fun heldRecordsAreNotDownloadedAgainAfterRestart() {
        val chain = Chain()
        seedChat(chain)
        val dir = tmp.newFolder("held")
        val first = store(eoa, dir, FakeNet(chain))
        prepare(first)
        sync(first)
        val net = FakeNet(chain)
        val again = store(eoa, dir, net)
        prepare(again)
        val out = java.util.concurrent.LinkedBlockingQueue<Int>()
        val done = CountDownLatch(1)
        again.load(JSONObject(), { _, entries, _ -> out.add(entries.size) }, { done.countDown() })
        assertTrue(done.await(30, TimeUnit.SECONDS))
        assertEquals("legacy history emit still delivers the held entries", 3, out.sum())
        // The only fetch allowed is the index head itself; no record fragment is downloaded again (spec 9.2).
        val index = chain.head!!.indexHash
        assertTrue("fetched ${net.fetched}", net.fetched.all { it == index })
    }

    @Test
    fun plaintextNeverReachesTheDisk() {
        val chain = Chain()
        seedChat(chain)
        val dir = tmp.newFolder("disk")
        val r = store(eoa, dir, FakeNet(chain))
        prepare(r)
        sync(r)
        val files = dir.listFiles()!!
        assertTrue(files.any { it.name.startsWith("chat-local-v1-") && it.name.endsWith(".sqlite") })
        for (f in files) {
            val text = String(f.readBytes(), Charsets.ISO_8859_1)
            assertFalse("${f.name} leaks body", text.contains("FIXTURE-HIST"))
            assertFalse("${f.name} leaks sendId", text.contains("sid-1"))
        }
        assertFalse(files.any { it.name.endsWith(".tmp") })
    }

    @Test
    fun syncInFlightDoesNotBlockTheFirstScreen() {
        val chain = Chain()
        seedChat(chain)
        val dir = tmp.newFolder("gate")
        val first = store(eoa, dir, FakeNet(chain))
        prepare(first)
        sync(first)
        val gated = FakeNet(chain)
        val gate = CountDownLatch(1)
        gated.snapGate = gate
        val again = store(eoa, dir, gated)
        prepare(again)
        val syncDone = CountDownLatch(1)
        again.startFullSync { syncDone.countDown() } // blocks inside readSnapshot until the gate opens
        Thread.sleep(100)
        val s = again.localStore()!!
        // T-15 (N5): 30 first-screen reads while the sync is blocked; P95 must stay within 80 ms.
        val times = ArrayList<Long>()
        var last = 0
        repeat(30) {
            val t0 = System.nanoTime()
            val page = s.openConversation(peer, vp)
            times.add((System.nanoTime() - t0) / 1_000)
            last = page.items.size
            assertEquals("running", page.syncState)
        }
        assertEquals(3, last)
        times.sort()
        val p95Ms = times[(times.size * 95) / 100] / 1000.0
        println("LOCALREAD_METRIC gated_first_screen_p95_ms=$p95Ms n=30 env=jvm-host")
        assertTrue("first screen P95 $p95Ms ms while sync was blocked", p95Ms <= 80.0)
        gate.countDown()
        assertTrue(syncDone.await(30, TimeUnit.SECONDS))
    }

    @Test
    fun withoutAWalletRootTheLocalStoreStaysLocked() {
        // The wallet boundary holds no key: the local store refuses to open; sync still runs on the network side.
        val chain = Chain()
        seedChat(chain)
        val dir = tmp.newFolder("noroot")
        val r = storeWithRoot(eoa, dir, FakeNet(chain)) { null }
        prepare(r)
        val page = r.localStore()!!.openConversation(peer, vp)
        assertEquals(LocalSource.LOCKED, page.source)
        assertEquals("db_root_missing", page.error)
        assertTrue(page.items.isEmpty())
        assertFalse(dir.listFiles()!!.any { it.name.endsWith(".sqlite") || it.name.endsWith("-wal") })
    }

    @Test
    fun mirroredTwiceIsStoredOnce() {
        // T-22: the same sendId-less message appended twice is one index record and one stored row.
        val chain = Chain()
        val w = store(eoa, null, FakeNet(chain))
        prepare(w)
        append(w, "in", 3000L, "FIXTURE-HIST mirrored once", null)
        append(w, "in", 3000L, "FIXTURE-HIST mirrored once", null)
        assertEquals(BeamioConetChatHistoryStore.FlushResult.OK, w.flushNowBlocking())
        val dir = tmp.newFolder("mirror")
        val r = store(eoa, dir, FakeNet(chain))
        prepare(r)
        sync(r)
        assertEquals(1, r.localStore()!!.openConversation(peer, vp).items.size)
    }

    @Test
    fun accountsDoNotSeeEachOthersRows() {
        val chain = Chain()
        seedChat(chain)
        val dir = tmp.newFolder("accounts")
        val a = store(eoa, dir, FakeNet(chain))
        prepare(a)
        sync(a)
        val otherChain = Chain()
        val w = store(other, null, FakeNet(otherChain))
        prepare(w)
        append(w, "in", 2000L, "FIXTURE-OTHER only one", "sid-other")
        assertEquals(BeamioConetChatHistoryStore.FlushResult.OK, w.flushNowBlocking())
        val b = store(other, dir, FakeNet(otherChain))
        prepare(b)
        sync(b)
        val bItems = b.localStore()!!.openConversation(peer, vp).items
        assertEquals(1, bItems.size)
        assertEquals("sid-other", bItems[0].sendId)
        assertEquals(3, a.localStore()!!.openConversation(peer, vp).items.size)
        assertEquals("one database file per account", 2, dir.listFiles()!!.count { it.name.endsWith(".sqlite") })
    }

    // ---- pending queue file: an unreadable file is kept and never written over -------------

    private fun pendingFileOf(dir: File): File = File(dir, ChatHistoryFileNames.pendingName(eoa))

    private fun prepareRefused(s: BeamioConetChatHistoryStore) {
        val latch = CountDownLatch(1)
        var ok = true
        s.prepare { ok = it; latch.countDown() }
        assertTrue(latch.await(30, TimeUnit.SECONDS))
        assertFalse("an unreadable pending queue must refuse prepare", ok)
    }

    private fun storeReplacing(eoaAddr: String, dir: File?, net: HistoryNet, replace: (File, File) -> Boolean): BeamioConetChatHistoryStore =
        BeamioConetChatHistoryStore(
            eoa = eoaAddr,
            chainId = 224422,
            conetRpcUrl = "",
            ipfsBaseUrl = "",
            ipfsWriteBaseUrl = null,
            apiBaseUrl = "",
            registryAddress = "0x1511Caa71081C84d8a591490D1b83879088EED72",
            log = { _, _ -> },
            storageDir = dir,
            sqlDbFactory = { network.conet.chat.localread.JdbcSqlDb.open(it) },
            net = net,
            clock = FixedClock,
            signer = FakeSigner,
            autoFlush = false,
            dbRootProvider = { LocalChatIds.rootDbFromPrivateKey(testPrivateKey, eoaAddr, "default") },
            replaceFile = replace,
        )

    @Test
    fun undecryptablePendingFileIsKeptAndPrepareRefuses() {
        val dir = tmp.newFolder("pending-garbage")
        val chain = Chain()
        val w = store(eoa, dir, FakeNet(chain))
        prepare(w)
        append(w, "out", 1000L, "FIXTURE-PENDING queued one", "sid-p1")
        val f = pendingFileOf(dir)
        f.writeText("not-an-encrypted-queue", Charsets.UTF_8)
        prepareRefused(store(eoa, dir, FakeNet(chain)))
        assertEquals("not-an-encrypted-queue", f.readText(Charsets.UTF_8))
    }

    @Test
    fun pendingFileOfAnUnknownFormatIsKeptAndPrepareRefuses() {
        val dir = tmp.newFolder("pending-format")
        val chain = Chain()
        prepare(store(eoa, dir, FakeNet(chain)))
        val key = ConetChatCryptoUtil.hkdf(masterOf(eoa), "pending-enc", 32)
        val future = JSONObject().put("v", 2).put("entries", JSONArray()).toString()
        val f = pendingFileOf(dir)
        f.writeText(ConetChatCryptoUtil.aesGcmEncrypt(key, future.toByteArray(Charsets.UTF_8)), Charsets.UTF_8)
        val before = f.readText(Charsets.UTF_8)
        prepareRefused(store(eoa, dir, FakeNet(chain)))
        assertEquals(before, f.readText(Charsets.UTF_8))
    }

    @Test
    fun failedReplaceKeepsThePreviousPendingFile() {
        val dir = tmp.newFolder("pending-replace")
        val chain = Chain()
        val w = store(eoa, dir, FakeNet(chain))
        prepare(w)
        append(w, "out", 1000L, "FIXTURE-PENDING kept one", "sid-k1")
        val f = pendingFileOf(dir)
        val before = f.readText(Charsets.UTF_8)
        val refusing = storeReplacing(eoa, dir, FakeNet(chain)) { _, _ -> false }
        prepare(refusing)
        append(refusing, "out", 1001L, "FIXTURE-PENDING not replaced", "sid-k2")
        assertEquals(before, f.readText(Charsets.UTF_8))
        prepare(store(eoa, dir, FakeNet(chain)))
    }
}
