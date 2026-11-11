package network.conet.chat

import network.conet.chat.localread.LocalChatIds
import network.conet.chat.localread.LocalViewport
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

    private fun store(eoaAddr: String, dir: File?, net: HistoryNet): BeamioConetChatHistoryStore =
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
            net = net,
            clock = FixedClock,
            signer = FakeSigner,
            autoFlush = false,
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
        assertEquals("sid-1", page.items[0].stableId)
        assertEquals("sid-3", page.items[2].stableId)
        // A sendId-less entry gets the sendId the write path assigns (HistoryBatch.recordKey); the head carries it.
        assertEquals(HistoryBatch.recordKey(null, peer, "out", 1001L, "FIXTURE-HIST hello two"), page.items[1].stableId)
        assertEquals(page.items[1].stableId, page.items[1].sendId)
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
        assertTrue(files.any { it.name.startsWith("chat-local-v1-") && it.name.endsWith(".sealed") })
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
        val t0 = System.nanoTime()
        val page = s.openConversation(peer, vp)
        val ms = (System.nanoTime() - t0) / 1_000_000
        assertEquals(3, page.items.size)
        assertEquals("running", page.syncState)
        assertTrue("first screen took $ms ms while sync was blocked", ms < 50)
        gate.countDown()
        assertTrue(syncDone.await(30, TimeUnit.SECONDS))
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
        assertEquals("sid-other", bItems[0].stableId)
        assertEquals(3, a.localStore()!!.openConversation(peer, vp).items.size)
        assertEquals("one sealed file per account", 2, dir.listFiles()!!.count { it.name.endsWith(".sealed") })
    }

}
