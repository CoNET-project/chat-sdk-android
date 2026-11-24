package network.conet.chat

import network.conet.chat.localread.LocalChatIds
import network.conet.chat.localread.LocalViewport
import network.conet.chat.nativekey.StoreAccountView
import network.conet.chat.nativekey.StoreSessionAdoption
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
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

/**
 * The history restore on a new device: a head or index that cannot be read, or records that cannot all be held, is never recorded as synced
 * or as "no history", and the retry still follows; an empty head pointer counts only when a second endpoint agrees; and a store account whose session is
 * ready completes init (so its history is pulled at all). A fake chain; no network, relay, key or chat data.
 */
class HistoryRestoreSemanticsTest {
    @get:Rule
    val tmp = TemporaryFolder()

    private val eoa = "0x" + "a1".repeat(20)
    private val peer = "0x" + "c3".repeat(20)
    private val vp = LocalViewport(390.0, 844.0, "portrait", 1.0, 1)

    private class Chain {
        val frags = ConcurrentHashMap<String, String>()
        @Volatile var head: HistorySnapshot? = null
    }

    private class FakeNet(val chain: Chain) : HistoryNet {
        @Volatile var headOnline = true
        @Volatile var fragmentsOnline = true
        /** When set, only these hashes can be fetched (the index, but not the record fragments). */
        @Volatile var onlyHashes: Set<String>? = null
        override fun readSnapshot(owner: String): HistorySnapshot? =
            if (!headOnline) null else chain.head ?: HistorySnapshot(null, "0", "0", "0")
        override fun fetchFragment(hash: String): String? =
            if (!fragmentsOnline || (onlyHashes != null && hash !in onlyHashes!!)) null else chain.frags[hash]
        override fun uploadFragment(cipherB64: String, legacy: LegacyUploadCredential?): HistoryBatch.UploadResult {
            chain.frags[ConetChatCryptoUtil.keccakUtf8Hex(cipherB64)] = cipherB64
            return HistoryBatch.UploadResult.Ok
        }
        override fun submitPointer(owner: String, indexHash: String, ts: String, seq: String, nonce: String, signature: String): HistoryBatch.SubmitResult {
            chain.head = HistorySnapshot(indexHash, ts, seq, BigInteger(nonce).add(BigInteger.ONE).toString())
            return HistoryBatch.SubmitResult.OK
        }
    }

    private object FakeSigner : HistorySigner {
        private fun digest(text: String): String = "0x" + ConetChatCryptoUtil.toHex(MessageDigest.getInstance("SHA-256").digest(text.toByteArray(Charsets.UTF_8)))
        override fun eip191(message: String): String = digest("191|$message")
        override fun eip712(typedData: JSONObject): String = digest("712|$typedData")
    }

    private object FixedClock : HistoryClock {
        override fun now(): Long = 1_767_300_000_000L
        override fun random(): Double = 0.5
        override fun sleep(ms: Long) {}
    }

    private val testKey = ConetChatCryptoUtil.hexToBytes("78c08ce2d2b3fcc5674235d61587b11daebeb0bd4b44a263b827f0ba7743b0bd")!!

    private fun store(dir: File?, net: HistoryNet) = BeamioConetChatHistoryStore(
        eoa = eoa, chainId = 224422, conetRpcUrl = "", ipfsBaseUrl = "", ipfsWriteBaseUrl = null, apiBaseUrl = "",
        registryAddress = "0x1511Caa71081C84d8a591490D1b83879088EED72", log = { _, _ -> }, storageDir = dir,
        sqlDbFactory = { network.conet.chat.localread.JdbcSqlDb.open(it) }, net = net, clock = FixedClock, signer = FakeSigner, autoFlush = false,
        dbRootProvider = { LocalChatIds.rootDbFromPrivateKey(testKey, eoa, "default") },
    )

    private fun prepare(s: BeamioConetChatHistoryStore) {
        val latch = CountDownLatch(1)
        s.prepare { latch.countDown() }
        assertTrue(latch.await(30, TimeUnit.SECONDS))
    }

    private fun append(s: BeamioConetChatHistoryStore, ts: Long, body: String, sendId: String) {
        val latch = CountDownLatch(1)
        s.append(JSONObject().put("peer", peer).put("dir", "in").put("ts", ts).put("body", body).put("sendId", sendId)) { latch.countDown() }
        assertTrue(latch.await(30, TimeUnit.SECONDS))
    }

    private fun fullSync(s: BeamioConetChatHistoryStore): Boolean {
        val latch = CountDownLatch(1)
        var ok = false
        s.startFullSync { ok = it; latch.countDown() }
        assertTrue(latch.await(30, TimeUnit.SECONDS))
        return ok
    }

    private fun seed(chain: Chain) {
        val w = store(null, FakeNet(chain))
        prepare(w)
        append(w, 1000L, "FIXTURE-HIST one", "sid-1")
        append(w, 1001L, "FIXTURE-HIST two", "sid-2")
        append(w, 1002L, "FIXTURE-HIST three", "sid-3")
        assertEquals(BeamioConetChatHistoryStore.FlushResult.OK, w.flushNowBlocking())
    }

    // ---- the failures are not "synced" and not "no history" -------------------------------------------------------------------------

    @Test
    fun aHeadThatCannotBeReadIsSyncFailedAndNeverRecordedAsSyncedOrEmpty() {
        val chain = Chain()
        seed(chain)
        val net = FakeNet(chain).apply { headOnline = false }
        val r = store(tmp.newFolder("r1"), net)
        prepare(r)
        assertFalse("fullSync answers sync_failed", fullSync(r))
        val local = r.localStore()!!
        assertFalse(local.isSyncComplete)
        assertEquals("error", local.syncState)
        assertNotEquals("complete", local.migration)
        val page = local.openConversation(peer, vp)
        assertNotEquals("the page is never told 'end'", "end", page.olderState)
        // The retry (the next sync, once the head is readable) completes it.
        net.headOnline = true
        assertTrue(fullSync(r))
        assertTrue(local.isSyncComplete)
        assertEquals("idle", local.syncState)
        assertEquals("complete", local.migration)
        assertEquals(3, local.openConversation(peer, vp).items.size)
    }

    @Test
    fun recordsThatCannotAllBeFetchedAreIncompleteKeepErrorAndLeaveTheMigrationOpen() {
        val chain = Chain()
        seed(chain)
        // The index is readable but not one record fragment of it: a partial restore, not an unreadable head.
        val net = FakeNet(chain).apply { onlyHashes = setOf(chain.head!!.indexHash!!) }
        val r = store(tmp.newFolder("r2"), net)
        prepare(r)
        assertFalse(fullSync(r))
        val local = r.localStore()!!
        assertFalse("not complete while a record is missing", local.isSyncComplete)
        assertEquals("the state stays error, not idle", "error", local.syncState)
        assertNotEquals("the migration is not marked complete by a partial ingest", "complete", local.migration)
        assertNotEquals("end", local.openConversation(peer, vp).olderState)
        net.onlyHashes = null
        assertTrue(fullSync(r))
        assertTrue(local.isSyncComplete)
        assertEquals("idle", local.syncState)
        assertEquals("complete", local.migration)
        assertEquals(3, local.openConversation(peer, vp).items.size)
    }

    @Test
    fun anOwnerWhoNeverWroteIsNoHistoryOnlyWhenTheHeadReadSaysSo() {
        val chain = Chain()
        val r = store(tmp.newFolder("r3"), FakeNet(chain))
        prepare(r)
        assertTrue(fullSync(r))
        val local = r.localStore()!!
        assertTrue(local.isSyncComplete)
        assertEquals("complete", local.migration)
        assertEquals("end", local.openConversation(peer, vp).olderState)
    }

    // ---- the empty pointer needs a second endpoint -------------------------------------------------------------------------------------

    @Test
    fun anEmptyPointerCountsOnlyWhenTheSecondEndpointAgreesAtTheSameBlock() {
        val zero = "0x" + "0".repeat(64 * 4)
        val hash = "0x" + "ab".repeat(32)
        assertTrue(HistoryEmptyPointer.agree(hash, hash, zero))
        assertFalse("another block hash", HistoryEmptyPointer.agree(hash, "0x" + "cd".repeat(32), zero))
        assertFalse("no block hash", HistoryEmptyPointer.agree(null, hash, zero))
        assertFalse("no answer", HistoryEmptyPointer.agree(hash, hash, null))
        assertFalse("a non-empty pointer", HistoryEmptyPointer.agree(hash, hash, "0x" + "ab".repeat(32) + "0".repeat(64 * 3)))
        assertFalse("a short answer", HistoryEmptyPointer.agree(hash, hash, "0x00"))
    }

    @Test
    fun theSecondEndpointIsAnotherOfficialOneAndNeverThePrimary() {
        assertEquals("https://publicrpc.conet.network", HistoryEmptyPointer.secondEndpoint("https://rpc1.conet.network"))
        assertEquals("https://publicrpc.conet.network", HistoryEmptyPointer.secondEndpoint("https://rpc1.conet.network/"))
        assertEquals("https://rpc1.conet.network", HistoryEmptyPointer.secondEndpoint("https://publicrpc.conet.network"))
        assertEquals("https://rpc1.conet.network", HistoryEmptyPointer.secondEndpoint("https://example.test"))
        assertTrue(File("src/main/java/network/conet/chat/BeamioConetChatHistoryStore.kt").readText().contains("emptyPointerConfirmed(owner, block)"))
    }

    // ---- a store account completes init -------------------------------------------------------------------------------------------------

    @Test
    fun aStoreAccountWithAReadySessionCompletesInit() {
        val plain = StoreAccountView.View.Plain(eoa)
        assertEquals(StoreSessionAdoption.InitStep.FINISH, StoreSessionAdoption.initStep(plain, plainAdopted = true, v3SessionKeyHeld = false))
        assertEquals(StoreSessionAdoption.InitStep.NO_KEY_STORE_ACCOUNT, StoreSessionAdoption.initStep(plain, plainAdopted = false, v3SessionKeyHeld = false))
        val unlocked = StoreAccountView.View.V3(eoa, unlocked = true)
        assertEquals(StoreSessionAdoption.InitStep.FINISH, StoreSessionAdoption.initStep(unlocked, plainAdopted = false, v3SessionKeyHeld = true))
        assertEquals("unlocked but no key to give the signer", StoreSessionAdoption.InitStep.NOT_READY_PASSCODE, StoreSessionAdoption.initStep(unlocked, false, false))
        assertEquals(StoreSessionAdoption.InitStep.NOT_READY_PASSCODE, StoreSessionAdoption.initStep(StoreAccountView.View.V3(eoa, unlocked = false), false, true))
        assertEquals(StoreSessionAdoption.InitStep.NOT_READY_UNREADABLE, StoreSessionAdoption.initStep(StoreAccountView.View.Unknown, false, false))
        assertEquals(StoreSessionAdoption.InitStep.NO_KEY, StoreSessionAdoption.initStep(StoreAccountView.View.None, false, false))
    }

    @Test
    fun theNoKeyBranchOfInitCompletesThroughDoneForAStoreAccount() {
        val module = File("src/main/java/network/conet/chat/BeamioConetChatModule.kt").readText()
        val branch = module.substringAfter("is NativeWalletVault.State.NoKey -> {").substringBefore("is NativeWalletVault.State.Locked -> {")
        assertTrue(branch.contains("StoreSessionAdoption.InitStep.FINISH -> done()"))
        assertTrue("the plain set is adopted before the step is chosen", branch.indexOf("plainAdoption(") in 0 until branch.indexOf("initStep("))
        assertTrue("a v3 set gives the signer its session key only when unlocked", branch.contains("StoreKeyAdapter.sessionKey(currentStore)"))
        assertFalse("the old unconditional no_key for a store account is gone", branch.contains("is StoreAccountView.View.Plain -> ack(reqId, false, error = \"no_key\""))
    }

    // ---- the real network path with a played chain: the second endpoint decides an empty pointer ---------------------------------------

    private val primaryUrl = "https://rpc1.conet.network"
    private val secondUrl = "https://publicrpc.conet.network"
    private val zeroWord = "0x" + "0".repeat(64 * 4)

    /** Plays the two endpoints. [second] answers for the second endpoint: (method) to (status, result JSON); the primary always says empty at block 42. */
    private fun playedChain(secondHash: String = "0x" + "ab".repeat(32), secondStatus: Int = 200, secondPointer: String = zeroWord): (String, String, Int) -> Pair<Int, String> =
        { url, body, _ ->
            val req = JSONObject(body)
            val method = req.getString("method")
            if (url == secondUrl && secondStatus != 200) {
                secondStatus to ""
            } else {
                val result: Any = when (method) {
                    "eth_blockNumber" -> "0x2a"
                    "eth_getBlockByNumber" -> JSONObject().put("number", "0x2a").put("hash", if (url == secondUrl) secondHash else "0x" + "ab".repeat(32))
                    "eth_call" -> if (url == secondUrl) secondPointer else zeroWord
                    else -> "0x"
                }
                200 to JSONObject().put("jsonrpc", "2.0").put("id", 1).put("result", result).toString()
            }
        }

    private fun storeOnPlayedChain(dir: File, transport: (String, String, Int) -> Pair<Int, String>) = BeamioConetChatHistoryStore(
        eoa = eoa, chainId = 224422, conetRpcUrl = primaryUrl, ipfsBaseUrl = "https://ipfs.test", ipfsWriteBaseUrl = null, apiBaseUrl = "https://api.test",
        registryAddress = "0x1511Caa71081C84d8a591490D1b83879088EED72", log = { _, _ -> }, storageDir = dir,
        sqlDbFactory = { network.conet.chat.localread.JdbcSqlDb.open(it) }, net = null, clock = FixedClock, signer = FakeSigner, autoFlush = false,
        dbRootProvider = { LocalChatIds.rootDbFromPrivateKey(testKey, eoa, "default") },
    ).also { it.transport = transport }

    @Test
    fun anEmptyPointerThatTheSecondEndpointConfirmsIsNoHistory() {
        val r = storeOnPlayedChain(tmp.newFolder("p1"), playedChain())
        prepare(r)
        assertTrue(fullSync(r))
        assertTrue(r.localStore()!!.isSyncComplete)
    }

    @Test
    fun anEmptyPointerWhenTheSecondEndpointFailsIsUnknownNotNoHistory() {
        val r = storeOnPlayedChain(tmp.newFolder("p2"), playedChain(secondStatus = 500))
        prepare(r)
        assertFalse(fullSync(r))
        val local = r.localStore()!!
        assertFalse(local.isSyncComplete)
        assertEquals("error", local.syncState)
        assertNotEquals("end", local.openConversation(peer, vp).olderState)
    }

    @Test
    fun anEmptyPointerWhenTheBlockHashDiffersIsUnknownNotNoHistory() {
        val r = storeOnPlayedChain(tmp.newFolder("p3"), playedChain(secondHash = "0x" + "cd".repeat(32)))
        prepare(r)
        assertFalse(fullSync(r))
        assertFalse(r.localStore()!!.isSyncComplete)
    }

    @Test
    fun anEmptyPointerWhenTheSecondEndpointShowsAHeadIsUnknownNotNoHistory() {
        val r = storeOnPlayedChain(tmp.newFolder("p4"), playedChain(secondPointer = "0x" + "ab".repeat(32) + "0".repeat(64 * 3)))
        prepare(r)
        assertFalse(fullSync(r))
        assertFalse(r.localStore()!!.isSyncComplete)
    }

    @Test
    fun theSecondEndpointIsNeverThePrimaryItself() {
        val asked = ArrayList<String>()
        val transport = playedChain()
        val r = storeOnPlayedChain(tmp.newFolder("p5")) { url, body, t ->
            if (JSONObject(body).getString("method") == "eth_getBlockByNumber") asked += url
            transport(url, body, t)
        }
        prepare(r)
        fullSync(r)
        assertEquals(setOf(primaryUrl, secondUrl), asked.toSet())
    }
}
