package network.conet.chat

import network.conet.chat.localread.JdbcSqlDb
import network.conet.chat.localread.LocalChatIds
import network.conet.chat.nativekey.NativeDerivation
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.file.Files
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * The fragment key (§25.43.5) is one derivation for three callers: the history write, the history read, and W4 (NativeDerivation). This test
 * writes two entries through the production write path, captures what is uploaded, and reads the fragments back through the production read
 * function ([BeamioConetChatHistoryStore.decryptFragment]). The keys are checked against the derivation vectors (D-01 for the master, D-03 and D-04
 * for the genesis and the first key). The second entry is chained on the first CID, as the store chains it.
 */
class HistoryFragmentDerivationTest {
    /** The expectation object of each derivation case, by id (spec/derivation-vectors.v1.json, r3cb). */
    private val cases: Map<String, JSONObject> by lazy {
        val doc = JSONObject(File("../spec/derivation-vectors.v1.json").readText(Charsets.UTF_8))
        val arr = doc.getJSONArray("cases")
        (0 until arr.length()).associate { i ->
            val c = arr.getJSONObject(i)
            c.getString("id") to c.getJSONObject("expect")
        }
    }

    private val domain = cases.getValue("D-01").getString("domain")
    private val signature = cases.getValue("D-01").getString("S")
    private val eoa = domain.substringAfterLast('|')

    /** Signs only the C1 domain, with the vector S; the store's master is keccak256 of that signature (§25.43.3). */
    private class VectorSigner(private val domain: String, private val sig: String) : HistorySigner {
        override fun eip191(message: String): String {
            check(message == domain) { "only the history domain is signed" }
            return sig
        }
        // The pointer signature is checked by the relay, not here: the stub test net does not verify it, so a deterministic value is enough.
        override fun eip712(typedData: JSONObject): String =
            "0x" + java.security.MessageDigest.getInstance("SHA-256").digest(typedData.toString().toByteArray(Charsets.UTF_8))
                .joinToString("") { "%02x".format(it) }
    }

    private object FixedClock : HistoryClock {
        override fun now(): Long = 1_767_300_000_000L
        override fun random(): Double = 0.5
        override fun sleep(ms: Long) {}
    }

    /** Records every fragment and index upload; serves the pointer like the relay. */
    private class CapturingNet : HistoryNet {
        val uploads = ArrayList<String>()

        @Volatile
        var head: HistorySnapshot? = null

        override fun readSnapshot(owner: String): HistorySnapshot? = head ?: HistorySnapshot(null, "0", "0", "0")

        override fun fetchFragment(hash: String): String? = null

        override fun uploadFragment(cipherB64: String, legacy: LegacyUploadCredential?): HistoryBatch.UploadResult {
            synchronized(uploads) { uploads += cipherB64 }
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
            head = HistorySnapshot(indexHash, ts, seq, (nonce.toBigInteger() + java.math.BigInteger.ONE).toString())
            return HistoryBatch.SubmitResult.OK
        }
    }

    private fun store(net: HistoryNet): BeamioConetChatHistoryStore {
        // The db root only has to exist for the local store to open; the key is a public test value, not the account's.
        val testKey = ConetChatCryptoUtil.hexToBytes("78c08ce2d2b3fcc5674235d61587b11daebeb0bd4b44a263b827f0ba7743b0bd")!!
        return BeamioConetChatHistoryStore(
            eoa = eoa,
            chainId = 224422,
            conetRpcUrl = "",
            ipfsBaseUrl = "",
            ipfsWriteBaseUrl = null,
            apiBaseUrl = "",
            registryAddress = "0x1511Caa71081C84d8a591490D1b83879088EED72",
            log = { _, _ -> },
            storageDir = Files.createTempDirectory("history-fragment").toFile(),
            sqlDbFactory = { JdbcSqlDb.open(it) },
            net = net,
            clock = FixedClock,
            signer = VectorSigner(domain, signature),
            autoFlush = false,
            dbRootProvider = { LocalChatIds.rootDbFromPrivateKey(testKey, eoa, "default") },
            writesEnabled = true,
        )
    }

    private fun prepare(s: BeamioConetChatHistoryStore) {
        val latch = CountDownLatch(1)
        var ok = false
        s.prepare {
            ok = it
            latch.countDown()
        }
        assertTrue(latch.await(30, TimeUnit.SECONDS))
        assertTrue("prepare", ok)
    }

    private fun append(s: BeamioConetChatHistoryStore, body: String, ts: Long) {
        val latch = CountDownLatch(1)
        val o = JSONObject().put("peer", "0xb2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2").put("dir", "in").put("ts", ts)
            .put("body", body).put("sendId", "sid-$ts")
        s.append(o) { latch.countDown() }
        assertTrue(latch.await(30, TimeUnit.SECONDS))
    }

    @Test
    fun theVectorMasterIsTheProtocolRootAndTheFirstFragmentDecryptsWithD04() {
        // D-01: the signature is the vector S; RPROTO is keccak256 of its UTF-8 bytes, and the store's master is the same bytes (§25.43.3).
        val rProto = NativeDerivation.protocolRoot(signature)
        assertEquals(cases.getValue("D-01").getString("RPROTO"), NativeDerivation.hex(rProto))

        val net = CapturingNet()
        val s = store(net)
        prepare(s)
        append(s, "first body", 1_000_000L)
        append(s, "second body", 1_000_001L)
        assertEquals(BeamioConetChatHistoryStore.FlushResult.OK, s.flushNowBlocking())

        // W4 (NativeDerivation) and D-04: the genesis is D-03, and the key of fragment 0 is D-04.
        val genesis = cases.getValue("D-03").getString("genesisCid")
        assertEquals(cases.getValue("D-04").getString("fragKey"), NativeDerivation.hex(NativeDerivation.fragmentKey(rProto, 0, genesis)))

        // The production read function decrypts the uploaded first fragment with the W4 key.
        val first = uploads(net).firstOrNull { readsAs(rProto, 0, genesis, it) } ?: error("no upload decrypts as fragment 0")
        assertEquals("first body", BeamioConetChatHistoryStore.decryptFragment(rProto, 0, genesis, first))
    }

    @Test
    fun aSecondFragmentIsChainedOnTheFirstCidAndReadsBack() {
        val rProto = NativeDerivation.protocolRoot(signature)
        val net = CapturingNet()
        val s = store(net)
        prepare(s)
        append(s, "first body", 1_000_000L)
        append(s, "second body", 1_000_001L)
        assertEquals(BeamioConetChatHistoryStore.FlushResult.OK, s.flushNowBlocking())

        val genesis = cases.getValue("D-03").getString("genesisCid")
        val first = uploads(net).first { readsAs(rProto, 0, genesis, it) }
        // The store's CID of a fragment is keccak256 of its base64 cipher; the next fragment is chained on it.
        val cid0 = ConetChatCryptoUtil.keccakUtf8Hex(first)
        val second = uploads(net).firstOrNull { readsAs(rProto, 1, cid0, it) } ?: error("no upload decrypts as fragment 1 on the first CID")
        assertEquals("second body", BeamioConetChatHistoryStore.decryptFragment(rProto, 1, cid0, second))
        // The W4 function gives the same key for seq 1 on that CID.
        assertEquals(
            NativeDerivation.hex(NativeDerivation.fragmentKey(rProto, 1, cid0)),
            NativeDerivation.hex(ConetChatCryptoUtil.fragmentKey(rProto, 1, cid0)),
        )
    }

    private fun uploads(net: CapturingNet): List<String> = synchronized(net.uploads) { net.uploads.toList() }

    /** True when [cipher] decrypts with the key of (seq, prevCid), through the production read function. */
    private fun readsAs(master: ByteArray, seq: Int, prevCid: String, cipher: String): Boolean =
        runCatching { BeamioConetChatHistoryStore.decryptFragment(master, seq, prevCid, cipher) }.isSuccess
}
