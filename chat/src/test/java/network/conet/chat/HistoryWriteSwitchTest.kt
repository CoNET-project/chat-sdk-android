package network.conet.chat

import network.conet.chat.localread.JdbcSqlDb
import network.conet.chat.localread.LocalChatIds
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.math.BigInteger
import java.nio.file.Files
import java.security.MessageDigest
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/**
 * R559: the QA switch that stops the history writes. With writesEnabled = false, ten entries and several flushes must make no upload and no
 * pointer submit; the entries stay in the local queue. With writesEnabled = true (the control), the same steps do write, which shows that the
 * setup can write and that the switch is what stops it.
 */
class HistoryWriteSwitchTest {
    private class CountingNet : HistoryNet {
        val uploads = AtomicInteger()
        val submits = AtomicInteger()

        @Volatile
        var head: HistorySnapshot? = null

        override fun readSnapshot(owner: String): HistorySnapshot? = head ?: HistorySnapshot(null, "0", "0", "0")

        override fun fetchFragment(hash: String): String? = null

        override fun uploadFragment(cipherB64: String, legacy: LegacyUploadCredential?): HistoryBatch.UploadResult {
            uploads.incrementAndGet()
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
            submits.incrementAndGet()
            head = HistorySnapshot(indexHash, ts, seq, BigInteger(nonce).add(BigInteger.ONE).toString())
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

    private val eoa = "0x" + "a1".repeat(20)
    private val peer = "0x" + "b2".repeat(20)

    /** Public test key from the spec vectors (not an account key). */
    private val testPrivateKey = ConetChatCryptoUtil.hexToBytes("78c08ce2d2b3fcc5674235d61587b11daebeb0bd4b44a263b827f0ba7743b0bd")!!

    private fun store(dir: File, net: HistoryNet, writesEnabled: Boolean): BeamioConetChatHistoryStore =
        BeamioConetChatHistoryStore(
            eoa = eoa,
            chainId = 224422,
            conetRpcUrl = "",
            ipfsBaseUrl = "",
            ipfsWriteBaseUrl = null,
            apiBaseUrl = "",
            registryAddress = "0x1511Caa71081C84d8a591490D1b83879088EED72",
            log = { _, _ -> },
            storageDir = dir,
            sqlDbFactory = { JdbcSqlDb.open(it) },
            net = net,
            clock = FixedClock,
            signer = FakeSigner,
            autoFlush = false,
            dbRootProvider = { LocalChatIds.rootDbFromPrivateKey(testPrivateKey, eoa, "default") },
            writesEnabled = writesEnabled,
        )

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

    private fun append(s: BeamioConetChatHistoryStore, i: Int) {
        val latch = CountDownLatch(1)
        val o = JSONObject().put("peer", peer).put("dir", "in").put("ts", 1_000_000L + i).put("body", "body $i").put("sendId", "sid-$i")
        s.append(o) { latch.countDown() }
        assertTrue(latch.await(30, TimeUnit.SECONDS))
    }

    /** Ten entries (one batch), then three flushes, the way a timer would make them. */
    private fun runWith(writesEnabled: Boolean): Pair<CountingNet, BeamioConetChatHistoryStore> {
        val net = CountingNet()
        val dir = Files.createTempDirectory("history-switch").toFile()
        val s = store(dir, net, writesEnabled)
        prepare(s)
        for (i in 1..10) append(s, i)
        repeat(3) { s.flushNowBlocking() }
        return net to s
    }

    @Test
    fun withTheSwitchOffNothingIsWrittenAndTheEntriesStayQueued() {
        val (net, s) = runWith(writesEnabled = false)
        assertEquals("fragment and index uploads", 0, net.uploads.get())
        assertEquals("pointer submits", 0, net.submits.get())
        assertEquals("entries kept in the local queue", 10, s.pendingCount())
    }

    @Test
    fun controlWithTheSwitchOnDoesWrite() {
        // The same steps write when the switch is on, so the zero above comes from the switch.
        val (net, _) = runWith(writesEnabled = true)
        assertTrue("uploads with the switch on", net.uploads.get() > 0)
        assertTrue("pointer submits with the switch on", net.submits.get() >= 1)
    }
}
