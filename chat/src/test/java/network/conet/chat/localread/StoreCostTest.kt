package network.conet.chat.localread

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

/**
 * Cost of the SQLite local store (replaces the snapshot cost test) for a 50k-row library written in
 * 200-row batches through [LocalChatStore.importRows]. Measures: WAL write amplification (bytes appended
 * to the WAL ÷ logical plaintext bytes), the on-disk footprint after a checkpoint, heap growth, cold start
 * (open + unlock + first page, 5 runs, P50 and max) and correctness (row counts, digest, a full paging walk).
 * Gated by env `CHAT_STORE_COST=1`. JVM on the developer host, not a device; device cold start is measured later.
 */
class StoreCostTest {
    @get:Rule
    val tmp = TemporaryFolder()

    private val master = ByteArray(32) { (it * 13 + 1).toByte() }
    private val vp = LocalViewport(390.0, 844.0, "portrait", 1.0, 1)
    private val account = "0xcost:default"
    private val total = 50_000
    private val convCount = 10
    private val batchRows = 200

    @Test
    fun measureStoreCostAt50k() {
        Assume.assumeTrue("CHAT_STORE_COST not set", System.getenv("CHAT_STORE_COST") == "1")
        val file = File(tmp.root, "chat-local-v1-cost.sqlite")
        // Checkpoints off during the write, so the WAL holds every byte the store appended.
        val db = JdbcSqlDb.open(file, walCheckpoints = false)
        val store = LocalChatStore(account, db)
        assertEquals(UnlockResult.OK, store.unlock(master, null))

        val rt = Runtime.getRuntime()
        rt.gc()
        val heapBefore = rt.totalMemory() - rt.freeMemory()
        var heapPeak = heapBefore
        var logicalBytes = 0L
        var batches = 0
        val tWrite0 = System.nanoTime()
        var n = 0
        while (n < total) {
            val end = minOf(total, n + batchRows)
            val rows = ArrayList<ImportRow>(end - n)
            for (i in n until end) {
                val body = "FIXTURE-COST message number $i with some words to fill the line"
                val sid = "sid-$i"
                logicalBytes += body.toByteArray(Charsets.UTF_8).size + sid.toByteArray(Charsets.UTF_8).size
                rows.add(ImportRow("0xconv${i % convCount}", sid, if (i % 2 == 0) "in" else "out",
                    1_700_000_000_000L + i, body, pendingPublish = false))
            }
            val r = store.importRows(rows)
            assertEquals("batch at $n", rows.size, r.inserted)
            n = end
            batches++
            val used = rt.totalMemory() - rt.freeMemory()
            if (used > heapPeak) heapPeak = used
        }
        val importMs = (System.nanoTime() - tWrite0) / 1_000_000
        // The 50k library stands for a finished full sync: older pages end instead of waiting (spec T-23).
        store.markSyncComplete()
        val walBytes = db.walBytes(file)
        // Checkpoint copies the pages into the main file; the main file is then the on-disk footprint.
        db.query("PRAGMA wal_checkpoint(TRUNCATE)", arrayOf())
        val mainBytes = file.length()
        store.lock()

        // Cold start: a fresh handle on the same file, unlock, first page. Five runs.
        val times = ArrayList<Long>()
        repeat(5) {
            val t0 = System.nanoTime()
            val fresh = newFileStore(account, file)
            val r = fresh.unlock(master, null)
            assertEquals(UnlockResult.OK, r)
            val page = fresh.openConversation("0xconv3", vp)
            times.add((System.nanoTime() - t0) / 1_000_000)
            assertTrue(page.items.isNotEmpty())
            fresh.lock()
        }
        times.sort()

        // Correctness on the reopened file.
        val reread = newFileStore(account, file)
        assertEquals(UnlockResult.OK, reread.unlock(master, null))
        val rowsTotal = (0 until convCount).sumOf { reread.rowCount("0xconv$it") }
        assertEquals(total, rowsTotal)
        val digest = reread.verifyDigest()
        assertEquals(total, digest.rows)
        // Full paging walk of one conversation: every row exactly once, no error, the oldest reached.
        val conv = "0xconv0"
        var page = reread.openConversation(conv, vp)
        val seen = HashSet<String>()
        var walked = page.items.size
        seen.addAll(page.items.map { it.stableId })
        var walkPages = 1
        while (page.hasOlder) {
            val cursor = checkNotNull(page.olderCursor) { "no cursor while olderState=${page.olderState}" }
            page = reread.loadOlder(conv, cursor, vp)
            assertNull(page.error)
            walked += page.items.size
            seen.addAll(page.items.map { it.stableId })
            walkPages++
        }
        assertEquals(reread.rowCount(conv), walked)
        assertEquals(walked, seen.size)
        reread.lock()

        val amplification = walBytes.toDouble() / logicalBytes.toDouble()
        val footprint = mainBytes.toDouble() / logicalBytes.toDouble()
        println(
            "LOCALREAD_STORE_COST rows=$total batches=$batches batchRows=$batchRows convs=$convCount " +
                "logicalBytes=$logicalBytes walBytes=$walBytes walWriteAmplification=${"%.2f".format(amplification)} " +
                "mainFileBytes=$mainBytes footprintRatio=${"%.2f".format(footprint)} " +
                "importTotalMs=$importMs coldStartMsP50=${times[2]} coldStartMsMax=${times.last()} " +
                "heapGrowthMB=${"%.1f".format((heapPeak - heapBefore) / 1048576.0)} " +
                "digestRows=${digest.rows} walkConv=$conv walkRows=$walked walkPages=$walkPages env=jvm-host",
        )
    }
}
