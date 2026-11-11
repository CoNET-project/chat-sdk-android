package network.conet.chat.localread

import org.junit.Assume
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.io.FileOutputStream

/**
 * spec r2 20 D-A1 condition (5): measures the snapshot path for a 50k-row library written in 200-row
 * batches: write amplification, cold start (unlock from the sealed file) and heap growth.
 * Gated by env `CHAT_SNAPSHOT_COST=1` (about a minute). JVM on the developer host, not a device.
 */
class SnapshotCostTest {
    @get:Rule
    val tmp = TemporaryFolder()

    @Test
    fun measureSnapshotCostAt50k() {
        Assume.assumeTrue("CHAT_SNAPSHOT_COST not set", System.getenv("CHAT_SNAPSHOT_COST") == "1")
        val master = ByteArray(32) { (it * 13 + 1).toByte() }
        val store = LocalChatStore("0xcost:default")
        assertTrueUnlock(store.unlock(master, null))
        val file = File(tmp.root, "chat-local-v1-cost.sealed")
        val total = 50_000
        var written = 0L
        var batchCount = 0
        val rt = Runtime.getRuntime()
        rt.gc()
        val heapBefore = rt.totalMemory() - rt.freeMemory()
        var heapPeak = heapBefore
        val tWrite0 = System.nanoTime()
        var n = 0
        while (n < total) {
            val end = minOf(total, n + 200)
            for (i in n until end) {
                val conv = "0xconv${i % 10}"
                store.applyRecord(conv, IncomingRecord(if (i % 2 == 0) "in" else "out", 1_700_000_000_000L + i,
                    LocalMediaKind.TEXT, "sid-$i", "FIXTURE-COST message number $i with some words to fill the line", "c$i"))
            }
            n = end
            // Atomic write: tmp, fsync, rename (spec D-A1 condition 3).
            val bytes = store.snapshot()
            written += bytes.size
            batchCount++
            val tmpFile = File(file.parentFile, file.name + ".tmp")
            FileOutputStream(tmpFile).use { out -> out.write(bytes); out.fd.sync() }
            if (file.exists()) file.delete()
            tmpFile.renameTo(file)
            val used = rt.totalMemory() - rt.freeMemory()
            if (used > heapPeak) heapPeak = used
        }
        val writeMs = (System.nanoTime() - tWrite0) / 1_000_000
        val finalBytes = file.length()
        // Cold start: fresh process state, unlock from the sealed file, repeated.
        val times = ArrayList<Long>()
        repeat(5) {
            val fresh = LocalChatStore("0xcost:default")
            val t0 = System.nanoTime()
            val r = fresh.unlock(master, file.readBytes())
            times.add((System.nanoTime() - t0) / 1_000_000)
            check(r == UnlockResult.OK) { "unlock $r" }
        }
        times.sort()
        val amplification = written.toDouble() / finalBytes.toDouble()
        println(
            "LOCALREAD_SNAPSHOT rows=$total batches=$batchCount batchRows=200 finalBytes=$finalBytes " +
                "bytesWritten=$written writeAmplification=${"%.1f".format(amplification)} " +
                "writeTotalMs=$writeMs coldStartMsP50=${times[2]} coldStartMsMax=${times.last()} " +
                "heapGrowthMB=${"%.1f".format((heapPeak - heapBefore) / 1048576.0)} env=jvm-host",
        )
    }

    private fun assertTrueUnlock(r: UnlockResult) {
        check(r == UnlockResult.OK) { "unlock $r" }
    }
}
