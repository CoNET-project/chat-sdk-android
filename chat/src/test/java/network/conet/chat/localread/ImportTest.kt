package network.conet.chat.localread

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** spec r2 11.1 M2–M3 and 11.2 (`historyImportBatch`, `historyVerifyImport`) on the store. */
class ImportTest {
    private val master = ByteArray(32) { (it * 5 + 9).toByte() }
    private val vp = LocalViewport(390.0, 844.0, "portrait", 1.0, 1)

    private fun store(): LocalChatStore {
        val s = LocalChatStore("0ximp:default")
        assertEquals(UnlockResult.OK, s.unlock(master, null))
        return s
    }

    private fun rows(): List<ImportRow> = listOf(
        ImportRow("0xp", "1767225601234-q9w8e7r6", "out", 1767225601234L, "你好，世界", pendingPublish = false),
        ImportRow("0xp", null, "in", 1767225602000L, "第一行\n第二行", pendingPublish = true),
        ImportRow("0xq", null, "out", 1767225603500L, "{\"v\":1,\"kind\":\"image\",\"text\":\"\",\"media\":{\"mime\":\"image/jpeg\",\"size\":1,\"blob\":\"b\"}}", pendingPublish = false),
    )

    @Test
    fun importIsIdempotentAndDedupesByStableId() {
        val s = store()
        val first = s.importRows(rows())
        assertEquals(3, first.inserted)
        assertEquals(0, first.existing)
        // A second import of the same rows changes nothing (M2 is re-runnable).
        val second = s.importRows(rows())
        assertEquals(0, second.inserted)
        assertEquals(3, second.existing)
        assertEquals(2, s.openConversation("0xp", vp).items.size)
    }

    @Test
    fun pendingRowsSurviveClearAndAreCounted() {
        val s = store()
        s.importRows(rows())
        assertEquals(1, s.pendingCount())
        assertEquals(1, s.clearConversation("0xp"))
    }

    @Test
    fun digestIsStableAcrossRestartAndSensitiveToContent() {
        val s = store()
        s.importRows(rows())
        val before = s.verifyDigest()
        assertEquals(3, before.rows)
        val re = LocalChatStore("0ximp:default")
        assertEquals(UnlockResult.OK, re.unlock(master, s.snapshot()))
        assertEquals(before, re.verifyDigest())
        // A different body under the same sendId changes the digest only when it is a new row; the same row is kept.
        val other = store()
        other.importRows(listOf(ImportRow("0xp", "1767225601234-q9w8e7r6", "out", 1767225601234L, "different", false)))
        assertNotEquals(before.digest, other.verifyDigest().digest)
    }

    @Test
    fun wrongMasterCannotReadTheImportedRows() {
        val s = store()
        s.importRows(rows())
        val other = LocalChatStore("0ximp:default")
        val r = other.unlock(ByteArray(32) { 3 }, s.snapshot())
        assertFalse(r == UnlockResult.OK && other.verifyDigest().rows == 3)
        assertTrue(r == UnlockResult.REBUILT_KCV_MISMATCH || r == UnlockResult.LOCKED_KCV_MISMATCH_PENDING)
    }
}
