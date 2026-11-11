package network.conet.chat.localread

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** spec r2 section 21 (T-32): the parser samples, plus the parser-missing and bad-bytes paths. */
class MediaManifestTest {
    private fun parse(text: String): ParsedBody = MediaManifestParser.parse(text.toByteArray(Charsets.UTF_8))

    @Test
    fun section21Samples() {
        assertEquals(LocalMediaKind.TEXT, parse("hello").kind)
        assertEquals(LocalMediaKind.TEXT, parse("你好\n第二行").kind)
        val img = parse("""{"v":1,"kind":"image","text":"","media":{"mime":"image/jpeg","size":1,"blob":"b1","width":4,"height":3}}""")
        assertEquals(LocalMediaKind.IMAGE, img.kind)
        assertEquals(4, img.width)
        assertEquals(3, img.height)
        assertFalse(img.failed)
        val vid = parse("""{"v":1,"kind":"video","text":"x","media":{"mime":"video/mp4","size":1,"blob":"b2"}}""")
        assertEquals(LocalMediaKind.VIDEO, vid.kind)
        assertEquals(null, vid.width)
        val bad = parse("""{"v":2,"kind":"image"}""")
        assertEquals(LocalMediaKind.UNKNOWN, bad.kind)
        assertTrue(bad.failed)
        val file = parse("""{"v":1,"kind":"file","text":"","media":{"mime":"application/pdf","size":9,"name":"a.pdf","blob":"b3"}}""")
        assertEquals(LocalMediaKind.FILE, file.kind)
        assertEquals("a.pdf", file.name)
    }

    @Test
    fun invalidManifestsAreUnknownAndFailedNeverText() {
        assertTrue(parse("""{"v":1,"kind":"image","text":"x"}""").failed) // media missing
        assertTrue(parse("""{"v":1,"kind":"audio","text":"x","media":{"mime":"a","size":1,"blob":"b"}}""").failed)
        assertTrue(parse("""{"v":1,"kind":"image","text":"x","media":{"mime":"a","size":"1","blob":"b"}}""").failed)
        assertEquals("manifest_invalid", parse("""{"v":1,"kind":"image","text":"x"}""").error)
    }

    @Test
    fun brace_text_without_manifest_fields_stays_text() {
        assertEquals(LocalMediaKind.TEXT, parse("{not json").kind)
        assertEquals(LocalMediaKind.TEXT, parse("""{"a":1}""").kind)
    }

    @Test
    fun invalidUtf8IsParseError() {
        val p = MediaManifestParser.parse(byteArrayOf(0xC3.toByte(), 0x28))
        assertEquals(LocalMediaKind.UNKNOWN, p.kind)
        assertEquals("parse_error", p.error)
        assertTrue(p.failed)
    }

    @Test
    fun missingParserMakesMediaFailedNotText() {
        val store = LocalChatStore("0xnoparser:default", JdbcSqlDb.memory(), null)
        assertEquals(UnlockResult.OK, store.unlock(ByteArray(32) { 7 }, null))
        store.applyRecord("0xp", IncomingRecord("in", 1L, LocalMediaKind.TEXT, "s1", "plain text", "c1"))
        val item = store.openConversation("0xp", LocalViewport(390.0, 844.0, "portrait", 1.0, 1)).items.single()
        assertEquals(LocalMediaKind.UNKNOWN, item.kind)
        assertEquals("failed", item.mediaState)
        assertEquals(null, item.body)
    }
}
