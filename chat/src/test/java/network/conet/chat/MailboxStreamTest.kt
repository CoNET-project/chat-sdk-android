package network.conet.chat

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Mailbox listen stream frames sealed by CoNET-SI (`mailboxStream.ts`) must
 * open here byte for byte. Vectors were produced by the SI implementation.
 */
class MailboxStreamTest {
    private val vectors: JSONObject by lazy {
        val stream = javaClass.classLoader!!.getResourceAsStream("mailbox-stream-vectors.v1.json")
            ?: error("mailbox-stream-vectors.v1.json missing from test resources")
        JSONObject(stream.bufferedReader().readText())
    }

    private val key: ByteArray by lazy { ConetChatCryptoUtil.base64Decode(vectors.getString("keyBase64")) }

    @Test
    fun opensFramesSealedByTheMailbox() {
        val frames = vectors.getJSONArray("frames")
        for (i in 0 until frames.length()) {
            val f = frames.getJSONObject(i)
            assertEquals(f.getString("json"), BeamioConetChatListenSession.openStreamFrame(f.getString("sealed"), key))
        }
    }

    @Test
    fun tamperedFrameIsDropped() {
        assertNull(BeamioConetChatListenSession.openStreamFrame(vectors.getString("tampered"), key))
    }

    @Test
    fun wrongKeyIsDropped() {
        val sealed = vectors.getJSONArray("frames").getJSONObject(0).getString("sealed")
        assertNull(BeamioConetChatListenSession.openStreamFrame(sealed, ByteArray(32) { 7 }))
    }

    @Test
    fun plainFrameIsDropped() {
        assertNull(BeamioConetChatListenSession.openStreamFrame(vectors.getString("plain"), key))
    }
}
