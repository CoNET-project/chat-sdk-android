package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException

/** Every request gets at most one reply, even when the emit that sends it throws (25.52Y.84). */
class SingleReplyTest {
    @Test
    fun aSecondReplyForTheSameRequestIsNotSent() {
        val reply = SingleReply()
        var sent = 0

        assertTrue(reply.once { sent++ })
        assertFalse(reply.once { sent++ })
        assertFalse(reply.once { sent++ })

        assertEquals(1, sent)
        assertTrue(reply.answered)
    }

    /** An emit that throws is one attempted reply: the caller's catch path must not send a second one. */
    @Test
    fun anEmitThatThrowsIsNotFollowedByASecondReply() {
        val reply = SingleReply()
        var sent = 0

        assertTrue(reply.once { sent++; throw IOException("emit failed") })
        // The caller's catch path would answer again with a fallback code; the guard refuses it.
        assertFalse(reply.once { sent++ })

        assertEquals(1, sent)
    }

    @Test
    fun aNewRequestHasItsOwnReply() {
        val first = SingleReply()
        val second = SingleReply()
        var sent = 0

        first.once { sent++ }
        second.once { sent++ }

        assertEquals(2, sent)
        assertFalse(SingleReply().answered)
    }
}
