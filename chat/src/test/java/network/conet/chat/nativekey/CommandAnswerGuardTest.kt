package network.conet.chat.nativekey

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** A request gets exactly one answer from the command guard: the first decision for its id, and none for a request without an id. */
class CommandAnswerGuardTest {

    @Test
    fun aRequestIdIsAnsweredOnlyOnce() {
        val answered = HashSet<String>()
        assertTrue(CommandAnswerGuard.firstAnswer(answered, "r-1"))
        assertFalse(CommandAnswerGuard.firstAnswer(answered, "r-1"))
    }

    @Test
    fun anIntegerRequestIdIsKeyedLikeItsText() {
        val answered = HashSet<String>()
        assertTrue(CommandAnswerGuard.firstAnswer(answered, 7))
        assertFalse(CommandAnswerGuard.firstAnswer(answered, "7"))
    }

    @Test
    fun aRequestWithoutAnIdOwesNoAnswer() {
        val answered = HashSet<String>()
        assertFalse(CommandAnswerGuard.firstAnswer(answered, null))
        assertFalse(CommandAnswerGuard.firstAnswer(answered, JSONObject.NULL))
        assertTrue(answered.isEmpty())
    }

    @Test
    fun aJsonNullIdHasNoKey() {
        assertNull(CommandAnswerGuard.keyOf(JSONObject.NULL))
        assertEquals("x", CommandAnswerGuard.keyOf("x"))
    }
}
