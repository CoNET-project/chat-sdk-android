package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** The init `ready` answer: an unreadable PGP store is reported as unknown, never as "no PGP". */
class InitReadyAnswerTest {

    @Test
    fun aReadablePgpStoreLeavesTheAnswerAsItWas() {
        val answer = InitReadyAnswer.payload("r-1", pgpStoreUnreadable = false)
        assertEquals("ready", answer.getString("type"))
        assertEquals("r-1", answer.getString("reqId"))
        assertFalse(answer.has(InitReadyAnswer.PGP_STATE))
    }

    @Test
    fun anUnreadablePgpStoreIsReportedAsUnknown() {
        val answer = InitReadyAnswer.payload("r-2", pgpStoreUnreadable = true)
        assertEquals("ready", answer.getString("type"))
        assertEquals("r-2", answer.getString("reqId"))
        assertEquals(InitReadyAnswer.UNREADABLE, answer.getString(InitReadyAnswer.PGP_STATE))
        assertTrue(answer.getString(InitReadyAnswer.PGP_STATE) != "none")
    }
}
