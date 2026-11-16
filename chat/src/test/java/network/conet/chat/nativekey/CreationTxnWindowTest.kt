package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** The creation transaction window (25.52Y.54 PY.18(b), AK-42): on for ten minutes after it is set, and ended at once when set off. */
class CreationTxnWindowTest {
    @Test
    fun isOnForTheWindowAndOffAfterIt() {
        var now = 1_000L
        val w = CreationTxnWindow { now }
        assertFalse(w.get())
        w.set(true)
        assertTrue(w.get())
        now += CreationTxnWindow.WINDOW_MS - 1
        assertTrue(w.get())
        now += 1
        assertFalse(w.get())
    }

    @Test
    fun setOffEndsItAtOnce() {
        var now = 0L
        val w = CreationTxnWindow { now }
        w.set(true)
        w.set(false)
        assertFalse(w.get())
    }

    @Test
    fun theWindowIsTenMinutes() {
        assertEquals(600_000L, CreationTxnWindow.WINDOW_MS)
    }
}
