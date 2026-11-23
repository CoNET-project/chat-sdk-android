package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.util.concurrent.atomic.AtomicInteger

/** The pre-read starts once from any entry, answers absent on an empty device, and is rebuilt after an accepted sync (E9.x pre-read start fix). */
class MnemonicPrereadStartTest {
    @Before fun reset() {
        MnemonicPreread.resetForTests()
    }

    private fun waitIdle() {
        val deadline = System.currentTimeMillis() + 5_000L
        while (MnemonicPreread.isInFlight() && System.currentTimeMillis() < deadline) Thread.sleep(2)
        assertFalse("read finished", MnemonicPreread.isInFlight())
    }

    @Test fun appForegroundBeforeTheFirstCommandStartsThePreread() {
        val reads = AtomicInteger(0)
        // foreground first (the entry that used to skip the start)
        assertTrue(MnemonicPreread.startIfIdle("foreground") { reads.incrementAndGet(); MnemonicPreread.Answer.Absent })
        // then the first command: already started, no second read
        assertFalse(MnemonicPreread.startIfIdle("command") { reads.incrementAndGet(); MnemonicPreread.Answer.Absent })
        waitIdle()
        assertEquals(1, reads.get())
        assertTrue("empty device answers absent", MnemonicPreread.answer() is MnemonicPreread.Answer.Absent)
    }

    @Test fun anUnknownReadIsNotCachedAndTheNextRequestReadsAgain() {
        val reads = AtomicInteger(0)
        assertTrue(MnemonicPreread.startIfIdle("page") { reads.incrementAndGet(); throw IllegalStateException("read fault") })
        waitIdle()
        assertTrue(MnemonicPreread.answer() is MnemonicPreread.Answer.Unknown)
        assertTrue("the next page request starts a fresh read", MnemonicPreread.startIfIdle("page") { reads.incrementAndGet(); MnemonicPreread.Answer.Absent })
        waitIdle()
        assertEquals(2, reads.get())
        assertTrue(MnemonicPreread.answer() is MnemonicPreread.Answer.Absent)
    }

    @Test fun anAcceptedSyncVoidsTheCacheAndTheIndependentReadRebuildsIt() {
        MnemonicPreread.startIfIdle("command") { MnemonicPreread.Answer.Absent }
        waitIdle()
        assertTrue(MnemonicPreread.answer() is MnemonicPreread.Answer.Absent)
        assertTrue(MnemonicPreread.accept(1L))
        assertTrue("the accepted sync voids the cache", MnemonicPreread.answer() is MnemonicPreread.Answer.Unknown)
        // the sync publishes its own read under its sequence (no cached unknown)
        MnemonicPreread.publishAfterSync(1L, MnemonicPreread.Answer.Absent)
        assertTrue("rebuilt after the sync", MnemonicPreread.answer() is MnemonicPreread.Answer.Absent)
    }

    @Test fun aSyncWithAnUnknownReadLeavesTheCacheEmptyForANewStart() {
        MnemonicPreread.startIfIdle("command") { MnemonicPreread.Answer.Absent }
        waitIdle()
        assertTrue(MnemonicPreread.accept(2L))
        MnemonicPreread.publishAfterSync(2L, MnemonicPreread.Answer.Unknown)
        assertTrue(MnemonicPreread.answer() is MnemonicPreread.Answer.Unknown)
        assertTrue("a page request after an unknown sync starts a read", MnemonicPreread.startIfIdle("page") { MnemonicPreread.Answer.Absent })
        waitIdle()
        assertTrue(MnemonicPreread.answer() is MnemonicPreread.Answer.Absent)
    }
}
