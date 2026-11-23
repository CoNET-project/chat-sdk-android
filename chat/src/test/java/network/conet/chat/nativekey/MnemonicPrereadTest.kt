package network.conet.chat.nativekey

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/** r2.4.3 sequence rules: a stale request or a late stale pre-read never overwrites a newer result. */
class MnemonicPrereadTest {
    private val oldAnswer = MnemonicPreread.Answer.Valid("0x9858effd232b4033e47d90003d41ec34ecaeda94", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")

    @Before
    fun reset() = MnemonicPreread.resetForTests()

    @After
    fun clear() = MnemonicPreread.resetForTests()

    /** Gives the single pre-read worker time to finish its current task (the pre-read reads are instant here). */
    private fun waitForWorker() = Thread.sleep(150)

    @Test
    fun beforeAnyPrereadFinishesTheAnswerIsUnknownNotEmpty() {
        assertTrue(MnemonicPreread.answer() is MnemonicPreread.Answer.Unknown)
    }

    @Test
    fun aFailedReadIsUnknown() {
        val a = MnemonicPreread.readAnswer { throw IllegalStateException("keystore") }
        assertTrue(a is MnemonicPreread.Answer.Unknown)
    }

    @Test
    fun aCompletedPrereadIsServedUntilAnAcceptedSync() {
        MnemonicPreread.start { oldAnswer }
        waitForWorker()
        assertTrue("the completed pre-read is served", MnemonicPreread.answer() is MnemonicPreread.Answer.Valid)
        assertTrue(MnemonicPreread.accept(1L))
        assertTrue("a sync voids the cached pre-read", MnemonicPreread.answer() is MnemonicPreread.Answer.Unknown)
    }

    /** The late old pre-read: started before the accepted sync, finishes after it. It must not be published. */
    @Test
    fun aLateOldPrereadCannotOverwriteANewerWrite() {
        val started = CountDownLatch(1)
        val release = CountDownLatch(1)
        MnemonicPreread.start {
            started.countDown()
            release.await(5, TimeUnit.SECONDS)
            oldAnswer
        }
        assertTrue(started.await(5, TimeUnit.SECONDS))
        assertTrue(MnemonicPreread.accept(7L))
        val fresh = MnemonicPreread.Answer.Absent
        MnemonicPreread.publishAfterSync(7L, fresh)
        release.countDown()
        waitForWorker()
        val answer = MnemonicPreread.answer()
        assertTrue("the fresh write stays: $answer", answer is MnemonicPreread.Answer.Absent)
    }

    @Test
    fun aStaleSequenceIsRefusedAndVoidsNothing() {
        assertTrue(MnemonicPreread.accept(5L))
        MnemonicPreread.publishAfterSync(5L, oldAnswer)
        assertFalse("an older sequence is stale", MnemonicPreread.accept(4L))
        assertTrue("the newest answer survives a stale request", MnemonicPreread.answer() is MnemonicPreread.Answer.Valid)
        // r2.5.6 SQ-07: an equal sequence is current and accepted (a PWA retry of the same transaction). It voids the cached pre-read,
        // and the sync publishes its read-back again under that sequence.
        assertTrue(MnemonicPreread.accept(5L))
        assertTrue("the equal retry voids the cache", MnemonicPreread.answer() is MnemonicPreread.Answer.Unknown)
        MnemonicPreread.publishAfterSync(5L, oldAnswer)
        assertTrue("republished under the same sequence", MnemonicPreread.answer() is MnemonicPreread.Answer.Valid)
    }

    @Test
    fun aPublishForAnOlderSequenceIsIgnored() {
        assertTrue(MnemonicPreread.accept(3L))
        assertTrue(MnemonicPreread.accept(4L))
        MnemonicPreread.publishAfterSync(3L, oldAnswer)
        assertTrue("the old sequence cannot publish", MnemonicPreread.answer() is MnemonicPreread.Answer.Unknown)
    }
}
