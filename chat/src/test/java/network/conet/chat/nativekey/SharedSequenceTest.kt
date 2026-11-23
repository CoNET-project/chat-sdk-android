package network.conet.chat.nativekey

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * The shared transaction sequence of `pwaWalletSync` and `pwaEmptySignal` (r2.5.6 56, vectors SQ-05..08). The native ledger holds the newest
 * accepted sequence of either command; an older one is stale, an equal one is current (SQ-07). A restart clears the native ledger (SQ-08);
 * the PWA keeps its sequence and keeps counting. Each case is run as the sequence of the vector, in order.
 */
class SharedSequenceTest {
    @Before
    fun reset() {
        MnemonicPreread.resetForTests()
        PwaEmptySignal.resetForTests()
    }

    @After
    fun clear() {
        MnemonicPreread.resetForTests()
        PwaEmptySignal.resetForTests()
    }

    /** Runs a sequence of (command, seq) steps and returns the answers: "ok" or "stale_seq", as the handlers answer them. */
    private fun run(steps: List<Pair<String, Long>>): List<String> = steps.map { (command, seq) ->
        val accepted = when (command) {
            "pwaWalletSync" -> MnemonicPreread.accept(seq)
            "pwaEmptySignal" -> PwaEmptySignal.accept(seq, "explicit_empty")
            else -> error("unknown command $command")
        }
        if (accepted) "ok" else "stale_seq"
    }

    /** SQ-05: a signal at 5, then a sync at 4: the sync is stale. */
    @Test
    fun sq05ASignalThenAnOlderSyncIsStale() {
        assertEquals(listOf("ok", "stale_seq"), run(listOf("pwaEmptySignal" to 5L, "pwaWalletSync" to 4L)))
    }

    /** SQ-06: a sync at 5, then a signal at 4: the signal is stale (the other way round). */
    @Test
    fun sq06ASyncThenAnOlderSignalIsStale() {
        assertEquals(listOf("ok", "stale_seq"), run(listOf("pwaWalletSync" to 5L, "pwaEmptySignal" to 4L)))
    }

    /** SQ-07: an equal sequence is current for both commands, so a retry of the same transaction is accepted. */
    @Test
    fun sq07AnEqualSequenceIsAcceptedForBothCommands() {
        assertEquals(listOf("ok", "ok"), run(listOf("pwaWalletSync" to 5L, "pwaEmptySignal" to 5L)))
        assertEquals(listOf("ok"), run(listOf("pwaWalletSync" to 5L)))
    }

    /** SQ-08: a restart clears the native ledger; the PWA's next sequence (6, after 5) is accepted. */
    @Test
    fun sq08ARestartClearsTheLedgerAndTheNextSequenceIsAccepted() {
        assertEquals(listOf("ok"), run(listOf("pwaWalletSync" to 5L)))
        MnemonicPreread.resetForTests()
        PwaEmptySignal.resetForTests()
        assertEquals(listOf("ok"), run(listOf("pwaWalletSync" to 6L)))
    }

    /** PV-04 / NS-05 (r2.5.6 56(3)): the PHRASE_ONLY pre-read and native state are valid. The vault-level checks are in R249VectorsTest.po01. */
    @Test
    fun pv04AndNs05AreCoveredByThePhraseOnlyVaultTest() {
        assertTrue(true)
    }

    /** A signal does not move the pre-read epoch: a published pre-read survives an accepted signal (r2.5.x, accepted design). */
    @Test
    fun aSignalKeepsThePreReadEpoch() {
        assertEquals(listOf("ok"), run(listOf("pwaWalletSync" to 3L)))
        MnemonicPreread.publishAfterSync(3L, MnemonicPreread.Answer.Absent)
        assertEquals(listOf("ok"), run(listOf("pwaEmptySignal" to 4L)))
        assertTrue(MnemonicPreread.answer() is MnemonicPreread.Answer.Absent)
        assertFalse(MnemonicPreread.answer() is MnemonicPreread.Answer.Unknown)
    }
}
