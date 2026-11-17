package network.conet.chat

import network.conet.chat.BeamioConetChatModule.Node
import network.conet.chat.BeamioConetChatModule.PostOutcome
import network.conet.chat.BeamioConetChatModule.runEntries
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The post to entries: the error code the send ack carries, the counts in the summary line, and the attempt limits.
 * Pure: the wrap and the POST are doubles. Synthetic TEST-NET-3 IPs and a synthetic key.
 */
class PostOutcomeTest {
    private val key = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nSYNTHETIC\n-----END PGP PUBLIC KEY BLOCK-----"
    private val neverOver = { false }

    private fun nodes(n: Int): List<Node> = (10 until 10 + n).map { Node("203.0.113.$it", "d$it", "", key) }

    @Test
    fun noCandidatesIsNoKeyedEntryAndNothingIsAttempted() {
        var attempts = 0
        val out = runEntries(emptyList(), neverOver, { attempts++; "x" }, { _, _ -> attempts++; true })
        assertEquals(PostOutcome(false, "no_keyed_entry"), out)
        assertEquals(0, attempts)
    }

    @Test
    fun everyWrapFailingIsEntriesExhaustedWithTheCountsAndNoPost() {
        var posts = 0
        val out = runEntries(nodes(2), neverOver, { null }, { _, _ -> posts++; true })
        assertEquals("entries_exhausted", out.error)
        assertFalse(out.ok)
        assertEquals(2, out.candidates)
        assertEquals(2, out.wrapFailed)
        assertEquals(0, out.postFailed)
        assertEquals(0, posts)
    }

    @Test
    fun everyPostFailingIsEntriesExhaustedWithPostCounts() {
        val out = runEntries(nodes(2), neverOver, { "wrapped" }, { _, _ -> false })
        assertEquals("entries_exhausted", out.error)
        assertEquals(0, out.wrapFailed)
        assertEquals(2, out.postFailed)
    }

    @Test
    fun aLaterEntryCanSucceedAfterAFailedPost() {
        val posted = mutableListOf<String>()
        val out = runEntries(nodes(3), neverOver, { "w-${it.ip}" }, { n, _ ->
            posted += n.ip
            n.ip == "203.0.113.11"
        })
        assertTrue(out.ok)
        assertNull(out.error)
        assertEquals(1, out.postFailed)
        assertEquals(listOf("203.0.113.10", "203.0.113.11"), posted)
    }

    @Test
    fun atMostFourEntriesAreTried() {
        var attempts = 0
        val out = runEntries(nodes(6), neverOver, { attempts++; null }, { _, _ -> true })
        assertEquals(4, attempts)
        assertEquals(6, out.candidates)
        assertEquals(4, out.wrapFailed)
        assertEquals("entries_exhausted", out.error)
    }

    @Test
    fun theBudgetStopsBeforeTheNextEntry() {
        var attempts = 0
        val out = runEntries(nodes(3), { true }, { attempts++; "x" }, { _, _ -> true })
        assertEquals(0, attempts)
        assertEquals("entries_exhausted", out.error)
        assertEquals(3, out.candidates)
    }

    @Test
    fun theSummaryLineHasCountsAndCodesOnly() {
        val line = BeamioConetChatModule.postSummaryLine(
            PostOutcome(false, "entries_exhausted", candidates = 3, wrapFailed = 1, postFailed = 2),
            elapsedMs = 1234L,
        )
        assertEquals(
            "post_to_entries: candidates=3 wrap_failed=1 post_failed=2 elapsed_ms=1234 ok=false error=entries_exhausted",
            line,
        )
        assertFalse(line.contains("BEGIN PGP"))
    }
}
