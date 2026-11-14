package network.conet.chat.nativekey

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.security.MessageDigest

/**
 * The log-scan pattern file that the SRC-3 scan (`scripts/log-scan.py`) reads. The copy in `spec/` must be the
 * protocol version listed in SHA256-CURRENT (spec r3i), and its digest allowlist must list the purpose vector file.
 */
class LogScanPatternsHashTest {
    private val raw = File(System.getenv("LOG_SCAN_PATTERNS") ?: "../spec/log-scan-patterns.v1.json").readBytes()

    @Test
    fun logScanPatternsAreTheR3ccCanonicalCopy() {
        // The canonical copy interface/protocol/log-scan-patterns.v1.json (spec r3cj, unchanged since r3ch), byte for byte. Previously 90ee2122… (r3ce) and e5d2fa13… (r3cc, which still
        // listed the spec's own hash) and d8cffc70… (r3i, without the chat-route sources).
        val sha = MessageDigest.getInstance("SHA-256").digest(raw).joinToString("") { "%02x".format(it) }
        assertEquals("8169b1bb6389afdbccb92a42348a3a323aa99663c0e4d4d05f2e349bf34dae1b", sha)
    }

    @Test
    fun digestAllowlistListsThePurposeVectorFile() {
        val entries = JSONObject(String(raw, Charsets.UTF_8)).getJSONObject("digestAllowlist").getJSONArray("entries")
        val sums = (0 until entries.length()).map { entries.getJSONObject(it).optString("sha256") }
        assertTrue(sums.contains("c55610e0b0596d79d8bb03ae88fa9ba10809f12d65f5a4e593de1acf579a4ef1"))
        // r3ce (25.52AG.4): the spec's own hash entry is removed; the other 11 entries stay, the two chat-route files among them.
        assertTrue("the spec does not list its own hash", sums.none { it == "0cca7f89bb7a3e83ff9671e8299e538cf1b71c17a6913832923364cc6087dddf" })
        assertTrue(sums.contains("51719937ab141db04694412be9c8d7bcee69db0e1c3a506ada3714d25769f700"))
        assertTrue(sums.contains("a26a24cd0397c280295d7b86df8ea27b733682c5166f99c053f18276840d5bd9"))
        // r3ch (25.52AJ.3): one literal exemption for the test directory file name digest (fceaf6c8…), listed by value. 12 entries.
        assertTrue(sums.contains("fceaf6c89021ad554dd855bd11d2cb71f69170a239b19c5cff7d844b071d5c9e"))
        assertEquals(12, entries.length())
    }
}
