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
        // r3dm (R700, R693): the protocol version is 884391e5…; the previous 8169b1bb… is withdrawn.
        // r3dp (R705): the protocol version is c2df8584…; 884391e5… is withdrawn.
        // r3dz (R721, R722): the protocol version is 273947fe…; c2df8584… is withdrawn.
        // r3eh (registry, 2026-11-14): the protocol version is 9803a2ba…; 62ae7afd… and 6e38a8ad… are withdrawn.
        // r3el (registry, 2026-11-14): the protocol version is 2b4f0f1d…; 714b96e2… is withdrawn.
        assertEquals("2b4f0f1d34bac9d72c05012213b6c4ad9f95cfcb41a14e75be4fb8cf8f16dac5", sha)
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
        // r3dm: the no-key and gate vector values are the current ones (R690 rule, 25.52BO and BP).
        assertTrue(sums.contains("6ec280f7b1afe018cf608ca8f438dc83c6531620a6e650e086959559718f32d8"))
        assertTrue(sums.contains("3c77e9ce497a16bd5140acc7307e3b8e812ddb9b8d0bd754e038cd940e101c22"))
        // r3dp: the negative tests file (25.52BS) is listed too: 13 entries.
        // r3eg: the negative tests file is 340fb917… (was a7a2246d…); r3dy adds table-T (c5e54b94…): 14 entries.
        assertTrue(sums.contains("f71ddd75b225b79d81716e0fc16fef88f8a783c4ea56221b6ca9c87fc61e4689"))
        assertTrue(sums.contains("b4085becedde13e91363bb5239be5552c80146603ebfc4fd0a167b44c349d983"))
        // r3ed, r3el: the domain tags vector file (01a77f65…) is listed too: 15 entries.
        assertTrue(sums.contains("01a77f6514225aa4045bbefb08664ed325ab142e6faad14fb071c0511d9ff651"))
        assertEquals(15, entries.length())
    }
}
