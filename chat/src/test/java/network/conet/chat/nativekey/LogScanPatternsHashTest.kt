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
        // r3el (registry, 2026-11-14): the protocol version is 1c118738… (spec r3rl sync, 2026-11-15); 714b96e2… is withdrawn.
        assertEquals("1c118738c95d4c01ed99ae691ed67abe1a390bedbc2b41f0c417dc6666b341f1", sha)
    }

    @Test
    fun digestAllowlistListsThePurposeVectorFile() {
        // Canonical allowlist (spec r3rl sync): 20 entries. The spec's own hash is not listed (r3ce, 25.52AG.4).
        val entries = JSONObject(String(raw, Charsets.UTF_8)).getJSONObject("digestAllowlist").getJSONArray("entries")
        val sums = (0 until entries.length()).map { entries.getJSONObject(it).optString("sha256") }
        val expected = listOf(
        "7aa7b4dbd93d0d42b594ab18f1d70e85a7d4b9dbba484bd7d6aba4e3851864b9",
        "de5e5d34284db8bc8903879a0ec633fd5d537aa89fdca1e8144cce329c9d4705",
        "0e0a5c88657f1a519254aae8ef9b0218614430d006fd84e58c3415493a5e928b",
        "6bcc5c696519889195f19b744c1e355f19bd031fdb9f673750e5ccf859f8f3a4",
        "369883a3298604ea0285acad1f0fcb747c9bf994bee595d099d04fbe5fc6cac5",
        "d5b9c948672ec1cde8a04c05f04be18aeaa04c375af81918cbb48a846f7c19a7",
        "48ac9bad09f748c7f965ecb42b332d6b4c5d765cc5940f1c98964a3f2e74f007",
        "c55610e0b0596d79d8bb03ae88fa9ba10809f12d65f5a4e593de1acf579a4ef1",
        "51719937ab141db04694412be9c8d7bcee69db0e1c3a506ada3714d25769f700",
        "9f9b7e8cc8df83d29d896c84d4d75687c9fd803b2cb283155e3dcc9fd9a35c2a",
        "86b836ef90586a665acfe1d935e5b3e10236a4cad07e7f93ef252ef4ef82aaef",
        "69b98a727dd85587a76b1a7e9d3a2490574abc37809d6ea27b4293affced3cf3",
        "0ad596aea11a0c67e42f7ec3d6c17b6af44a9e2a5e3ec7c09dc4da6bdbd30983",
        "5004af6d5f63ffaa03ab8bd88c8a3c858a253011dbe370531f70335bbfd3876d",
        "c7382cddccaa5153c81684440b1321b0261ee30c6dc8227437161af72d340811",
        "16856fa46d9d766826253432585fea99fef59e94bf92463c656b49f7f547ac3e",
        "723c2a931f7697851c49a6af5dc6e36442c251f4064dac0a927d868ae9250990",
        "85f5b914af50d8354437dfcfa22ccd7f5c059fb25d6876069fdf67cbf789864d",
        "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda",
        "fceaf6c89021ad554dd855bd11d2cb71f69170a239b19c5cff7d844b071d5c9e",
        )
        assertEquals(expected, sums)
        assertTrue("the spec does not list its own hash", sums.none { it == "0cca7f89bb7a3e83ff9671e8299e538cf1b71c17a6913832923364cc6087dddf" })
    }
}
