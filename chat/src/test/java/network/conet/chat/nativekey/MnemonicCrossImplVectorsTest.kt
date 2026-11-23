package network.conet.chat.nativekey

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test
import java.security.MessageDigest

/**
 * Cross-implementation vectors for the mnemonic-to-EOA rule (2026-11-18, review r95). The vectors are byte-identical copies in
 * src/test/resources/vectors/, read from the classpath; each file's SHA-256 is asserted before use. A missing resource or a different
 * hash fails the build; nothing is skipped and no environment variable changes the lookup.
 *  - vectors/VECTORS-mnemonic-eoa-crossimpl.json (23 cases, public BIP-39 test phrases; expected EOA also derived with ethers 6.16.0);
 *  - vectors/VECTORS-mnemonic-eoa-random1000.json (1000 seeded phrases, 200 each for 12/15/18/21/24 words).
 * TEST DATA ONLY: public seeds, never funded, never on chain, not tied to any account. The generator is
 * chat/tools/test-vectors/gen-random-mnemonic-vectors.cjs (its SHA-256 is recorded in the random file header).
 *
 * SDK rule (MnemonicDerivation): trim ASCII whitespace; lower-case; split on JavaScript whitespace; NFKD per word; count 12/15/18/21/24;
 * English list; checksum. `pwa_sync_emits` is PWA_SYNC_RE (pwaWalletSyncTransport.ts:22) applied to the trimmed input.
 */
class MnemonicCrossImplVectorsTest {
    companion object {
        private const val CROSSIMPL = "VECTORS-mnemonic-eoa-crossimpl.json"
        private const val CROSSIMPL_SHA = "170ca427206544e3634704c8393c0987ef32e698f60736bf1c7b6ae1f3845b78"
        private const val RANDOM = "VECTORS-mnemonic-eoa-random1000.json"
        private const val RANDOM_SHA = "44f6270e0ed652e214ecaf3c743936b2cde21233c5c09c314747e92bbc3827fd"
        private val PWA_SYNC_RE = Regex("[a-z]+( [a-z]+)*")
    }

    private fun sha256Hex(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

    /** Reads a vector resource and asserts its SHA-256 first. A missing resource is an error (never skipped). */
    private fun loadVerified(name: String, expectedSha: String): JSONArray {
        val stream = javaClass.classLoader!!.getResourceAsStream("vectors/$name")
        assertNotNull("vector resource missing: vectors/$name", stream)
        val bytes = stream!!.use { it.readBytes() }
        assertEquals("SHA-256 of $name", expectedSha, sha256Hex(bytes))
        return JSONObject(String(bytes, Charsets.UTF_8)).getJSONArray("cases")
    }

    private fun runVectors(cases: JSONArray): Int {
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            val id = c.getString("id")
            val input = c.getString("input")
            val accept = c.getBoolean("sdk_accept")
            val key = MnemonicDerivation.deriveKey(input)
            try {
                assertEquals("$id: pwa_sync_emits", c.getBoolean("pwa_sync_emits"), PWA_SYNC_RE.matches(input.trim()))
                if (!accept) {
                    assertNull("$id: must be rejected", key)
                    continue
                }
                assertNotNull("$id: must be accepted", key)
                assertEquals("$id: EOA", c.getString("expected_eoa"), WalletAddress.fromPrivateKey(key!!))
                assertEquals("$id: canonical", c.getString("sdk_canonical"), MnemonicDerivation.canonicalPhrase(input))
            } finally {
                key?.fill(0)
            }
        }
        return cases.length()
    }

    @Test
    fun crossImplVectorsMatchTheSdk() {
        assertEquals(23, runVectors(loadVerified(CROSSIMPL, CROSSIMPL_SHA)))
    }

    @Test
    fun random1000VectorsMatchTheSdk() {
        val cases = loadVerified(RANDOM, RANDOM_SHA)
        assertEquals(1000, runVectors(cases))
        val counts = (0 until cases.length()).map { cases.getJSONObject(it).getInt("word_count") }.groupingBy { it }.eachCount()
        assertEquals(mapOf(12 to 200, 15 to 200, 18 to 200, 21 to 200, 24 to 200), counts)
    }
}
