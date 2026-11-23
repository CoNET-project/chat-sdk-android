package network.conet.chat.nativekey

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.File
import java.security.MessageDigest

/** The registry reads (§25.42.5 steps 4 and 4.1, §25.42.6) and the cooldown table (§25.42.7), on the JVM without a network. */
class RecoveryRestoreTest {
    private val ep1 = RegistryEndpoint("https://rpc1.conet.network", 12_000)
    private val ep2 = RegistryEndpoint("https://publicrpc.conet.network", 12_000)
    private val config = RegistryConfig("0xfFDc8d2021A41F4638Cb3eCf58B5155383EE9f6d", listOf(ep1, ep2))

    /** A fake JSON-RPC: a per-URL answer, or a failure. Records the URLs it was asked. */
    /** Both endpoints are at block 100 with one hash (review 7, item 2); only the eth_call answers differ per endpoint. */
    private class Fake(
        private val answers: Map<String, () -> Any?>,
        private val url: String,
        private val asked: MutableList<String>,
    ) : AddressPgpRead.Rpc {
        override fun call(method: String, params: JSONArray): Any? = when (method) {
            "eth_blockNumber" -> "0x64"
            "eth_getBlockByNumber" -> JSONObject().put("number", "0x64").put("hash", "0x" + "cd".repeat(32))
            "eth_call" -> {
                asked += url
                answers.getValue(url)()
            }
            else -> error("unexpected $method")
        }
    }

    private fun stringAnswer(s: String): String {
        val b = s.toByteArray(Charsets.UTF_8)
        val pad = (32 - b.size % 32) % 32
        val body = word(b.size.toLong()) + b + ByteArray(pad)
        return "0x" + (word(32) + body).joinToString("") { "%02x".format(it) }
    }

    private fun word(v: Long): ByteArray = ByteArray(32).also { w ->
        for (i in 0 until 8) w[31 - i] = ((v shr (8 * i)) and 0xFF).toByte()
    }

    /** Runs [readAgreed] with a fake RPC per endpoint; the RPC records the endpoint it was built for. */
    private fun read(answers: Map<String, () -> Any?>, cfg: RegistryConfig = config): Pair<String?, List<String>> {
        val asked = mutableListOf<String>()
        val result = AccountRegistryRead.readAgreed(cfg, { ep -> Fake(answers, ep.url, asked) }, "0x")
        return result to asked
    }

    @Test
    fun bothEndpointsAnswerTheSameAndBothAreAsked() {
        val (value, asked) = read(mapOf(ep1.url to { stringAnswer("cipher") }, ep2.url to { stringAnswer("cipher") }))
        assertEquals("cipher", value)
        assertEquals(listOf(ep1.url, ep2.url), asked)
    }

    /** Review 7 item 2: a failing endpoint is no longer a fallback; the read fails (network_error) and no record is claimed. */
    @Test
    fun aFailingEndpointIsAFailureNotAFallback() {
        try {
            read(mapOf(ep1.url to { error("timeout") }, ep2.url to { stringAnswer("cipher") }))
            fail("expected a failure")
        } catch (e: IllegalStateException) {
            // The engine turns any read failure into network_error (RecoveryRestore: "network_error" on every exception).
        }
    }

    @Test
    fun anEmptyAnswerOnBothEndpointsIsNoRecord() {
        val (value, asked) = read(mapOf(ep1.url to { stringAnswer("") }, ep2.url to { stringAnswer("") }))
        assertNull(value)
        assertEquals(listOf(ep1.url, ep2.url), asked)
    }

    /** Review 7 item 2: an empty answer on one endpoint only is never "no record". */
    @Test
    fun anEmptyAnswerOnOneEndpointOnlyIsAFailure() {
        try {
            read(mapOf(ep1.url to { stringAnswer("") }, ep2.url to { stringAnswer("cipher") }))
            fail("expected a failure")
        } catch (e: IllegalStateException) {
            // The engine turns any read failure into network_error (RecoveryRestore: "network_error" on every exception).
        }
    }

    @Test
    fun bothEndpointsFailingIsAFailure() {
        try {
            read(mapOf(ep1.url to { error("down") }, ep2.url to { error("down") }))
            fail("expected a failure")
        } catch (e: IllegalStateException) {
            // The engine turns any read failure into network_error (RecoveryRestore: "network_error" on every exception).
        }
    }

    @Test
    fun theNameCallIsTheSelectorOffsetLengthAndPaddedUtf8() {
        val data = AccountRegistryRead.callDataByAccountName("syn_recover_0001")
        assertEquals(AddressPgpRead.selector("getBase64ByAccountName(string)"), data.substring(0, 10))
        assertEquals("%064x".format(32), data.substring(10, 74))
        assertEquals("%064x".format(16), data.substring(74, 138))
        // "syn_recover_0001" is 16 bytes: the data word is the bytes followed by zeros to 32 bytes.
        val word = data.substring(138)
        assertEquals(64, word.length)
        assertTrue(word.startsWith("73796e5f7265636f7665725f30303031"))
        assertTrue(word.endsWith("0".repeat(32)))
    }

    @Test
    fun theNameCallForAnEmptyNameCarriesZeroLength() {
        assertEquals(10 + 64 + 64, AccountRegistryRead.callDataByAccountName("").length)
    }

    @Test
    fun theNameHashCallCarriesTheIndexUnchanged() {
        val index = ByteArray(32) { (it * 7).toByte() }
        val data = AccountRegistryRead.callDataByNameHash(index)
        assertEquals(AddressPgpRead.selector("getBase64ByNameHash(bytes32)"), data.substring(0, 10))
        assertEquals(index.joinToString("") { "%02x".format(it) }, data.substring(10))
    }

    @Test
    fun theCooldownTableMatchesSpec() {
        assertEquals(0, RecoveryBackoff.cooldownSeconds(4))
        assertEquals(30, RecoveryBackoff.cooldownSeconds(5))
        assertEquals(60, RecoveryBackoff.cooldownSeconds(6))
        assertEquals(300, RecoveryBackoff.cooldownSeconds(7))
        assertEquals(900, RecoveryBackoff.cooldownSeconds(8))
        assertEquals(3600, RecoveryBackoff.cooldownSeconds(9))
        assertEquals(3600, RecoveryBackoff.cooldownSeconds(40))
    }

    @Test
    fun theRemainingCooldownRoundsUpAndEndsAtZero() {
        val store = object : RecoveryFailureStore {
            override fun failures(): Int = 5
            override fun lastFailureAtMs(): Long = 1_000L
            override fun save(failures: Int, atMs: Long) = Unit
            override fun clear() = Unit
        }
        assertEquals(30, RecoveryBackoff.remainingSeconds(store, 1_000L))
        // 29.999 s left rounds up to 30: the countdown never shows 0 while the cooldown lasts.
        assertEquals(30, RecoveryBackoff.remainingSeconds(store, 1_001L))
        assertEquals(29, RecoveryBackoff.remainingSeconds(store, 2_000L))
        assertEquals(1, RecoveryBackoff.remainingSeconds(store, 30_000L))
        assertEquals(0, RecoveryBackoff.remainingSeconds(store, 31_000L))
    }
}
