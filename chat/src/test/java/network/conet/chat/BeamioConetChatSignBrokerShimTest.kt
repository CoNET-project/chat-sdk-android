package network.conet.chat

import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * The two compatibility shims that the application still calls (§38): `requestEip191(text, timeoutMs)` and
 * `hasLocalSigner()`. Neither takes a key, neither opens a key path, and both delegate to the native methods. The test key
 * is the spec's synthetic test key (`spec/gossip-sign-vectors.v1.json`, not a wallet).
 */
@Suppress("DEPRECATION")
class BeamioConetChatSignBrokerShimTest {
    private val key: String =
        JSONObject(File("../spec/gossip-sign-vectors.v1.json").readText(Charsets.UTF_8)).getString("privateKeyHex")

    @After
    fun clearTheKey() = BeamioConetChatSignBroker.clearNativeSigner()

    /** Calls the shim (with its timeout) and returns what the completion received, or null if it did not run. */
    private fun shim(timeoutMs: Long, message: String): Result<String>? {
        var out: Result<String>? = null
        BeamioConetChatSignBroker.requestEip191(message, timeoutMs) { out = it }
        return out
    }

    private fun native(message: String): Result<String>? {
        var out: Result<String>? = null
        BeamioConetChatSignBroker.requestEip191(message) { out = it }
        return out
    }

    @Test
    fun theShimWithoutANativeKeyFailsNotReadyAtOnce() {
        BeamioConetChatSignBroker.clearNativeSigner()
        val r = shim(10_000L, "hello")
        assertNotNull("the completion must run at once", r)
        assertTrue(r!!.isFailure)
        assertEquals("not_ready", r.exceptionOrNull()?.message)
    }

    @Test
    fun theShimSignsTheSameAsTheNativeMethod() {
        BeamioConetChatSignBroker.setNativeSigner(ConetChatCryptoUtil.hexToBytes(key)!!)
        val viaShim = shim(10_000L, "hello")
        val viaNative = native("hello")
        assertNotNull(viaShim)
        assertNotNull(viaNative)
        assertTrue("shim: ${viaShim!!.exceptionOrNull()}", viaShim.isSuccess)
        assertEquals(viaNative!!.getOrThrow(), viaShim.getOrThrow())
        // EIP-191 signature: 0x + 65 bytes.
        assertTrue(viaShim.getOrThrow().matches(Regex("^0x[0-9a-fA-F]{130}$")))
    }

    @Test
    fun theTimeoutIsIgnored() {
        BeamioConetChatSignBroker.setNativeSigner(ConetChatCryptoUtil.hexToBytes(key)!!)
        val expected = native("timeout probe")!!.getOrThrow()
        for (timeout in listOf(0L, 1L, -1L, 10_000L, Long.MAX_VALUE)) {
            val r = shim(timeout, "timeout probe")
            assertNotNull("timeout $timeout: the completion must run at once", r)
            assertEquals("timeout $timeout", expected, r!!.getOrThrow())
        }
    }

    @Test
    fun hasLocalSignerIsTheNativeKeyAnswerAndNothingElse() {
        BeamioConetChatSignBroker.clearNativeSigner()
        assertFalse(BeamioConetChatSignBroker.hasLocalSigner())
        assertEquals(BeamioConetChatSignBroker.hasNativeSigner(), BeamioConetChatSignBroker.hasLocalSigner())

        BeamioConetChatSignBroker.setNativeSigner(ConetChatCryptoUtil.hexToBytes(key)!!)
        assertTrue(BeamioConetChatSignBroker.hasLocalSigner())
        assertEquals(BeamioConetChatSignBroker.hasNativeSigner(), BeamioConetChatSignBroker.hasLocalSigner())

        BeamioConetChatSignBroker.clearNativeSigner()
        assertFalse(BeamioConetChatSignBroker.hasLocalSigner())
    }

    @Test
    fun theShimsTakeNoKeyParameter() {
        // Reflection on the public surface: the timeout overload is (String, long, function); the alias takes nothing.
        val methods = BeamioConetChatSignBroker::class.java.declaredMethods
        val shim = methods.filter { it.name == "requestEip191" && it.parameterTypes.size == 3 }
        assertEquals("one timeout overload", 1, shim.size)
        val types = shim[0].parameterTypes.map { it.name }
        assertEquals(listOf("java.lang.String", "long", "kotlin.jvm.functions.Function1"), types)
        val alias = methods.filter { it.name == "hasLocalSigner" }
        assertEquals("one alias", 1, alias.size)
        assertEquals(0, alias[0].parameterTypes.size)
    }

    @Test
    fun theSourceHasExactlyTheTwoApprovedShimsAndNoKeyPath() {
        val src = File("src/main/java/network/conet/chat/BeamioConetChatSignBroker.kt").readText()
        assertEquals("two @Deprecated shims", 2, Regex("@Deprecated\\(").findAll(src).count())
        assertTrue(src.contains("fun requestEip191(message: String, timeoutMs: Long, completion: (Result<String>) -> Unit) {"))
        assertTrue(src.contains("fun hasLocalSigner(): Boolean = hasNativeSigner()"))
        // The shim lines never mention a key.
        for (line in src.lines().filter { it.contains("fun requestEip191(message: String, timeoutMs") || it.contains("fun hasLocalSigner") }) {
            assertFalse(line, line.contains("privateKey", ignoreCase = true))
        }
        // The only public key-taking function is the native setter the module already used.
        val keyFuns = Regex("fun (\\w+)\\([^)]*(?i:privatekey|key)[^)]*\\)").findAll(src).map { it.groupValues[1] }.toList()
        assertEquals(listOf("setNativeSigner"), keyFuns)
    }
}
