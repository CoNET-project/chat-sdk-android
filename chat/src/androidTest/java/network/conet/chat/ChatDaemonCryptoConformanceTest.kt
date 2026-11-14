package network.conet.chat

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import network.conet.chat.ConetChatCryptoUtil
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * ChatDaemon protocol v1 conformance (Android, on a device): EIP-191 signing,
 * PGP envelopes and ACK hashes through the module's WebView crypto host, plus
 * the module's own `hello` / `command_rejected` answers (25.52AR.2). Same shared vectors as
 * the JVM test (assets: `chat-daemon-vectors.v1.json`).
 *
 *   ./gradlew :chat:connectedDebugAndroidTest
 */
@RunWith(AndroidJUnit4::class)
class ChatDaemonCryptoConformanceTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val host get() = BeamioOpenPgpHost.shared(context)

    private val vectors: JSONObject by lazy {
        val text = InstrumentationRegistry.getInstrumentation().context.assets
            .open("chat-daemon-vectors.v1.json").bufferedReader(Charsets.UTF_8).readText()
        JSONObject(text)
    }

    private fun key(which: String, field: String): String = vectors.getJSONObject("keys").getJSONObject(which).getString(field)

    private fun <T> call(body: ((Result<T>) -> Unit) -> Unit): T {
        val latch = CountDownLatch(1)
        var out: Result<T>? = null
        body { out = it; latch.countDown() }
        assertTrue("crypto host timed out", latch.await(30, TimeUnit.SECONDS))
        return out!!.getOrThrow()
    }

    private fun decodeLiteral(text: String, encoding: String): JSONObject =
        if (encoding == "base64-json") JSONObject(String(ConetChatCryptoUtil.base64Decode(text), Charsets.UTF_8)) else JSONObject(text)

    /**
     * EIP-191 and the wallet address run in native code (nativekey: Eip191Signer, WalletAddress); the WebView host no
     * longer signs (§35, e69b6c2). The host's `verifyMessage` (public-key recovery) is still checked here.
     */
    @Test
    fun eip191SignAndRecover() {
        val keyBytes = ConetChatCryptoUtil.hexToBytes(key("wallet", "privateKey").removePrefix("0x"))!!
        assertEquals(key("wallet", "address").lowercase(), network.conet.chat.nativekey.WalletAddress.fromPrivateKey(keyBytes))
        val cases = vectors.getJSONArray("eip191")
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            val message = c.getString("message")
            val sig = network.conet.chat.nativekey.Eip191Signer.sign(keyBytes, message.toByteArray(Charsets.UTF_8))
            assertEquals(message, c.getString("signature"), sig)
            val signer = call<String> { host.verifyMessage(message, sig!!, it) }
            assertEquals(message, c.getString("signer").lowercase(), signer.lowercase())
        }
    }

    /**
     * Inbound decryption no longer runs in the WebView host, and the vector keys are no longer passed to it: the PGP
     * private key lives in the native vault (§36-B). The envelope decryption checks (armor hash, literal structure,
     * signer) moved to the JVM test `nativekey/NativePgpVectorsTest`, which runs the native decryption on the same
     * vector file. This test keeps the encoder shape checks only.
     */
    @Test
    fun envelopes() {
        val cases = vectors.getJSONArray("envelopes")
        assertTrue("envelope vectors present", cases.length() > 0)
    }

    @Test
    fun encodersRoundTrip() {
        val cases = vectors.getJSONArray("envelopes")
        val byName = (0 until cases.length()).associate { cases.getJSONObject(it).let { c -> c.getString("name") to c } }
        val route = byName.getValue("routeCommand").getJSONObject("expect")
        val work = byName.getValue("mailboxWork").getJSONObject("expect")
        val routePub = key("routePgp", "publicArmored")

        val routeArmor = call<String> { host.encryptSignedRouteCommand(route.getString("message"), route.getString("signMessage"), routePub, it) }
        assertTrue("encryptSignedRouteCommand armors a PGP message", routeArmor.contains("BEGIN PGP MESSAGE"))

        val workArmor = call<String> { host.wrapArmorToMailboxWork(work.getString("data"), routePub, true, it) }
        assertTrue("wrapArmorToMailboxWork armors a PGP message", workArmor.contains("BEGIN PGP MESSAGE"))
    }

    @Test
    fun moduleAnswersHelloAndUnknownCommands() {
        val acks = java.util.concurrent.ConcurrentHashMap<Int, JSONObject>()
        val latch = CountDownLatch(2)
        val emit: (JSONObject) -> Unit = { payload ->
            val event = payload.optJSONObject("event")
            if (event?.optString("type") == "ack") {
                acks[event.getInt("reqId")] = event
                latch.countDown()
            }
        }
        BeamioConetChatModule.handleCommand(context, JSONObject().put("type", "hello").put("reqId", 41), emit)
        BeamioConetChatModule.handleCommand(context, JSONObject().put("type", "notACommand").put("reqId", 42), emit)
        BeamioConetChatModule.handleCommand(context, JSONObject().put("type", "notACommand").put("reqId", -1), emit)
        assertTrue(latch.await(10, TimeUnit.SECONDS))
        val hello = acks.getValue(41)
        assertTrue(hello.getBoolean("ok"))
        assertTrue(jsonEquals(hello.getJSONObject("result"), BeamioConetChatProtocol.helloResult()))
        val unknown = acks.getValue(42)
        assertEquals(false, unknown.getBoolean("ok"))
        assertEquals("command_rejected", unknown.getString("error"))
    }
}

/** Structural JSON equality (Android's org.json has no `similar`). Numbers compare by value. */
private fun jsonEquals(a: Any?, b: Any?): Boolean = when {
    a is org.json.JSONObject && b is org.json.JSONObject -> {
        val ka = a.keys().asSequence().toSet()
        val kb = b.keys().asSequence().toSet()
        ka == kb && ka.all { jsonEquals(a.opt(it), b.opt(it)) }
    }
    a is org.json.JSONArray && b is org.json.JSONArray ->
        a.length() == b.length() && (0 until a.length()).all { jsonEquals(a.opt(it), b.opt(it)) }
    a is Number && b is Number -> a.toDouble() == b.toDouble() && a.toLong() == b.toLong()
    else -> a == b
}
