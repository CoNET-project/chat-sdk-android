package network.conet.chat

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
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
 * the module's own `hello` / `unknown_command` answers. Same shared vectors as
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

    @Test
    fun eip191SignAndRecover() {
        val pk = key("wallet", "privateKey").removePrefix("0x")
        assertEquals(key("wallet", "address").lowercase(), call<String> { host.walletAddress(pk, it) })
        val cases = vectors.getJSONArray("eip191")
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            val message = c.getString("message")
            val sig = call<String> { host.signEip191(pk, message, it) }
            assertEquals(message, c.getString("signature"), sig)
            val signer = call<String> { host.verifyMessage(message, sig, it) }
            assertEquals(message, c.getString("signer").lowercase(), signer.lowercase())
        }
    }

    @Test
    fun envelopes() {
        val cases = vectors.getJSONArray("envelopes")
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            val name = c.getString("name")
            val priv = key(c.getString("decryptWith"), "privateArmored")
            val out = call<BeamioOpenPgpHost.DecryptInbound> { host.decryptInboundArmor(priv, "", c.getString("armor"), it) }
            assertEquals("$name armorHash", c.getString("armorHash"), out.armorHash)
            val obj = decodeLiteral(out.text, c.getString("literal"))
            assertTrue("$name structure", jsonEquals(obj, c.getJSONObject("expect")))
            c.optJSONObject("signed")?.let { s ->
                val signer = call<String> { host.verifyMessage(obj.getString(s.getString("textField")), obj.getString(s.getString("signatureField")), it) }
                assertEquals("$name signer", s.getString("signer").lowercase(), signer.lowercase())
            }
            c.optJSONObject("messageJson")?.let { assertTrue("$name message", jsonEquals(JSONObject(obj.getString("message")), it)) }
        }
    }

    @Test
    fun encodersRoundTrip() {
        val cases = vectors.getJSONArray("envelopes")
        val byName = (0 until cases.length()).associate { cases.getJSONObject(it).let { c -> c.getString("name") to c } }
        val route = byName.getValue("routeCommand").getJSONObject("expect")
        val work = byName.getValue("mailboxWork").getJSONObject("expect")
        val routePub = key("routePgp", "publicArmored")
        val routePriv = key("routePgp", "privateArmored")

        val routeArmor = call<String> { host.encryptSignedRouteCommand(route.getString("message"), route.getString("signMessage"), routePub, it) }
        val routeOut = call<BeamioOpenPgpHost.DecryptInbound> { host.decryptInboundArmor(routePriv, "", routeArmor, it) }
        assertTrue("encryptSignedRouteCommand", jsonEquals(decodeLiteral(routeOut.text, "base64-json"), route))

        val workArmor = call<String> { host.wrapArmorToMailboxWork(work.getString("data"), routePub, true, it) }
        val workOut = call<BeamioOpenPgpHost.DecryptInbound> { host.decryptInboundArmor(routePriv, "", workArmor, it) }
        assertTrue("wrapArmorToMailboxWork", jsonEquals(JSONObject(workOut.text), work))
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
        assertEquals("unknown_command", unknown.getString("error"))
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
