package network.conet.chat

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * ChatDaemon protocol v1 conformance (Android, JVM part). Reads the shared
 * vectors `spec/chat-daemon-vectors.v1.json` — a copy of the spec's file in
 * `@conet.project/chat-sdk`, the same vectors the TS Worker and chat-sdk-ios
 * test against. Signing and PGP envelopes run in the WebView and are covered by
 * the instrumented `ChatDaemonCryptoConformanceTest`.
 */
class ChatDaemonConformanceTest {
    private val vectors: JSONObject by lazy {
        val stream = javaClass.classLoader!!.getResourceAsStream("chat-daemon-vectors.v1.json")
            ?: error("chat-daemon-vectors.v1.json missing from test resources")
        JSONObject(stream.bufferedReader(Charsets.UTF_8).readText())
    }

    private fun strings(arr: JSONArray): List<String> = (0 until arr.length()).map { arr.getString(it) }

    @Test
    fun helloMatchesVectors() {
        val hello = vectors.getJSONObject("hello")
        val all = strings(hello.getJSONArray("capabilities"))
        val android = hello.getJSONObject("implementations").getJSONObject("android")
        val result = BeamioConetChatProtocol.helloResult()
        assertEquals(vectors.getInt("protocolVersion"), BeamioConetChatProtocol.PROTOCOL_VERSION)
        assertEquals(android.getInt("protocolVersion"), result.getInt("protocolVersion"))
        assertEquals(android.getInt("minProtocolVersion"), result.getInt("minProtocolVersion"))
        assertEquals("android", result.getString("implementation"))
        // The shared vector lists the production capabilities. A QA build also declares wallet.credential.v1 (spec 25.37.4 第 1 项, 25.52Y.44;
        // PM R2048); the vector has no QA variant yet, so that one bit is added here only when this build is a QA build.
        val expected = strings(android.getJSONArray("capabilities")) +
            (if (BuildConfig.WALLET_CREDENTIAL_QA) listOf("wallet.credential.v1") else emptyList())
        assertEquals(expected, strings(result.getJSONArray("capabilities")))
        for (cap in BeamioConetChatProtocol.CAPABILITIES) {
            // The QA-only bit is not in the shared vector yet (see above); every other declared name must be a spec capability.
            if (cap == BeamioConetChatProtocol.WALLET_CREDENTIAL_CAPABILITY) continue
            assertTrue("$cap is not a spec capability", cap in all)
        }
        assertTrue(Regex("""^\d+\.\d+\.\d+$""").matches(result.getString("sdkVersion")))
    }

    @Test
    fun callSignalClassification() {
        val cases = vectors.getJSONArray("callSignal")
        assertTrue(cases.length() > 0)
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            val name = c.getString("name")
            val line = c.getString("line")
            val got = BeamioConetChatCallSignal.classify(line)
            val expect = c.optJSONObject("expect")
            if (expect == null) {
                assertNull(name, got)
                continue
            }
            assertNotNull(name, got)
            assertEquals(name, expect.getString("kind"), got!!.kind)
            assertEquals(name, expect.getString("type"), got.type)
            assertEquals(name, expect.getString("callId"), got.callId)
            assertEquals(name, expect.getString("sessionId"), got.sessionId)
            assertEquals(name, if (expect.has("rejectReason")) expect.getString("rejectReason") else null, got.rejectReason)
        }
    }

    @Test
    fun wireBuilders() {
        val cases = vectors.getJSONArray("builders")
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            val name = c.getString("name")
            val inp = c.getJSONObject("input")
            val built = when (name) {
                "deliveryAckCommand" ->
                    BeamioConetChatWire.deliveryAckCommand(inp.getString("eoa"), inp.getString("armorHash"), inp.getLong("timestamp"))
                "deliveryReceipt" ->
                    BeamioConetChatWire.deliveryReceipt(inp.getString("sendId"), inp.getString("armorHash"), inp.getLong("deliveredAt"), inp.getString("eoa"))
                "pendingRow" ->
                    BeamioConetChatWire.pendingRow(inp.getString("sendId"), inp.getString("text"), inp.getLong("createdAt"))
                "chatEnvelope" ->
                    BeamioConetChatWire.chatEnvelope(inp.getLong("timestamp"), inp.getString("text"), inp.getString("from"), inp.getString("signMessage"))
                "mailboxWork", "mailboxWorkPush" ->
                    BeamioConetChatWire.mailboxWork(inp.getString("data"), inp.getBoolean("noPush"))
                else -> {
                    fail("no Android builder for $name")
                    continue
                }
            }
            assertTrue("$name: $built", jsonEquals(built, c.getJSONObject("expect")))
        }
    }

    @Test
    fun ackHashes() {
        val cases = vectors.getJSONArray("ackHash")
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            assertEquals(c.getString("name"), c.getString("armorHash"), ConetChatCryptoUtil.keccakUtf8Hex(c.getString("armor")))
        }
        val envelopes = vectors.getJSONArray("envelopes")
        for (i in 0 until envelopes.length()) {
            val e = envelopes.getJSONObject(i)
            assertEquals(e.getString("name"), e.getString("armorHash"), ConetChatCryptoUtil.keccakUtf8Hex(e.getString("armor")))
        }
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
