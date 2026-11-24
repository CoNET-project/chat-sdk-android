package network.conet.chat.nativekey

import network.conet.chat.BeamioConetChatProtocol
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.math.BigDecimal
import java.math.BigInteger

/**
 * The request rule of `gossipSign` in a build that does not implement the inbound generation: `inboundGeneration` is required of a deferAck page's
 * envelope or group only when THIS SDK declares `inbound.generation.v1`; when the field appears its type is judged by value, for every page and shell.
 * This build has no inbound generation (no event, no check), so a request is not bound to a generation.
 */
class SignRequestRuleTest {
    private fun req(vararg pairs: Pair<String, Any?>): JSONObject = JSONObject().also { o -> for ((k, v) in pairs) o.put(k, v) }
    private fun nullGen(): JSONObject = JSONObject("{\"inboundGeneration\":null}")

    private fun check(kind: String, r: JSONObject, deferAck: Boolean, declared: Boolean) = SignRequestRule.check(kind, r, deferAck, declared)

    // ---- missing field -------------------------------------------------------------------------------------------------------------------

    @Test
    fun declaredAndDeferAckRequiresTheFieldOnEnvelopeAndGroup() {
        for (kind in listOf("envelope", "group")) assertEquals(kind, "bad_request", check(kind, JSONObject(), deferAck = true, declared = true))
    }

    @Test
    fun notDeclaredTheMissingFieldIsLegal() {
        for (kind in listOf("envelope", "group")) assertNull(kind, check(kind, JSONObject(), deferAck = true, declared = false))
    }

    @Test
    fun anOldPageMayOmitItWhateverTheShellDeclares() {
        for (declared in listOf(true, false)) for (kind in listOf("envelope", "group", "gossip")) {
            assertNull("$kind declared=$declared", check(kind, JSONObject(), deferAck = false, declared = declared))
        }
    }

    @Test
    fun aGossipAckNeverNeedsTheField() {
        for (declared in listOf(true, false)) for (deferAck in listOf(true, false)) {
            assertNull(check("gossip", JSONObject(), deferAck, declared))
        }
    }

    // ---- a present field: by value, in every combination ----------------------------------------------------------------------------------

    private val bad: List<Any?> = listOf(
        "2", "", true, false, -1, -1L, 2.5, -0.5,
        BridgeInteger.MAX_SAFE + 1, Long.MAX_VALUE, 9_007_199_254_740_992.0, 1e300, BigInteger.valueOf(BridgeInteger.MAX_SAFE).add(BigInteger.ONE),
        BigDecimal("2.5"), JSONObject(), org.json.JSONArray(), Any(),
    )
    private val good: List<Any> = listOf(
        0, 0L, 2, 7L, 5.0, 0.0, BridgeInteger.MAX_SAFE, BridgeInteger.MAX_SAFE.toDouble(), BigInteger.valueOf(7), BigDecimal("5.0"), BigDecimal("5"), 3.0f,
    )

    @Test
    fun aWrongTypeIsBadRequestForEveryPageAndEveryDeclaration() {
        for (declared in listOf(true, false)) for (deferAck in listOf(true, false)) for (kind in listOf("envelope", "group", "gossip")) {
            for (v in bad) assertEquals("kind=$kind deferAck=$deferAck declared=$declared value=$v", "bad_request", check(kind, req("inboundGeneration" to v), deferAck, declared))
            assertEquals("an explicit null is a present field of the wrong type", "bad_request", check(kind, nullGen(), deferAck, declared))
        }
    }

    @Test
    fun aValueThatIsAnIntegerIsAcceptedWhateverItsCarrierType() {
        for (declared in listOf(true, false)) for (deferAck in listOf(true, false)) for (kind in listOf("envelope", "group")) {
            for (v in good) assertNull("kind=$kind deferAck=$deferAck declared=$declared value=$v (${v::class.simpleName})", check(kind, req("inboundGeneration" to v), deferAck, declared))
        }
    }

    @Test
    fun theTextualFormsOfAJsonNumber() {
        // What the page's JSON text becomes: an integer literal, a double literal, a string.
        assertNull(check("envelope", JSONObject("{\"inboundGeneration\":5}"), true, true))
        assertNull(check("envelope", JSONObject("{\"inboundGeneration\":5.0}"), true, true))
        assertNull(check("envelope", JSONObject("{\"inboundGeneration\":9007199254740991}"), true, true))
        assertEquals("bad_request", check("envelope", JSONObject("{\"inboundGeneration\":9007199254740992}"), true, true))
        assertEquals("bad_request", check("envelope", JSONObject("{\"inboundGeneration\":2.5}"), true, true))
        assertEquals("bad_request", check("envelope", JSONObject("{\"inboundGeneration\":\"2\"}"), true, true))
        assertEquals("bad_request", check("envelope", JSONObject("{\"inboundGeneration\":true}"), true, false))
    }

    @Test
    fun theIntegerFunctionIsOneReading() {
        assertEquals(5L, BridgeInteger.nonNegativeSafe(5.0))
        assertEquals(0L, BridgeInteger.nonNegativeSafe(0))
        assertEquals(BridgeInteger.MAX_SAFE, BridgeInteger.nonNegativeSafe(BridgeInteger.MAX_SAFE))
        assertNull(BridgeInteger.nonNegativeSafe(BridgeInteger.MAX_SAFE + 1))
        assertNull(BridgeInteger.nonNegativeSafe(true))
        assertNull(BridgeInteger.nonNegativeSafe(null))
        assertNull(BridgeInteger.nonNegativeSafe(JSONObject.NULL))
        // JSONObject cannot hold a non-finite number, so these are judged on the function directly.
        assertNull(BridgeInteger.nonNegativeSafe(Double.NaN))
        assertNull(BridgeInteger.nonNegativeSafe(Double.POSITIVE_INFINITY))
        assertNull(BridgeInteger.nonNegativeSafe(Double.NEGATIVE_INFINITY))
        assertNull(BridgeInteger.nonNegativeSafe(Float.NaN))
        assertNull(BridgeInteger.nonNegativeSafe(-0.5))
        assertEquals(9_007_199_254_740_991L, 9_007_199_254_740_991L) // 2^53 - 1
        assertEquals(1L shl 53, BridgeInteger.MAX_SAFE + 1)
    }

    // ---- sendId and the signed bytes are untouched ----------------------------------------------------------------------------------------

    @Test
    fun theSendIdRuleIsUnchanged() {
        for (declared in listOf(true, false)) {
            assertEquals("bad_request", check("envelope", req("sendId" to ""), false, declared))
            assertEquals("bad_request", check("envelope", req("sendId" to 5), false, declared))
            assertNull(check("envelope", req("sendId" to "s-1", "inboundGeneration" to 2), true, declared))
        }
    }

    // ---- the declaration and the enforcement are one fact ---------------------------------------------------------------------------------

    @Test
    fun theSdkDoesNotDeclareTheCapabilityAndTheRuleReadsThatOneSource() {
        assertFalse("not implemented: not declared", BeamioConetChatProtocol.CAPABILITIES.contains("inbound.generation.v1"))
        assertFalse(BeamioConetChatProtocol.declaresInboundGeneration())
        assertEquals("inbound.generation.v1", BeamioConetChatProtocol.INBOUND_GENERATION_CAPABILITY)
        // With the real declaration (none), the default arguments make a deferAck page's missing field legal: the live behaviour of this build.
        assertNull(SignRequestRule.check("envelope", JSONObject(), pageDeferAck = true))
        assertNull(SignRequestRule.check("group", JSONObject(), pageDeferAck = true))
        // and a wrong type still is not
        assertEquals("bad_request", SignRequestRule.check("envelope", req("inboundGeneration" to "2"), pageDeferAck = true))
        val src = File("src/main/java/network/conet/chat/nativekey/SignRequestRule.kt").readText().lines().filterNot { it.trim().startsWith("*") || it.trim().startsWith("/**") }.joinToString("\n")
        assertTrue("one source: the protocol's own declaration", src.contains("BeamioConetChatProtocol.declaresInboundGeneration()"))
        assertFalse("no second copy of the fact", src.contains("\"inbound.generation.v1\"") || src.contains("shellDeclaresGeneration: Boolean = true"))
        val protocol = File("src/main/java/network/conet/chat/BeamioConetChatProtocol.kt").readText()
        assertTrue(protocol.contains("fun declaresInboundGeneration(): Boolean = CAPABILITIES.contains(INBOUND_GENERATION_CAPABILITY)"))
        // The module calls it with the default: no override at the call site.
        val module = File("src/main/java/network/conet/chat/BeamioConetChatModule.kt").readText()
        assertTrue(module.contains("SignRequestRule.check(kind, body, pageDeferAck)?.let { refusal ->"))
    }

    @Test
    fun theSharedHelloVectorKeepsAndroidWithoutTheCapability() {
        val d = JSONObject(File("../spec/chat-daemon-vectors.v1.json").readText())
        val android = d.getJSONObject("hello").getJSONObject("implementations").getJSONObject("android").getJSONArray("capabilities")
        val names = (0 until android.length()).map { android.getString(it) }
        assertFalse(names.contains("inbound.generation.v1"))
        assertEquals("the live list is what the vector says", names.toSet(), BeamioConetChatProtocol.CAPABILITIES.toSet() - setOf("identity.native-keys.v1", "identity.kpresent.v1") + names.filter { it in setOf("identity.native-keys.v1", "identity.kpresent.v1") }.toSet())
    }
}
