package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** The submission order and outcomes (25.52Y.61 第 4 项). A local stand-in poster only: no real request is sent. */
class ChatRouteSubmitTest {
    private val ip = "http://192.0.2.10"
    private val domain = "https://beamio.ca"
    private val fields = mapOf(
        "wallet" to "0x" + "a".repeat(40),
        "keyID" to "0011AABB22CC33DD",
        "publicKeyArmored" to "QUJD",
        "encrypKeyArmored" to "eHl6",
        "routeKeyID" to "route",
        "timestamp" to "1700000000000",
        "nonce" to "0x" + "b".repeat(32),
        "signature" to "0x" + "c".repeat(130),
    )

    @Test
    fun ipUnreachableThenDomainSubmits() {
        val seen = mutableListOf<String>()
        val poster = ChatRouteSubmit.Poster { url, _, _ ->
            seen.add(url)
            if (url.startsWith(ip)) ChatRouteSubmit.Transport.Unreachable else ChatRouteSubmit.Transport.Answer(200, "{\"ok\":true}")
        }
        val out = ChatRouteSubmit.submit(listOf(ip, domain), ChatRouteSubmit.bodyJson(fields), poster)
        assertEquals(ChatRouteSubmit.Outcome.Submitted, out)
        assertEquals(listOf("$ip${ChatRouteSubmit.PATH}", "$domain${ChatRouteSubmit.PATH}"), seen)
    }

    @Test
    fun aServerAnswerIsFinalAndRefuses() {
        var calls = 0
        val poster = ChatRouteSubmit.Poster { _, _, _ ->
            calls++
            ChatRouteSubmit.Transport.Answer(400, "{\"ok\":false}")
        }
        val out = ChatRouteSubmit.submit(listOf(ip, domain), ChatRouteSubmit.bodyJson(fields), poster)
        assertEquals("chain_refused", (out as ChatRouteSubmit.Outcome.Refused).code)
        assertEquals(1, calls)
    }

    @Test
    fun noAnswerFromBothIsNetworkUnavailable() {
        val poster = ChatRouteSubmit.Poster { _, _, _ -> ChatRouteSubmit.Transport.Unreachable }
        assertEquals(ChatRouteSubmit.Outcome.NetworkUnavailable, ChatRouteSubmit.submit(listOf(ip, domain), ChatRouteSubmit.bodyJson(fields), poster))
    }

    @Test
    fun bodyKeysKeepTheFixedOrder() {
        val json = ChatRouteSubmit.bodyJson(fields)
        val order = listOf("wallet", "keyID", "publicKeyArmored", "encrypKeyArmored", "routeKeyID", "timestamp", "nonce", "signature")
        val positions = order.map { json.indexOf("\"$it\":") }
        assertTrue(positions.zipWithNext().all { (a, b) -> a in 0 until b })
    }
}
