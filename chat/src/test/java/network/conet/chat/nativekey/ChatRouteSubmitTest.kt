package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** The submission order, the chain confirmation and the 5xx rules (25.52Y.61 第 4 项; PM ruling 2026-11-15). A local stand-in poster only: no real request. */
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
    private val ok = ChatRouteSubmit.Transport.Answer(200, "{\"ok\":true}")
    private val fail5xx = ChatRouteSubmit.Transport.Answer(503, "{}")
    private fun body(attempt: Int) = ChatRouteSubmit.bodyJson(fields + ("nonce" to "0x" + attempt.toString().padStart(32, '0')))
    private fun chain(v: Boolean?) = ChatRouteSubmit.ChainCheck { v }
    private val noPause: (Long) -> Unit = {}

    private fun run(
        answers: List<ChatRouteSubmit.Transport>,
        chainAnswer: Boolean?,
        bases: List<String> = listOf(ip, domain),
        seen: MutableList<String> = mutableListOf(),
    ): ChatRouteSubmit.Outcome {
        var i = 0
        val poster = ChatRouteSubmit.Poster { url, _, _ ->
            seen.add(url)
            answers[minOf(i++, answers.size - 1)]
        }
        return ChatRouteSubmit.submit(bases, ::body, poster, chain(chainAnswer), backoffMs = { 0L }, pause = noPause)
    }

    @Test
    fun ipSuccessIsSubmittedOnlyWhenTheChainShowsIt() {
        val seen = mutableListOf<String>()
        val out = run(listOf(ok), chainAnswer = true, bases = listOf(ip, domain), seen = seen)
        assertEquals(ChatRouteSubmit.Outcome.Submitted, out)
        assertEquals(listOf("$ip${ChatRouteSubmit.PATH}"), seen)
    }

    @Test
    fun ipSuccessNotOnChainIsNetworkUnavailable() {
        assertEquals(ChatRouteSubmit.Outcome.NetworkUnavailable, run(listOf(ok), chainAnswer = false, bases = listOf(ip)))
    }

    @Test
    fun ipSuccessChainUnreadableIsNetworkUnavailable() {
        assertEquals(ChatRouteSubmit.Outcome.NetworkUnavailable, run(listOf(ok), chainAnswer = null, bases = listOf(ip)))
    }

    @Test
    fun ipUnreachableThenDomainSuccessIsSubmittedWithoutChainCheck() {
        val seen = mutableListOf<String>()
        val out = run(listOf(ChatRouteSubmit.Transport.Unreachable, ok), chainAnswer = null, seen = seen)
        assertEquals(ChatRouteSubmit.Outcome.Submitted, out)
        assertEquals(listOf("$ip${ChatRouteSubmit.PATH}", "$domain${ChatRouteSubmit.PATH}"), seen)
    }

    @Test
    fun a4xxIsRefusedAndFinal() {
        val seen = mutableListOf<String>()
        val out = run(listOf(ChatRouteSubmit.Transport.Answer(400, "{\"ok\":false}")), chainAnswer = false, seen = seen)
        assertEquals("chain_refused", (out as ChatRouteSubmit.Outcome.Refused).code)
        assertEquals(1, seen.size)
    }

    @Test
    fun a5xxRegisteredOnChainIsSubmittedWithoutResend() {
        val seen = mutableListOf<String>()
        assertEquals(ChatRouteSubmit.Outcome.Submitted, run(listOf(fail5xx), chainAnswer = true, bases = listOf(domain), seen = seen))
        assertEquals(1, seen.size)
    }

    @Test
    fun a5xxNotRegisteredRetriesWithAFreshSignatureAtMostThreeTimes() {
        val bodies = mutableListOf<String>()
        val poster = ChatRouteSubmit.Poster { _, json, _ ->
            bodies.add(json)
            fail5xx
        }
        val out = ChatRouteSubmit.submit(listOf(domain), ::body, poster, chain(false), backoffMs = { 0L }, pause = noPause)
        assertEquals(ChatRouteSubmit.Outcome.NetworkUnavailable, out)
        assertEquals(1 + ChatRouteSubmit.MAX_5XX_RETRIES, bodies.size)
        assertEquals(bodies.size, bodies.toSet().size) // every attempt carries its own nonce
    }

    @Test
    fun a5xxWithUnreadableChainDoesNotResend() {
        val seen = mutableListOf<String>()
        assertEquals(ChatRouteSubmit.Outcome.NetworkUnavailable, run(listOf(fail5xx), chainAnswer = null, bases = listOf(domain), seen = seen))
        assertEquals(1, seen.size)
    }

    @Test
    fun noAnswerFromBothIsNetworkUnavailable() {
        assertEquals(ChatRouteSubmit.Outcome.NetworkUnavailable, run(listOf(ChatRouteSubmit.Transport.Unreachable), chainAnswer = null))
    }

    @Test
    fun bodyKeysKeepTheFixedOrder() {
        val json = ChatRouteSubmit.bodyJson(fields)
        val order = listOf("wallet", "keyID", "publicKeyArmored", "encrypKeyArmored", "routeKeyID", "timestamp", "nonce", "signature")
        val positions = order.map { json.indexOf("\"$it\":") }
        assertTrue(positions.zipWithNext().all { (a, b) -> a in 0 until b })
    }
}
