package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

/**
 * The submission rules of 25.52Y.63 and 25.52Y.64. The names IP-01 to IP-07 are the v2 vector IDs (`ipSubmitVerificationCases`). The vector file is
 * not yet run from this module, so these are rule-level tests and do not claim a vector PASS. No real request is sent.
 */
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
    private val fiveXx = ChatRouteSubmit.Transport.Answer(503, "{}")
    private val timeout = ChatRouteSubmit.Transport.Ambiguous
    private fun body(attempt: Int) = ChatRouteSubmit.bodyJson(fields + ("nonce" to "0x" + attempt.toString().padStart(32, '0')))
    private val noPause: (Long) -> Unit = {}

    /** Chain answers in call order; the last repeats. Null means the chain read failed. */
    private fun chain(vararg answers: Boolean?): ChatRouteSubmit.ChainCheck {
        var i = 0
        return ChatRouteSubmit.ChainCheck { answers[minOf(i++, answers.size - 1)] }
    }

    private fun run(
        answers: List<ChatRouteSubmit.Transport>,
        chainAnswers: ChatRouteSubmit.ChainCheck,
        bases: List<String>,
        posts: MutableList<String> = mutableListOf(),
    ): ChatRouteSubmit.Outcome {
        var i = 0
        val poster = ChatRouteSubmit.Poster { _, json, _ ->
            posts.add(json)
            answers[minOf(i++, answers.size - 1)]
        }
        return ChatRouteSubmit.submit(bases, ::body, poster, chainAnswers, backoffMs = { 0L }, pause = noPause)
    }

    @Test
    fun ip01_successAndRegisteredIsSubmitted() {
        assertEquals(ChatRouteSubmit.Outcome.Submitted, run(listOf(ok), chain(true), listOf(ip)))
    }

    @Test
    fun ip02_successButNotRegisteredIsUnverifiedSubmit() {
        val posts = mutableListOf<String>()
        assertEquals(ChatRouteSubmit.Outcome.UnverifiedSubmit, run(listOf(ok), chain(false), listOf(ip), posts))
        assertEquals(1, posts.size)
    }

    @Test
    fun ip03_successWithChainUnreadableIsNetworkUnavailable() {
        assertEquals(ChatRouteSubmit.Outcome.NetworkUnavailable, run(listOf(ok), chain(null), listOf(ip)))
    }

    @Test
    fun ip04_fiveXxRegisteredOnChainIsSubmittedWithoutResend() {
        val posts = mutableListOf<String>()
        assertEquals(ChatRouteSubmit.Outcome.Submitted, run(listOf(fiveXx), chain(true), listOf(ip), posts))
        assertEquals(1, posts.size)
    }

    @Test
    fun ip05_timeoutNotRegisteredRetriesOnceWithAFreshSignature() {
        val posts = mutableListOf<String>()
        // The check before the retry: not registered. The retry is answered ok, and the check after it shows the keyId.
        val out = run(listOf(timeout, ok), chain(false, true), listOf(ip), posts)
        assertEquals(ChatRouteSubmit.Outcome.Submitted, out)
        assertEquals(2, posts.size)
        assertFalse(posts[0] == posts[1]) // re-signed: a fresh nonce, never a blind resend
    }

    @Test
    fun ip06_fiveXxNotRegisteredAfterTheRetryIsNetworkUnavailable() {
        val posts = mutableListOf<String>()
        assertEquals(ChatRouteSubmit.Outcome.NetworkUnavailable, run(listOf(fiveXx), chain(false), listOf(ip), posts))
        assertEquals(1 + ChatRouteSubmit.MAX_RETRIES, posts.size)
    }

    @Test
    fun ip07_fiveXxWithChainUnreadableIsNetworkUnavailableWithoutRetry() {
        val posts = mutableListOf<String>()
        assertEquals(ChatRouteSubmit.Outcome.NetworkUnavailable, run(listOf(fiveXx), chain(null), listOf(ip), posts))
        assertEquals(1, posts.size)
    }

    @Test
    fun domainSuccessRegisteredOnChainIsSubmitted() {
        assertEquals(ChatRouteSubmit.Outcome.Submitted, run(listOf(ok), chain(true), listOf(domain)))
    }

    @Test
    fun domainSuccessNotOnChainIsUnverifiedSubmit() {
        assertEquals(ChatRouteSubmit.Outcome.UnverifiedSubmit, run(listOf(ok), chain(false), listOf(domain)))
    }

    @Test
    fun ipUnreachableFallsThroughToDomain() {
        val posts = mutableListOf<String>()
        assertEquals(ChatRouteSubmit.Outcome.Submitted, run(listOf(ChatRouteSubmit.Transport.Unreachable, ok), chain(true), listOf(ip, domain), posts))
        assertEquals(2, posts.size)
    }

    @Test
    fun a4xxIsRefusedAndFinal() {
        val posts = mutableListOf<String>()
        val out = run(listOf(ChatRouteSubmit.Transport.Answer(400, "{}")), chain(false), listOf(ip), posts)
        assertEquals("chain_refused", (out as ChatRouteSubmit.Outcome.Refused).code)
        assertEquals(1, posts.size)
    }

    @Test
    fun noAnswerFromAnyBaseIsNetworkUnavailable() {
        assertEquals(ChatRouteSubmit.Outcome.NetworkUnavailable, run(listOf(ChatRouteSubmit.Transport.Unreachable), chain(null), listOf(ip, domain)))
    }
}
