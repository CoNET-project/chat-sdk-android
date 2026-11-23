package network.conet.chat.nativekey

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.File

/**
 * `nativeMnemonicPreread` (r2.5.19 60; vectors NP-01..13 in `spec/mnemonic-preread-vectors.v1.json`). The order is trustedOrigin, then the
 * credential check, then seq (missing, not an integer literal, above 2^53 - 1: bad_request), then a stale seq (below the newest accepted: stale_seq,
 * before the state), then the state answer. The phrase is returned only for valid, with all three passing. The pre-read only compares; it does not
 * move the ledger (60(4)). The state answer is supplied directly (the synthetic values of the vector, not a derivation).
 */
class NativePrereadVectorsTest {
    private val doc = JSONObject(File("../spec/mnemonic-preread-vectors.v2.json").readText(Charsets.UTF_8))
    private val cases = doc.getJSONArray("cases")
    private val eoa = "0x1111111111111111111111111111111111111111"
    private val phrase = "SYNTHETIC-TEST-PHRASE-NOT-A-WALLET"
    private val valid = { MnemonicPreread.Answer.Valid(eoa, phrase) }
    private val absent = { MnemonicPreread.Answer.Absent }
    private val unknown = { MnemonicPreread.Answer.Unknown }

    @Before
    fun baseline() {
        // The newest accepted sequence of the scenario is 5 (vector titles).
        MnemonicPreread.resetForTests()
        assertTrue(MnemonicPreread.accept(5L))
    }

    private fun request(trusted: Boolean, seq: Any?): JSONObject {
        val body = JSONObject().put("type", "nativeMnemonicPreread").put("reqId", "np")
        if (trusted) body.put("trustedOrigin", true)
        if (seq != null) body.put("seq", seq)
        return body
    }

    private fun ask(body: JSONObject, answer: () -> MnemonicPreread.Answer): JSONObject =
        NativeSyncAck.prereadPayload("np", body, answer).let { JSONObject(it.toString()).apply { remove("type"); remove("reqId") } }

    private fun expectOf(id: String, index: Int = 0): JSONObject {
        val c = (0 until cases.length()).map { cases.getJSONObject(it) }.first { it.getString("id") == id }
        return c.getJSONArray("expect").getJSONObject(index)
    }

    /** The reply carries exactly the expected ok and error or result; a reply without a valid answer carries no phrase. */
    private fun assertAnswer(id: String, got: JSONObject, want: JSONObject) {
        assertEquals("$id ok", want.getBoolean("ok"), got.getBoolean("ok"))
        if (want.has("error")) assertEquals("$id error", want.getString("error"), got.getString("error"))
        if (want.has("result")) {
            val w = want.getJSONObject("result")
            val g = got.getJSONObject("result")
            assertEquals("$id result keys", w.keys().asSequence().toSet(), g.keys().asSequence().toSet())
            for (k in w.keys()) assertEquals("$id result.$k", w.get(k).toString(), g.get(k).toString())
        }
        if (!want.has("result") || !want.getJSONObject("result").has("mnemonic")) {
            assertFalse("$id carries no phrase", got.toString().contains(phrase))
        }
    }

    @Test
    fun np01ValidAboveTheNewestSequenceReturnsThePhrase() = assertAnswer("NP-01", ask(request(true, 7), valid), expectOf("NP-01"))

    @Test
    fun np02EqualSequenceIsCurrentAndReturnsThePhrase() = assertAnswer("NP-02", ask(request(true, 5), valid), expectOf("NP-02"))

    @Test
    fun np03AbsentReturnsOnlyTheState() = assertAnswer("NP-03", ask(request(true, 6), absent), expectOf("NP-03"))

    @Test
    fun np04UnknownReturnsOnlyTheState() = assertAnswer("NP-04", ask(request(true, 6), unknown), expectOf("NP-04"))

    /** NP-05: a pre-read at 9 does not move the ledger; 6 is still current (the newest accepted stays 5). */
    @Test
    fun np05APreReadDoesNotAdvanceTheLedger() {
        assertAnswer("NP-05", ask(request(true, 9), valid), expectOf("NP-05", 0))
        assertEquals(5L, MnemonicPreread.latestAcceptedSeq())
        assertAnswer("NP-05", ask(request(true, 6), valid), expectOf("NP-05", 1))
    }

    @Test
    fun np06StaleSequenceIsStaleAndHasNoPhrase() = assertAnswer("NP-06", ask(request(true, 4), valid), expectOf("NP-06"))

    /** NP-07: the stale check runs before the state: a stale request with an absent state is still stale_seq. */
    @Test
    fun np07StaleBeforeTheState() = assertAnswer("NP-07", ask(request(true, 4), absent), expectOf("NP-07"))

    @Test
    fun np08MissingSequenceIsBadRequestEvenWhenValid() = assertAnswer("NP-08", ask(request(true, null), valid), expectOf("NP-08"))

    @Test
    fun np09MissingSequenceIsBadRequestEvenWhenAbsent() = assertAnswer("NP-09", ask(request(true, null), absent), expectOf("NP-09"))

    /** NP-10: 1.0 is a JSON double, not an integer literal. */
    @Test
    fun np10OneDotZeroIsBadRequest() {
        val body = JSONObject("{\"type\":\"nativeMnemonicPreread\",\"reqId\":\"np\",\"trustedOrigin\":true,\"seq\":1.0}")
        assertAnswer("NP-10", ask(body, valid), expectOf("NP-10"))
    }

    @Test
    fun np11TwoToTheFiftyThreeIsBadRequest() = assertAnswer("NP-11", ask(request(true, 9007199254740992L), valid), expectOf("NP-11"))

    @Test
    fun np12UntrustedIsUntrustedWithAValidStateAndNoPhrase() = assertAnswer("NP-12", ask(request(false, 7), valid), expectOf("NP-12"))

    @Test
    fun np13UntrustedBeforeTheFormatCheck() = assertAnswer("NP-13", ask(request(false, null), valid), expectOf("NP-13"))

    /** The W-class check (59(1)(c)): a key-like field in a pre-read request is key_over_bridge_refused, with no echo. */
    @Test
    fun aCredentialFieldInThePreReadIsRefusedAndNothingIsEchoed() {
        val body = request(true, 6).put("privateKeyHex", "0x" + "ab".repeat(32))
        val got = ask(body, valid)
        assertEquals(false, got.getBoolean("ok"))
        assertEquals("key_over_bridge_refused", got.getString("error"))
        assertFalse(got.toString().contains("ab".repeat(32)))
        assertFalse(got.toString().contains(phrase))
    }
}
