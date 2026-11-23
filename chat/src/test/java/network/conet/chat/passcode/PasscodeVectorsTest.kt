package network.conet.chat.passcode

import network.conet.chat.ConetChatCryptoUtil
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import java.io.File
import java.security.MessageDigest

/**
 * Passcode rules, KDF known answer, cooldown schedule and the 19 transitions, against
 * `spec/passcode-vectors.v1.json` (sha256 1b2bca82…, spec r3b 25.17). The vector file is the
 * canonical one, copied byte for byte. Synthetic material only.
 */
class PasscodeVectorsTest {
    private val bytes = File(System.getenv("PASSCODE_VECTORS") ?: "../spec/passcode-vectors.v1.json").readBytes()
    private val v = JSONObject(String(bytes, Charsets.UTF_8))

    private fun nullableString(o: JSONObject, key: String): String? = if (o.isNull(key)) null else o.getString(key)

    @Test
    fun vectorFileIsTheCanonicalOne() {
        val sha = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
        assertEquals("1b2bca82b1d00067365f776b2bce15fcc06d023118832f7c1f67bcc1bb2e4961", sha)
    }

    @Test
    fun policyNumbersAndReasonCodesMatchTheVector() {
        val policy = v.getJSONObject("policy")
        assertEquals(PasscodePolicy.MIN_DIGITS, policy.getInt("minDigits"))
        assertEquals(PasscodePolicy.MAX_DIGITS, policy.getInt("maxDigits"))
        val common = policy.getJSONArray("common")
        assertEquals(PasscodePolicy.COMMON, (0 until common.length()).map { common.getString(it) }.toSet())
        val codes = policy.getJSONArray("reasonCodes")
        assertEquals(PasscodePolicy.Reason.values().map { it.code }, (0 until codes.length()).map { codes.getString(it) })
    }

    @Test
    fun every_policy_case_matches_its_expected_result() {
        val cases = v.getJSONObject("policy").getJSONArray("cases")
        assertEquals(24, cases.length())
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            val passcode = c.getString("passcode")
            val reason = PasscodePolicy.reject(passcode)
            assertEquals("accepted? $passcode", c.getBoolean("expectOk"), reason == null)
            assertEquals("reason for $passcode", nullableString(c, "expectReason"), reason?.code)
        }
    }

    @Test
    fun birthdayFormatIsRejectedAndOutOfRangeDatesAreAccepted() {
        // 20251231 must be rejected (spec r3b 25.17, batch 10); 21000101 is outside 1900–2099 in every reading.
        assertEquals(PasscodePolicy.Reason.BIRTHDAY, PasscodePolicy.reject("20251231"))
        assertNull(PasscodePolicy.reject("21000101"))
        // 29 February: 2024 is a leap year (rejected), 2023 is not (accepted).
        assertEquals(PasscodePolicy.Reason.BIRTHDAY, PasscodePolicy.reject("29022024"))
        assertNull(PasscodePolicy.reject("29022023"))
    }

    @Test
    fun kdfKnownAnswerMatches() {
        val kdf = v.getJSONObject("kdf")
        assertEquals("PBKDF2-HMAC-SHA256", kdf.getString("alg"))
        assertEquals(PasscodeKdf.ITERATIONS, kdf.getInt("iterations"))
        assertEquals(32, kdf.getInt("dkLen"))
        val salt = ConetChatCryptoUtil.hexToBytes(kdf.getString("saltHex"))!!
        val key = PasscodeKdf.derive(kdf.getString("passcode"), salt)
        assertEquals(kdf.getString("outputHex"), ConetChatCryptoUtil.toHex(key))
    }

    @Test
    fun nineteenTransitionsMatchTheVectorRowByRow() {
        val rows = v.getJSONObject("stateMachine").getJSONArray("transitions")
        assertEquals(19, rows.length())
        assertEquals(19, PasscodeStateMachine.TRANSITIONS.size)
        for (i in 0 until rows.length()) {
            val r = rows.getJSONObject(i)
            val expected = PasscodeTransition(
                mode = r.getString("mode"),
                from = r.getString("from"),
                event = r.getString("event"),
                to = r.getString("to"),
                message = nullableString(r, "message"),
                result = nullableString(r, "result"),
                specAdded = r.optBoolean("specAdded", false),
                pwaAdded = r.optBoolean("pwaAdded", false),
            )
            assertEquals("row $i", expected, PasscodeStateMachine.TRANSITIONS[i])
        }
        assertEquals(3, PasscodeStateMachine.TRANSITIONS.count { it.pwaAdded })
    }

    @Test
    fun lookupUsesExactRowsThenWildcards() {
        assertEquals("setup_new", PasscodeStateMachine.next("change", "verify_old", "submit_match")?.to)
        // Wildcard rows apply to any mode and state.
        assertEquals("done", PasscodeStateMachine.next("unlock", "setup_new", "cancel")?.to)
        assertEquals("error", PasscodeStateMachine.next("disable", "verify", "internal_error")?.result)
        // Not a legal transition: no row.
        assertNull(PasscodeStateMachine.next("enable", "done", "submit_valid"))
    }
}
