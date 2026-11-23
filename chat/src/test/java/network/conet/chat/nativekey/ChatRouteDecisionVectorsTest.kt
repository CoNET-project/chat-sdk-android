package network.conet.chat.nativekey

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.MessageDigest

/**
 * chat-route-decision-vectors.v1.json (spec 25.29, 25.28.9, the ack envelope of 25.19.2 I-3 and 25.28.3, reqId of 25.28.3, 25.52CO.3, 25.52CQ.1,
 * 25.52CT.3, EOA password of 25.28.4; segment).
 *  A: the ack envelope (success carries result, no code; failure carries error, no result).
 *  B: the reqId rules, JSON-text and structured entries.
 *  C: the EOA password is the canonical "0x"+64 lower-case hex form; other forms do not open a canonical backup.
 *  D: the chat-mode and capability decision belongs to the shell and the page. The SDK makes no such decision, so D is recorded as
 *     not applicable to the SDK (not a pass, not a silent skip).
 */
class ChatRouteDecisionVectorsTest {
    private fun resource(name: String): JSONObject =
        JSONObject(javaClass.classLoader!!.getResource(name)!!.readText(Charsets.UTF_8))

    private fun sha256Hex(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

    /** B: the reqId rule on each case. JSON-text entries are parsed from their literal; structured entries are given as values. */
    @Test
    fun reqIdRuleMatchesEveryCase() {
        val cases = resource("chat-route-decision-vectors.v1.json").getJSONObject("B_reqId").getJSONArray("cases")
        var checked = 0
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            val id = c.getString("id")
            val expectOk = c.getJSONObject("expect").getBoolean("ok")
            val body = JSONObject()
            when {
                c.getBoolean("valueAbsent") -> Unit
                c.optString("jsonLiteral", "").isNotEmpty() -> body.put("reqId", JSONObject("{\"v\":${c.getString("jsonLiteral")}}").get("v"))
                else -> body.put("reqId", c.get("value"))
            }
            val actual = ShellRecordPolicy.reqIdValid(if (body.has("reqId")) body.opt("reqId") else null)
            assertEquals(id, expectOk, actual)
            checked++
        }
        assertEquals(21, checked)
    }

    /**
     * A: the ack envelope, driven by A_ack. Each case's `ack` is checked against the rule: success carries `result` and no `code` or
     * `error`; failure carries a string `error` and no `result` and no `code`. A case without `expect` is valid unless its
     * description marks it as forbidden ("禁止"). A case with `reason` must also give that reason.
     */
    @Test
    fun ackEnvelopeCasesFollowTheRule() {
        val cases = resource("chat-route-decision-vectors.v1.json").getJSONArray("A_ack")
        assertEquals(5, cases.length())
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            val id = c.getString("id")
            val ack = c.getJSONObject("ack")
            val expectValid = c.optJSONObject("expect")?.getBoolean("valid") ?: !c.getString("desc").contains("禁止")
            val reason = ackViolation(ack)
            assertEquals("$id valid", expectValid, reason == null)
            c.optJSONObject("expect")?.optString("reason", "")?.takeIf { it.isNotEmpty() }?.let { assertEquals("$id reason", it, reason) }
        }
    }

    /** Returns the reason an ack breaks the envelope rule, or null when it follows the rule. */
    private fun ackViolation(ack: JSONObject): String? {
        if (ack.optString("type") != "ack") return "not_ack"
        return if (ack.getBoolean("ok")) {
            when {
                ack.has("code") -> {
                    val extra = ack.keys().asSequence().any { it !in setOf("type", "reqId", "ok", "code") }
                    if (extra) "top_level_data_and_code" else "code_on_success"
                }
                ack.has("error") -> "error_on_success"
                !ack.has("result") -> "no_result"
                else -> null
            }
        } else {
            when {
                ack.has("result") -> "result_on_failure"
                ack.has("code") -> "code_instead_of_error"
                !ack.has("error") || ack.opt("error") !is String -> "no_error"
                else -> null
            }
        }
    }

    /** C: the password is the canonical form; the canonical bytes hash matches the vector, and non-canonical forms do not open the backup. */
    @Test
    fun passwordFormIsCanonicalAndOtherFormsDoNotOpenABackup() {
        val cases = resource("chat-route-decision-vectors.v1.json").getJSONObject("C_password").getJSONArray("cases")
        val byId = (0 until cases.length()).associate { cases.getJSONObject(it).getString("id") to cases.getJSONObject(it) }
        val canonical = byId.getValue("C-1").getString("passwordString")
        assertEquals(canonical, NativePgpBackup.passwordString(bytesOfHex(canonical.removePrefix("0x"))))
        assertEquals(byId.getValue("C-1").getString("passwordBytesSha256"), sha256Hex(canonical.toByteArray(Charsets.UTF_8)))

        val armor = "synthetic-armor-placeholder".toByteArray(Charsets.UTF_8)
        val backup = NativePgpBackup.encryptArmor(canonical, armor, ByteArray(12) { it.toByte() })
        assertTrue("the canonical form opens the backup", NativePgpBackup.decryptArmor(canonical, backup)?.contentEquals(armor) == true)
        for (id in listOf("C-2", "C-3", "C-4", "C-5", "C-6")) {
            val other = byId.getValue(id).getString("passwordString")
            assertNull("$id does not open a canonical backup", NativePgpBackup.decryptArmor(other, backup))
        }
    }

    /**
     * D: the chat mode and the capability decision are the shell's and the page's (25.29). The SDK makes no such decision (no chatMode in the
     * SDK), so the D cases are recorded as not applicable to the SDK. This test checks the record, not a pass.
     */
    @Test
    fun capabilityStateCasesAreNotAnSdkDecision() {
        val cases = resource("chat-route-decision-vectors.v1.json").getJSONObject("D_capabilityState").getJSONArray("cases")
        assertEquals(5, cases.length())
        val ids = (0 until cases.length()).map { cases.getJSONObject(it).getString("id") }
        assertEquals(listOf("D-1", "D-2", "D-3", "D-4", "D-5"), ids)
    }

    private fun bytesOfHex(hex: String): ByteArray = ByteArray(hex.length / 2) { hex.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
}
