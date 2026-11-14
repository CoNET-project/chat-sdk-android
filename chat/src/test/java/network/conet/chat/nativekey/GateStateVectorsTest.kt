package network.conet.chat.nativekey

import network.conet.chat.BridgeCommandTable
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.security.MessageDigest

/**
 * T-160, T-161 (spec 25.26.4c), 25.52BK (r3di), 25.52BL (r3dj), 25.52BO.1 and 25.52BP.1 (r3dl, r3dm) against `spec/gate-state-vectors.v1.json`
 * (r3dm, sha256 94792dc4…, 133 cases).
 * G0 cases answer `no_key`; G1 cases answer `not_ready`, except `init` (EOA check) and the status queries (table D).
 *
 * The 26 cases with `forbiddenCodes` (25.52BK.2) are shell-layer actions that the gate does not refuse. The SDK does not register them, so an
 * SDK name outside the command table is answered `unknown_command` before the gate (25.52AT.1, AT.2). Such a case asserts `gateRefused` false and
 * that the answer is none of `forbiddenCodes`. The other cases are decided by name and gate only.
 */
class GateStateVectorsTest {
    private val bytes = File(System.getenv("GATE_STATE_VECTORS") ?: "../spec/gate-state-vectors.v1.json").readBytes()
    private val v = JSONObject(String(bytes, Charsets.UTF_8))
    private val cases = v.getJSONArray("cases")

    private fun sha256Hex(b: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }

    @Test
    fun vectorFileIsTheCanonicalOne() {
        assertEquals("94792dc4b2eed210b15caf7be612ce7fb96babb80c0bd74d4edb491ca3eb2da0", sha256Hex(bytes))
    }

    @Test
    fun caseCountsMatchTheVector() {
        // r3dm: 133 cases (G0 32, G1 101). G1 allowed commands 66 (pgpSign removed, 25.52BP.1); init 3; shell-layer not gated 26; rejected names 8.
        assertEquals(133, cases.length())
        val counts = v.getJSONObject("counts")
        assertEquals(133, counts.getInt("cases"))
        assertEquals(66, counts.getInt("g1Commands"))
        assertEquals(3, counts.getInt("g1Init"))
        assertEquals(26, counts.getInt("shellNotGatedCases"))
        assertEquals(8, counts.getInt("shellRejectCases"))
        var g0 = 0
        var g1 = 0
        for (i in 0 until cases.length()) if (cases.getJSONObject(i).getString("state") == "G0") g0++ else g1++
        assertEquals(32, g0)
        assertEquals(101, g1)
    }

    @Test
    fun everyCaseMatchesTheVector() {
        val recordEoa = v.getString("recordEoa")
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            val id = c.getString("id")
            val command = c.getString("command")
            val expect = c.getJSONObject("expect")
            if (expect.has("forbiddenCodes")) {
                shellNotGatedCase(id, command, expect)
                continue
            }
            // G0 has no record; G1 has the record and no session (sessionReady false).
            val state: NativeWalletVault.State =
                if (c.getString("state") == "G0") NativeWalletVault.State.NoKey else NativeWalletVault.State.Ready(recordEoa)
            val gate = NoKeyGate.gateOf(state, sessionReady = false)
            val payload = c.optJSONObject("payload") ?: JSONObject()
            val payloadEoa = payload.optJSONObject("identity")?.optString("eoaAddress", "")?.ifEmpty { null }

            when {
                command == "walletStatus" -> assertEquals(
                    id,
                    expect.getString("status"),
                    NoKeyGate.walletStatusFor(gate, state).getString("status"),
                )
                command == "passcodeStatus" -> assertEquals(
                    id,
                    expect.getBoolean("hasKey"),
                    NoKeyGate.passcodeStatusFor(gate).getBoolean("hasKey"),
                )
                else -> {
                    val code = if (gate == NoKeyGate.Gate.G1 && command == "init") {
                        NoKeyGate.initAnswer(recordEoa, payloadEoa)
                    } else {
                        NoKeyGate.answerFor(command, gate)
                    }
                    // The vector's `ok` is the G1 init success; `allowed` is the allowed-list answer.
                    val expected = expect.getString("code")
                    assertEquals(id, expected, if (code == "init") "ok" else code)
                    assertEquals(id, command == "init", expect.getBoolean("payloadRead"))
                }
            }
        }
    }

    /**
     * 25.52BK.2: the action is not gated. The SDK does not register the name, so the answer is `unknown_command` (before the gate), which is not
     * one of the forbidden codes. The vector's `gateRefused` is false. The vector does not name a code, and the test does not require one.
     */
    private fun shellNotGatedCase(id: String, command: String, expect: JSONObject) {
        assertFalse("$id: the action is not gated", expect.getBoolean("gateRefused"))
        assertFalse("$id: the SDK does not register the shell-layer name $command", BridgeCommandTable.isRegistered(command))
        val answer = BridgeCommandTable.UNKNOWN_COMMAND
        val forbidden = expect.getJSONArray("forbiddenCodes")
        for (k in 0 until forbidden.length()) {
            assertTrue("$id: the answer $answer is not ${forbidden.getString(k)}", answer != forbidden.getString(k))
        }
    }

    @Test
    fun g1InitWithTheRecordsEoaIsTheOnlyOkAndOnlyAfterTheEoaCheck() {
        val recordEoa = v.getString("recordEoa")
        assertEquals("ok", NoKeyGate.initAnswer(recordEoa, recordEoa))
        assertEquals("address_mismatch", NoKeyGate.initAnswer(recordEoa, "0x2222222222222222222222222222222222222222"))
        assertEquals("address_mismatch", NoKeyGate.initAnswer(recordEoa, null))
    }
}
