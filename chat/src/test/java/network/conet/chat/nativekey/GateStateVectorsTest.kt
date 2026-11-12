package network.conet.chat.nativekey

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.File
import java.security.MessageDigest

/**
 * T-160 and T-161 (spec 25.26.4c) against `spec/gate-state-vectors.v1.json` (r3h, sha256 e789d901…3a27, 101 cases).
 * G0 cases answer `no_key`; G1 cases answer `not_ready`, except `init` (EOA check) and the status queries (table D).
 * Each case is decided by name and gate only; the payload is read solely by the G1 `init` check.
 */
class GateStateVectorsTest {
    private val bytes = File(System.getenv("GATE_STATE_VECTORS") ?: "../spec/gate-state-vectors.v1.json").readBytes()
    private val v = JSONObject(String(bytes, Charsets.UTF_8))
    private val cases = v.getJSONArray("cases")

    private fun sha256Hex(b: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }

    @Test
    fun vectorFileIsTheCanonicalOne() {
        assertEquals("e789d90175db53035397ddb1dbdb729b1df92b7d855d234dc006abf4906e3a27", sha256Hex(bytes))
    }

    @Test
    fun caseCountsMatchTheVector() {
        assertEquals(101, cases.length())
        assertEquals(66, v.getJSONObject("counts").getInt("g1Commands"))
        assertEquals(3, v.getJSONObject("counts").getInt("g1Init"))
    }

    @Test
    fun everyCaseMatchesTheVector() {
        val recordEoa = v.getString("recordEoa")
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            val id = c.getString("id")
            val command = c.getString("command")
            val expect = c.getJSONObject("expect")
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

    @Test
    fun g1InitWithTheRecordsEoaIsTheOnlyOkAndOnlyAfterTheEoaCheck() {
        val recordEoa = v.getString("recordEoa")
        assertEquals("ok", NoKeyGate.initAnswer(recordEoa, recordEoa))
        assertEquals("address_mismatch", NoKeyGate.initAnswer(recordEoa, "0x2222222222222222222222222222222222222222"))
        assertEquals("address_mismatch", NoKeyGate.initAnswer(recordEoa, null))
    }
}
