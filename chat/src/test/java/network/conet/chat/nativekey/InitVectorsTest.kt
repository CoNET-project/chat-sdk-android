package network.conet.chat.nativekey

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.File

/**
 * Runs every `init` case of the gate-state vector file through the rules the module applies (PM R1861; spec §25.52Y.29,
 * §25.52Y.32, §25.52GJ): the EOA check first (NoKeyGate.initAnswer), then, in G1 only, the nodes verdict (InitNodesGate).
 * The Keychain roster is taken from the case id: an id ending in `-KC` means the device stores nodes.
 * The file is GATE_STATE_VECTORS, or ../spec/gate-state-vectors.v1.json when unset.
 */
class InitVectorsTest {
    private val file = File(System.getenv("GATE_STATE_VECTORS") ?: "../spec/gate-state-vectors.v1.json")
    private val root = JSONObject(file.readText(Charsets.UTF_8))
    private val cases = root.getJSONArray("cases")

    @Test
    fun everyInitCaseMatchesTheVector() {
        val recordEoa = root.getString("recordEoa")
        var ran = 0
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            if (c.getString("command") != "init") continue
            val id = c.getString("id")
            val state = c.getString("state")
            val payload = c.getJSONObject("payload")
            val expected = c.getJSONObject("expect").getString("code")
            val payloadEoa = payload.optJSONObject("identity")?.optString("eoaAddress", "").orEmpty()
            val eoaAnswer = NoKeyGate.initAnswer(recordEoa, payloadEoa)
            val actual = when {
                eoaAnswer != "ok" -> "address_mismatch"
                state == "G1" -> {
                    val stored = if (id.endsWith("-KC")) 1 else 0
                    InitNodesGate.errorOf(InitNodesGate.verdict(payload) { stored }) ?: "ok"
                }
                else -> "ok" // G2: the nodes rule does not apply (§25.52GJ; G2-INIT-MATCH has no nodes key and expects ok)
            }
            assertEquals(id, expected, actual)
            ran++
        }
        assertEquals("init cases run", 13, ran) // 10 G1-INIT + 3 G2-INIT in the 146-case file
    }
}
