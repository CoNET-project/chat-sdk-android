package network.conet.chat

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * The names that the gate-state vectors G1-NK-W2 to W4 and W5a to W5g expect as `unknown_command` (spec §25.52DP.1, §25.52DW.1,
 * §25.52GE.2). This is a baseline gap for the vector model, not a pass there. The answer is produced by the module before the gate,
 * from [BridgeCommandTable] alone; the vector model does not reach it.
 *
 * No in-process harness exists for `handleCommand` (it needs an Android Context), so the module check is a source-structure test, in the
 * style of [BridgeCommandTableTest]: the pre-gate `isRegistered` answer precedes the gate in `handleCommand`.
 */
class UnknownBridgeNamesTest {
    private val names = listOf("deriveLocalKeys", "protocolKeys", "fragmentKeys", "signMessage")
    private val source: String by lazy {
        File("src/main/java/network/conet/chat/BeamioConetChatModule.kt").readText(Charsets.UTF_8)
    }

    @Test
    fun theVectorNamesAreNotBridgeCommands() {
        for (name in names) {
            assertFalse("$name must not be a bridge command", BridgeCommandTable.isRegistered(name))
        }
    }

    @Test
    fun theModuleAnswersUnknownCommandBeforeTheGate() {
        val body = source.substringAfter("fun handleCommand(context: Context, body: JSONObject, emit: (JSONObject) -> Unit) {")
            .substringBefore("\n    }\n")
        val unknown = body.indexOf("if (!BridgeCommandTable.isRegistered(type))")
        val gate = body.indexOf("NoKeyGate.route(type)")
        assertTrue("the pre-gate unknown_command check is in handleCommand", unknown >= 0)
        assertTrue("the gate is in handleCommand", gate >= 0)
        assertTrue("the unknown check comes before the gate", unknown < gate)
        assertTrue("the check answers BridgeCommandTable.UNKNOWN_COMMAND", body.substring(unknown, gate).contains("BridgeCommandTable.UNKNOWN_COMMAND"))
    }
}
