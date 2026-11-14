package network.conet.chat

import network.conet.chat.localread.NativeHistoryDelete
import network.conet.chat.nativekey.NoKeyGate
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * 25.52AR.2 (PM R647) and 25.52AN.5 (r3cl): a name outside the bridge command table is rejected with `command_rejected`, before the gate.
 * The dispatch table in the source is read and compared with [BridgeCommandTable.DISPATCH], name by name, in both directions.
 */
class BridgeCommandTableTest {
    private val source: String by lazy {
        File("src/main/java/network/conet/chat/BeamioConetChatModule.kt").readText(Charsets.UTF_8)
    }

    /** The names of the `when (type)` table in `dispatch`, read from the source (one arrow line per name or name group). */
    private fun dispatchNamesInSource(): Set<String> {
        val lines = source.lines()
        val start = lines.indexOfFirst { "private fun dispatch(type: String, body: JSONObject)" in it }
        require(start >= 0) { "dispatch not found in the source" }
        val whenAt = (start until lines.size).first { "when (type) {" in lines[it] }
        val elseAt = (whenAt until lines.size).first { lines[it].trimStart().startsWith("else ->") }
        val arrow = Regex("""^\s+((?:"[A-Za-z0-9_]+"\s*,\s*)*"[A-Za-z0-9_]+")\s*->""")
        val quoted = Regex("\"([A-Za-z0-9_]+)\"")
        return (whenAt + 1 until elseAt).flatMap { i ->
            val group = arrow.find(lines[i])?.groupValues?.get(1) ?: return@flatMap emptyList<String>()
            quoted.findAll(group).map { it.groupValues[1] }.toList()
        }.toSet()
    }

    @Test
    fun theDispatchTableInTheSourceIsTheRegisteredSet() {
        assertEquals(BridgeCommandTable.DISPATCH, dispatchNamesInSource())
    }

    @Test
    fun theNamesDecidedBeforeDispatchAreInTheSource() {
        for (name in listOf("pgpDecryptInbound", "identityPublic", "pgpMigrate")) {
            assertTrue("$name is decided in handleCommand", source.contains("type == \"$name\""))
        }
        assertTrue(source.contains("NativeHistoryDelete.MESSAGE") && source.contains("NativeHistoryDelete.CONVERSATION"))
        assertTrue(NativeHistoryDelete.MESSAGE in BridgeCommandTable.DECIDED_BEFORE_DISPATCH)
        assertTrue(NativeHistoryDelete.CONVERSATION in BridgeCommandTable.DECIDED_BEFORE_DISPATCH)
    }

    @Test
    fun theGateStatusNamesAreRoutedByTheGate() {
        assertEquals(NoKeyGate.Route.WALLET_STATUS, NoKeyGate.route("walletStatus"))
        assertEquals(NoKeyGate.Route.PASSCODE_STATUS, NoKeyGate.route("passcodeStatus"))
        assertTrue(BridgeCommandTable.isRegistered("walletStatus"))
        assertTrue(BridgeCommandTable.isRegistered("passcodeStatus"))
    }

    @Test
    fun theRetiredNamesStayRegistered() {
        for (name in NoKeyGate.RETIRED) assertTrue(name, BridgeCommandTable.isRegistered(name))
    }

    @Test
    fun registeredNamesAreRecognised() {
        for (name in listOf("hello", "pgpRestoreEvaluate", "pgpDecryptInbound", "historyDeleteMessage", "shellRecordRead", "voiceFrame")) {
            assertTrue(name, BridgeCommandTable.isRegistered(name))
        }
    }

    @Test
    fun unknownNamesAreNotRegistered() {
        // Not bridge names: unknown names, the empty name, the wallet-layer and W5 names that are not bridge commands (25.52AR.3), and QA identifiers (25.52AN.2).
        val unknown = listOf(
            "notACommand", "", "signMessage", "pgpDecrypt", "removeEOAPrivateKey", "dropEoaKey", "dropEoaKeyOfAccount",
            "runCommand", "runWith", "ALLOWED_COMMANDS", "NativeQaHooks",
        )
        for (name in unknown) assertFalse("'$name' is not a bridge name", BridgeCommandTable.isRegistered(name))
    }

    @Test
    fun anUnknownNameIsCountedAndAnswersUnknownCommand() {
        val before = BridgeCommandTable.rejectionCount
        assertEquals("unknown_command", BridgeCommandTable.countUnknown())
        assertEquals(before + 1, BridgeCommandTable.rejectionCount)
    }

    @Test
    fun theModuleJudgesInTheOrderOf25_52AT1() {
        // Step 2 (CRED for the six commands), then step 3 (the name), then step 4 (the gate). Structure only; the answers are checked on a device.
        val cred = source.indexOf("CredFields.COMMANDS")
        val name = source.indexOf("BridgeCommandTable.isRegistered(type)")
        val gate = source.indexOf("val route = NoKeyGate.route(type)")
        assertTrue("CRED comes first", cred in 0 until name)
        assertTrue("the name check comes before the gate", name in 0 until gate)
        assertTrue("the unknown answer is unknown_command", source.contains("unknown_command name="))
        assertFalse("command_rejected is not an answer to a name outside the table (25.52AS.3)", source.contains("\"command_rejected"))
    }
}
