package network.conet.chat

import network.conet.chat.localread.NativeHistoryDelete
import network.conet.chat.nativekey.NoKeyGate
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
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
    fun aKnownCommandsRefusalIsCountedAsCommandRejected() {
        // 25.52AW.2: command_rejected is an in-process count of a refusal of a known command's kind or shape. It is not an answer.
        val before = BridgeCommandTable.commandRejectedCount
        assertEquals("command_rejected", BridgeCommandTable.countCommandRejected())
        assertEquals(before + 1, BridgeCommandTable.commandRejectedCount)
    }

    @Test
    fun theChatChannelShellRecordCodesAreNotSupportedAndUnknown() {
        // 25.52AY.1, AU.1: shellRecordRead and shellRecordWrite are not_supported on the chat channel; another shellRecord* name is unknown_command.
        assertEquals("not_supported", BridgeCommandTable.chatChannelShellRecordCode("shellRecordRead"))
        assertEquals("not_supported", BridgeCommandTable.chatChannelShellRecordCode("shellRecordWrite"))
        assertEquals("unknown_command", BridgeCommandTable.chatChannelShellRecordCode("shellRecordMigrationState"))
        assertNull(BridgeCommandTable.chatChannelShellRecordCode("send"))
        assertFalse(BridgeCommandTable.isRegistered("shellRecordMigrationState"))
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
        assertFalse("an unknown name is not counted (25.52AW.2)", source.contains("countUnknown"))
    }

    /**
     * 25.52AU.4, AV.2, AW.3: the command table T is T0 (from the no-key vectors) plus T1 (the seven names of AV.2). The shell list H is the
     * shellLayerIos list of the same file (§25.26.4b). Every registered name must be in T or in H.
     */
    private fun tAndH(): Pair<Set<String>, Set<String>> {
        val doc = JSONObject(File("../spec/no-key-reject-vectors.v1.json").readText(Charsets.UTF_8))
        val t0 = mutableSetOf<String>()
        for (key in listOf("walletCommands", "chatCommands", "retiredCommands", "specialStatus")) {
            val arr = doc.getJSONArray(key)
            for (i in 0 until arr.length()) t0 += arr.getJSONObject(i).getString("command")
        }
        for (key in listOf("allowedUnderNoKey", "lifecycleExcluded")) {
            val arr = doc.getJSONArray(key)
            for (i in 0 until arr.length()) t0 += arr.getString(i)
        }
        val mapping = doc.getJSONArray("mapping")
        for (i in 0 until mapping.length()) mapping.getJSONObject(i).optString("bridgeName", "").takeIf { it.isNotEmpty() }?.let { t0 += it }
        t0 += listOf("shellRecordRead", "shellRecordWrite")
        val t1 = setOf("identityPublic", "historyDeleteMessage", "historyDeleteConversation", "pgpIdentityCreate", "pgpRestore", "pgpRestoreEvaluate", "pgpMigrate")
        val shell = doc.getJSONArray("shellLayerIos")
        val h = (0 until shell.length()).map { shell.getJSONObject(it).getString("name") }.toSet()
        return (t0 + t1) to h
    }

    @Test
    fun everyRegisteredNameIsInTOrH() {
        val (t, h) = tAndH()
        val exact = BridgeCommandTable.DISPATCH + BridgeCommandTable.DECIDED_BEFORE_DISPATCH + BridgeCommandTable.GATE_STATUS + NoKeyGate.RETIRED
        // 25.52AW.3: the registered exact names are 44 + 5 + 2 + 3; the two page-record names are in T as well (AU.4).
        assertEquals(54, exact.size)
        val outside = (exact + BridgeCommandTable.CHAT_CHANNEL_SHELL_RECORD).filter { it !in t && it !in h }
        assertTrue("registered names outside T and H: $outside", outside.isEmpty())
        assertTrue("T1 names are in T", t.containsAll(setOf("identityPublic", "historyDeleteMessage", "historyDeleteConversation", "pgpIdentityCreate", "pgpRestore", "pgpRestoreEvaluate", "pgpMigrate")))
    }

    @Test
    fun theEnvelopeIsCheckedBeforeAnyStateChange() {
        // 25.52AW.1, AU.1: the reqId envelope is the first check. Only then does the legacy adoption (a state change) run.
        val envelope = source.indexOf("ShellRecordPolicy.reqIdValid(body.opt(\"reqId\"))")
        val adoption = source.indexOf("NativeWallet.migrateLegacy(context)")
        assertTrue("the envelope check exists", envelope > 0)
        assertTrue("the envelope comes before the legacy adoption", envelope in 0 until adoption)
    }

    @Test
    fun theCountOfAnUnknownNameIsNotTakenHere() {
        // 25.52AW.2: an unknown name is not counted as command_rejected; the module never calls countCommandRejected for it.
        val unknownBranch = source.substringAfter("if (!BridgeCommandTable.isRegistered(type)) {").substringBefore("return")
        assertFalse("the unknown branch does not count", unknownBranch.contains("countCommandRejected"))
        assertTrue("the unknown branch answers unknown_command", unknownBranch.contains("BridgeCommandTable.UNKNOWN_COMMAND"))
    }
}
