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
    fun theChatChannelShellRecordPrefixIsNotSupportedForEveryName() {
        // 25.52AZ.1, BO.4 (r3dl): the chat channel answers not_supported, once, for every name with the shellRecord prefix. Per prefix, not per name.
        assertEquals("not_supported", BridgeCommandTable.chatChannelShellRecordCode("shellRecordRead"))
        assertEquals("not_supported", BridgeCommandTable.chatChannelShellRecordCode("shellRecordWrite"))
        assertEquals("not_supported", BridgeCommandTable.chatChannelShellRecordCode("shellRecordMigrationState"))
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
        val shellRecordBranch = source.indexOf("BridgeCommandTable.chatChannelShellRecordCode(type)")
        assertTrue("the shellRecord prefix branch comes before the name check (25.52AZ.1)", cred in 0 until shellRecordBranch && shellRecordBranch < name)
        val migrate = source.indexOf("NativeWallet.migrateLegacy(context)")
        val pgpDecrypt = source.indexOf("if (type == \"pgpDecryptInbound\")")
        assertTrue("the name check comes before the gate", name in 0 until gate)
        // 25.52AT.1 (AQ.2, AU.2): the refusals and the name check come before the legacy adoption (a state change) and before the handlers.
        assertTrue("the name check comes before the legacy adoption", name in 0 until migrate)
        assertTrue("the legacy adoption comes before the pgpDecryptInbound handler", migrate in 0 until pgpDecrypt)
        assertTrue("the unknown answer is unknown_command", source.contains("unknown_command name="))
        assertFalse("command_rejected is not an answer to a name outside the table (25.52AS.3)", source.contains("\"command_rejected"))
        assertFalse("an unknown name is not counted (25.52AW.2)", source.contains("countUnknown"))
    }

    /**
     * 25.52BY.1, BW.2 (r3dw, r3dy): the reference table T is protocol/table-T.v1.json (67 names, spec/table-T.v1.json). The audit of the dispatch
     * table refers to it. Every registered name must be in it.
     */
    private fun tableT(): Set<String> {
        val doc = JSONObject(File("../spec/table-T.v1.json").readText(Charsets.UTF_8))
        val names = doc.getJSONArray("names")
        return (0 until names.length()).map { names.getString(it) }.toSet()
    }

    @Test
    fun everyRegisteredNameIsInTheReferenceTable() {
        val t = tableT()
        assertEquals(68, t.size) // 25.52Y.95 第 1 条: T1 13 names (accountCleanupOld), total 68
        val exact = BridgeCommandTable.DISPATCH + BridgeCommandTable.DECIDED_BEFORE_DISPATCH + BridgeCommandTable.GATE_STATUS + NoKeyGate.RETIRED
        // 25.52AW.3, BG.4, BP.1: the registered exact names are 43 + 5 + 2 + 3 (pgpSign is not bridged); chatRouteRegister (W5, 25.28.3, PM R2085)
        // makes 54; the page-record names are in T too.
        // 25.52Y.65 第 5 项: pgpUpgradeRetry is in table-T (T1 12, total 67); it is the 55th registered name.
        assertEquals(55, exact.size)
        val outside = (exact + BridgeCommandTable.CHAT_CHANNEL_SHELL_RECORD).filter { it !in t }
        assertTrue("registered names outside table-T: $outside", outside.isEmpty())
        assertTrue("T1 names are in table-T", t.containsAll(setOf("identityPublic", "historyDeleteMessage", "historyDeleteConversation", "pgpIdentityCreate", "pgpRestore", "pgpRestoreEvaluate", "pgpMigrate")))
        assertFalse("pgpSign is not in table-T (25.52BP.1)", "pgpSign" in t)
    }

    @Test
    fun theLockedCheckComesAfterTheNameCheckAndBeforeTheParameters() {
        // 25.52BZ.4: the locked check of the gate step is after the name check and before the no_key or not_ready answers and the handlers.
        val name = source.indexOf("BridgeCommandTable.isRegistered(type)")
        val locked = source.indexOf("NoKeyGate.lockedAnswer(type, state)")
        val gateAnswer = source.indexOf("when (NoKeyGate.answerFor(type, gate))")
        assertTrue("the locked check exists", locked > 0)
        assertTrue("the name check comes before the locked check", name in 0 until locked)
        assertTrue("the locked check comes before the no_key and not_ready answers", locked in 0 until gateAnswer)
    }

    @Test
    fun theRetiredNamesAreAnsweredBeforeTheGateInEveryState() {
        // 25.52BZ.3: the retired names answer not_supported in every state, locked included, before the gate and the locked check.
        val retired = source.indexOf("if (route == NoKeyGate.Route.NOT_SUPPORTED) {")
        val locked = source.indexOf("NoKeyGate.lockedAnswer(type, state)")
        assertTrue("the retired answer comes before the locked check", retired in 0 until locked)
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
