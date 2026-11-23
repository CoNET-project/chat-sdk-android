package network.conet.chat.nativekey

import network.conet.chat.BridgeCommandTable
import network.conet.chat.localread.NativeHistoryDelete
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * The page-record gate exceptions and the shared judgement (spec r3bz §25.52AD.2 to §25.52AD.5; GX-01 to GX-10b, 11 cases; T-369 to T-372).
 *
 * An imported copy under G0 is an account for `shellRecord` (GX-01, GX-02). Other native names stay `no_key` under G0, with or without a copy
 * (GX-06, GX-07). A fresh device is `absent` once the reader has finished (GX-03, GX-10a); before that it is `migrating` (GX-05). An unreadable
 * legacy store is `legacy_store_unreadable` (GX-04). G1 is `not_ready` (GX-08), and the origin is checked first (GX-09).
 *
 * GX-10b: the chat-module channel gets no reply on Android (§25.52AB.5). The case therefore checks that the chat channel sends nothing,
 * and that the judgement the window channel gives for the same request is `absent`, which the chat channel would share.
 */
class GateExceptionTest {
    // The vectors through the sidecar (25.52AL.3): placeholders of the profiles are mapped to test keys for this run only.
    private val doc = VectorSidecar.map(
        JSONObject(
            String(
                File(System.getenv("PGP_MIGRATION_VECTORS") ?: "../spec/pgp-migration-vectors.v1.json").readBytes(),
                Charsets.UTF_8,
            ),
        ),
    )

    @Test
    fun everyGateExceptionCaseMatchesItsExpectation() {
        val failures = mutableListOf<String>()
        val cases = doc.getJSONArray("gateExceptionCases")
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            failures += runCase(c).map { "${c.getString("id")}: $it" }
        }
        assertEquals(emptyList<String>(), failures)
    }

    @Test
    fun aCopyNamedByTwoFilesIsNotDiscovered() {
        val files = NativeTestFiles()
        val wrap = NativeTestWrap()
        val storeFor = storeFactory(wrap, files)
        storeFor(A1).write(heldRecord(A1))
        storeFor(A2).write(heldRecord(A2))
        assertNull(ShellRecordAccounts.heldCopy(files.map.keys.toList(), storeFor))
    }

    @Test
    fun aCopyWithoutTheEoaKeyIsNotHeld() {
        val files = NativeTestFiles()
        val wrap = NativeTestWrap()
        val storeFor = storeFactory(wrap, files)
        val record = JSONObject().put("rev", 1).put("schemaVersion", 2)
            .put("profiles", JSONArray().put(JSONObject().put("keyID", A1).put("emailAddr", "a")))
        storeFor(A1).write(record)
        assertNull(ShellRecordAccounts.heldCopy(files.map.keys.toList(), storeFor))
    }

    @Test
    fun anUnreadableCopyIsARecordAndNeverAbsent() {
        val files = NativeTestFiles()
        val wrap = NativeTestWrap()
        files.write(COPY_NAME, ByteArray(40) { 7 })
        val account = ShellRecordAccounts.heldCopy(listOf(COPY_NAME), storeFactory(wrap, files))
        assertTrue(account is ShellRecordAccount.Ready)
        val bridge = ShellRecordBridge(account = { account!! }, migrating = { false }, outcome = { ImportOutcome.ABSENT }, flags = NoDeviceFlags)
        val ack = bridge.handle(ShellOrigin.EMBEDDED_PAGE, JSONObject().put("type", "shellRecordRead").put("reqId", "u1"), 0)
        val result = ack.v()
        assertEquals("error", result.getString("code"))
        assertEquals("record_unreadable", result.getString("sub"))
    }

    @Test
    fun aNotReadyAnswerComesBeforeThePayloadIsChecked() {
        val bridge = ShellRecordBridge(account = { ShellRecordAccount.NotReady }, migrating = { false }, outcome = { null }, flags = NoDeviceFlags)
        // An extra key would be a bad_request with a name. The gate answers first, so the payload is not read.
        val body = JSONObject().put("type", "shellRecordWrite").put("reqId", "n1").put("record", JSONObject()).put("extra", 1)
        val ack = bridge.handle(ShellOrigin.EMBEDDED_PAGE, body, 0)
        val want = JSONObject().put("type", "ack").put("reqId", "n1").put("ok", false).put("error", "not_ready")
        assertEquals(CanonicalJson.encode(want), CanonicalJson.encode(ack))
    }

    @Test
    fun theSessionGateDoesNotApplyToTheNativeCreation() {
        val vault = NativeWalletVault.State.Ready(A1)
        val gated = ShellRecordAccounts.resolve(
            vault, sessionReady = false, sessionGate = true, bound = null,
            copyNames = { emptyList() }, storeOf = storeFactory(NativeTestWrap(), NativeTestFiles()),
        )
        assertEquals(ShellRecordAccount.NotReady, gated)
        val native = ShellRecordAccounts.resolve(
            vault, sessionReady = false, sessionGate = false, bound = null,
            copyNames = { emptyList() }, storeOf = storeFactory(NativeTestWrap(), NativeTestFiles()),
        )
        assertTrue(native is ShellRecordAccount.Ready)
    }

    @Test
    fun theChatChannelAnswersShellRecordReadOnceAsNotSupported() {
        // 25.52AY.1 (r3cw): on the chat channel shellRecordRead is not_supported, once. Not silent.
        assertEquals("not_supported", BridgeCommandTable.chatChannelShellRecordCode("shellRecordRead"))
    }

    @Test
    fun otherNativeNamesStayNoKeyUnderG0WhateverTheCopy() {
        // The gate reads only the vault state, so a copy of the page record cannot change it (GX-06, GX-07).
        val gate = NoKeyGate.gateOf(NativeWalletVault.State.NoKey, sessionReady = false)
        assertEquals(NoKeyGate.Gate.G0, gate)
        assertEquals(NoKeyGate.NO_KEY, NoKeyGate.answerFor("identityPublic", gate))
        assertEquals(NoKeyGate.NO_KEY, NoKeyGate.answerFor("historyOpenConversation", gate))
        // The copy does give shellRecord an account (GX-01).
        val files = NativeTestFiles()
        val wrap = NativeTestWrap()
        storeFactory(wrap, files)(A1).write(heldRecord(A1))
        val copy = ShellRecordAccounts.resolve(
            NativeWalletVault.State.NoKey, sessionReady = false, sessionGate = true, bound = null,
            copyNames = { files.map.keys.toList() }, storeOf = storeFactory(wrap, files),
        )
        assertTrue(copy is ShellRecordAccount.Ready)
    }

    @Test
    fun theDeleteCommandsKeepTheGateOfHistoryOpen() {
        // r3by §25.52AC.5: the same gate as historyOpenConversation (G0 no_key, G1 not_ready).
        assertEquals(NoKeyGate.NO_KEY, NoKeyGate.answerFor(NativeHistoryDelete.MESSAGE, NoKeyGate.Gate.G0))
        assertEquals(NoKeyGate.NOT_READY, NoKeyGate.answerFor(NativeHistoryDelete.CONVERSATION, NoKeyGate.Gate.G1))
    }

    private fun runCase(c: JSONObject): List<String> {
        val expect = c.getJSONObject("expect")
        if (c.getString("kind") == "other") {
            val gate = NoKeyGate.gateOf(NativeWalletVault.State.NoKey, sessionReady = false)
            val answer = NoKeyGate.answerFor("identityPublic", gate)
            return if (answer == expect.getString("error")) emptyList() else listOf("gate $answer != ${expect.getString("error")}")
        }
        // GX-10b is a recorded deviation from the vector, pinned by gx10bChatChannelDeviatesFromTheVectorByR476. Not compared here.
        if (c.getJSONObject("input").optString("channel") == "chat") return emptyList()
        val judged = judge(c)
        // The vectors name the account a1; the expectation is mapped the same way as the input.
        return compare(judged.window, withA1(expect))
    }

    /** The window channel's answer to the case's request, and the request itself. */
    private class Judged(val window: JSONObject, val body: JSONObject)

    private fun judge(c: JSONObject): Judged {
        val input = c.getJSONObject("input")
        val files = NativeTestFiles()
        val wrap = NativeTestWrap()
        val storeFor = storeFactory(wrap, files)
        val copy = input.optBoolean("copy")
        if (copy) storeFor(A1).write(withA1(input.getJSONObject("store").getJSONObject("record")))
        val names = if (copy) listOf(COPY_NAME) else emptyList()
        val vault: NativeWalletVault.State =
            if (input.optString("gate") == "G1") NativeWalletVault.State.Ready(A1) else NativeWalletVault.State.NoKey
        val account = ShellRecordAccounts.resolve(
            vault, sessionReady = false, sessionGate = true, bound = null, copyNames = { names }, storeOf = storeFor,
        )
        val outcome = when (input.optString("legacy")) {
            "absent" -> ImportOutcome.ABSENT
            "unreadable" -> ImportOutcome.LEGACY_UNREADABLE
            else -> null
        }
        // §25.52Y.157 (GX-01): under native G0 a read returns the page copy without the three W fields (Y.151 第 2 項).
        val bridge = ShellRecordBridge(
            account = { account }, migrating = { false }, outcome = { outcome }, flags = NoDeviceFlags,
            nativeNoKey = { vault is NativeWalletVault.State.NoKey },
        )
        val origin = if (input.optString("origin") == "refused") ShellOrigin.OTHER else ShellOrigin.EMBEDDED_PAGE

        val req = c.getJSONObject("req")
        val body = JSONObject().put("type", if (c.getString("kind") == "read") "shellRecordRead" else "shellRecordWrite")
        for (k in req.keys()) body.put(k, if (k == "record") withA1(req.getJSONObject(k)) else req.get(k))
        val window = bridge.handle(origin, body, body.toString().toByteArray(Charsets.UTF_8).size)

        return Judged(window, body)
    }

    /**
     * GX-10b (recorded deviation, §25.52AB.5). The vector expects the chat channel to answer `absent`. The rule says the chat channel never
     * replies, and the implementation follows the rule. This test pins the deviation without editing the vector: the chat channel answers not_supported (AY.1),
     * and the judgement the window channel gives for the same request is the vector's `absent`. The decision belongs to the interface owner.
     */
    @Test
    fun gx10bChatChannelDeviatesFromTheVectorByR476() {
        val cases = doc.getJSONArray("gateExceptionCases")
        val c = (0 until cases.length()).map { cases.getJSONObject(it) }.single { it.getString("id") == "GX-10b" }
        val judged = judge(c)
        assertEquals("the chat channel answers not_supported (AY.1)", "not_supported",
            BridgeCommandTable.chatChannelShellRecordCode(judged.body.getString("type")))
        assertEquals(emptyList<String>(), compare(judged.window, withA1(c.getJSONObject("expect"))))
    }

    /** The ack against the vector's expectation: the reqId and `ok`, then the error, or each field of the expected result. */
    private fun compare(resp: JSONObject, expect: JSONObject): List<String> {
        val out = mutableListOf<String>()
        if (resp.optString("type") != "ack") return listOf("not an ack: $resp")
        if (expect.has("reqId") && resp.opt("reqId") != expect.opt("reqId")) out += "reqId ${resp.opt("reqId")}"
        if (resp.optBoolean("ok") != expect.getBoolean("ok")) out += "ok ${resp.opt("ok")}"
        if (!expect.getBoolean("ok")) {
            if (resp.optString("error") != expect.getString("error")) out += "error ${resp.opt("error")} != ${expect.getString("error")}"
            return out
        }
        val want = expect.getJSONObject("result")
        val got = resp.getJSONObject("result")
        for (k in want.keys()) {
            if (CanonicalJson.encode(got.opt(k)) != CanonicalJson.encode(want.opt(k))) {
                out += "result.$k ${CanonicalJson.encode(got.opt(k))} != ${CanonicalJson.encode(want.opt(k))}"
            }
        }
        return out
    }

    companion object {
        /** The vectors' account `a1`, written as a 40-digit address, so that the copy's file name is the one the store makes. */
        val A1 = VectorSidecar.ACCOUNT
        val A2 = "0x" + "b2".repeat(20)
        val COPY_NAME = "page.v1.${A1.removePrefix("0x")}.default.rec"

        internal fun storeFactory(wrap: KeyWrap, files: VaultFiles): (String) -> SealedPageRecordStore =
            { eoa -> SealedPageRecordStore(wrap, files, eoa.lowercase() + ":default") }

        fun heldRecord(eoa: String): JSONObject = JSONObject().put("rev", 2).put("schemaVersion", 2)
            .put("profiles", JSONArray().put(JSONObject().put("keyID", eoa).put("privateKeyArmor", VectorSidecar.ARMOR_OF_ACCOUNT)))
            .put("mnemonicPhrase", "M")

        /** The vectors name the account `a1`; this maps that label to [A1] wherever it is a quoted value. */
        fun withA1(o: JSONObject): JSONObject = JSONObject(o.toString().replace("\"a1\"", "\"$A1\""))
    }
}
