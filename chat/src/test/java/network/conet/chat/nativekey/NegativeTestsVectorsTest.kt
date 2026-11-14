package network.conet.chat.nativekey

import network.conet.chat.BridgeCommandTable
import network.conet.chat.identity.CredFields
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.security.MessageDigest

/**
 * The negative tests of spec §25.22 (`spec/negative-tests-v1.json`, registered revision r3dz, §25.52BZ; sha256 ccc445ec…). Each case the SDK can run on
 * Android is run here. A case that cannot run is listed in [pending] with its reason: it is not a pass. The test fails if the pending set changes.
 * The vector file is a byte copy of the interface file and is not edited.
 *
 * The vector's `shellOrigin` is a synthetic value (`https://shell.test.invalid`). The SDK's window channel accepts [BeamioShellRecordImport.ALLOWED_ORIGIN]
 * (§25.52D.5), so that origin stands for the vector's shell origin; every other origin is taken as written.
 *
 * The locked state of the passcode families (§25.22.4) is produced by the vault itself: a record whose marker does not match is `Locked` (the only
 * locked state the SDK has; Android has no passcode API, 25.52BZ.4 and the receipt).
 */
class NegativeTestsVectorsTest {
    private val bytes = File("../spec/negative-tests-v1.json").readBytes()
    private val v = JSONObject(String(bytes, Charsets.UTF_8))

    /** The cases that are not run here, with the reason. Each is a pending ruling, a vector gap, or a surface run elsewhere. */
    private val pending: Map<String, String> = buildMap {
        put("T-control-sign", "signature output not applicable: chatEnvelope is not registered (25.52BW.1, BZ.2); the domain tag is checked by a separate test")
        put("T-130-04", "conflicts with T-130-14 and 25.52BP.1: family C4 expects locked for pgpSign, but pgpSign is unknown_command in every state; ruling pending")
        put("T-130-06", "family W5 has no bridge name (25.52AR.3), so there is no command to run")
        for (id in listOf("T-130-09", "T-130-10", "T-130-11", "T-130-12")) {
            put(id, "family N1-N4: no command mapping in the vector (25.52BZ.5); ruling pending")
        }
        put("T-130-16", "family identityReady: no command mapping in the vector (25.52BZ.5); ruling pending")
        put("T-131", "native-log surface: run by scripts/log-scan.py on the device logcat, not in the JVM tests (see the receipt)")
        put("T-132", "WebView console and storage surface: run by scripts/log-scan.py on the device capture, not in the JVM tests (see the receipt)")
    }

    private fun cases(section: String): List<JSONObject> {
        val arr = v.getJSONObject(section).getJSONArray("cases")
        return (0 until arr.length()).map { arr.getJSONObject(it) }
    }

    /** A record whose marker does not match: the vault reports `Locked` (NativeWalletVault.state). */
    private fun lockedState(): NativeWalletVault.State {
        val files = NativeTestFiles()
        val wrap = NativeTestWrap()
        val key = ByteArray(32) { 0x11 }
        val eoa = requireNotNull(WalletAddress.fromPrivateKey(key)).lowercase()
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importKey(eoa, key))
        files.map[NativeWalletVault.MARK] = "00".toByteArray()
        return NativeWalletVault(wrap, files).state()
    }

    @Test
    fun vectorFileIsTheRegisteredCopy() {
        val sha = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
        assertEquals("ccc445ec563b6b3fcbdecf0c891ede5caec289fc6ef6911db08dee5ebf266c5b", sha)
        assertEquals(35, cases("bridgeSource").size + cases("pgpFixedDomain").size + cases("importPolicy").size +
            cases("passcodeLocked").size + cases("logScan").size)
    }

    @Test
    fun bridgeSourceCasesAcceptOnlyTheMainFrameOfTheShellOrigin() {
        // 25.52BS: the window channel accepts a message from the main frame whose origin is the shell origin, and no other.
        // The rule is the expression of BeamioShellRecordImport.answerFromPage; it is asserted in the source, then replayed on answerAtBoundary.
        val source = File("src/main/java/network/conet/chat/nativekey/ShellRecord.kt").readText()
        assertTrue(source.contains("answerAtBoundary(isMainFrame && sourceOrigin == ALLOWED_ORIGIN, body, requestBytes)"))
        val shellOrigin = v.getString("shellOrigin")
        for (c in cases("bridgeSource")) {
            val id = c.getString("id")
            val src = c.getJSONObject("src")
            val origin = src.getString("origin").let { if (it == shellOrigin) BeamioShellRecordImport.ALLOWED_ORIGIN else it }
            val answer = answerAtBoundary(
                originAllowed = src.getBoolean("isMainFrame") && origin == BeamioShellRecordImport.ALLOWED_ORIGIN,
                body = JSONObject().put("type", "shellRecordRead").put("reqId", "neg"),
                requestBytes = 40,
            ) { _, _ -> JSONObject().put("ok", true) }
            assertEquals(id, c.getBoolean("expect"), answer != null)
        }
    }

    @Test
    fun pgpFixedDomainCasesRefuseUnknownPurposesAndCertificationTypes() {
        // The first two checks of NativePgpVault.sign: the signature type, then the purpose (registry). A refused case is not signed.
        val source = File("src/main/java/network/conet/chat/nativekey/NativePgpVault.kt").readText()
        assertTrue(source.contains("if (sigType !in NativePgp.ALLOWED_SIG_TYPES) return NativePgp.Outcome.fail(\"sig_type_not_allowed\")"))
        assertTrue(source.contains("purposeId !in registry"))
        for (c in cases("pgpFixedDomain")) {
            val id = c.getString("id")
            if (pending.containsKey(id)) continue
            val req = c.getJSONObject("req")
            val sigType = req.getString("sigType").removePrefix("0x").toInt(16)
            val purpose = req.getString("purposeId")
            val signed = sigType in NativePgp.ALLOWED_SIG_TYPES && purpose in NativePgpVault.REGISTERED_PURPOSES
            assertEquals(id, c.getBoolean("expect"), signed)
        }
    }

    @Test
    fun theDomainTagOfTheEnumeratedPurposeIsTheFixedOne() {
        // T-control-sign (25.52BZ.2): the signature output is not applicable here, but the domain tag still is checked.
        val c = cases("pgpFixedDomain").single { it.getString("id") == "T-control-sign" }
        assertEquals(c.getString("domainTag"), NativePgpVault.domainLabel(c.getJSONObject("req").getString("purposeId")))
    }

    @Test
    fun importPolicyCasesRefuseKeysOverTheBridgeAndForbidTheImportNames() {
        val policy = v.getJSONObject("importPolicy")
        val forbidden = policy.getJSONArray("forbiddenImportCommandNames")
        for (i in 0 until forbidden.length()) {
            val name = forbidden.getString(i)
            assertFalse("$name is not a bridge name", BridgeCommandTable.isRegistered(name))
        }
        for (c in cases("importPolicy")) {
            val id = c.getString("id")
            val command = c.getString("command")
            if (c.optBoolean("carriesKey") && c.getString("expect") == "key_over_bridge_refused") {
                // A key carried by an identity or PGP command is refused before the gate, with the field name (25.52AQ.2).
                assertEquals(id, listOf("privateKeyHex"), CredFields.refusalNames(command, JSONObject().put("privateKeyHex", "x")))
            } else if (command == "walletTransferOnce") {
                // A retired name is not_supported in every state (25.24, 25.52BZ.3), solicited or not.
                assertEquals(id, NoKeyGate.Route.NOT_SUPPORTED, NoKeyGate.route(command))
                assertEquals(id, "not_supported", c.getString("expect"))
            }
        }
    }

    @Test
    fun theLockedFamilyCommandsAreTheMappedOnesOfTheVector() {
        // 25.52BZ.4: the families that answer locked, by the bridge names the vector maps them to. pgpSign is not one of them (BP.1).
        val mapped = cases("passcodeLocked")
            .filter { it.getString("expect") == "locked" }
            .flatMap { c -> c.optJSONArray("commands")?.let { a -> (0 until a.length()).map { a.getString(it) } } ?: emptyList() }
            .toSet() - "pgpSign"
        assertEquals(mapped, NoKeyGate.LOCKED_FAMILY_COMMANDS)
    }

    @Test
    fun passcodeLockedCasesAnswerLockedForTheMappedFamiliesAndTheRestAsTheVectorSays() {
        val locked = lockedState()
        assertTrue("the record is locked", locked is NativeWalletVault.State.Locked)
        for (c in cases("passcodeLocked")) {
            val id = c.getString("id")
            if (pending.containsKey(id)) continue
            val expect = c.getString("expect")
            val commands = c.optJSONArray("commands")
            when (expect) {
                "locked" -> {
                    val name = (0 until commands!!.length()).map { commands.getString(it) }.single()
                    assertEquals(id, "locked", NoKeyGate.lockedAnswer(name, locked))
                }
                "unknown_command" -> {
                    // T-130-14 (25.52BP.1): pgpSign is not a bridge name; the lock does not change that.
                    assertFalse(id, BridgeCommandTable.isRegistered("pgpSign"))
                    assertNull(id, NoKeyGate.lockedAnswer("pgpSign", locked))
                }
                "not_supported" -> {
                    // T-130-15 (25.52BZ.3): a retired name is not_supported in every state, the lock included.
                    assertEquals(id, NoKeyGate.Route.NOT_SUPPORTED, NoKeyGate.route("walletTransferOnce"))
                    assertNull(id, NoKeyGate.lockedAnswer("walletTransferOnce", locked))
                }
            }
        }
    }

    @Test
    fun theLogScanPositiveControlNamesThePatternTheVectorExpects() {
        // T-131-control: the scanner must hit an injected pattern. The scan itself runs on device logs (scripts/log-scan.py, see the receipt).
        val log = v.getJSONObject("logScan")
        assertEquals("T-131-control（扫描器必须命中一条注入的模式）", log.getString("positiveControl"))
        assertTrue(log.getJSONArray("patterns").length() > 0)
        val control = cases("logScan").single { it.getString("id") == "T-131-control" }
        assertEquals(listOf("wallet-private-key-hex"), (0 until control.getJSONArray("expect").length()).map { control.getJSONArray("expect").getString(it) })
    }

    @Test
    fun thePendingCasesAreExactlyTheListedOnes() {
        // Every case of the file is either run by a test above or listed here with its reason. The pending ids exist in the file.
        val all = listOf("bridgeSource", "pgpFixedDomain", "importPolicy", "passcodeLocked", "logScan").flatMap { s -> cases(s).map { it.getString("id") } }
        assertEquals(35, all.size)
        val unknown = pending.keys.filter { it !in all }
        assertTrue("pending ids exist in the file: $unknown", unknown.isEmpty())
        assertEquals(10, pending.size)
        assertNotNull(pending["T-control-sign"])
    }
}
