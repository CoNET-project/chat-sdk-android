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
 * The negative tests of spec §25.22 (`spec/negative-tests-v1.json`, registered in r3dp, §25.52BS; sha256 57c6bbfc…). Each case the SDK can run on
 * Android is run here. A case that cannot run is listed in [pending] with its reason: it is not a pass. The test fails if the set of pending cases
 * changes. The vector file is a byte copy of the interface file and is not edited.
 *
 * The vector's `shellOrigin` is a synthetic value (`https://shell.test.invalid`). The SDK's window channel accepts [BeamioShellRecordImport.ALLOWED_ORIGIN]
 * (§25.52D.5), so that origin stands for the vector's shell origin; every other origin is taken as written.
 */
class NegativeTestsVectorsTest {
    private val bytes = File("../spec/negative-tests-v1.json").readBytes()
    private val v = JSONObject(String(bytes, Charsets.UTF_8))

    /** The cases that are not run, with the reason. Each is a pending ruling or a state the SDK cannot produce through a public interface. */
    private val pending: Map<String, String> = buildMap {
        put("T-control-sign", "the purpose chatEnvelope is not in NativePgpVault.REGISTERED_PURPOSES (empty until the owner lists them); the internal C4 path awaits the ruling (R705)")
        put("T-127c", "walletTransferOnce is retired (25.24): the SDK answers not_supported, the vector expects accepted for a solicited call; the ruling is pending")
        for (id in listOf("T-130-01", "T-130-02", "T-130-03", "T-130-04", "T-130-05", "T-130-06", "T-130-07", "T-130-08", "T-130-09", "T-130-10",
            "T-130-11", "T-130-12", "T-130-13", "T-130-15", "T-130-16")) {
            put(id, "locked: Android has no public passcode or lock API; the locked state comes from record or marker integrity (NativeWalletVault.state), not a user action (BT.4)")
        }
        put("T-131", "the native-log surface: run by scripts/log-scan.py on the device logcat, not in the JVM tests (see the receipt)")
        put("T-132", "the WebView console and storage surface: run by scripts/log-scan.py on the device capture, not in the JVM tests (see the receipt)")
    }

    private val ran = mutableListOf<String>()

    private fun run(id: String, block: () -> Unit) {
        if (pending.containsKey(id)) return
        block()
        ran += id
    }

    private fun cases(section: String): List<JSONObject> {
        val arr = v.getJSONObject(section).getJSONArray("cases")
        return (0 until arr.length()).map { arr.getJSONObject(it) }
    }

    @Test
    fun vectorFileIsTheRegisteredCopy() {
        val sha = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
        assertEquals("57c6bbfcf51f0493188ca0bf6d792826c54585cc4f6acd3ebd237fa95ba790c0", sha)
    }

    @Test
    fun bridgeSourceCasesAcceptOnlyTheMainFrameOfTheShellOrigin() {
        // 25.52BS (r3dp): the window channel accepts a message from the main frame whose origin is the shell origin, and no other.
        // The rule is the expression of BeamioShellRecordImport.answerFromPage; it is asserted in the source, then replayed on answerAtBoundary.
        val source = File("src/main/java/network/conet/chat/nativekey/ShellRecord.kt").readText()
        assertTrue(source.contains("answerAtBoundary(isMainFrame && sourceOrigin == ALLOWED_ORIGIN, body, requestBytes)"))
        val shellOrigin = v.getString("shellOrigin")
        for (c in cases("bridgeSource")) {
            val id = c.getString("id")
            run(id) {
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
    }

    @Test
    fun pgpFixedDomainCasesRefuseUnknownPurposesAndCertificationTypes() {
        // The first two checks of NativePgpVault.sign: the signature type, then the purpose (registry). A refused case is not signed.
        val source = File("src/main/java/network/conet/chat/nativekey/NativePgpVault.kt").readText()
        assertTrue(source.contains("if (sigType !in NativePgp.ALLOWED_SIG_TYPES) return NativePgp.Outcome.fail(\"sig_type_not_allowed\")"))
        assertTrue(source.contains("purposeId !in registry"))
        val purposes = v.getJSONObject("pgpFixedDomain").getJSONArray("purposes")
        assertEquals(3, purposes.length())
        for (c in cases("pgpFixedDomain")) {
            val id = c.getString("id")
            run(id) {
                val req = c.getJSONObject("req")
                val sigType = req.getString("sigType").removePrefix("0x").toInt(16)
                val purpose = req.getString("purposeId")
                val signed = sigType in NativePgp.ALLOWED_SIG_TYPES && purpose in NativePgpVault.REGISTERED_PURPOSES
                assertEquals(id, c.getBoolean("expect"), signed)
            }
        }
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
            run(id) {
                val command = c.getString("command")
                if (c.optBoolean("carriesKey") && c.getString("expect") == "key_over_bridge_refused") {
                    // A key carried by an identity or PGP command is refused before the gate, with the field name (25.52AQ.2).
                    val names = CredFields.refusalNames(command, JSONObject().put("privateKeyHex", "x"))
                    assertEquals(id, listOf("privateKeyHex"), names)
                } else if (command == "walletTransferOnce") {
                    // A retired name is not_supported in every state (25.24): an unsolicited call is refused.
                    assertEquals(id, NoKeyGate.Route.NOT_SUPPORTED, NoKeyGate.route(command))
                    assertEquals(id, "refused", c.getString("expect"))
                }
            }
        }
    }

    @Test
    fun passcodeLockedCaseForPgpSignIsUnknownCommand() {
        // T-130-14 (BP.1, BS): pgpSign is not a bridge name, so it is unknown_command in every state, locked included.
        val c = cases("passcodeLocked").single { it.getString("id") == "T-130-14" }
        run("T-130-14") {
            assertEquals("T-130-14", "unknown_command", c.getString("expect"))
            assertFalse("pgpSign is not registered", BridgeCommandTable.isRegistered("pgpSign"))
        }
    }

    @Test
    fun theLogScanPositiveControlNamesAPatternTheScannerMustHit() {
        // T-131-control: the scanner must hit an injected pattern. The scan itself runs on device logs (scripts/log-scan.py, see the receipt).
        val log = v.getJSONObject("logScan")
        assertEquals("the control is named", "T-131-control（扫描器必须命中一条注入的模式）", log.getString("positiveControl"))
        val patterns = log.getJSONArray("patterns")
        assertTrue(patterns.length() > 0)
        val controls = cases("logScan").single { it.getString("id") == "T-131-control" }
        assertEquals(listOf("wallet-private-key-hex"), (0 until controls.getJSONArray("expect").length()).map { controls.getJSONArray("expect").getString(it) })
    }

    @Test
    fun theSetOfCasesNotRunIsTheListedOne() {
        // The pending list is exact: a case moves out of it only when it runs. Every case of the file is either run or listed.
        val all = listOf("bridgeSource", "pgpFixedDomain", "importPolicy", "passcodeLocked", "logScan").flatMap { s -> cases(s).map { it.getString("id") } }
        assertEquals(35, all.size)
        assertNotNull(pending["T-control-sign"])
        val unknownToThePending = pending.keys.filter { it !in all }
        assertTrue("pending ids exist in the file: $unknownToThePending", unknownToThePending.isEmpty())
    }
}
