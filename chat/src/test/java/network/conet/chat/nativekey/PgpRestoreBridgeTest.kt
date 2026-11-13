package network.conet.chat.nativekey

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * The P-IMP-PGP restore commands (§25.35) against the bridge vectors, group C. Each in-scope case builds the chain state the
 * case describes, runs the command through the real machine, and compares the ack result or the event with the vector.
 * `pgpIdentityCreate` (C-10 to C-24) is the chain write path, which is not implemented: it is covered by the refusal test only.
 */
class PgpRestoreBridgeTest {
    private val acceptance = JSONObject(
        String(File(System.getenv("PGP_RESTORE_VECTORS") ?: "../spec/pgp-restore-acceptance-vectors.v1.json").readBytes(), Charsets.UTF_8),
    )
    private val bridge = JSONObject(
        String(File(System.getenv("PGP_BRIDGE_VECTORS") ?: "../spec/pgp-bridge-command-vectors.v1.json").readBytes(), Charsets.UTF_8),
    )
    private val backupCompat = JSONObject(
        String(File(System.getenv("PGP_BACKUP_VECTORS") ?: "../spec/pgp-backup-compat-vectors.v1.json").readBytes(), Charsets.UTF_8),
    )
    private val password = backupCompat.getJSONArray("positives").getJSONObject(0).getString("passwordString")
    private val account = acceptance.getJSONObject("syntheticAccount").getString("address").lowercase()

    private fun identityOf(name: String) = PgpIdentity(
        acceptance.getJSONObject("identities").getJSONObject(name).getString("fingerprint"),
        acceptance.getJSONObject("identities").getJSONObject(name).getString("subkeyKeyID"),
    )

    private fun backupOf(label: String): String = acceptance.getJSONObject("backups").getJSONObject(label).getString("base64")

    /** A chain that is what the case describes: readable or not, with or without an identity and a backup. */
    private class FakeChain(
        private val readable: Boolean,
        private val backupReadable: Boolean,
        private val id: PgpIdentity?,
        private val text: String,
    ) : PgpRestoreChain {
        override fun chainReadable(): Boolean = readable
        override fun backupReadable(): Boolean = backupReadable
        override fun version(): Long = 0L
        override fun identity(): PgpIdentity? = id
        override fun backupText(): String = text
        override fun write(identity: PgpIdentity, backupText: String) = error("the restore never writes the chain")
    }

    private fun machineFor(chain: PgpRestoreChain, files: NativeTestFiles): PgpRestoreMachine = PgpRestoreMachine(
        chain = chain,
        wallet = object : PgpRestoreWallet {
            override fun ready(): Boolean = true
            override fun passwordString(): String? = password
        },
        keys = object : PgpRestoreKeys {
            override fun newKey(deviceId: String): PgpNewKey = error("the restore never generates a key")
        },
        ivFor = { error("the restore never writes a backup") },
        devices = mapOf(PgpRestoreBridge.DEVICE to PgpRestoreDevice(PgpRestoreBridge.DEVICE, account, NativeTestWrap(), files)),
    )

    /** The chain state each in-scope group C case describes. */
    private fun chainFor(caseId: String): PgpRestoreChain = when (caseId) {
        "C-01" -> FakeChain(true, true, identityOf("P3"), "")                        // backup missing
        "C-02" -> FakeChain(true, true, null, "")                                     // no record: first identity
        "C-03" -> FakeChain(false, false, null, "")                                   // read failed: undetermined
        "C-06" -> FakeChain(true, true, identityOf("P3"), backupOf("B_P3_UNDER_A"))   // ok
        "C-07" -> FakeChain(true, true, identityOf("P4"), backupOf("B_P3_UNDER_A"))   // fingerprint mismatch
        "C-08" -> FakeChain(true, true, null, backupOf("B_P3_UNDER_A"))               // backup without registration
        "C-09" -> FakeChain(true, true, identityOf("P3"), "AAAA-not-a-backup")        // undecryptable
        else -> error("no chain for $caseId")
    }

    private fun caseById(id: String): JSONObject {
        val cases = bridge.getJSONArray("cases")
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            if (c.getString("id") == id) return c
        }
        error("no case $id")
    }

    @Test
    fun evaluateCasesMatchTheVectorAckAndWriteNothing() {
        for (id in listOf("C-01", "C-02", "C-03")) {
            val c = caseById(id)
            val files = NativeTestFiles()
            val machine = machineFor(chainFor(id), files)
            val got = PgpRestoreBridge.evaluate(machine)
            val want = c.getJSONObject("expect").getJSONObject("ack").getJSONObject("result")
            assertEquals(id, want.getString("state"), got.getString("state"))
            assertEquals(id, want.optString("failureClass", "").ifEmpty { null }, got.optString("failureClass", "").ifEmpty { null })
            assertEquals(id, want.optString("code", "").ifEmpty { null }, got.optString("code", "").ifEmpty { null })
            assertEquals(id, want.getBoolean("offerEntry"), got.getBoolean("offerEntry"))
            assertEquals(id, want.optString("uiKey", "").ifEmpty { null }, got.optString("uiKey", "").ifEmpty { null })
            // Evaluation is read only: nothing is written to the native store.
            assertTrue("$id wrote nothing", files.map.isEmpty())
            assertEquals(0, machine.counters.localWrites)
        }
    }

    @Test
    fun aMatchingEvaluationIsOkAndStillWritesNothing() {
        val files = NativeTestFiles()
        val machine = machineFor(chainFor("C-06"), files)
        val got = PgpRestoreBridge.evaluate(machine)
        assertEquals("ok", got.getString("state"))
        assertTrue(files.map.isEmpty())
        assertEquals(0, machine.counters.localWrites)
    }

    @Test
    fun restoreCasesSendTheVectorEventCodeAndWriteOnlyOnAMatch() {
        for (id in listOf("C-06", "C-07", "C-08", "C-09")) {
            val c = caseById(id)
            val wantCode = c.getJSONObject("expect").getJSONArray("events").getJSONObject(0).getString("code")
            val files = NativeTestFiles()
            val machine = machineFor(chainFor(id), files)
            val event = PgpRestoreBridge.restore(machine)
            assertEquals(id, wantCode, event.getString("code"))
            if (wantCode == "ok") {
                assertEquals(id, 1, machine.counters.localWrites)
                assertTrue(id, files.map.isNotEmpty())
            } else {
                assertEquals(id, 0, machine.counters.localWrites)
                assertTrue("$id wrote nothing", files.map.isEmpty())
            }
        }
    }

    @Test
    fun aFailedRestoreCarriesTheFailureClassAndTheEntry() {
        val files = NativeTestFiles()
        val event = PgpRestoreBridge.restore(machineFor(chainFor("C-07"), files))
        assertEquals("failed", event.getString("state"))
        assertEquals("fingerprint_mismatch", event.getString("failureClass"))
        assertEquals("chat.restore_failed.body", event.getString("uiKey"))
    }

    @Test
    fun theGateRefusesEvaluateAndRestoreBeforeAnyPayloadInG1AndG0() {
        // C-04 and C-05 (and C-23, C-24 for the create command): the gate answers, nothing else runs.
        for (command in listOf("pgpRestoreEvaluate", "pgpRestore")) {
            assertEquals(NoKeyGate.Route.NO_KEY, NoKeyGate.route(command))
            assertEquals("not_ready", NoKeyGate.answerFor(command, NoKeyGate.Gate.G1))
            assertEquals("no_key", NoKeyGate.answerFor(command, NoKeyGate.Gate.G0))
        }
    }

    @Test
    fun theChainWriteCommandIsNotImplementedAndTheChainIsNotTouched() {
        // The write path (pgpIdentityCreate, C-10 to C-22) is pending approval (§25.44). The adapter refuses any write.
        val chain = AddressPgpChain.read(account, AddressPgpConfig("0x684b0ac760cEE9c9b85de36d69746420648Cf9e2", emptyList())) {
            error("no endpoint")
        }
        try {
            chain.write(identityOf("P3"), "x")
            throw AssertionError("the chain write must be refused")
        } catch (e: IllegalStateException) {
            assertTrue(e.message!!.contains("not implemented"))
        }
        assertFalse(chain.chainReadable())
    }
}
