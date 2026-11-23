package network.conet.chat.nativekey

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * LK-01..04 of `spec/rpc-state-vectors.v1.json` (draft r2.5.20 第 6 版, 5B and the local-state rule): the pending slot's local probe.
 * absent = no entry (NoKey), present = readable (Ready), Locked = an entry that cannot be read (counts as pending), failed = the enumeration fails
 * (unknown, never absent). Synthetic keys only.
 */
class LocalProbeVectorsTest {
    private val doc = JSONObject(File("../spec/rpc-state-vectors.v1.json").readText(Charsets.UTF_8))
    private val acceptance = JSONObject(File("../spec/pgp-restore-acceptance-vectors.v1.json").readText(Charsets.UTF_8))
    private val account = acceptance.getJSONObject("syntheticAccount").getString("address").lowercase()

    private fun armorOf(name: String): String = acceptance.getJSONObject("syntheticKeys").getJSONObject(name).getString("privateArmor")

    /** Reads of the pending slot's files throw when [failPending] is set: the enumeration of that slot fails. */
    private class ProbeFiles(private val inner: VaultFiles, private val failPending: Boolean) : VaultFiles {
        var writes = 0
        override fun read(name: String): ByteArray? {
            if (failPending && name.startsWith("pgp.v1.pending.")) error("enumeration failed")
            return inner.read(name)
        }
        override fun write(name: String, bytes: ByteArray) {
            writes++
            inner.write(name, bytes)
        }
        override fun delete(name: String) = inner.delete(name)
    }

    private data class Probe(val label: String, val pendingExists: Boolean?)

    /** Runs one LK case and returns the Android label and the pending-exists value (null when the probe cannot answer). */
    private fun probe(id: String): Probe {
        val files = NativeTestFiles()
        val wrap = NativeTestWrap()
        val pendingKey = NativePgpVault(wrap, files, account, NativePgpVault.Slot.PENDING)
        return when (id) {
            "LK-01" -> {
                val state = pendingKey.state()
                Probe(if (state is NativePgpVault.State.NoKey) "absent" else "other", state !is NativePgpVault.State.NoKey)
            }
            "LK-02" -> {
                assertEquals(NativePgpVault.Put.OK, pendingKey.put(account, armorOf("P4"), ""))
                val state = pendingKey.state()
                Probe(if (state is NativePgpVault.State.Ready) "present" else "other", state !is NativePgpVault.State.NoKey)
            }
            "LK-03" -> {
                assertEquals(NativePgpVault.Put.OK, pendingKey.put(account, armorOf("P4"), ""))
                files.delete(NativePgpVault.markName(account, NativePgpVault.Slot.PENDING))
                val state = pendingKey.state()
                Probe(if (state is NativePgpVault.State.Locked) "Locked" else "other", state !is NativePgpVault.State.NoKey)
            }
            "LK-04" -> {
                assertEquals(NativePgpVault.Put.OK, pendingKey.put(account, armorOf("P4"), ""))
                val failing = NativePgpVault(wrap, ProbeFiles(files, failPending = true), account, NativePgpVault.Slot.PENDING)
                // The enumeration fails: the probe answers nothing. It must not answer absent (NoKey).
                val answer = runCatching { failing.state() }
                Probe(if (answer.isFailure) "failed" else "other", null)
            }
            else -> error("no probe for $id")
        }
    }

    @Test
    fun thereAreFourLocalProbeCases() {
        val lk = (0 until doc.getJSONArray("cases").length()).map { doc.getJSONArray("cases").getJSONObject(it) }.filter { it.getString("id").startsWith("LK-") }
        assertEquals(4, lk.size)
    }

    @Test
    fun eachLocalProbeMatchesItsVector() {
        val lk = (0 until doc.getJSONArray("cases").length()).map { doc.getJSONArray("cases").getJSONObject(it) }.filter { it.getString("id").startsWith("LK-") }
        for (c in lk) {
            val id = c.getString("id")
            val want = c.getJSONObject("expect")
            val got = probe(id)
            val wantLabel = when (want.getString("state")) {
                "absent" -> "absent"
                "present" -> "present"
                "Locked" -> "Locked"
                "failed" -> "failed"
                else -> error("state of $id")
            }
            assertEquals("$id state", wantLabel, got.label)
            if (want.has("pendingExists") && got.pendingExists != null) {
                assertEquals("$id pendingExists", want.getBoolean("pendingExists"), got.pendingExists)
            }
        }
    }

    /** LK-04 end to end: a failed enumeration of the pending slot during the evaluation is unknown, and nothing is written. */
    @Test
    fun aFailedEnumerationIsUnknownNotAbsentInTheEvaluation() {
        val inner = NativeTestFiles()
        val dev0 = PgpRestoreDevice("A", account, NativeTestWrap(), inner)
        assertEquals(NativePgpVault.Put.OK, dev0.pending.put(account, armorOf("P4"), ""))
        dev0.markRegistering(100L)
        val files = ProbeFiles(inner, failPending = true)
        val dev = PgpRestoreDevice("A", account, NativeTestWrap(), files)
        val m = PgpRestoreMachine(
            chain = object : PgpRestoreChain {
                override fun chainReadable(): Boolean = true
                override fun backupReadable(): Boolean = true
                override fun version(): Long = 0L
                override fun identity(): PgpIdentity? = null
                override fun backupText(): String = ""
                override fun write(identity: PgpIdentity, backupText: String) = error("no write")
            },
            wallet = object : PgpRestoreWallet {
                override fun ready(): Boolean = true
                override fun passwordString(): String? = "x"
            },
            keys = object : PgpRestoreKeys {
                override fun newKey(deviceId: String): PgpNewKey = error("no key")
            },
            ivFor = { ByteArray(12) },
            devices = mapOf("A" to dev),
        )
        val writesBefore = files.writes
        val r = m.evaluate("A")
        assertEquals("undetermined", r.result)
        assertEquals("pgp_source_unavailable", dev.ui.code)
        assertEquals("nothing written", writesBefore, files.writes)
        assertFalse("never taken as an empty pending slot", dev.ui.state == "first_identity")
        assertTrue("the marker stays", dev.registeringMarked())
    }
}
