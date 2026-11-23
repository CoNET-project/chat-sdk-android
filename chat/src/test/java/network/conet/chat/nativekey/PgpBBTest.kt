package network.conet.chat.nativekey

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test
import java.io.File

/**
 * B-B (review): the write path re-reads the chain before the write and reads it back after. A commit done under an idempotency key is not
 * repeated. The stale snapshot in the first test says the chain is empty while the live chain holds another identity: nothing is written.
 */
class PgpBBTest {
    private val acceptance = JSONObject(File("../spec/pgp-restore-acceptance-vectors.v1.json").readText(Charsets.UTF_8))
    private val account = acceptance.getJSONObject("syntheticAccount").getString("address").lowercase()
    private val password = JSONObject(File("../spec/pgp-backup-compat-vectors.v1.json").readText(Charsets.UTF_8))
        .getJSONArray("positives").getJSONObject(0).getString("passwordString")

    private fun identityOf(name: String) = PgpIdentity(
        acceptance.getJSONObject("identities").getJSONObject(name).getString("fingerprint"),
        acceptance.getJSONObject("identities").getJSONObject(name).getString("subkeyKeyID"),
    )

    private fun armorOf(name: String): String = acceptance.getJSONObject("syntheticKeys").getJSONObject(name).getString("privateArmor")

    /** The live record; the snapshot the machine holds can be older than it (a stale adapter). */
    private class LiveChain {
        var id: PgpIdentity? = null
        var text: String = ""
        var writes = 0
        var persistWrites = true
    }

    private class StaleChain(private val live: LiveChain) : PgpRestoreChain {
        private val snapshotId: PgpIdentity? = live.id
        private val snapshotText: String = live.text
        override fun chainReadable(): Boolean = true
        override fun backupReadable(): Boolean = true
        override fun version(): Long = 0L
        override fun identity(): PgpIdentity? = snapshotId
        override fun backupText(): String = snapshotText
        override fun write(identity: PgpIdentity, backupText: String) {
            live.writes++
            if (live.persistWrites) {
                live.id = identity
                live.text = backupText
            }
        }
        override fun reread(): PgpRestoreChain = object : PgpRestoreChain {
            override fun chainReadable(): Boolean = true
            override fun backupReadable(): Boolean = true
            override fun version(): Long = live.writes.toLong()
            override fun identity(): PgpIdentity? = live.id
            override fun backupText(): String = live.text
            override fun write(identity: PgpIdentity, backupText: String) = error("not used")
        }
    }

    private fun machine(chain: PgpRestoreChain, files: NativeTestFiles, dev: PgpRestoreDevice): PgpRestoreMachine = PgpRestoreMachine(
        chain = chain,
        wallet = object : PgpRestoreWallet {
            override fun ready(): Boolean = true
            override fun passwordString(): String? = password
        },
        keys = object : PgpRestoreKeys {
            override fun newKey(deviceId: String): PgpNewKey = PgpNewKey(armorOf("P4"), identityOf("P4"))
        },
        ivFor = { ByteArray(12) { 1 } },
        devices = mapOf("A" to dev),
    )

    /** Pre-write re-read: the snapshot says empty, the live chain already holds P3. The commit must not register P4 over it. */
    @Test
    fun theCommitRereadsTheChainBeforeWriting() {
        val files = NativeTestFiles()
        val dev = PgpRestoreDevice("A", account, NativeTestWrap(), files)
        val live = LiveChain()
        val m = machine(StaleChain(live), files, dev)
        m.restore("A")
        m.tapEntry("A")
        m.keygen("A", "idem-1", nativeConfirmed = true)
        live.id = identityOf("P3") // another client registered in the meantime
        live.text = "other-backup"
        m.commit("A")
        assertEquals("no write after a live change", 0, live.writes)
        assertNotEquals("ok", dev.ui.state)
    }

    /** Post-write read-back: a write that does not persist is write_failed, not ok, and the marker stays (unknown). */
    @Test
    fun aWriteThatDoesNotPersistIsWriteFailedWithTheMarkerKept() {
        val files = NativeTestFiles()
        val dev = PgpRestoreDevice("A", account, NativeTestWrap(), files)
        val live = LiveChain().apply { persistWrites = false }
        val m = machine(StaleChain(live), files, dev)
        m.restore("A")
        m.tapEntry("A")
        m.keygen("A", "idem-1", nativeConfirmed = true)
        m.commit("A")
        assertEquals(1, live.writes)
        // P2 (review 3): an absent read-back after the write is its own undetermined code; the marker and the pending key stay.
        assertEquals("readback_failed", dev.ui.code)
        assertEquals("undetermined", dev.ui.state)
        assertEquals(true, dev.registeringMarked())
    }

    /** Client dedupe by idempotency key: a commit repeated after the first succeeded writes nothing more. */
    @Test
    fun aRepeatedCommitUnderTheSameKeyIsNotRepeated() {
        val files = NativeTestFiles()
        val dev = PgpRestoreDevice("A", account, NativeTestWrap(), files)
        val live = LiveChain()
        val m = machine(StaleChain(live), files, dev)
        m.restore("A")
        m.tapEntry("A")
        m.keygen("A", "idem-1", nativeConfirmed = true)
        m.commit("A")
        assertEquals("ok", dev.ui.state)
        assertEquals(1, live.writes)
        m.keygen("A", "idem-1", nativeConfirmed = true) // the same key again: noop
        m.commit("A")
        assertEquals("no second write under the same key", 1, live.writes)
    }

    /**
     * Mutation M6 (commit without the idempotency dedupe): a pending key that is still on the device, under the key already completed, must not be
     * written again. The meta is of kind "replace" with the current version, so only the dedupe stops the second write.
     */
    @Test
    fun aCommitUnderACompletedKeyIsNotWrittenAgain() {
        val files = NativeTestFiles()
        val dev = PgpRestoreDevice("A", account, NativeTestWrap(), files)
        val live = LiveChain()
        val m = machine(StaleChain(live), files, dev)
        m.restore("A")
        m.tapEntry("A")
        m.keygen("A", "idem-1", nativeConfirmed = true)
        m.commit("A")
        assertEquals(1, live.writes)
        // The pending key is still there under the completed key (the clear did not survive); the chain version is the current one.
        assertEquals(NativePgpVault.Put.OK, dev.pending.put(account, armorOf("P4"), ""))
        dev.writePendingMeta(PendingMeta("idem-1", live.writes.toLong(), "replace"))
        val step = m.commit("A")
        assertEquals("noop", step.result)
        assertEquals("the completed key is not written again", 1, live.writes)
    }

}
