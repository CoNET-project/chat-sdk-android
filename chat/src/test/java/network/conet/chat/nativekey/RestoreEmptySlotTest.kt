package network.conet.chat.nativekey

import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Review v7 item 2: restore writes only an empty slot. Each case reaches the write branch with a decryptable backup for the chain identity; the
 * active slot is never overwritten (its record bytes are unchanged).
 */
class RestoreEmptySlotTest {
    private val acceptance = JSONObject(File("../spec/pgp-restore-acceptance-vectors.v1.json").readText(Charsets.UTF_8))
    private val account = acceptance.getJSONObject("syntheticAccount").getString("address").lowercase()
    private val password = JSONObject(File("../spec/pgp-backup-compat-vectors.v1.json").readText(Charsets.UTF_8))
        .getJSONArray("positives").getJSONObject(0).getString("passwordString")

    private fun identityOf(name: String) = PgpIdentity(
        acceptance.getJSONObject("identities").getJSONObject(name).getString("fingerprint"),
        acceptance.getJSONObject("identities").getJSONObject(name).getString("subkeyKeyID"),
    )

    private fun armorOf(name: String): String = acceptance.getJSONObject("syntheticKeys").getJSONObject(name).getString("privateArmor")

    private class Chain(var id: PgpIdentity?, var text: String) : PgpRestoreChain {
        var writes = 0
        override fun chainReadable(): Boolean = true
        override fun backupReadable(): Boolean = true
        override fun version(): Long = 0L
        override fun identity(): PgpIdentity? = id
        override fun backupText(): String = text
        override fun write(identity: PgpIdentity, backupText: String) {
            writes++
            id = identity
            text = backupText
        }
    }

    private inner class Fixture(chain: Chain, generates: Boolean = false) {
        val files = NativeTestFiles()
        val dev = PgpRestoreDevice("A", account, NativeTestWrap(), files)
        val chain = chain
        val m = PgpRestoreMachine(
            chain = chain,
            wallet = object : PgpRestoreWallet {
                override fun ready(): Boolean = true
                override fun passwordString(): String? = password
            },
            keys = object : PgpRestoreKeys {
                override fun newKey(deviceId: String): PgpNewKey =
                    if (generates) PgpNewKey(armorOf("P4"), identityOf("P4")) else error("restore never generates a key")
            },
            ivFor = { ByteArray(12) { 1 } },
            devices = mapOf("A" to dev),
        )

        fun activeRecordBytes(): ByteArray? = files.read(NativePgpVault.recName(account))
    }

    private fun backupOf(name: String): String =
        NativePgpBackup.encryptArmor(password, armorOf(name).toByteArray(Charsets.UTF_8), ByteArray(12) { 1 })

    @Test
    fun anEmptySlotIsWrittenFromADecryptableBackup() {
        val f = Fixture(Chain(identityOf("P4"), backupOf("P4")))
        assertEquals("ok", f.m.restore("A").result)
        assertEquals("the empty slot was written", identityOf("P4").fingerprint, f.dev.active.identity()?.fingerprint)
        assertEquals("the chain is never written by restore", 0, f.chain.writes)
    }

    /** The write branch is entered (the active key differs from the chain identity) and refuses: the existing key is not overwritten. */
    @Test
    fun anActiveKeyThatDiffersIsNeverOverwrittenByTheRestore() {
        val f = Fixture(Chain(identityOf("P4"), backupOf("P4")))
        assertEquals(NativePgpVault.Put.OK, f.dev.active.put(account, armorOf("P2"), ""))
        val before = f.activeRecordBytes()
        val r = f.m.restore("A")
        assertEquals("undetermined", r.result)
        assertEquals("pgp_locked", f.dev.ui.code)
        assertArrayEquals("the active record bytes are unchanged", before, f.activeRecordBytes())
        assertEquals(identityOf("P2").fingerprint, f.dev.active.identity()?.fingerprint)
        assertEquals(0, f.chain.writes)
    }

    /** The active slot holds the chain's own key: nothing is written (no second write of the same key). */
    @Test
    fun anActiveKeyThatMatchesIsLeftAsItIs() {
        val f = Fixture(Chain(identityOf("P4"), backupOf("P4")))
        assertEquals(NativePgpVault.Put.OK, f.dev.active.put(account, armorOf("P4"), ""))
        val before = f.activeRecordBytes()
        assertEquals("ok", f.m.restore("A").result)
        assertArrayEquals(before, f.activeRecordBytes())
    }

    /** An unreadable active slot is not empty: the restore does not write over it (pgp_locked). */
    @Test
    fun aLockedActiveSlotIsNeverWrittenOver() {
        val f = Fixture(Chain(identityOf("P4"), backupOf("P4")))
        assertEquals(NativePgpVault.Put.OK, f.dev.active.put(account, armorOf("P2"), ""))
        f.files.delete(NativePgpVault.markName(account))
        assertTrue("the active slot is Locked", f.dev.active.state() is NativePgpVault.State.Locked)
        val before = f.activeRecordBytes()
        f.m.restore("A")
        assertEquals("pgp_locked", f.dev.ui.code)
        assertArrayEquals(before, f.activeRecordBytes())
    }

    /**
     * Review r9 probe, as a case: the local active write fails after the chain write. The pending key and the marker stay, no completed key is
     * recorded, the state is write_failed, and nothing is resolved (5B 2(a)). A later run completes it once the slot can be written.
     */
    @Test
    fun aFailedActiveWriteAfterTheChainWriteKeepsThePendingKeyAndTheMarker() {
        val chain = Chain(null, "")
        val f = Fixture(chain, generates = true)
        f.m.restore("A")
        f.m.tapEntry("A")
        f.m.keygen("A", "idem-1", nativeConfirmed = true)
        f.files.failWrite = NativePgpVault.recName(account)
        val step = f.m.commit("A")
        assertEquals("the chain holds K1", identityOf("P4").fingerprint, chain.id?.fingerprint)
        assertEquals("undetermined", step.result)
        assertEquals("write_failed", f.dev.ui.code)
        assertTrue("the active slot stays empty", f.dev.active.state() is NativePgpVault.State.NoKey)
        assertTrue("the pending key stays", f.dev.pending.state() is NativePgpVault.State.Ready)
        assertTrue("the marker stays", f.dev.registeringMarked())
        assertTrue("no completed key is recorded", f.dev.completedIdem() != "idem-1")
        assertEquals(null, f.files.read("pgp.restore.registering.resolved.$account"))

        f.files.failWrite = null
        f.m.restore("A")
        assertTrue("the active slot is written from the same key", f.dev.active.state() is NativePgpVault.State.Ready)
        assertEquals(identityOf("P4").fingerprint, f.dev.active.identity()?.fingerprint)
        assertTrue("the pending key goes once resolved", f.dev.pending.state() is NativePgpVault.State.NoKey)
        assertTrue("the marker goes once resolved", !f.dev.registeringMarked())
    }

    /** The same probe with the marker write failing on the active side: the state is kept the same way. */
    @Test
    fun aFailedActiveMarkerWriteAfterTheChainWriteKeepsThePendingKey() {
        val chain = Chain(null, "")
        val f = Fixture(chain, generates = true)
        f.m.restore("A")
        f.m.tapEntry("A")
        f.m.keygen("A", "idem-1", nativeConfirmed = true)
        f.files.failWrite = NativePgpVault.markName(account)
        f.m.commit("A")
        assertTrue("the pending key stays", f.dev.pending.state() is NativePgpVault.State.Ready)
        assertTrue("no completed key", f.dev.completedIdem() != "idem-1")
    }

    /**
     * Review r10: a registering marker that cannot be written is a controlled failure. The chain is not written, the pending key stays, and no
     * completed key is recorded; the next commit (with the marker writable) registers with the same key.
     */
    @Test
    fun aMarkerThatCannotBeWrittenIsAControlledFailureAndNothingReachesTheChain() {
        val chain = Chain(null, "")
        val f = Fixture(chain, generates = true)
        f.m.restore("A")
        f.m.tapEntry("A")
        f.m.keygen("A", "idem-1", nativeConfirmed = true)
        f.files.failWrite = "pgp.restore.registering.$account"
        val step = f.m.commit("A")
        assertEquals("undetermined", step.result)
        assertEquals("write_failed", f.dev.ui.code)
        assertEquals("the chain is not written", 0, chain.writes)
        assertTrue("the pending key stays", f.dev.pending.state() is NativePgpVault.State.Ready)
        assertTrue("no completed key", f.dev.completedIdem() != "idem-1")

        f.files.failWrite = null
        f.m.commit("A")
        assertEquals("ok", f.dev.ui.state)
        assertEquals("the same key registers once", 1, chain.writes)
        assertEquals(identityOf("P4").fingerprint, chain.id?.fingerprint)
    }
}
