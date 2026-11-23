package network.conet.chat.nativekey

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * G2 of the review of the restore path: a first identity is never registered over an active key. The probes failed on the unfixed
 * code (evidence kept outside the repository, under the PGP G1-G3 review record); they pass with the fix.
 */
class PgpG2Test {
    private val acceptance = JSONObject(File("../spec/pgp-restore-acceptance-vectors.v1.json").readText(Charsets.UTF_8))
    private val account = acceptance.getJSONObject("syntheticAccount").getString("address").lowercase()
    private val password = JSONObject(File("../spec/pgp-backup-compat-vectors.v1.json").readText(Charsets.UTF_8))
        .getJSONArray("positives").getJSONObject(0).getString("passwordString")

    private fun identityOf(name: String) = PgpIdentity(
        acceptance.getJSONObject("identities").getJSONObject(name).getString("fingerprint"),
        acceptance.getJSONObject("identities").getJSONObject(name).getString("subkeyKeyID"),
    )

    private fun armorOf(name: String): String = acceptance.getJSONObject("syntheticKeys").getJSONObject(name).getString("privateArmor")

    /** An empty chain that counts its writes and keeps what was written (the record is visible to later reads). */
    private class RecordingChain : PgpRestoreChain {
        var id: PgpIdentity? = null
        var text: String = ""
        var writes = 0
        override fun chainReadable(): Boolean = true
        override fun backupReadable(): Boolean = true
        override fun version(): Long = writes.toLong()
        override fun identity(): PgpIdentity? = id
        override fun backupText(): String = text
        override fun write(identity: PgpIdentity, backupText: String) {
            id = identity
            text = backupText
            writes++
        }
    }

    private fun machine(chain: PgpRestoreChain, files: NativeTestFiles, newKey: (String) -> PgpNewKey): PgpRestoreMachine {
        val wrap = NativeTestWrap()
        return PgpRestoreMachine(
            chain = chain,
            wallet = object : PgpRestoreWallet {
                override fun ready(): Boolean = true
                override fun passwordString(): String? = password
            },
            keys = object : PgpRestoreKeys {
                override fun newKey(deviceId: String): PgpNewKey = newKey(deviceId)
            },
            ivFor = { ByteArray(12) { 1 } },
            devices = mapOf("A" to PgpRestoreDevice("A", account, wrap, files)),
        )
    }

    /** G2: the chain is empty, the active slot already holds K_pgp (P3). The first-identity path must not register P4 over it. */
    @Test
    fun g2FirstIdentityDoesNotRegisterOverAnActiveKey() {
        val files = NativeTestFiles()
        val wrap = NativeTestWrap()
        val dev = PgpRestoreDevice("A", account, wrap, files)
        assertEquals(NativePgpVault.Put.OK, dev.active.put(account, armorOf("P3"), ""))
        val chain = RecordingChain()
        val m = machine(chain, files) { PgpNewKey(armorOf("P4"), identityOf("P4")) }
        m.restore("A")
        m.tapEntry("A")
        m.keygen("A", "idem-1", nativeConfirmed = true)
        m.commit("A")
        assertEquals("nothing is registered over the active key", 0, chain.writes)
        assertNotEquals("the device does not report ok", "ok", dev.ui.state)
    }

    /**
     * G2, the write-side guard: the first identity was offered over an empty slot, then the slot became occupied before the commit. The commit
     * must not register anything over it.
     */
    @Test
    fun g2CommitDoesNotRegisterWhenTheActiveSlotBecameOccupied() {
        val files = NativeTestFiles()
        val dev = PgpRestoreDevice("A", account, NativeTestWrap(), files)
        val chain = RecordingChain()
        val m = machine(chain, files) { PgpNewKey(armorOf("P4"), identityOf("P4")) }
        m.restore("A")
        m.tapEntry("A")
        m.keygen("A", "idem-1", nativeConfirmed = true)
        assertEquals(NativePgpVault.Put.OK, dev.active.put(account, armorOf("P3"), ""))
        m.commit("A")
        assertEquals("nothing registered over the occupied slot", 0, chain.writes)
        assertNotEquals("the device does not report ok", "ok", dev.ui.state)
    }


    /**
     * Mutation M2 (the first-identity guard in the evaluation removed): the active slot holds a key and the chain is empty: the evaluation must
     * not offer a first identity (it is undetermined), so nothing can be generated over the key.
     */
    @Test
    fun g2EvaluationDoesNotOfferAFirstIdentityOverAnOccupiedSlot() {
        val files = NativeTestFiles()
        val dev = PgpRestoreDevice("A", account, NativeTestWrap(), files)
        assertEquals(NativePgpVault.Put.OK, dev.active.put(account, armorOf("P3"), ""))
        val m = PgpRestoreMachine(
            chain = RecordingChain(),
            wallet = object : PgpRestoreWallet {
                override fun ready(): Boolean = true
                override fun passwordString(): String? = password
            },
            keys = object : PgpRestoreKeys {
                override fun newKey(deviceId: String): PgpNewKey = error("never generated")
            },
            ivFor = { ByteArray(12) { 1 } },
            devices = mapOf("A" to dev),
        )
        val step = m.evaluate("A")
        assertNotEquals("first_identity", dev.ui.state)
        assertEquals("undetermined", step.result)
        assertEquals("pgp_locked", dev.ui.code)
    }

    /** The direct registration (registerDirect) refuses an occupied slot: nothing is written. */
    @Test
    fun g2DirectRegistrationRefusesAnOccupiedSlot() {
        val files = NativeTestFiles()
        val dev = PgpRestoreDevice("A", account, NativeTestWrap(), files)
        assertEquals(NativePgpVault.Put.OK, dev.active.put(account, armorOf("P3"), ""))
        val chain = RecordingChain()
        val m = PgpRestoreMachine(
            chain = chain,
            wallet = object : PgpRestoreWallet {
                override fun ready(): Boolean = true
                override fun passwordString(): String? = password
            },
            keys = object : PgpRestoreKeys {
                override fun newKey(deviceId: String): PgpNewKey = error("never generated")
            },
            ivFor = { ByteArray(12) { 1 } },
            devices = mapOf("A" to dev),
        )
        val step = m.registerDirect(identityOf("P4"), "backup", expectedVersion = 0L, nativeConfirmed = true)
        assertEquals("cas_conflict", step.code)
        assertEquals("nothing registered", 0, chain.writes)
    }
}
