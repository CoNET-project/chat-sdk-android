package network.conet.chat.nativekey

import java.io.File
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * resolveMarker with a failed erase: when the chain write has landed and the active slot holds the key, but the pending
 * key cannot be erased, the registration is not complete. The registering marker stays, no completed idempotency key is recorded, the chain is
 * not written again, and nothing is reported as discarded.
 */
class PgpResolveMarkerEraseTest {
    private val acceptance = JSONObject(File("../spec/pgp-restore-acceptance-vectors.v1.json").readText(Charsets.UTF_8))
    private val account = acceptance.getJSONObject("syntheticAccount").getString("address").lowercase()
    private val password = JSONObject(File("../spec/pgp-backup-compat-vectors.v1.json").readText(Charsets.UTF_8))
        .getJSONArray("positives").getJSONObject(0).getString("passwordString")

    private fun identityOf(name: String) = PgpIdentity(
        acceptance.getJSONObject("identities").getJSONObject(name).getString("fingerprint"),
        acceptance.getJSONObject("identities").getJSONObject(name).getString("subkeyKeyID"),
    )

    private fun armorOf(name: String): String = acceptance.getJSONObject("syntheticKeys").getJSONObject(name).getString("privateArmor")

    private class Chain : PgpRestoreChain {
        var id: PgpIdentity? = null
        var writes = 0
        override fun chainReadable(): Boolean = true
        override fun backupReadable(): Boolean = true
        override fun version(): Long = writes.toLong()
        override fun identity(): PgpIdentity? = id
        override fun backupText(): String = ""
        override fun write(identity: PgpIdentity, backupText: String) {
            id = identity
            writes++
        }
    }

    private fun machine(chain: PgpRestoreChain, files: NativeTestFiles) = PgpRestoreMachine(
        chain = chain,
        wallet = object : PgpRestoreWallet {
            override fun ready(): Boolean = true
            override fun passwordString(): String? = password
        },
        keys = object : PgpRestoreKeys {
            override fun newKey(deviceId: String): PgpNewKey = PgpNewKey(armorOf("P4"), identityOf("P4"))
        },
        ivFor = { ByteArray(12) { 1 } },
        devices = mapOf("A" to PgpRestoreDevice("A", account, NativeTestWrap(), files)),
    )

    @Test
    fun aLandedWriteWhosePendingKeyCannotBeErasedIsNotComplete() {
        val chain = Chain()
        val files = NativeTestFiles()
        val m = machine(chain, files)
        m.restore("A")
        m.tapEntry("A")
        assertEquals("ok", m.keygen("A", "idem-1", nativeConfirmed = true).result)

        // The pending key's erase fails when the registration is resolved. Everything before it succeeds: the chain write lands, the active slot holds the key.
        files.silentDeleteFailure = NativePgpVault.recName(account, NativePgpVault.Slot.PENDING)
        m.commit("A")

        val dev = m.devices.getValue("A")
        assertEquals("the chain is written once", 1, chain.writes)
        assertEquals("the write is not reported as complete", "pgp_write_in_progress", dev.ui.code)
        assertTrue("the registering marker stays", dev.registeringMarked())
        assertNotNull("the pending key is kept", files.read(NativePgpVault.recName(account, NativePgpVault.Slot.PENDING)))
        assertFalse("no completed idempotency key is recorded", files.read(NativePgpVault.completedName(account)) != null)
        assertEquals("nothing is reported as discarded", 0, m.counters.pendingDiscarded)
    }
}
