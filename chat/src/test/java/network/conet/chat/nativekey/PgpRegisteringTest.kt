package network.conet.chat.nativekey

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * The registering state (review): a chain write that is followed by a crash leaves the marker. The next evaluation reads the chain again and
 * resolves the marker (see PgpRegisteringResolutionTest for the unknown and past-limit cases). Nothing is written by the evaluation.
 */
class PgpRegisteringTest {
    private val acceptance = JSONObject(File("../spec/pgp-restore-acceptance-vectors.v1.json").readText(Charsets.UTF_8))
    private val account = acceptance.getJSONObject("syntheticAccount").getString("address").lowercase()
    private val password = JSONObject(File("../spec/pgp-backup-compat-vectors.v1.json").readText(Charsets.UTF_8))
        .getJSONArray("positives").getJSONObject(0).getString("passwordString")

    private fun identityOf(name: String) = PgpIdentity(
        acceptance.getJSONObject("identities").getJSONObject(name).getString("fingerprint"),
        acceptance.getJSONObject("identities").getJSONObject(name).getString("subkeyKeyID"),
    )

    private fun armorOf(name: String): String = acceptance.getJSONObject("syntheticKeys").getJSONObject(name).getString("privateArmor")

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

    @Test
    fun aCrashAfterTheChainWriteLeavesAnUnknownStateNotOk() {
        val files = NativeTestFiles()
        val dev = PgpRestoreDevice("A", account, NativeTestWrap(), files)
        val chain = RecordingChain()
        val m = PgpRestoreMachine(
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
        m.restore("A")
        m.tapEntry("A")
        m.keygen("A", "idem-1", nativeConfirmed = true)
        m.commit("A", crashAt = "after_write")
        assertEquals("the chain holds the new identity", 1, chain.writes)
        assertTrue("the registering marker stays", dev.registeringMarked())

        // Resolved by the read-back (registering resolution): the chain holds this identity, so the marker goes and the evaluation goes on.
        val again = m.restore("A")
        assertFalse("the marker goes once the chain holds the identity", dev.registeringMarked())
        assertNotEquals("pgp_write_in_progress", dev.ui.code)
        assertEquals("nothing written again by the evaluation", 1, chain.writes)
    }
}
