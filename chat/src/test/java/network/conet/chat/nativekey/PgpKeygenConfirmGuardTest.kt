package network.conet.chat.nativekey

import java.io.File
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Confirmation-stage guard: the user's confirmation re-reads the chain before any key is generated. A first identity
 * is never generated on a chain that already holds a registration, so no second identity can be created.
 */
class PgpKeygenConfirmGuardTest {
    private val acceptance = JSONObject(File("../spec/pgp-restore-acceptance-vectors.v1.json").readText(Charsets.UTF_8))
    private val account = acceptance.getJSONObject("syntheticAccount").getString("address").lowercase()
    private val password = JSONObject(File("../spec/pgp-backup-compat-vectors.v1.json").readText(Charsets.UTF_8))
        .getJSONArray("positives").getJSONObject(0).getString("passwordString")

    private fun identityOf(name: String) = PgpIdentity(
        acceptance.getJSONObject("identities").getJSONObject(name).getString("fingerprint"),
        acceptance.getJSONObject("identities").getJSONObject(name).getString("subkeyKeyID"),
    )

    private fun armorOf(name: String): String = acceptance.getJSONObject("syntheticKeys").getJSONObject(name).getString("privateArmor")

    /** A chain whose record can change between the restore screen and the confirmation (a registration by another client). */
    private class ChangingChain : PgpRestoreChain {
        var id: PgpIdentity? = null
        var unreadable = false
        var writes = 0
        override fun chainReadable(): Boolean = !unreadable
        override fun backupReadable(): Boolean = true
        override fun version(): Long = writes.toLong()
        override fun identity(): PgpIdentity? = id
        override fun identityRead(): IdentityRead = when {
            unreadable -> IdentityRead.Unknown
            id == null -> IdentityRead.Absent
            else -> IdentityRead.Present(id!!)
        }
        override fun backupText(): String = ""
        override fun write(identity: PgpIdentity, backupText: String) {
            id = identity
            writes++
        }
    }

    private fun machine(chain: PgpRestoreChain, files: NativeTestFiles, generated: MutableList<String>): PgpRestoreMachine = PgpRestoreMachine(
        chain = chain,
        wallet = object : PgpRestoreWallet {
            override fun ready(): Boolean = true
            override fun passwordString(): String? = password
        },
        keys = object : PgpRestoreKeys {
            override fun newKey(deviceId: String): PgpNewKey {
                generated += deviceId
                return PgpNewKey(armorOf("P4"), identityOf("P4"))
            }
        },
        ivFor = { ByteArray(12) { 1 } },
        devices = mapOf("A" to PgpRestoreDevice("A", account, NativeTestWrap(), files)),
    )

    @Test
    fun aChainRegisteredAfterTheOfferGeneratesNoKeyAndWritesNothing() {
        val files = NativeTestFiles()
        val chain = ChangingChain()
        val generated = mutableListOf<String>()
        val m = machine(chain, files, generated)
        m.restore("A")
        assertEquals("first_identity", m.devices.getValue("A").ui.state)
        m.tapEntry("A")
        // Another client registers between the offer and the confirmation.
        chain.id = identityOf("P3")
        val step = m.keygen("A", "idem-1", nativeConfirmed = true)
        assertEquals("rejected", step.result)
        assertEquals("cas_conflict", step.code)
        assertTrue("no key is generated on a registered chain", generated.isEmpty())
        assertEquals("nothing is written", 0, chain.writes)
    }

    @Test
    fun anUnreadableChainAtConfirmationIsRefused() {
        val files = NativeTestFiles()
        val chain = ChangingChain()
        val generated = mutableListOf<String>()
        val m = machine(chain, files, generated)
        m.restore("A")
        m.tapEntry("A")
        chain.unreadable = true
        val step = m.keygen("A", "idem-2", nativeConfirmed = true)
        assertEquals("cas_conflict", step.code)
        assertTrue("an unreadable chain generates no key", generated.isEmpty())
    }
}
