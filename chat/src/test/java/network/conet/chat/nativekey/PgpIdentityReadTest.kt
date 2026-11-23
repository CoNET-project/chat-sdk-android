package network.conet.chat.nativekey

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * G1: the identity read is three-state. A record that exists but whose public key does not parse is Unknown, not Absent,
 * so the restore answers undetermined (pgp_source_unavailable) and nothing is generated or overwritten. A vault slot with an unreadable record
 * is Unknown; only a confirmed empty slot is Absent.
 */
class PgpIdentityReadTest {
    private val acceptance = JSONObject(File("../spec/pgp-restore-acceptance-vectors.v1.json").readText(Charsets.UTF_8))
    private val account = acceptance.getJSONObject("syntheticAccount").getString("address").lowercase()
    private val password = JSONObject(File("../spec/pgp-backup-compat-vectors.v1.json").readText(Charsets.UTF_8))
        .getJSONArray("positives").getJSONObject(0).getString("passwordString")

    private fun armorOf(name: String): String = acceptance.getJSONObject("syntheticKeys").getJSONObject(name).getString("privateArmor")

    private fun addressChain(exists: Boolean, publicArmor: String): AddressPgpChain = AddressPgpChain(
        chainOk = true,
        backupOk = true,
        record = AddressPgpRead.Record(pgpKeyId = "", publicKeyArmored = publicArmor, encryptKeyArmored = "", exists = exists),
        backup = "",
    )

    @Test
    fun aRecordThatDoesNotParseIsUnknownNotAbsent() {
        val read = addressChain(exists = true, publicArmor = "not-a-public-key").identityRead()
        assertTrue("unknown, not absent: $read", read is IdentityRead.Unknown)
    }

    @Test
    fun aConfirmedEmptyRecordIsAbsent() {
        assertTrue(addressChain(exists = false, publicArmor = "").identityRead() is IdentityRead.Absent)
    }

    /** The restore on an unparseable record answers undetermined and generates nothing: no first identity is offered over it. */
    @Test
    fun theRestoreOnAnUnparseableRecordIsUndeterminedNotFirstIdentity() {
        val files = NativeTestFiles()
        val dev = PgpRestoreDevice("A", account, NativeTestWrap(), files)
        val machine = PgpRestoreMachine(
            chain = addressChain(exists = true, publicArmor = "garbage"),
            wallet = object : PgpRestoreWallet {
                override fun ready(): Boolean = true
                override fun passwordString(): String? = password
            },
            keys = object : PgpRestoreKeys {
                override fun newKey(deviceId: String): PgpNewKey = error("never generated")
            },
            ivFor = { error("never written") },
            devices = mapOf("A" to dev),
        )
        val step = machine.restore("A")
        assertEquals("undetermined", step.result)
        assertEquals("pgp_source_unavailable", dev.ui.code)
        assertEquals("undetermined", dev.ui.state)
    }

    /** The vault slot: a record with a broken marker is unknown; a slot with no record is absent. */
    @Test
    fun theVaultSlotIsThreeState() {
        val files = NativeTestFiles()
        val wrap = NativeTestWrap()
        val vault = NativePgpVault(wrap, files, account)
        assertTrue("empty slot is absent", vault.identityRead() is IdentityRead.Absent)
        assertEquals(NativePgpVault.Put.OK, vault.put(account, armorOf("P3"), ""))
        assertTrue("a readable record is present", vault.identityRead() is IdentityRead.Present)
        files.write(NativePgpVault.markName(account), ByteArray(64) { 0x41 })
        assertTrue("a broken marker is unknown", NativePgpVault(wrap, files, account).identityRead() is IdentityRead.Unknown)
    }
}
