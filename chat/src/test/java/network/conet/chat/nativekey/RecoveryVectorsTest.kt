package network.conet.chat.nativekey

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * The shared restore vectors (`pgp-restore-acceptance-vectors.v1.json`, `pgp-backup-compat-vectors.v1.json`) run for real through the page restore with the
 * recovery gate on: the vector keys sign the challenge and the registered public key (the vector key's own public armor, read as the registry's) verifies it.
 */
class RecoveryVectorsTest {
    private val acceptance = JSONObject(File("../spec/pgp-restore-acceptance-vectors.v1.json").readText(Charsets.UTF_8))
    private val backupCompat = JSONObject(File("../spec/pgp-backup-compat-vectors.v1.json").readText(Charsets.UTF_8))
    private val password = backupCompat.getJSONArray("positives").getJSONObject(0).getString("passwordString")
    private val account = acceptance.getJSONObject("syntheticAccount").getString("address").lowercase()

    private fun identityOf(name: String) = PgpIdentity(
        acceptance.getJSONObject("identities").getJSONObject(name).getString("fingerprint"),
        acceptance.getJSONObject("identities").getJSONObject(name).getString("subkeyKeyID"),
    )

    private fun publicArmorOf(name: String): String =
        NativePgpKeyGen.publicArmorOf(acceptance.getJSONObject("syntheticKeys").getJSONObject(name).getString("privateArmor"))!!

    private fun backupOf(label: String): String = acceptance.getJSONObject("backups").getJSONObject(label).getString("base64")

    private fun registered(identity: PgpIdentity, armorOf: String, source: RegisteredPgpKey.Source = RegisteredPgpKey.Source.SINGLE) = RegisteredKeyRead.Present(
        RegisteredPgpKey(
            account, identity.fingerprint, identity.subkeyKeyId, publicArmorOf(armorOf), 5L, source,
            AddressPgpChain.CONET_CHAIN_ID, AddressPgpConfig.default.contract.lowercase(),
        ),
    )

    private fun run(chain: PgpRestoreChain, files: NativeTestFiles = NativeTestFiles()): Pair<JSONObject, NativeTestFiles> {
        val machine = PgpRestoreMachine(
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
            recoveryGate = PageRecoveryGate(),
        )
        return PgpRestoreBridge.restore(machine) to files
    }

    @Test
    fun theVectorBackupOfTheRegisteredKeyRestoresThroughTheGate() {
        val (result, files) = run(RecChain(registered = registered(identityOf("P3"), "P3"), backup = backupOf("B_P3_UNDER_A")))
        assertEquals("ok", result.getString("code"))
        assertTrue(files.map.isNotEmpty())
    }

    @Test
    fun aVectorBackupOfAnotherKeyIsAFingerprintMismatchAndWritesNothing() {
        // Case C-07: the registry holds P4, the backup is P3's.
        val (result, files) = run(RecChain(registered = registered(identityOf("P4"), "P4"), backup = backupOf("B_P3_UNDER_A")))
        assertEquals("pgp_fingerprint_mismatch", result.getString("code"))
        assertTrue(files.map.isEmpty())
    }

    @Test
    fun aRecordThatNamesP3ButHoldsP4sPublicRingFailsTheChallengeAndWritesNothing() {
        val forged = registered(identityOf("P3"), "P4")
        val (result, files) = run(RecChain(registered = forged, backup = backupOf("B_P3_UNDER_A")))
        assertEquals("pgp_verify_failed", result.getString("code"))
        assertTrue(files.map.isEmpty())
    }

    @Test
    fun theUndecryptableAndMissingVectorBackupsStillFailAsBeforeAndWriteNothing() {
        val ids = registered(identityOf("P3"), "P3")
        val (undecryptable, f1) = run(RecChain(registered = ids, backup = "AAAA-not-a-backup"))
        assertEquals("pgp_backup_undecryptable", undecryptable.getString("code"))
        assertTrue(f1.map.isEmpty())
        val (missing, f2) = run(RecChain(registered = ids, backup = ""))
        assertEquals("pgp_backup_missing", missing.getString("code"))
        assertTrue(f2.map.isEmpty())
        val (wrongPw, f3) = run(RecChain(registered = ids, backup = backupOf("B_WRONG_PW")))
        assertTrue(wrongPw.getString("code").startsWith("pgp_"))
        assertTrue(f3.map.isEmpty())
    }

    @Test
    fun anUnreadableRegistryIsUndeterminedAndWritesNothing() {
        val (result, files) = run(RecChain(readable = false, registered = RegisteredKeyRead.Unknown, backup = backupOf("B_P3_UNDER_A")))
        assertEquals("pgp_source_unavailable", result.getString("code"))
        assertTrue(files.map.isEmpty())
    }

    // ---- the same vectors, with the record in the shape the chain really holds (base64 text of the armor) ----------------------------------

    private fun chainWith(stored: String?, backup: String) = ChainFixture.single(
        account,
        ChainFixture.Endpoint(record = ChainFixture.recordHex(stored), backup = ChainFixture.backupHex(backup)),
    )

    @Test
    fun theVectorBackupRestoresThroughTheRealReaderOnABase64Record() {
        val (result, files) = run(chainWith(ChainFixture.base64Of(publicArmorOf("P3")), backupOf("B_P3_UNDER_A")))
        assertEquals("ok", result.getString("code"))
        assertTrue(files.map.isNotEmpty())
    }

    @Test
    fun theVectorBackupRestoresThroughTheRealReaderOnARawRecordToo() {
        val (result, _) = run(chainWith(publicArmorOf("P3"), backupOf("B_P3_UNDER_A")))
        assertEquals("ok", result.getString("code"))
    }

    @Test
    fun aBase64RecordOfAnotherVectorKeyIsAFingerprintMismatchAndWritesNothing() {
        val (result, files) = run(chainWith(ChainFixture.base64Of(publicArmorOf("P4")), backupOf("B_P3_UNDER_A")))
        assertEquals("pgp_fingerprint_mismatch", result.getString("code"))
        assertTrue(files.map.isEmpty())
    }

    @Test
    fun aBase64RecordWithNoBackupOffersTheEntryAndAnAbsentRecordIsAFirstIdentity() {
        val (missing, f1) = run(chainWith(ChainFixture.base64Of(publicArmorOf("P3")), ""))
        assertEquals("pgp_backup_missing", missing.getString("code"))
        assertTrue(f1.map.isEmpty())
        val machineNone = chainWith(null, "")
        assertTrue(machineNone.identityRead() is IdentityRead.Absent)
    }

    @Test
    fun aRecordThatIsNeitherAnArmorNorBase64IsUndeterminedNotAFirstIdentity() {
        val (result, files) = run(chainWith("this is not a key", backupOf("B_P3_UNDER_A")))
        assertEquals("pgp_source_unavailable", result.getString("code"))
        assertTrue(files.map.isEmpty())
    }
}
