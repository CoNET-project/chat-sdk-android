package network.conet.chat.nativekey

import network.conet.chat.BeamioChatPgpStore
import network.conet.chat.identity.CredFields
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.SecureRandom

/**
 * The registered public key as the chain stores it: the registration writes the armor as base64 text, so every reader decodes it. A real
 * record shape (base64) runs through the two real readers and both recoveries; a raw armor still works; a text that is neither is unknown, never absent.
 */
class RegisteredArmorTest {
    private val random = SecureRandom()
    private val account = "0x" + "ab".repeat(20)
    private val own = RecKeys.generate(account, random)
    private val other = RecKeys.generate(account, random)
    private val accountKey = ByteArray(32) { (it + 3).toByte() }
    private val canonical = NativePgpBackup.passwordString(accountKey)
    private val forms: () -> List<String>? = { NativePgpBackup.passwordForms(accountKey) }

    private fun backupOf(pgp: RecPgp): String =
        NativePgpBackup.encryptArmor(canonical, pgp.privateArmor.toByteArray(Charsets.UTF_8), ByteArray(12).also { random.nextBytes(it) })

    private fun endpoint(stored: String?, backup: String = "") = ChainFixture.Endpoint(record = ChainFixture.recordHex(stored), backup = ChainFixture.backupHex(backup))

    // ---- the normalizer ---------------------------------------------------------------------------------------------------------------

    @Test
    fun aRawArmorIsUsedAsItIs() {
        assertEquals(own.publicArmor, RegisteredArmor.normalize(own.publicArmor))
        assertEquals(own.identity, RegisteredArmor.identityOf(own.publicArmor))
    }

    @Test
    fun aBase64ArmorIsDecodedAndHasTheSameIdentity() {
        val stored = ChainFixture.base64Of(own.publicArmor)
        assertFalse(stored.contains("BEGIN"))
        assertEquals(own.publicArmor, RegisteredArmor.normalize(stored))
        assertEquals(own.identity, RegisteredArmor.identityOf(stored))
        assertEquals("surrounding whitespace of the stored text is not part of it", own.identity, RegisteredArmor.identityOf("  $stored\n"))
    }

    @Test
    fun anythingElseIsNull() {
        assertNull(RegisteredArmor.normalize(""))
        assertNull(RegisteredArmor.normalize("   "))
        assertNull("neither an armor nor base64", RegisteredArmor.normalize("not an armor!"))
        assertNull("base64 of something that is not an armor", RegisteredArmor.normalize(ChainFixture.base64Of("hello world")))
        assertNull("base64 with a broken pad", RegisteredArmor.normalize(ChainFixture.base64Of(own.publicArmor).dropLast(1)))
    }

    @Test
    fun aPrivateKeyHeaderOrAnyOtherBeginHeaderIsUnknownNotAnArmor() {
        val privateArmor = own.privateArmor
        assertTrue("fixture is a private armor", privateArmor.contains("BEGIN PGP PRIVATE KEY BLOCK"))
        assertNull("a bare private armor", RegisteredArmor.normalize(privateArmor))
        assertNull("a private armor as base64", RegisteredArmor.normalize(ChainFixture.base64Of(privateArmor)))
        assertNull("another BEGIN header", RegisteredArmor.normalize("-----BEGIN PGP MESSAGE-----\n\nabc\n-----END PGP MESSAGE-----"))
        assertNull("a public armor with text in front", RegisteredArmor.normalize("note\n" + own.publicArmor))
        assertNull("a public armor followed by a private block", RegisteredArmor.normalize(own.publicArmor + "\n" + privateArmor))
        assertNull("the same, as base64", RegisteredArmor.normalize(ChainFixture.base64Of(own.publicArmor + "\n" + privateArmor)))
        assertNull("identity of a bare private armor", RegisteredArmor.identityOf(privateArmor))
        val chain = ChainFixture.single(account, endpoint(privateArmor))
        assertTrue("a bare private armor in the record is unknown", chain.registeredKey() is RegisteredKeyRead.Unknown)
        assertTrue(chain.identityRead() is IdentityRead.Unknown)
        assertNull(RegisteredArmor.identityOf(ChainFixture.base64Of("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nxx\n-----END PGP PUBLIC KEY BLOCK-----")))
    }

    // ---- the real readers with a base64 record ---------------------------------------------------------------------------------------

    @Test
    fun theAgreedReadOfABase64RecordGivesTheRegisteredKeyWithTheDecodedArmor() {
        val ep = endpoint(ChainFixture.base64Of(own.publicArmor), backupOf(own))
        val chain = ChainFixture.agreed(account, ep)
        val key = (chain.registeredKey() as RegisteredKeyRead.Present).key
        assertEquals("the key holds the decoded armor, the one the gate verifies with", own.publicArmor, key.publicArmor)
        assertEquals(own.identity.fingerprint, key.fingerprint)
        assertEquals(own.identity.subkeyKeyId, key.subkeyKeyId)
        assertEquals(own.identity, chain.identity())
        assertTrue(chain.identityRead() is IdentityRead.Present)
        assertNull(chain.registeredKeyFailure())
    }

    @Test
    fun theSingleReadOfABase64RecordAndARawRecordBothGiveTheKey() {
        for (stored in listOf(ChainFixture.base64Of(own.publicArmor), own.publicArmor)) {
            val chain = ChainFixture.single(account, endpoint(stored))
            val key = (chain.registeredKey() as RegisteredKeyRead.Present).key
            assertEquals(RegisteredPgpKey.Source.SINGLE, key.source)
            assertEquals(own.publicArmor, key.publicArmor)
        }
    }

    @Test
    fun aRecordThatIsNeitherAnArmorNorBase64IsUnknownNotAbsentOnEveryReader() {
        val junk = endpoint("this is not a key", "")
        for (chain in listOf(ChainFixture.agreed(account, junk), ChainFixture.single(account, junk))) {
            assertTrue(chain.registeredKey() is RegisteredKeyRead.Unknown)
            assertTrue("the identity read is unknown, not absent", chain.identityRead() is IdentityRead.Unknown)
            assertFalse(chain.chainReadable())
            assertEquals("armor_parse", chain.registeredKeyFailure())
        }
        // A record that does not exist is the one absent case.
        val none = ChainFixture.agreed(account, endpoint(null))
        assertTrue(none.registeredKey() is RegisteredKeyRead.Absent)
        assertTrue(none.identityRead() is IdentityRead.Absent)
    }

    // ---- both recoveries, end to end, on a base64 record -----------------------------------------------------------------------------

    private class Env {
        val log = ArrayList<String>()
        val base = NativeTestFiles()
        val files = CountingFiles(base, log)
        val kBackend = CountingKBackend(log)
        val k = AccountPgpK(kBackend)
        val wrap = NativeTestWrap()
    }

    @Test
    fun theAutomaticRecoveryRunsThroughReadAgreedOnABase64Record() {
        val e = Env()
        val chain = ChainFixture.agreed(account, endpoint(ChainFixture.base64Of(own.publicArmor), backupOf(own)))
        val out = AutoRecovery.recover(account, NativePgpVault(e.wrap, e.files, account), e.k, chain, null, forms, 1L)
        assertEquals("upgraded_from_chain", out.expect.action)
        assertEquals(own.privateArmor, e.k.read(account, PgpMigrationPolicy.WORKSPACE)!!.getString("privateKeyArmor"))
        assertTrue(NativePgpVault(e.wrap, e.files, account).state() is NativePgpVault.State.Ready)
    }

    @Test
    fun theAutomaticRecoveryWithTheOldKeyRunsThroughReadAgreedOnABase64Record() {
        val e = Env()
        val chain = ChainFixture.agreed(account, endpoint(ChainFixture.base64Of(own.publicArmor), ""))
        val legacy = BeamioChatPgpStore.LegacyCopy(account, own.privateArmor, own.publicArmor)
        val out = AutoRecovery.recover(account, NativePgpVault(e.wrap, e.files, account), e.k, chain, legacy, forms, 1L)
        assertEquals("upgraded_from_L", out.expect.action)
    }

    @Test
    fun theAutomaticRecoveryRefusesABase64RecordOfAnotherKey() {
        val e = Env()
        val chain = ChainFixture.agreed(account, endpoint(ChainFixture.base64Of(other.publicArmor), backupOf(own)))
        val out = AutoRecovery.recover(account, NativePgpVault(e.wrap, e.files, account), e.k, chain, null, forms, 1L)
        assertEquals("pgp_migration_retry", out.expect.action)
        assertTrue(out.logCode, out.logCode.contains("identity_mismatch"))
        assertTrue(e.files.untouched)
        assertEquals(0, e.kBackend.puts)
    }

    @Test
    fun thePageRestoreRunsThroughReadSingleOnABase64Record() {
        val env = Env()
        val chain = ChainFixture.single(account, endpoint(ChainFixture.base64Of(own.publicArmor), backupOf(own)))
        val m = PgpRestoreMachine(
            chain = chain,
            wallet = object : PgpRestoreWallet {
                override fun ready(): Boolean = true
                override fun passwordString(): String? = canonical
                override fun passwordForms(): List<String>? = NativePgpBackup.passwordForms(accountKey)
            },
            keys = object : PgpRestoreKeys { override fun newKey(deviceId: String): PgpNewKey = error("never") },
            ivFor = { error("never") },
            devices = mapOf(PgpRestoreBridge.DEVICE to PgpRestoreDevice(PgpRestoreBridge.DEVICE, account, env.wrap, env.files)),
            recoveryGate = PageRecoveryGate(),
        )
        val result = PgpRestoreBridge.restore(m)
        assertEquals("ok", result.getString("code"))
        assertTrue(m.devices.getValue(PgpRestoreBridge.DEVICE).active.identity()!!.sameAs(own.identity))
        assertFalse(result.keys().asSequence().any { it in CredFields.NAMES })
    }

    @Test
    fun thePageRestoreEvaluateSeesTheBase64RecordAsPresent() {
        val chain = ChainFixture.single(account, endpoint(ChainFixture.base64Of(own.publicArmor), backupOf(own)))
        assertTrue(chain.identityRead() is IdentityRead.Present)
        assertEquals("registered", FirstIdentityRule.chainOfRead(chain))
    }

    // ---- the log sub-reasons -----------------------------------------------------------------------------------------------------------

    private fun good() = endpoint(ChainFixture.base64Of(own.publicArmor), backupOf(own))

    @Test
    fun everyFailureExitOfTheAgreedReadHasItsOwnSubReason() {
        val ok = good()
        fun reason(a: ChainFixture.Endpoint, b: ChainFixture.Endpoint, cfg: AddressPgpConfig = ChainFixture.config) =
            ChainFixture.agreed(account, a, b, cfg).registeredKeyFailure()
        assertEquals("endpoints", reason(ok, ok, AddressPgpConfig(AddressPgpConfig.default.contract, listOf(RegistryEndpoint(ChainFixture.urlA, 1000)))))
        assertEquals("chainid_a", reason(ChainFixture.Endpoint(chainId = "0x1", record = ok.record, backup = ok.backup), ok))
        assertEquals("chainid_b", reason(ok, ChainFixture.Endpoint(chainId = null, record = ok.record, backup = ok.backup)))
        assertEquals("blocknumber", reason(ChainFixture.Endpoint(blockNumber = null, record = ok.record, backup = ok.backup), ok))
        assertEquals("hash_differ", reason(ok, ChainFixture.Endpoint(hash = "0x" + "cd".repeat(32), record = ok.record, backup = ok.backup)))
        assertEquals("snapshot_a", reason(ChainFixture.Endpoint(callFails = true, record = ok.record, backup = ok.backup), ok))
        assertEquals("snapshot_b", reason(ok, ChainFixture.Endpoint(callFails = true, record = ok.record, backup = ok.backup)))
        assertEquals("record_differ", reason(ok, endpoint(ChainFixture.base64Of(other.publicArmor), backupOf(own))))
        assertEquals("armor_parse", reason(endpoint("nope"), endpoint("nope")))
        assertNull(reason(ok, ok))
    }

    @Test
    fun theAutoRecoveryLogCodeCarriesTheSubReasonAndTheSingleReadHasItsOwn() {
        val e = Env()
        val bad = ChainFixture.Endpoint(chainId = "0x1", record = good().record, backup = good().backup)
        val out = AutoRecovery.recover(account, NativePgpVault(e.wrap, e.files, account), e.k, ChainFixture.agreed(account, good(), bad), null, forms, 1L)
        assertEquals("registration_unavailable:chainid_b", out.logCode)
        assertTrue(e.files.untouched)
        assertEquals("chainid_a", ChainFixture.single(account, bad).registeredKeyFailure())
        assertEquals("snapshot_a", ChainFixture.single(account, ChainFixture.Endpoint(callFails = true, record = good().record, backup = good().backup)).registeredKeyFailure())
    }

    @Test
    fun theSubReasonsStayInTheLogAndOffTheBridge() {
        val chain = java.io.File("src/main/java/network/conet/chat/nativekey/AddressPgpChain.kt").readText()
        assertFalse("the chain file puts no JSON field", Regex("""\.put\(\s*"""").containsMatchIn(chain))
        val auto = java.io.File("src/main/java/network/conet/chat/nativekey/AutoRecovery.kt").readText()
        assertFalse(Regex("""\.put\(""").containsMatchIn(auto))
        assertNotNull(JSONObject())
    }
}
