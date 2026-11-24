package network.conet.chat.nativekey

import network.conet.chat.BeamioChatPgpStore
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.SecureRandom

/**
 * The automatic recovery with real keys, a write-counting vault and K_pgp store, and one ordered log of the calls: nothing is
 * written until the key has signed a fresh challenge that the registered key verifies; any refusal leaves zero writes, zero deletes, zero overwrites.
 */
class AutoRecoveryTest {
    private val random = SecureRandom()
    private val account = "0x" + "ab".repeat(20)
    private val own = RecKeys.generate(account, random)
    private val other = RecKeys.generate(account, random)
    private val accountKey = ByteArray(32) { (it + 1).toByte() }
    private val canonical = NativePgpBackup.passwordString(accountKey)
    private val forms: () -> List<String>? = { NativePgpBackup.passwordForms(accountKey) }

    private class Env {
        val log = ArrayList<String>()
        val base = NativeTestFiles()
        val files = CountingFiles(base, log)
        val kBackend = CountingKBackend(log)
        val k = AccountPgpK(kBackend)
        val wrap = NativeTestWrap()
    }

    private fun vaultOf(e: Env) = NativePgpVault(e.wrap, e.files, account)

    private fun backupOf(pgp: RecPgp, form: String = canonical): String =
        NativePgpBackup.encryptArmor(form, pgp.privateArmor.toByteArray(Charsets.UTF_8), ByteArray(12).also { random.nextBytes(it) })

    private fun legacy(pgp: RecPgp, owner: String = account) = BeamioChatPgpStore.LegacyCopy(owner, pgp.privateArmor, pgp.publicArmor)

    private fun recover(
        e: Env,
        chain: PgpRestoreChain,
        legacy: BeamioChatPgpStore.LegacyCopy? = null,
        signer: RecoveryChallengeGate.ChallengeSigner? = null,
        vault: NativePgpVault = vaultOf(e),
    ): AutoRecovery.Outcome = AutoRecovery.recover(account, vault, e.k, chain, legacy, forms, 1L, random, signer)

    private fun loggingSigner(e: Env, inner: RecoveryChallengeGate.ChallengeSigner? = null) = RecoveryChallengeGate.ChallengeSigner { s, label, message ->
        e.log += "sign"
        inner?.sign(s, label, message) ?: NativePgp.signDocument(s, "", label, message, NativePgp.SIG_CANONICAL_TEXT)
    }

    private fun assertZeroWrites(e: Env) {
        assertTrue("no vault write, delete or rename: ${e.log}", e.files.untouched)
        assertEquals(0, e.kBackend.puts)
        assertEquals(0, e.kBackend.removes)
        assertTrue(e.base.map.isEmpty())
        assertTrue(e.kBackend.inner.items.isEmpty())
    }

    // ---- recovered ------------------------------------------------------------------------------------------------------------------

    @Test
    fun theOldKeyThatIsTheRegisteredKeyIsRecoveredAfterTheChallengeAndTheOrderIsSignThenVaultThenK() {
        val e = Env()
        val out = recover(e, RecKeyChain(own, backup = ""), legacy = legacy(own), signer = loggingSigner(e))
        assertEquals("upgraded_from_L", out.expect.action)
        assertEquals("recovered:legacy_store", out.logCode)
        val vault = vaultOf(e)
        assertTrue(vault.state() is NativePgpVault.State.Ready)
        assertTrue(PgpIdentity(NativePgp.parseSecret(String(vault.armorForMove()!!))!!.fingerprint.uppercase(), own.identity.subkeyKeyId).sameAs(own.identity))
        assertEquals(own.privateArmor, e.k.read(account, PgpMigrationPolicy.WORKSPACE)!!.getString("privateKeyArmor"))
        val first = e.log.indexOf("sign")
        val vaultWrite = e.log.indexOf("vault.write")
        val kPut = e.log.indexOf("k.put")
        assertTrue("sign comes first: ${e.log}", first in 0 until vaultWrite)
        assertTrue("the vault is written before K_pgp: ${e.log}", vaultWrite in 0 until kPut)
    }

    @Test
    fun theChainBackupOfEveryFormIsRecoveredWhenThereIsNoOldKey() {
        for (form in NativePgpBackup.passwordForms(accountKey)) {
            val e = Env()
            val out = recover(e, RecKeyChain(own, backup = backupOf(own, form)), signer = loggingSigner(e))
            assertEquals("form $form", "upgraded_from_chain", out.expect.action)
            assertTrue(vaultOf(e).state() is NativePgpVault.State.Ready)
            assertEquals(own.privateArmor, e.k.read(account, PgpMigrationPolicy.WORKSPACE)!!.getString("privateKeyArmor"))
        }
    }

    @Test
    fun anOldKeyThatIsNotRegisteredFallsBackToTheChainBackupAndTheOldFileIsNotTheOneWritten() {
        val e = Env()
        val out = recover(e, RecKeyChain(own, backup = backupOf(own)), legacy = legacy(other), signer = loggingSigner(e))
        assertEquals("upgraded_from_chain", out.expect.action)
        assertEquals(own.privateArmor, e.k.read(account, PgpMigrationPolicy.WORKSPACE)!!.getString("privateKeyArmor"))
    }

    @Test
    fun theOldKeyComesBeforeTheChainBackup() {
        val e = Env()
        val out = recover(e, RecKeyChain(own, backup = backupOf(own)), legacy = legacy(own), signer = loggingSigner(e))
        assertEquals("upgraded_from_L", out.expect.action)
        assertEquals("only one candidate was tried", 1, e.log.count { it == "sign" })
    }

    // ---- refused: zero writes ---------------------------------------------------------------------------------------------------------

    @Test
    fun anUnreadableOrAbsentRegistrationWritesNothing() {
        for ((registered, code) in listOf(
            RegisteredKeyRead.Unknown to "registration_unavailable",
            RegisteredKeyRead.Absent to "registration_missing",
        )) {
            val e = Env()
            val out = recover(e, RecChain(registered = registered, backup = backupOf(own)), legacy = legacy(own), signer = loggingSigner(e))
            assertEquals("pgp_migration_retry", out.expect.action)
            assertEquals(code, out.logCode)
            assertZeroWrites(e)
            assertFalse("no candidate was even signed: ${e.log}", e.log.contains("sign"))
        }
    }

    @Test
    fun aRegistrationOfAnotherAccountOrAnotherKeyWritesNothing() {
        val e1 = Env()
        val foreign = "0x" + "cd".repeat(20)
        val o1 = recover(e1, RecChain(registered = registeredOf(own, foreign), backup = backupOf(own)), legacy = legacy(own), signer = loggingSigner(e1))
        assertEquals("pgp_migration_retry", o1.expect.action)
        assertZeroWrites(e1)
        // The registry holds another key than the candidates.
        val e2 = Env()
        val o2 = recover(e2, RecChain(registered = registeredOf(other, account), backup = backupOf(own)), legacy = legacy(own), signer = loggingSigner(e2))
        assertEquals("pgp_migration_retry", o2.expect.action)
        assertTrue(o2.logCode.contains("identity_mismatch"))
        assertZeroWrites(e2)
    }

    @Test
    fun aSingleEndpointRegistrationIsNotEnoughForTheAutomaticRecovery() {
        val e = Env()
        val chain = RecChain(registered = registeredOf(own, account, source = RegisteredPgpKey.Source.SINGLE), backup = backupOf(own))
        val out = recover(e, chain, legacy = legacy(own), signer = loggingSigner(e))
        assertEquals("pgp_migration_retry", out.expect.action)
        assertZeroWrites(e)
    }

    @Test
    fun aSignatureThatFailsOrDoesNotVerifyWritesNothing() {
        val ownRegistry = RecKeyChain(own, backup = backupOf(own))
        val e1 = Env()
        val o1 = recover(e1, ownRegistry, legacy = legacy(own), signer = RecoveryChallengeGate.ChallengeSigner { _, _, _ -> NativePgp.Outcome.fail("sign_failed") })
        assertEquals("pgp_migration_retry", o1.expect.action)
        assertZeroWrites(e1)
        val e2 = Env()
        val otherSecret = NativePgp.parseSecret(other.privateArmor)!!
        val o2 = recover(e2, ownRegistry, legacy = legacy(own), signer = RecoveryChallengeGate.ChallengeSigner { _, l, m ->
            NativePgp.signDocument(otherSecret, "", l, m, NativePgp.SIG_CANONICAL_TEXT)
        })
        assertEquals("pgp_migration_retry", o2.expect.action)
        assertTrue(o2.logCode.contains("verify_failed"))
        assertZeroWrites(e2)
    }

    @Test
    fun anOldChallengeSignatureIsNotReusedAcrossRuns() {
        val e1 = Env()
        var recorded: String? = null
        val ownRegistry = RecKeyChain(own, backup = "")
        recover(e1, ownRegistry, legacy = legacy(own), signer = RecoveryChallengeGate.ChallengeSigner { s, l, m ->
            NativePgp.signDocument(s, "", l, m, NativePgp.SIG_CANONICAL_TEXT).also { recorded = it.value }
        })
        val e2 = Env()
        val out = recover(e2, ownRegistry, legacy = legacy(own), signer = RecoveryChallengeGate.ChallengeSigner { _, _, _ -> NativePgp.Outcome.ok(recorded!!) })
        assertEquals("pgp_migration_retry", out.expect.action)
        assertZeroWrites(e2)
    }

    @Test
    fun noCandidateAtAllWritesNothingAndNeverGenerates() {
        for (chain in listOf(
            RecKeyChain(own, backup = ""),
            RecKeyChain(own, backup = "AAAA-not-a-backup"),
            RecKeyChain(own, backup = backupOf(other)),
            RecChain(readable = false, registered = registeredOf(own, account)),
        )) {
            val e = Env()
            val out = recover(e, chain, signer = loggingSigner(e))
            assertEquals("pgp_migration_retry", out.expect.action)
            assertZeroWrites(e)
        }
    }

    @Test
    fun theOldKeyOfAnotherAccountIsNotACandidate() {
        val e = Env()
        val out = recover(e, RecKeyChain(own, backup = ""), legacy = legacy(own, owner = "0x" + "cd".repeat(20)), signer = loggingSigner(e))
        assertEquals("pgp_migration_retry", out.expect.action)
        assertZeroWrites(e)
    }

    // ---- the vault ------------------------------------------------------------------------------------------------------------------

    @Test
    fun aLockedOrReadyVaultIsNotTouched() {
        val e = Env()
        // A record without its marker: the slot is locked.
        val seed = Env()
        NativePgpVault(seed.wrap, seed.base, account).put(account, other.privateArmor, "")
        e.base.map.putAll(seed.base.map.filterKeys { !it.endsWith(".ok") && !it.contains("mark") })
        val locked = NativePgpVault(seed.wrap, e.files, account)
        val state = locked.state()
        val before = e.base.map.mapValues { it.value.toList() }
        val out = recover(e, RecKeyChain(own, backup = backupOf(own)), legacy = legacy(own), signer = loggingSigner(e), vault = locked)
        assertEquals("pgp_migration_retry", out.expect.action)
        assertEquals(before, e.base.map.mapValues { it.value.toList() })
        assertTrue(state !is NativePgpVault.State.NoKey)
        assertTrue("nothing was signed for a slot that is not empty: ${e.log}", e.log.isEmpty())
        assertTrue(e.kBackend.inner.items.isEmpty())
    }

    @Test
    fun aSlotFilledWhileTheChallengeRunsIsNeverOverwritten() {
        val e = Env()
        val vault = vaultOf(e)
        val racing = RecoveryChallengeGate.ChallengeSigner { s, l, m ->
            // Another writer fills the slot after the state was read and before the write.
            vault.put(account, other.privateArmor, "")
            NativePgp.signDocument(s, "", l, m, NativePgp.SIG_CANONICAL_TEXT)
        }
        val out = recover(e, RecKeyChain(own, backup = ""), legacy = legacy(own), signer = racing, vault = vault)
        assertEquals("pgp_migration_retry", out.expect.action)
        assertEquals("vault_exists", out.logCode)
        assertTrue(e.kBackend.inner.items.isEmpty())
        val kept = NativePgp.parseSecret(String(vault.armorForMove()!!))!!.fingerprint.uppercase()
        assertEquals("the other writer's key is still there", other.identity.fingerprint, kept)
    }

    @Test
    fun aVaultWriteThatFailsLeavesNothingAndNoK() {
        val e = Env()
        val failingWrites = RecoveryChallengeGate.ChallengeSigner { s, l, m ->
            e.files.refuseWrites = true
            NativePgp.signDocument(s, "", l, m, NativePgp.SIG_CANONICAL_TEXT)
        }
        val out = recover(e, RecKeyChain(own, backup = ""), legacy = legacy(own), signer = failingWrites)
        assertEquals("pgp_migration_retry", out.expect.action)
        assertEquals("vault_write_failed:write_failed", out.logCode)
        assertTrue(e.base.map.isEmpty())
        assertTrue(e.kBackend.inner.items.isEmpty())
    }

    @Test
    fun aFailedMirrorKeepsTheVerifiedVaultKeyAndTheNextRunCompletesItThroughTheVault() {
        val e = Env()
        e.kBackend.refusePut = true
        val out = recover(e, RecKeyChain(own, backup = ""), legacy = legacy(own), signer = loggingSigner(e))
        assertEquals("pgp_migration_retry", out.expect.action)
        assertEquals("k_mirror_failed", out.logCode)
        val vault = vaultOf(e)
        assertTrue("the verified key is in the vault", vault.state() is NativePgpVault.State.Ready)
        assertTrue(e.kBackend.inner.items.isEmpty())
        // The restart: the vault is Ready now, so the original path copies it into K_pgp, with no chain read and no challenge.
        e.kBackend.refusePut = false
        val record = KpgpUpgrade.LRecord(String(vault.armorForMove()!!), own.identity.subkeyKeyId)
        val again = KpgpUpgrade.upgrade(e.k, account, record, userClick = false, nowSec = 2L)
        assertEquals("upgraded_from_L", again.action)
        assertEquals(own.privateArmor, e.k.read(account, PgpMigrationPolicy.WORKSPACE)!!.getString("privateKeyArmor"))
    }

    @Test
    fun aRunTwiceFindsTheVaultReadyAndWritesNothingMore() {
        val e = Env()
        recover(e, RecKeyChain(own, backup = ""), legacy = legacy(own), signer = loggingSigner(e))
        val writes = e.files.writes
        val puts = e.kBackend.puts
        val signs = e.log.count { it == "sign" }
        val again = recover(e, RecKeyChain(own, backup = ""), legacy = legacy(own), signer = loggingSigner(e))
        assertEquals("pgp_migration_retry", again.expect.action)
        assertEquals("a ready vault is the original path's, not this one's", "vault_ready", again.logCode)
        assertEquals("nothing is even signed for it", signs, e.log.count { it == "sign" })
        assertEquals(writes, e.files.writes)
        assertEquals(puts, e.kBackend.puts)
    }

    // ---- the chain read (typed registered key) ----------------------------------------------------------------------------------

    @Test
    fun aChainThatDoesNotProvideTheRegisteredKeyNeverOpensAWrite() {
        val bare = object : PgpRestoreChain {
            override fun chainReadable(): Boolean = true
            override fun backupReadable(): Boolean = true
            override fun version(): Long = 0L
            override fun identity(): PgpIdentity? = own.identity
            override fun backupText(): String = backupOf(own)
            override fun write(identity: PgpIdentity, backupText: String) = error("never")
        }
        assertTrue(bare.registeredKey() is RegisteredKeyRead.Unknown)
        val e = Env()
        val out = recover(e, bare, legacy = legacy(own), signer = loggingSigner(e))
        assertEquals("pgp_migration_retry", out.expect.action)
        assertZeroWrites(e)
    }

    @Test
    fun theChallengeNonceDiffersOnEveryRun() {
        val messages = ArrayList<String>()
        for (i in 0 until 3) {
            val e = Env()
            recover(e, RecKeyChain(own, backup = ""), legacy = legacy(own), signer = RecoveryChallengeGate.ChallengeSigner { s, l, m ->
                messages += String(m)
                NativePgp.signDocument(s, "", l, m, NativePgp.SIG_CANONICAL_TEXT)
            })
        }
        assertEquals(3, messages.toSet().size)
        assertNotEquals(messages[0], messages[1])
    }

    /** A chain whose registry holds [pgp]'s public key (its armor is the registered one) and whose backup is [backup]. */
    private fun RecKeyChain(pgp: RecPgp, backup: String) = RecChain(registered = registeredOf(pgp, account), backup = backup)

    @Test
    fun anOldKeyWithTheSameMasterButAnotherSubkeyIsNotACandidateAndTheChainBackupDecides() {
        val (registeredKey, olderRing) = sameMasterKeys(account, random)
        val e = Env()
        val chain = RecChain(registered = registeredOf(registeredKey, account), backup = backupOf(registeredKey))
        val out = recover(e, chain, legacy = legacy(olderRing), signer = loggingSigner(e))
        assertEquals("upgraded_from_chain", out.expect.action)
        assertEquals(registeredKey.privateArmor, e.k.read(account, PgpMigrationPolicy.WORKSPACE)!!.getString("privateKeyArmor"))
        assertEquals("the old key was never even signed with", 1, e.log.count { it == "sign" })
    }

    // ---- the vault key is held to the gate before it is mirrored into K_pgp -----------------------------------------------------------------

    private fun lRecordOf(pgp: RecPgp) = KpgpUpgrade.LRecord(pgp.privateArmor, pgp.identity.subkeyKeyId)

    @Test
    fun aVaultKeyThatIsTheRegisteredKeyIsMirroredIntoKAfterTheChallenge() {
        val e = Env()
        val out = AutoRecovery.mirrorVault(account, lRecordOf(own), e.k, RecKeyChain(own, backup = ""), 1L, random, loggingSigner(e))
        assertEquals("upgraded_from_L", out.expect.action)
        assertEquals("mirrored:vault_record", out.logCode)
        assertEquals(own.privateArmor, e.k.read(account, PgpMigrationPolicy.WORKSPACE)!!.getString("privateKeyArmor"))
        assertTrue("sign comes before the K write: ${e.log}", e.log.indexOf("sign") in 0 until e.log.indexOf("k.put"))
        assertTrue("the vault is not written by the mirror", e.files.untouched)
    }

    @Test
    fun aVaultKeyThatIsNotVerifiedIsNotMirrored() {
        val registeredOther = RecChain(registered = registeredOf(other, account), backup = "")
        val cases = listOf(
            "registration_unavailable" to RecChain(registered = RegisteredKeyRead.Unknown),
            "registration_missing" to RecChain(registered = RegisteredKeyRead.Absent),
            "vault_record:identity_mismatch" to registeredOther,
            "vault_record:registration_unavailable" to RecChain(registered = registeredOf(own, account, source = RegisteredPgpKey.Source.SINGLE)),
        )
        for ((code, chain) in cases) {
            val e = Env()
            val out = AutoRecovery.mirrorVault(account, lRecordOf(own), e.k, chain, 1L, random, loggingSigner(e))
            assertEquals(code, "pgp_migration_retry", out.expect.action)
            assertEquals(code, out.logCode)
            assertEquals(0, e.kBackend.puts)
            assertTrue(e.kBackend.inner.items.isEmpty())
            assertTrue(e.files.untouched)
        }
    }

    @Test
    fun aVaultKeyWhoseChallengeFailsIsNotMirrored() {
        val e = Env()
        val otherSecret = NativePgp.parseSecret(other.privateArmor)!!
        val out = AutoRecovery.mirrorVault(account, lRecordOf(own), e.k, RecKeyChain(own, backup = ""), 1L, random,
            RecoveryChallengeGate.ChallengeSigner { _, l, m -> NativePgp.signDocument(otherSecret, "", l, m, NativePgp.SIG_CANONICAL_TEXT) })
        assertEquals("pgp_migration_retry", out.expect.action)
        assertEquals("vault_record:verify_failed", out.logCode)
        assertEquals(0, e.kBackend.puts)
        val failing = AutoRecovery.mirrorVault(account, lRecordOf(own), e.k, RecKeyChain(own, backup = ""), 1L, random,
            RecoveryChallengeGate.ChallengeSigner { _, _, _ -> NativePgp.Outcome.fail("sign_failed") })
        assertEquals("vault_record:sign_failed", failing.logCode)
        assertEquals(0, e.kBackend.puts)
    }

    @Test
    fun aMirrorThatCannotWriteKReportsARetryAndKeepsTheVaultOut() {
        val e = Env()
        e.kBackend.refusePut = true
        val out = AutoRecovery.mirrorVault(account, lRecordOf(own), e.k, RecKeyChain(own, backup = ""), 1L, random)
        assertEquals("pgp_migration_retry", out.expect.action)
        assertEquals("k_mirror_failed", out.logCode)
        assertTrue(e.files.untouched)
    }

    @Test
    fun theReadyVaultBranchMirrorsThroughTheGateAndKeepsAnExistingKWithoutReadingTheChain() {
        val text = java.io.File("src/main/java/network/conet/chat/nativekey/KpgpUpgrade.kt").readText()
        val body = text.substringAfter("fun fromDevice(")
        // An existing K_pgp returns before any chain read.
        assertTrue(body.indexOf("if (!kAbsent) return upgrade(") in 0 until body.indexOf("readAgreedTimed("))
        // The Ready branch goes through the gate, not straight to the write.
        val ready = body.substringAfter("is NativePgpVault.State.Ready -> {").substringBefore("is NativePgpVault.State.Locked -> {")
        assertTrue(ready.contains("AutoRecovery.mirrorVault("))
        assertFalse("no direct K write from the vault record in the Ready branch", Regex("""return upgrade\(store, eoa, record""").containsMatchIn(ready))
    }
}
