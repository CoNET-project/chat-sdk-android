package network.conet.chat.nativekey

import network.conet.chat.BeamioChatPgpStore
import network.conet.chat.identity.CredFields
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.File
import java.security.SecureRandom

/**
 * A store account (a vault with no record, the account in the two-state store) takes part in the PGP recovery: the store
 * account rules, the six password forms, the page restore with the old key (machine without the gate, the older fixtures), the trigger (one request per
 * account, retry with delay) and the handler order. The recovery gate itself is in `RecoveryChallengeGateTest`; the orchestration in `AutoRecoveryTest`.
 */
class StoreAccountPgpRecoveryTest {
    private val random = SecureRandom()
    private val approving = NativeMigrationCrypto(true)
    private val workspace = PgpMigrationPolicy.WORKSPACE

    // ---- the account and its keys ---------------------------------------------------------------------------------------------------

    private val phrase = "test test test test test test test test test test test junk"
    private val accountKey: ByteArray = MnemonicDerivation.deriveKey(phrase)!!
    private val eoa: String = WalletAddress.fromPrivateKey(accountKey)!!.lowercase()

    private class Pgp(val privateArmor: String, val publicArmor: String, val identity: PgpIdentity)

    private fun newPgp(): Pgp {
        val gen = NativePgpKeyGen.generate(eoa, random)
        val secret = NativePgp.parseSecret(gen.privateArmor)!!
        return Pgp(gen.privateArmor, gen.publicArmor, PgpIdentity(secret.fingerprint.uppercase(), NativePgpBackup.subkeyKeyId(secret)!!))
    }

    private val own = newPgp()
    private val other = newPgp()

    private fun backupOf(pgp: Pgp, form: String): String =
        NativePgpBackup.encryptArmor(form, pgp.privateArmor.toByteArray(Charsets.UTF_8), ByteArray(12).also { random.nextBytes(it) })

    private val canonical = NativePgpBackup.passwordString(accountKey)

    private class FakeChain(
        private val readable: Boolean = true,
        private val record: PgpIdentity? = null,
        private val backup: String = "",
    ) : PgpRestoreChain {
        override fun chainReadable(): Boolean = readable
        override fun backupReadable(): Boolean = readable
        override fun version(): Long = 0L
        override fun identity(): PgpIdentity? = record
        override fun backupText(): String = backup
        override fun write(identity: PgpIdentity, backupText: String) = error("the recovery never writes the chain")
    }

    private fun legacyCopy(pgp: Pgp = own, owner: String = eoa) = BeamioChatPgpStore.LegacyCopy(owner, pgp.privateArmor, pgp.publicArmor)

    private fun forms(): () -> List<String>? = { NativePgpBackup.passwordForms(accountKey) }

    @Before
    fun clean() {
        KpgpUpgradeTrigger.resetForTests()
        SessionKeyHolder.clear()
    }

    @After
    fun cleanAfter() {
        KpgpUpgradeTrigger.resetForTests()
        SessionKeyHolder.clear()
    }

    // ---- the store account ----------------------------------------------------------------------------------------------------------

    @Test
    fun aPlainSetIsAnAccountOfItsOwn() {
        val found = MnemonicSetStore.Current.Found(eoa, MnemonicSetStore.Kind.PLAIN, phrase, 1)
        val r = StoreAwareAccount.resolve(found) { false } as StoreAwareAccount.Resolution.Account
        assertEquals(eoa, r.eoa)
        assertEquals(StoreAwareAccount.Source.STORE_PLAIN, r.source)
        val key = StoreAwareAccount.keyOf(found, r)
        assertNotNull(key)
        assertArrayEquals(accountKey, key)
        key!!.fill(0)
    }

    @Test
    fun aV3SetThatIsNotUnlockedIsNotReadyNeverNoKey() {
        val found = MnemonicSetStore.Current.Found(eoa, MnemonicSetStore.Kind.V3, "{}", 1)
        val r = StoreAwareAccount.resolve(found) { false }
        assertTrue(r is StoreAwareAccount.Resolution.NotReady)
        assertEquals(NoKeyGate.NOT_READY_PASSCODE_REQUIRED, (r as StoreAwareAccount.Resolution.NotReady).reason)
    }

    @Test
    fun aV3SetIsAnAccountOnlyWhileTheSessionHoldsItsKey() {
        val found = MnemonicSetStore.Current.Found(eoa, MnemonicSetStore.Kind.V3, "{}", 1)
        SessionKeyHolder.put(eoa, accountKey)
        val r = StoreAwareAccount.resolve(found) { f -> SessionKeyHolder.keyFor(f.eoa)?.also { it.fill(0) } != null } as StoreAwareAccount.Resolution.Account
        assertEquals(StoreAwareAccount.Source.STORE_SESSION, r.source)
        val key = StoreAwareAccount.keyOf(found, r)
        assertArrayEquals(accountKey, key)
        key!!.fill(0)
        SessionKeyHolder.clear()
        assertNull("the lock is lost: no key", StoreAwareAccount.keyOf(found, r))
    }

    @Test
    fun anUnreadableStoreIsNotReadyAndAnAbsentStoreIsNoKey() {
        val unknown = StoreAwareAccount.resolve(MnemonicSetStore.Current.Unknown("store_unreadable")) { false }
        assertEquals(NoKeyGate.NOT_READY_UNREADABLE, (unknown as StoreAwareAccount.Resolution.NotReady).reason)
        val pointerMissing = StoreAwareAccount.resolve(MnemonicSetStore.Current.Unknown(MnemonicSetStore.POINTER_MISSING)) { false }
        assertTrue(pointerMissing is StoreAwareAccount.Resolution.NotReady)
        assertTrue(StoreAwareAccount.resolve(MnemonicSetStore.Current.Absent) { false } is StoreAwareAccount.Resolution.NoKey)
    }

    @Test
    fun aKeyOfAnotherSetOrAnotherAccountIsNeverGiven() {
        val found = MnemonicSetStore.Current.Found(eoa, MnemonicSetStore.Kind.PLAIN, phrase, 1)
        val account = StoreAwareAccount.resolve(found) { false } as StoreAwareAccount.Resolution.Account
        val moved = MnemonicSetStore.Current.Found("0x" + "cd".repeat(20), MnemonicSetStore.Kind.PLAIN, phrase, 1)
        assertNull(StoreAwareAccount.keyOf(moved, account))
        assertNull(StoreAwareAccount.keyOf(MnemonicSetStore.Current.Absent, account))
    }

    // ---- the six password forms -----------------------------------------------------------------------------------------------------

    @Test
    fun theSixFormsStartWithTheCanonicalOne() {
        val f = NativePgpBackup.passwordForms(accountKey)
        assertEquals(6, f.size)
        assertEquals(canonical, f.first())
        assertEquals(f.size, f.toSet().size)
    }

    @Test
    fun aBackupSealedWithAnyFormOpensAndAWrongKeyDoesNot() {
        for (form in NativePgpBackup.passwordForms(accountKey)) {
            val text = backupOf(own, form)
            val opened = NativePgpBackup.decryptArmorAny(NativePgpBackup.passwordForms(accountKey), text)
            assertNotNull("form $form", opened)
            assertEquals(own.privateArmor, String(opened!!, Charsets.UTF_8))
        }
        val wrong = ByteArray(32) { 7 }
        assertNull(NativePgpBackup.decryptArmorAny(NativePgpBackup.passwordForms(wrong), backupOf(own, canonical)))
    }

    // ---- the restore machine with a store wallet ----------------------------------------------------------------------------------

    @Test
    fun thePageRestoreOpensABackupSealedWithANonCanonicalFormAndWritesTheEmptySlot() {
        val form = "0X" + canonical.removePrefix("0x").uppercase()
        val chain = FakeChain(record = own.identity, backup = backupOf(own, form))
        val files = NativeTestFiles()
        val machine = PgpRestoreMachine(
            chain = chain,
            wallet = object : PgpRestoreWallet {
                override fun ready(): Boolean = true
                override fun passwordString(): String? = canonical
                override fun passwordForms(): List<String>? = NativePgpBackup.passwordForms(accountKey)
            },
            keys = object : PgpRestoreKeys {
                override fun newKey(deviceId: String): PgpNewKey = error("the restore never generates a key")
            },
            ivFor = { error("the restore never writes a backup") },
            devices = mapOf(PgpRestoreBridge.DEVICE to PgpRestoreDevice(PgpRestoreBridge.DEVICE, eoa, NativeTestWrap(), files)),
        )
        val result = PgpRestoreBridge.restore(machine)
        assertEquals("ok", result.getString("code"))
        assertTrue(machine.devices.getValue(PgpRestoreBridge.DEVICE).active.state() is NativePgpVault.State.Ready)
        assertFalse("no key field on the answer", result.keys().asSequence().any { it in CredFields.NAMES })
    }

    @Test
    fun theFailuresOfThePageRestoreOfferTheUserEntryAndNeverGenerate() {
        val cases = mapOf(
            "pgp_backup_missing" to FakeChain(record = own.identity, backup = ""),
            "pgp_backup_undecryptable" to FakeChain(record = own.identity, backup = "AAAA-not-a-backup"),
            "pgp_fingerprint_mismatch" to FakeChain(record = other.identity, backup = backupOf(own, canonical)),
        )
        for ((code, chain) in cases) {
            val machine = PgpRestoreMachine(
                chain = chain,
                wallet = object : PgpRestoreWallet {
                    override fun ready(): Boolean = true
                    override fun passwordString(): String? = canonical
                    override fun passwordForms(): List<String>? = NativePgpBackup.passwordForms(accountKey)
                },
                keys = object : PgpRestoreKeys {
                    override fun newKey(deviceId: String): PgpNewKey = error("the restore never generates a key")
                },
                ivFor = { error("the restore never writes a backup") },
                devices = mapOf(PgpRestoreBridge.DEVICE to PgpRestoreDevice(PgpRestoreBridge.DEVICE, eoa, NativeTestWrap(), NativeTestFiles())),
            )
            val evaluated = PgpRestoreBridge.evaluate(machine)
            assertEquals(code, code, evaluated.getString("code"))
            assertEquals("failed", evaluated.getString("state"))
            assertTrue("the user entry is offered: $code", evaluated.getBoolean("offerEntry"))
            assertTrue(machine.devices.getValue(PgpRestoreBridge.DEVICE).active.state() is NativePgpVault.State.NoKey)
        }
    }

    @Test
    fun anUnreadableChainIsUndeterminedNotAFailure() {
        val machine = PgpRestoreMachine(
            chain = FakeChain(readable = false),
            wallet = object : PgpRestoreWallet {
                override fun ready(): Boolean = true
                override fun passwordString(): String? = canonical
            },
            keys = object : PgpRestoreKeys {
                override fun newKey(deviceId: String): PgpNewKey = error("never")
            },
            ivFor = { error("never") },
            devices = mapOf(PgpRestoreBridge.DEVICE to PgpRestoreDevice(PgpRestoreBridge.DEVICE, eoa, NativeTestWrap(), NativeTestFiles())),
        )
        val evaluated = PgpRestoreBridge.evaluate(machine)
        assertEquals("undetermined", evaluated.getString("state"))
        assertEquals("pgp_source_unavailable", evaluated.getString("code"))
    }

    // ---- the trigger: one request per account, retry with delay ----------------------------------------------------------------------

    @Test
    fun oneRequestPerAccountAtATime() {
        assertTrue(KpgpUpgradeTrigger.claimFor(eoa, 0L))
        assertFalse("a second request while one is in flight", KpgpUpgradeTrigger.claimFor(eoa, 0L))
        assertFalse(KpgpUpgradeTrigger.claimForUserRetry(eoa))
        assertTrue("another account is its own request", KpgpUpgradeTrigger.claimFor("0x" + "cd".repeat(20), 0L))
    }

    @Test
    fun aRetryStateIsReleasedWithADelayAndASettledAccountIsNotRepeated() {
        assertTrue(KpgpUpgradeTrigger.claimFor(eoa, 1_000L))
        KpgpUpgradeTrigger.release(eoa, 1_000L)
        assertTrue("a retry is still wanted", KpgpUpgradeTrigger.pending())
        assertFalse("before the delay", KpgpUpgradeTrigger.claimFor(eoa, 1_000L + 59_999L))
        assertTrue("after the delay", KpgpUpgradeTrigger.claimFor(eoa, 1_000L + 60_000L))
        KpgpUpgradeTrigger.release(eoa, 100_000L)
        assertFalse("the second delay doubles", KpgpUpgradeTrigger.claimFor(eoa, 100_000L + 119_999L))
        assertTrue(KpgpUpgradeTrigger.claimFor(eoa, 100_000L + 120_000L))
        KpgpUpgradeTrigger.settle(eoa)
        assertFalse(KpgpUpgradeTrigger.claimFor(eoa, Long.MAX_VALUE / 2))
        assertFalse("nothing is waiting any more", KpgpUpgradeTrigger.pending())
    }

    @Test
    fun theRetryDelayIsCapped() {
        assertEquals(60_000L, KpgpUpgradeTrigger.delayMs(1))
        assertEquals(120_000L, KpgpUpgradeTrigger.delayMs(2))
        assertEquals(30L * 60_000L, KpgpUpgradeTrigger.delayMs(50))
    }

    @Test
    fun aUserRetryIgnoresTheDelayButNotARunInFlight() {
        assertTrue(KpgpUpgradeTrigger.claimFor(eoa, 0L))
        KpgpUpgradeTrigger.release(eoa, 0L)
        assertTrue(KpgpUpgradeTrigger.claimForUserRetry(eoa))
        assertFalse(KpgpUpgradeTrigger.claimForUserRetry(eoa))
    }

    @Test
    fun aRestartForgetsTheClaimsAndTheUpgradeRunsAgain() {
        assertTrue(KpgpUpgradeTrigger.claimFor(eoa, 0L))
        KpgpUpgradeTrigger.release(eoa, 0L)
        KpgpUpgradeTrigger.resetForTests()
        assertTrue(KpgpUpgradeTrigger.claimFor(eoa, 0L))
    }

    // ---- nothing key-like on the bridge --------------------------------------------------------------------------------------------

    @Test
    fun noKeyFieldIsEverPutOnTheBridgeByTheFilesOfThisChange() {
        val names = CredFields.NAMES.toSet()
        val put = Regex("""\.put\(\s*"([A-Za-z0-9_]+)"""")
        val root = File("src/main/java/network/conet/chat")
        val files = listOf(
            "nativekey/StoreAwareAccount.kt", "nativekey/LegacyArmorRestore.kt", "nativekey/KpgpUpgrade.kt",
            "nativekey/KpgpUpgradeTrigger.kt", "nativekey/PgpRestoreBridge.kt", "nativekey/ChainBackupRestore.kt",
        )
        for (f in files) {
            val text = File(root, f).readText(Charsets.UTF_8)
            val bad = put.findAll(text).map { it.groupValues[1] }.filter { it in names || it.contains("rivate", ignoreCase = true) && it != "private" }.toList()
            assertTrue("$f puts a key-like name: $bad", bad.isEmpty())
        }
        // The events the module emits for this change carry a code and nothing else.
        val module = File(root, "BeamioConetChatModule.kt").readText(Charsets.UTF_8)
        val upgradeEvents = Regex("""JSONObject\(\)\.put\("type", "pgpUpgradeState"\)\.put\("code", code\)""").findAll(module).count()
        assertEquals("both pgpUpgradeState emits are {type, code}", 2, upgradeEvents)
        assertFalse(module.contains("put(\"pgpUpgradeState\"") && Regex("""pgpUpgradeState"\)\.put\("(?!code)""").containsMatchIn(module))
    }

    // ---- the handlers read the store only when the vault has no record ----------------------------------------------------------------

    private val moduleText: String by lazy { File("src/main/java/network/conet/chat/BeamioConetChatModule.kt").readText(Charsets.UTF_8) }

    private fun bodyOf(signature: String): String {
        val start = moduleText.indexOf(signature)
        assertTrue("$signature exists", start >= 0)
        val next = Regex("""\n    (private |internal |fun |/\*\*)""").find(moduleText, start + signature.length)?.range?.first ?: moduleText.length
        return moduleText.substring(start, next)
    }

    @Test
    fun everyPgpHandlerReadsTheStoreOnlyAfterTheVaultHasNoRecord() {
        val restore = bodyOf("private fun pgpRestoreCommand(")
        assertTrue(restore.indexOf("State.Ready)?.eoa ?:") in 0 until restore.indexOf("StoreAwareAccount.resolveOnDevice"))
        val migrate = bodyOf("private fun pgpMigrateCommand(")
        assertTrue(migrate.contains("gate == NoKeyGate.Gate.G0 && ctx != null"))
        assertTrue(migrate.indexOf("NoKeyGate.gateOf(") in 0 until migrate.indexOf("StoreAwareAccount.resolveOnDevice"))
        val identity = bodyOf("private fun identityPublicCommand(")
        assertTrue(identity.indexOf("NoKeyGate.gateOf(") in 0 until identity.indexOf("StoreAwareAccount.resolveOnDevice"))
        assertTrue("a v3 set that is not unlocked answers not_ready, not no_key", identity.contains("notReadyAck(reqId, r.reason)"))
        val retry = bodyOf("private fun pgpUpgradeRetryCommand(")
        assertTrue(retry.indexOf("State.Ready)?.eoa") in 0 until retry.indexOf("StoreAwareAccount.resolveOnDevice"))
        assertTrue("a retry beside a run in flight is busy", retry.contains("claimForUserRetry"))
        assertTrue(moduleText.contains("trigger.claimFor(eoa, System.currentTimeMillis())"))
    }

    @Test
    fun theUpgradeTriggerSettlesOnlyOnASuccessAndReleasesTheRest() {
        val m = moduleText
        assertEquals(
            "the trigger and the retry command both settle only keep_existing, upgraded_from_L, upgraded_from_chain and first_identity_registered",
            2,
            Regex("""code == "keep_existing" \|\| code == "upgraded_from_L" \|\| code == "upgraded_from_chain" \|\| code == network\.conet\.chat\.nativekey\.KpgpUpgrade\.FIRST_IDENTITY_REGISTERED\) trigger\.settle""").findAll(m).count(),
        )
    }

    // ---- the page restore with the old key of an older build -----------------------------------------------------------------------

    private fun machineWith(
        chain: PgpRestoreChain,
        files: NativeTestFiles = NativeTestFiles(),
        shipped: () -> String? = { null },
        wrap: NativeTestWrap = NativeTestWrap(),
    ) = PgpRestoreMachine(
        chain = chain,
        wallet = object : PgpRestoreWallet {
            override fun ready(): Boolean = true
            override fun passwordString(): String? = canonical
            override fun passwordForms(): List<String>? = NativePgpBackup.passwordForms(accountKey)
        },
        keys = object : PgpRestoreKeys {
            override fun newKey(deviceId: String): PgpNewKey = error("the restore never generates a key")
        },
        ivFor = { error("the restore never writes a backup") },
        devices = mapOf(PgpRestoreBridge.DEVICE to PgpRestoreDevice(PgpRestoreBridge.DEVICE, eoa, wrap, files)),
        shippedArmor = shipped,
    )

    private fun activeOf(m: PgpRestoreMachine) = m.devices.getValue(PgpRestoreBridge.DEVICE).active

    @Test
    fun theOldKeyThatIsTheRegisteredIdentityRestoresWithoutAChainBackup() {
        // The approval flag is not involved: the machine checks the master fingerprint and the subkey keyId, as it does for the backup.
        assertFalse(PgpMigrationPolicy.OPENPGP_APPROVED)
        val m = machineWith(FakeChain(record = own.identity, backup = ""), shipped = { own.privateArmor })
        val result = PgpRestoreBridge.restore(m)
        assertEquals("ok", result.getString("code"))
        assertTrue(activeOf(m).identity()!!.sameAs(own.identity))
        assertFalse(result.keys().asSequence().any { it in CredFields.NAMES })
    }

    @Test
    fun evaluatingWithTheOldKeyWritesNothing() {
        val m = machineWith(FakeChain(record = own.identity, backup = ""), shipped = { own.privateArmor })
        val result = PgpRestoreBridge.evaluate(m)
        assertEquals("ok", result.getString("state"))
        assertTrue(activeOf(m).state() is NativePgpVault.State.NoKey)
    }

    @Test
    fun anOldKeyThatIsNotTheRegisteredIdentityIsIgnoredAndTheBackupDecides() {
        val m = machineWith(FakeChain(record = own.identity, backup = backupOf(own, canonical)), shipped = { other.privateArmor })
        assertEquals("ok", PgpRestoreBridge.restore(m).getString("code"))
        assertTrue("the registered key was restored, not the old one", activeOf(m).identity()!!.sameAs(own.identity))
    }

    @Test
    fun anOldKeyThatCannotBeReadIsNoSourceAndNothingIsGeneratedWhenTheBackupIsMissing() {
        val m = machineWith(FakeChain(record = own.identity, backup = ""), shipped = { throw java.io.IOException("unreadable") })
        val result = PgpRestoreBridge.evaluate(m)
        assertEquals("failed", result.getString("state"))
        assertEquals("pgp_backup_missing", result.getString("code"))
        assertTrue(result.getBoolean("offerEntry"))
        assertTrue(activeOf(m).state() is NativePgpVault.State.NoKey)
    }

    @Test
    fun aKeyThatIsNotTheRegisteredIdentityAndNoBackupOffersTheEntryOnly() {
        val m = machineWith(FakeChain(record = own.identity, backup = ""), shipped = { other.privateArmor })
        val result = PgpRestoreBridge.evaluate(m)
        assertEquals("failed", result.getString("state"))
        assertTrue(result.getBoolean("offerEntry"))
        assertTrue(activeOf(m).state() is NativePgpVault.State.NoKey)
    }

    @Test
    fun anUnreadableChainWithAnOldKeyIsUndeterminedNotRestored() {
        val m = machineWith(FakeChain(readable = false), shipped = { own.privateArmor })
        val result = PgpRestoreBridge.restore(m)
        assertEquals("pgp_source_unavailable", result.getString("code"))
        assertTrue(activeOf(m).state() is NativePgpVault.State.NoKey)
    }

    @Test
    fun anActiveKeyIsNeverOverwrittenByTheOldKey() {
        val files = NativeTestFiles()
        val wrap = NativeTestWrap()
        val first = machineWith(FakeChain(record = own.identity, backup = backupOf(own, canonical)), files, wrap = wrap)
        assertEquals("ok", PgpRestoreBridge.restore(first).getString("code"))
        val before = activeOf(first).identity()!!
        // The chain now registers another identity; the old key matches it. The slot is not empty, so nothing is written over the active key.
        val second = machineWith(FakeChain(record = other.identity, backup = ""), files, shipped = { other.privateArmor }, wrap = wrap)
        PgpRestoreBridge.restore(second)
        assertTrue(activeOf(second).identity()!!.sameAs(before))
    }

    @Test
    fun theClaimIsGivenBackWhateverEndsTheRunAnErrorIncluded() {
        // Both claim sites hold the claim in a try with a finally that releases it when the run did not reach settle or release.
        val m = moduleText
        assertEquals(2, Regex("""var given = false""").findAll(m).count())
        assertEquals(2, Regex("""if \(!given\) trigger\.release\(eoa, System\.currentTimeMillis\(\)\)""").findAll(m).count())
        // And at the unit level: a claim that is released can be claimed again after its delay, so an escaped Error cannot leave the account busy.
        assertTrue(KpgpUpgradeTrigger.claimFor(eoa, 0L))
        KpgpUpgradeTrigger.release(eoa, 0L)
        assertTrue(KpgpUpgradeTrigger.claimFor(eoa, 60_000L))
    }

    // ---- every put of the module: no key-like name on an ack or an event --------------------------------------------------------------

    @Test
    fun noAckOrEventOfTheModuleCarriesAKeyLikeField() {
        val put = Regex("""\.put\(\s*"([A-Za-z0-9_]+)"""")
        val keyLike = CredFields.NAMES.toSet() + setOf("mnemonic", "phrase", "seed", "secret", "privateKey", "private", "passcode", "passphrase", "pin", "armor", "privateKeyArmor")
        val offenders = moduleText.lines().filter { line -> put.findAll(line).any { it.groupValues[1] in keyLike } }.map { it.trim() }
        // The only key-like names in the module are the status word of the passcode command and an internal value that is never emitted.
        val expected = listOf(
            """ack(reqId, true, result = JSONObject().put("passcode", "set").put("eoa", r.eoa).put("verifiedAddress", r.verifiedAddress))""",
            """val admitFields = JSONObject().put("eoa", eoa).put("passcode", passcode)""",
        )
        assertEquals("a key-like field was put in the module: $offenders", expected, offenders)
    }
}
