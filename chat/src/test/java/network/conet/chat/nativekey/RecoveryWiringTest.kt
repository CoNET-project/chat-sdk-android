package network.conet.chat.nativekey

import network.conet.chat.nativekey.PgpMigrationKeys.ACCOUNT
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.security.SecureRandom

/**
 * The wiring around the recovery gate: the typed registered key and the chain id, the page restore with the gate (zero writes on a refusal), the
 * migration that verifies in memory before it stages anything, the account served by `pgp(app)`, and the source guards (who may construct the typed
 * values, who may write the vault, that the gate does not read the global flag).
 */
class RecoveryWiringTest {
    private val random = SecureRandom()
    private val account = "0x" + "ab".repeat(20)
    private val own = RecKeys.generate(account, random)
    private val other = RecKeys.generate(account, random)
    private val accountKey = ByteArray(32) { (it + 7).toByte() }
    private val canonical = NativePgpBackup.passwordString(accountKey)

    private fun backupOf(pgp: RecPgp): String =
        NativePgpBackup.encryptArmor(canonical, pgp.privateArmor.toByteArray(Charsets.UTF_8), ByteArray(12).also { random.nextBytes(it) })

    // ---- the registry read ------------------------------------------------------------------------------------------------------------

    private fun word(v: Long): ByteArray = ByteArray(32).also { w -> for (i in 0 until 8) w[31 - i] = ((v shr (8 * i)) and 0xFF).toByte() }
    private fun string(s: String): ByteArray {
        val b = s.toByteArray(Charsets.UTF_8)
        return word(b.size.toLong()) + b + ByteArray((32 - b.size % 32) % 32)
    }
    private fun hex(b: ByteArray) = "0x" + b.joinToString("") { "%02x".format(it) }
    private fun recordHex(publicArmor: String?): String {
        val a = string("")
        val p = string(publicArmor ?: "")
        val c = string("")
        val head = word(128) + word(128L + a.size) + word(128L + a.size + p.size) + word(if (publicArmor != null) 1 else 0)
        return hex(head + a + p + c)
    }
    private fun backupHex(text: String): String = hex(word(32) + string(text))

    private class Endpoint(val chainId: String?, val record: String, val backup: String) : AddressPgpRead.Rpc {
        override fun call(method: String, params: JSONArray): Any? = when (method) {
            "eth_chainId" -> chainId ?: error("down")
            "eth_blockNumber" -> "0x2a"
            "eth_getBlockByNumber" -> JSONObject().put("number", "0x2a").put("hash", "0x" + "ab".repeat(32))
            "eth_call" -> {
                val data = params.getJSONObject(0).getString("data").substring(0, 10)
                if (data == AddressPgpRead.selector(AddressPgpRead.SIG_PGP_KEYS)) record else backup
            }
            else -> error("unexpected $method")
        }
    }

    private val config = AddressPgpConfig(
        AddressPgpConfig.default.contract,
        listOf(RegistryEndpoint("https://a.test", 1000), RegistryEndpoint("https://b.test", 1000)),
    )

    private fun agreed(a: Endpoint, b: Endpoint) = AddressPgpChain.readAgreed(account, config) { ep -> if (ep.url == "https://a.test") a else b }

    @Test
    fun theAgreedReadGivesTheRegisteredKeyWithItsBlockAccountContractAndSource() {
        val ok = Endpoint("0x36ca6", recordHex(own.publicArmor), backupHex(""))
        val read = agreed(ok, ok).registeredKey() as RegisteredKeyRead.Present
        val key = read.key
        assertEquals(account, key.account)
        assertEquals(own.identity.fingerprint, key.fingerprint)
        assertEquals(own.identity.subkeyKeyId, key.subkeyKeyId)
        assertEquals("the armor is the record's own", own.publicArmor, key.publicArmor)
        assertEquals(42L, key.block)
        assertEquals(224422L, key.chainId)
        assertEquals(AddressPgpConfig.default.contract.lowercase(), key.contract)
        assertEquals(RegisteredPgpKey.Source.AGREED, key.source)
    }

    @Test
    fun aWrongChainIdOnEitherEndpointIsUnknown() {
        val good = Endpoint("0x36ca6", recordHex(own.publicArmor), backupHex(""))
        val wrong = Endpoint("0x1", recordHex(own.publicArmor), backupHex(""))
        val down = Endpoint(null, recordHex(own.publicArmor), backupHex(""))
        for (pair in listOf(good to wrong, wrong to good, wrong to wrong, good to down)) {
            val chain = agreed(pair.first, pair.second)
            assertFalse(chain.chainReadable())
            assertTrue(chain.registeredKey() is RegisteredKeyRead.Unknown)
        }
    }

    @Test
    fun anAbsentRecordIsAbsentAndAnUnparsableOneIsUnknown() {
        val absent = Endpoint("0x36ca6", recordHex(null), backupHex(""))
        assertTrue(agreed(absent, absent).registeredKey() is RegisteredKeyRead.Absent)
        val junk = Endpoint("0x36ca6", recordHex("not an armor"), backupHex(""))
        assertTrue(agreed(junk, junk).registeredKey() is RegisteredKeyRead.Unknown)
    }

    @Test
    fun theSingleReadIsSingleAndAFirstAnswerReadGivesNoRegisteredKey() {
        val ok = Endpoint("0x36ca6", recordHex(own.publicArmor), backupHex(""))
        val single = AddressPgpChain.readSingle(account, config) { ok }.registeredKey() as RegisteredKeyRead.Present
        assertEquals(RegisteredPgpKey.Source.SINGLE, single.key.source)
        val first = AddressPgpChain.read(account, config) { ok }
        assertTrue("a first-answer read is never a gate input", first.registeredKey() is RegisteredKeyRead.Unknown)
    }

    // ---- the page restore with the gate ------------------------------------------------------------------------------------------------

    private class PageEnv {
        val log = ArrayList<String>()
        val base = NativeTestFiles()
        val files = CountingFiles(base, log)
        val wrap = NativeTestWrap()
    }

    private fun machine(env: PageEnv, chain: PgpRestoreChain, shipped: () -> String? = { null }, gate: PageRecoveryGate? = PageRecoveryGate()) = PgpRestoreMachine(
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
        devices = mapOf(PgpRestoreBridge.DEVICE to PgpRestoreDevice(PgpRestoreBridge.DEVICE, account, env.wrap, env.files)),
        shippedArmor = shipped,
        recoveryGate = gate,
    )

    private fun active(m: PgpRestoreMachine) = m.devices.getValue(PgpRestoreBridge.DEVICE).active

    @Test
    fun thePageRestoreWritesTheVaultOnlyAfterTheKeyVerifiedAgainstTheRegisteredKey() {
        val env = PageEnv()
        val m = machine(env, RecChain(registered = registeredOf(own, account, source = RegisteredPgpKey.Source.SINGLE), backup = backupOf(own)))
        val result = PgpRestoreBridge.restore(m)
        assertEquals("ok", result.getString("code"))
        assertTrue(active(m).state() is NativePgpVault.State.Ready)
        assertTrue(env.files.writes > 0)
    }

    @Test
    fun aPageChallengeThatFailsWritesNothing() {
        // The record names the candidate's identity, but the registered public ring is another key's: the signature cannot verify with it.
        val env = PageEnv()
        val chain = RecChain(registered = registeredOf(own, account, source = RegisteredPgpKey.Source.SINGLE, publicArmor = other.publicArmor), backup = backupOf(own))
        val m = machine(env, chain)
        val result = PgpRestoreBridge.restore(m)
        assertEquals("pgp_verify_failed", result.getString("code"))
        assertEquals("failed", result.getString("state"))
        assertTrue(env.files.untouched)
        assertTrue(env.base.map.isEmpty())
        assertTrue(active(m).state() is NativePgpVault.State.NoKey)
        assertTrue("the entry is offered, nothing is generated", m.devices.getValue(PgpRestoreBridge.DEVICE).ui.offerEntry)
    }

    @Test
    fun aPageRestoreWithAChainThatGivesNoRegisteredKeyWritesNothing() {
        val env = PageEnv()
        val bare = object : PgpRestoreChain {
            override fun chainReadable(): Boolean = true
            override fun backupReadable(): Boolean = true
            override fun version(): Long = 0L
            override fun identity(): PgpIdentity? = own.identity
            override fun backupText(): String = backupOf(own)
            override fun write(identity: PgpIdentity, backupText: String) = error("never")
        }
        val m = machine(env, bare)
        assertEquals("pgp_verify_failed", PgpRestoreBridge.restore(m).getString("code"))
        assertTrue(env.files.untouched)
    }

    @Test
    fun theOldKeyOfThePageRestoreIsHeldToTheSameGate() {
        val ok = PageEnv()
        val m1 = machine(ok, RecChain(registered = registeredOf(own, account, source = RegisteredPgpKey.Source.SINGLE), backup = ""), shipped = { own.privateArmor })
        assertEquals("ok", PgpRestoreBridge.restore(m1).getString("code"))
        // An old key that is the registered identity by name but not by key: the gate refuses it, and no backup exists.
        val bad = PageEnv()
        val forged = registeredOf(own, account, source = RegisteredPgpKey.Source.SINGLE, publicArmor = other.publicArmor)
        val m2 = machine(bad, RecChain(registered = forged, backup = ""), shipped = { own.privateArmor })
        assertEquals("pgp_verify_failed", PgpRestoreBridge.restore(m2).getString("code"))
        assertTrue(bad.files.untouched)
    }

    @Test
    fun evaluatingIsUnchangedByTheGate() {
        val env = PageEnv()
        val forged = registeredOf(own, account, source = RegisteredPgpKey.Source.SINGLE, publicArmor = other.publicArmor)
        val m = machine(env, RecChain(registered = forged, backup = backupOf(own)))
        val result = PgpRestoreBridge.evaluate(m)
        assertEquals("ok", result.getString("state"))
        assertTrue(env.files.untouched)
    }

    @Test
    fun aMachineWithoutTheGateKeepsTheOlderBehaviourAndTheProductionMachineAlwaysHasOne() {
        val env = PageEnv()
        val m = machine(env, RecChain(registered = RegisteredKeyRead.Unknown, backup = backupOf(own)), gate = null)
        // RecChain derives its identity from the registered key; with none, the older fixtures use their own chains. Here only the wiring is checked.
        assertNotNull(m)
        val bridge = File("src/main/java/network/conet/chat/nativekey/PgpRestoreBridge.kt").readText()
        assertTrue("productionMachine passes the page gate", Regex("""recoveryGate\s*=\s*PageRecoveryGate\(\)""").containsMatchIn(bridge))
    }

    // ---- the migration verifies in memory first ----------------------------------------------------------------------------------------

    private val legacyA = legacyRecord(ACCOUNT, PgpMigrationKeys.a.priv, PgpMigrationKeys.a.pub)
    private val wrap = NativeTestWrap()

    @Test
    fun aMigrationChallengeThatFailsPersistsNothingNotEvenTheStagedItem() {
        val base = NativeTestFiles()
        val files = CountingFiles(base, ArrayList())
        val result = migrationEngine(files, wrap, legacyA, ChainAnswer.Found(PgpMigrationKeys.a.fp), MigrationFaults(challenge = true)).run()
        assertEquals(MigrationCode.CHALLENGE_FAILED, result.code)
        // Not written and rolled back: never written (the last-code record is the only write of a refusal).
        assertTrue("nothing of the key reached the disk: ${base.map.keys}", base.map.keys.none { it.endsWith(".n") || it.endsWith(".m") })
        assertTrue("no staged item was ever written, not even for a moment", files.writes <= 1 && files.deletes == 0)
    }

    @Test
    fun aMigrationInterruptedAfterTheMemoryChallengeHasStagedNothing() {
        val files = NativeTestFiles()
        val faults = MigrationFaults(interrupt = "afterVerify")
        try {
            migrationEngine(files, wrap, legacyA, ChainAnswer.Found(PgpMigrationKeys.a.fp), faults).run(checkpointFor(faults))
            error("expected an interruption")
        } catch (_: PgpMigrationInterrupted) {
        }
        assertTrue("no staged item, no marker: ${files.map.keys}", files.map.keys.none { it.endsWith(".n") || it.endsWith(".m") })
        // The next run starts from nothing and completes.
        val done = migrationEngine(files, wrap, legacyA, ChainAnswer.Found(PgpMigrationKeys.a.fp)).run()
        assertEquals(MigrationCode.OK, done.code)
    }

    @Test
    fun theMigrationStillNeedsTheGlobalFlagAndWritesNothingWithoutIt() {
        val files = NativeTestFiles()
        val result = migrationEngine(files, wrap, legacyA, ChainAnswer.Found(PgpMigrationKeys.a.fp), MigrationFaults(approved = false)).run()
        assertEquals(MigrationCode.VERIFY_UNAVAILABLE, result.code)
        assertTrue(files.map.keys.none { it.endsWith(".n") })
        assertFalse(PgpMigrationPolicy.OPENPGP_APPROVED)
    }

    // ---- the account served by pgp(app) -----------------------------------------------------------------------------------------------

    @Test
    fun pgpServesTheVaultAccountFirstThenTheStoreAccountAndOtherwiseNone() {
        val storeAccount = StoreAwareAccount.Resolution.Account(account, StoreAwareAccount.Source.STORE_PLAIN)
        val other = "0x" + "cd".repeat(20)
        assertEquals(other, StoreAwareAccount.pgpAccountOf(other) { error("the store is not asked when the vault is Ready") })
        assertEquals(account, StoreAwareAccount.pgpAccountOf(null) { storeAccount })
        assertEquals(NativePgpVault.NO_ACCOUNT, StoreAwareAccount.pgpAccountOf(null) { StoreAwareAccount.Resolution.NotReady("passcode_not_provided") })
        assertEquals(NativePgpVault.NO_ACCOUNT, StoreAwareAccount.pgpAccountOf(null) { StoreAwareAccount.Resolution.NoKey })
    }

    // ---- source guards ----------------------------------------------------------------------------------------------------------------

    private fun mainSources(): List<File> =
        File("src/main/java").walkTopDown().filter { it.isFile && it.extension == "kt" }.toList()

    @Test
    fun onlyTheGateBuildsAVerifiedKeyAndOnlyTheChainReadBuildsARegisteredKey() {
        val verified = mainSources().filter { Regex("""(?<![A-Za-z])VerifiedRecoveryKey\(""").containsMatchIn(it.readText()) && it.name != "RecoveryChallengeGate.kt" }
        assertTrue("a VerifiedRecoveryKey is built outside the gate: ${verified.map { it.name }}", verified.isEmpty())
        val registered = mainSources().filter { Regex("""(?<![A-Za-z])RegisteredPgpKey\(""").containsMatchIn(it.readText()) && it.name != "AddressPgpChain.kt" }
        assertTrue("a RegisteredPgpKey is built outside the chain read: ${registered.map { it.name }}", registered.isEmpty())
    }

    @Test
    fun onlyTheAutoRecoveryAndThePageMachineActivateAVerifiedKey() {
        val users = mainSources().filter { it.readText().contains("VerifiedPgpActivation.write") && it.name != "RecoveryChallengeGate.kt" }.map { it.name }.toSet()
        assertEquals(setOf("AutoRecovery.kt", "PgpRestoreMachine.kt"), users)
    }

    /** Every line of the main sources that holds a three-argument `put` (the shape of `NativePgpVault.put(eoa, armor, passphrase[, overwrite])`), with its file, one entry per line. */
    private fun vaultPutLines(): List<Pair<String, String>> {
        val call = Regex("""\.put\(\s*[\w.]+\s*,\s*[^,()]*(?:\([^()]*\))?[^,()]*,\s*(?:"[^"]*"|[\w.]+)\s*(?:,\s*overwrite\s*=\s*\w+\s*)?\)""")
        return mainSources().flatMap { f -> f.readLines().filter { call.containsMatchIn(it) }.map { f.name to it.trim() } }.sortedBy { it.first + it.second }
    }

    @Test
    fun everyVaultPutCallIsOneOfTheseExactLines() {
        // Any receiver, any argument names, counted by line: a new three-argument put anywhere, or a copy or edit of a listed one, changes this list.
        val allowed = listOf(
            "BeamioConetChatModule.kt" to "return when (NativeWallet.pgpFor(ctx, eoa).put(eoa, armor, passphrase)) {", // init field (a key in the init payload is refused first)
            "PgpRestoreMachine.kt" to "if (dev.old.put(dev.account, armor, \"\") == NativePgpVault.Put.OK) counters.localWrites++", // old backup before a replacement
            "PgpRestoreMachine.kt" to "if (dev.active.put(dev.account, key.armorText(), \"\") == NativePgpVault.Put.OK) return true", // a new key after its registration
            "PgpRestoreMachine.kt" to "val putResult = verifiedKey?.let { VerifiedPgpActivation.write(dev.active, it) } ?: dev.active.put(dev.account, armor, \"\")", // gate null: older fixtures only
            "PgpRestoreMachine.kt" to "if (dev.pending.put(dev.account, key.armorText(), \"\") != NativePgpVault.Put.OK) {", // a new key waiting for its registration
            "RecoveryChallengeGate.kt" to "vault.put(key.account, key.privateArmor, \"\", overwrite = false)", // the activation of a verified key
            "FirstIdentityCoordinator.kt" to "val put = dev.pending.put(account, generated.privateArmor, \"\")", // the key generated on the confirmed-no-record branch, kept pending
            "FirstIdentityCoordinator.kt" to "val put = dev.active.put(account, armor, \"\")", // the pending key after its registration was read back
        ).sortedBy { it.first + it.second }
        assertEquals("the vault put calls changed", allowed, vaultPutLines())
    }

    @Test
    fun theRecoveryEntriesTakeAVerifiedKeyAndNothingElseWritesTheVaultFromARecoveredArmor() {
        // The two recovery writers go through VerifiedPgpActivation, whose only parameter is the verified key.
        val activation = File("src/main/java/network/conet/chat/nativekey/RecoveryChallengeGate.kt").readText()
        assertTrue(Regex("""fun write\(vault: NativePgpVault, key: VerifiedRecoveryKey\)""").containsMatchIn(activation))
        val auto = File("src/main/java/network/conet/chat/nativekey/AutoRecovery.kt").readText()
        assertFalse("AutoRecovery has no put of its own", Regex("""\.put\(""").containsMatchIn(auto))
        val upgrade = File("src/main/java/network/conet/chat/nativekey/KpgpUpgrade.kt").readText()
        assertFalse("KpgpUpgrade does not write the vault", Regex("""\.put\(""").containsMatchIn(upgrade))
        // The page machine is built in the bridge only, with its gate.
        val builders = mainSources().filter { Regex("""(?<![A-Za-z])PgpRestoreMachine\(""").containsMatchIn(it.readText()) && it.name != "PgpRestoreMachine.kt" }.map { it.name }
        assertEquals(listOf("PgpRestoreBridge.kt"), builders)
    }

    @Test
    fun theGateDoesNotReadTheGlobalFlagOrCallApproved() {
        val gate = File("src/main/java/network/conet/chat/nativekey/RecoveryChallengeGate.kt").readText()
        val code = gate.lines().filterNot { it.trim().startsWith("*") || it.trim().startsWith("//") || it.trim().startsWith("/*") }.joinToString("\n")
        assertFalse(code.contains("OPENPGP_APPROVED"))
        assertFalse(code.contains(".approved()"))
        val auto = File("src/main/java/network/conet/chat/nativekey/AutoRecovery.kt").readText()
        assertFalse(auto.lines().filterNot { it.trim().startsWith("*") }.joinToString("\n").contains("approved()"))
        assertFalse(PgpMigrationPolicy.OPENPGP_APPROVED)
    }

    @Test
    fun theGateAndTheRecoveryFilesPutNoKeyLikeFieldOnTheBridgeAndLogNoSecret() {
        val names = listOf("RecoveryChallengeGate.kt", "AutoRecovery.kt", "LegacyArmorRestore.kt", "ChainBackupRestore.kt")
        for (n in names) {
            val text = File("src/main/java/network/conet/chat/nativekey/$n").readText()
            assertFalse("$n puts a JSON field", Regex("""\.put\(\s*"""").containsMatchIn(text))
            assertFalse("$n logs", Regex("""Log\.|println""").containsMatchIn(text))
        }
        // The only log of the recovery goes through DiagTiming with a code; the codes are fixed words.
        val auto = File("src/main/java/network/conet/chat/nativekey/KpgpUpgrade.kt").readText()
        assertTrue(auto.contains("DiagTiming.log(\"autorecovery\", t0, outcome.logCode)"))
    }

    // ---- the same master with another subkey --------------------------------------------------------------------------------------------

    @Test
    fun anOldKeyWithTheSameMasterButAnotherSubkeyIsIgnoredAndAValidChainBackupDecides() {
        val (registeredKey, olderRing) = sameMasterKeys(account, random)
        assertEquals("same master fingerprint", registeredKey.identity.fingerprint, olderRing.identity.fingerprint)
        assertTrue("another first subkey", registeredKey.identity.subkeyKeyId != olderRing.identity.subkeyKeyId)
        val env = PageEnv()
        val backup = NativePgpBackup.encryptArmor(canonical, registeredKey.privateArmor.toByteArray(Charsets.UTF_8), ByteArray(12).also { random.nextBytes(it) })
        val m = machine(env, RecChain(registered = registeredOf(registeredKey, account, source = RegisteredPgpKey.Source.SINGLE), backup = backup), shipped = { olderRing.privateArmor })
        val result = PgpRestoreBridge.restore(m)
        assertEquals("ok", result.getString("code"))
        assertTrue("the backup decided: the registered ring's key is the active one", active(m).identity()!!.sameAs(registeredKey.identity))
    }

    @Test
    fun theSameCaseWithoutABackupOffersTheEntryAndWritesNothing() {
        val (registeredKey, olderRing) = sameMasterKeys(account, random)
        val env = PageEnv()
        val m = machine(env, RecChain(registered = registeredOf(registeredKey, account, source = RegisteredPgpKey.Source.SINGLE), backup = ""), shipped = { olderRing.privateArmor })
        val result = PgpRestoreBridge.restore(m)
        assertEquals("pgp_backup_missing", result.getString("code"))
        assertTrue(env.files.untouched)
    }
}
