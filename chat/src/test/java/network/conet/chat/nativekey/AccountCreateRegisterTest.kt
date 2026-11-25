package network.conet.chat.nativekey

import java.io.File
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * `accountCreateRegister` : the request shape, the error table, the answer whitelist, no plain secret anywhere, one
 * payload at a time, the registry check before a payload, and a recover record the existing restore reads. Synthetic phrase and password only.
 * (N-01 to N-07, N-09, N-10; N-08 is the page's: it reuses one payload.)
 */
class AccountCreateRegisterTest {
    private val random = SecureRandom()
    private val phraseText = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    private val key = MnemonicDerivation.deriveKey(phraseText)!!
    private val eoa = WalletAddress.fromPrivateKey(key)!!
    private val cheap: (ByteArray, RecoveryRecord.Stored) -> ByteArray = { p, s -> MessageDigest.getInstance("SHA-256").digest(p + s.salt) }
    private val secretPassword = "pw-9f3a-distinct-secret"

    @Before
    fun reset() = AccountRegisterCommand.Flight.resetForTests()

    private fun req(vararg extra: Pair<String, Any?>): JSONObject =
        JSONObject().put("type", "accountCreateRegister").put("reqId", "r1").put("tag", "qa.tag_1").put("password", secretPassword).also { o ->
            extra.forEach { (k, v) -> if (v == null) o.remove(k) else o.put(k, v) }
        }

    private fun material() = AccountRegisterCommand.MaterialRead.Ready(AccountRegisterCommand.Material(eoa, key.copyOf(), phraseText.toByteArray()))

    private fun run(
        tag: String = "qa.tag_1",
        password: ByteArray = secretPassword.toByteArray(),
        mat: () -> AccountRegisterCommand.MaterialRead = { material() },
        registry: (String) -> String? = { null },
        enter: (String) -> Boolean = AccountRegisterCommand.Flight::tryEnter,
        exit: (String) -> Unit = AccountRegisterCommand.Flight::exit,
    ) = AccountRegisterCommand.run(tag, password, mat, registry, { n, p, e, k, ph -> AccountRegisterPayload.build(n, p, e, k, ph, random, cheap) }, enter, exit)

    // ---- N-01: the request keys ------------------------------------------------------------------------------------------------------------

    @Test
    fun onlyTheFourKeysAreAcceptedAndBothValuesMustBeStrings() {
        assertTrue(AccountRegisterCommand.parse(req()) is AccountRegisterCommand.Parsed.Ok)
        for (bad in listOf(
            req("tag" to null),
            req("password" to null),
            req("reqId" to null),
            req("extra" to "x"),
            req("accountName" to "x"),
            req("tag" to 5),
            req("password" to 5),
            req("tag" to JSONObject()),
        )) {
            val r = AccountRegisterCommand.parse(bad)
            assertTrue("refused: $bad", r is AccountRegisterCommand.Parsed.Refused && r.code == "bad_request")
        }
    }

    // ---- N-02: tag and password ------------------------------------------------------------------------------------------------------------

    @Test
    fun anInvalidTagIsBadTagAndAnEmptyPasswordIsBadPassword() {
        for (tag in listOf("ab", "has space", "x".repeat(27), "tag!", "", "@")) {
            assertEquals("bad_tag for '$tag'", "bad_tag", run(tag = tag).error)
        }
        assertEquals("bad_password", run(password = ByteArray(0)).error)
        assertTrue("a leading @ is dropped, as the server does", run(tag = "@qa.tag_1").ok)
    }

    // ---- N-03 and N-04: the answer ---------------------------------------------------------------------------------------------------------

    @Test
    fun theSuccessAnswerHasTheWhitelistedKeysAndNoPlainSecret() {
        val out = run()
        assertTrue(out.ok)
        val r = out.result!!
        assertEquals(AccountRegisterCommand.RESULT_KEYS, r.keys().asSequence().toSet())
        assertEquals("qa.tag_1", r.getString("accountName"))
        assertEquals("the wallet is lower case", eoa.lowercase(), r.getString("wallet"))
        assertTrue(r.getString("signMessage").startsWith("0x") && r.getString("signMessage").length == 132)
        assertEquals(2, r.getJSONArray("recover").length())
        for (i in 0 until 2) assertEquals("recover entries are the existing IAccountRecover fields", setOf("hash", "encrypto"), r.getJSONArray("recover").getJSONObject(i).keys().asSequence().toSet())
        val code = r.getString("recoverCodeBase58")
        assertEquals(22, code.length)
        val text = r.toString()
        for (secret in listOf(secretPassword, phraseText, "abandon", ConetHex.of(key))) assertFalse("no $secret in the answer", text.contains(secret))
        assertFalse("no key or armor field", text.contains("PRIVATE") || text.contains("privateKey") || text.contains("mnemonic"))
    }

    @Test
    fun aFailureAnswerHoldsOnlyTheCodeAndTheOptionalReason() {
        val taken = run(registry = { "0x" + "11".repeat(20) })
        assertEquals("tag_taken", taken.error)
        assertEquals(null, taken.result)
        assertEquals(null, taken.reason)
    }

    // ---- N-05 and N-06: the password is nowhere -------------------------------------------------------------------------------------------

    @Test
    fun thePasswordIsZeroedAndNeverInAnAnswerALogLineOrAnyStorage() {
        val pw = secretPassword.toByteArray()
        val out = run(password = pw)
        assertTrue(out.ok)
        assertTrue("zeroed after the run", pw.all { it == 0.toByte() })
        assertFalse(out.result.toString().contains(secretPassword))
        // The module handler logs lengths only; no password value reaches a log line, an event or a counter.
        val module = File("src/main/java/network/conet/chat/BeamioConetChatModule.kt").readText()
        val handler = module.substringAfter("private fun accountCreateRegisterCommand(").substringBefore("/** The read-only chain check")
        val logLines = handler.lines().filter { it.contains("Log.") }
        assertTrue(logLines.isNotEmpty())
        for (line in logLines) {
            assertFalse("a log line does not take the password value: $line", Regex("""request\.password(?!\.length)""").containsMatchIn(line) || line.contains("password)") || line.contains("\$password"))
        }
        assertTrue(handler.contains("passwordLen=\${request.password.length}") && handler.contains("tagLen=\${request.tag.length}"))
        // No storage, no event and no counter in the command's own files.
        for (name in listOf("AccountRegisterCommand.kt", "AccountRegisterPayload.kt")) {
            val src = File("src/main/java/network/conet/chat/nativekey/$name").readText()
            assertFalse("$name does not log", src.contains("Log.") || src.contains("println") || src.contains("DiagTiming"))
            assertFalse("$name does not store", src.contains("SharedPreferences") || src.contains("files.write") || src.contains("File("))
        }
        val bridge = File("src/main/java/network/conet/chat/BridgeCommandTable.kt").readText()
        assertFalse("the password is not a counter key", bridge.contains("password"))
    }

    @Test
    fun theCommandKeepsNoCopyOfTheRecoverCodeAcrossCalls() {
        val a = run().result!!.getString("recoverCodeBase58")
        val b = run().result!!.getString("recoverCodeBase58")
        assertNotEquals("each call makes its own code; the page must reuse one payload (N-08 is the page's)", a, b)
    }

    // ---- N-07: one at a time ----------------------------------------------------------------------------------------------------------------

    @Test
    fun twoCallsForOneAccountAtTheSameTimeGiveOneInFlight() {
        val inside = CountDownLatch(1)
        val release = CountDownLatch(1)
        val first = java.util.concurrent.FutureTask {
            run(registry = { inside.countDown(); release.await(10, TimeUnit.SECONDS); null })
        }
        Thread(first).also { it.isDaemon = true; it.start() }
        assertTrue(inside.await(5, TimeUnit.SECONDS))
        val second = run()
        assertEquals("in_flight", second.error)
        release.countDown()
        assertTrue(first.get(10, TimeUnit.SECONDS).ok)
        assertTrue("released after the call", run().ok)
    }

    // ---- N-09: the registry first -----------------------------------------------------------------------------------------------------------

    @Test
    fun anOwnTagIsAlreadyRegisteredAndGeneratesNothingAndAnUnreadableRegistryIsNotReadyNeverTagTaken() {
        val built = AtomicInteger()
        val countingBuild = { n: String, p: ByteArray, e: String, k: ByteArray, ph: ByteArray -> built.incrementAndGet(); AccountRegisterPayload.build(n, p, e, k, ph, random, cheap) }
        val ours = AccountRegisterCommand.run("qa.tag_1", secretPassword.toByteArray(), { material() }, { eoa.lowercase() }, countingBuild)
        assertEquals("a payload would overwrite the recover the user was shown; the page calls no addUser", "already_registered", ours.error)
        val unreadable = AccountRegisterCommand.run("qa.tag_1", secretPassword.toByteArray(), { material() }, { throw IllegalStateException("network_error") }, countingBuild)
        assertEquals("not_ready", unreadable.error)
        assertEquals(null, unreadable.reason)
        assertEquals("nothing was signed or sealed", 0, built.get())
        val taken = AccountRegisterCommand.run("qa.tag_1", secretPassword.toByteArray(), { material() }, { "0x" + "11".repeat(20) }, countingBuild)
        assertEquals("tag_taken", taken.error)
        assertEquals(0, built.get())
        assertTrue("a free tag is built", AccountRegisterCommand.run("qa.tag_1", secretPassword.toByteArray(), { material() }, { null }, countingBuild).ok)
        assertEquals(1, built.get())
    }

    @Test
    fun anInternalFailureMapsToTheDocumentedCodes() {
        fun failWith(code: String) = AccountRegisterCommand.run("qa.tag_1", secretPassword.toByteArray(), { material() }, { null }, { _, _, _, _, _ -> AccountRegisterPayload.Built.Refused(code) }).error
        assertEquals("an address the phrase does not derive", "sign_failed", failWith("phrase_mismatch"))
        assertEquals("sign_failed", failWith("sign_failed"))
        assertEquals("a failed random or KDF", "seal_failed", failWith("seal_failed"))
        assertEquals("an account without a plain phrase (a v3 ciphertext account)", "seal_failed",
            AccountRegisterCommand.run("qa.tag_1", secretPassword.toByteArray(), { AccountRegisterCommand.MaterialRead.Ready(AccountRegisterCommand.Material(eoa, key.copyOf(), null)) }, { null }).error)
    }

    // ---- not_ready and the reason --------------------------------------------------------------------------------------------------------------

    @Test
    fun aMissingPasscodePackageIsNotReadyWithTheReasonAndAnUnreadableStateHasNone() {
        val passcode = run(mat = { AccountRegisterCommand.MaterialRead.NotReady(true) })
        assertEquals("not_ready", passcode.error)
        assertEquals("passcode_not_provided", passcode.reason)
        val unknown = run(mat = { AccountRegisterCommand.MaterialRead.NotReady(false) })
        assertEquals("not_ready", unknown.error)
        assertEquals(null, unknown.reason)
        assertEquals("a key-only account has nothing to seal", "seal_failed",
            run(mat = { AccountRegisterCommand.MaterialRead.Ready(AccountRegisterCommand.Material(eoa, key.copyOf(), null)) }).error)
    }

    // ---- N-10: the recover record is readable by the existing restore -----------------------------------------------------------------------

    @Test
    fun theRecoverCodeAndThePasswordRestoreTheAccountThroughTheExistingEngine() {
        val r = run().result!!
        val code = r.getString("recoverCodeBase58")
        val recover = r.getJSONArray("recover")
        val byHash = (0 until 2).associate { recover.getJSONObject(it).getString("hash") to recover.getJSONObject(it).getString("encrypto") }
        val registry = object : RecoveryRegistryReader {
            override fun byNameHash(indexHash: ByteArray): String? = byHash["0x" + indexHash.joinToString("") { "%02x".format(it) }]
            override fun byAccountName(name: String): String? =
                byHash["0x" + network.conet.chat.ConetChatCryptoUtil.keccak256(name.toByteArray()).joinToString("") { "%02x".format(it) }]
        }
        val store = object : RecoveryFailureStore {
            var n = 0
            override fun failures() = n
            override fun lastFailureAtMs() = 0L
            override fun save(failures: Int, atMs: Long) { n = failures }
            override fun clear() { n = 0 }
        }
        // By the recover code (path A) into a fresh vault.
        val a = NativeWalletVault(NativeTestWrap(), NativeTestFiles())
        val outA = RecoveryEngine(a, registry, store, RecoveryClock { 1_700_000_000_000L }, cheap).restoreWithCode(code.toByteArray())
        assertEquals("ok", outA.code)
        assertEquals(eoa, outA.eoa)
        // By the account name and the password (path B) into another fresh vault.
        val b = NativeWalletVault(NativeTestWrap(), NativeTestFiles())
        val outB = RecoveryEngine(b, registry, store, RecoveryClock { 1_700_000_000_000L }, cheap).restoreWithAccountPassword("qa.tag_1", secretPassword.toCharArray())
        assertEquals("ok", outB.code)
        assertEquals(eoa, outB.eoa)
        assertEquals("a wrong password does not restore", "bad_pin",
            RecoveryEngine(NativeWalletVault(NativeTestWrap(), NativeTestFiles()), registry, store, RecoveryClock { 1_700_000_000_000L }, cheap).restoreWithAccountPassword("qa.tag_1", "wrong".toCharArray()).code)
    }

    // ---- the password allowance is for this command only (table-T and the bridge audit) ---------------------------------------------------------

    @Test
    fun thePasswordFieldIsPassedForThisCommandAndStillRefusedForTheOthers() {
        val withPassword = JSONObject().put("type", "x").put("reqId", "r").put("password", "p")
        assertFalse("accountCreateRegister is not in the credential-refusal commands", "accountCreateRegister" in network.conet.chat.identity.CredFields.COMMANDS)
        assertTrue(network.conet.chat.identity.CredFields.refusalNames("accountCreateRegister", withPassword).isEmpty())
        for (cmd in network.conet.chat.identity.CredFields.COMMANDS) {
            assertEquals("$cmd still refuses a password field", listOf("password"), network.conet.chat.identity.CredFields.refusalNames(cmd, withPassword))
        }
        // The allowed source lines are in this command's file only.
        val readers = File("src/main/java/network/conet/chat").walkTopDown().filter { it.name.endsWith(".kt") }
            .filter { it.readText().contains("body.opt(\"password\")") }.map { it.name }.toList()
        assertEquals(listOf("AccountRegisterCommand.kt"), readers)
    }

    // ---- availability and wiring -------------------------------------------------------------------------------------------------------------

    @Test
    fun theCommandIsRegisteredAndEnabledInEveryBuildWithItsOwnSwitch() {
        assertTrue(network.conet.chat.BridgeCommandTable.isRegistered("accountCreateRegister"))
        assertFalse("not in the pinned table-T dispatch set", network.conet.chat.BridgeCommandTable.DISPATCH.contains("accountCreateRegister"))
        val module = File("src/main/java/network/conet/chat/BeamioConetChatModule.kt").readText()
        val handler = module.substringAfter("private fun accountCreateRegisterCommand(").substringBefore("/** The read-only chain check")
        // Its gate is its own switch, ahead of any work, and it no longer reads the first-identity QA flag.
        assertTrue(handler.indexOf("if (!BuildConfig.ACCOUNT_CREATE_REGISTER) return fail(\"not_available\")") in 0 until handler.indexOf("io.execute"))
        assertFalse("the command does not depend on the first-identity QA flag", handler.contains("IDENTITY_STATE_EVENTS_QA"))
        // A production build: this command is on, the first-identity features stay off.
        assertEquals("a production build enables the command", true, network.conet.chat.BuildConfig.ACCOUNT_CREATE_REGISTER)
        assertEquals("a production build keeps the first-identity features off", false, network.conet.chat.BuildConfig.IDENTITY_STATE_EVENTS_QA)
        assertTrue(handler.contains("password.fill(0)"))
        assertFalse("the native layer never POSTs addUser", handler.contains("addUser") || handler.contains("HttpURLConnection") || handler.contains("httpPost"))
    }

    @Test
    fun theSwitchDefaultsOnAndOnlyTheValueFalseTurnsItOff() {
        val gradle = File("build.gradle.kts").readText()
        val block = gradle.substringAfter("\"ACCOUNT_CREATE_REGISTER\",").substringBefore("),")
        assertTrue(block.contains("project.findProperty(\"chatAccountCreateRegister\")?.toString() != \"false\""))
        assertFalse("the QA property is not the switch", block.contains("chatIdentityStateEventsQa"))
    }
}

/** Hex of a byte array for the tests' no-secret scans. */
private object ConetHex {
    fun of(b: ByteArray) = b.joinToString("") { "%02x".format(it) }
}
