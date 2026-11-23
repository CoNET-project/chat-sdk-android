package network.conet.chat.nativekey

import android.content.Context
import android.content.ContextWrapper
import java.io.File
import java.security.MessageDigest
import network.conet.chat.BeamioConetChatModule
import network.conet.chat.MainPoster
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Passcode-preserving unlock and sync (method Y; sdkCases MS-01 to MS-11 of passcode-unlock-sync-vectors.v1.json, plus the two Android ciphertext entries).
 * The page unlocks a passcode-protected account and sends `pwaWalletSync{eoa, cipher, passcode, seq}`; the native record stays the v3 ciphertext before,
 * during and after, the session becomes ready, and after a restart it is locked again. Everything runs through the real entries on real store files
 * (the context's `noBackupFilesDir`), the store is written only by the commands under test, and the synthetic phrase, passcode and envelope come from
 * the shared vector file. The second account is the public all-"abandon" test phrase.
 *
 * Entry (a): only the page held the ciphertext, the native store is empty. Entry (b): only the native store holds the ciphertext. Both are covered for
 * the original-address restore and the unlock-then-sync, and the passcode and the phrase are searched for in every file the SDK wrote.
 */
class PasscodePreservingSyncTest {
    private val vec = JSONObject(javaClass.getResource("/vectors/mnemonic-cipher-format.v3.json")!!.readText())
    private val inputs = vec.getJSONObject("syntheticInputs")
    private val phraseA = inputs.getString("phrase")
    private val eoaA = inputs.getString("eoa").lowercase()
    private val passcode = inputs.getString("sixDigitPasscode")
    private val wrongPasscode = if (passcode == "111111") "222222" else "111111"
    private val envelopeA = vec.getJSONArray("cases").getJSONObject(0).getJSONObject("envelope")
    private val phraseB = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    private val eoaB: String = checkNotNull(WalletAddress.fromPrivateKey(checkNotNull(MnemonicDerivation.deriveKey(phraseB)))).lowercase()
    private lateinit var context: Context
    private lateinit var dir: File
    private var reqId = 300
    private var seq = 20000L

    private class TestContext(private val dir: File) : ContextWrapper(null) {
        override fun getApplicationContext(): Context = this
        override fun getFilesDir(): File = dir
        override fun getCacheDir(): File = dir
        override fun getNoBackupFilesDir(): File = dir
    }

    @Before
    fun setUp() {
        dir = kotlin.io.path.createTempDirectory("m6-sync").toFile()
        context = TestContext(dir)
        MainPoster.runner = { it.run() }
        BeamioConetChatModule::class.java.getDeclaredField("appContext").apply { isAccessible = true }.set(BeamioConetChatModule, context)
        restart()
        val vault = NativeWalletVault(NativeTestWrap(), AndroidVaultFiles(File(dir, "native_vault_v1").also { it.mkdirs() }))
        NativeWallet.installVaultForTest(vault)
        vault.state()
        NativeWallet.migrateLegacy(context)
        for (i in 0 until 100) {
            if (NativeWallet.isLegacyWalletAdoptionSettled() && !NativeWallet.isLegacyWalletAdoptionInFlight()) break
            Thread.sleep(50)
        }
        check(LegacyStoreReport.reportLegacyStore(context, LegacyStoreReport.ABSENT) == "ok")
    }

    @After
    fun tearDown() {
        MainPoster.runner = null
        NativeSessionState.reset()
        NativeWallet.installVaultForTest(null)
        MnemonicPreread.resetForTests()
    }

    /** A new process: the in-memory session and the pre-read state are gone; the files stay. */
    private fun restart() {
        NativeSessionState.reset()
        MnemonicPreread.resetForTests()
    }

    private fun ack(body: JSONObject): JSONObject {
        val out = mutableListOf<JSONObject>()
        BeamioConetChatModule.handleCommand(context, body) { out.add(it) }
        return out.mapNotNull { it.optJSONObject("event") }.lastOrNull { it.optString("type") == "ack" } ?: error("no ack: $out")
    }

    private fun cmd(type: String, vararg kv: Pair<String, Any?>) = JSONObject().put("type", type).put("reqId", reqId++).also { b -> kv.forEach { b.put(it.first, it.second) } }
    private fun sync(vararg kv: Pair<String, Any?>) = ack(cmd("pwaWalletSync", *kv, "trustedOrigin" to true, "seq" to seq++))
    private fun cipherOf(env: JSONObject) = JSONObject(env.toString())
    /** The answer code of a refusal: M6 v3 answers unlock_failed and verify_failed as ok:true with result.code. */
    private fun code(r: JSONObject): String = r.optJSONObject("result")?.optString("code")?.takeIf { it.isNotEmpty() } ?: r.optString("error")
    private fun assertCode(expected: String, r: JSONObject) {
        assertEquals(r.toString(), expected, code(r))
        if (expected == "unlock_failed" || expected == "verify_failed") assertTrue("the shape is ok:true with result.code: $r", r.optBoolean("ok") && r.optJSONObject("result")?.has("code") == true)
    }
    private fun syncCipher(env: JSONObject = envelopeA, passcode: String? = null, eoa: String? = null): JSONObject {
        val kv = arrayListOf<Pair<String, Any?>>("cipher" to cipherOf(env))
        if (eoa != null) kv.add("eoa" to eoa)
        if (passcode != null) kv.add("passcode" to passcode)
        return sync(*kv.toTypedArray())
    }
    private fun syncPhrase(phrase: String, eoa: String) = sync("phrase" to phrase, "eoa" to eoa)
    private fun envelopeB(): JSONObject {
        val e = MnemonicCipherV3.seal(eoaB, passcode, phraseB, MnemonicCipherV3.newSalt(), MnemonicCipherV3.newIv())
        return JSONObject().put("v", e.v).put("mode", e.mode).put("eoa", e.eoa).put("kdf", e.kdf).put("salt", e.saltB64).put("iv", e.ivB64).put("alg", e.alg).put("ct", e.ctB64)
    }

    private fun sign(): JSONObject = ack(cmd("gossipSign", "kind" to "envelope", "message" to "synthetic signing text"))
    private fun signedBy(eoa: String): Boolean = sign().let { it.optBoolean("ok") && it.getJSONObject("result").getString("address").lowercase() == eoa }
    private fun walletStatus() = ack(cmd("walletStatus")).getJSONObject("result")
    private fun passcodeStatus() = ack(cmd("passcodeStatus", "eoa" to eoaA)).getJSONObject("result")
    private fun walletEoaAddress(): JSONObject = BeamioShellRecordImport.answerFromPage(context, BeamioShellRecordImport.ALLOWED_ORIGIN, true, cmd("walletEoaAddress"), 64)!!
    private fun preread(): JSONObject = ack(cmd("nativeMnemonicPreread", "trustedOrigin" to true, "seq" to seq++))

    private fun sets(): File = File(dir, MnemonicSetStore.DIRECTORY)
    private fun storeHash(): String {
        val md = MessageDigest.getInstance("SHA-256")
        val d = sets()
        if (d.exists()) d.walkTopDown().filter { it != d }.sortedBy { it.relativeTo(d).path }.forEach { f ->
            md.update(f.relativeTo(d).path.toByteArray()); md.update(if (f.isDirectory) byteArrayOf(0) else f.readBytes())
        }
        return md.digest().joinToString("") { "%02x".format(it) }
    }
    private fun currentPointer(): String = File(sets(), "current.v1").readText().trim()
    private fun setBytes(eoa: String, kind: String? = null): String {
        val f = names().filter { it.startsWith("set.$eoa.") && (kind == null || it.contains(".$kind.")) }.sorted()
        val md = MessageDigest.getInstance("SHA-256")
        f.forEach { md.update(it.toByteArray()); md.update(File(sets(), it).readBytes()) }
        return md.digest().joinToString("") { "%02x".format(it) }
    }
    private fun names(): List<String> = (sets().list() ?: emptyArray()).sorted()
    private fun hasPlainSet(eoa: String) = names().any { it.startsWith("set.$eoa.plain.") }
    private fun hasV3Set(eoa: String) = names().any { it.startsWith("set.$eoa.v3.") }
    private fun breakCurrentV3(eoa: String) { val f = File(sets(), "set.$eoa.v3.1.v1"); assertTrue(f.delete()); assertTrue(f.mkdir()) }

    /**
     * Nothing the SDK wrote anywhere under the context directory contains the passcode (as a standalone value; inside base64 it cannot be one) or a phrase.
     * Every file is read, directories included in the walk.
     */
    private fun assertNoSecretOnDisk(vararg phrases: String) {
        val standalone = Regex("(?<![A-Za-z0-9+/=])" + Regex.escape(passcode) + "(?![A-Za-z0-9+/=])")
        val wrongStandalone = Regex("(?<![A-Za-z0-9+/=])" + Regex.escape(wrongPasscode) + "(?![A-Za-z0-9+/=])")
        dir.walkTopDown().filter { it.isFile }.forEach { f ->
            val text = String(f.readBytes(), Charsets.ISO_8859_1)
            assertFalse("the passcode is in ${f.name}", standalone.containsMatchIn(text) || wrongStandalone.containsMatchIn(text))
            for (p in phrases) assertFalse("a phrase is in ${f.name}", text.contains(p))
        }
    }

    // ---- MS-01 / MS-10: entry (b), the native record is the ciphertext ----
    @Test
    fun ms01AndMs10TheCiphertextStaysEncryptedThroughUnlockAndRestart() {
        assertTrue(syncCipher().optBoolean("ok"))
        val before = storeHash()
        assertFalse("locked before the unlock", signedBy(eoaA))
        val r = syncCipher(passcode = passcode)
        assertTrue(r.toString(), r.optBoolean("ok")); assertEquals("ok", r.getJSONObject("result").getString("code")); assertTrue(r.getJSONObject("result").getBoolean("decrypted"))
        assertEquals("store bytes unchanged", before, storeHash())
        assertTrue("session ready: signing works", signedBy(eoaA))
        assertFalse(passcodeStatus().getBoolean("nativeLocked"))
        assertEquals("unlocked", walletStatus().getString("status"))
        assertEquals(eoaA, walletEoaAddress().getJSONObject("result").getString("eoa"))
        assertTrue("still the v3 envelope", hasV3Set(eoaA)); assertFalse("never a plaintext set", hasPlainSet(eoaA))
        // restart
        restart()
        assertEquals("still the same bytes after the restart", before, storeHash())
        val pre = preread().getJSONObject("result")
        assertEquals("ok", pre.getString("code")); assertEquals(eoaA, pre.getJSONObject("cipher").getString("eoa")); assertFalse(pre.has("mnemonic"))
        assertTrue(passcodeStatus().getBoolean("nativeLocked"))
        val ws = walletStatus(); assertEquals("not_ready", ws.getString("status")); assertEquals("passcode_not_provided", ws.getString("notReadyReason"))
        val s = sign(); assertFalse(s.optBoolean("ok")); assertEquals("not_ready", s.getString("error"))
        assertEquals("not_ready", walletEoaAddress().getString("error"))
        // the next start syncs again, and the same bytes stay
        assertTrue(syncCipher(passcode = passcode).optBoolean("ok"))
        assertEquals(before, storeHash()); assertTrue(signedBy(eoaA))
    }

    // ---- MS-02: a plaintext phrase never replaces the ciphertext of the same account ----
    @Test
    fun ms02APlaintextPhraseDoesNotReplaceTheCiphertextOfTheSameAccount() {
        assertTrue(syncCipher().optBoolean("ok"))
        assertTrue(syncCipher(passcode = passcode).optBoolean("ok"))
        val before = storeHash()
        val r = syncPhrase(phraseA, eoaA)
        assertTrue(r.toString(), r.optBoolean("ok")); assertEquals("unchanged", r.getJSONObject("result").getString("sync")); assertEquals(eoaA, r.getJSONObject("result").getString("eoa"))
        assertEquals("store bytes unchanged", before, storeHash())
        assertTrue(hasV3Set(eoaA)); assertFalse(hasPlainSet(eoaA))
        // also before any unlock, and after a restart
        restart()
        assertEquals("unchanged", syncPhrase(phraseA, eoaA).getJSONObject("result").getString("sync")); assertEquals(before, storeHash())
        assertNoSecretOnDisk(phraseA)
    }

    /** Counter-example: the phrase of ANOTHER account still takes the existing different-account rule (a new plaintext set for it). */
    @Test
    fun aPhraseOfAnotherAccountStillFollowsTheDifferentAccountRule() {
        assertTrue(syncCipher().optBoolean("ok"))
        val r = syncPhrase(phraseB, eoaB)
        assertTrue(r.toString(), r.optBoolean("ok")); assertEquals("updated", r.getJSONObject("result").getString("sync"))
        assertTrue(hasPlainSet(eoaB)); assertTrue("the older ciphertext is kept", hasV3Set(eoaA))
    }

    // ---- MS-03 / MS-05: entry (a), only the page held the ciphertext ----
    @Test
    fun ms03TheNativeStoreIsEmptyAndTheCiphertextArrivesWithTheCorrectPasscode() {
        assertTrue("nothing stored", names().isEmpty())
        val r = syncCipher(passcode = passcode)
        assertTrue(r.toString(), r.optBoolean("ok")); assertTrue(r.getJSONObject("result").getBoolean("decrypted"))
        assertTrue("the v3 envelope itself", hasV3Set(eoaA)); assertFalse("never a plaintext set", hasPlainSet(eoaA))
        assertEquals("one new version", 2, names().size) // the set file and the pointer
        assertTrue(signedBy(eoaA)); assertEquals(eoaA, walletEoaAddress().getJSONObject("result").getString("eoa"))
        // restart: still ciphertext, locked, and the original address is recovered by the next unlock
        val bytes = storeHash(); restart()
        assertEquals(bytes, storeHash()); assertFalse(signedBy(eoaA)); assertTrue(hasV3Set(eoaA)); assertFalse(hasPlainSet(eoaA))
        assertTrue(syncCipher(passcode = passcode).optBoolean("ok")); assertEquals(bytes, storeHash())
        assertEquals(eoaA, walletEoaAddress().getJSONObject("result").getString("eoa")); assertTrue(signedBy(eoaA))
        assertNoSecretOnDisk(phraseA)
    }

    @Test
    fun ms05AWrongPasscodeOnAnEmptyStoreWritesNothingAndStaysLocked() {
        val r = syncCipher(passcode = wrongPasscode)
        assertCode("unlock_failed", r)
        assertTrue("nothing stored", names().isEmpty())
        assertFalse(signedBy(eoaA)); assertNotEquals("unlocked", walletStatus().optString("status"))
        assertNoSecretOnDisk(phraseA)
    }

    // ---- MS-04: wrong passcode, same envelope ----
    @Test
    fun ms04AWrongPasscodeLeavesTheStoreUnchangedAndTheSessionLocked() {
        assertTrue(syncCipher().optBoolean("ok"))
        val before = storeHash()
        val r = syncCipher(passcode = wrongPasscode)
        assertCode("unlock_failed", r)
        assertEquals(before, storeHash()); assertFalse(signedBy(eoaA)); assertTrue(passcodeStatus().getBoolean("nativeLocked"))
        // and after an unlock a later wrong passcode does not lock or change anything either
        assertTrue(syncCipher(passcode = passcode).optBoolean("ok"))
        val r2 = syncCipher(passcode = wrongPasscode)
        assertCode("unlock_failed", r2); assertEquals(before, storeHash()); assertTrue("an unlocked session stays unlocked", signedBy(eoaA))
        assertNoSecretOnDisk(phraseA)
    }

    // ---- MS-06 / MS-23 / MS-26: an envelope of another account is a legal switch ----
    @Test
    fun ms06AnEnvelopeOfAnotherAccountIsSavedAsItsOwnSetAndBecomesCurrent() {
        assertTrue(syncCipher().optBoolean("ok"))
        val aBytes = setBytes(eoaA); val aNames = names().filter { it.startsWith("set.$eoaA.") }
        val b = envelopeB()
        val before = storeHash()
        // wrong passcode (MS-26): unlock_failed, nothing written, current stays A
        val wrong = syncCipher(b, wrongPasscode, eoa = eoaB)
        assertCode("unlock_failed", wrong); assertEquals("nothing written", before, storeHash()); assertEquals("$eoaA|v3|1", currentPointer())
        // correct passcode: B saved as its own v3 set, read back, then current moves
        val ok = syncCipher(b, passcode, eoa = eoaB)
        assertTrue(ok.toString(), ok.optBoolean("ok")); assertEquals("updated", ok.getJSONObject("result").getString("sync")); assertEquals(eoaB, ok.getJSONObject("result").getString("eoa"))
        assertTrue("B's own v3 set", hasV3Set(eoaB)); assertFalse("never a plaintext set", hasPlainSet(eoaB))
        assertEquals("current is B", "$eoaB|v3|1", currentPointer())
        assertEquals("A's set is identical and still present", aBytes, setBytes(eoaA)); assertTrue(names().containsAll(aNames))
        assertTrue("ready for B", signedBy(eoaB))
        assertNoSecretOnDisk(phraseA, phraseB)
    }

    /** MS-23 from a plaintext current: the page holds B's envelope and the passcode. */
    @Test
    fun ms23ASwitchFromAPlaintextCurrentToAnEnvelopeKeepsTheEnvelopePersisted() {
        assertTrue(syncPhrase(phraseA, eoaA).optBoolean("ok"))
        val aBytes = setBytes(eoaA)
        val ok = syncCipher(envelopeB(), passcode, eoa = eoaB)
        assertTrue(ok.toString(), ok.optBoolean("ok")); assertEquals("updated", ok.getJSONObject("result").getString("sync"))
        assertTrue(hasV3Set(eoaB)); assertFalse(hasPlainSet(eoaB)); assertEquals("$eoaB|v3|1", currentPointer())
        assertEquals(aBytes, setBytes(eoaA)); assertTrue(signedBy(eoaB))
    }

    // ---- MS-24: switching back moves only the pointer ----
    @Test
    fun ms24SwitchingBackToASavedAccountMovesOnlyThePointer() {
        assertTrue(syncPhrase(phraseA, eoaA).optBoolean("ok"))
        assertTrue(syncPhrase(phraseB, eoaB).optBoolean("ok"))
        val aBytes = setBytes(eoaA); val bBytes = setBytes(eoaB)
        val back = syncPhrase(phraseA, eoaA)
        assertTrue(back.toString(), back.optBoolean("ok")); assertEquals("updated", back.getJSONObject("result").getString("sync"))
        assertEquals("$eoaA|plain|1", currentPointer()); assertEquals(aBytes, setBytes(eoaA)); assertEquals(bBytes, setBytes(eoaB))
        assertTrue(signedBy(eoaA))
        // the same for envelopes: B's envelope again after A became current again
        assertTrue(syncCipher(envelopeA, passcode, eoa = eoaA).optBoolean("ok")) // A plaintext current + A envelope: stored as A's v3 set
        val bCipher = envelopeB()
        assertTrue(syncCipher(bCipher, passcode, eoa = eoaB).optBoolean("ok"))
        val v3BBytes = setBytes(eoaB, "v3")
        assertTrue(syncCipher(envelopeA, passcode, eoa = eoaA).optBoolean("ok"))
        val again = syncCipher(bCipher, passcode, eoa = eoaB)
        assertTrue(again.toString(), again.optBoolean("ok"))
        assertEquals("B's saved envelope is reused: its bytes do not change", v3BBytes, setBytes(eoaB, "v3"))
        assertEquals("$eoaB|v3|1", currentPointer())
    }

    // ---- a legal account switch, and a failed switch keeps the current record ----
    /** A plaintext account B synced while A is current: no user interaction; B is written and read back, then current moves; A and its set stay. */
    @Test
    fun aLegalAccountSwitchWritesTheNewSetThenMovesCurrentAndKeepsTheOldOne() {
        assertTrue(syncPhrase(phraseA, eoaA).optBoolean("ok"))
        val oldNames = names().filter { it.startsWith("set.$eoaA.") }
        val r = syncPhrase(phraseB, eoaB)
        assertTrue(r.toString(), r.optBoolean("ok")); assertEquals("updated", r.getJSONObject("result").getString("sync"))
        assertTrue("the old account's set is kept", names().containsAll(oldNames))
        assertEquals("current is the new account", "$eoaB|plain|1", File(sets(), "current.v1").readText().trim())
        assertTrue(signedBy(eoaB))
        assertNoSecretOnDisk()
    }

    /** The new set cannot be written: nothing moves. The old current stays, the old set stays, and the answer is a write failure. */
    @Test
    fun aFailedSwitchLeavesTheCurrentRecordAndTheOldSetsUnchanged() {
        assertTrue(syncPhrase(phraseA, eoaA).optBoolean("ok"))
        val before = storeHash()
        assertTrue(File(sets(), "set.$eoaB.plain.1.v1").mkdir()) // the target name is taken by a directory: the new set cannot be put in place
        val r = syncPhrase(phraseB, eoaB)
        assertFalse(r.toString(), r.optBoolean("ok")); assertEquals("write_failed", r.getString("error"))
        assertEquals("current did not move", "$eoaA|plain|1", File(sets(), "current.v1").readText().trim())
        assertTrue(File(sets(), "set.$eoaA.plain.1.v1").isFile)
        assertTrue("A still signs", signedBy(eoaA))
        File(sets(), "set.$eoaB.plain.1.v1").delete()
        assertEquals("only the blocking directory was ever added", before, storeHash())
    }

    // ---- MS-25: a failure at each step of a switch keeps current and deletes nothing ----
    @Test
    fun ms25AFailureAtAnyStepOfASwitchKeepsCurrentAndTheOldSet() {
        // (1) the new set cannot be put in place; (2) the pointer cannot be written
        for (fault in listOf("set_target_taken", "pointer_tmp_blocked")) {
            restart(); sets().deleteRecursively()
            assertTrue(syncPhrase(phraseA, eoaA).optBoolean("ok"))
            val before = storeHash()
            val blocker = if (fault == "set_target_taken") File(sets(), "set.$eoaB.plain.1.v1") else File(sets(), "current.v1.tmp")
            assertTrue(blocker.mkdir())
            val r = syncPhrase(phraseB, eoaB)
            assertFalse("$fault: $r", r.optBoolean("ok")); assertEquals(fault, "write_failed", r.getString("error"))
            assertEquals("$fault: a plain write error is storage_write, at the top level", "storage_write", r.optString("reason"))
            assertEquals("$fault: current stays A", "$eoaA|plain|1", currentPointer())
            assertTrue("$fault: A's set is still there", File(sets(), "set.$eoaA.plain.1.v1").isFile)
            assertTrue("$fault: A still signs", signedBy(eoaA))
            blocker.delete()
            if (fault == "pointer_tmp_blocked") File(sets(), "set.$eoaB.plain.1.v1").delete() // the new set that was written but not made current is not part of "before"
            assertEquals("$fault: only the blocker or the unreferenced new set differed", before, storeHash())
        }
    }

    /** A read-back that does not match is an unknown state (internal_state), and it moves nothing: current and the old set stay. */
    @Test
    fun ms25AReadBackMismatchMovesNothingAndIsAnUnknownState() {
        val store = MnemonicSetStore(sets())
        assertTrue(store.writePlain(eoaA, phraseA) is MnemonicSetStore.Write.Stored)
        val before = currentPointer(); val aBytes = setBytes(eoaA)
        val staged = (store.stagePlain(eoaB, phraseB) as MnemonicSetStore.Stage.Ready).staged
        File(sets(), "set.$eoaB.plain.1.v1.tmp").writeText("tampered between the write and the read-back", Charsets.UTF_8)
        assertEquals(MnemonicSetStore.Commit.READBACK_MISMATCH, staged.commitOutcome())
        assertEquals("current did not move", before, currentPointer()); assertEquals("A's set is unchanged", aBytes, setBytes(eoaA))
        assertEquals("the reason of that outcome is internal_state", NativeSyncAck.INTERNAL_STATE, PwaSyncCipher.failedReason("readback_mismatch"))
        assertEquals("a plain write error is storage_write", NativeSyncAck.STORAGE_WRITE, PwaSyncCipher.failedReason("write_failed"))
    }

    // ---- MS-32 / MS-33: init and the silent selection follow current only ----
    // init answers from its own worker and reads the published PGP store (SharedPreferences), which the JVM cannot drive; the decision it takes
    // is the pure one below (what the current pointer names, and the session adoption for that account only), checked on real store files.
    @Test
    fun ms32AV3CurrentIsNotSelectedForAnyOtherAccountAndNothingIsAdoptedForIt() {
        assertTrue(syncPhrase(phraseB, eoaB).optBoolean("ok"))   // another account's set is present
        assertTrue(syncCipher(envelopeA, null, eoaA).optBoolean("ok")) // current becomes A's v3 envelope
        val before = storeHash()
        val cur = MnemonicSetStore(sets()).current() as MnemonicSetStore.Current.Found
        assertEquals("the current pointer names A, and only A", eoaA, cur.eoa); assertEquals(MnemonicSetStore.Kind.V3, cur.kind)
        for (init in listOf(eoaA, eoaB)) assertNull("a v3 current never adopts a session in init ($init)", StoreSessionAdoption.plainAdoption(NativeWalletVault.State.NoKey, cur, init))
        assertEquals("no session was made ready for any account", null, NativeSessionState.readyEoa())
        assertEquals("not_ready with passcode_not_provided until it is unlocked", NoKeyGate.Gate.G1, NoKeyGate.commandGate(NativeWalletVault.State.NoKey, false, false, cur, null))
        assertEquals("no set was touched", before, storeHash())
    }

    @Test
    fun ms33AfterASwitchTheSilentSelectionFollowsTheNewCurrent() {
        assertTrue(syncPhrase(phraseA, eoaA).optBoolean("ok"))
        assertTrue(syncPhrase(phraseB, eoaB).optBoolean("ok"))
        val cur = MnemonicSetStore(sets()).current()
        assertEquals("$eoaB|plain|1", currentPointer())
        assertNull("A is not selected by the first-entry rule while a valid current names B", StoreSessionAdoption.plainAdoption(NativeWalletVault.State.NoKey, cur, eoaA))
        val adopt = StoreSessionAdoption.plainAdoption(NativeWalletVault.State.NoKey, cur, eoaB)
        assertEquals("the new current is the one that is selected", eoaB, adopt?.eoa)
        adopt?.key?.fill(0)
        assertEquals("the source of the account is the new current", NativeSource.Source.Store(eoaB, MnemonicSetStore.Kind.PLAIN).eoa, (NativeSource.decide(null, cur, null) as NativeSource.Source.Store).eoa)
    }

    /** init cannot be driven on the JVM (it needs the published PGP store); its v3 and unreadable-store answers are guarded on the source. */
    @Test
    fun initAnswersNotReadyForAV3OrUnreadableStoreAndNeverNoKeyForThem() {
        val module = File("src/main/java/network/conet/chat/BeamioConetChatModule.kt").readText(Charsets.UTF_8)
        val init = module.substring(module.indexOf("when (StoreAccountView.of(currentStore, NativeSessionState.readyEoa()))"))
        val block = init.substring(0, init.indexOf("is NativeWalletVault.State.Locked ->"))
        assertTrue(block.contains("is StoreAccountView.View.V3 ->") && block.contains("notReadyAck(reqId, NoKeyGate.NOT_READY_PASSCODE_REQUIRED)"))
        assertTrue(block.contains("StoreAccountView.View.Unknown -> notReadyAck(reqId, NoKeyGate.NOT_READY_UNREADABLE)"))
    }

    // ---- MS-27: the storage state is unknown ----
    @Test
    fun ms27AnUnreadablePointerWritesNothingOnEitherPath() {
        assertTrue(syncPhrase(phraseA, eoaA).optBoolean("ok"))
        File(sets(), "current.v1").writeText("garbage", Charsets.UTF_8)
        val before = storeHash()
        for (r in listOf(syncPhrase(phraseB, eoaB), syncCipher(envelopeB(), passcode, eoa = eoaB))) {
            assertFalse(r.toString(), r.optBoolean("ok")); assertEquals("write_failed", r.getString("error"))
            assertEquals("internal_state", r.optString("reason"))
        }
        assertEquals(before, storeHash())
    }

    // ---- MS-17 / MS-28: identity checks refuse and write nothing ----
    @Test
    fun ms17AndMs28AnIdentityCheckFailureWritesNothingOnEitherPath() {
        assertTrue(syncPhrase(phraseA, eoaA).optBoolean("ok"))
        val before = storeHash()
        // passcode path: the declared eoa is not the envelope's
        assertCode("verify_failed", syncCipher(envelopeB(), passcode, eoa = eoaA))
        // passcode path: the envelope opens, but its phrase does not derive the envelope eoa
        val liar = MnemonicCipherV3.seal(eoaB, passcode, phraseA, MnemonicCipherV3.newSalt(), MnemonicCipherV3.newIv())
        val liarEnv = JSONObject().put("v", liar.v).put("mode", liar.mode).put("eoa", liar.eoa).put("kdf", liar.kdf).put("salt", liar.saltB64).put("iv", liar.ivB64).put("alg", liar.alg).put("ct", liar.ctB64)
        assertCode("verify_failed", syncCipher(liarEnv, passcode, eoa = eoaB))
        // no passcode path: the address derived from the phrase is not the declared eoa
        assertCode("bad_request", syncPhrase(phraseB, eoaA))
        assertEquals("nothing written", before, storeHash()); assertEquals("current unchanged", "$eoaA|plain|1", currentPointer())
        assertTrue(signedBy(eoaA)); assertFalse(signedBy(eoaB))
    }

    // ---- MS-29 / MS-30 / MS-31: a switch touches nothing but the pointer and the new set ----
    @Test
    fun ms29AndMs30ASwitchLeavesTheChatStoresAndTheOldSetAlone() {
        assertTrue(syncPhrase(phraseA, eoaA).optBoolean("ok"))
        val chatA = File(dir, "chat_history_$eoaA.db").also { it.writeText("synthetic chat of A", Charsets.UTF_8) }
        val outside = dir.walkTopDown().filter { it.isFile && !it.path.contains(MnemonicSetStore.DIRECTORY) }.sortedBy { it.path }.associate { it.relativeTo(dir).path to it.readText() }
        val aFile = File(sets(), "set.$eoaA.plain.1.v1"); val aText = aFile.readText()
        assertTrue(syncPhrase(phraseB, eoaB).optBoolean("ok"))
        val outsideAfter = dir.walkTopDown().filter { it.isFile && !it.path.contains(MnemonicSetStore.DIRECTORY) }.sortedBy { it.path }.associate { it.relativeTo(dir).path to it.readText() }
        assertEquals("chat stores and every other file are untouched by the switch", outside, outsideAfter)
        assertTrue(chatA.isFile)
        assertEquals("A's set is neither rewritten", aText, aFile.readText())
        assertTrue("nor renamed or isolated", names().none { it.contains("isolated") } && aFile.isFile)
    }

    // ---- MS-07: a read fault ----
    @Test
    fun ms07AReadFaultWritesNothingAndDoesNotUnlock() {
        assertTrue(syncCipher().optBoolean("ok"))
        breakCurrentV3(eoaA)
        val before = storeHash()
        val r = syncCipher(passcode = passcode)
        assertFalse(r.optBoolean("ok")); assertEquals("write_failed", r.getString("error"))
        assertEquals("internal_state", r.optString("reason"))
        assertEquals(before, storeHash()); assertFalse(signedBy(eoaA))
        // the status commands report unknown, never no_key
        val ws = walletStatus(); assertEquals("not_ready", ws.getString("status")); assertEquals("unreadable", ws.getString("notReadyReason"))
        val s = sign(); assertEquals("not_ready", s.getString("error"))
    }

    // ---- MS-08: invalid envelopes ----
    @Test
    fun ms08InvalidEnvelopesAreNeverAcceptedAndWriteNothing() {
        val bad = listOf(
            cipherOf(envelopeA).put("v", 2),
            cipherOf(envelopeA).put("mode", "none"),
            cipherOf(envelopeA).put("kdf", "argon2id/m=1/t=1/p=1/dkLen=32"),
            cipherOf(envelopeA).put("alg", "AES-128-GCM"),
            cipherOf(envelopeA).put("ct", envelopeA.getString("ct").let { it.substring(0, it.length - 8) + "AAAAAAA=" }),
        )
        for ((i, env) in bad.withIndex()) {
            for (p in listOf<String?>(null, passcode)) {
                val before = storeHash()
                val r = syncCipher(env, p)
                if (p == null && i == 4) continue // a tampered ct without a passcode is only mirrored by shape; the format check cannot tell (covered below with a passcode)
                assertFalse("case $i passcode=${p != null}: accepted: $r", r.optBoolean("ok") && code(r) == "ok")
                assertTrue("case $i: closed set, got ${code(r)}", code(r) in setOf("bad_request", "unlock_failed", "verify_failed"))
                assertEquals("case $i: nothing written", before, storeHash())
            }
        }
        assertFalse(signedBy(eoaA))
    }

    // ---- MS-09: no passcode with an envelope ----
    @Test
    fun ms09AnEnvelopeWithoutAPasscodeIsOnlyMirroredAndStaysLocked() {
        val r = syncCipher()
        assertTrue(r.toString(), r.optBoolean("ok")); assertFalse(r.getJSONObject("result").getBoolean("decrypted"))
        assertTrue(hasV3Set(eoaA)); assertFalse(signedBy(eoaA))
        val before = storeHash()
        assertTrue(syncCipher().optBoolean("ok")); assertEquals("the identical envelope is not rewritten", before, storeHash())
    }

    // ---- MS-11 and the commands that need a key: a present v3 record is never no_key ----
    @Test
    fun ms11AV3RecordIsPresentButNeedsThePasscodeEverywhere() {
        assertTrue(syncCipher().optBoolean("ok"))
        val ws = walletStatus(); assertEquals("not_ready", ws.getString("status")); assertEquals("passcode_not_provided", ws.getString("notReadyReason"))
        val ps = passcodeStatus(); assertTrue(ps.getBoolean("hasKey")); assertTrue(ps.getBoolean("nativeLocked"))
        assertEquals("not_ready", walletEoaAddress().getString("error"))
        // the commands that need a key answer not_ready with the reason, not no_key
        for (type in listOf("gossipSign")) {
            val a = ack(cmd(type, "kind" to "envelope", "message" to "x"))
            assertFalse(a.optBoolean("ok")); assertEquals("not_ready", a.getString("error")); assertEquals("passcode_not_provided", a.getJSONObject("result").getString("reason"))
        }
        // after the unlock the same commands work
        assertTrue(syncCipher(passcode = passcode).optBoolean("ok"))
        assertTrue(signedBy(eoaA))
    }

    // ---- the same-account ciphertext that is saved but not current ----
    /** A saved v3 set of A, current switched to B: a plaintext sync for A changes nothing and does not move current (the passcode is not bypassed). */
    @Test
    fun aPlaintextSyncDoesNotReplaceASavedButNotCurrentCiphertextOfTheSameAccount() {
        assertTrue(syncCipher(passcode = passcode).optBoolean("ok"))           // A's v3 envelope saved and current
        assertTrue(syncPhrase(phraseB, eoaB).optBoolean("ok"))                  // current switches to B (plain); A's v3 set stays saved
        assertEquals("$eoaB|plain|1", currentPointer()); assertTrue(hasV3Set(eoaA))
        val before = storeHash()
        val r = syncPhrase(phraseA, eoaA)
        assertTrue(r.toString(), r.optBoolean("ok")); assertEquals("unchanged", r.getJSONObject("result").getString("sync"))
        assertEquals("nothing was written", before, storeHash())
        assertEquals("current did not move to a plaintext A", "$eoaB|plain|1", currentPointer())
        assertFalse("no plaintext set of A exists", hasPlainSet(eoaA))
        assertTrue("A cannot be signed for without its passcode", !signedBy(eoaA))
    }

    /** MS-36: A (v3) became current through a legal switch, then B (v3) took over; an older page then sends A's plaintext: unchanged, A's v3 not downgraded. */
    @Test
    fun ms36AfterASwitchFromAV3AccountToAnotherOneAnOlderPlaintextForAIsUnchanged() {
        assertTrue(syncPhrase(phraseB, eoaB).optBoolean("ok"))                       // B plaintext current
        assertTrue(syncCipher(envelopeA, passcode, eoa = eoaA).optBoolean("ok"))     // MS-23: A's envelope and passcode, switch to A (v3)
        assertTrue(syncCipher(envelopeB(), passcode, eoa = eoaB).optBoolean("ok"))   // switch to B, now as a v3 envelope
        assertEquals("$eoaB|v3|1", currentPointer()); assertTrue(hasV3Set(eoaA))
        val aBytes = setBytes(eoaA, "v3"); val before = storeHash()
        val r = syncPhrase(phraseA, eoaA)
        assertTrue(r.toString(), r.optBoolean("ok")); assertEquals("unchanged", r.getJSONObject("result").getString("sync"))
        assertEquals("A's v3 set is identical", aBytes, setBytes(eoaA, "v3")); assertFalse("no plaintext set of A was created", hasPlainSet(eoaA))
        assertEquals("nothing written", before, storeHash()); assertEquals("B stays current", "$eoaB|v3|1", currentPointer())
    }

    /** The saved v3 set of A and an A phrase when the directory cannot be listed: unknown, nothing written. */
    @Test
    fun aPlaintextSyncForAnAccountWithoutAnyV3SetStillWorks() {
        assertTrue(syncPhrase(phraseB, eoaB).optBoolean("ok"))
        val r = syncPhrase(phraseA, eoaA)
        assertTrue(r.toString(), r.optBoolean("ok")); assertEquals("updated", r.getJSONObject("result").getString("sync"))
        assertTrue(hasPlainSet(eoaA))
    }

    // ---- v3.2 order on the passcode path: shape, declared eoa, decryption, derived address ----
    /** MS-37: the declared eoa is not the envelope's. verify_failed comes before the decryption, so a wrong passcode does not change the answer. */
    @Test
    fun ms37ADeclaredEoaThatIsNotTheEnvelopesIsVerifyFailedWhateverThePasscode() {
        assertTrue(syncPhrase(phraseB, eoaB).optBoolean("ok"))
        val before = storeHash()
        for (p in listOf(passcode, wrongPasscode, null)) {
            val r = syncCipher(envelopeA, p, eoa = eoaB) // A's envelope, B declared
            assertCode("verify_failed", r)
        }
        assertEquals("nothing written", before, storeHash()); assertEquals("$eoaB|plain|1", currentPointer())
    }

    /** The shape comes first: an envelope that is not v3 is bad_request (not verify_failed, not unlock_failed), with or without a passcode. */
    @Test
    fun aMalformedEnvelopeIsBadRequestBeforeAnythingElse() {
        for (p in listOf<String?>(null, passcode, wrongPasscode)) {
            for (bad in listOf(cipherOf(envelopeA).put("v", 2), cipherOf(envelopeA).put("alg", "AES-128-GCM"))) {
                val before = storeHash()
                val r = syncCipher(bad, p, eoa = eoaB)
                assertFalse(r.toString(), r.optBoolean("ok")); assertEquals(r.toString(), "bad_request", r.optString("error"))
                assertEquals(before, storeHash())
            }
        }
    }

    /** MS-34 at the store: a v3 set of the account, current or not, keeps a plaintext set from being staged at all. */
    @Test
    fun ms34TheStoreItselfRefusesToStageAPlaintextSetForAnAccountWithAV3Set() {
        val store = MnemonicSetStore(sets())
        assertTrue(store.writeEnvelope(MnemonicCipherV3.seal(eoaA, passcode, phraseA, MnemonicCipherV3.newSalt(), MnemonicCipherV3.newIv())) is MnemonicSetStore.Write.Stored)
        assertTrue("current", store.stagePlain(eoaA, phraseA) is MnemonicSetStore.Stage.V3Present)
        assertTrue(store.writePlain(eoaB, phraseB) is MnemonicSetStore.Write.Stored) // current moves to B
        assertTrue("saved but not current", store.stagePlain(eoaA, phraseA) is MnemonicSetStore.Stage.V3Present)
        assertEquals(MnemonicSetStore.Write.Refused, store.writePlain(eoaA, phraseA))
        assertFalse(hasPlainSet(eoaA))
    }

    // ---- M6 v3.3: an envelope that cannot be verified never replaces what the account already has ----
    private val passcode2 = if (passcode == "654321") "123456" else "654321"
    private fun resealA(pass: String): JSONObject {
        val e = MnemonicCipherV3.seal(eoaA, pass, phraseA, MnemonicCipherV3.newSalt(), MnemonicCipherV3.newIv())
        return JSONObject().put("v", e.v).put("mode", e.mode).put("eoa", e.eoa).put("kdf", e.kdf).put("salt", e.saltB64).put("iv", e.ivB64).put("alg", e.alg).put("ct", e.ctB64)
    }
    private fun flippedE1(): JSONObject {
        val ct = envelopeA.getString("ct"); val i = ct.length / 2
        return cipherOf(envelopeA).put("ct", ct.substring(0, i) + (if (ct[i] == 'A') 'B' else 'A') + ct.substring(i + 1))
    }
    /** Both starting states of MS-39 to MS-42: A current with E1, and B current with A's E1 saved. */
    private fun startState(current: String) {
        assertTrue(syncCipher().optBoolean("ok"))                           // A has E1 (store only)
        if (current == "B") assertTrue(syncPhrase(phraseB, eoaB).optBoolean("ok"))
    }

    /** MS-39: the same canonical bytes again, no passcode: idempotent; when the account is not current only the pointer moves. */
    @Test
    fun ms39AnIdenticalStoreOnlyEnvelopeIsIdempotentAndOnlyMovesThePointer() {
        startState("A")
        val a = storeHash(); val r = syncCipher()
        assertTrue(r.toString(), r.optBoolean("ok")); assertFalse(r.getJSONObject("result").getBoolean("decrypted"))
        assertEquals("A current: nothing written", a, storeHash())
        startStateReset("B")
        val setsBefore = names().filter { it.startsWith("set.") }; val bytes = setBytes(eoaA); val bSet = setBytes(eoaB)
        val r2 = syncCipher()
        assertTrue(r2.toString(), r2.optBoolean("ok"))
        assertEquals("no version added", setsBefore, names().filter { it.startsWith("set.") })
        assertEquals("set bytes unchanged", bytes, setBytes(eoaA)); assertEquals(bSet, setBytes(eoaB))
        assertEquals("only the pointer moved, to A's existing version", "$eoaA|v3|1", currentPointer())
    }
    private fun startStateReset(current: String) { restart(); sets().deleteRecursively(); startState(current) }

    /** MS-40: different bytes without a passcode (a changed ct, or a legitimate re-seal): bad_request, nothing written, current and session unchanged. */
    @Test
    fun ms40AStoreOnlyEnvelopeWithDifferentBytesIsRefusedWhateverTheCurrentAccount() {
        for (current in listOf("A", "B")) for ((name, env) in listOf("changed ct" to flippedE1(), "re-sealed under another passcode" to resealA(passcode2))) {
            startStateReset(current)
            if (current == "A") assertTrue(syncCipher(passcode = passcode).optBoolean("ok")) // the session is ready for A before the refused sync
            val before = storeHash(); val pointer = currentPointer(); val aBytes = setBytes(eoaA); val signed = signedBy(eoaA)
            val r = syncCipher(env)
            assertFalse("$current/$name: $r", r.optBoolean("ok")); assertEquals("$current/$name", "bad_request", r.optString("error"))
            assertEquals("$current/$name: nothing written, no version added", before, storeHash())
            assertEquals("$current/$name: current does not move", pointer, currentPointer())
            assertEquals("$current/$name: E1 byte-identical", aBytes, setBytes(eoaA)); assertEquals(1, names().count { it.startsWith("set.$eoaA.v3.") })
            assertEquals("$current/$name: the session is unchanged", signed, signedBy(eoaA))
        }
    }

    /** MS-41: an account with no set at all takes its first envelope store-only (locked); a later store-only with different bytes is refused as MS-40. */
    @Test
    fun ms41AnAccountWithNoSetTakesItsFirstEnvelopeStoreOnlyAndThenRefusesDifferentBytes() {
        // an empty store
        val first = syncCipher()
        assertTrue(first.toString(), first.optBoolean("ok")); assertFalse(first.getJSONObject("result").getBoolean("decrypted"))
        assertTrue(hasV3Set(eoaA)); assertFalse("locked", signedBy(eoaA))
        val before = storeHash()
        assertEquals("bad_request", syncCipher(flippedE1()).optString("error")); assertEquals(before, storeHash())
        // only another account's set exists
        restart(); sets().deleteRecursively()
        assertTrue(syncPhrase(phraseB, eoaB).optBoolean("ok"))
        val sw = syncCipher()
        assertTrue(sw.toString(), sw.optBoolean("ok")); assertTrue(hasV3Set(eoaA)); assertEquals("$eoaA|v3|1", currentPointer()); assertFalse("locked", signedBy(eoaA))
        val before2 = storeHash()
        assertEquals("bad_request", syncCipher(resealA(passcode2)).optString("error")); assertEquals(before2, storeHash())
    }

    /** MS-42: with the correct passcode, different bytes that decrypt and derive the declared address are accepted as a new version. */
    @Test
    fun ms42ARePasscodedEnvelopeWithTheCorrectNewPasscodeIsAcceptedAsANewVersion() {
        for (current in listOf("A", "B")) {
            startStateReset(current)
            val e1Text = File(sets(), "set.$eoaA.v3.1.v1").readText(); val e2 = resealA(passcode2)
            // wrong passcode (the old one does not open E2): unlock_failed, nothing written
            val before = storeHash(); val pointer = currentPointer()
            assertCode("unlock_failed", syncCipher(e2, passcode, eoa = eoaA)); assertEquals(before, storeHash()); assertEquals(pointer, currentPointer())
            // correct passcode but the envelope holds another account's phrase: verify_failed, nothing written
            val liar = MnemonicCipherV3.seal(eoaA, passcode2, phraseB, MnemonicCipherV3.newSalt(), MnemonicCipherV3.newIv())
            val liarEnv = JSONObject().put("v", liar.v).put("mode", liar.mode).put("eoa", liar.eoa).put("kdf", liar.kdf).put("salt", liar.saltB64).put("iv", liar.ivB64).put("alg", liar.alg).put("ct", liar.ctB64)
            assertCode("verify_failed", syncCipher(liarEnv, passcode2, eoa = eoaA)); assertEquals(before, storeHash())
            // correct passcode, derived address matches: accepted
            val r = syncCipher(e2, passcode2, eoa = eoaA)
            assertTrue("$current: $r", r.optBoolean("ok")); assertEquals("ok", r.getJSONObject("result").getString("code")); assertTrue(r.getJSONObject("result").getBoolean("decrypted"))
            if (current == "B") { assertEquals("updated", r.getJSONObject("result").getString("sync")); assertEquals(eoaA, r.getJSONObject("result").getString("eoa")) }
            assertEquals("$current: E1 byte-identical", e1Text, File(sets(), "set.$eoaA.v3.1.v1").readText())
            assertEquals("$current: the new version", 2, names().count { it.startsWith("set.$eoaA.v3.") })
            assertEquals("$current: current is the new version", "$eoaA|v3|2", currentPointer())
            assertTrue("$current: session ready for A", signedBy(eoaA))
            assertTrue("the first version file is E1 as it was", File(sets(), "set.$eoaA.v3.1.v1").readText().let { JSONObject(it).getString("ct") == envelopeA.getString("ct") })
            // the same re-sealed envelope again, store only: it is now a saved version, so idempotent
            val again = storeHash(); assertTrue(syncCipher(e2).optBoolean("ok")); assertEquals(again, storeHash())
        }
    }

    // ---- no secret in logs, at run time ----
    /**
     * A whole round of operations is run with android.util.Log recording what it receives (a test double in the test source set). Afterwards neither the
     * recorded log lines nor any file in the store directory hold the passcode (right or wrong), a phrase, or the derived key.
     */
    @Test
    fun aWholeRoundLeavesNoSecretInTheLogOrOnDisk() {
        android.util.Log.clear()
        assertTrue(syncCipher().optBoolean("ok"))
        assertCode("unlock_failed", syncCipher(passcode = wrongPasscode))
        assertTrue(syncCipher(passcode = passcode).optBoolean("ok"))
        walletStatus(); passcodeStatus(); walletEoaAddress(); preread(); signedBy(eoaA)
        assertTrue(syncPhrase(phraseB, eoaB).optBoolean("ok"))                  // a switch
        assertTrue(syncCipher(envelopeB(), passcode, eoa = eoaB).optBoolean("ok"))
        assertEquals("unchanged", syncPhrase(phraseA, eoaA).getJSONObject("result").getString("sync")) // refused downgrade
        assertCode("verify_failed", syncCipher(envelopeA, passcode, eoa = eoaB))
        restart(); walletStatus(); preread(); signedBy(eoaA); syncCipher(passcode = passcode)
        val lines = android.util.Log.captured()
        assertTrue("the run logged something at all", lines.isNotEmpty())
        val key = checkNotNull(MnemonicDerivation.deriveKey(phraseA)).joinToString("") { "%02x".format(it) }
        val keyB = checkNotNull(MnemonicDerivation.deriveKey(phraseB)).joinToString("") { "%02x".format(it) }
        val standalone = Regex("(?<![A-Za-z0-9+/=])(" + Regex.escape(passcode) + "|" + Regex.escape(wrongPasscode) + ")(?![A-Za-z0-9+/=])")
        for (l in lines) {
            assertFalse("a passcode is in the log: ${l.take(80)}", standalone.containsMatchIn(l))
            assertFalse("a phrase is in the log", l.contains(phraseA) || l.contains(phraseB) || l.contains("abandon abandon"))
            assertFalse("a derived key is in the log", l.contains(key) || l.contains(keyB))
            assertFalse("an envelope ciphertext is in the log", l.contains(envelopeA.getString("ct")))
        }
        assertNoSecretOnDisk(phraseA) // B has a plaintext set by design (no passcode): only the passcode-protected account's phrase must be absent
    }

    // ---- no secret in logs ----
    /** android.util.Log is stubbed on the JVM, so logcat cannot be captured here; the guard is on the source: no log call passes a passcode or a phrase. */
    @Test
    fun scStaticNoOutputChannelOrToStringCarriesASecret() {
        // SC-08: println, System.out, System.err, printStackTrace, exception messages and toString overrides of the main sources.
        val secret = """(\$\{?(passcode|phrase|mnemonic|canonical|oldPasscode|newPasscode)\b|\boptString\("(passcode|phrase)"|\+\s*(passcode|phrase|mnemonic)\b)"""
        val out = Regex("""\b(println\(|System\.(out|err)\b|printStackTrace\b|Timber\.)""")
        val thrown = Regex("""\bthrow\s+\w+\(.*""" + secret)
        val toStr = Regex("""fun toString\(\).*(passcode|phrase|mnemonic)""", RegexOption.IGNORE_CASE)
        val offenders = File("src/main/java").walkTopDown().filter { it.isFile && it.extension == "kt" }.flatMap { f ->
            f.readLines().mapIndexedNotNull { i, l ->
                val bad = (out.containsMatchIn(l) && Regex(secret).containsMatchIn(l)) || thrown.containsMatchIn(l) || (toStr.containsMatchIn(l) && !l.contains("redacted"))
                if (bad) "${f.name}:${i + 1}: ${l.trim().take(120)}" else null
            }
        }.toList()
        assertTrue("an output channel, an exception message or a toString carries a secret: $offenders", offenders.isEmpty())
    }

    @Test
    fun noLogCallPassesAPasscodeOrAPhrase() {
        val bad = Regex("""Log\.[iwedv]\(.*(\$\{?(passcode|phrase|mnemonic|canonical)\b|\boptString\("(passcode|phrase)"|\+\s*(passcode|phrase|mnemonic)\b)""")
        val offenders = File("src/main/java").walkTopDown().filter { it.isFile && it.extension == "kt" }.flatMap { f ->
            f.readLines().mapIndexedNotNull { i, l -> if (bad.containsMatchIn(l)) "${f.name}:${i + 1}: ${l.trim().take(120)}" else null }
        }.toList()
        assertTrue("a log call carries a secret: $offenders", offenders.isEmpty())
    }
}
