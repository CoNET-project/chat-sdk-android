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
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * `walletStatus`, `passcodeStatus` and `walletEoaAddress` follow the two-state store (store-primary rule, 2026-11-22), and `pwaWalletSync` writes nothing
 * when the current set cannot be read (42(3)). Everything runs through the real entries ([BeamioConetChatModule.handleCommand] and
 * [BeamioShellRecordImport.answerFromPage]) on real store files in the context's `noBackupFilesDir`. The account is made by the product flow
 * (`pwaWalletSync` from the page), the vault stays empty, and nothing is seeded behind the entry. The two synthetic accounts come from the shared
 * vectors (the v3 envelope of the shared vector file, and its passcode) and from the public test phrase of the all-"abandon" account.
 */
class StoreStatusCommandsTest {
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
    private var reqId = 200
    private var seq = 9000L

    private class TestContext(private val dir: File) : ContextWrapper(null) {
        override fun getApplicationContext(): Context = this
        override fun getFilesDir(): File = dir
        override fun getCacheDir(): File = dir
        override fun getNoBackupFilesDir(): File = dir
    }

    @Before
    fun setUp() {
        dir = kotlin.io.path.createTempDirectory("store-status").toFile()
        context = TestContext(dir)
        MainPoster.runner = { it.run() }
        BeamioConetChatModule::class.java.getDeclaredField("appContext").apply { isAccessible = true }.set(BeamioConetChatModule, context)
        MnemonicPreread.resetForTests()
        NativeSessionState.reset()
        val vault = NativeWalletVault(NativeTestWrap(), AndroidVaultFiles(File(dir, "native_vault_v1").also { it.mkdirs() }))
        NativeWallet.installVaultForTest(vault)
        vault.state()
        // As at a normal start: the legacy adoption gate is settled and the shell has reported that no legacy store exists.
        NativeWallet.migrateLegacy(context)
        for (i in 0 until 100) {
            if (NativeWallet.isLegacyWalletAdoptionSettled() && !NativeWallet.isLegacyWalletAdoptionInFlight()) break
            Thread.sleep(50)
        }
        check(NativeWallet.isLegacyWalletAdoptionSettled())
        check(LegacyStoreReport.reportLegacyStore(context, LegacyStoreReport.ABSENT) == "ok")
    }

    @After
    fun tearDown() {
        MainPoster.runner = null
        NativeSessionState.reset()
        NativeWallet.installVaultForTest(null)
        MnemonicPreread.resetForTests()
    }

    private fun ack(body: JSONObject): JSONObject {
        val out = mutableListOf<JSONObject>()
        BeamioConetChatModule.handleCommand(context, body) { out.add(it) }
        return out.mapNotNull { it.optJSONObject("event") }.lastOrNull { it.optString("type") == "ack" } ?: error("no ack: $out")
    }

    private fun cmd(type: String, vararg kv: Pair<String, Any?>) = JSONObject().put("type", type).put("reqId", reqId++).also { b -> kv.forEach { b.put(it.first, it.second) } }
    private fun sync(vararg kv: Pair<String, Any?>) = ack(cmd("pwaWalletSync", *kv, "trustedOrigin" to true, "seq" to seq++))
    private fun syncPhrase(phrase: String, eoa: String) = sync("phrase" to phrase, "eoa" to eoa)
    private fun syncCipher(passcode: String? = null): JSONObject {
        val body = arrayListOf<Pair<String, Any?>>("cipher" to JSONObject(envelopeA.toString()))
        if (passcode != null) body.add("passcode" to passcode)
        return sync(*body.toTypedArray())
    }

    private fun walletStatus() = ack(cmd("walletStatus")).also { assertTrue(it.toString(), it.optBoolean("ok")) }.getJSONObject("result")
    private fun passcodeStatus() = ack(cmd("passcodeStatus", "eoa" to eoaA)).also { assertTrue(it.toString(), it.optBoolean("ok")) }.getJSONObject("result")
    private fun walletEoaAddress(): JSONObject = BeamioShellRecordImport.answerFromPage(
        context, BeamioShellRecordImport.ALLOWED_ORIGIN, true, cmd("walletEoaAddress"), 64,
    )!!

    private fun breakCurrentSet(eoa: String, kind: String) {
        val f = File(File(dir, MnemonicSetStore.DIRECTORY), "set.$eoa.$kind.1.v1")
        assertTrue(f.delete()); assertTrue(f.mkdir())
    }

    private fun storeHash(): String {
        val d = File(dir, MnemonicSetStore.DIRECTORY)
        val md = MessageDigest.getInstance("SHA-256")
        d.walkTopDown().filter { it != d }.sortedBy { it.relativeTo(d).path }.forEach { f ->
            md.update(f.relativeTo(d).path.toByteArray()); md.update(if (f.isDirectory) byteArrayOf(0) else f.readBytes())
        }
        return md.digest().joinToString("") { "%02x".format(it) }
    }

    // ---- control ----
    /**
     * Nothing was synced and the vault is empty: no account and nothing unlocked. The legacy adoption gate is process-wide state that other tests in the
     * same JVM may re-kick while this runs, in which case the SDK answers its unknown form (not_ready; passcodeStatus walletState not_ready) instead of
     * the settled no_key. Both are "no account": neither is an account, a key or an address, and never unlocked.
     */
    @Test
    fun noStoreSetAndAnEmptyVaultAnswersNoAccountEverywhere() {
        val ws = walletStatus()
        assertTrue(ws.toString(), ws.getString("status") in setOf("no_key", "not_ready"))
        assertFalse(ws.toString(), ws.has("accountKey"))
        val ps = passcodeStatus()
        assertTrue(ps.toString(), !ps.getBoolean("hasKey") || ps.optString("walletState") == "not_ready")
        assertTrue(ps.getBoolean("nativeLocked"))
        val addr = walletEoaAddress()
        assertFalse(addr.toString(), addr.getBoolean("ok"))
        assertTrue(addr.toString(), addr.getString("error") in setOf("no_key", "not_ready"))
    }

    // ---- plain set (create / restore, store-only) ----
    @Test
    fun aPlainSetIsAnAccountThatNeedsNoPasscode() {
        assertTrue(syncPhrase(phraseA, eoaA).optBoolean("ok"))
        // before the session is initialised: has, not initialised
        val ws = walletStatus()
        assertEquals("not_ready", ws.getString("status")); assertEquals("g1_uninitialized", ws.getString("notReadyReason"))
        val ps = passcodeStatus()
        assertTrue(ps.getBoolean("hasKey")); assertTrue("nativeLocked is a boolean", ps.get("nativeLocked") is Boolean)
        assertFalse(ps.getBoolean("set")); assertFalse(ps.getBoolean("locked"))
        val addr = walletEoaAddress()
        assertTrue(addr.toString(), addr.getBoolean("ok")); assertEquals(eoaA, addr.getJSONObject("result").getString("eoa"))
        // once the session is ready for it: unlocked with its account key, and nativeLocked false
        NativeSessionState.markReady(eoaA)
        val ws2 = walletStatus()
        assertEquals("unlocked", ws2.getString("status")); assertEquals("$eoaA:default", ws2.getString("accountKey"))
        assertFalse(passcodeStatus().getBoolean("nativeLocked"))
    }

    @Test
    fun aRestoredAccountIsTheOneTheStatusNames() {
        assertTrue(syncPhrase(phraseA, eoaA).optBoolean("ok"))
        assertTrue(syncPhrase(phraseB, eoaB).optBoolean("ok"))
        assertEquals(eoaB, walletEoaAddress().getJSONObject("result").getString("eoa"))
        NativeSessionState.markReady(eoaB)
        assertEquals("$eoaB:default", walletStatus().getString("accountKey"))
    }

    // ---- v3 ciphertext ----
    @Test
    fun aV3SetIsAnAccountThatNeedsThePasscode() {
        assertTrue(syncCipher().optBoolean("ok"))
        val ws = walletStatus()
        assertEquals("not_ready", ws.getString("status")); assertEquals("passcode_not_provided", ws.getString("notReadyReason"))
        val ps = passcodeStatus()
        assertTrue("an account exists: hasKey", ps.getBoolean("hasKey")); assertTrue("not unlocked", ps.getBoolean("nativeLocked"))
        val addr = walletEoaAddress()
        assertFalse(addr.toString(), addr.getBoolean("ok")); assertEquals("not_ready", addr.getString("error"))
        assertFalse("no address is given before the passcode", addr.toString().contains(eoaA))
    }

    @Test
    fun aV3SetUnlockedInThisSessionIsUnlocked() {
        assertTrue(syncCipher(passcode).optBoolean("ok"))
        val ws = walletStatus()
        assertEquals("unlocked", ws.getString("status")); assertEquals("$eoaA:default", ws.getString("accountKey"))
        assertFalse(passcodeStatus().getBoolean("nativeLocked"))
        assertEquals(eoaA, walletEoaAddress().getJSONObject("result").getString("eoa"))
    }

    @Test
    fun aWrongPasscodeLeavesTheV3SetLockedAndUnchanged() {
        assertTrue(syncCipher().optBoolean("ok"))
        val before = storeHash()
        val wrong = syncCipher(wrongPasscode)
        assertTrue(wrong.toString(), wrong.optBoolean("ok")); assertEquals("unlock_failed", wrong.getJSONObject("result").getString("code"))
        assertEquals(before, storeHash())
        assertEquals("passcode_not_provided", walletStatus().getString("notReadyReason"))
        assertTrue(passcodeStatus().getBoolean("nativeLocked"))
    }

    @Test
    fun aSessionUnlockedForAnotherAccountDoesNotUnlockTheV3Set() {
        assertTrue(syncCipher().optBoolean("ok"))
        NativeSessionState.markReady(eoaB)
        assertEquals("passcode_not_provided", walletStatus().getString("notReadyReason"))
        assertTrue(passcodeStatus().getBoolean("nativeLocked"))
        assertEquals("not_ready", walletEoaAddress().getString("error"))
    }

    // ---- unreadable store: unknown, never no_key ----
    @Test
    fun anUnreadableStoreIsUnknownNotNoAccount() {
        assertTrue(syncPhrase(phraseA, eoaA).optBoolean("ok"))
        File(File(dir, MnemonicSetStore.DIRECTORY), "current.v1").writeText("not-a-pointer", Charsets.UTF_8)
        val ws = walletStatus()
        assertEquals("not_ready", ws.getString("status")); assertEquals("unreadable", ws.getString("notReadyReason"))
        val ps = passcodeStatus()
        assertTrue("unknown never reads as no account", ps.getBoolean("hasKey")); assertEquals("not_ready", ps.getString("walletState"))
        assertTrue(ps.getBoolean("nativeLocked"))
        assertEquals("not_ready", walletEoaAddress().getString("error"))
    }

    // ---- M4: pwaWalletSync writes nothing when the current set cannot be read ----
    @Test
    fun pwaWalletSyncWithAPhraseWritesNothingWhenTheCurrentSetCannotBeRead() {
        assertTrue(syncCipher().optBoolean("ok"))
        breakCurrentSet(eoaA, "v3")
        val before = storeHash()
        val ans = syncPhrase(phraseB, eoaB)
        assertFalse(ans.toString(), ans.optBoolean("ok")); assertEquals("write_failed", ans.getString("error"))
        assertEquals("internal_state", ans.optJSONObject("result")?.optString("reason") ?: ans.optString("reason"))
        assertEquals("nothing written, the pointer did not move", before, storeHash())
    }

    @Test
    fun pwaWalletSyncWithACipherWritesNothingAndDoesNotUnlockWhenTheCurrentSetCannotBeRead() {
        assertTrue(syncCipher().optBoolean("ok"))
        breakCurrentSet(eoaA, "v3")
        val before = storeHash()
        val ans = syncCipher(passcode)
        assertFalse(ans.toString(), ans.optBoolean("ok")); assertEquals("write_failed", ans.getString("error"))
        assertEquals(before, storeHash())
        assertFalse("the session was not unlocked by a refused sync", NativeSessionState.isReadyFor(eoaA))
    }

    @Test
    fun aReadableCurrentSetStillTakesTheSync() {
        assertTrue(syncPhrase(phraseA, eoaA).optBoolean("ok"))
        val ans = syncPhrase(phraseB, eoaB)
        assertTrue(ans.toString(), ans.optBoolean("ok"))
        assertEquals(eoaB, walletEoaAddress().getJSONObject("result").getString("eoa"))
    }
}
