package network.conet.chat.nativekey

import android.content.Context
import android.content.ContextWrapper
import java.io.File
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
 * A store-only account signs through the real command entry ([BeamioConetChatModule.handleCommand]). The account is made by the product flow:
 * `pwaWalletSync` (the page creates or restores the account and syncs its phrase or its ciphertext), which writes the two-state store and not the
 * vault. The vault stays empty (NoKey). The store is the real [MnemonicSetStore] on real files in the context's `noBackupFilesDir`, and nothing is
 * seeded behind the entry: the store is written only by the command under test. Then `gossipSign` is sent.
 *
 * The rule (store-primary rule, 2026-11-22): the store answers for the account it names, whatever the vault holds. A plain set signs. A v3 set
 * signs only while the session is unlocked for its account (the passcode accepted in this process). A set that cannot be read is unknown: the
 * command is retryable (not_ready), never no_key and never a signature. Without any store set, the vault decides, and an empty vault is no_key.
 */
class StoreOnlyAccountSignsTest {
    private val phraseA = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    private val phraseB = "fog spot notable regret pizza coffee harvest ensure fog spot notable reflect"
    private val eoaA: String = eoaOf(phraseA)
    private val eoaB: String = eoaOf(phraseB)
    private val passcode = "482913"
    private val message = "synthetic signing text"
    private lateinit var context: Context
    private lateinit var dir: File
    private var reqId = 100
    private var seq = 1000L

    private fun eoaOf(phrase: String): String =
        checkNotNull(WalletAddress.fromPrivateKey(checkNotNull(MnemonicDerivation.deriveKey(phrase)))).lowercase()

    /** A context whose application context is itself and whose private and no-backup files live in a temporary directory. */
    private class TestContext(private val dir: File) : ContextWrapper(null) {
        override fun getApplicationContext(): Context = this
        override fun getFilesDir(): File = dir
        override fun getCacheDir(): File = dir
        override fun getNoBackupFilesDir(): File = dir
    }

    @Before
    fun setUp() {
        dir = kotlin.io.path.createTempDirectory("store-only-signs").toFile()
        context = TestContext(dir)
        MainPoster.runner = { it.run() }
        BeamioConetChatModule::class.java.getDeclaredField("appContext").apply { isAccessible = true }.set(BeamioConetChatModule, context)
        MnemonicPreread.resetForTests()
        NativeSessionState.reset()
        // The vault is empty: no key record at all (G0), published by one read as the gate reads it.
        val vault = NativeWalletVault(NativeTestWrap(), NativeTestFiles())
        NativeWallet.installVaultForTest(vault)
        vault.state()
    }

    @After
    fun tearDown() {
        MainPoster.runner = null
        NativeSessionState.reset()
        NativeWallet.installVaultForTest(null)
        MnemonicPreread.resetForTests()
    }

    private fun send(body: JSONObject): JSONObject {
        val out = mutableListOf<JSONObject>()
        BeamioConetChatModule.handleCommand(context, body) { out.add(it) }
        return out.mapNotNull { it.optJSONObject("event") }.lastOrNull { it.optString("type") == "ack" }
            ?: error("no ack for ${body.optString("type")}: $out")
    }

    private fun syncPhrase(phrase: String, eoa: String): JSONObject = send(
        JSONObject().put("type", "pwaWalletSync").put("reqId", reqId++).put("trustedOrigin", true).put("seq", seq++)
            .put("phrase", phrase).put("eoa", eoa),
    )

    private fun syncCipher(eoa: String, phrase: String, withPasscode: Boolean): JSONObject {
        val env = MnemonicCipherV3.seal(eoa, passcode, phrase, MnemonicCipherV3.newSalt(), MnemonicCipherV3.newIv())
        val cipher = JSONObject().put("v", env.v).put("mode", env.mode).put("eoa", env.eoa).put("kdf", env.kdf)
            .put("salt", env.saltB64).put("iv", env.ivB64).put("alg", env.alg).put("ct", env.ctB64)
        val body = JSONObject().put("type", "pwaWalletSync").put("reqId", reqId++).put("trustedOrigin", true).put("seq", seq++).put("cipher", cipher)
        if (withPasscode) body.put("passcode", passcode)
        return send(body)
    }

    private fun sign(): JSONObject = send(
        JSONObject().put("type", "gossipSign").put("reqId", reqId++).put("kind", "envelope").put("message", message),
    )

    private fun assertSigned(ack: JSONObject, eoa: String) {
        assertTrue("expected a signature, got $ack", ack.optBoolean("ok"))
        val result = ack.getJSONObject("result")
        assertEquals(eoa, result.getString("address").lowercase())
        assertTrue(result.getString("signature").matches(Regex("^0x[0-9a-fA-F]{130}$")))
    }

    private fun assertRefused(ack: JSONObject, error: String) {
        assertFalse("expected a refusal, got $ack", ack.optBoolean("ok"))
        assertEquals(error, ack.optString("error"))
        assertFalse("no signature may be returned on a refusal: $ack", ack.has("result") && ack.optJSONObject("result")?.has("signature") == true)
    }

    /** The control: nothing was synced, the vault is empty, the store is absent: no_key. Without it a state that did not take effect would pass. */
    @Test
    fun noStoreSetAndAnEmptyVaultIsNoKey() {
        // no_key once the legacy adoption gate is settled; not_ready while another test in the same JVM has it in flight. Either way nothing is signed.
        val ack = sign()
        assertFalse(ack.toString(), ack.optBoolean("ok"))
        assertTrue(ack.toString(), ack.optString("error") in setOf("no_key", "not_ready"))
        assertFalse(ack.has("result") && ack.optJSONObject("result")?.has("signature") == true)
    }

    /** Create: the page creates an account and syncs its phrase (store-only). The account signs with its own key. */
    @Test
    fun anAccountCreatedByTheProductFlowSignsFromTheStore() {
        val sync = syncPhrase(phraseA, eoaA)
        assertTrue("the sync must succeed, got $sync", sync.optBoolean("ok"))
        assertTrue("the store holds the set, not the vault", File(dir, MnemonicSetStore.DIRECTORY).list()?.any { it.startsWith("set.$eoaA.plain.") } == true)
        assertSigned(sign(), eoaA)
    }

    /** Restore: a second account is synced over the first (a restore). The store answers for the newest account (store-primary). */
    @Test
    fun aRestoredAccountSignsAndTheNewestAccountIsTheSigner() {
        assertTrue(syncPhrase(phraseA, eoaA).optBoolean("ok"))
        assertSigned(sign(), eoaA)
        assertTrue(syncPhrase(phraseB, eoaB).optBoolean("ok"))
        assertSigned(sign(), eoaB)
    }

    /** Counter-example: a ciphertext (v3) account whose passcode was not given is not unlocked: not_ready with the reason, never no_key, no signature. */
    @Test
    fun aV3AccountThatIsNotUnlockedIsRefused() {
        val sync = syncCipher(eoaA, phraseA, withPasscode = false)
        assertTrue("the envelope is stored, got $sync", sync.optBoolean("ok"))
        val ack = sign()
        assertRefused(ack, "not_ready")
        assertEquals("passcode_not_provided", ack.getJSONObject("result").getString("reason"))
    }

    /** Positive: the same ciphertext account, synced with the passcode (the session unlocks in memory), signs. */
    @Test
    fun aV3AccountUnlockedInThisSessionSigns() {
        val sync = syncCipher(eoaA, phraseA, withPasscode = true)
        assertTrue("the envelope is stored and opened, got $sync", sync.optBoolean("ok"))
        assertSigned(sign(), eoaA)
    }

    /** Counter-example: the session is unlocked for another account than the stored v3 set names: refused, no signature. */
    @Test
    fun aV3SetOfAnotherAccountThanTheUnlockedOneIsRefused() {
        assertTrue(syncCipher(eoaA, phraseA, withPasscode = false).optBoolean("ok"))
        NativeSessionState.markReady(eoaB)
        val ack = sign()
        assertRefused(ack, "not_ready")
    }

    /** Counter-example: the store cannot be read (the pointer is invalid): unknown, retryable (not_ready), never no_key and never a signature. */
    @Test
    fun anUnreadableStoreIsUnknownAndNotReady() {
        assertTrue(syncPhrase(phraseA, eoaA).optBoolean("ok"))
        File(File(dir, MnemonicSetStore.DIRECTORY), "current.v1").writeText("not-a-pointer", Charsets.UTF_8)
        assertRefused(sign(), "not_ready")
    }

    /** Counter-example: the pointer names a set file that is missing: unknown, not_ready. */
    @Test
    fun aMissingSetFileIsUnknownAndNotReady() {
        assertTrue(syncPhrase(phraseA, eoaA).optBoolean("ok"))
        File(File(dir, MnemonicSetStore.DIRECTORY).also { assertTrue(it.exists()) }, "set.$eoaA.plain.1.v1").delete()
        assertRefused(sign(), "not_ready")
    }
}
