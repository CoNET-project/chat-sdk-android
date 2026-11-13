package network.conet.chat.nativekey

import network.conet.chat.ConetChatCryptoUtil
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.math.BigInteger
import java.security.MessageDigest
import java.util.Base64

/**
 * Path A (spec 25.26.4e.3) on the JVM: the restore core against the synthetic record vectors, the registry read against a
 * fake RPC, and the outcome codes. Nothing here touches a network, a chain, or a real account. The test accounts are the
 * BIP-39 public vector and a key derived from a fixed synthetic string.
 */
class RecoveryRestoreTest {
    private val doc = JSONObject(
        String(File(System.getenv("RECOVERY_RECORD_VECTORS") ?: "../spec/recovery-record-vectors.v1.json").readBytes(), Charsets.UTF_8),
    )
    private val testEoa = "0x9858effd232b4033e47d90003d41ec34ecaeda94"

    /** The small-parameter case: the same layout, with a cheap Argon2 run. */
    private val case = doc.getJSONArray("cases").getJSONObject(1)
    private val code = case.getString("code").toByteArray(Charsets.UTF_8)
    private val record = case.getString("record")

    private fun emptyVault() = NativeWalletVault(NativeTestWrap(), NativeTestFiles())

    private fun indexOf(c: ByteArray): ByteArray = ConetChatCryptoUtil.keccak256(c)

    @Test
    fun theRecordRestoresTheTestAccountIntoAnEmptyVault() {
        val vault = emptyVault()
        var askedIndex: ByteArray? = null
        val out = RecoveryRestore.run(code.copyOf(), vault) { index ->
            askedIndex = index
            Result.success(record)
        }
        assertEquals("ok", out.code)
        assertEquals(testEoa, out.eoa)
        // The lookup is keyed by keccak256 of the code, the index createRecover registered.
        assertTrue(indexOf(code).contentEquals(askedIndex!!))
        val state = vault.state()
        assertTrue(state is NativeWalletVault.State.Ready && state.eoa == testEoa)
    }

    @Test
    fun aSecondRestoreIsAlreadyExistsAndKeepsTheStoredKey() {
        val vault = emptyVault()
        assertEquals("ok", RecoveryRestore.run(code.copyOf(), vault) { Result.success(record) }.code)
        val again = RecoveryRestore.run(code.copyOf(), vault) { Result.success(record) }
        assertEquals("already_exists", again.code)
        assertNullEoa(again)
        val state = vault.state()
        assertTrue(state is NativeWalletVault.State.Ready && state.eoa == testEoa)
    }

    @Test
    fun anExistingAccountIsNeverOverwritten() {
        val vault = emptyVault()
        val otherKey = MessageDigest.getInstance("SHA-256").digest("chat-local-test-private-key-v1".toByteArray(Charsets.UTF_8))
        val otherEoa = WalletAddress.fromPrivateKey(otherKey)!!
        assertEquals(NativeWalletVault.Import.OK, vault.importKey(otherEoa, otherKey))
        val out = RecoveryRestore.run(code.copyOf(), vault) { Result.success(record) }
        assertEquals("already_exists", out.code)
        val state = vault.state()
        assertTrue(state is NativeWalletVault.State.Ready && state.eoa == otherEoa)
    }

    @Test
    fun aMalformedCodeIsRejectedBeforeTheRegistryIsAsked() {
        var asked = false
        val out = RecoveryRestore.run("not a code".toByteArray(Charsets.UTF_8), emptyVault()) {
            asked = true
            Result.success(record)
        }
        assertEquals("invalid_format", out.code)
        assertFalse(asked)
    }

    @Test
    fun noRecordIsNotFound() {
        val out = RecoveryRestore.run(code.copyOf(), emptyVault()) { Result.success(null) }
        assertEquals("not_found", out.code)
    }

    @Test
    fun aRegistryFailureIsNetworkErrorNotNotFound() {
        val out = RecoveryRestore.run(code.copyOf(), emptyVault()) { Result.failure(IllegalStateException("timeout")) }
        assertEquals("network_error", out.code)
    }

    @Test
    fun aWrongCodeDoesNotDecryptAndWritesNothing() {
        val vault = emptyVault()
        val neg = doc.getJSONArray("negatives").getJSONObject(0)
        val wrong = neg.getString("code").toByteArray(Charsets.UTF_8)
        val out = RecoveryRestore.run(wrong, vault) { Result.success(record) }
        assertEquals("record_invalid", out.code)
        assertTrue(vault.state() is NativeWalletVault.State.NoKey)
    }

    @Test
    fun aRecordThatIsNotARecordIsRecordInvalid() {
        val notRecord = Base64.getEncoder().encodeToString("not a record".toByteArray(Charsets.UTF_8))
        val out = RecoveryRestore.run(code.copyOf(), emptyVault()) { Result.success(notRecord) }
        assertEquals("record_invalid", out.code)
    }

    private fun assertNullEoa(o: RecoveryOutcome) {
        assertEquals(null, o.eoa)
    }
}

/** The registry read (25.26.4e.3 step 3): one `eth_call` of `getBase64ByNameHash(bytes32)`, against a fake RPC. */
class AccountRegistryReadTest {
    private val cfg = AccountRegistryRead.Config(
        registry = "0xfFDc8d2021A41F4638Cb3eCf58B5155383EE9f6d",
        rpcUrl = "https://publicrpc.conet.network",
        chainId = 224422L,
    )
    private val index = ByteArray(32) { (it + 1).toByte() }

    private fun word(v: Long): ByteArray = ByteArray(32).also { w ->
        for (i in 0 until 8) w[31 - i] = ((v shr (8 * i)) and 0xFF).toByte()
    }

    private fun stringAnswer(s: String): String {
        val b = s.toByteArray(Charsets.UTF_8)
        val pad = (32 - b.size % 32) % 32
        val body = word(b.size.toLong()) + b + ByteArray(pad)
        return "0x" + (word(32) + body).joinToString("") { "%02x".format(it) }
    }

    private class Fake(private val answer: () -> Any?) : AddressPgpRead.Rpc {
        val calls = mutableListOf<Pair<String, JSONArray>>()
        override fun call(method: String, params: JSONArray): Any? {
            calls += method to params
            return answer()
        }
    }

    @Test
    fun theCallReadsTheRegistryAtLatestWithTheIndex() {
        val fake = Fake { stringAnswer("cipher") }
        val out = AccountRegistryRead.getBase64ByNameHash(fake, cfg, index).getOrThrow()
        assertEquals("cipher", out)
        val (method, params) = fake.calls.single()
        assertEquals("eth_call", method)
        assertEquals("latest", params.getString(1))
        val call = params.getJSONObject(0)
        assertEquals(cfg.registry, call.getString("to"))
        val data = call.getString("data")
        assertEquals(AddressPgpRead.selector(AccountRegistryRead.SIG), data.substring(0, 10))
        assertEquals(index.joinToString("") { "%02x".format(it) }, data.substring(10))
    }

    @Test
    fun anEmptyAnswerIsNoRecord() {
        val out = AccountRegistryRead.getBase64ByNameHash(Fake { stringAnswer("") }, cfg, index).getOrThrow()
        assertEquals(null, out)
    }

    @Test
    fun aTransportFailureIsNetworkError() {
        val r = AccountRegistryRead.getBase64ByNameHash(Fake { error("timeout") }, cfg, index)
        assertTrue(r.isFailure)
        assertEquals("network_error", r.exceptionOrNull()!!.message)
    }

    @Test
    fun aNonStringAnswerIsNetworkError() {
        val r = AccountRegistryRead.getBase64ByNameHash(Fake { JSONArray() }, cfg, index)
        assertTrue(r.isFailure)
        assertEquals("network_error", r.exceptionOrNull()!!.message)
    }

    @Test
    fun theDefaultConfigIsHttpsOnly() {
        // The shell cannot point the read at plain http: HttpRpc refuses it at construction.
        val bad = AccountRegistryRead.Config(cfg.registry, "http://rpc.example.invalid", cfg.chainId)
        val refused = try {
            AddressPgpRead.HttpRpc(bad.rpcUrl)
            false
        } catch (_: IllegalArgumentException) {
            true
        }
        assertTrue(refused)
    }
}
