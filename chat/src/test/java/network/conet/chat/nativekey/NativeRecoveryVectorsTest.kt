package network.conet.chat.nativekey

import network.conet.chat.ConetChatCryptoUtil
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.io.IOException
import java.security.MessageDigest

/**
 * Spec §25.42 (r3u) and §25.47 (r3ab) against `spec/native-recovery-vectors.v1.json`, 38 cases: the r3u 24 unchanged, plus
 * R-14 to R-22 and B-12 to B-16. Each case runs the real [RecoveryEngine] with the vector's registry fixtures, device state
 * and clock. The results must match in order, and the final state must match. Synthetic data only: the phrase is the BIP-39
 * public test vector.
 */
class NativeRecoveryVectorsTest {
    private val raw = File(System.getenv("NATIVE_RECOVERY_VECTORS") ?: "../spec/native-recovery-vectors.v1.json").readBytes()
    private val doc = JSONObject(String(raw, Charsets.UTF_8))

    @Test
    fun vectorFileIsThePinnedBatch() {
        val sha = MessageDigest.getInstance("SHA-256").digest(raw).joinToString("") { "%02x".format(it) }
        assertEquals("817957b9bb63fd31de9bb82f739405260ca998752b3fe7afc660601604c12b80", sha)
    }

    @Test
    fun theThirtyEightCasesAllMatchTheSpec() {
        val cases = doc.getJSONArray("cases")
        assertEquals(38, cases.length())
        for (i in 0 until cases.length()) {
            runCase(cases.getJSONObject(i))
        }
    }

    private data class Got(val reqId: String, val code: String, val eoa: String?, val cooldownSec: Int?)

    private fun runCase(c: JSONObject) {
        val id = c.getString("id")
        val env = c.getJSONObject("env")
        val device = env.optJSONObject("device") ?: JSONObject()
        val rpcFails = env.optString("rpc") == "fail"

        val inner = NativeTestFiles()
        val files = FaultyFiles(inner, writeFail = device.optBoolean("writeFail"), readbackFail = device.optBoolean("readbackFail"))
        val vault = NativeWalletVault(NativeTestWrap(), files)
        if (device.optBoolean("hasKey")) {
            val key = MessageDigest.getInstance("SHA-256").digest("chat-local-test-private-key-v1".toByteArray(Charsets.UTF_8))
            val eoa = WalletAddress.fromPrivateKey(key)!!
            assertEquals(id, NativeWalletVault.Import.OK, vault.importKey(eoa, key))
        }
        // The fault wrapper only starts corrupting reads after a write, so pre-populating above is unaffected.
        val failures = MemoryFailureStore()
        val clock = FakeClock(1_700_000_000_000L)
        // A device that already has failures: the count is set at the clock's now, so a cooldown starts from this moment.
        if (device.has("failures")) failures.save(device.getInt("failures"), clock.now)
        val registry = FixtureRegistry(
            current = doc.getJSONObject("fixtures").getJSONObject("registry"),
            fail = rpcFails,
        )
        val engine = RecoveryEngine(vault, registry, failures, RecoveryClock { clock.now })

        val got = mutableListOf<Got>()
        val steps = c.getJSONArray("steps")
        for (s in 0 until steps.length()) {
            val step = steps.getJSONObject(s)
            when (step.getString("op")) {
                "elapse" -> clock.now += 3_600_000L
                "attempt" -> got += attempt(engine, step.getJSONObject("a"))
                else -> error("unknown op in $id")
            }
        }

        val expect = c.getJSONObject("expect")
        val results = expect.getJSONArray("results")
        assertEquals("$id results", results.length(), got.size)
        for (i in 0 until results.length()) {
            val e = results.getJSONObject(i)
            val g = got[i]
            assertEquals("$id[$i] type", "nativeRecoveryResult", e.getString("type"))
            assertEquals("$id[$i] reqId", e.getString("reqId"), g.reqId)
            assertEquals("$id[$i] code", e.getString("code"), g.code)
            if (e.has("eoa")) {
                assertEquals("$id[$i] eoa", e.getString("eoa"), g.eoa)
            } else if (g.code == "already_exists") {
                // 25.52X.4 (r3kg, coordinator ruling): already_exists carries the public lower-case eoa when derivation and storage succeed. This
                // vector predates r3kg and has no eoa field; the vector is re-pinned with the unified re-pin. The eoa is absent or a valid EOA.
                assertTrue("$id[$i] eoa is absent or the public lower-case EOA", g.eoa == null || Regex("^0x[0-9a-f]{40}$").matches(g.eoa))
            } else {
                assertNull("$id[$i] eoa", g.eoa)
            }
            if (e.has("cooldownSec")) {
                assertEquals("$id[$i] cooldownSec", e.getInt("cooldownSec"), g.cooldownSec)
            } else {
                assertNull("$id[$i] cooldownSec", g.cooldownSec)
            }
        }

        val state = expect.getJSONObject("state")
        assertEquals("$id hasKey", state.getBoolean("hasKey"), vault.state() !is NativeWalletVault.State.NoKey)
        assertEquals("$id failures", state.getInt("failures"), failures.failures())
        assertEquals(
            "$id cooldownActive",
            state.getBoolean("cooldownActive"),
            RecoveryBackoff.remainingSeconds(failures, clock.now) > 0,
        )
    }

    private fun attempt(engine: RecoveryEngine, a: JSONObject): Got {
        val reqId = a.getString("reqId")
        // The page was closed before any submission: no read, `cancelled`.
        if (a.optBoolean("cancel")) return Got(reqId, "cancelled", null, null)
        val outcome = when (a.getString("path")) {
            "A" -> engine.restoreWithCode(a.getString("code").toByteArray(Charsets.UTF_8))
            "B" -> engine.restoreWithAccountPassword(a.getString("name"), a.getString("password").toCharArray())
            else -> error("unknown path")
        }
        return Got(reqId, outcome.code, outcome.eoa, outcome.cooldownSec)
    }

    /** The vector's registry: `nameHash:0x…` keys by the keccak of the code, `name:…` keys by account name. */
    private class FixtureRegistry(
        private val current: JSONObject,
        private val fail: Boolean,
    ) : RecoveryRegistryReader {
        override fun byNameHash(indexHash: ByteArray): String? {
            if (fail) error("rpc unavailable")
            val k = "nameHash:0x" + indexHash.joinToString("") { "%02x".format(it) }
            return if (current.has(k)) current.getString(k) else null
        }

        override fun byAccountName(name: String): String? {
            if (fail) error("rpc unavailable")
            val k = "name:$name"
            return if (current.has(k)) current.getString(k) else null
        }
    }

    private class FakeClock(var now: Long)

    private class MemoryFailureStore : RecoveryFailureStore {
        private var count = 0
        private var at = 0L
        override fun failures(): Int = count
        override fun lastFailureAtMs(): Long = at
        override fun save(failures: Int, atMs: Long) {
            count = failures
            at = atMs
        }
        override fun clear() {
            count = 0
            at = 0L
        }
    }

    /**
     * Device faults: a refused write, or a readback that does not match what was written. Reads before any write are
     * unchanged, so pre-populating a key is not affected.
     */
    private class FaultyFiles(
        private val inner: NativeTestFiles,
        private val writeFail: Boolean,
        private val readbackFail: Boolean,
    ) : VaultFiles {
        private var wrote = false

        override fun read(name: String): ByteArray? {
            val b = inner.read(name) ?: return null
            if (!readbackFail || !wrote) return b
            val corrupt = b.copyOf()
            corrupt[corrupt.size - 1] = (corrupt[corrupt.size - 1].toInt() xor 1).toByte()
            return corrupt
        }

        override fun write(name: String, bytes: ByteArray) {
            if (writeFail) throw IOException("write refused")
            inner.write(name, bytes)
            wrote = true
        }

        override fun delete(name: String) = inner.delete(name)
    }

    /** Keeps the import of the test key and the hash helpers in use. */
    @Suppress("unused")
    private fun indexOf(code: String): String =
        "0x" + ConetChatCryptoUtil.keccak256(code.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }

    @Test
    fun theRecordFixturesAreKeyedByTheCodesKeccak() {
        // Sanity check of the harness: every nameHash key is the keccak256 of a code in the cases.
        val fixtures = doc.getJSONObject("fixtures").getJSONObject("registry")
        val keys = fixtures.keys().asSequence().map { it.toString() }.filter { it.startsWith("nameHash:") }.toList()
        assertTrue(keys.isNotEmpty())
        val codes = doc.getJSONArray("cases").let { arr ->
            (0 until arr.length()).flatMap { i ->
                val steps = arr.getJSONObject(i).getJSONArray("steps")
                (0 until steps.length()).mapNotNull { s ->
                    steps.getJSONObject(s).optJSONObject("a")?.optString("code")?.takeIf { it.isNotEmpty() }
                }
            }
        }
        for (k in keys) {
            assertTrue("no code for $k", codes.any { indexOf(it.trim()) == k.removePrefix("nameHash:") })
        }
    }
}
