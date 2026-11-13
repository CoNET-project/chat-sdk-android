package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test
import java.util.Base64

/**
 * The parameter bounds of a stored record are decided before the Argon2id step (spec r3af, §25.47.9). Each case runs the real
 * [RecoveryEngine] (path B, the account and password) with a stub KDF that counts its calls. An out-of-range record is
 * `record_invalid`, with no KDF call and no failure counted. The boundary values reach the KDF: m 8192 and 65536, t 10, p 4.
 * m 8191, m 65537, t 11, p 5 and v 18 are refused.
 */
class RecoveryKdfBoundsTest {
    private class CountingFailures : RecoveryFailureStore {
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

    /** A stored record (base64 of `{stored, img}`) with the given parameters. The ciphertext is a 32-byte placeholder. */
    private fun record(m: Int, t: Int, p: Int, v: Int = 19): String {
        val salt = Base64.getEncoder().encodeToString(ByteArray(16))
        val img = Base64.getEncoder().encodeToString(ByteArray(32))
        val json = """{"stored":{"algo":"argon2id","v":$v,"m":$m,"t":$t,"p":$p,"hash":"AAAA","salt":"$salt"},"img":"$img"}"""
        return Base64.getEncoder().encodeToString(json.toByteArray(Charsets.UTF_8))
    }

    /** Runs path B against [rec]; the registry returns the record for any name. Returns the outcome code. */
    private fun run(rec: String, failures: CountingFailures, kdfCalls: IntArray): String {
        val registry = object : RegistryReader {
            override fun byNameHash(indexHash: ByteArray): String? = rec
            override fun byAccountName(name: String): String? = rec
            override fun legacyByAccountName(name: String): String? = null
        }
        val vault = NativeWalletVault(NativeTestWrap(), NativeTestFiles())
        val kdf: (ByteArray, RecoveryRecord.Stored) -> ByteArray = { _, _ ->
            kdfCalls[0]++
            ByteArray(32)
        }
        val engine = RecoveryEngine(vault, registry, failures, RecoveryClock { 1_700_000_000_000L }, kdf)
        return engine.restoreWithAccountPassword("synthetic-account", "synthetic-password".toCharArray()).code
    }

    @Test
    fun outOfRangeParametersAreRefusedBeforeTheKdfAndNotCounted() {
        val cases = listOf(
            "m 8191" to record(8191, 1, 1),
            "m 65537" to record(65537, 1, 1),
            "t 11" to record(8192, 11, 1),
            "p 5" to record(8192, 1, 5),
            "p 0" to record(8192, 1, 0),
            "v 18" to record(8192, 1, 1, v = 18),
        )
        for ((name, rec) in cases) {
            val calls = IntArray(1)
            val failures = CountingFailures()
            assertEquals(name, "record_invalid", run(rec, failures, calls))
            assertEquals("$name: KDF calls", 0, calls[0])
            assertEquals("$name: failures counted", 0, failures.failures())
        }
    }

    @Test
    fun boundaryValuesAreAcceptedAndReachTheKdf() {
        val cases = listOf(
            "m 8192" to record(8192, 1, 1),
            "m 65536" to record(65536, 1, 1),
            "t 10" to record(8192, 10, 1),
            "p 4" to record(8192, 1, 4),
        )
        for ((name, rec) in cases) {
            val calls = IntArray(1)
            val code = run(rec, CountingFailures(), calls)
            // The placeholder key does not open the ciphertext, so the outcome is a wrong password, not a refusal of the record.
            assertNotEquals("$name: refused", "record_invalid", code)
            assertEquals("$name: KDF calls", 1, calls[0])
        }
    }
}
