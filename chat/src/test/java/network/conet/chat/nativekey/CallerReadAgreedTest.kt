package network.conet.chat.nativekey

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * The four production callers that read AddressPGP now use [AddressPgpChain.readAgreed] (review 5, item 2). These tests pin the consequence
 * for the restore decision: a single endpoint's absence (the other endpoint failing, or the two disagreeing) is unknown, never NoSource, so
 * the upgrade path cannot treat it as "nothing to restore".
 */
class CallerReadAgreedTest {
    private val acceptance = JSONObject(File("../spec/pgp-restore-acceptance-vectors.v1.json").readText(Charsets.UTF_8))
    private val account = acceptance.getJSONObject("syntheticAccount").getString("address").lowercase()
    private val rpcA = RegistryEndpoint("https://rpc1.conet.network", 12_000)
    private val rpcB = RegistryEndpoint("https://publicrpc.conet.network", 12_000)
    private val config = AddressPgpConfig("0x684b0ac760cEE9c9b85de36d69746420648Cf9e2", listOf(rpcA, rpcB))

    private fun word(v: Long): ByteArray = ByteArray(32).also { w ->
        for (i in 0 until 8) w[31 - i] = ((v shr (8 * i)) and 0xFF).toByte()
    }

    private fun string(s: String): ByteArray {
        val b = s.toByteArray(Charsets.UTF_8)
        return word(b.size.toLong()) + b + ByteArray((32 - b.size % 32) % 32)
    }

    private fun hex(b: ByteArray) = "0x" + b.joinToString("") { "%02x".format(it) }

    private fun absentRecord(): String {
        val a = string("")
        val p = string("")
        val c = string("")
        return hex(word(128) + word(128L + a.size) + word(128L + a.size + p.size) + word(0) + a + p + c)
    }

    private fun emptyBackup(): String = hex(word(32) + string(""))

    /** One endpoint answering absent at block 42, or failing. */
    private class Endpoint(val ok: Boolean, val record: String, val backup: String) : AddressPgpRead.Rpc {
        override fun call(method: String, params: JSONArray): Any? {
            if (!ok) error("down")
            return when (method) {
                "eth_blockNumber" -> "0x2a"
                "eth_getBlockByNumber" -> JSONObject().put("number", "0x2a").put("hash", "0x" + "ab".repeat(32))
                "eth_call" -> {
                    val data = params.getJSONObject(0).getString("data").substring(0, 10)
                    if (data == AddressPgpRead.selector(AddressPgpRead.SIG_PGP_KEYS)) record else backup
                }
                else -> error("unexpected $method")
            }
        }
    }

    private fun chain(a: Endpoint, b: Endpoint): PgpRestoreChain = AddressPgpChain.readAgreed(account, config) { ep ->
        if (ep.url == rpcA.url) a else b
    }

    private fun restore(chain: PgpRestoreChain): ChainBackupRestore.Result =
        ChainBackupRestore.restore(account, chain, { "0x" + "11".repeat(32) }, NativeMigrationCrypto())

    @Test
    fun bothEndpointsAbsentWithNoBackupIsNoSource() {
        val ok = Endpoint(true, absentRecord(), emptyBackup())
        assertTrue(restore(chain(ok, ok)) is ChainBackupRestore.Result.NoSource)
    }

    @Test
    fun oneEndpointAbsentAndTheOtherDownIsUnverifiedNotNoSource() {
        val result = restore(chain(Endpoint(true, absentRecord(), emptyBackup()), Endpoint(false, "", "")))
        assertTrue("unknown is not 'nothing to restore'", result is ChainBackupRestore.Result.Unverified)
    }

    @Test
    fun aDisagreementBetweenTheEndpointsIsUnverifiedNotNoSource() {
        val absent = Endpoint(true, absentRecord(), emptyBackup())
        val other = Endpoint(true, absentRecord(), hex(word(32) + string("x")))
        val result = restore(chain(absent, other))
        assertTrue(result is ChainBackupRestore.Result.Unverified)
        assertEquals(false, result is ChainBackupRestore.Result.NoSource)
    }
}
