package network.conet.chat.nativekey

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.security.MessageDigest

/**
 * `spec/rpc-state-vectors.v1.json` (draft r2.5.20 第 6 版, T-3; source: interface/protocol, sha f0d3b1b8…4ebd74eb): the RP cases of the two-endpoint
 * read, run through [AddressPgpChain.readAgreed] with a fake RPC per endpoint. Each endpoint answers at the block the case gives (or fails).
 * The LK cases are the local Locked rule and are not run here.
 */
class RpcStateVectorsTest {
    private val bytes = File("../spec/rpc-state-vectors.v1.json").readBytes()
    private val doc = JSONObject(String(bytes, Charsets.UTF_8))
    private val acceptance = JSONObject(File("../spec/pgp-restore-acceptance-vectors.v1.json").readText(Charsets.UTF_8))
    private val account = acceptance.getJSONObject("syntheticAccount").getString("address").lowercase()
    private val rpcA = RegistryEndpoint("https://rpc1.conet.network", 12_000)
    private val rpcB = RegistryEndpoint("https://publicrpc.conet.network", 12_000)
    private val config = AddressPgpConfig("0x684b0ac760cEE9c9b85de36d69746420648Cf9e2", listOf(rpcA, rpcB))

    private fun identityOf(name: String) = PgpIdentity(
        acceptance.getJSONObject("identities").getJSONObject(name).getString("fingerprint"),
        acceptance.getJSONObject("identities").getJSONObject(name).getString("subkeyKeyID"),
    )

    private fun armorOf(name: String): String = NativePgpKeyGen.publicArmorOf(
        acceptance.getJSONObject("syntheticKeys").getJSONObject(name).getString("privateArmor"),
    )!!

    private fun word(v: Long): ByteArray = ByteArray(32).also { w ->
        for (i in 0 until 8) w[31 - i] = ((v shr (8 * i)) and 0xFF).toByte()
    }

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

    /** One endpoint of a case. A timeout or error fails every call; otherwise it answers at [block] with the record of [e]. */
    private inner class CaseEndpoint(val n: Long, val e: JSONObject) : AddressPgpRead.Rpc {
        private val failing = e.getString("result") == "timeout" || e.getString("result") == "error"
        private val block = e.getInt("block").toLong()
        override fun call(method: String, params: JSONArray): Any? {
            if (failing) error("endpoint ${e.getString("result")}")
            return when (method) {
                "eth_chainId" -> "0x36ca6"
                "eth_blockNumber" -> "0x" + n.toString(16)
                "eth_getBlockByNumber" -> JSONObject().put("number", "0x" + block.toString(16)).put("hash", "0x" + "%064x".format(block))
                "eth_call" -> {
                    val data = params.getJSONObject(0).getString("data").substring(0, 10)
                    val record = if (e.getString("result") == "present") recordHex(if (e.getString("keyId") == "KEY-7F3A") armorOf("P3") else armorOf("P4")) else recordHex(null)
                    if (data == AddressPgpRead.selector(AddressPgpRead.SIG_PGP_KEYS)) record else backupHex("")
                }
                else -> error("unexpected $method")
            }
        }
    }

    private fun run(case: JSONObject): AddressPgpChain {
        val n = case.getJSONObject("request").getLong("N")
        val eps = case.getJSONObject("request").getJSONArray("eps")
        val a = eps.getJSONObject(0)
        val b = eps.getJSONObject(1)
        return AddressPgpChain.readAgreed(account, config) { ep ->
            if (ep.url == rpcA.url) CaseEndpoint(n, a) else CaseEndpoint(n, b)
        }
    }

    @Test
    fun theVectorFileIsTheInterfaceOwnersCopy() {
        assertEquals("f0d3b1b876403a72cbae2468b356d802f143a91f64bd24cad0f293d2306be3a4", MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) })
    }

    @Test
    fun everyRpCaseHasItsExpectedState() {
        val rp = (0 until doc.getJSONArray("cases").length()).map { doc.getJSONArray("cases").getJSONObject(it) }.filter { it.getString("id").startsWith("RP-") }
        assertEquals(8, rp.size)
        for (c in rp) {
            val id = c.getString("id")
            val chain = run(c)
            when (c.getJSONObject("expect").getString("state")) {
                "absent" -> {
                    assertTrue("$id readable", chain.chainReadable())
                    assertEquals("$id absent", null, chain.identity())
                    assertTrue("$id absence confirmed later than N-1", chain.confirmedAbsentAfter(c.getJSONObject("request").getLong("N") - 1))
                }
                "present" -> {
                    assertTrue("$id readable", chain.chainReadable())
                    assertTrue("$id present", chain.identity() != null)
                    assertEquals("$id the identity", identityOf("P3"), chain.identity())
                    assertFalse("$id not absence", chain.confirmedAbsentAfter(0L))
                }
                "unknown" -> {
                    assertFalse("$id is unknown: unreadable", chain.chainReadable())
                    assertFalse("$id is unknown: no absence", chain.confirmedAbsentAfter(0L))
                }
                else -> error("state of $id")
            }
        }
    }

    /** Review (B's block): an endpoint that answers another block than N is unknown, even when the values agree (RP-05, RP-08). */
    @Test
    fun aDifferentBlockOnEndpointBIsUnknownEvenWhenTheValuesAgree() {
        val chain = AddressPgpChain.readAgreed(account, config) { ep ->
            if (ep.url == rpcA.url) {
                CaseEndpoint(100L, JSONObject().put("result", "absent").put("block", 100))
            } else {
                // B answers block 101 but with the same hash as A: only the block-number check can refuse it.
                val base = CaseEndpoint(100L, JSONObject().put("result", "absent").put("block", 101))
                object : AddressPgpRead.Rpc by base {
                    override fun call(method: String, params: JSONArray): Any? =
                        if (method == "eth_getBlockByNumber") {
                            JSONObject().put("number", "0x65").put("hash", "0x" + "%064x".format(100L))
                        } else {
                            base.call(method, params)
                        }
                }
            }
        }
        assertFalse(chain.chainReadable())
        assertFalse(chain.confirmedAbsentAfter(41L))
    }

    @Test
    fun theSameBlockWithDifferentHashesIsUnknown() {
        val chain = AddressPgpChain.readAgreed(account, config) { ep ->
            val base = CaseEndpoint(100L, JSONObject().put("result", "absent").put("block", 100))
            object : AddressPgpRead.Rpc by base {
                override fun call(method: String, params: JSONArray): Any? =
                    if (method == "eth_getBlockByNumber" && ep.url == rpcB.url) {
                        JSONObject().put("number", "0x64").put("hash", "0x" + "11".repeat(32))
                    } else {
                        base.call(method, params)
                    }
            }
        }
        assertFalse(chain.chainReadable())
    }
}
