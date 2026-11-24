package network.conet.chat.nativekey

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Draft r2.5.20 第 6 版 T-3: the two-endpoint read at one block, and the absence confirmation built on it (5B.7). The RPC is a fake per endpoint.
 */
class AddressPgpAgreedTest {
    private val acceptance = JSONObject(File("../spec/pgp-restore-acceptance-vectors.v1.json").readText(Charsets.UTF_8))
    private val account = acceptance.getJSONObject("syntheticAccount").getString("address").lowercase()
    private val password = JSONObject(File("../spec/pgp-backup-compat-vectors.v1.json").readText(Charsets.UTF_8))
        .getJSONArray("positives").getJSONObject(0).getString("passwordString")
    private val rpcA = RegistryEndpoint("https://rpc1.conet.network", 12_000)
    private val rpcB = RegistryEndpoint("https://publicrpc.conet.network", 12_000)
    private val config = AddressPgpConfig("0x684b0ac760cEE9c9b85de36d69746420648Cf9e2", listOf(rpcA, rpcB))

    private fun identityOf(name: String) = PgpIdentity(
        acceptance.getJSONObject("identities").getJSONObject(name).getString("fingerprint"),
        acceptance.getJSONObject("identities").getJSONObject(name).getString("subkeyKeyID"),
    )

    private fun publicArmorOf(name: String): String = NativePgpKeyGen.publicArmorOf(
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

    /** One endpoint: block number [block] and the answers for the record and the backup; a null answer is a failed call. */
    private class Endpoint(val block: String?, val record: String?, val backup: String?) : AddressPgpRead.Rpc {
        override fun call(method: String, params: JSONArray): Any? = when (method) {
            "eth_chainId" -> if (block == null) error("down") else "0x36ca6"
            "eth_blockNumber" -> block ?: error("down")
            "eth_getBlockByNumber" -> JSONObject().put("number", block ?: error("down")).put("hash", "0x" + "ab".repeat(32))
            "eth_call" -> {
                val data = params.getJSONObject(0).getString("data").substring(0, 10)
                if (data == AddressPgpRead.selector(AddressPgpRead.SIG_PGP_KEYS)) record ?: error("down") else backup ?: error("down")
            }
            else -> error("unexpected $method")
        }
    }

    private fun chainWith(a: Endpoint, b: Endpoint): AddressPgpChain = AddressPgpChain.readAgreed(account, config) { ep ->
        if (ep.url == rpcA.url) a else b
    }

    private val absentAt42 = Endpoint("0x2a", recordHex(null), backupHex(""))

    @Test
    fun bothEndpointsAbsentAtOneBlockConfirmAbsenceAfterAnEarlierWriteBlock() {
        val c = chainWith(absentAt42, Endpoint("0x2a", recordHex(null), backupHex("")))
        assertTrue(c.chainReadable())
        assertEquals(IdentityRead.Absent, c.identityRead())
        assertTrue("absent at 42 is later than writeBlock 41", c.confirmedAbsentAfter(41L))
        assertFalse("not later than the write block 42", c.confirmedAbsentAfter(42L))
    }

    @Test
    fun oneEndpointDownIsUnknownNotAbsence() {
        val c = chainWith(absentAt42, Endpoint(null, null, null))
        assertFalse(c.chainReadable())
        assertFalse("one endpoint is not confirmation", c.confirmedAbsentAfter(41L))
        assertTrue(c.identityRead() is IdentityRead.Unknown)
    }

    @Test
    fun aDisagreementIsUnknown() {
        val c = chainWith(absentAt42, Endpoint("0x2a", recordHex(publicArmorOf("P3")), backupHex("")))
        assertFalse(c.chainReadable())
        assertFalse(c.confirmedAbsentAfter(41L))
    }

    @Test
    fun aBackupDisagreementIsUnknown() {
        val c = chainWith(Endpoint("0x2a", recordHex(null), backupHex("")), Endpoint("0x2a", recordHex(null), backupHex("x")))
        assertFalse(c.chainReadable())
    }

    @Test
    fun aPresentIdentityOnBothEndpointsIsReadAndIsNotAbsence() {
        val present = Endpoint("0x2a", recordHex(publicArmorOf("P3")), backupHex(""))
        val c = chainWith(present, present)
        assertEquals(identityOf("P3"), c.identity())
        assertFalse(c.confirmedAbsentAfter(0L))
    }

    @Test
    fun fewerThanTwoEndpointsIsUnknown() {
        val single = AddressPgpConfig("0x684b0ac760cEE9c9b85de36d69746420648Cf9e2", listOf(rpcA))
        val c = AddressPgpChain.readAgreed(account, single) { absentAt42 }
        assertFalse(c.chainReadable())
    }

    /** Draft 5B.7 end to end: a Ready pending key and a marker; the two-endpoint absence after the write block allows the retry; before it, not. */
    @Test
    fun theMachineRetriesOnlyAfterTwoEndpointAbsenceLaterThanTheWriteBlock() {
        val files = NativeTestFiles()
        val dev = PgpRestoreDevice("A", account, NativeTestWrap(), files)
        val chain = chainWith(absentAt42, Endpoint("0x2a", recordHex(null), backupHex("")))
        val m = PgpRestoreMachine(
            chain = chain,
            wallet = object : PgpRestoreWallet {
                override fun ready(): Boolean = true
                override fun passwordString(): String? = password
            },
            keys = object : PgpRestoreKeys {
                override fun newKey(deviceId: String): PgpNewKey = PgpNewKey(
                    acceptance.getJSONObject("syntheticKeys").getJSONObject("P4").getString("privateArmor"),
                    identityOf("P4"),
                )
            },
            ivFor = { ByteArray(12) { 1 } },
            devices = mapOf("A" to dev),
            absence = RegisteringAbsenceRule { wb -> chain.confirmedAbsentAfter(wb) },
        )
        m.restore("A")
        m.tapEntry("A")
        m.keygen("A", "idem-1", nativeConfirmed = true)

        dev.markRegistering(42L)
        assertEquals("the write block is not earlier than the read block: still unresolved", "undetermined", m.restore("A").result)
        assertEquals("pgp_write_in_progress", dev.ui.code)

        dev.markRegistering(41L)
        assertEquals("retry_ready", m.restore("A").result)
        assertEquals("retry_ready", dev.ui.state)
        assertTrue("the marker stays, the same key retries", dev.registeringMarked())
    }
}
