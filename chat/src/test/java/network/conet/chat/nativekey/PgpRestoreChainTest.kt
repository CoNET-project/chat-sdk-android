package network.conet.chat.nativekey

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * The AddressPGP chain for the restore (§25.30.2, §25.36.2, §25.36.5) against a mock RPC, with the acceptance vectors' keys
 * and backups. No endpoint is contacted. The identity parsed from the on-chain public armor must equal the vector's
 * identity, because the restore compares the two.
 */
class PgpRestoreChainTest {
    private val acceptance = JSONObject(
        String(File(System.getenv("PGP_RESTORE_VECTORS") ?: "../spec/pgp-restore-acceptance-vectors.v1.json").readBytes(), Charsets.UTF_8),
    )
    private val backupCompat = JSONObject(
        String(File(System.getenv("PGP_BACKUP_VECTORS") ?: "../spec/pgp-backup-compat-vectors.v1.json").readBytes(), Charsets.UTF_8),
    )
    private val password = backupCompat.getJSONArray("positives").getJSONObject(0).getString("passwordString")
    private val account = acceptance.getJSONObject("syntheticAccount").getString("address").lowercase()
    private val rpc1 = RegistryEndpoint("https://rpc1.conet.network", 12_000)
    private val rpc2 = RegistryEndpoint("https://publicrpc.conet.network", 12_000)
    private val config = AddressPgpConfig("0x684b0ac760cEE9c9b85de36d69746420648Cf9e2", listOf(rpc1, rpc2))

    private fun identityOf(name: String) = PgpIdentity(
        acceptance.getJSONObject("identities").getJSONObject(name).getString("fingerprint"),
        acceptance.getJSONObject("identities").getJSONObject(name).getString("subkeyKeyID"),
    )

    private fun publicArmorOf(name: String): String = NativePgpKeyGen.publicArmorOf(
        acceptance.getJSONObject("syntheticKeys").getJSONObject(name).getString("privateArmor"),
    )!!

    private fun backupOf(label: String): String = acceptance.getJSONObject("backups").getJSONObject(label).getString("base64")

    private fun word(v: Long): ByteArray = ByteArray(32).also { w ->
        for (i in 0 until 8) w[31 - i] = ((v shr (8 * i)) and 0xFF).toByte()
    }

    private fun string(s: String): ByteArray {
        val b = s.toByteArray(Charsets.UTF_8)
        return word(b.size.toLong()) + b + ByteArray((32 - b.size % 32) % 32)
    }

    private fun hex(b: ByteArray) = "0x" + b.joinToString("") { "%02x".format(it) }

    /** `_pgpKeys(address)` as the contract returns it: (string, string, string, bool). */
    private fun recordHex(publicArmor: String?): String {
        val a = string("")
        val p = string(publicArmor ?: "")
        val c = string("")
        val head = word(128) + word(128L + a.size) + word(128L + a.size + p.size) + word(if (publicArmor != null) 1 else 0)
        return hex(head + a + p + c)
    }

    private fun backupHex(text: String): String = hex(word(32) + string(text))

    /** A mock JSON-RPC. Each endpoint has its own answer for the record and the backup, or fails. */
    private class MockRpc(
        private val record: String?,
        private val backup: String?,
        private val seen: MutableList<Pair<String, JSONObject?>>,
    ) : AddressPgpRead.Rpc {
        override fun call(method: String, params: JSONArray): Any? {
            return when (method) {
                "eth_blockNumber" -> "0x2a"
                "eth_call" -> {
                    val call = params.getJSONObject(0)
                    seen += call.getString("data").substring(0, 10) to call
                    val recordSel = AddressPgpRead.selector(AddressPgpRead.SIG_PGP_KEYS)
                    when (call.getString("data").substring(0, 10)) {
                        recordSel -> record ?: error("record endpoint down")
                        else -> backup ?: error("backup endpoint down")
                    }
                }
                else -> error("unexpected $method")
            }
        }
    }

    private fun readWith(endpointAnswers: Map<String, Pair<String?, String?>>, seen: MutableList<Pair<String, JSONObject?>>): AddressPgpChain =
        AddressPgpChain.read(account, config) { ep ->
            val (rec, back) = endpointAnswers.getValue(ep.url)
            MockRpc(rec, back, seen)
        }

    @Test
    fun theIdentityParsedFromTheOnChainArmorIsTheVectorIdentity() {
        assertEquals(identityOf("P3"), PgpPublicIdentity.parse(publicArmorOf("P3")))
        assertEquals(identityOf("P4"), PgpPublicIdentity.parse(publicArmorOf("P4")))
        assertNull(PgpPublicIdentity.parse("not an armor"))
    }

    @Test
    fun theRecordAndBackupComeFromTheFirstEndpointThatAnswers() {
        val seen = mutableListOf<Pair<String, JSONObject?>>()
        val chain = readWith(
            mapOf(
                rpc1.url to Pair(null, null),
                rpc2.url to Pair(recordHex(publicArmorOf("P3")), backupHex(backupOf("B_P3_UNDER_A"))),
            ),
            seen,
        )
        assertTrue(chain.chainReadable())
        assertTrue(chain.backupReadable())
        assertEquals(identityOf("P3"), chain.identity())
        assertEquals(backupOf("B_P3_UNDER_A"), chain.backupText())
    }

    @Test
    fun aBothEndpointsDownIsUnreadableNotAbsence() {
        val seen = mutableListOf<Pair<String, JSONObject?>>()
        val chain = readWith(mapOf(rpc1.url to Pair(null, null), rpc2.url to Pair(null, null)), seen)
        assertFalse(chain.chainReadable())
        assertFalse(chain.backupReadable())
    }

    @Test
    fun aRecordWithNoIdentityIsReadableAndHasNoBackup() {
        val seen = mutableListOf<Pair<String, JSONObject?>>()
        val chain = readWith(mapOf(rpc1.url to Pair(recordHex(null), backupHex("")), rpc2.url to Pair(null, null)), seen)
        assertTrue(chain.chainReadable())
        assertTrue(chain.backupReadable())
        assertNull(chain.identity())
        assertEquals("", chain.backupText())
    }

    @Test
    fun anUnparseableRecordIsUnreadable() {
        val seen = mutableListOf<Pair<String, JSONObject?>>()
        val chain = readWith(
            mapOf(rpc1.url to Pair(recordHex("garbage armor"), backupHex("x")), rpc2.url to Pair(null, null)),
            seen,
        )
        assertFalse(chain.chainReadable())
    }

    @Test
    fun onlyTheTwoViewCallsAreMadeAndTheBackupCarriesTheAccountAsFrom() {
        val seen = mutableListOf<Pair<String, JSONObject?>>()
        readWith(
            mapOf(rpc1.url to Pair(recordHex(null), backupHex("")), rpc2.url to Pair(null, null)),
            seen,
        )
        val selectors = seen.map { it.first }.toSet()
        assertEquals(
            setOf(AddressPgpRead.selector(AddressPgpRead.SIG_PGP_KEYS), AddressPgpRead.selector(AddressPgpRead.SIG_ENCRYPTED_BACKUP)),
            selectors,
        )
        val backupCall = seen.first { it.first == AddressPgpRead.selector(AddressPgpRead.SIG_ENCRYPTED_BACKUP) }.second!!
        assertEquals(account, backupCall.getString("from"))
    }

    @Test
    fun theRestoreThroughTheMockChainWritesTheMatchingIdentity() {
        val seen = mutableListOf<Pair<String, JSONObject?>>()
        val chain = readWith(
            mapOf(
                rpc1.url to Pair(recordHex(publicArmorOf("P3")), backupHex(backupOf("B_P3_UNDER_A"))),
                rpc2.url to Pair(null, null),
            ),
            seen,
        )
        val files = NativeTestFiles()
        val device = PgpRestoreDevice("A", account, NativeTestWrap(), files)
        val machine = PgpRestoreMachine(
            chain = chain,
            wallet = object : PgpRestoreWallet {
                override fun ready(): Boolean = true
                override fun passwordString(): String? = password
            },
            keys = object : PgpRestoreKeys {
                override fun newKey(deviceId: String): PgpNewKey = error("restore never generates a key")
            },
            ivFor = { error("restore never writes a backup") },
            devices = mapOf("A" to device),
        )
        assertEquals("ok", machine.restore("A").result)
        val active = device.active.identity()
        assertEquals(identityOf("P3").fingerprint.uppercase(), active!!.fingerprint.uppercase())
        assertEquals(0, machine.counters.onchainWrites)
        assertEquals(0, machine.counters.keygen)
    }
}
