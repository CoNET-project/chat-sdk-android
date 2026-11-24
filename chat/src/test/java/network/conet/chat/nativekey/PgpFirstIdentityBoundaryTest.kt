package network.conet.chat.nativekey

import java.io.File
import java.net.SocketTimeoutException
import org.json.JSONArray
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Boundaries of the first-identity restore:
 *  - KpgpUpgrade and PgpMigration (still on the two-endpoint readAgreed, deferred to a separate single-RPC task) never give an unregistered
 *    verdict, never open a first identity, and fail closed when the chain is unreadable;
 *  - the first-identity chain read runs on the restore worker, never on the main thread;
 *  - the primary endpoint's timeout is 12 000 ms, and a timeout is unknown.
 */
class PgpFirstIdentityBoundaryTest {
    private val eoa = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"
    private val module = File("src/main/java/network/conet/chat/BeamioConetChatModule.kt").readText(Charsets.UTF_8)

    @Test
    fun kpgpAndMigrationNeverDecideUnregisteredOrOpenACreation() {
        for (path in listOf("src/main/java/network/conet/chat/nativekey/KpgpUpgrade.kt", "src/main/java/network/conet/chat/nativekey/PgpMigration.kt")) {
            val src = File(path).readText(Charsets.UTF_8)
            assertFalse("$path does not use the first-identity rule", src.contains("FirstIdentityRule"))
            assertFalse("$path does not open a creation entry", src.contains("creationEntryOpen"))
            assertFalse("$path does not generate a key", src.contains("keygen("))
        }
        // The K upgrade hands a vault with no key to the first-identity coordinator, which is the only place that
        // generates a key, and only after the chain read confirmed no record. The migration still never states a first identity.
        assertFalse("PgpMigration does not state first_identity", File("src/main/java/network/conet/chat/nativekey/PgpMigration.kt").readText(Charsets.UTF_8).contains("first_identity"))
    }

    @Test
    fun aSingleEndpointChainIsUnreadableAndTheRestoreIsUnverified() {
        val oneEndpoint = AddressPgpConfig(AddressPgpConfig.default.contract, listOf(AddressPgpConfig.default.endpoints[0]))
        val chain = AddressPgpChain.readAgreed(eoa, oneEndpoint) { _ -> object : AddressPgpRead.Rpc {
            override fun call(method: String, params: JSONArray): Any? = throw IllegalStateException("unused")
        } }
        assertFalse("a chain that cannot be cross-read is unreadable", chain.chainReadable())
        val result = ChainBackupRestore.candidate(chain) { null }
        assertEquals("unreadable chain is unreadable, never a created identity", ChainBackupRestore.Candidate.Unreadable, result)
    }

    @Test
    fun theFirstIdentityChainReadRunsOnTheRestoreWorkerNotTheMainThread() {
        assertTrue("the restore worker is a background executor", module.contains("private val pgpRestoreWorker = Executors.newSingleThreadExecutor()"))
        val evaluate = module.substringAfter("if (evaluateOnly) {").substringBefore("answer(true, result = JSONObject().put(\"accepted\", true))")
        assertTrue("the chain read happens inside the worker", evaluate.indexOf("pgpRestoreWorker.execute {") in 0 until evaluate.indexOf("productionChain(eoa)"))
    }

    @Test
    fun thePrimaryEndpointTimeoutIs12000AndATimeoutIsUnknown() {
        assertEquals(12_000, AddressPgpConfig.default.endpoints[0].timeoutMs)
        val chain = AddressPgpChain.readSingle(eoa, rpcFor = { _ -> object : AddressPgpRead.Rpc {
            override fun call(method: String, params: JSONArray): Any? = throw SocketTimeoutException("timeout")
        } })
        assertEquals("unknown", FirstIdentityRule.chainOfRead(chain))
    }
}
