package network.conet.chat.nativekey

import org.json.JSONArray
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The single-RPC chain read: the primary endpoint only, the CoNET L1 chain id is checked, and any failure is unknown.
 */
class AddressPgpChainSingleRpcTest {
    private val eoa = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"

    /** A fake endpoint: answers the chain id, and fails every other call (so a read that reaches the record would be visible). */
    private class FakeRpc(private val chainIdHex: Any?) : AddressPgpRead.Rpc {
        var calls = 0
        override fun call(method: String, params: JSONArray): Any? {
            calls++
            if (method == "eth_chainId") return chainIdHex
            throw IllegalStateException("network_error")
        }
    }

    @Test
    fun aWrongChainIdIsUnknownNotUnregistered() {
        val rpc = FakeRpc("0x1")
        val chain = AddressPgpChain.readSingle(eoa, rpcFor = { rpc })
        assertTrue("a wrong chain id is a read failure", chain.identityRead() == IdentityRead.Unknown)
        assertEquals("unknown", FirstIdentityRule.chainOfRead(chain))
    }

    @Test
    fun aMalformedChainIdIsUnknown() {
        assertEquals("unknown", FirstIdentityRule.chainOfRead(AddressPgpChain.readSingle(eoa, rpcFor = { FakeRpc("0xzz") })))
        assertEquals("unknown", FirstIdentityRule.chainOfRead(AddressPgpChain.readSingle(eoa, rpcFor = { FakeRpc(null) })))
    }

    @Test
    fun onlyThePrimaryEndpointIsQueried() {
        val urls = mutableListOf<String>()
        val rpc = FakeRpc("0x1")
        AddressPgpChain.readSingle(eoa, rpcFor = { ep -> urls += ep.url; rpc })
        assertEquals("one endpoint is asked: the primary", listOf(AddressPgpConfig.default.endpoints[0].url), urls)
    }

    @Test
    fun aFailingPrimaryNeverFallsBackToTheSecondEndpoint() {
        val urls = mutableListOf<String>()
        val chain = AddressPgpChain.readSingle(eoa, rpcFor = { ep ->
            urls += ep.url
            object : AddressPgpRead.Rpc {
                override fun call(method: String, params: JSONArray): Any? = throw IllegalStateException("timeout")
            }
        })
        assertEquals("unknown", FirstIdentityRule.chainOfRead(chain))
        assertEquals("the second endpoint is never asked", 1, urls.size)
    }
}
