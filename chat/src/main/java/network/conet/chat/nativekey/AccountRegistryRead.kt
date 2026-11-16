package network.conet.chat.nativekey

import org.json.JSONArray
import org.json.JSONObject

/** One read-only JSON-RPC endpoint and its timeout (§25.42.6). */
internal class RegistryEndpoint(val url: String, val timeoutMs: Int)

/** A registry: its address and the endpoints to try in order. */
internal class RegistryConfig(val registry: String, val endpoints: List<RegistryEndpoint>)

/**
 * The account registry reads of the recovery engine (§25.42.5 steps 4 and 4.1, §25.42.6). Only `eth_call`. No write
 * method is named here. Addresses and endpoints are the PWA's live values, pending the interface owner's confirmation
 * (§25.42.6 gives them; §25.36.4 confirmation is pending for AddressPGP).
 */
internal object AccountRegistryRead {
    const val SIG_BY_NAME_HASH = "getBase64ByNameHash(bytes32)"
    const val SIG_BY_ACCOUNT_NAME = "getBase64ByAccountName(string)"

    /** The current account registry. The primary endpoint is tried first, then the backup, 12 seconds each. */
    @Volatile
    var current: RegistryConfig = RegistryConfig(
        registry = "0xfFDc8d2021A41F4638Cb3eCf58B5155383EE9f6d",
        endpoints = listOf(
            RegistryEndpoint("https://rpc1.conet.network", 12_000),
            RegistryEndpoint("https://publicrpc.conet.network", 12_000),
        ),
    )

    /** Call data for `getBase64ByNameHash(bytes32)`: the selector and the 32-byte key. */
    fun callDataByNameHash(indexHash: ByteArray): String {
        require(indexHash.size == 32)
        return AddressPgpRead.selector(SIG_BY_NAME_HASH) + indexHash.joinToString("") { "%02x".format(it) }
    }

    /** Call data for `getBase64ByAccountName(string)`: selector, offset 0x20, length, UTF-8 bytes padded to 32. */
    fun callDataByAccountName(name: String): String {
        val b = name.toByteArray(Charsets.UTF_8)
        val padded = b.joinToString("") { "%02x".format(it) }.padEnd(((b.size + 31) / 32) * 64, '0')
        return AddressPgpRead.selector(SIG_BY_ACCOUNT_NAME) +
            "%064x".format(32) + "%064x".format(b.size) + padded
    }

    /**
     * One `eth_call` against [registry] on the first endpoint that answers. An empty answer is a definitive "no record"
     * (returned as null), not a failure. Throws when every endpoint fails (transport, HTTP, RPC or decode).
     */
    fun readFirst(
        config: RegistryConfig,
        rpcFor: (RegistryEndpoint) -> AddressPgpRead.Rpc,
        data: String,
    ): String? {
        var last: Exception? = null
        for (ep in config.endpoints) {
            try {
                val call = JSONObject().put("to", config.registry).put("data", data)
                val hex = rpcFor(ep).call("eth_call", JSONArray().put(call).put("latest")) as? String
                    ?: throw IllegalStateException("no result")
                val text = AddressPgpRead.decodeString(hex) ?: throw IllegalStateException("undecodable")
                return text.ifEmpty { null }
            } catch (e: Exception) {
                last = e
            }
        }
        throw IllegalStateException("network_error", last)
    }
}
