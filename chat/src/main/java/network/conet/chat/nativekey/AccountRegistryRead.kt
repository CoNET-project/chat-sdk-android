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
    const val SIG_OWNER_BY_ACCOUNT_NAME = "getOwnerByAccountName(string)"

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

    /** Call data for `getOwnerByAccountName(string)`. */
    fun callDataOwnerByAccountName(name: String): String {
        val b = name.toByteArray(Charsets.UTF_8)
        val padded = b.joinToString("") { "%02x".format(it) }.padEnd(((b.size + 31) / 32) * 64, '0')
        return AddressPgpRead.selector(SIG_OWNER_BY_ACCOUNT_NAME) + "%064x".format(32) + "%064x".format(b.size) + padded
    }

    /**
     * The owner of [name] (lower-case `0x` address), or null when the registry answers the zero address, read at one block on both endpoints with
     * the same rule as [readAgreed]. A failure or a disagreement throws (never "no owner").
     */
    fun ownerAgreed(
        config: RegistryConfig,
        rpcFor: (RegistryEndpoint) -> AddressPgpRead.Rpc,
        name: String,
    ): String? {
        if (config.endpoints.size < 2) throw IllegalStateException("network_error")
        val rpcA = rpcFor(config.endpoints[0])
        val rpcB = rpcFor(config.endpoints[1])
        val tag = rpcA.call("eth_blockNumber", JSONArray()) as? String ?: throw IllegalStateException("network_error")
        val n = tag.removePrefix("0x").toLongOrNull(16) ?: throw IllegalStateException("network_error")
        val hashA = AddressPgpRead.blockHashAt(rpcA, tag, n) ?: throw IllegalStateException("network_error")
        val hashB = AddressPgpRead.blockHashAt(rpcB, tag, n) ?: throw IllegalStateException("network_error")
        if (hashA != hashB) throw IllegalStateException("network_error")
        val data = callDataOwnerByAccountName(name)
        val a = addressAt(rpcA, config.registry, data, tag)
        val b = addressAt(rpcB, config.registry, data, tag)
        if (a != b) throw IllegalStateException("network_error")
        return a
    }

    private fun addressAt(rpc: AddressPgpRead.Rpc, registry: String, data: String, tag: String): String? {
        val call = JSONObject().put("to", registry).put("data", data)
        val hex = (rpc.call("eth_call", JSONArray().put(call).put(tag)) as? String)?.removePrefix("0x") ?: throw IllegalStateException("network_error")
        if (hex.length != 64 || !hex.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) throw IllegalStateException("network_error")
        val addr = hex.substring(24).lowercase()
        return if (addr.all { it == '0' }) null else "0x$addr"
    }

    /**
     * One `eth_call` against [registry], read at one block on both endpoints (draft r2.5.20 第 7 版, the same rule as the binding lookup): the
     * block is the first endpoint's number N, each endpoint must return block N with the same hash, and both must answer the same text. Both empty
     * is "no record" (null). A single empty answer, a disagreement, or any failure throws (network_error): never "no record".
     */
    fun readAgreed(
        config: RegistryConfig,
        rpcFor: (RegistryEndpoint) -> AddressPgpRead.Rpc,
        data: String,
    ): String? {
        if (config.endpoints.size < 2) throw IllegalStateException("network_error")
        val rpcA = rpcFor(config.endpoints[0])
        val rpcB = rpcFor(config.endpoints[1])
        val tag = rpcA.call("eth_blockNumber", JSONArray()) as? String ?: throw IllegalStateException("network_error")
        val n = tag.removePrefix("0x").toLongOrNull(16) ?: throw IllegalStateException("network_error")
        val hashA = AddressPgpRead.blockHashAt(rpcA, tag, n) ?: throw IllegalStateException("network_error")
        val hashB = AddressPgpRead.blockHashAt(rpcB, tag, n) ?: throw IllegalStateException("network_error")
        if (hashA != hashB) throw IllegalStateException("network_error")
        val textA = textAt(rpcA, config.registry, data, tag)
        val textB = textAt(rpcB, config.registry, data, tag)
        if (textA != textB) throw IllegalStateException("network_error")
        return textA.ifEmpty { null }
    }

    private fun textAt(rpc: AddressPgpRead.Rpc, registry: String, data: String, tag: String): String {
        val call = JSONObject().put("to", registry).put("data", data)
        val hex = rpc.call("eth_call", JSONArray().put(call).put(tag)) as? String ?: throw IllegalStateException("network_error")
        return AddressPgpRead.decodeString(hex) ?: throw IllegalStateException("network_error")
    }
}
