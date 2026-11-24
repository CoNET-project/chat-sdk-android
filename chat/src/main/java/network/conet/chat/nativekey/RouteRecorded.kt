package network.conet.chat.nativekey

import network.conet.chat.ConetChatCryptoUtil
import org.json.JSONArray
import org.json.JSONObject

/**
 * The read-only precheck of a mailbox node before an account is registered on it. A route the contract does not accept reverts in the
 * Master's paid transaction, so the node is checked first, with the same rule as the PWA's `pickRecordedMailbox`:
 *  1. AddressPGP has recorded the node as a mailbox (`nodeKeyExists(keccak256(routeKeyId))`): on an unrecorded node SI answers `not_my_route`;
 *  2. GuardianNodesInfoV6 knows the route key (`getPGPKeyIPaddress(routeKeyId)` is not empty): the contract's own registration requirement.
 * A failed read throws (never "not recorded"); the pick then answers unreadable and nothing is submitted.
 */
internal object RouteRecorded {
    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

    private fun call(rpc: AddressPgpRead.Rpc, to: String, data: String): String {
        val c = JSONObject().put("to", to).put("data", data)
        val r = rpc.call("eth_call", JSONArray().put(c).put("latest")) as? String ?: throw IllegalStateException("route_read_failed")
        return r.removePrefix("0x")
    }

    /** ABI call data for a function taking one string. */
    internal fun callDataString(signature: String, value: String): String {
        val b = value.toByteArray(Charsets.UTF_8)
        val padded = hex(b).padEnd(((b.size + 31) / 32) * 64, '0')
        return AddressPgpRead.selector(signature) + "%064x".format(32) + "%064x".format(b.size) + padded
    }

    fun isRecorded(routeKeyId: String, rpc: AddressPgpRead.Rpc, addressPgp: String = AddressPgpConfig.default.contract): Boolean {
        val id = routeKeyId.trim()
        if (id.isEmpty()) return false
        val keyHash = hex(ConetChatCryptoUtil.keccak256(id.toByteArray(Charsets.UTF_8)))
        val exists = call(rpc, addressPgp, AddressPgpRead.selector("nodeKeyExists(bytes32)") + keyHash)
        if (exists.length != 64 || !exists.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) throw IllegalStateException("route_read_failed")
        if (exists.last() != '1') return false
        val guardianWord = call(rpc, addressPgp, AddressPgpRead.selector("guardianNodes()"))
        if (guardianWord.length != 64 || !guardianWord.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) throw IllegalStateException("route_read_failed")
        val guardian = "0x" + guardianWord.substring(24)
        if (guardian.substring(2).all { it == '0' }) throw IllegalStateException("route_read_failed")
        val ip = AddressPgpRead.decodeString("0x" + call(rpc, guardian, callDataString("getPGPKeyIPaddress(string)", id))) ?: throw IllegalStateException("route_read_failed")
        return ip.isNotEmpty()
    }

    /** Tries the primary endpoint, then the backup; both failing throws. */
    fun failover(rpcs: List<AddressPgpRead.Rpc>): AddressPgpRead.Rpc = AddressPgpRead.Rpc { method, params ->
        var last: Exception? = null
        for (r in rpcs) {
            try {
                return@Rpc r.call(method, params)
            } catch (e: Exception) {
                last = e
            }
        }
        throw last ?: IllegalStateException("route_read_failed")
    }

    /**
     * The pick, as the PWA does it: [candidates] in random order, at most [maxChecks] distinct ids, the first recorded one wins; a failed check picks
     * nothing (unreadable); none recorded is none.
     */
    fun pick(candidates: List<String>, isRecorded: (String) -> Boolean, maxChecks: Int = 8): RouteChoice {
        val seen = HashSet<String>()
        for (raw in candidates) {
            if (seen.size >= maxChecks) break
            val id = raw.trim()
            if (id.isEmpty() || !seen.add(id.uppercase())) continue
            val recorded = try { isRecorded(id) } catch (_: Exception) { return RouteChoice.Unreadable }
            if (recorded) return RouteChoice.Ok(id)
        }
        return RouteChoice.None
    }
}
