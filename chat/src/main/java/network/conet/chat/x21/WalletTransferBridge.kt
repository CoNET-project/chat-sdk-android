package network.conet.chat.x21

import org.json.JSONArray
import org.json.JSONObject
import java.util.UUID

/**
 * X-21 one-time wallet transfer, bridge side (spec r3b 25.6.1, batch 14).
 *
 * - The three commands `walletTransferOnce`, `walletTransferStatus`, `walletTransferSwitched` arrive through
 *   the chat module command channel (`cmd.type` dispatch, [onCommand]). No per-command bridge method.
 * - Every command gets an `ack`, which only accepts or rejects. The outcome of a transfer is only the
 *   asynchronous `walletTransferResult` event.
 * - Payloads are flat dictionaries; the module wraps them as `{action: "chatModuleEvent", event: payload}`.
 * - The request is native-initiated ([issue]) and carries public data only: `{requestId, kind, eoa}`.
 *
 * This build has no native key store ([NativeStore.NotWired]). Nothing is requested, and commands are
 * answered with `native_store_unavailable` or `not_requested`. Matching, payload checks, busy and timeout
 * are implemented here so the store can be wired in without changing the bridge contract.
 */
class WalletTransferBridge(
    private val now: () -> Long,
    private val store: NativeStore = NativeStore.NotWired,
) {
    /** Native side: key records, completion markers and the write pipeline. */
    interface NativeStore {
        /** False when the store cannot be used at all (no wiring in this build). */
        val available: Boolean

        /** EOA or PGP: no key record, no completion marker, no passcode, and no other request pending. */
        fun mayRequest(eoa: String, kind: String): Boolean

        /** Writes and reads back the record; returns the result code, or `null` when the store is unavailable. */
        fun commit(eoa: String, kind: String, bytes: ByteArray): String?

        /** complete -> switched. `true` when done, `false` when no completed record matches, `null` when unavailable. */
        fun markSwitched(requestId: String): Boolean?

        object NotWired : NativeStore {
            override val available: Boolean = false
            override fun mayRequest(eoa: String, kind: String): Boolean = false
            override fun commit(eoa: String, kind: String, bytes: ByteArray): String? = null
            override fun markSwitched(requestId: String): Boolean? = null
        }
    }

    private class Outstanding(val requestId: String, val eoa: String, val kind: String, val issuedAt: Long)

    private val outstanding = HashMap<String, Outstanding>()

    /**
     * Native-initiated request. Returns the `walletTransferRequest` payload, or `null` when a request of the
     * same kind is already pending for this account, or the store does not allow one.
     */
    @Synchronized
    fun issue(eoa: String, kind: String): JSONObject? {
        if (kind !in KINDS) return null
        val key = key(eoa, kind)
        if (outstanding.containsKey(key)) return null
        if (!store.mayRequest(eoa, kind)) return null
        val requestId = UUID.randomUUID().toString()
        outstanding[key] = Outstanding(requestId, eoa, kind, now())
        return JSONObject()
            .put("type", "walletTransferRequest")
            .put("requestId", requestId)
            .put("kind", kind)
            .put("eoa", eoa)
    }

    /**
     * A PWA command (`cmd.type`). Returns the payloads to emit, in order: results of requests that timed out,
     * then this command's `ack`, then any result this command ends. Unknown types return nothing.
     */
    @Synchronized
    fun onCommand(cmd: JSONObject): List<JSONObject> {
        val out = ArrayList<JSONObject?>()
        out += sweep()
        val reqId = cmd.optInt("reqId", 0)
        when (cmd.optString("type", "")) {
            "walletTransferOnce" -> out += onOnce(cmd, reqId)
            "walletTransferStatus" -> out += ackOf(reqId, store.available, if (store.available) null else ERR_NO_STORE)
            "walletTransferSwitched" -> out += when (store.markSwitched(cmd.optString("requestId", ""))) {
                true -> ackOf(reqId, true, null)
                false -> ackOf(reqId, false, ERR_NOT_REQUESTED)
                null -> ackOf(reqId, false, ERR_NO_STORE)
            }
            else -> Unit
        }
        return out.filterNotNull()
    }

    /**
     * Ends requests that were not answered within [TIMEOUT_MS]: each gets a `timeout` result and no state
     * changes. Called on every command, since the module has no timer of its own.
     */
    @Synchronized
    fun sweep(): List<JSONObject> {
        val t = now()
        val expired = outstanding.values.filter { t - it.issuedAt >= TIMEOUT_MS }
        expired.forEach { outstanding.remove(key(it.eoa, it.kind)) }
        return expired.map { result(it.requestId, it.kind, CODE_TIMEOUT) }
    }

    private fun onOnce(cmd: JSONObject, reqId: Int): List<JSONObject?> {
        val requestId = cmd.optString("requestId", "")
        val kind = cmd.optString("kind", "")
        val pending = outstanding.values.firstOrNull { it.requestId == requestId && it.kind == kind }
            ?: return listOf(ackOf(reqId, false, ERR_NOT_REQUESTED))
        // The response ends the request whatever its outcome.
        outstanding.remove(key(pending.eoa, pending.kind))
        val bytes = parseBytes(cmd.optJSONArray("bytes"), kind)
            ?: return listOf(ackOf(reqId, false, CODE_INVALID_PAYLOAD), result(requestId, kind, CODE_INVALID_PAYLOAD))
        val code = store.commit(pending.eoa, kind, bytes)
        bytes.fill(0)
        if (code == null) return listOf(ackOf(reqId, false, ERR_NO_STORE))
        return listOf(ackOf(reqId, true, null), result(requestId, kind, code))
    }

    /**
     * Integer array (each 0–255) to bytes. EOA key: exactly 32 bytes. PGP armor: 1 to 65536 bytes.
     * Returns `null` for any other shape. Only the copy is zeroed by the caller; the JSON value itself is not under our control.
     */
    private fun parseBytes(arr: JSONArray?, kind: String): ByteArray? {
        if (arr == null) return null
        val n = arr.length()
        when (kind) {
            "eoaKey" -> if (n != 32) return null
            "pgpArmor" -> if (n < 1 || n > 65536) return null
            else -> return null
        }
        val out = ByteArray(n)
        for (i in 0 until n) {
            val v = arr.opt(i)
            if (v !is Int || v < 0 || v > 255) {
                out.fill(0)
                return null
            }
            out[i] = v.toByte()
        }
        return out
    }

    private fun ackOf(reqId: Int, ok: Boolean, error: String?): JSONObject? {
        if (reqId <= 0) return null
        val payload = JSONObject().put("type", "ack").put("reqId", reqId).put("ok", ok)
        if (!ok) payload.put("error", error ?: "error")
        return payload
    }

    private fun result(requestId: String, kind: String, code: String): JSONObject =
        JSONObject()
            .put("type", "walletTransferResult")
            .put("requestId", requestId)
            .put("kind", kind)
            .put("code", code)

    private fun key(eoa: String, kind: String): String = "${eoa.lowercase()}|$kind"

    companion object {
        /** Kinds of key material the one-time transfer carries (spec 25.6.1). */
        val KINDS = setOf("eoaKey", "pgpArmor")

        /** No response within this time ends the request (spec r3b 25.6.1). */
        const val TIMEOUT_MS = 30_000L

        const val CODE_TIMEOUT = "timeout"
        const val CODE_INVALID_PAYLOAD = "invalid_payload"
        const val ERR_NOT_REQUESTED = "not_requested"
        const val ERR_NO_STORE = "native_store_unavailable"
    }
}
