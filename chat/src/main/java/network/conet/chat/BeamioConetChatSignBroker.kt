package network.conet.chat

import android.os.Handler
import android.os.Looper
import org.json.JSONObject
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Signing for the module. With a wallet key from the page (kept in
 * [BeamioChatWalletKeyStore]) the module signs locally, so a call push can open
 * the mailbox listen without the page. Without one it falls back to model 1B: it
 * asks the host PWA to EIP-191 / EIP-712 sign and receives the signature through
 * [fulfill] (`{ action: "chatModuleSignRequest", reqId, kind, … }`).
 */
object BeamioConetChatSignBroker {
    private const val DEFAULT_TIMEOUT_MS = 30_000L

    private class Pending(val cb: (ok: Boolean, signature: String?, error: String?) -> Unit)

    private val pending = ConcurrentHashMap<String, Pending>()
    private val timer = Handler(Looper.getMainLooper())

    @Volatile
    private var emit: ((JSONObject) -> Unit)? = null

    /** Local signer: hex key (memory only) and the host that runs ethers. */
    @Volatile
    private var localKey: String = ""
    @Volatile
    private var localHost: BeamioOpenPgpHost? = null

    fun setLocalSigner(host: BeamioOpenPgpHost?, privateKeyHex: String) {
        localHost = host
        localKey = BeamioChatWalletKeyStore.normalizeKey(privateKeyHex)
    }

    /**
     * R_db for the local DB, derived here inside the wallet boundary from the in-memory private key
     * (spec v1.1-r1 22.2). The key itself never leaves this object. Null when no local key is held.
     */
    fun deriveLocalRoot(eoa: String, workspace: String): ByteArray? {
        val key = localKey
        if (key.isEmpty()) return null
        val p = ConetChatCryptoUtil.hexToBytes(key) ?: return null
        try {
            return network.conet.chat.localread.LocalChatIds.rootDbFromPrivateKey(p, eoa.lowercase(), workspace)
        } finally {
            p.fill(0)
        }
    }

    fun clearLocalSigner() {
        localKey = ""
        localHost = null
    }

    fun hasLocalSigner(): Boolean = localKey.isNotEmpty() && localHost != null

    fun setEmit(emit: ((JSONObject) -> Unit)?) {
        this.emit = emit
    }

    /** Request EIP-191 `personal_sign(message)` from the PWA. */
    fun requestEip191(
        message: String,
        timeoutMs: Long = DEFAULT_TIMEOUT_MS,
        completion: (Result<String>) -> Unit,
    ) {
        val key = localKey
        val host = localHost
        if (key.isNotEmpty() && host != null) {
            host.signEip191(key, message, completion)
            return
        }
        request("eip191", message, null, timeoutMs, completion)
    }

    /** Request an EIP-712 typed data signature from the PWA. */
    fun requestEip712(
        typedData: JSONObject,
        timeoutMs: Long = DEFAULT_TIMEOUT_MS,
        completion: (Result<String>) -> Unit,
    ) {
        val key = localKey
        val host = localHost
        if (key.isNotEmpty() && host != null) {
            host.signEip712(key, typedData, completion)
            return
        }
        request("eip712", null, typedData, timeoutMs, completion)
    }

    /** PWA answer: `{ reqId, ok, signature?, error? }`. */
    fun fulfill(body: JSONObject) {
        val reqId = body.optString("reqId", "")
        if (reqId.isEmpty()) return
        val cb = pending.remove(reqId) ?: return
        cb.cb(
            body.optBoolean("ok", false),
            body.optString("signature", "").takeIf { it.isNotEmpty() },
            body.optString("error", "").takeIf { it.isNotEmpty() },
        )
    }

    fun cancelAll(reason: String = "destroyed") {
        val keys = pending.keys.toList()
        for (k in keys) {
            pending.remove(k)?.cb?.invoke(false, null, reason)
        }
    }

    private fun request(
        kind: String,
        message: String?,
        typedData: JSONObject?,
        timeoutMs: Long,
        completion: (Result<String>) -> Unit,
    ) {
        val reqId = UUID.randomUUID().toString()
        pending[reqId] = Pending { ok, signature, error ->
            if (ok && !signature.isNullOrEmpty()) {
                completion(Result.success(signature))
            } else {
                completion(Result.failure(IllegalStateException(error ?: "sign_failed")))
            }
        }
        val emitFn = emit
        if (emitFn == null) {
            pending.remove(reqId)?.cb?.invoke(false, null, "no_web_emit")
            return
        }
        val payload = JSONObject()
            .put("action", "chatModuleSignRequest")
            .put("reqId", reqId)
            .put("kind", kind)
        if (message != null) payload.put("message", message)
        if (typedData != null) payload.put("typedData", typedData)
        // WebView APIs (the shell dispatches this into the PWA) must run on the main thread.
        timer.post { emitFn(payload) }
        timer.postDelayed({
            pending.remove(reqId)?.cb?.invoke(false, null, "sign_timeout")
        }, timeoutMs)
    }
}
