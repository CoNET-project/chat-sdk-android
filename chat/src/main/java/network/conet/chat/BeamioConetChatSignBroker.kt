package network.conet.chat

import network.conet.chat.nativekey.Eip191Signer
import network.conet.chat.nativekey.Eip712
import org.json.JSONObject

/**
 * Signing for the module. The wallet key comes only from the native vault (`nativekey.NativeWallet`) and
 * is handed here in memory, so a call push can open the mailbox listen without the page. The bridge never
 * supplies it.
 *
 * Without a native key nothing is signed. The request fails at once with `no_key`, and no signing request is
 * sent to the page (spec 25.26.4, S-3, T-155). The page never holds a key that signs for the wallet. The earlier
 * fallback that asked the page to sign (model 1B) is removed.
 */
object BeamioConetChatSignBroker {
    /** Answer for a signing request made while no native key is held. */
    const val NO_KEY = "no_key"

    /**
     * Local signer: the hex key, in memory only. Signing runs in native code (EIP-191 and EIP-712 in nativekey), so the
     * key never reaches the WebView (AND-K-c2, A-4).
     */
    @Volatile
    private var localKey: String = ""

    /** Called only with a key read from the native vault. */
    fun setNativeSigner(privateKeyHex: String) {
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

    fun clearNativeSigner() {
        localKey = ""
    }

    fun hasNativeSigner(): Boolean = localKey.isNotEmpty()

    /**
     * Compatibility alias for the application's voice path (PM decision, §38). It answers the same question as
     * [hasNativeSigner]: whether the native vault key is held in this session. It does not mean that a page holds a key.
     */
    @Deprecated(
        message = "Use hasNativeSigner(). The answer is about the native vault key, not a page key.",
        replaceWith = ReplaceWith("hasNativeSigner()"),
    )
    fun hasLocalSigner(): Boolean = hasNativeSigner()

    /** Retired: the module no longer sends a page-signing request. Kept so existing call sites compile. */
    fun setEmit(emit: ((JSONObject) -> Unit)?) = Unit

    /**
     * Request EIP-191 `personal_sign(message)`, signed in native code with the vault key. Without a key the completion
     * fails with [NO_KEY] at once, and nothing is sent to the page.
     */
    fun requestEip191(message: String, completion: (Result<String>) -> Unit) {
        val key = localKey
        if (key.isEmpty()) {
            completion(Result.failure(IllegalStateException(NO_KEY)))
            return
        }
        val p = ConetChatCryptoUtil.hexToBytes(key)
        val sig = try {
            p?.let { Eip191Signer.sign(it, message.toByteArray(Charsets.UTF_8)) }
        } finally {
            p?.fill(0)
        }
        completion(sig?.let { Result.success(it) } ?: Result.failure(IllegalStateException("sign_failed")))
    }

    /**
     * Compatibility shim for the application's voice path (PM decision, §38). It takes no key and opens no key path:
     * [timeoutMs] is ignored, because native signing answers at once, and the call delegates to [requestEip191].
     */
    @Suppress("UNUSED_PARAMETER")
    @Deprecated(
        message = "Native signing answers at once, so the timeout is ignored. Use requestEip191(message, completion).",
        replaceWith = ReplaceWith("requestEip191(message, completion)"),
    )
    fun requestEip191(message: String, timeoutMs: Long, completion: (Result<String>) -> Unit) {
        requestEip191(message, completion)
    }

    /**
     * Request an EIP-712 typed data signature, signed in native code with the vault key. Without a key the completion
     * fails with [NO_KEY] at once, and nothing is sent to the page.
     */
    fun requestEip712(typedData: JSONObject, completion: (Result<String>) -> Unit) {
        val key = localKey
        if (key.isEmpty()) {
            completion(Result.failure(IllegalStateException(NO_KEY)))
            return
        }
        val p = ConetChatCryptoUtil.hexToBytes(key)
        val sig = try {
            p?.let { Eip712.signTypedData(it, typedData) }
        } finally {
            p?.fill(0)
        }
        completion(sig?.let { Result.success(it) } ?: Result.failure(IllegalStateException("sign_failed")))
    }

    /** Retired: no page-signing request can be pending, so a page answer has nothing to resolve. Ignored. */
    fun fulfill(body: JSONObject) = Unit

    /** Retired: no page-signing request can be pending. Ignored. */
    fun cancelAll(reason: String = "destroyed") = Unit
}
