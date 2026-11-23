package network.conet.chat

import network.conet.chat.nativekey.NativeWalletVault

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
    /** Answer for a signing request made while no native key is held, and the vault state confirms there is no key. */
    const val NO_KEY = "no_key"
    /** The vault is locked. */
    const val LOCKED = "locked"
    /** Unreadable, not loaded, or a read failed: unknown, retryable. Never `no_key` (v187 §207.1). */
    const val NOT_READY = "not_ready"

    /**
     * The answer when no key is held, decided by the vault state (not by the session alone). Set by the module, which holds the context. Until it is
     * set, and if it throws, the answer is not_ready (fail closed).
     */
    @Volatile
    private var absentAnswer: () -> String = { NOT_READY }

    fun setAbsentAnswer(provider: () -> String) {
        absentAnswer = provider
    }

    /** The answer for a vault state with no held key: `no_key` only when the state confirms there is no key; `locked` when locked; otherwise not_ready. */
    internal fun absentAnswerOf(state: NativeWalletVault.State): String = when (state) {
        NativeWalletVault.State.NoKey -> NO_KEY
        is NativeWalletVault.State.Locked -> LOCKED
        is NativeWalletVault.State.Ready -> NOT_READY
    }

    /** The answer for a published snapshot: null (not known yet) is not_ready, never a read on the caller's thread. */
    internal fun absentAnswerOfSnapshot(state: NativeWalletVault.State?): String = state?.let { absentAnswerOf(it) } ?: NOT_READY

    private fun absent(): String = runCatching { absentAnswer() }.getOrDefault(NOT_READY)

    /**
     * Local signer: the private key bytes (32), in memory only, zeroed at every clear (spec: no String residence of a private key, T-49).
     * Signing runs in native code (EIP-191 and EIP-712 in nativekey), so the key never reaches the WebView (AND-K-c2, A-4).
     */
    @Volatile
    private var localKey: ByteArray? = null

    /** Called only with a key read from the native vault. The argument is copied; the caller clears its own buffer. */
    @Synchronized
    fun setNativeSigner(privateKey: ByteArray) {
        val held = privateKey.copyOf()
        val previous = localKey
        localKey = held
        previous?.fill(0)
    }

    /**
     * R_db for the local DB, derived here inside the wallet boundary from the in-memory private key
     * (spec v1.1-r1 22.2). The key itself never leaves this object. Null when no local key is held.
     */
    @Synchronized
    fun deriveLocalRoot(eoa: String, workspace: String): ByteArray? {
        val key = localKey ?: return null
        val p = key.copyOf()
        try {
            return network.conet.chat.localread.LocalChatIds.rootDbFromPrivateKey(p, eoa.lowercase(), workspace)
        } finally {
            p.fill(0)
        }
    }

    /** Lock and session clear: the held key is zeroed in place, then the reference is dropped. */
    @Synchronized
    fun clearNativeSigner() {
        localKey?.fill(0)
        localKey = null
    }

    fun hasNativeSigner(): Boolean = localKey != null

    /**
     * Compatibility alias for the application's voice path (§38). It answers the same question as
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
        if (key == null) {
            completion(Result.failure(IllegalStateException(absent())))
            return
        }
        val p = key.copyOf()
        val sig = try {
            Eip191Signer.sign(p, message.toByteArray(Charsets.UTF_8))
        } finally {
            p.fill(0)
        }
        completion(sig?.let { Result.success(it) } ?: Result.failure(IllegalStateException("sign_failed")))
    }

    /**
     * Compatibility shim for the application's voice path (§38). It takes no key and opens no key path:
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
        if (key == null) {
            completion(Result.failure(IllegalStateException(absent())))
            return
        }
        val p = key.copyOf()
        val sig = try {
            Eip712.signTypedData(p, typedData)
        } finally {
            p.fill(0)
        }
        completion(sig?.let { Result.success(it) } ?: Result.failure(IllegalStateException("sign_failed")))
    }

    /** Retired: no page-signing request can be pending, so a page answer has nothing to resolve. Ignored. */
    fun fulfill(body: JSONObject) = Unit

    /** Retired: no page-signing request can be pending. Ignored. */
    fun cancelAll(reason: String = "destroyed") = Unit
}
