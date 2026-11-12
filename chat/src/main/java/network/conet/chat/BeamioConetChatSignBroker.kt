package network.conet.chat

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

    /** Local signer: hex key (memory only) and the host that runs ethers. */
    @Volatile
    private var localKey: String = ""
    @Volatile
    private var localHost: BeamioOpenPgpHost? = null

    /** Called only with a key read from the native vault. */
    fun setNativeSigner(host: BeamioOpenPgpHost?, privateKeyHex: String) {
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

    fun clearNativeSigner() {
        localKey = ""
        localHost = null
    }

    fun hasNativeSigner(): Boolean = localKey.isNotEmpty() && localHost != null

    /** Retired: the module no longer sends a page-signing request. Kept so existing call sites compile. */
    fun setEmit(emit: ((JSONObject) -> Unit)?) = Unit

    /**
     * Request EIP-191 `personal_sign(message)`. With a native key the host signs. Without one the completion
     * fails with [NO_KEY] at once, and nothing is sent to the page.
     */
    fun requestEip191(message: String, completion: (Result<String>) -> Unit) {
        val key = localKey
        val host = localHost
        if (key.isNotEmpty() && host != null) {
            host.signEip191(key, message, completion)
            return
        }
        completion(Result.failure(IllegalStateException(NO_KEY)))
    }

    /**
     * Request an EIP-712 typed data signature. With a native key the host signs. Without one the completion
     * fails with [NO_KEY] at once, and nothing is sent to the page.
     */
    fun requestEip712(typedData: JSONObject, completion: (Result<String>) -> Unit) {
        val key = localKey
        val host = localHost
        if (key.isNotEmpty() && host != null) {
            host.signEip712(key, typedData, completion)
            return
        }
        completion(Result.failure(IllegalStateException(NO_KEY)))
    }

    /** Retired: no page-signing request can be pending, so a page answer has nothing to resolve. Ignored. */
    fun fulfill(body: JSONObject) = Unit

    /** Retired: no page-signing request can be pending. Ignored. */
    fun cancelAll(reason: String = "destroyed") = Unit
}
