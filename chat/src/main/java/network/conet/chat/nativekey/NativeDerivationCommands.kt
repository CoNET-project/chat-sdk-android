package network.conet.chat.nativekey

import org.json.JSONArray
import org.json.JSONObject

/**
 * The bridge answers for the derivation commands (spec §25.3 W2 to W4, §25.15.3 C5, §25.43.3 and §25.43.7). The module unlocks
 * the account key and passes it here; this object returns only the values the spec allows across the bridge. The key bytes are
 * not kept, logged or returned.
 *
 * Errors: `bad_request` (format), `account_mismatch` (the account is not the vault's), `locked` (the key is not unlocked),
 * `unknown_channel` (W7 has no temporary key for the session), `not_supported` (C1 is in-process only, §25.43.3).
 */
internal object NativeDerivationCommands {
    const val BAD_REQUEST = "bad_request"
    const val ACCOUNT_MISMATCH = "account_mismatch"
    const val LOCKED = "locked"
    const val UNKNOWN_CHANNEL = "unknown_channel"
    const val NOT_SUPPORTED = "not_supported"

    /** W4: at most 64 `(seq, prevCid)` pairs per call (§25.3, §25.43.5). */
    const val MAX_BATCH = 64

    private const val WORKSPACE = "default"
    private val EOA_RE = Regex("^0x[0-9a-f]{40}$")

    /** The decision: [error] is null for ok. */
    class Outcome(val error: String?, val result: JSONObject?) {
        val ok: Boolean get() = error == null

        companion object {
            fun ok(result: JSONObject) = Outcome(null, result)
            fun fail(code: String) = Outcome(code, null)
        }
    }

    /**
     * The account the request names: `accountKey` must be `eoa:default` with a lower-case EOA (§25.43.2, D5). Returns the EOA,
     * or the error code.
     */
    private fun accountOf(accountKey: String, vaultEoa: String): Pair<String?, String?> {
        val cut = accountKey.lastIndexOf(':')
        if (cut < 0) return null to BAD_REQUEST
        val eoa = accountKey.substring(0, cut)
        val workspace = accountKey.substring(cut + 1)
        if (!EOA_RE.matches(eoa) || workspace != WORKSPACE) return null to BAD_REQUEST
        if (eoa != vaultEoa.lowercase()) return null to ACCOUNT_MISMATCH
        return eoa to null
    }

    /** C5 `deriveSubkeys` (bridge): the four children only (§25.43.6). */
    fun deriveSubkeys(key: ByteArray, accountKey: String, vaultEoa: String): Outcome {
        val (eoa, error) = accountOf(accountKey, vaultEoa)
        if (error != null) return Outcome.fail(error)
        val k = NativeDerivation.subkeys(key, eoa!!, WORKSPACE)
        return Outcome.ok(
            JSONObject()
                .put("kId", NativeDerivation.hex(k.kId))
                .put("kIdx", NativeDerivation.hex(k.kIdx))
                .put("dek", NativeDerivation.hex(k.dek))
                .put("kcv", k.kcv),
        )
    }

    /** W2 `deriveLocalKeys` (bridge): `{DEK, K_idx, K_id}` (§25.3). */
    fun deriveLocalKeys(key: ByteArray, accountKey: String, vaultEoa: String): Outcome {
        val (eoa, error) = accountOf(accountKey, vaultEoa)
        if (error != null) return Outcome.fail(error)
        val k = NativeDerivation.subkeys(key, eoa!!, WORKSPACE)
        return Outcome.ok(
            JSONObject()
                .put("DEK", NativeDerivation.hex(k.dek))
                .put("K_idx", NativeDerivation.hex(k.kIdx))
                .put("K_id", NativeDerivation.hex(k.kId)),
        )
    }

    /**
     * W3 `protocolKeys` (bridge): `{indexEncKey, genesisCid}` (§25.43.4). R_proto comes from C1 inside this call and is not returned.
     */
    fun protocolKeys(key: ByteArray, accountKey: String, vaultEoa: String): Outcome {
        val (eoa, error) = accountOf(accountKey, vaultEoa)
        if (error != null) return Outcome.fail(error)
        val signature = NativeDerivation.historySignature(key, eoa!!) ?: return Outcome.fail(LOCKED)
        val rProto = NativeDerivation.protocolRoot(signature)
        return Outcome.ok(
            JSONObject()
                .put("indexEncKey", NativeDerivation.hex(NativeDerivation.indexEncKey(rProto)))
                .put("genesisCid", NativeDerivation.genesisCid(rProto)),
        )
    }

    /**
     * W4 `fragmentKeys` (bridge): one key per `(seq, prevCid)`, at most [MAX_BATCH] pairs (§25.3, §25.43.5). `seq` is a
     * non-negative integer and `prevCid` a non-empty string used as given. The reply is `{fragKeys: [{seq, fragKey}]}`.
     */
    fun fragmentKeys(key: ByteArray, accountKey: String, batch: JSONArray?, vaultEoa: String): Outcome {
        val (eoa, error) = accountOf(accountKey, vaultEoa)
        if (error != null) return Outcome.fail(error)
        if (batch == null || batch.length() == 0 || batch.length() > MAX_BATCH) return Outcome.fail(BAD_REQUEST)
        val signature = NativeDerivation.historySignature(key, eoa!!) ?: return Outcome.fail(LOCKED)
        val rProto = NativeDerivation.protocolRoot(signature)
        val out = JSONArray()
        for (i in 0 until batch.length()) {
            val item = batch.optJSONObject(i) ?: return Outcome.fail(BAD_REQUEST)
            val seq = item.opt("seq")
            val prevCid = item.optString("prevCid", "")
            if (seq !is Int || seq < 0 || prevCid.isEmpty()) return Outcome.fail(BAD_REQUEST)
            out.put(
                JSONObject()
                    .put("seq", seq)
                    .put("fragKey", NativeDerivation.hex(NativeDerivation.fragmentKey(rProto, seq, prevCid))),
            )
        }
        return Outcome.ok(JSONObject().put("fragKeys", out))
    }

    /**
     * W7 `ephemeralSign` (bridge, §25.43.7): `sid`, `wk`, `relayKeyId`, `timestamp` in the request. Only `voiceListen`. The temporary
     * key T is found by `sid` in [VoiceChannelKeys]. The reply is `{temp, tempSig}`.
     */
    fun ephemeralSign(body: JSONObject): Outcome {
        val sid = body.optString("sid", "")
        val wk = body.optString("wk", "")
        val relayKeyId = body.optString("relayKeyId", "")
        val timestamp = body.opt("timestamp")
        val seconds = when (timestamp) {
            is Int -> timestamp.toLong()
            is Long -> timestamp
            else -> return Outcome.fail(BAD_REQUEST)
        }
        val text = NativeDerivation.voiceListenText(sid, wk, relayKeyId, seconds) ?: return Outcome.fail(BAD_REQUEST)
        val tk = VoiceChannelKeys.lookup(sid) ?: return Outcome.fail(UNKNOWN_CHANNEL)
        val signature = NativeDerivation.voiceListenSignature(tk, text) ?: return Outcome.fail(BAD_REQUEST)
        val temp = WalletAddress.fromPrivateKey(tk)?.lowercase() ?: return Outcome.fail(BAD_REQUEST)
        return Outcome.ok(JSONObject().put("temp", temp).put("tempSig", signature))
    }
}

/**
 * The temporary voice keys T by session id (§25.43.7). The key stays here, not in the WebView, and is cleared when the session
 * ends (X-15). Nothing registers a key yet: the channel-creation command that generates T is not in the spec (see the receipt).
 */
internal object VoiceChannelKeys {
    private val keys = HashMap<String, ByteArray>()

    @Synchronized
    fun register(sid: String, temporaryKey: ByteArray) {
        keys.put(sid, temporaryKey.copyOf())?.fill(0)
    }

    @Synchronized
    fun lookup(sid: String): ByteArray? = keys[sid]?.copyOf()

    @Synchronized
    fun clear() {
        for (k in keys.values) k.fill(0)
        keys.clear()
    }
}
