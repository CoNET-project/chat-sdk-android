package network.conet.chat.nativekey

import org.json.JSONArray
import org.json.JSONObject

/**
 * The bridge answers for the derivation commands (spec §25.3 W2 to W4, §25.15.3 C5, §25.43.3 and §25.43.7). The module unlocks
 * the account key and passes it here; this object returns only the values the spec allows across the bridge. The key bytes are
 * not kept, logged or returned.
 *
 * Errors: `bad_request` (format), `account_mismatch` (the account is not the vault's), `locked` (the key is not unlocked),
 * `not_ready` with reason `unreadable` (the wallet state or the unlock cannot be read: unknown, never locked, 25.52Y.84),
 * `unknown_channel` (W7 has no temporary key for the session), `not_supported` (C1 is in-process only, §25.43.3).
 */
internal object NativeDerivationCommands {
    const val BAD_REQUEST = "bad_request"
    const val ACCOUNT_MISMATCH = "account_mismatch"
    const val LOCKED = "locked"
    const val NOT_READY = "not_ready"
    const val UNKNOWN_CHANNEL = "unknown_channel"
    const val NOT_SUPPORTED = "not_supported"

    /** The reason of a `not_ready` answer when the wallet state or the unlock cannot be read (25.52Y.84). A code, never key material. */
    const val UNREADABLE = "unreadable"

    /** W4: at most 64 `(seq, prevCid)` pairs per call (§25.3, §25.43.5). */
    const val MAX_BATCH = 64

    /** W4 (r3cb, §25.43.5): zero pairs is `bad_batch`. */
    const val BAD_BATCH = "bad_batch"

    /** W4 (r3cb, §25.43.5): more than [MAX_BATCH] pairs refuses the whole batch, with no truncation and no partial derivation. */
    const val BATCH_TOO_LARGE = "batch_too_large"

    private const val WORKSPACE = "default"
    private val EOA_RE = Regex("^0x[0-9a-f]{40}$")

    /** The decision: [error] is null for ok. [reason] is set only with a `not_ready` error. */
    class Outcome(val error: String?, val result: JSONObject?, val reason: String? = null) {
        val ok: Boolean get() = error == null

        companion object {
            fun ok(result: JSONObject) = Outcome(null, result)
            fun fail(code: String) = Outcome(code, null)
            fun notReady(reason: String) = Outcome(NOT_READY, null, reason)
        }
    }

    /**
     * The gate before a derivation reads the key (25.52Y.84). [state] returns null when reading the wallet state threw; [unlock]
     * returns null or throws when the key cannot be read (the caller maps a throw to null). A true lock (no key record, a record
     * that is not usable, a phrase only) is `locked`. A read that failed is unknown: `not_ready` with reason [UNREADABLE]. The key is
     * read only when the state is ready; [body] runs with it, and the key is zeroed after the call.
     */
    fun withKey(
        state: () -> NativeWalletVault.State?,
        unlock: () -> ByteArray?,
        body: (ByteArray, String) -> Outcome,
    ): Outcome {
        val s = state()
        if (s == null || (s is NativeWalletVault.State.Locked && s.reason == UNREADABLE)) return Outcome.notReady(UNREADABLE)
        if (s !is NativeWalletVault.State.Ready) return Outcome.fail(LOCKED)
        val key = unlock() ?: return Outcome.notReady(UNREADABLE)
        try {
            return body(key, s.eoa)
        } finally {
            key.fill(0)
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
        // r3cb: zero pairs is bad_batch; more than MAX_BATCH refuses the whole batch before any key is derived (no truncation).
        if (batch == null || batch.length() == 0) return Outcome.fail(BAD_BATCH)
        if (batch.length() > MAX_BATCH) return Outcome.fail(BATCH_TOO_LARGE)
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
        // The copy of T is zeroed on every path once the signature is made (2026-11-21).
        try {
            val signature = NativeDerivation.voiceListenSignature(tk, text) ?: return Outcome.fail(BAD_REQUEST)
            val temp = WalletAddress.fromPrivateKey(tk)?.lowercase() ?: return Outcome.fail(BAD_REQUEST)
            return Outcome.ok(JSONObject().put("temp", temp).put("tempSig", signature))
        } finally {
            tk.fill(0)
        }
    }
}

/**
 * The temporary voice keys T by session id (§25.43.7). The key stays here, not in the WebView, and is cleared when the session
 * ends (X-15). Nothing registers a key yet: the channel-creation command that generates T is not in the spec (see the receipt).
 */
internal object VoiceChannelKeys {
    /**
     * The longest a temporary key is kept, even when the call never ends cleanly (2026-11-21, to confirm: six hours). An entry older than this is
     * zeroed and removed when the store is next touched. A clock that has gone back before the registration is treated as expired (fail closed).
     */
    const val MAX_AGE_MS = 6L * 60 * 60 * 1000

    private class Entry(val key: ByteArray, val registeredAtMs: Long)

    private val keys = HashMap<String, Entry>()

    @Synchronized
    fun register(sid: String, temporaryKey: ByteArray, nowMs: Long = System.currentTimeMillis()) {
        sweep(nowMs)
        keys.put(sid, Entry(temporaryKey.copyOf(), nowMs))?.key?.fill(0)
    }

    /** A copy of the key of [sid], or null when there is none or it has expired. The caller zeroes the copy. */
    @Synchronized
    fun lookup(sid: String, nowMs: Long = System.currentTimeMillis()): ByteArray? {
        sweep(nowMs)
        return keys[sid]?.key?.copyOf()
    }

    /** Removes and zeroes the temporary key of [sid] when the call ends. Idempotent; nothing else is touched. */
    @Synchronized
    fun forget(sid: String) {
        keys.remove(sid)?.key?.fill(0)
    }

    @Synchronized
    fun clear() {
        for (e in keys.values) e.key.fill(0)
        keys.clear()
    }

    /** Zeroes and removes every entry that has expired, or whose registration is later than [nowMs] (clock rollback). */
    private fun sweep(nowMs: Long) {
        val it = keys.entries.iterator()
        while (it.hasNext()) {
            val e = it.next().value
            val age = nowMs - e.registeredAtMs
            if (age < 0 || age > MAX_AGE_MS) {
                e.key.fill(0)
                it.remove()
            }
        }
    }
}
