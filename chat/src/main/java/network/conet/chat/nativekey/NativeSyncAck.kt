package network.conet.chat.nativekey

import org.json.JSONObject

/**
 * The bridge answers of `pwaWalletSync` and `nativeMnemonicPreread` (r2.4.6 46(4) closed sets). Pure functions, so the module and the tests
 * share one mapping. Nothing here carries a phrase, except the `phrase` of a `valid` pre-read answer, which the page needs to restore its wallet.
 */
internal object NativeSyncAck {
    /** The external answers of `pwaWalletSync` (r2.4.8 R2): ok, stale_seq, write_failed, untrusted_source, bad_request. */
    const val OK = "ok"
    const val STALE_SEQ = "stale_seq"
    const val WRITE_FAILED = "write_failed"

    /**
     * The closed reasons of the write-failure envelope (interface PROTOCOL-srp04-write-failed-reason-and-android-correction-2026-11-22): internal_state,
     * storage_write, rollback_pending, old_copy_unverified. A reason outside this set, or none, is internal_state.
     */
    val WRITE_FAILURE_REASONS: Set<String> = setOf(INTERNAL_STATE, STORAGE_WRITE, ROLLBACK_PENDING_REASON, OLD_COPY_UNVERIFIED_REASON)

    /** The SRP-04 write-failure envelope `{type, reqId, ok:false, error:"write_failed", reason}` (reason at the top level, never in result). */
    fun writeFailedEnvelope(reqId: Any?, reason: String?): JSONObject =
        JSONObject().put("type", "ack").put("reqId", reqId ?: JSONObject.NULL).put("ok", false).put("error", WRITE_FAILED)
            .put("reason", reason?.takeIf { it in WRITE_FAILURE_REASONS } ?: INTERNAL_STATE)
    const val UNTRUSTED_SOURCE = "untrusted_source"

    /** The W-class answer of a payload that carries a credential field (59(1)(c)). */
    const val KEY_REFUSED = "key_over_bridge_refused"
    /** The cipher sync answers (the codes of the interface's closed set for pwaWalletSync). */
    const val VERIFY_FAILED = "verify_failed"
    const val UNLOCK_FAILED = "unlock_failed"
    /** Input the sender got wrong (a phrase that is not canonical, no sequence). Nothing is written. */
    const val BAD_REQUEST = "bad_request"

    /**
     * The shell sets `trustedOrigin: true` after its verified single-ZIP check (46(5)). Anything else is refused before any other check.
     * R3 (r2.4.8): the SDK checks that the marker is present and true; it does not judge whether the origin is genuine.
     *
     * Contract (next-version hardening noted): only the value the shell sets is trusted. Every page entry of
     * `pwaWalletSync`, `pwaEmptySignal` and `nativeMnemonicPreread` must strip the page's own `trustedOrigin` before the shell decides and
     * sets its verdict (the shell does this on all page entries, build). The SDK cannot tell a shell-set marker from a page-set one in
     * the JSON, so this contract is what keeps a page from passing the gate; a typed shell-only channel is a later version (not in this one).
     */
    fun trusted(body: JSONObject): Boolean = body.opt("trustedOrigin") == true

    /**
     * The untrusted refusal of a request, or null when the marker is present. Nothing is read or written on a refusal.
     * Contract: a missing marker, `false`, or any non-boolean value is refused. The SDK relies on the shell's stripping of the page's value (see [trusted]).
     */
    fun admit(body: JSONObject): String? = if (trusted(body)) null else UNTRUSTED_SOURCE

    /** A sync answer: a code of the closed set and, for a failure, a fixed reason word (R2, r2.4.8). */
    class SyncAnswer(val code: String, val reason: String?)

    /**
     * The reason words of a write_failed answer (r2.5.0 裁定, r2.4.9 G2): every write_failed carries one of exactly these two.
     * `internal_state`: a mapped internal state (not_ready, readback_failed, rollback_pending). `storage_write`: a plain store write failure.
     * Neither carries a phrase, key or path.
     */
    const val INTERNAL_STATE = "internal_state"
    const val STORAGE_WRITE = "storage_write"
    /** The two reasons added on 2026-11-18: an unverifiable old copy, and a rollback that did not finish. */
    const val OLD_COPY_UNVERIFIED_REASON = "old_copy_unverified"
    const val ROLLBACK_PENDING_REASON = "rollback_pending"

    /** The largest transaction sequence the SDK accepts: 2^53 - 1, the largest integer a JSON number carries exactly. */
    const val MAX_SEQ: Long = (1L shl 53) - 1

    /**
     * The transaction sequence of a request (shellTxSeq): a JSON integer (Int or Long as parsed; 1.0, 1e0, strings and missing values are
     * not integers here) in 0 .. 2^53 - 1, kept as Long. Anything else is null, and the caller answers bad_request.
     */
    fun seqOf(body: JSONObject): Long? {
        val v = when (val raw = body.opt("seq")) {
            is Int -> raw.toLong()
            is Long -> raw
            else -> return null
        }
        return if (v in 0L..MAX_SEQ) v else null
    }

    /** The optional `eoa` of a pwaWalletSync request (spec 59(1)(a), 2026-11-18): `0x` plus 40 lower-case hex digits. */
    private val EOA_FORMAT = Regex("0x[0-9a-f]{40}")

    /**
     * (3)(a) with the optional `eoa` (spec 59(1)(a), r3sa): when the request carries `eoa`, it must be well formed and equal the address
     * derived from the phrase, otherwise bad_request and nothing is written. Absent `eoa` changes nothing (null). The caller passes the
     * derived address, never a key.
     */
    fun eoaRefusal(body: JSONObject, derivedEoa: String): String? {
        if (!body.has("eoa")) return null
        val raw = body.opt("eoa") as? String ?: return BAD_REQUEST
        if (!EOA_FORMAT.matches(raw)) return BAD_REQUEST
        return if (raw == derivedEoa) null else BAD_REQUEST
    }

    /**
     * G1 (r2.4.9): the request format is wrong, and only then, is it bad_request: the sequence is not a JSON integer, or the phrase does not
     * derive a key and an address. Returns the answer, or null when the request is well formed. Nothing is read or written on a refusal.
     */
    fun formatError(body: JSONObject, phrase: String): String? {
        if (seqOf(body) == null) return BAD_REQUEST
        val key = MnemonicDerivation.deriveKey(phrase) ?: return BAD_REQUEST
        key.fill(0)
        if (MnemonicDerivation.canonicalPhrase(phrase) == null) return BAD_REQUEST
        return null
    }

    /**
     * r2.4.8 49(1), r2.4.9 G2: the external answer is one of ok, stale_seq, write_failed, untrusted_source, bad_request. Every write_failed
     * carries `reason: internal_state`. An unconfirmed rollback is write_failed as well, and nothing is deleted or overwritten in that case
     * (the marker is kept). There is no separate unknown answer.
     */
    fun answerOf(outcome: NativeWalletVault.SyncOutcome): SyncAnswer = when (outcome) {
        NativeWalletVault.SyncOutcome.UPDATED, NativeWalletVault.SyncOutcome.IDEMPOTENT -> SyncAnswer(OK, null)
        NativeWalletVault.SyncOutcome.BAD_INPUT -> SyncAnswer(BAD_REQUEST, null)
        NativeWalletVault.SyncOutcome.WRITE_FAILED -> SyncAnswer(WRITE_FAILED, STORAGE_WRITE)
        // v3.2 §六 / SO-24: the wire reason is internal_state (a seal or read-back failure is an internal state on the wire).
        NativeWalletVault.SyncOutcome.SEALING_FAILED -> SyncAnswer(WRITE_FAILED, INTERNAL_STATE)
        NativeWalletVault.SyncOutcome.NOT_READY,
        NativeWalletVault.SyncOutcome.READBACK_FAILED,
        -> SyncAnswer(WRITE_FAILED, INTERNAL_STATE)
        // an unverifiable old copy is refused as old_copy_unverified (the page shows no retry for it); a rollback that did not
        // finish is rollback_pending. Both are write_failed on the wire.
        NativeWalletVault.SyncOutcome.OLD_COPY_UNVERIFIED -> SyncAnswer(WRITE_FAILED, OLD_COPY_UNVERIFIED_REASON)
        NativeWalletVault.SyncOutcome.ROLLBACK_PENDING -> SyncAnswer(WRITE_FAILED, ROLLBACK_PENDING_REASON)
    }

    /** The external code of an outcome (the closed set). */
    fun codeOf(outcome: NativeWalletVault.SyncOutcome): String = answerOf(outcome).code

    /** The `result.sync` label of a plaintext sync that left the v3 ciphertext of the same account untouched. */
    const val SYNC_UNCHANGED = "unchanged"

    /** The log line of that case: the outcome word only, never a phrase or a path. */
    fun unchangedLogLine(): String = "pwaWalletSync sync=$SYNC_UNCHANGED"

    /** The `result.sync` label of a successful outcome. */
    fun syncLabel(outcome: NativeWalletVault.SyncOutcome): String? = when (outcome) {
        NativeWalletVault.SyncOutcome.UPDATED -> "updated"
        NativeWalletVault.SyncOutcome.IDEMPOTENT -> "idempotent"
        else -> null
    }

    /** The log line of a refused sync (untrusted, bad format): the answer code only. Used by the module's Log call and by the log-scan tests. */
    fun refusedLogLine(code: String): String = "pwaWalletSync refused: $code"

    /** The log line of a stale sync: no sequence, no phrase. */
    fun staleLogLine(): String = "pwaWalletSync outcome=STALE"

    /** The log line of a pre-read reply: the ok flag only, never the phrase. */
    fun prereadLogLine(ok: Boolean): String = "nativeMnemonicPreread ok=$ok"

    /** The one-line log of a sync: the outcome name only. */
    fun logLine(outcome: NativeWalletVault.SyncOutcome): String = "pwaWalletSync outcome=${outcome.name}"

    /**
     * PV-05 (r2.5.7 46(7)): the `nativeMnemonicPreread` reply. The request must carry the shell's trustedOrigin marker, and only then is the
     * pre-read read: an untrusted request answers ok:false with untrusted_source and carries no phrase (the read is not called). Authenticity is
     * the shell's PageSyncGate; the SDK checks the marker only.
     */
    fun prereadPayload(reqId: Any?, body: JSONObject, answer: () -> MnemonicPreread.Answer): JSONObject {
        val payload = JSONObject().put("type", "ack").put("reqId", reqId ?: JSONObject.NULL)
        // r2.5.19 60(3), in this order; the first that matches answers. The phrase is returned only when all three pass.
        //  (a) trustedOrigin missing or not true: untrusted_source, nothing read.
        admit(body)?.let { return payload.put("ok", false).put("error", it) }
        //  (b) the credential check (59(1)(c)): no key-like field; the pre-read has no field of its own besides seq.
        credentialRefusal(body, allowedField = null)?.let { return payload.put("ok", false).put("error", it) }
        // E6-4 NE-06 (E1): the phrase is a credential field of pwaWalletSync only; a pre-read request that carries it is refused before any read.
        if (body.has("phrase")) return payload.put("ok", false).put("error", KEY_REFUSED)
        //  (c) seq missing, not an integer literal, or above 2^53 - 1: bad_request.
        if (seqOf(body) == null) return payload.put("ok", false).put("error", BAD_REQUEST)
        //  (d) seq older than the newest accepted sequence: stale_seq, before the state is looked at. The pre-read compares only; it does not
        //      move the ledger (60(4)).
        if (seqOf(body)!! < MnemonicPreread.latestAcceptedSeq()) return payload.put("ok", false).put("error", STALE_SEQ)
        //  (e) the state answer. valid carries eoa and phrase (59(2)(a)); absent and unknown carry only the state.
        return payload.put("ok", true).put("result", prereadResult(answer()))
    }

    /**
     * The W-class refusal (59(1)(c), 25.41.3, 25.52AQ.2): a credential or key field in the payload, other than [allowedField], answers
     * key_over_bridge_refused. Only the field name is considered, never the value, and nothing is echoed.
     */
    fun credentialRefusal(body: JSONObject, allowedField: String?): String? {
        val keys = body.keys()
        while (keys.hasNext()) {
            val k = keys.next()
            if (k == allowedField) continue
            if (isCredentialField(k)) return KEY_REFUSED
        }
        return null
    }

    /** The same check with a set of allowed names (the cipher sync allows phrase, cipher and passcode; other credential names are still refused). */
    fun credentialRefusal(body: JSONObject, allowed: Set<String>): String? {
        val keys = body.keys()
        while (keys.hasNext()) {
            val k = keys.next()
            if (k in allowed) continue
            if (isCredentialField(k)) return KEY_REFUSED
        }
        return null
    }

    /**
     * The credential-class names: the 25.41.3 list (including eoaPrivateKey, 25.52Y.38 第 8 项, 8848), the identity forbidden list, and the exact
     * secret names of the key-shape scan (r3bk, 25.52O.2: seed, recoveryPhrase, duplicatePassword, duplicateMnemonicPhrase, duplicateCode,
     * _duplicateCode). The prefix families of the key-shape scan (privateKey*, mnemonic*, pgpPrivate*, pgpPassphrase*) are refused too.
     */
    private val CREDENTIAL_NAMES: Set<String> = NativeOpenRules.CREDENTIAL_FIELDS +
        setOf("eoaPrivateKey", "seed", "recoveryPhrase", "duplicatePassword", "duplicateMnemonicPhrase", "duplicateCode", "_duplicateCode") +
        network.conet.chat.identity.IdentityProvisionContract.FORBIDDEN_KEYS.toSet()

    private val CREDENTIAL_PREFIXES: List<String> = listOf("privatekey", "mnemonic", "pgpprivate", "pgppassphrase")

    /** True when [name] is a credential-class field name (case-insensitive; the value is not read). */
    fun isCredentialField(name: String): Boolean {
        val lower = name.lowercase()
        return CREDENTIAL_NAMES.any { it.lowercase() == lower } || CREDENTIAL_PREFIXES.any { lower.startsWith(it) }
    }

    /**
     * The `nativeMnemonicPreread` reply from the two-state store (step (2), 2026-11-22). The same checks as [prereadPayload]
     * (trusted origin, no credential field, no phrase in the request, a seq that is not stale); then the store's current record is returned as
     * the code shape: `result {code: ok | confirmed_missing | read_error, ...}` (PrereadStoreAnswer). No passphrase, no unlock, no init wait.
     * A read that cannot be completed is read_error, never confirmed_missing. No state shape is returned.
     */
    fun prereadStorePayload(
        reqId: Any?,
        body: JSONObject,
        vault: () -> PrereadStoreAnswer.VaultSource = { PrereadStoreAnswer.VaultSource.NoKey },
        onDiag: (String) -> Unit = {},
        current: () -> MnemonicSetStore.Current,
    ): JSONObject {
        val payload = JSONObject().put("type", "ack").put("reqId", reqId ?: JSONObject.NULL)
        admit(body)?.let { return payload.put("ok", false).put("error", it) }
        credentialRefusal(body, allowedField = null)?.let { return payload.put("ok", false).put("error", it) }
        if (body.has("phrase")) return payload.put("ok", false).put("error", KEY_REFUSED)
        if (seqOf(body) == null) return payload.put("ok", false).put("error", BAD_REQUEST)
        if (seqOf(body)!! < MnemonicPreread.latestAcceptedSeq()) return payload.put("ok", false).put("error", STALE_SEQ)
        val result = try {
            val r = PrereadStoreAnswer.answerWithVault(current()) { try { vault() } catch (_: Exception) { PrereadStoreAnswer.VaultSource.Unreadable } }
            r.diag?.let(onDiag)
            // NP-16: a store and vault EOA mismatch is reported at the top level of the reply (the answer itself is the store's).
            r.diag?.let { payload.put("diagnostic", it) }
            r.answer
        } catch (_: Exception) {
            JSONObject().put("code", "read_error")
        }
        return payload.put("ok", true).put("result", result)
    }

    /** The `nativeMnemonicPreread` answer: `valid`, `absent` or `unknown`. Never an empty result. */
    fun prereadResult(answer: MnemonicPreread.Answer): JSONObject = when (answer) {
        // The code shape (vectors v2 292b53de): the mnemonic is returned only with ok; no eoa, no state field.
        is MnemonicPreread.Answer.Valid -> JSONObject().put("code", "ok").put("mnemonic", answer.phrase)
        is MnemonicPreread.Answer.Absent -> JSONObject().put("code", "confirmed_missing")
        is MnemonicPreread.Answer.Unknown -> JSONObject().put("code", "read_error")
    }
}
