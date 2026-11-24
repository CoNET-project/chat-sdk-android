package network.conet.chat.nativekey

import android.content.Context
import org.json.JSONObject
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.Executors

/**
 * The native account-creation page (spec r3w §25.46). `nativeAccountCreateOpen` opens it in G0 only; the decision is
 * [NativeOpenRules.accountCreateOpen]. The shell sets [launcher] to show its page, and calls [NativeAccountCreate.confirm]
 * when the user confirms, and [pageClosed] when the page closes. Not registered is `not_supported`; registered but refused
 * is `not_available`. The page itself is the shell's. Nothing it shows or types passes through the bridge.
 */
object NativeAccountCreateHost {
    @Volatile
    var launcher: (() -> Boolean)? = null

    /** Set by the module, so results go out through the chat module event envelope. */
    @Volatile
    internal var events: ((JSONObject) -> Unit)? = null

    /** The verdict on one reported result that the SDK did not forward (§25.50.3). Only [reason] and [fields] may be logged. */
    class Drop(val reason: String, val fields: List<String> = emptyList())

    /** The `reqId` of the open page, or `null` when no page is open. Set by [open], cleared by `ok` or by the page closing. */
    @Volatile
    private var pageReqId: Any? = null

    /** A native result for this page has arrived, forwarded or dropped. Then a close sends nothing more (§25.50.5, NC-06, NC-16). */
    @Volatile
    private var resultSeen = false

    /**
     * The `reqId`s that have a final answer (r3kn, r3la, §25.46.2): `ok`, `cancelled` (the page closed with no result), `already_bound`, and
     * `lookup_unavailable`. A later delivery of one of them is `not_available`. The set is not cleared when another page opens (N-42).
     */
    private val completed = mutableSetOf<String>()

    /** The `reqId` whose binding lookup is in flight (r3kl, M-1): another `reqId` is refused until it is answered. */
    private var queryKey: String? = null

    /** The admission of one open request (§25.46.2): a lookup may start, the open page is the same request, or the request is refused. */
    enum class Admission { LOOKUP, SAME_PAGE, REFUSED }

    /**
     * Admits one open request before its lookup. A completed `reqId` is refused; while a page is open, the same `reqId` is that page (N-31) and any
     * other is refused (N-32); while a lookup is in flight, every request is refused (N-39, N-41). Otherwise the lookup may start and holds the slot.
     */
    @Synchronized
    internal fun admit(reqId: Any): Admission {
        val k = keyOf(reqId)
        if (k in completed) return Admission.REFUSED
        pageReqId?.let { return if (keyOf(it) == k) Admission.SAME_PAGE else Admission.REFUSED }
        if (queryKey != null) return Admission.REFUSED
        queryKey = k
        return Admission.LOOKUP
    }

    /**
     * The answer of a lookup (or its failure, [code] null) releases the slot. An answer that is final completes the `reqId`.
     */
    @Synchronized
    internal fun settle(reqId: Any, code: String?) {
        val k = keyOf(reqId)
        if (queryKey == k) queryKey = null
        if (code == "already_bound" || code == "lookup_unavailable") completed += k
    }

    /** The key of a reqId in the completed set and the slot: the type is part of it, so the number 1 and the string "1" are different requests. */
    private fun keyOf(reqId: Any): String = when (reqId) {
        is Int, is Long -> "n:$reqId"
        else -> "s:$reqId"
    }

    /** Tests only: the state of the host is cleared, so each case starts from a fresh host. */
    @Synchronized
    internal fun resetForTests() {
        pageReqId = null
        resultSeen = false
        completed.clear()
        queryKey = null
    }

    private val ALLOWED_FIELDS = setOf("type", "reqId", "code", "eoa", "cleanupPending")
    private val RESULT_CODES = setOf("ok", "cancelled", "already_exists", "write_failed", "readback_failed")
    private val CANONICAL_EOA = Regex("^0x[0-9a-f]{40}$")

    /** `nativeAccountCreateOpen` (§25.46.2): `true` when the page is open. The `reqId` is kept for the result. */
    @Synchronized
    internal fun open(reqId: Any): Boolean {
        val show = launcher ?: return false
        pageReqId = reqId
        resultSeen = false
        val opened = try {
            show()
        } catch (_: Exception) {
            false
        }
        if (!opened) {
            pageReqId = null
            return false
        }
        return true
    }

    /** `true` while a page is open and its result is still pending. */
    @Synchronized
    internal fun isPageOpen(): Boolean = pageReqId != null

    /**
     * A result reported by the shell's page (§25.50.3). Forwards `{type, reqId, code, eoa?}` built from the checked fields, or
     * returns the [Drop]. Checks, in order: the page is open; `type` and `reqId` match the open page (a mismatch does not count
     * as this page's result); the fields are on the whitelist; the code is one of the five; `eoa` is present only for `ok`, and
     * is lowercase `0x` plus 40 hex digits. `ok` ends the page. Any other result keeps it open for a retry (§25.46.6).
     */
    @Synchronized
    fun report(event: JSONObject): Drop? {
        val id = pageReqId ?: return Drop("no_page")
        if (event.optString("type", "") != "nativeAccountCreateResult") return Drop("type_mismatch")
        val got = event.opt("reqId")
        if (got == null || got != id) return Drop("reqid_mismatch")
        resultSeen = true
        val extra = event.keys().asSequence().map { it.toString() }.filter { it !in ALLOWED_FIELDS }.toList().sorted()
        if (extra.isNotEmpty()) return Drop("field_not_allowed", extra)
        val code = event.optString("code", "")
        if (code !in RESULT_CODES) return Drop("unknown_code")
        val hasEoa = event.has("eoa")
        if (code == NativeAccountCreate.Code.OK.wire) {
            if (!hasEoa) return Drop("eoa_invalid")
            val eoa = event.optString("eoa", "")
            if (!CANONICAL_EOA.matches(eoa)) return Drop("eoa_invalid")
            forward(id, code, eoa, event.optBoolean("cleanupPending", false))
            completed += keyOf(id)
            pageReqId = null
            resultSeen = false
            return null
        }
        // 25.52Y.137 第 6 項: the account of an already_exists answer is carried; any other failure answer carries no eoa.
        val eoaOut = if (hasEoa && code == NativeAccountCreate.Code.ALREADY_EXISTS.wire) {
            val e = event.optString("eoa", "")
            if (!CANONICAL_EOA.matches(e)) return Drop("eoa_invalid")
            e
        } else {
            if (hasEoa) return Drop("eoa_not_allowed")
            null
        }
        forward(id, code, eoaOut, null)
        return null
    }

    /** The page was closed. Sends `cancelled` when no result was produced for this page (§25.46.6, §25.50.5). */
    @Synchronized
    fun pageClosed() {
        val id = pageReqId ?: return
        if (!resultSeen) {
            // A cancelled creation ends its creation transaction (the key is not created, so no copy is written for it).
            ShellRecordState.creationTxn.set(false)
            forward(id, NativeAccountCreate.Code.CANCELLED.wire, null, null)
            completed += keyOf(id)
        }
        pageReqId = null
        resultSeen = false
    }

    /** The engine's own result for the open page. It goes through the same checks as a result from the shell. */
    @Synchronized
    internal fun finish(code: NativeAccountCreate.Code, eoa: String?, cleanupPending: Boolean = false) {
        val id = pageReqId ?: return
        if (code == NativeAccountCreate.Code.NOT_READY) {
            // 25.52Y.140: not_ready is not an event. Nothing is pushed; the page stays open and no nativeAccountCreateResult is sent for it.
            return
        }
        val event = JSONObject().put("type", "nativeAccountCreateResult").put("reqId", id).put("code", code.wire)
        if (eoa != null) event.put("eoa", eoa)
        if (code == NativeAccountCreate.Code.OK) event.put("cleanupPending", cleanupPending)
        report(event)
    }

    /**
     * 25.52Y.137 第 6 項: `{type, reqId, ok, result: {code, eoa?, cleanupPending?}}`. `eoa` only for `already_exists` and `ok`; `cleanupPending` only
     * when `ok` is true (true while the marker removal is pending, false when it is complete).
     */
    private fun forward(id: Any, code: String, eoa: String?, cleanupPending: Boolean?) {
        val result = JSONObject().put("code", code)
        if (eoa != null && (code == NativeAccountCreate.Code.OK.wire || code == NativeAccountCreate.Code.ALREADY_EXISTS.wire)) result.put("eoa", eoa)
        if (code == NativeAccountCreate.Code.OK.wire && cleanupPending != null) result.put("cleanupPending", cleanupPending)
        val payload = JSONObject()
            .put("type", "nativeAccountCreateResult")
            .put("reqId", id)
            .put("ok", code == NativeAccountCreate.Code.OK.wire)
            .put("result", result)
        events?.invoke(payload)
    }
}

/**
 * Creation of the account key in native code (spec r3w §25.46.5). The phrase is generated, derived and dropped inside this
 * object. Only the code and the public address leave it. Nothing is stored, shown or logged except the key, which goes into
 * the vault through its write, readback and rollback.
 */
object NativeAccountCreate {
    enum class Code(val wire: String) {
        OK("ok"),
        CANCELLED("cancelled"),
        ALREADY_EXISTS("already_exists"),
        WRITE_FAILED("write_failed"),
        READBACK_FAILED("readback_failed"),
        ROLLBACK_PENDING("rollback_pending"),
        /** Not decided: the wrap is unconfirmed (25.52Y.136 第 7 項). Retryable. */
        NOT_READY("not_ready"),
    }

    /**
     * [residue] is true when the creation failed and the K item that was written could not be removed: a half PGP item may remain on the device for
     * an account that has no wallet. The code stays write_failed; the caller records the residue (code only, never the key) for a later sweep.
     */
    class Result(val code: Code, val eoa: String? = null, val residue: Boolean = false, val cleanupPending: Boolean = false)

    private val worker = Executors.newSingleThreadExecutor()

    /**
     * The user confirmed on the page (§25.46.5 step 1). Creates the key on a worker thread, reports the result to
     * [NativeAccountCreateHost], then calls [onResult]. The page stays open unless the code is `ok`.
     */
    fun confirm(context: Context, onResult: (Result) -> Unit = {}) {
        val app = context.applicationContext
        worker.execute {
            val result = try {
                // The guard runs again at confirm: the legacy report, pointer, page copies or key may have changed since
                // the page opened. A denial writes nothing and answers write_failed, the only code that says nothing was stored.
                val denial = AccountCreateGuard.denial(AccountCreateGuard.inputsFor(app))
                // The denial code is not logged here: this file is under the no-log rule (KeyPathGuardTest).
                if (denial != null) {
                    Result(Code.WRITE_FAILED)
                } else {
                    // The explicit creation transaction starts here (25.52Y.54 PY.18(b)): the first page copy write is the creation write.
                    ShellRecordState.creationTxn.set(true)
                    create(NativeWallet.vault(app))
                }
            } catch (_: Exception) {
                Result(Code.WRITE_FAILED)
            }
            if (result.code != Code.OK) ShellRecordState.creationTxn.set(false)
            NativeAccountCreateHost.finish(result.code, result.eoa, result.cleanupPending)
            onResult(result)
        }
    }

    /**
     * Creates and stores a new account (steps 2 to 4): the wallet W only. No PGP key is generated here and no
     * K is written; the account's first PGP identity is made by [FirstIdentityCoordinator] after init, and only when the chain confirms no record
     *. A record that already exists is never overwritten. The caller's [entropy] is copied and zeroed; so are the derived key and the copy.
     */
    internal fun create(vault: NativeWalletVault, entropy: ByteArray = randomEntropy()): Result {
        val e = entropy.copyOf()
        try {
            if (vault.state() !is NativeWalletVault.State.NoKey) return Result(Code.ALREADY_EXISTS, vault.publicEoaIfReadable())
            val phrase = phraseOf(e)
            val key = MnemonicDerivation.deriveKey(phrase) ?: return Result(Code.WRITE_FAILED)
            try {
                val eoa = WalletAddress.fromPrivateKey(key) ?: return Result(Code.WRITE_FAILED)
                // r3nw 第 1 项: the account keeps the phrase its entropy spells (12 words, m/44'/60'/0'/0/0); the phrase is sealed
                // beside the key and is never returned from here.
                return when (vault.importMnemonicKey(eoa, key, phrase, NativeWalletVault.SOURCE_NATIVE_CREATE)) {
                    NativeWalletVault.Import.OK -> Result(Code.OK, eoa)
                    NativeWalletVault.Import.OK_CLEANUP_PENDING -> Result(Code.OK, eoa, cleanupPending = true)
                    NativeWalletVault.Import.ALREADY_PRESENT, NativeWalletVault.Import.RECORD_EXISTS ->
                        Result(Code.ALREADY_EXISTS, vault.publicEoaIfReadable())
                    NativeWalletVault.Import.READBACK_FAILED -> Result(Code.READBACK_FAILED)
                    // v2 §三 seal and readback reasons: only the sync path produces them; a failed write on this path.
                    NativeWalletVault.Import.SEALING_FAILED -> Result(Code.WRITE_FAILED)
                    // 25.52Y.138 第 4 項: rollback_pending is not sent outbound by account creation; it is write_failed.
                    NativeWalletVault.Import.ROLLBACK_PENDING -> Result(Code.WRITE_FAILED)
                    // Only the sync path (requireOpenable) produces it: a failed write on this path.
                    NativeWalletVault.Import.OLD_COPY_UNVERIFIED -> Result(Code.WRITE_FAILED)
                    // Store failures roll back inside the vault. A derived key that the vault refuses is treated the same:
                    // nothing was stored.
                    // wrap_key_missing (25.52Y.124): nothing was written. No wire code is defined for it yet; reported as a failed write.
                    NativeWalletVault.Import.STORE_FAILED, NativeWalletVault.Import.BAD_KEY,
                    NativeWalletVault.Import.BAD_EOA, NativeWalletVault.Import.ADDRESS_MISMATCH,
                    -> Result(Code.WRITE_FAILED)
                    // Not decided: nothing was written; not_ready (25.52Y.136 第 7 項).
                    NativeWalletVault.Import.WRAP_KEY_MISSING -> Result(Code.NOT_READY)
                }
            } finally {
                key.fill(0)
            }
        } finally {
            e.fill(0)
        }
    }

    /**
     * BIP-39 encoding of 16 bytes of entropy: 12 words, the last 4 bits being the first bits of SHA-256(entropy) (§25.26.1).
     * Only the phrase's derived key is used afterwards. The JVM string cannot be zeroed (same limit as MnemonicDerivation).
     */
    internal fun phraseOf(entropy: ByteArray): String {
        require(entropy.size == 16) { "entropy must be 16 bytes" }
        val checksum = MessageDigest.getInstance("SHA-256").digest(entropy)[0].toInt() and 0xff
        val bits = IntArray(132)
        for (i in 0 until 128) bits[i] = (entropy[i / 8].toInt() shr (7 - i % 8)) and 1
        for (i in 0 until 4) bits[128 + i] = (checksum shr (7 - i)) and 1
        return (0 until 12).joinToString(" ") { w ->
            var index = 0
            for (b in 0 until 11) index = (index shl 1) or bits[w * 11 + b]
            Bip39English.WORDS[index]
        }
    }

    private fun randomEntropy(): ByteArray = ByteArray(16).also { SecureRandom().nextBytes(it) }
}
