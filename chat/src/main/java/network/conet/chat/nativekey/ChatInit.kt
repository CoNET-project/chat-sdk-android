package network.conet.chat.nativekey

import org.json.JSONObject
import java.util.concurrent.atomic.AtomicBoolean

/**
 * `chatInit` phase 1 (draft r2.5.20 第 5 版, 第 1 节 and 1A): the pure rules and the G2 flow. The bridge does not register the name yet: the
 * table-T (70 names, pinned) and the no-key list (9 names) must be re-pinned by the interface owner first (71 and 10). Until then nothing here
 * is reachable from the bridge; the handler is a unit-tested unit only.
 *
 * Rules, in order:
 *  - Input: a credential field is `key_over_bridge_refused`; any field other than `type`, `reqId`, `workspace` is `bad_request`; `reqId` must be
 *    present; `workspace`, when given, is `default`.
 *  - Gate: G0 (no key) and G1 (not ready) answer `pending_confirm` and read or write nothing (draft 1A, 2).
 *  - G2: the single in-flight flow ([ChatInitFlight]); a second call while one runs answers `pending_confirm` without a read.
 *  - Recovery protection (draft 3, N-1): a failed-recovery counter above zero is `restore_failed`; nothing is generated or overwritten.
 *  - Otherwise the existing evaluation ([PgpRestoreMachine.evaluate], the same `evalRestore`) decides, and its UI state maps to a status.
 *    `unknown` never leaves the SDK: every unknown source is `pending_confirm`.
 *  - The result carries only the public whitelist; no private field name can appear.
 */
internal object ChatInitRules {
    const val NAME = "chatInit"
    const val RESULT_TYPE = "chatInitResult"
    const val DEFAULT_WORKSPACE = "default"

    const val READY = "ready"
    const val PENDING_CONFIRM = "pending_confirm"
    const val RESTORE_FAILED = "restore_failed"
    const val REGISTERING = "registering"
    const val ERROR = "error"

    const val BAD_REQUEST = "bad_request"
    const val KEY_REFUSED = "key_over_bridge_refused"

    /** Input names. Anything else is `bad_request`. */
    val INPUT_FIELDS: Set<String> = setOf("type", "reqId", "workspace")

    /** Public result names (draft 第 1 节 白名单). The builder never adds a name outside this set. */
    val PUBLIC_FIELDS: Set<String> = setOf("type", "reqId", "status", "eoa", "keyId", "publicKeyArmored", "registrationStatus", "code")

    /** Names that never appear in any answer or event (draft 第 1 节 禁止字段), in addition to the credential fields of the bridge. */
    val FORBIDDEN_FIELDS: Set<String> = NativeOpenRules.CREDENTIAL_FIELDS + setOf(
        "privateKeyArmor", "userPgpPrivateArmor", "pgpPrivateKeyArmored", "walletSignature", "armored", "backupCiphertext",
        "mnemonic", "passphrase", "pin", "pgpPassphrase",
    )

    /** The input check (draft 第 1 节 请求字段). Returns the error code, or `null` when the input is accepted. */
    fun inputError(fields: Collection<String>, reqId: Any?, workspace: Any?): String? {
        if (fields.any { it in FORBIDDEN_FIELDS }) return KEY_REFUSED
        if (fields.any { it !in INPUT_FIELDS }) return BAD_REQUEST
        if (reqId == null) return BAD_REQUEST
        if (workspace != null && workspace != DEFAULT_WORKSPACE) return BAD_REQUEST
        return null
    }

    /** G0 and G1 answer `pending_confirm` (the flow is not run). `null` at G2. */
    fun gateStatus(gate: NoKeyGate.Gate): String? = when (gate) {
        NoKeyGate.Gate.G0, NoKeyGate.Gate.G1 -> PENDING_CONFIRM
        NoKeyGate.Gate.G2 -> null
    }

    /**
     * The status of a UI state after the evaluation (draft 第 1 节, 第 4 节). `unknown` is not a status: every undetermined, blocked or first-identity
     * state is `pending_confirm` here (the first identity is not generated in phase 1).
     */
    fun statusOf(uiState: String, activeMatchesChain: Boolean): String = when (uiState) {
        "ok" -> if (activeMatchesChain) READY else PENDING_CONFIRM
        // Draft r2.5.20 第 7 版 4.2 and the status table: retry_ready is never registering; the flow retries it (see ChatInitFlow).
        "retry_ready" -> PENDING_CONFIRM
        "failed" -> RESTORE_FAILED
        else -> PENDING_CONFIRM
    }

    /** The status of an outcome after a flow step (a retry or a restore): a retryable write failure stays pending_confirm. */
    fun statusOfResult(uiState: String, uiCode: String?, activeMatchesChain: Boolean): String =
        if (uiState == "failed" && (uiCode == "write_failed" || uiCode == "write_reverted")) PENDING_CONFIRM else statusOf(uiState, activeMatchesChain)

    /** `registrationStatus` (`none` | `submitted` | `confirmed`) for a status. */
    fun registrationStatusOf(status: String): String = when (status) {
        READY -> "confirmed"
        REGISTERING -> "submitted"
        else -> "none"
    }

    /**
     * The `chatInitResult` event, built from the whitelist only. `code` appears only for `error`. `eoa`, `keyId` and `publicKeyArmored` appear
     * only when given. The caller passes public values; nothing else can be added.
     */
    fun resultPayload(reqId: Any, status: String, eoa: String? = null, keyId: String? = null, publicKeyArmored: String? = null, code: String? = null): JSONObject {
        val out = JSONObject().put("type", RESULT_TYPE).put("reqId", reqId).put("status", status)
        eoa?.let { out.put("eoa", it.lowercase()) }
        keyId?.let { out.put("keyId", it) }
        publicKeyArmored?.let { out.put("publicKeyArmored", it) }
        out.put("registrationStatus", registrationStatusOf(status))
        if (status == ERROR) out.put("code", code ?: BAD_REQUEST)
        return out
    }

    /** The synchronous ack: `{type, reqId, ok}`, with `error` only when not accepted. */
    fun ackPayload(reqId: Any?, error: String?): JSONObject {
        val out = JSONObject().put("type", "ack").put("reqId", reqId ?: JSONObject.NULL).put("ok", error == null)
        error?.let { out.put("error", it) }
        return out
    }
}

/** The single in-flight guard for `chatInit` (draft 第 5 节 单在途). Process-wide in production. */
internal class ChatInitFlight {
    private val busy = AtomicBoolean(false)

    /** `true` when this call may run; the caller must [exit] when it returns. */
    fun tryEnter(): Boolean = busy.compareAndSet(false, true)

    fun exit() {
        busy.set(false)
    }
}

/** The one in-flight guard of this process (draft 第 5 节): every chatInit call shares it, whatever machine it builds. */
internal object ChatInitProcess {
    val flight = ChatInitFlight()
}

/** The G2 flow: recovery protection, then the existing evaluation, then the status. Nothing is written to the chain. */
internal object ChatInitFlow {
    /**
     * The production entry (not registered in the bridge yet): the recovery protection comes from the stored path B failure counter (N-1), and the
     * in-flight guard is the process one. [store] is the counter; the machine is the production machine for [eoa].
     */
    fun runWithStore(machine: PgpRestoreMachine, devId: String, eoa: String, reqId: Any, store: RecoveryFailureStore, flight: ChatInitFlight): JSONObject =
        run(machine, devId, eoa, reqId, recoveryProtected = store.failures() > 0, flight = flight)

    /**
     * Runs the flow for [devId] of [eoa]. [recoveryProtected] is the N-1 counter (path_b_failures above zero). Returns the `chatInitResult` payload
     * without `reqId` handling; the caller adds the reqId through [ChatInitRules.resultPayload].
     */
    fun run(machine: PgpRestoreMachine, devId: String, eoa: String, reqId: Any, recoveryProtected: Boolean, flight: ChatInitFlight): JSONObject {
        if (!flight.tryEnter()) return ChatInitRules.resultPayload(reqId, ChatInitRules.PENDING_CONFIRM, eoa = eoa)
        try {
            if (recoveryProtected) return ChatInitRules.resultPayload(reqId, ChatInitRules.RESTORE_FAILED, eoa = eoa)
            machine.evaluate(devId)
            val dev = machine.devices.getValue(devId)
            var restored = false
            if (dev.ui.state == "retry_ready") {
                // Draft 4.2: chatInit triggers the retry itself, with the same pending key and idempotency key.
                machine.retryWrite(devId)
            } else if (dev.ui.state == "ok" && dev.active.state() is NativePgpVault.State.NoKey) {
                // Draft 4.3: the chain holds an identity whose backup decrypts and the active slot is empty: restore writes the empty slot only.
                machine.restore(devId)
                restored = true
            }
            val chainNow = machine.chainIdentityRead()
            val active = if (dev.active.state() is NativePgpVault.State.Ready) dev.active.identity() else null
            val matches = active != null && chainNow is IdentityRead.Present && chainNow.identity.sameAs(active)
            val status = when {
                restored && dev.ui.state == "ok" -> if (matches) ChatInitRules.READY else ChatInitRules.RESTORE_FAILED
                restored && (dev.ui.code == "write_failed" || dev.ui.code == "write_reverted") -> ChatInitRules.RESTORE_FAILED
                else -> ChatInitRules.statusOfResult(dev.ui.state, dev.ui.code, matches)
            }
            val keyId = if (status == ChatInitRules.READY) active?.subkeyKeyId else null
            return ChatInitRules.resultPayload(reqId, status, eoa = eoa, keyId = keyId)
        } finally {
            flight.exit()
        }
    }
}
