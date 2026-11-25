package network.conet.chat.nativekey

import org.json.JSONObject

/**
 * Gate for every bridge name (spec §25.26.4, §25.26.4c, r3g and r3h). The module asks it before any dispatch and
 * before any payload is read. The payload is never read here.
 *
 * Order (25.26.4c): X-21 names answer `not_supported` in every state. Allowed names and the two status queries follow
 * table D. Other names depend on the gate:
 *  - G0 (no native record): `no_key`.
 *  - G1 (a record, this session not initialised): `init` checks the EOA against the record; every other name answers
 *    `not_ready`.
 *  - G2 (initialised, EOA equal to the record): dispatch as before.
 *
 * `no_key` means G0 only and `not_ready` means G1 only. They are never interchanged (25.26.4c).
 */
object NoKeyGate {
    const val NO_KEY = "no_key"
    const val NOT_READY = "not_ready"
    const val LOCKED = "locked"
    const val NOT_SUPPORTED = "not_supported"
    const val NOT_READY_G1_UNINITIALIZED = "g1_uninitialized"
    const val NOT_READY_UNREADABLE = "unreadable"

    /**
     * The reason word on an `init` `no_key` answer when the vault holds no record but the two-state store names this account (0.2.30): the account
     * exists, so the page does not treat it as "no account" and goes on to the PGP restore (`pgpRestoreEvaluate`, then `pgpRestore`).
     */
    const val NO_KEY_REASON_STORE_ACCOUNT = "store_account"
    /** A native record that is confirmed to hold no valid phrase ( c): the page goes on to the sealed copies. */
    const val NOT_READY_KEY_ONLY = "key_only"

    /**
     * notReadyReason for a Locked(passcode_required) state: the UI must hand over the passcode first. Never shown as unreadable.
     * One code for this state on every path (2026-11-22, as v264 §284.3 and iOS): `passcode_not_provided`. It is the same value as
     * [NOT_READY_PASSCODE_NOT_PROVIDED]; the name `passcode_required` is kept only so the internal reference reads the same.
     */
    const val NOT_READY_PASSCODE_REQUIRED = "passcode_not_provided"

    /** not_ready reason: the record is passcode-protected and no passcode was given. Retryable; nothing is missing. */
    const val NOT_READY_PASSCODE_NOT_PROVIDED = "passcode_not_provided"

    /**
     * The not_ready reason for a vault state that cannot run the command. A passcode-protected record without a passcode is
     * [NOT_READY_PASSCODE_NOT_PROVIDED]; any other state keeps the reason of [notReadyReasonOf]. Never "locked", and an unreadable state is never
     * reported as missing.
     */
    fun lockedReasonOf(state: NativeWalletVault.State, vault: NativeWalletVault? = null): String =
        if (state is NativeWalletVault.State.Locked && state.reason == NativeWalletVault.PASSCODE_REQUIRED) NOT_READY_PASSCODE_NOT_PROVIDED
        else notReadyReasonOf(state, vault)

    /** The `result` of a not_ready answer: the reason, and `retryable` true (every reason here keeps the data and may be retried). */
    fun notReadyResult(reason: String): JSONObject = JSONObject().put("reason", reason).put("retryable", true)

    enum class Gate { G0, G1, G2 }

    /**
     * LIFECYCLE (r2.4.8 48(1), 48(7) 做法 (b)): `pwaWalletSync` runs on its own route, not on the no-key list. The handler enforces the two
     * conditions (trustedOrigin, and a current transaction sequence); nothing else is checked here.
     */
    enum class Route { PASS, NO_KEY, NOT_SUPPORTED, UNKNOWN_NAME, WALLET_STATUS, PASSCODE_STATUS, LIFECYCLE }

    /**
     * W2 `deriveLocalKeys`, W3 `protocolKeys` and W4 `fragmentKeys` are not bridge names (25.52DP.1, r3fp; the vectors NK-W2 to NK-W4 and G1-NK-W2
     * to G1-NK-W4). W5 `signMessage` (kinds selfAuth and so on) has no bridge name (25.52AR.3; NK-W5a to NK-W5g). All of them answer
     * `unknown_command` before the gate, in every state, and the payload is not read.
     */
    val NOT_BRIDGE: Set<String> = setOf("deriveLocalKeys", "protocolKeys", "fragmentKeys", "signMessage", "nativeImportOpen")

    /**
     * The command families of §25.22.4 that answer `locked` while the passcode state is locked, by the bridge names they map to in
     * negative-tests-v2 (r3dz). Not here: the retired names (25.52BZ.3, `not_supported` in every state), pgpSign (unknown, 25.52BP.1), W5
     * (no bridge name, 25.52AR.3), and N1–N4 and identityReady (no mapping in the vector yet, 25.52BZ.5).
     */
    val LOCKED_FAMILY_COMMANDS: Set<String> =
        setOf(
            "historySign", "gossipSign", "pgpDecryptInbound", "deriveSubkeys", "ephemeralSign", "walletAddress",
            "walletSignTypedData", "walletSignMessage", "walletSendTransaction", "walletTransfer", "walletSignUserOp",
            "chatRouteRegister", "pgpRestoreEvaluate", "pgpRestore", "pgpIdentityCreate",
        )

    /** The locked check of the gate step (25.52BZ.4): `locked` for a family command while the record is locked, else null. No payload is read. */
    fun lockedAnswer(command: String, state: NativeWalletVault.State): String? =
        if (state is NativeWalletVault.State.Locked && command in LOCKED_FAMILY_COMMANDS) NOT_READY else null

    /**
     * The `reason` of a lock-family `not_ready` answer (shared vectors A-08, C-25 to C-27): `passcode_not_provided` only when the
     * passcode package is missing (a vault Locked for the passcode); any other Locked state is a storage state that cannot be read, answered
     * `not_ready` with no reason. The answer is never `locked`. No UI lock or app lock is read.
     */
    fun lockedReasonTopLevel(state: NativeWalletVault.State): String? =
        if (state is NativeWalletVault.State.Locked && state.reason == NativeWalletVault.PASSCODE_REQUIRED) NOT_READY_PASSCODE_NOT_PROVIDED else null

    /** The ack of a lock-family command refused for a Locked vault: `error: not_ready`, and `reason` at the top level when it is the passcode package. */
    fun lockedAck(reqId: Any?, state: NativeWalletVault.State): JSONObject {
        val out = JSONObject().put("type", "ack").put("reqId", reqId ?: JSONObject.NULL).put("ok", false).put("error", NOT_READY)
        lockedReasonTopLevel(state)?.let { out.put("reason", it) }
        return out
    }

    /**
     * The ack of a lock-family command for a store account that cannot be used : `not_ready`, with the top-level reason
     * `passcode_not_provided` only when the store set needs the passcode package; any other store state is unknown: no reason.
     */
    fun storeNotReadyAck(reqId: Any?, storeReason: String): JSONObject {
        val out = JSONObject().put("type", "ack").put("reqId", reqId ?: JSONObject.NULL).put("ok", false).put("error", NOT_READY)
        if (storeReason == NOT_READY_PASSCODE_REQUIRED) out.put("reason", NOT_READY_PASSCODE_NOT_PROVIDED)
        return out
    }

    /** Table C (§25.24): retired X-21 commands. They answer `not_supported` in every state. */
    val RETIRED: Set<String> = setOf("walletTransferOnce", "walletTransferStatus", "walletTransferSwitched")

    /**
     * Allowed names keep their normal semantics in every gate (25.26.4, 25.26.4c item 2). The three page-open names
     * pass the gate and are decided by their own handler (`NativeOpenRules`): G0 `nativeAccountCreateOpen` is never `no_key`.
     * `accountCreateRegister` (0.2.32) also decides in its own handler: it follows a successful `nativeAccountCreateOpen`, which leaves the
     * device in G1 (a record, the session not initialised), so the gate must not answer it `not_ready`; with no account its handler answers
     * `not_ready` itself (never `no_key`), and it reads the vault directly, not the session.
     */
    private val PASS_THROUGH: Set<String> =
        setOf("hello", "pause", "resume", "destroy", "nativeRecoveryOpen", "nativeAccountCreateOpen", "accountCreateRegister", "nativeMnemonicPreread", "nativeIdentityCheck", "uiLockState", "passcodeProvision", "passcodeUnlock")

    /** Where a name goes before the gate is applied. The name is the only input. */
    fun route(command: String): Route = when {
        command in RETIRED -> Route.NOT_SUPPORTED
        command in NOT_BRIDGE -> Route.UNKNOWN_NAME
        command == "walletStatus" -> Route.WALLET_STATUS
        command == "passcodeStatus" -> Route.PASSCODE_STATUS
        command == "pwaWalletSync" -> Route.LIFECYCLE
        command == "pwaEmptySignal" -> Route.LIFECYCLE
        command in PASS_THROUGH -> Route.PASS
        else -> Route.NO_KEY
    }

    /**
     * The gate for the vault state and the session. A record that is locked still counts as a record. The session is
     * ready only after a successful `init` for the record's EOA.
     */
    /**
     * [keyOnly]: the account is a readable key record with no phrase (alignment v2, the startup classification ): it is not an account, so
     * it never reaches G2 (no session can make it one), whatever the session flag says.
     */
    /**
     * The gate of the walletStatus route (31(3), PK-03): a key-only account is no_key (G0), not not_ready. Every other state is [gateOf]. The module
     * and the tests use this one function.
     */
    fun walletStatusGate(state: NativeWalletVault.State, sessionReady: Boolean, keyOnly: Boolean): Gate =
        if (keyOnly && state is NativeWalletVault.State.Ready) Gate.G0 else gateOf(state, sessionReady, keyOnly)

    fun gateOf(state: NativeWalletVault.State, sessionReady: Boolean, keyOnly: Boolean = false): Gate = when (state) {
        is NativeWalletVault.State.NoKey -> Gate.G0
        is NativeWalletVault.State.Ready -> if (keyOnly) Gate.G1 else if (sessionReady) Gate.G2 else Gate.G1
        is NativeWalletVault.State.Locked -> if (sessionReady) Gate.G2 else Gate.G1
    }

    /**
     * The gate of the commands that need a key, with the answer of the two-state store (store-primary rule, 2026-11-22: the store is the source of
     * the account after a page sync, and the vault is no longer written). It differs from [gateOf] only when the vault has no record (G0):
     *  - a plain set in the store is an account of its own: G2 (the command is dispatched, and the signer takes the store's key);
     *  - a v3 set is an account only while this session is unlocked for its EOA (the passcode was accepted in this process): then G2; otherwise
     *    G1 (`not_ready`, with reason `passcode_not_provided` at the module): the account exists and needs the passcode, so it is never `no_key`,
     *    and the set is not opened here;
     *  - a store that cannot be read is unknown: G1 (`not_ready`, retryable), never G0 (`no_key` would say there is no account) and never G2;
     *  - an absent store leaves G0.
     * Every other vault state keeps [gateOf]. The status routes do not use this function.
     */
    internal fun commandGate(
        state: NativeWalletVault.State,
        sessionReady: Boolean,
        keyOnly: Boolean,
        store: MnemonicSetStore.Current,
        readyEoa: String?,
    ): Gate {
        val base = gateOf(state, sessionReady, keyOnly)
        if (base != Gate.G0) return base
        return when (store) {
            is MnemonicSetStore.Current.Found -> when (store.kind) {
                MnemonicSetStore.Kind.PLAIN -> Gate.G2
                MnemonicSetStore.Kind.V3 -> if (readyEoa != null && readyEoa.equals(store.eoa, ignoreCase = true)) Gate.G2 else Gate.G1
            }
            is MnemonicSetStore.Current.Unknown -> Gate.G1
            MnemonicSetStore.Current.Absent -> Gate.G0
        }
    }

    /**
     * The answer for a name that is not a status query, under [gate]:
     * `not_supported`, `allowed`, `status`, `no_key`, `not_ready`, `init` (G1: the module runs the EOA check) or
     * `dispatch` (G2).
     */
    fun answerFor(command: String, gate: Gate): String = when {
        command in RETIRED -> NOT_SUPPORTED
        route(command) == Route.PASS -> "allowed"
        route(command) == Route.WALLET_STATUS || route(command) == Route.PASSCODE_STATUS -> "status"
        gate == Gate.G0 -> NO_KEY
        gate == Gate.G1 -> if (command == "init") "init" else NOT_READY
        else -> "dispatch"
    }

    /**
     * G1 `init` (25.26.4c item 4): the EOA in the payload must equal the record. A mismatch or a missing EOA answers
     * `address_mismatch`. The comparison is on lower-case EOAs.
     */
    fun initAnswer(recordEoa: String, payloadEoa: String?): String =
        if (!payloadEoa.isNullOrEmpty() && payloadEoa.lowercase() == recordEoa.lowercase()) "ok" else "address_mismatch"

    /** `walletStatus` without a record: the status only. No `accountKey` field (table D). */
    fun walletStatusNoKey(): JSONObject = JSONObject().put("status", NO_KEY)

    /** `passcodeStatus` without a record (25.25.4). */
    fun passcodeStatusNoKey(): JSONObject =
        JSONObject().put("set", false).put("locked", false).put("hasKey", false)

    /**
     * `walletStatus` for a gate (table D, r3g): G0 `no_key`; G1 `not_ready`; G2 `unlocked` with `accountKey` when the
     * record opens, or `locked` otherwise. A locked record has no verified account, so it carries no `accountKey`.
     */
    fun walletStatusFor(
        gate: Gate,
        state: NativeWalletVault.State,
        vault: NativeWalletVault? = null,
        pointerAccount: () -> String? = { null },
    ): JSONObject = when (gate) {
        Gate.G0 -> walletStatusNoKey()
        // spec §25.52Y.39 第 9 项: the G1 answer carries why it is not ready. A readable record that is not initialised is
        // `g1_uninitialized`; a record that cannot be read (a locked or storage-derived state) is `unreadable`. The field is only on
        // `not_ready`; with no field the page treats the state as unreadable (fail-closed).
        // r3oc (spec §25.52Y.42 第 4 项 (k)): a damaged marker, a pending rollback, and a store that cannot be read all answer not_ready with
        // reason unreadable. `unavailable` is a walletState value (§25.52GX.1), not a walletStatus status; locked and no_key are not used.
        Gate.G1 -> JSONObject().put("status", NOT_READY).put("notReadyReason", notReadyReasonOf(state, vault))
        Gate.G2 -> when {
            state is NativeWalletVault.State.Ready ->
                JSONObject().put("status", "unlocked").put("accountKey", accountKeyOf(state.eoa))
            state is NativeWalletVault.State.Locked && state.reason == NativeWalletVault.PHRASE_ONLY -> phraseOnlyWalletStatus(pointerAccount())
            state is NativeWalletVault.State.Locked && state.reason == NativeWalletVault.PASSCODE_REQUIRED ->
                JSONObject().put("status", "locked").put("notReadyReason", NOT_READY_PASSCODE_REQUIRED)
            else -> JSONObject().put("status", "locked")
        }
    }

    /**
     * The G2 answer of a readable phrase without the key record (spec §25.52Y.117 第 2 项, §25.52Y.118): `locked` with the accountKey of the
     * account pointer and `reason` `phrase_only`. The page reads it as has. A pointer that cannot be read is unknown: `not_ready` with
     * reason unreadable, never `no_key` and never a lock without the account.
     */
    fun phraseOnlyWalletStatus(pointer: String?): JSONObject {
        val eoa = pointer?.takeIf { ShellRecordAccounts.isAddress(it) }
            ?: return JSONObject().put("status", NOT_READY).put("notReadyReason", NOT_READY_UNREADABLE)
        return JSONObject()
            .put("status", "locked")
            .put("accountKey", accountKeyOf(eoa))
            .put("reason", NativeWalletVault.PHRASE_ONLY)
    }

    /** The `notReadyReason` of a G1 answer (spec §25.52Y.39 第 9 项): readable and not initialised, or unreadable. */
    fun notReadyReasonOf(state: NativeWalletVault.State, vault: NativeWalletVault? = null): String {
        if (vault == null) return legacyNotReadyReasonOf(state)
        //  (c): g1_uninitialized needs a verified phrase (the current account, or a phrase-only record that verifies); a record
        // confirmed to hold no valid phrase (every phrase position read, none valid) is key_only; anything else is unreadable.
        if (state is NativeWalletVault.State.Locked && state.reason == NativeWalletVault.PASSCODE_REQUIRED) return NOT_READY_PASSCODE_REQUIRED
        if (state is NativeWalletVault.State.Locked && state.reason != NativeWalletVault.PHRASE_ONLY) return NOT_READY_UNREADABLE
        if (state is NativeWalletVault.State.Locked && vault.phraseOnlyVerifies()) return NOT_READY_G1_UNINITIALIZED
        if (state !is NativeWalletVault.State.Ready) return NOT_READY_UNREADABLE
        return when {
            vault.liveValidAccount() != null -> NOT_READY_G1_UNINITIALIZED
            vault.noValidPhraseConfirmed() -> NOT_READY_KEY_ONLY
            else -> NOT_READY_UNREADABLE
        }
    }

    private fun legacyNotReadyReasonOf(state: NativeWalletVault.State): String =
        if (state is NativeWalletVault.State.Locked && state.reason == NativeWalletVault.PASSCODE_REQUIRED) NOT_READY_PASSCODE_REQUIRED else legacyNotReadyReasonOfBase(state)

    private fun legacyNotReadyReasonOfBase(state: NativeWalletVault.State): String =
        // A readable record that is not initialised, and a readable phrase without the key record (25.52Y.106 第 1 条), are has (g1_uninitialized).
        if (state is NativeWalletVault.State.Ready || (state as? NativeWalletVault.State.Locked)?.reason == NativeWalletVault.PHRASE_ONLY) {
            NOT_READY_G1_UNINITIALIZED
        } else {
            NOT_READY_UNREADABLE
        }

    /**
     * `passcodeStatus` for a gate (25.25.4, table D): G0 `hasKey:false`; G1 and G2 `hasKey:true`. The SDK has no
     * passcode layer yet, so `set` and `locked` stay false until one exists.
     */
    fun passcodeStatusFor(gate: Gate): JSONObject =
        if (gate == Gate.G0) passcodeStatusNoKey()
        else JSONObject().put("set", false).put("locked", false).put("hasKey", true)

    /** The answers of 25.52Y.88 while the snapshot is unknown or the store is storage-derived Locked. */
    enum class StorageAnswer { ACK_NOT_READY, WALLET_STATUS_NOT_READY, PASSCODE_UNKNOWN, HISTORY_SOURCE_NOT_READY }

    /** Historical reads (25.52DL.1): `ok:true` with `result.source` `not_ready` and no data, not an error ack. */
    val HISTORY_READS: Set<String> = setOf("historyRead", "historyLoad", "historyLoadOlder", "historyListConversations", "historyOpenConversation")

    /** The three page-open names (25.52Y.88 B): they pass the name check but still need the keystore before the handler runs. */
    val PAGE_OPEN: Set<String> = setOf("nativeAccountCreateOpen", "nativeRecoveryOpen")

    /** Lifecycle names answer before the gate and are never decided here (25.52Y.88 A). */
    private val LIFECYCLE: Set<String> = setOf("hello", "pause", "resume", "destroy")

    /**
     * 25.52Y.88: the answer for [command] while the snapshot is unknown ([state] null) or the store is storage-derived Locked. Null means the
     * gate decides as before (Ready, G0 `no_key`, lifecycle). A null state always has an answer, so an unknown snapshot never reaches the
     * keystore. Nothing is read from the payload and nothing is written.
     */
    fun storageAnswer(command: String, state: NativeWalletVault.State?): StorageAnswer? {
        if (command in LIFECYCLE) return null
        if (state != null && state !is NativeWalletVault.State.Locked) return null
        return when (command) {
            // A readable phrase without the key record is has (Y.107 第 1 条): not a storage lock, so walletStatus is not intercepted here.
            "walletStatus" -> if (state is NativeWalletVault.State.Locked && state.reason == NativeWalletVault.PHRASE_ONLY) {
                null
            } else {
                StorageAnswer.WALLET_STATUS_NOT_READY
            }
            "passcodeStatus" -> if (state == null) StorageAnswer.PASSCODE_UNKNOWN else null
            // clearIdentity keeps its own redo path for a storage-derived lock (25.52PY.4); only an unknown snapshot answers here.
            "clearIdentity" -> if (state == null) StorageAnswer.ACK_NOT_READY else null
            in HISTORY_READS -> StorageAnswer.HISTORY_SOURCE_NOT_READY
            else -> StorageAnswer.ACK_NOT_READY
        }
    }

    /** `walletStatus` while the state is unknown or unreadable: `status not_ready`, `notReadyReason unreadable` (25.52Y.75 第 1 项). */
    fun walletStatusUnreadable(): JSONObject = JSONObject().put("status", NOT_READY).put("notReadyReason", NOT_READY_UNREADABLE)

    /**
     * `passcodeStatus` while the snapshot is unknown (25.52Y.88 A). `hasKey` is true: the unknown state never reads as "no account"
     * (25.52GX.2, only `absent` may). `walletState` is `not_ready` (undetermined).
     */
    fun passcodeStatusUnknown(): JSONObject =
        JSONObject().put("set", false).put("locked", false).put("hasKey", true).put("walletState", NOT_READY)

    /**
     * `passcodeStatus` under G0 while the legacy adoption is unsettled or in flight (0.2.28 follow-up, 2026-11-20): the answer is the
     * unknown one (`walletState` not_ready, `hasKey` true), never `hasKey:false`, which the page would read as "confirmed none". G1 and G2
     * are unaffected (a key exists). Once the adoption has settled, G0 answers `hasKey:false`.
     */
    fun passcodeStatusWhileAdopting(gate: Gate, adoptionSettled: Boolean, adoptionInFlight: Boolean): JSONObject =
        if (gate == Gate.G0 && (!adoptionSettled || adoptionInFlight)) passcodeStatusUnknown() else passcodeStatusFor(gate)

    /** A historical read under a storage lock or an unknown snapshot (25.52DL.1): `source` is `not_ready`, no data. */
    fun historySourceNotReady(): JSONObject = JSONObject().put("source", NOT_READY)

    /** `eoa + ":" + workspace`, workspace `default` (D5). The EOA is lower-case. */
    fun accountKeyOf(eoa: String, workspace: String = "default"): String = eoa.lowercase() + ":" + workspace
}
