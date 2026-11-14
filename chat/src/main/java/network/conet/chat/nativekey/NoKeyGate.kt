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

    enum class Gate { G0, G1, G2 }

    enum class Route { PASS, NO_KEY, NOT_SUPPORTED, WALLET_STATUS, PASSCODE_STATUS }

    /**
     * The command families of §25.22.4 that answer `locked` while the passcode state is locked, by the bridge names they map to in
     * negative-tests-v1 (r3dz). Not here: the retired names (25.52BZ.3, `not_supported` in every state), pgpSign (unknown, 25.52BP.1), W5
     * (no bridge name, 25.52AR.3), and N1–N4 and identityReady (no mapping in the vector yet, 25.52BZ.5).
     */
    val LOCKED_FAMILY_COMMANDS: Set<String> =
        setOf("historySign", "gossipSign", "pgpDecryptInbound", "deriveSubkeys", "ephemeralSign", "walletAddress")

    /** The locked check of the gate step (25.52BZ.4): `locked` for a family command while the record is locked, else null. No payload is read. */
    fun lockedAnswer(command: String, state: NativeWalletVault.State): String? =
        if (state is NativeWalletVault.State.Locked && command in LOCKED_FAMILY_COMMANDS) LOCKED else null

    /** Table C (§25.24): retired X-21 commands. They answer `not_supported` in every state. */
    val RETIRED: Set<String> = setOf("walletTransferOnce", "walletTransferStatus", "walletTransferSwitched")

    /**
     * Allowed names keep their normal semantics in every gate (25.26.4, 25.26.4c item 2). The three page-open names
     * pass the gate and are decided by their own handler (`NativeOpenRules`): G0 `nativeAccountCreateOpen` is never `no_key`.
     */
    private val PASS_THROUGH: Set<String> =
        setOf("hello", "pause", "resume", "destroy", "nativeImportOpen", "nativeRecoveryOpen", "nativeAccountCreateOpen")

    /** Where a name goes before the gate is applied. The name is the only input. */
    fun route(command: String): Route = when {
        command in RETIRED -> Route.NOT_SUPPORTED
        command == "walletStatus" -> Route.WALLET_STATUS
        command == "passcodeStatus" -> Route.PASSCODE_STATUS
        command in PASS_THROUGH -> Route.PASS
        else -> Route.NO_KEY
    }

    /**
     * The gate for the vault state and the session. A record that is locked still counts as a record. The session is
     * ready only after a successful `init` for the record's EOA.
     */
    fun gateOf(state: NativeWalletVault.State, sessionReady: Boolean): Gate = when (state) {
        is NativeWalletVault.State.NoKey -> Gate.G0
        is NativeWalletVault.State.Ready, is NativeWalletVault.State.Locked -> if (sessionReady) Gate.G2 else Gate.G1
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
    fun walletStatusFor(gate: Gate, state: NativeWalletVault.State): JSONObject = when (gate) {
        Gate.G0 -> walletStatusNoKey()
        Gate.G1 -> JSONObject().put("status", NOT_READY)
        Gate.G2 -> when (state) {
            is NativeWalletVault.State.Ready ->
                JSONObject().put("status", "unlocked").put("accountKey", accountKeyOf(state.eoa))
            else -> JSONObject().put("status", "locked")
        }
    }

    /**
     * `passcodeStatus` for a gate (25.25.4, table D): G0 `hasKey:false`; G1 and G2 `hasKey:true`. The SDK has no
     * passcode layer yet, so `set` and `locked` stay false until one exists.
     */
    fun passcodeStatusFor(gate: Gate): JSONObject =
        if (gate == Gate.G0) passcodeStatusNoKey()
        else JSONObject().put("set", false).put("locked", false).put("hasKey", true)

    /** `eoa + ":" + workspace`, workspace `default` (D5). The EOA is lower-case. */
    fun accountKeyOf(eoa: String, workspace: String = "default"): String = eoa.lowercase() + ":" + workspace
}
