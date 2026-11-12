package network.conet.chat.nativekey

import org.json.JSONObject

/**
 * Routing when the native vault has no record (spec §25.25.4, §25.26.4, T-155). The module asks this gate before
 * any dispatch, and only when the vault is in the no-key state. The command's payload is never read here, so a key
 * sent in a payload is neither parsed nor echoed (NK-P1 to NK-P3).
 *
 * Default deny: a name that is not on the allowed list gets `no_key`. That covers unknown names, `history*` names
 * and names outside the manifest. The manifest is `spec/no-key-reject-vectors.v1.json`.
 */
object NoKeyGate {
    const val NO_KEY = "no_key"

    enum class Route { PASS, NO_KEY, NOT_SUPPORTED, WALLET_STATUS, PASSCODE_STATUS }

    /** Table C (§25.24): retired X-21 commands. They answer `not_supported` even when a key exists. */
    val RETIRED: Set<String> = setOf("walletTransferOnce", "walletTransferStatus", "walletTransferSwitched")

    /** Lifecycle commands and the import-page opener keep their normal semantics without a key (§25.26.4). */
    private val PASS_THROUGH: Set<String> = setOf("hello", "pause", "resume", "destroy", "nativeImportOpen")

    /** Where a command goes when the vault has no record. The name is the only input. */
    fun route(command: String): Route = when {
        command in RETIRED -> Route.NOT_SUPPORTED
        command == "walletStatus" -> Route.WALLET_STATUS
        command == "passcodeStatus" -> Route.PASSCODE_STATUS
        command in PASS_THROUGH -> Route.PASS
        else -> Route.NO_KEY
    }

    /** `walletStatus` without a key: the status only. No `accountKey` field (§25.26.4, table D). */
    fun walletStatusNoKey(): JSONObject = JSONObject().put("status", NO_KEY)

    /** `passcodeStatus` without a key (§25.25.4). */
    fun passcodeStatusNoKey(): JSONObject =
        JSONObject().put("set", false).put("locked", false).put("hasKey", false)
}
