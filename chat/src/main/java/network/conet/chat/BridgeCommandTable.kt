package network.conet.chat

import network.conet.chat.localread.NativeHistoryDelete
import network.conet.chat.nativekey.NoKeyGate
import java.util.concurrent.atomic.AtomicInteger

/**
 * The bridge command table (25.52AS.3, 25.52AT.1 step 3, 25.52AT.2). A name outside it is answered `unknown_command` before the gate, in every
 * state (G0, G1, G2, locked, busy): no output, no state change, no event beyond that ack, and one in-process count. `command_rejected` is not
 * used for names outside the table: it is for a known command's own kind or field refusal (25.52AS.3).
 *
 * The table lists what [BeamioConetChatModule] answers: the names of its dispatch table, the names decided in `handleCommand` before it, the status
 * names the gate answers (`walletStatus`, `passcodeStatus`), and the retired X-21 names (`not_supported`, 25.24). `shellRecord*` is a prefix (25.52AA.3):
 * on the chat channel those names get no reply, by the shared rule.
 *
 * [BridgeCommandTableTest] reads the dispatch table in the source and compares it with [DISPATCH], name by name, in both directions.
 * A name added to dispatch must be added here, and the reverse.
 */
internal object BridgeCommandTable {
    const val UNKNOWN_COMMAND = "unknown_command"
    const val SHELL_RECORD_PREFIX = "shellRecord"

    /** The `when (type)` table of [BeamioConetChatModule] (dispatch). */
    val DISPATCH: Set<String> = setOf(
        "ackInbound", "clearIdentity", "deriveSubkeys", "destroy", "ephemeralSign", "gossipSign", "hello",
        "historyAppend", "historyClearCache", "historyFullSync", "historyImportBatch", "historyLoad", "historyLoadOlder",
        "historyOpenConversation", "historyRead", "historyReportLayout", "historySign", "historyVerifyImport", "init",
        "issueGroupRoster", "issueGroupTombstone", "mailboxCommand", "nativeAccountCreateOpen", "nativeImportOpen",
        "nativeRecoveryOpen", "nodesResponse", "ownMailboxCommand", "pause", "pgpIdentityCreate", "pgpRestore",
        "pgpRestoreEvaluate", "pgpSign", "provisionIdentity", "queryNativeWake", "queryPresence", "resume", "send",
        "sendGroup", "setNodes", "setRoutes", "voiceFrame", "voiceListen", "voiceUnlisten", "walletAddress",
    )

    /** Decided in `handleCommand` before the table (25.34, 25.48, 25.52.4, 25.52AC). */
    val DECIDED_BEFORE_DISPATCH: Set<String> = setOf(
        "pgpDecryptInbound", "identityPublic", "pgpMigrate", NativeHistoryDelete.MESSAGE, NativeHistoryDelete.CONVERSATION,
    )

    /** Answered by the gate (`NoKeyGate.route`) without dispatch (table D). */
    val GATE_STATUS: Set<String> = setOf("walletStatus", "passcodeStatus")

    /** True when [name] is a name the module answers. A name that is not registered is answered `unknown_command` before the gate. */
    fun isRegistered(name: String): Boolean =
        name in DISPATCH ||
            name in DECIDED_BEFORE_DISPATCH ||
            name in GATE_STATUS ||
            name in NoKeyGate.RETIRED ||
            name.startsWith(SHELL_RECORD_PREFIX)

    private val rejected = AtomicInteger(0)

    /** Counts one `unknown_command` and returns its code. The count is in-process; the tests read it. */
    fun countUnknown(): String {
        rejected.incrementAndGet()
        return UNKNOWN_COMMAND
    }

    val rejectionCount: Int
        get() = rejected.get()
}
