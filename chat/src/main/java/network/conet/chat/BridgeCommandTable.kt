package network.conet.chat

import network.conet.chat.localread.NativeHistoryDelete
import network.conet.chat.nativekey.NoKeyGate
import java.util.concurrent.atomic.AtomicInteger

/**
 * The bridge command table (25.52AR.2, 25.52AN.5). A name outside it is rejected with `command_rejected` before the gate and before any payload is
 * read: no output, no state change, no event beyond that ack, and one count of `command_rejected`. The answer does not depend on the gate state.
 *
 * The table lists what [BeamioConetChatModule] answers: the names of its dispatch table, the names decided in `handleCommand` before it, the status
 * names the gate answers (`walletStatus`, `passcodeStatus`), and the retired X-21 names (`not_supported`, 25.24). `shellRecord*` is a prefix (25.52AA.3):
 * on the chat channel those names get no reply, by the shared rule.
 *
 * [BridgeCommandTableTest] reads the dispatch table in the source and compares it with [DISPATCH], name by name, in both directions.
 * A name added to dispatch must be added here, and the reverse.
 */
internal object BridgeCommandTable {
    const val COMMAND_REJECTED = "command_rejected"
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

    /** True when [name] is a name the module answers. A name that is not registered is rejected before the gate. */
    fun isRegistered(name: String): Boolean =
        name in DISPATCH ||
            name in DECIDED_BEFORE_DISPATCH ||
            name in GATE_STATUS ||
            name in NoKeyGate.RETIRED ||
            name.startsWith(SHELL_RECORD_PREFIX)

    private val rejected = AtomicInteger(0)

    /** Counts one `command_rejected` and returns its code. The count is in-process; the tests read it. */
    fun countRejection(): String {
        rejected.incrementAndGet()
        return COMMAND_REJECTED
    }

    val rejectionCount: Int
        get() = rejected.get()
}
