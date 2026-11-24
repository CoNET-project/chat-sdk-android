package network.conet.chat

import network.conet.chat.localread.NativeHistoryDelete
import network.conet.chat.nativekey.NoKeyGate
import java.util.concurrent.atomic.AtomicInteger
import network.conet.chat.nativekey.WalletCredentialBridge
import network.conet.chat.nativekey.WalletEoaAddressBridge

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
    const val COMMAND_REJECTED = "command_rejected"
    const val SHELL_RECORD_PREFIX = "shellRecord"

    /** The `when (type)` table of [BeamioConetChatModule] (dispatch). */
    val DISPATCH: Set<String> = setOf(
        "ackInbound", "clearIdentity", "deriveSubkeys", "destroy", "ephemeralSign", "gossipSign", "hello",
        "historyAppend", "historyClearCache", "historyFullSync", "historyImportBatch", "historyLoad", "historyLoadOlder",
        "historyOpenConversation", "historyRead", "historyReportLayout", "historySign", "historyVerifyImport", "init",
        "issueGroupRoster", "issueGroupTombstone", "mailboxCommand", "nativeAccountCreateOpen",
        "nativeRecoveryOpen", "nodesResponse", "nativeMnemonicPreread", "pwaEmptySignal", "pwaWalletSync", "ownMailboxCommand", "pause", "pgpIdentityCreate", "pgpRestore",
        "accountCleanupOld", "pgpRestoreEvaluate", "pgpUpgradeRetry", "provisionIdentity", "queryNativeWake", "queryPresence", "resume", "send", "chatRouteRegister",
        "sendGroup", "setNodes", "setRoutes", "voiceFrame", "voiceListen", "voiceUnlisten", "walletAddress",
        "nativeIdentityCheck", "uiLockState", "passcodeProvision", "passcodeUnlock",
    )

    /**
     * Names the module answers that are kept out of table-T:
     * `accountCreateRegister`. The reference-table test pins [DISPATCH] to table-T v3, so these are listed apart. The name is answered in every build:
     * `not_available` unless the build enables the first-identity features (QA only).
     */
    val OUTSIDE_TABLE_T: Set<String> = setOf("accountCreateRegister")

    /** Decided in `handleCommand` before the table (25.34, 25.48, 25.52.4, 25.52AC). */
    val DECIDED_BEFORE_DISPATCH: Set<String> = setOf(
        "pgpDecryptInbound", "identityPublic", "pgpMigrate", NativeHistoryDelete.MESSAGE, NativeHistoryDelete.CONVERSATION,
    )

    /** Answered by the gate (`NoKeyGate.route`) without dispatch (table D). */
    val GATE_STATUS: Set<String> = setOf("walletStatus", "passcodeStatus")

    /**
     * The page-record commands (25.52AA.2, AY.1). On the chat channel they are answered `not_supported`, once. Other `shellRecord*` names are
     * `unknown_command` (25.52AW.1). They are listed here because they are in the command table T (25.52AU.4).
     */
    val CHAT_CHANNEL_SHELL_RECORD: Set<String> = setOf("shellRecordRead", "shellRecordWrite")

    /**
     * The chat-channel answer for a `shellRecord` prefix (25.52AZ.1, BO.4): `not_supported`, once, for every name with the prefix. The rule is
     * per prefix, not per name. The window channel is different: an unknown `shellRecord*` name there is `unknown_command` (25.52AY.1, AU.1).
     * Null for a name without the prefix.
     */
    fun chatChannelShellRecordCode(type: String): String? = if (type.startsWith(SHELL_RECORD_PREFIX)) "not_supported" else null

    /**
     * Names answered on the window channel behind the origin boundary (not the chat channel): `walletEoaAddress` (spec §25.52Y.42 第 5 项 (c)).
     * They are not in [DISPATCH], so the chat channel answers them `unknown_command`.
     */
    val WINDOW_CHANNEL: Set<String> = setOf(WalletEoaAddressBridge.NAME, WalletCredentialBridge.NAME)

    /** True when [name] is a name the module answers. A name that is not registered is answered `unknown_command` before the gate. */
    fun isRegistered(name: String): Boolean =
        name in DISPATCH ||
            name in OUTSIDE_TABLE_T ||
            name in DECIDED_BEFORE_DISPATCH ||
            name in GATE_STATUS ||
            name in NoKeyGate.RETIRED ||
            name in CHAT_CHANNEL_SHELL_RECORD

    private val commandRejected = AtomicInteger(0)

    /**
     * Counts one `command_rejected` (25.52AW.2, T-53, T-135): a refusal of the kind or the shape of a known command. It is an in-process
     * diagnostic count. It is not in any answer or event, and it is not persisted. A name outside the table is `unknown_command` and is not counted.
     */
    fun countCommandRejected(): String {
        commandRejected.incrementAndGet()
        return COMMAND_REJECTED
    }

    /** The in-process count of `command_rejected`. Read by the tests. */
    val commandRejectedCount: Int
        get() = commandRejected.get()
}
