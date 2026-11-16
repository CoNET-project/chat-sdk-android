package network.conet.chat

import android.content.Context
import android.os.Handler
import android.os.Looper
import android.util.Log
import org.json.JSONArray
import java.io.IOException
import network.conet.chat.identity.CredFields
import network.conet.chat.identity.IdentityProvisionContract
import network.conet.chat.nativekey.NativeMessageSigner
import network.conet.chat.nativekey.IdentityPublic
import network.conet.chat.nativekey.NativeDerivationCommands
import network.conet.chat.nativekey.VoiceChannelKeys
import network.conet.chat.nativekey.NativeOpenRules
import network.conet.chat.nativekey.NativeWallet
import network.conet.chat.nativekey.NativeWalletCommands
import network.conet.chat.nativekey.NativePgp
import network.conet.chat.nativekey.NativePgpVault
import network.conet.chat.nativekey.NativeAccountCreateHost
import network.conet.chat.nativekey.NativeRecoveryHost
import network.conet.chat.nativekey.NativeImportHost
import network.conet.chat.nativekey.AccountCleanupOld
import network.conet.chat.nativekey.AccountCleanupRun
import network.conet.chat.nativekey.AccountCleanupWiring
import network.conet.chat.nativekey.AccountPgpK
import network.conet.chat.nativekey.CleanupConfirmation
import network.conet.chat.nativekey.CleanupJournal
import network.conet.chat.nativekey.accountCleanupAck
import network.conet.chat.nativekey.AccountCleanupDispatch
import network.conet.chat.nativekey.CleanupRun
import network.conet.chat.nativekey.PgpDecryptInbound
import network.conet.chat.nativekey.PgpRestoreBridge
import network.conet.chat.nativekey.BeamioPgpMigrationImport
import network.conet.chat.nativekey.MigrationCode
import network.conet.chat.nativekey.PgpMigrationBridge
import network.conet.chat.nativekey.PgpMigrationInterrupted
import network.conet.chat.nativekey.PgpMigrationPolicy
import network.conet.chat.nativekey.NativeSessionState
import network.conet.chat.nativekey.IdentityClear
import network.conet.chat.nativekey.IdentityClearCode
import network.conet.chat.nativekey.ClearFlagFiles
import network.conet.chat.nativekey.DeviceFlagFiles
import network.conet.chat.nativekey.AndroidVaultFiles
import network.conet.chat.nativekey.VaultFiles
import network.conet.chat.nativekey.eraseChecked
import network.conet.chat.nativekey.pageRecordFiles
import network.conet.chat.nativekey.MigrationResult
import network.conet.chat.nativekey.SingleReply
import network.conet.chat.nativekey.migrationAccountOfName
import network.conet.chat.nativekey.OrphanSweepRule
import network.conet.chat.nativekey.SignRequestRule
import network.conet.chat.nativekey.orphanSweepMayRun
import network.conet.chat.nativekey.eraseBackupFlagsOfUnknownAccount
import java.io.File
import network.conet.chat.nativekey.NativeWalletVault
import network.conet.chat.nativekey.ChatRouteRegister
import network.conet.chat.nativekey.AccountCreateGuard
import network.conet.chat.nativekey.NoKeyGate
import network.conet.chat.nativekey.InitNodesGate
import network.conet.chat.nativekey.ShellRecordPolicy
import network.conet.chat.localread.LocalChatEvent
import network.conet.chat.localread.NativeHistoryDelete
import network.conet.chat.localread.LocalMediaKind
import network.conet.chat.localread.LocalPage
import network.conet.chat.localread.LocalSource
import network.conet.chat.localread.LocalViewport
import network.conet.chat.localread.PageItem
import org.json.JSONObject
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import network.conet.chat.nativekey.BeamioShellRecordImport
import network.conet.chat.nativekey.BindingCode
import network.conet.chat.nativekey.BindingDecision
import network.conet.chat.nativekey.BindingDevice
import network.conet.chat.nativekey.BindingKind
import network.conet.chat.nativekey.ChainRegistryReader
import network.conet.chat.nativekey.RegistryBudget
import network.conet.chat.nativekey.RegistryRead
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Native Conet Chat module — WorkerCommand / WorkerOutbound parity with
 * `@conet.project/chat-sdk`, model 1B signing (the host PWA signs, see
 * [BeamioConetChatSignBroker]).
 *
 * Wire contract (same as the iOS `ConetChatSDK`):
 *  - PWA → native: `handleCommand({ type, reqId, … })`
 *  - native → PWA: `{ action: "chatModuleEvent", event: { type: "ready" | "ack" | "event:*", … } }`
 *    and `{ action: "chatModuleSignRequest", … }` (through the same emitter).
 */
object BeamioConetChatModule {
    private const val TAG = "BeamioConetChat"

    /** Entry / mailbox node with optional route PGP (from the PWA `setNodes`). */
    data class Node(
        val ip: String,
        val domain: String,
        val region: String,
        val armoredPublicKey: String,
    ) {
        fun asStoreNode() = BeamioChatPgpStore.SiNode(ip, domain, region, armoredPublicKey)
    }

    class Session {
        @Volatile var eoa: String = ""
        // The PGP private key and its passphrase are not held by the session: they live in the native PGP record
        // (nativekey.NativePgpVault), and only the native decryption reads them (§36-B).
        @Volatile var pgpPublicKeyArmored: String = ""
        @Volatile var ownRouteArmoredPublicKey: String = ""
        @Volatile var mailboxIp: String = ""
        /** Route key ID the running listen sent its last `mailbox_listen` to (log + handoff check). */
        @Volatile var listenRouteKeyId: String = ""
        @Volatile var nodes: List<Node> = emptyList()
        @Volatile var routes: List<JSONObject> = emptyList()
        @Volatile var conetRpcUrl: String = "https://rpc1.conet.network"
        @Volatile var ipfsBaseUrl: String = "https://ipfs.conet.network/api"
        @Volatile var ipfsWriteBaseUrl: String = ""
        @Volatile var apiBaseUrl: String = "https://beamio.ca/api"
        @Volatile var chatIndexRegistryAddress: String = "0x1511Caa71081C84d8a591490D1b83879088EED72"
        @Volatile var chainId: Int = 224422
        @Volatile var history: BeamioConetChatHistoryStore? = null
        @Volatile var destroyed: Boolean = false
        /**
         * The app confirms each inbound message with `ackInbound` after it has
         * stored it. Until then the mailbox keeps its offline copy, so a message
         * is not lost when the page is starting, suspended or killed.
         */
        @Volatile var deferAck: Boolean = false
        val pendingAcks = java.util.concurrent.ConcurrentHashMap<String, PendingAck>()
    }

    class PendingAck(val plaintext: String, val from: String, val viaDomain: String, val at: Long)

    private val lock = Any()
    private var session: Session? = null
    private var appContext: Context? = null

    /**
     * The web emit of the last [handleCommand]. Internal, not private: the QA source set (chatQaHooks) swaps it through an extension of this
     * object (25.52AX.3). The release source has no swap.
     */
    @Volatile
    internal var emitFn: ((JSONObject) -> Unit)? = null

    private val listen = BeamioConetChatListenSession()
    private val voiceSessions = HashSet<String>()
    private val seenArmor = object : LinkedHashMap<String, Boolean>(256, 0.75f, false) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Boolean>?): Boolean = size > 512
    }
    private val main = Handler(Looper.getMainLooper())
    /**
     * The route submission bases, IP first when the roster is wired (25.52Y.61 第 4 项). Until then the domain only. The IP addresses are not
     * in source: they come from the global native network roster, which is not wired yet.
     */
    private val ROUTE_BASES: List<String> = listOf("https://beamio.ca")

    private val io = Executors.newCachedThreadPool { r ->
        Thread(r, "conet-chat-module").apply { isDaemon = true }
    }

    /**
     * Shell hook: sees every module event (messages included) even when no page
     * is attached, so the shell can act on a caller's cancel natively. Main thread.
     */
    @Volatile
    @JvmField
    var nativeObserver: ((JSONObject) -> Unit)? = null

    /**
     * Shell hook: `true` while a call rings or is up. The page's background
     * `pause` is then deferred: the mailbox listen stays connected until the call ends.
     */
    @Volatile
    @JvmField
    var keepListenWhile: (() -> Boolean)? = null

    /**
     * Shell call layer: a verified peer call-control message arrived over Chat
     * (type, callId, sessionId, recovered signer). Main thread.
     */
    @Volatile
    @JvmField
    var callControlObserver: ((type: String, callId: String, sessionId: String, from: String) -> Unit)? = null

    /** A pause is owed once [keepListenWhile] turns false. Main thread. */
    private var pauseOwed = false

    /** Read-only for the shell's gate: true only after a successful `init` for the native record (25.26.4c, G2). */
    fun isNativeSessionReady(): Boolean = NativeSessionState.isReady()
    private var idleCheckPosted = false
    private const val IDLE_CHECK_MS = 10_000L

    fun isAvailable(): Boolean = true

    fun isRunning(): Boolean = synchronized(lock) { session != null } && listen.isRunning()

    /**
     * Entry point for every PWA command. [emit] delivers payloads to the web layer
     * (the shell dispatches them as a `cashtreesandroid` `CustomEvent`).
     */
    fun handleCommand(context: Context, body: JSONObject, emit: (JSONObject) -> Unit) {
        val t0 = network.conet.chat.nativekey.DiagTiming.now()
        val type = body.optString("type", "")
        try {
            handleCommandInner(context, body, emit)
        } finally {
            network.conet.chat.nativekey.DiagTiming.log("handleCommand:$type", t0)
        }
    }

    private fun handleCommandInner(context: Context, body: JSONObject, emit: (JSONObject) -> Unit) {
        val ctxIn = context.applicationContext
        if (appContext == null) {
            // r3rh 第 1 项 (PY.8 第 5 项): the redo is local-only and runs synchronously before the first command. If it fails, the wallet and
            // identity commands answer not_ready until a redo succeeds (see dispatch).
            // The marker is read before the redo, which clears it on success. The orphan sweep is for an interrupted clear only.
            val interrupted = orphanSweepMayRun(ClearFlagFiles(pageRecordFiles(ctxIn)))
            // The cleared account is the active pointer, read before the redo removes it (25.52Y.85 第 6 条, rc2.2-qa item 2).
            val involvedAccount = if (interrupted) activePointerAccount(ctxIn) else null
            retryClearRedo(ctxIn)
            // Background only; it never blocks start-up or a command. It runs only as the continuation of an interrupted clear (clear_pending
            // set, strictly read) and removes only the account that clear involves (OrphanSweepRule). No-account alone is not a reason.
            if (interrupted) {
                pgpMigrateWorker.execute {
                    runCatching { sweepOrphanMigrations(ctxIn, interrupted, involvedAccount) }
                        .onFailure { Log.w(TAG, "orphan sweep skipped") }
                }
            }
        }
        appContext = ctxIn
        emitFn = emit
        // The K_pgp upgrade (PM ruling): once per process, after the keychain is readable; asynchronous, never blocks a command.
        // The vault state is read on the io executor only: NativeWalletVault.state() is synchronized and slow (a keystore open), and
        // reading it on the caller's (main) thread froze the start-up (S25 contention, 2026-11-15).
        if (network.conet.chat.nativekey.KpgpUpgradeTrigger.pending()) {
            io.execute {
                val vaultState = try {
                    network.conet.chat.nativekey.NativeWallet.vault(ctxIn).state()
                } catch (_: Exception) {
                    null
                }
                if (network.conet.chat.nativekey.KpgpUpgradeTrigger.claim(vaultState)) {
                    val eoa = (vaultState as network.conet.chat.nativekey.NativeWalletVault.State.Ready).eoa
                    val result = try {
                        network.conet.chat.nativekey.KpgpUpgrade.fromDevice(ctxIn, eoa, userClick = false, nowSec = System.currentTimeMillis() / 1000L)
                    } catch (_: Exception) {
                        // 25.52Y.62 第 3 项: any internal exception is pgp_migration_retry, with no cause code.
                        null
                    }
                    val code = result?.action ?: "pgp_migration_retry"
                    // The page learns the state through the event channel; success is silent, a retry state shows the existing retry notice.
                    if (code != "keep_existing" && code != "upgraded_from_L") {
                        emitEvent(JSONObject().put("type", "pgpUpgradeState").put("code", code))
                    }
                }
            }
        }
        BeamioConetChatSignBroker.setEmit(emit)
        // 25.52AW.1, 25.52AU.1, 25.52AX.1: the envelope comes first, for every entry. A reqId that is missing or not valid is `bad_request` with a
        // null reqId, answered once, before any gate or state change. Integer 0 is valid and is echoed (T-179).
        if (!ShellRecordPolicy.reqIdValid(body.opt("reqId"))) {
            emitEvent(JSONObject().put("type", "ack").put("reqId", JSONObject.NULL).put("ok", false).put("error", "bad_request"))
            return
        }
        val type = body.optString("type", "")
        // Order (25.52AT.1, AU.2, AQ.2): the credential check, the command name, and the chat-channel shell-record answer come before the
        // legacy adoption, so a refused or unknown request changes no state. For a known command the adoption still runs before its gate
        // (25.25.6 U-3, U-4).
        // 25.52AT.1 step 2 (25.52AQ.2, BG.3: pgpMigrate included): a credential field of a CRED command is refused before the gate, with the field names and no values.
        if (type in CredFields.COMMANDS) {
            val names = CredFields.refusalNames(type, body)
            if (names.isNotEmpty()) {
                refuseCredential(type, body, names)
                return
            }
        }
        // shellRecord* prefix on the chat channel (25.52AZ.1, BO.4): one answer, not_supported, for every name with the prefix. The page records
        // come only through window.BeamioShellRecord (25.52AA.2).
        BridgeCommandTable.chatChannelShellRecordCode(type)?.let { code ->
            ack(echoId(body), false, error = code)
            return
        }
        // 25.52AT.1 step 3, 25.52AS.3, 25.52AT.2: a name outside the bridge command table is `unknown_command` before the gate, in every state
        // (G0 no_key, G1 not_ready, locked, busy). Nothing is read from the payload and no state changes. It is not counted (25.52AW.2).
        if (!BridgeCommandTable.isRegistered(type)) {
            Log.w(TAG, "unknown_command name=${type.take(64)}")
            ack(echoId(body), false, error = BridgeCommandTable.UNKNOWN_COMMAND)
            return
        }
        // A pre-upgrade wallet key is adopted before the no-key check, so an upgraded install keeps its wallet even
        // when the first command is `init` (25.25.6 U-3, U-4). This does nothing once a native record exists or when
        // no legacy key is left. Only the outcome is logged, never the key.
        runCatching { NativeWallet.migrateLegacy(context) }
            .onFailure { Log.w(TAG, "legacy wallet adoption failed: ${it.javaClass.simpleName}") }
        runCatching { NativeWallet.migrateLegacyPgp(context) }
            .onFailure { Log.w(TAG, "legacy PGP adoption failed: ${it.javaClass.simpleName}") }
        // pgpDecryptInbound (25.34): reqId first, then the gate, inside the handler. It is not routed through the table.
        if (type == "pgpDecryptInbound") {
            handlePgpDecryptInbound(body)
            return
        }
        // identityPublic (25.48): G2 only, read-only. Like pgpDecryptInbound it is decided in its handler, gate first.
        if (type == "identityPublic") {
            identityPublicCommand(body)
            return
        }
        // pgpMigrate (r3at §25.52.4): decided in its handler, key fields first, before the gate (R-02).
        if (type == "pgpMigrate") {
            pgpMigrateCommand(body)
            return
        }
        // historyDeleteMessage and historyDeleteConversation (r3by §25.52AC): the gate of historyOpenConversation, then the native store.
        // The reqId is echoed as sent (a string or an integer), so the ack does not go through [ack].
        if (type == NativeHistoryDelete.MESSAGE || type == NativeHistoryDelete.CONVERSATION) {
            historyDeleteCommand(context, type, body)
            return
        }
        val route = NoKeyGate.route(type)
        // X-21 is retired (no key crosses the bridge): refused whether or not a key exists (25.24, 25.26.4 table C).
        if (route == NoKeyGate.Route.NOT_SUPPORTED) {
            ack(echoId(body), false, error = network.conet.chat.x21.X21Retired.ERROR)
            return
        }
        // W2 to W4 are not bridge names (25.52DP.1): unknown_command before the gate, in every state. The payload is not read.
        if (route == NoKeyGate.Route.UNKNOWN_NAME) {
            ack(echoId(body), false, error = BridgeCommandTable.UNKNOWN_COMMAND)
            return
        }
        // Allowed names keep their normal semantics. Everything else is gated by the state of the native record and
        // of this session (25.26.4c): G0 no_key, G1 not_ready (init checks the EOA in dispatch), G2 as before. The
        // payload is not read for any refused name.
        if (route != NoKeyGate.Route.PASS) {
            val reqId = echoId(body)
            // r3rh 第 1 项: while the redo is blocked, each wallet or identity command first retries the redo; it is answered only once a redo
            // has succeeded. Otherwise it answers not_ready.
            // clearIdentity is exempt: the page's retry of an unfinished clear must reach it (25.52PY.4, 25.26.4c 第 3a 項).
            if (clearRedoBlocked && type != "clearIdentity") {
                retryClearRedo(context)
                if (clearRedoBlocked) {
                    ack(reqId, false, error = NoKeyGate.NOT_READY)
                    return
                }
            }
            // 25.52Y.70 第 4 项, 25.52Y.75, 25.52Y.88: the gate reads the snapshot, never the keystore on this thread. An unknown snapshot, or a
            // storage-derived lock, is answered by NoKeyGate.storageAnswer: not_ready once for the keystore names, walletStatus with the
            // unreadable reason, passcodeStatus with its status, and the historical reads with source not_ready. Nothing is read or written.
            val snap = NativeWallet.vault(context).snapshotState()
            if (snap == null) scheduleSnapshotRefresh(context)
            NoKeyGate.storageAnswer(type, snap)?.let { answer ->
                answerStorageUnknown(reqId, answer)
                return
            }
            val state = snap ?: return
            val gate = NoKeyGate.gateOf(state, NativeSessionState.isReady())
            // clear_pending set (strictly read): clearIdentity finishes the interrupted clear in G0 and G1 (25.26.4c 第 3a 項, 25.52Y.21 (a),
            // gate-state G0-CLR-PENDING and G1-CLR-PENDING, no-key NK-CP1). Without the marker, the gate answers as before (G0 no_key, G1 not_ready).
            if (type == "clearIdentity" && gate != NoKeyGate.Gate.G2 &&
                ClearFlagFiles(pageRecordFiles(context)).clearPendingStrict()
            ) {
                clearIdentity(reqId)
                return
            }
            // 25.52BZ.4 (r3dz): the locked check of the gate step, after the name check and before the parameters and the no_key or not_ready
            // answers. No payload is read.
            NoKeyGate.lockedAnswer(type, state)?.let { code ->
                ack(reqId, false, error = code)
                return
            }
            when (route) {
                NoKeyGate.Route.WALLET_STATUS -> {
                    ack(reqId, true, result = NoKeyGate.walletStatusFor(gate, state))
                    return
                }
                NoKeyGate.Route.PASSCODE_STATUS -> {
                    ack(reqId, true, result = NoKeyGate.passcodeStatusFor(gate))
                    return
                }
                else -> Unit
            }
            when (NoKeyGate.answerFor(type, gate)) {
                NoKeyGate.NO_KEY -> {
                    ack(reqId, false, error = NoKeyGate.NO_KEY)
                    return
                }
                NoKeyGate.NOT_READY -> {
                    ack(reqId, false, error = NoKeyGate.NOT_READY)
                    return
                }
                else -> Unit
            }
        }
        // 25.52Y.88 B: the page-open names pass the gate by name, so the storage check is made here, before the handler reads the keystore.
        if (type in NoKeyGate.PAGE_OPEN) {
            val snapOpen = NativeWallet.vault(context).snapshotState()
            if (snapOpen == null) scheduleSnapshotRefresh(context)
            NoKeyGate.storageAnswer(type, snapOpen)?.let { answer ->
                answerStorageUnknown(echoId(body), answer)
                return
            }
        }
        dispatch(type, body)
    }

    /** Sends the 25.52Y.88 answer: one ack for the keystore names, or the business result of a walletStatus or historical read. */
    private fun answerStorageUnknown(reqId: Any, answer: NoKeyGate.StorageAnswer) {
        when (answer) {
            NoKeyGate.StorageAnswer.ACK_NOT_READY -> ack(reqId, false, error = NoKeyGate.NOT_READY)
            NoKeyGate.StorageAnswer.WALLET_STATUS_NOT_READY -> ack(reqId, true, result = NoKeyGate.walletStatusUnreadable())
            NoKeyGate.StorageAnswer.PASSCODE_UNKNOWN -> ack(reqId, true, result = NoKeyGate.passcodeStatusUnknown())
            NoKeyGate.StorageAnswer.HISTORY_SOURCE_NOT_READY -> ack(reqId, true, result = NoKeyGate.historySourceNotReady())
        }
    }

    private fun dispatch(type: String, body: JSONObject) {
        when (type) {
            // Protocol v1: version + capabilities (see BeamioConetChatProtocol).
            "hello" -> ack(echoId(body), true, result = BeamioConetChatProtocol.helloResult())
            "init" -> handleInit(body)
            "setRoutes" -> currentSession()?.let { s -> body.optJSONArray("routes")?.let { s.routes = objects(it) } }
            "setNodes" -> currentSession()?.let { s -> body.optJSONArray("nodes")?.let { s.nodes = parseNodes(it) } }
            "nodesResponse" -> Unit
            "send" -> handleSend(body)
            "sendGroup", "issueGroupRoster", "issueGroupTombstone" -> handleGroup(body)
            "queryPresence" -> handleQueryPresence(body)
            "queryNativeWake" -> handleQueryNativeWake(body)
            "historyLoad" -> handleHistoryLoad(body)
            "historyRead" -> handleHistoryRead(body)
            "historyOpenConversation" -> handleHistoryOpen(body)
            "historyLoadOlder" -> handleHistoryLoadOlder(body)
            "historyReportLayout" -> handleHistoryReportLayout(body)
            "historyClearCache" -> handleHistoryClearCache(body)
            "historyFullSync" -> handleHistoryFullSync(body)
            "historyImportBatch" -> handleHistoryImportBatch(body)
            "historyVerifyImport" -> handleHistoryVerifyImport(body)
            "historyAppend" -> handleHistoryAppend(body)
            "mailboxCommand" -> handleMailboxCommand(body)
            "ownMailboxCommand" -> {
                currentSession()?.let { body.put("routerArmoredPublicKey", it.ownRouteArmoredPublicKey) }
                handleMailboxCommand(body)
            }
            "voiceFrame" -> handleVoiceFrame(body)
            "voiceListen" -> handleVoiceListen(body)
            "voiceUnlisten" -> handleVoiceUnlisten(body)
            "pause" -> main.post { requestPause() }
            "ackInbound" -> handleAckInbound(body)
            "resume" -> main.post {
                // The shell reported the app in the background: the page (or a
                // wake event it got) does not reopen the listen there.
                if (!BeamioListenPolicy.pageResumeApplies(lifecycleKnown, appInForeground, keepListenWhile?.invoke() == true)) {
                    Log.i(TAG, "page resume ignored: app in the background")
                    return@post
                }
                pauseOwed = false
                resumeListen()
            }
            "destroy" -> destroy()
            "clearIdentity" -> clearIdentity(echoId(body))
            "provisionIdentity" -> provisionIdentity(body)
            "walletAddress" -> walletAddressCommand(body)
            "gossipSign" -> gossipSignCommand(body)
            "nativeImportOpen" -> nativeImportOpenCommand(body)
            "nativeRecoveryOpen" -> nativeRecoveryOpenCommand(body)
            "nativeAccountCreateOpen" -> nativeAccountCreateOpenCommand(body)
            // Derivation (§25.15.3 C5, §25.43): the key is unlocked here and cleared after the call. W2, W3 and W4 are not
            // bridge commands (§25.37.4 補充, r3al): they stay in-process and are not dispatched here.
            "deriveSubkeys" -> derivationCommand(body) { key, eoa ->
                NativeDerivationCommands.deriveSubkeys(key, body.optString("accountKey", ""), eoa)
            }
            "ephemeralSign" -> emitEvent(derivationAck(PgpDecryptInbound.reqIdOf(body), NativeDerivationCommands.ephemeralSign(body)))
            // C1 historySign is in-process only (§25.43.3): the bridge answers not_supported, and nothing else.
            "historySign" -> emitEvent(
                derivationAck(PgpDecryptInbound.reqIdOf(body), NativeDerivationCommands.Outcome.fail(NativeDerivationCommands.NOT_SUPPORTED)),
            )
            "pgpRestoreEvaluate" -> pgpRestoreCommand(body, evaluateOnly = true)
            "pgpRestore" -> pgpRestoreCommand(body, evaluateOnly = false)
            "pgpUpgradeRetry" -> pgpUpgradeRetryCommand(body)
            "accountCleanupOld" -> accountCleanupOldCommand(body)
            "pgpIdentityCreate" -> pgpIdentityCreateWaiting(body)
            "chatRouteRegister" -> chatRouteRegisterCommand(body)
            else -> {
                // Unreachable while the table and this dispatch agree (BridgeCommandTableTest). Answered the same way if they ever diverge.
                Log.w(TAG, "unknown_command name=${type.take(64)}")
                ack(echoId(body), false, error = BridgeCommandTable.UNKNOWN_COMMAND)
            }
        }
    }

    /** PWA answered a `chatModuleSignRequest`. */
    fun fulfillSign(body: JSONObject) = BeamioConetChatSignBroker.fulfill(body)

    // ---- init / routes / nodes -----------------------------------------------------

    /**
     * The API base an `init` payload leaves in the session (PM R2043): a non-blank `apiBaseUrl` in the payload overrides; a blank or absent one
     * keeps [current] (the session default, `https://beamio.ca/api`).
     */
    internal fun resolveApiBase(payload: JSONObject, current: String): String = payload.optString("apiBaseUrl", "").ifBlank { current }

    private fun handleInit(body: JSONObject) {
        val reqId = echoId(body)
        val ctx = appContext ?: return
        val payload = body.optJSONObject("payload")
        if (payload == null) {
            ack(reqId, false, error = "missing_payload")
            return
        }
        val idEoa = payload.optJSONObject("identity")?.let { id ->
            normalizeAddress(id.optString("eoaAddress", "").ifBlank { id.optString("eoa", "") })
        }.orEmpty()
        // identity.native-keys.v1 (spec 25.19.2, 25.19.3, 25.20.1): the contract checks the init payload before any state
        // changes. Key material is refused, and the EOA must be canonical.
        when (val checked = IdentityProvisionContract.validate(IdentityProvisionContract.Command.INIT, payload)) {
            is IdentityProvisionContract.Result.Reject -> {
                Log.w(TAG, "init refused: ${checked.error}")
                ack(reqId, false, error = checked.error)
                return
            }
            is IdentityProvisionContract.Result.Accept -> Unit
        }
        // G1 (25.26.4c item 4): a native record exists and this session is not ready. The EOA in the payload must equal
        // the record; a mismatch or a missing EOA changes nothing. A locked record cannot be checked against the EOA.
        // 25.52Y.75: the snapshot, never the keystore on this thread. An unknown snapshot is not_ready once, with nothing changed.
        val vaultNow = NativeWallet.vault(ctx).snapshotState() ?: run {
            scheduleSnapshotRefresh(ctx)
            ack(reqId, false, error = NoKeyGate.NOT_READY)
            return
        }
        if (NoKeyGate.gateOf(vaultNow, NativeSessionState.isReady()) == NoKeyGate.Gate.G1) {
            if (vaultNow !is NativeWalletVault.State.Ready) {
                ack(reqId, false, error = "locked")
                return
            }
            if (NoKeyGate.initAnswer(vaultNow.eoa, idEoa) != "ok") {
                ack(reqId, false, error = "address_mismatch")
                return
            }
            // R1841 / Y.29 / Y.32: the nodes rule of the G1 identity-only init, after the EOA check. A refusal is not ready, and the
            // session is not changed. G2 init is not under this rule (§25.52GJ).
            InitNodesGate.errorOf(InitNodesGate.verdict(payload) { BeamioChatPgpStore.loadSiNodes(ctx).size })?.let { code ->
                Log.w(TAG, "init refused in G1: $code (nodes rule, Y.29/Y.32); no ready, nodes unchanged")
                ack(reqId, false, error = code)
                return
            }
        }
        // A listen started without the page (call push) for this wallet: the page
        // takes it over as it is. No reconnect, and the messages it holds unconfirmed
        // are handed to the page below.
        val running = currentSession()
        val attach = running != null && idEoa.isNotEmpty() && running.eoa == idEoa && listen.isActive()
        val s = if (attach) running!! else Session()
        if (!attach) {
            // A new session is not ready until its init succeeds for the record (25.26.4c, G1 -> G2).
            NativeSessionState.reset()
            synchronized(lock) {
                listen.stop()
                session?.history?.destroy()
                session = s
            }
        }
        main.post { pauseOwed = false }
        s.deferAck = payload.optBoolean("deferAck", false) || (attach && s.deferAck)
        if (s.deferAck && !attach) {
            // A new page has seen nothing: let the mailbox's redelivery of
            // messages the previous page never confirmed reach it again.
            synchronized(seenArmor) { seenArmor.clear() }
        }

        // A4 audit (F1): `identity.pgpPrivateKeyArmored` and `identity.pgpPassphrase` are refused before this point. validate(INIT) above is
        // recursive and rejects every forbidden key name (key_over_bridge_refused), so these two reads only ever see empty values. They are kept
        // until P-IMP-PGP removes them (spec 25.19.4 step 4); see BridgeKeyAuditTest.
        var pgpArmorInInit = ""
        var pgpPassphraseInInit = ""
        payload.optJSONObject("identity")?.let { id ->
            s.eoa = normalizeAddress(id.optString("eoaAddress", "").ifBlank { id.optString("eoa", "") })
            pgpArmorInInit = id.optString("pgpPrivateKeyArmored", "")
            s.pgpPublicKeyArmored = id.optString("pgpPublicKeyArmored", "")
            pgpPassphraseInInit = id.optString("pgpPassphrase", "")
            s.ownRouteArmoredPublicKey = id.optString("ownRouteArmoredPublicKey", "")
                .ifBlank { id.optString("routePublicKeyArmored", "") }
            s.mailboxIp = id.optString("mailboxIp", "")
        }
        if (s.ownRouteArmoredPublicKey.isEmpty() || s.pgpPublicKeyArmored.isEmpty()) {
            (try { BeamioChatPgpStore.load(ctx) } catch (_: IOException) { null })?.let { kc ->
                if (s.pgpPublicKeyArmored.isEmpty()) s.pgpPublicKeyArmored = kc.publicKeyArmor
                if (s.ownRouteArmoredPublicKey.isEmpty()) s.ownRouteArmoredPublicKey = kc.routePublicKeyArmor
                if (s.mailboxIp.isEmpty()) s.mailboxIp = kc.mailboxIp
                if (s.eoa.isEmpty()) s.eoa = normalizeAddress(kc.eoa)
            }
        }
        s.conetRpcUrl = payload.optString("conetRpcUrl", "").ifBlank { s.conetRpcUrl }
        s.ipfsBaseUrl = payload.optString("ipfsBaseUrl", "").ifBlank { s.ipfsBaseUrl }
        s.ipfsWriteBaseUrl = payload.optString("ipfsWriteBaseUrl", "")
        s.apiBaseUrl = resolveApiBase(payload, s.apiBaseUrl)
        s.chatIndexRegistryAddress = payload.optString("chatIndexRegistryAddress", "")
            .ifBlank { s.chatIndexRegistryAddress }
        if (payload.has("chainId")) s.chainId = payload.optInt("chainId", s.chainId)

        val nodesRaw = payload.optJSONArray("nodes")
        if (nodesRaw != null) {
            s.nodes = parseNodes(nodesRaw)
        } else {
            val saved = BeamioChatPgpStore.loadSiNodes(ctx)
            if (saved.isNotEmpty()) s.nodes = saved.map { Node(it.ip, it.domain, it.region, it.armoredPublicKey) }
        }
        payload.optJSONArray("routes")?.let { s.routes = objects(it) }

        // The EOA is what G2 needs (§25.26.4c). The PGP key is not required here: a recovered wallet has none until pgpRestore
        // runs, and pgpRestore needs G2 (§25.30.2 step 1). PGP-dependent chat features stay off until then.
        if (s.eoa.isEmpty()) {
            ack(reqId, false, error = "missing_identity")
            return
        }

        // Keep the killed-app voice path working: it reads the route / roster from here (public material only).
        try {
            val upsert = JSONObject()
                .put("publicKeyArmor", s.pgpPublicKeyArmored)
                .put("eoa", s.eoa)
            // An omitted route key stays omitted (r3aj): no empty string stands in for it.
            if (s.ownRouteArmoredPublicKey.isNotEmpty()) upsert.put("routePublicKeyArmor", s.ownRouteArmoredPublicKey)
            BeamioChatPgpStore.upsertFromWeb(ctx, upsert)
            // A payload roster that carries PGP keys replaces the stored one: background listen starts from the stored keys.
            if (nodesRaw != null && s.nodes.any { it.armoredPublicKey.contains("BEGIN PGP PUBLIC KEY") }) {
                BeamioChatPgpStore.storeChainRoster(ctx, s.nodes.map { it.asStoreNode() }, s.mailboxIp.ifBlank { null })
            }
        } catch (e: Exception) {
            Log.w(TAG, "persist identity: ${e.message}")
        }

        val host = BeamioOpenPgpHost.shared(ctx)
        host.ensureReady { ok ->
            if (!ok) {
                ack(reqId, false, error = "openpgp_not_ready")
                return@ensureReady
            }
            // diag4 (logging only): the init segments, with thread, milliseconds and the result.
            val tAdopt = network.conet.chat.nativekey.DiagTiming.now()
            adoptNativeWallet(ctx, host, reqId, s.eoa) {
                val tPgp = network.conet.chat.nativekey.DiagTiming.now()
                val pgpOk = storeInitPgp(ctx, reqId, s.eoa, pgpArmorInInit, pgpPassphraseInInit)
                network.conet.chat.nativekey.DiagTiming.log("init:storeInitPgp", tPgp, if (pgpOk) "ok" else "no")
                if (pgpOk) {
                    val tFin = network.conet.chat.nativekey.DiagTiming.now()
                    finishInit(ctx, reqId, s, attach)
                    network.conet.chat.nativekey.DiagTiming.log("init:finishInit", tFin)
                }
            }
            network.conet.chat.nativekey.DiagTiming.log("init:adoptNativeWallet+done", tAdopt)
        }
    }

    /**
     * Signing uses only the native vault key (spec 25.20.1, R5). The vault must hold the session's account
     * with a passed readback. Otherwise init is refused and the user imports the key natively: nothing is
     * accepted from the bridge, and the page does not sign for the wallet.
     */
    /**
     * `init`'s PGP fields (to be removed with P-IMP-PGP). A key in the payload is written to the native PGP record for
     * the wallet's account, after the wallet check. Nothing is kept in the session, and nothing goes back to the page.
     * With no key in the payload, the existing record stands. Returns `false` after acking an error.
     */
    private fun storeInitPgp(ctx: Context, reqId: Any, eoa: String, armor: String, passphrase: String): Boolean {
        if (armor.isEmpty()) return true
        return when (NativeWallet.pgpFor(ctx, eoa).put(eoa, armor, passphrase)) {
            // The legacy copy L is kept (r3as §25.52.3): this version never clears it.
            NativePgpVault.Put.OK -> true
            else -> {
                ack(reqId, false, error = "pgp_key_rejected")
                false
            }
        }
    }

    private fun adoptNativeWallet(
        ctx: Context,
        host: BeamioOpenPgpHost,
        reqId: Any,
        eoa: String,
        done: () -> Unit,
    ) {
        NativeWallet.migrateLegacy(ctx)
        val vault = NativeWallet.vault(ctx)
        // 25.52Y.75: the snapshot. An unknown state is not_ready: nothing is adopted, imported or written (25.52CS.2).
        val known: NativeWalletVault.State = vault.snapshotState() ?: run {
            scheduleSnapshotRefresh(ctx)
            ack(reqId, false, error = NoKeyGate.NOT_READY)
            return
        }
        when (val st = known) {
            is NativeWalletVault.State.Ready -> {
                if (st.eoa != eoa) {
                    BeamioConetChatSignBroker.clearNativeSigner()
                    ack(reqId, false, error = "address_mismatch")
                    return
                }
                val key = vault.unlock()
                if (key == null) {
                    BeamioConetChatSignBroker.clearNativeSigner()
                    ack(reqId, false, error = "locked")
                    return
                }
                try {
                    BeamioConetChatSignBroker.setNativeSigner(ConetChatCryptoUtil.toHex(key))
                } finally {
                    key.fill(0)
                }
                // G2 (25.26.4c): the record opened and the EOA matched, so the session is ready.
                NativeSessionState.markReady()
                done()
            }
            is NativeWalletVault.State.NoKey -> {
                BeamioConetChatSignBroker.clearNativeSigner()
                ack(reqId, false, error = "no_key")
            }
            is NativeWalletVault.State.Locked -> {
                BeamioConetChatSignBroker.clearNativeSigner()
                ack(reqId, false, error = "locked")
            }
        }
    }

    private fun finishInit(ctx: Context, reqId: Any, s: Session, attach: Boolean) {
        run {
            val history = BeamioConetChatHistoryStore(
                eoa = s.eoa,
                chainId = s.chainId,
                conetRpcUrl = s.conetRpcUrl,
                ipfsBaseUrl = s.ipfsBaseUrl,
                ipfsWriteBaseUrl = s.ipfsWriteBaseUrl.ifBlank { null },
                apiBaseUrl = s.apiBaseUrl,
                registryAddress = s.chatIndexRegistryAddress,
                storageDir = java.io.File(ctx.filesDir, "conet-chat"),
                // Local-DB root from the wallet boundary (in-memory key only; no key -> the local store stays locked).
                dbRootProvider = { BeamioConetChatSignBroker.deriveLocalRoot(s.eoa, "default") },
                log = { level, msg ->
                    // Shape only (counts / short cid) — never plaintext or key material.
                    Log.i(TAG, msg)
                    // Routine history lines stay in logcat only. Forwarding each one to the page
                    // cost a bridge call plus console output per line (2026-11-11: 892 of 947
                    // page console lines were echoed [history] lines). Problems still reach it.
                    if (HistoryLogPolicy.reachesPage(level, msg)) {
                        emitEvent(JSONObject().put("type", "event:log").put("level", level).put("message", msg))
                    }
                },
            )
            history.onLocalEvent = { ev -> emitEvent(localEventJson(ev)) }
            s.history?.destroy()
            s.history = history
            // Listen first: it must not wait on the (sign-dependent) history key derivation.
            emitEvent(JSONObject().put("type", "ready").put("reqId", reqId))
            if (attach) {
                Log.i(TAG, "page attached to the running listen pending=${s.pendingAcks.size}")
                if (listen.isRunning()) emitStatus("listening", "attached") else resumeListen()
                checkOwnRoute(ctx, s, "page attach")
                for ((hash, p) in s.pendingAcks.entries.toList()) {
                    emitInboundMessage(p.plaintext, p.from, hash, p.viaDomain)
                }
            } else {
                startListen(ctx, s)
            }
            if (s.deferAck) replayInbox(ctx, s)
            history.prepare { }
        }
    }

    // ---- no-page start (call push) -----------------------------------------------------

    /**
     * Open the mailbox listen from the stored identity, without the page: a call
     * push woke the app. Messages are handed to [nativeObserver] and kept
     * unconfirmed (no mailbox ACK) until the page starts and stores them. When a
     * session already exists it is only resumed. Returns false when no stored
     * identity can listen (no wallet key, PGP key, route key or roster).
     */
    fun startFromStore(context: Context, reason: String): Boolean {
        val t0 = network.conet.chat.nativekey.DiagTiming.now()
        try {
            return startFromStoreInner(context, reason)
        } finally {
            network.conet.chat.nativekey.DiagTiming.log("startFromStore:$reason", t0)
        }
    }

    private fun startFromStoreInner(context: Context, reason: String): Boolean {
        val ctx = context.applicationContext
        appContext = ctx
        currentSession()?.let { existing ->
            if (listen.isRunning() && !listenConnected) {
                // Reconnecting (e.g. the network was blocked in the background):
                // retry now instead of waiting out the backoff.
                Log.i(TAG, "listen not connected; retrying now for $reason")
                startListen(ctx, existing)
            } else if (!listen.isRunning()) {
                Log.i(TAG, "listen resumed for $reason")
                // Paused by the page in the background: pause again after the call.
                main.post {
                    pauseOwed = true
                    postIdleCheck()
                }
                listen.resume(ctx, existing, onStatus = { st, d -> emitStatus(st, d) }, onInbound = { p, h, v, a -> handleInbound(p, h, v, a) })
            }
            return true
        }
        NativeWallet.migrateLegacy(ctx)
        NativeWallet.migrateLegacyPgp(ctx)
        val vault = NativeWallet.vault(ctx)
        // An unreadable store is unknown: the listen does not start (false), never taken for an absent account (25.52Y.84).
        val walletEoa = try {
            (vault.state() as? NativeWalletVault.State.Ready)?.eoa
        } catch (_: Exception) {
            return false
        }
        // Unknown (unreadable) stored identity is treated as not there: the listen does not start and nothing is written.
        val pgp = try { BeamioChatPgpStore.load(ctx) } catch (_: IOException) { null }
        val pgpReady = try {
            NativeWallet.pgp(ctx).state() is NativePgpVault.State.Ready
        } catch (_: Exception) {
            return false
        }
        if (pgp == null || !pgpReady || !pgp.hasRoutePublic || walletEoa == null) {
            Log.w(TAG, "no stored identity for a no-page listen ($reason)")
            return false
        }
        if (pgp.eoa.isNotBlank() && normalizeAddress(pgp.eoa) != walletEoa) {
            Log.w(TAG, "stored PGP and wallet belong to different wallets; no-page listen skipped")
            return false
        }
        // Only stored nodes that carry a PGP key can be entries; none keyed means the listen does not start.
        val nodes = BeamioChatPgpStore.noPageRoster(BeamioChatPgpStore.loadSiNodes(ctx))
        if (nodes == null) {
            Log.w(TAG, "no-page listen: no stored node has a PGP key ($reason); open the app once to refresh the roster")
            return false
        }
        val walletKey = vault.unlock() ?: run {
            Log.w(TAG, "native wallet key unavailable; no-page listen skipped")
            return false
        }
        val walletHex = ConetChatCryptoUtil.toHex(walletKey)
        walletKey.fill(0)
        val s = Session().apply {
            eoa = walletEoa
            pgpPublicKeyArmored = pgp.publicKeyArmor
            ownRouteArmoredPublicKey = pgp.routePublicKeyArmor
            mailboxIp = pgp.mailboxIp
            this.nodes = nodes.map { Node(it.ip, it.domain, it.region, it.armoredPublicKey) }
            deferAck = true
        }
        synchronized(lock) {
            if (session != null) return true
            session = s
        }
        Log.i(TAG, "no-page listen starting for $reason")
        val host = BeamioOpenPgpHost.shared(ctx)
        host.ensureReady { ok ->
            if (!ok || currentSession() !== s) return@ensureReady
            BeamioConetChatSignBroker.setNativeSigner(walletHex)
            startListen(ctx, s)
        }
        main.post {
            pauseOwed = true
            postIdleCheck()
        }
        return true
    }

    // ---- background pause vs. calls ------------------------------------------------------

    /** Main thread. */
    private fun requestPause() {
        if (keepListenWhile?.invoke() == true) {
            Log.i(TAG, "pause deferred: call in progress")
            pauseOwed = true
            postIdleCheck()
            return
        }
        if (!BeamioListenPolicy.pauseApplies(lifecycleKnown, appInForeground, callInProgress = false)) {
            // The app is in the foreground: it keeps its listen.
            Log.i(TAG, "pause skipped: app in the foreground")
            pauseOwed = false
            return
        }
        pauseOwed = false
        listen.pause()
        emitEvent(JSONObject().put("type", "event:status").put("payload", statusPayload("idle", "paused")))
    }

    /** Main thread. */
    private fun postIdleCheck() {
        if (idleCheckPosted) return
        idleCheckPosted = true
        main.postDelayed({
            idleCheckPosted = false
            if (!pauseOwed) return@postDelayed
            if (keepListenWhile?.invoke() == true) {
                postIdleCheck()
            } else {
                Log.i(TAG, "call over; owed pause applied")
                requestPause()
            }
        }, IDLE_CHECK_MS)
    }

    // ---- app foreground / background (shell) --------------------------------------------

    /** The shell reports the app state ([appForeground] / [appBackground]). Main thread. */
    private var lifecycleKnown = false
    private var appInForeground = true
    /** How long the listen stays after the app goes to the background (a call may be starting). */
    private const val BACKGROUND_GRACE_MS = IDLE_CHECK_MS

    /**
     * Shell: the app went to the background. The app does not run there: the
     * listen is paused after a short grace (a call push or dial may be starting),
     * or when the call that rings / is up ends. Nothing retries while paused.
     */
    fun appBackground(reason: String = "background") {
        main.post {
            lifecycleKnown = true
            if (!appInForeground) return@post
            appInForeground = false
            if (currentSession() == null) return@post
            Log.i(TAG, "app in the background ($reason); listen pauses in ${BACKGROUND_GRACE_MS / 1000}s unless a call needs it")
            pauseOwed = true
            postIdleCheck()
        }
    }

    /**
     * Shell: the app came to the foreground. Reconnect now: resume a paused
     * listen, cut a retry wait short, or reopen a listen the mailbox has been
     * quiet on for 45 s (it may have died while the app was frozen).
     */
    fun appForeground(context: Context, reason: String = "foreground") {
        val ctx = context.applicationContext
        if (appContext == null) appContext = ctx
        main.post {
            lifecycleKnown = true
            appInForeground = true
            pauseOwed = false
            val s = currentSession() ?: return@post
            ensureNetworkWatch(ctx)
            when {
                !listen.isRunning() -> {
                    Log.i(TAG, "app in the foreground ($reason); listen resumed")
                    listen.resume(ctx, s, onStatus = { st, d -> emitStatus(st, d) }, onInbound = { p, h, v, a -> handleInbound(p, h, v, a) })
                }
                !listenConnected -> {
                    Log.i(TAG, "app in the foreground ($reason); retrying the listen now")
                    listen.retryNow()
                }
                else -> resumeListen()
            }
        }
    }

    @Volatile private var networkWatchOn = false

    /**
     * Retry at once when a network comes up, instead of waiting out the backoff.
     * Has an effect only while the listen runs and is not connected (never while
     * paused in the background).
     */
    private fun ensureNetworkWatch(ctx: Context) {
        if (networkWatchOn) return
        networkWatchOn = true
        try {
            val cm = ctx.getSystemService(Context.CONNECTIVITY_SERVICE) as? android.net.ConnectivityManager ?: return
            cm.registerDefaultNetworkCallback(object : android.net.ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: android.net.Network) {
                    if (listen.isRunning() && !listenConnected) {
                        Log.i(TAG, "network available; retrying the listen now")
                        listen.retryNow()
                    }
                    kickOwnRouteCheck()
                }
            })
        } catch (e: Exception) {
            // No ACCESS_NETWORK_STATE: the backoff alone applies.
            Log.w(TAG, "network watch unavailable: ${e.javaClass.simpleName}")
        }
    }

    /**
     * Logout / wallet removed or switched: stop and forget the stored keys.
     *
     * The migration's M and N are removed only after the recovery check of r3av §25.52C.3. The check may read the chain, so it
     * runs on the worker. A refusal (`unregister_refused`) removes nothing and keeps the session. L, the legacy PGP copy, is kept
     * in every case: the migration never removes it, and PM R364 asks that clearIdentity not remove it before the check.
     */
    private fun clearIdentity(reqId: Any) {
        val ctx = appContext
        if (ctx == null) {
            ack(reqId, false, error = IdentityClearCode.CLEAR_INCOMPLETE)
            return
        }
        pgpMigrateWorker.execute {
            // (1a), 25.52PY.8 第 1 项: the C.3 check runs when an account exists. `unregister` checks N and M (§25.52I.8). Anything but `ok`
            // removes nothing.
            // (1a) to (1c) and (2) to (8), PY.8 and PY.12: the refusals come before any write (identityClear). A storage error is a code, never
            // ok (PY.3).
            // An unknown snapshot is not "no account": the clear must not run on a state it cannot determine (25.52Y.75, 25.52CS.2).
            if (NativeWallet.vault(ctx).snapshotState() == null) {
                scheduleSnapshotRefresh(ctx)
                main.post { finishClearIdentity(reqId, IdentityClearCode.CLEAR_INCOMPLETE) }
                return@execute
            }
            val eoa = recoveryAccountOf(ctx)
            val code = runCatching { identityClear(ctx, eoa).clear() }.getOrElse { IdentityClearCode.CLEAR_INCOMPLETE }
            main.post { finishClearIdentity(reqId, code) }
        }
    }

    /**
     * Reports the identity clear. The session stops for every outcome except `unregister_refused`, which removes nothing and keeps the
     * session (§25.52I.8, PY.9). Only `ok` is a success; `clear_incomplete` is returned with no value.
     */
    private fun finishClearIdentity(reqId: Any, code: String) {
        if (code != IdentityClearCode.UNREGISTER_REFUSED) {
            NativeSessionState.reset()
            destroy()
            BeamioConetChatSignBroker.clearNativeSigner()
        }
        Log.i(TAG, "identity clear result=$code")
        if (code == IdentityClearCode.OK) {
            ack(reqId, true, result = JSONObject().put("ok", true))
        } else {
            ack(reqId, false, error = code)
        }
    }

    /**
     * The erase of the identity over the app's stores (25.52PY.8). Page records and the device flags share the no-backup
     * directory `page_record_v1` (the same directory as ShellRecord's flagsOf). The native PGP record and L are not erased.
     */
    private fun identityClear(ctx: Context, eoa: String?): IdentityClear {
        val page = pageRecordFiles(ctx)
        val flags = ClearFlagFiles(page)
        val vault = NativeWallet.vault(ctx)
        val vaultFiles = NativeWallet.migrationFiles(ctx)
        fun holds(): Boolean? = holdsWallet(ctx, vaultFiles, page)
        // (1a): N and M, the migration's own check, with no removal (PY.8 第 1 项).
        val migrationCheck = {
            eoa == null || runCatching { BeamioPgpMigrationImport.clearCheck(ctx, eoa, false).code == MigrationCode.OK }
                .getOrDefault(false)
        }
        // (1c): a native PGP record needs a recovery source, L, P readable, or a chain backup (PY.12). With no account there is no such
        // source, so a record left in the vault refuses the clear.
        val pgpRecordPresent = { NativeWallet.migrationNames(ctx).any { it.startsWith("pgp.v1.") } }
        val pgpSourceAvailable = {
            eoa != null && runCatching { BeamioPgpMigrationImport.clearCheck(ctx, eoa, true).code == MigrationCode.OK }
                .getOrDefault(false)
        }
        // (1b), PY.10 and r3rq: the flag of the account whose W is held. With no account, W cannot be attributed, so it is not confirmed (fail closed).
        val backupConfirmed = { eoa != null && flags.recoveryBackupConfirmed(eoa) }
        return IdentityClear(
            flags = flags,
            backupConfirmed = backupConfirmed,
            migrationCheck = migrationCheck,
            pgpRecordPresent = pgpRecordPresent,
            pgpSourceAvailable = pgpSourceAvailable,
            holdsWallet = { holds() },
            eraseWallet = {
                // (3), PY.8 第 1 项 (3) and r3qy: the migration records (M, N, lastCode) come first, and W is removed only after they all
                // succeeded (M.2). The native PGP envelopes do not depend on that order. If the migration records fail, no W is removed and the
                // backup flag stays, so the redo can finish the records first. Every step that runs is attempted.
                // With an account, its migration records are removed here. With no account, nothing is removed in this clear: the orphan sweep runs in
                // the background at start-up (PY.8 第 7 项, r3rh 第 2 项).
                val migrationRecordsOk = eoa?.let { BeamioPgpMigrationImport.clearMigrationRecords(ctx, it) } ?: true
                val nativePgpOk = NativeWallet.migrationNames(ctx).filter { it.startsWith("pgp.v1.") }
                    .map { eraseChecked(vaultFiles, it) }.all { it }
                if (!migrationRecordsOk) {
                    false
                } else {
                    // The snapshot is dropped in a finally block: an exception in forget() must not leave a stale Ready (25.52Y.75 review).
                    val vaultOk = try {
                        vault.forget()
                    } finally {
                        vault.invalidateSnapshot()
                    }
                    val pagesOk = page.names().filter { !isFlagFile(it) }.map { eraseChecked(page, it) }.all { it }
                    val keystoreOk = BeamioChatWalletKeyStore.clear(ctx)
                    val pgpOk = BeamioChatPgpStore.clearKeepingLegacy(ctx)
                    val migrationWalletOk = eoa?.let { BeamioPgpMigrationImport.clearMigrationWallet(ctx, it) } ?: true
                    // PY.10/PY.11 and r3qv: the recovery-backup flag goes with W only. A failure of the PGP page copy or the PGP envelopes does
                    // not decide the flag (r3qx); it still makes step (3) incomplete, and the redo completes those deletions.
                    // r3rd (R2168 (b)): the PGP page copy (pgpOk) is not part of W; it is still removed in (3), after (1a) and (1c).
                    val wOk = vaultOk && pagesOk && keystoreOk && migrationWalletOk
                    // PM R2212 第 2 项: with no account known, the flags of every account are removed (the W is gone, so none is stale).
                    val flagOk = wOk && (eoa?.let { flags.clearRecoveryBackupConfirmed(it) }
                        ?: eraseBackupFlagsOfUnknownAccount(page.names()) { eraseChecked(page, it) })
                    wOk && flagOk && pgpOk && nativePgpOk
                }
            },
            eraseInbox = { BeamioConetChatInboxStore.clear(ctx) },
            // (5): the reported legacy value is `absent`, only after the wallet and the inbox are erased and no W remains (Y.19 第 10 项).
            // L is kept by design; the unreadable marker (T.5) is not touched here.
            reportLegacyAbsent = { holds() == false && flags.writeLegacyReportAbsent() },
            // (6): the account pointer and its address, the last deletion.
            clearPointer = {
                val pointerOk = eraseChecked(page, DeviceFlagFiles.POINTER)
                val addressOk = eraseChecked(page, DeviceFlagFiles.ADDRESS)
                pointerOk && addressOk
            },
        )
    }

    /** True while the last redo failed (clear_incomplete): wallet and identity commands answer not_ready until a redo succeeds (r3rh). */
    @Volatile
    private var clearRedoBlocked = false

    /** Runs the redo again and sets [clearRedoBlocked] from its result: blocked on clear_incomplete or an exception, free otherwise. */
    private fun retryClearRedo(ctx: Context) {
        // Unknown snapshot: the redo waits for a known state (never run as "no account").
        if (NativeWallet.vault(ctx).snapshotState() == null) {
            scheduleSnapshotRefresh(ctx)
            return
        }
        runCatching { identityClear(ctx, recoveryAccountOf(ctx)).redoIfInterrupted() }
            .onSuccess { code ->
                code?.let { Log.i(TAG, "identity clear redo result=$it") }
                clearRedoBlocked = code == IdentityClearCode.CLEAR_INCOMPLETE
            }
            .onFailure {
                Log.w(TAG, "identity clear redo failed: ${it.javaClass.simpleName}")
                clearRedoBlocked = true
            }
    }

    /** The account of the active pointer, lower-case, or null when it is not set or not readable. Read before the redo removes it. */
    private fun activePointerAccount(ctx: Context): String? = try {
        pageRecordFiles(ctx).read(DeviceFlagFiles.ADDRESS)?.toString(Charsets.UTF_8)?.lowercase()?.takeIf { it.isNotEmpty() }
    } catch (_: Exception) {
        null
    }

    /**
     * PY.8 第 7 项 (r3rd, R2169 (i); r3rf, R2170 (a)), narrowed by 25.52Y.85 第 6 条 (rc2.2-qa item 2): the orphan sweep removes migration
     * records only as the continuation of an interrupted clear ([clearPending], read strictly at start-up), and only of the account that clear
     * involves ([involved], the pointer read before the redo). [OrphanSweepRule] decides the candidates. A live account (the new account) is
     * never removed. Each candidate gets the C.3 check (any one of L, P readable natively, or a chain backup); a passing one is removed in
     * M → N → lastCode order, a refused one is kept. An unknown snapshot, a wallet or an unreadable store keeps everything.
     * Only codes and counts are logged, never an account value. Returns false when a removal failed (clear_incomplete; the redo continues).
     */
    private fun sweepOrphanMigrations(ctx: Context, clearPending: Boolean, involved: String?): Boolean {
        // The live account is needed to exclude it: an unknown snapshot is not "no live account" (fail closed).
        val snap = NativeWallet.vault(ctx).snapshotState() ?: return false
        val live = (snap as? NativeWalletVault.State.Ready)?.eoa
        val accounts = NativeWallet.migrationNames(ctx).mapNotNull { migrationAccountOfName(it) }.distinct()
        // PY.8 第 7 项: W present, or unreadable (the answer unknown), keeps every account (fail closed; nothing is removed).
        val wallet = holdsWallet(ctx, NativeWallet.migrationFiles(ctx), pageRecordFiles(ctx))
        if (wallet != false) {
            // R2172: a diagnostic code and the kept count only, never an account value.
            val code = if (wallet == null) "orphan_sweep_wallet_unknown" else "orphan_sweep_wallet_present"
            Log.i(TAG, "$code kept=${accounts.size}")
            return true
        }
        val candidates = OrphanSweepRule.accountsToRemove(clearPending, involved, live, accounts)
        var removed = 0
        var kept = accounts.size - candidates.size
        var failed = false
        for (account in candidates) {
            if (!BeamioPgpMigrationImport.orphanSourceOk(ctx, account)) {
                kept++
                continue
            }
            if (BeamioPgpMigrationImport.clearMigrationRecords(ctx, account)) removed++ else failed = true
        }
        Log.i(TAG, "orphan migration sweep removed=$removed kept=$kept failed=$failed")
        return !failed
    }

    /**
     * Whether any wallet material may still exist: true, false, or null when the storage cannot be read (then the clear is refused,
     * PY.10 / PY.8 第 6 项).
     */
    private fun holdsWallet(ctx: Context, vaultFiles: VaultFiles, page: AndroidVaultFiles): Boolean? {
        val vaultHas = try {
            listOf(NativeWalletVault.REC, NativeWalletVault.MARK, NativeWalletVault.MNEM, NativeWalletVault.INTENT, NativeWalletVault.COMMIT)
                .any { vaultFiles.read(it) != null }
        } catch (_: Exception) {
            return null
        }
        val pageHas = try {
            page.names().any { !isFlagFile(it) }
        } catch (_: Exception) {
            return null
        }
        val keystoreHas = try {
            ctx.getSharedPreferences(BeamioChatWalletKeyStore.PREFS, Context.MODE_PRIVATE).all.isNotEmpty()
        } catch (_: Exception) {
            return null
        }
        return vaultHas || pageHas || keystoreHas
    }

    private fun isFlagFile(name: String): Boolean {
        val bare = name.removeSuffix(".tmp")
        return bare.startsWith(ClearFlagFiles.BACKUP_PREFIX) || bare in setOf(
            DeviceFlagFiles.POINTER, DeviceFlagFiles.ADDRESS, DeviceFlagFiles.LEGACY,
            ClearFlagFiles.CLEAR_PENDING, ClearFlagFiles.LEGACY_REPORT,
        )
    }

    /** The account whose migration records logout must check: the wallet's, else the legacy copy's. Null when neither. */
    private fun recoveryAccountOf(ctx: Context): String? {
        // 25.52Y.75: the snapshot. An unknown snapshot is not an account and not "no account" either: the caller must check that it is known.
        (NativeWallet.vault(ctx).snapshotState() as? NativeWalletVault.State.Ready)?.let { return it.eoa }
        return BeamioChatPgpStore.legacyCopy(ctx)?.eoa?.takeIf { PgpMigrationPolicy.EOA_RE.matches(it) }
    }

    /**
     * Hand the page what the inbox store holds and the page has not been given
     * in this session (received while it was not running, or never confirmed).
     */
    private fun replayInbox(ctx: Context, s: Session) {
        val all = try {
            BeamioConetChatInboxStore.list(ctx)
        } catch (e: IOException) {
            // Unknown, not empty: nothing is replayed and nothing is written; the mailbox still holds the copies. Retried next session.
            Log.w(TAG, "inbox unreadable; not replayed")
            return
        }
        val stored = all.filter { !s.pendingAcks.containsKey(it.armorHash) }
        if (stored.isEmpty()) return
        Log.i(TAG, "inbox replay count=${stored.size}")
        for (e in stored) {
            synchronized(seenArmor) { seenArmor.remove(e.armorHash) }
            BeamioConetChatListenSession.decryptArmor(ctx, s, e.armor) { line, hash ->
                handleInbound(line, hash, e.viaDomain, e.armor)
            }
        }
    }

    /**
     * `pgpDecryptInbound` (spec 25.34, A1). Order: `reqId`, then the gate (25.34.4), then the payload in
     * [PgpDecryptInbound.answer]. The plaintext goes only into the ack. The log holds the command name and result code.
     */
    /**
     * 25.52AT.1 steps 1 and 2 for a CRED command (25.52AQ.2): an invalid reqId is `bad_request`; otherwise a credential field is
     * `key_over_bridge_refused`, with the field names and no values. Only the names are logged. The gate is not run, and no state changes.
     */
    private fun refuseCredential(command: String, body: JSONObject, names: List<String>) {
        val reqId = PgpDecryptInbound.reqIdOf(body)
        val code = if (reqId == null) "bad_request" else "key_over_bridge_refused"
        Log.i(TAG, "$command result=$code fields=${names.joinToString(",")}")
        val payload = JSONObject().put("type", "ack").put("reqId", reqId ?: JSONObject.NULL).put("ok", false).put("error", code)
        // 25.52BG.5: the names of an ack-level refusal are in the result, not at the top level.
        if (reqId != null) payload.put("result", JSONObject().put("names", JSONArray(names)))
        emitEvent(payload)
    }

    private fun handlePgpDecryptInbound(body: JSONObject) {
        val reqId = PgpDecryptInbound.reqIdOf(body)
        fun refuse(code: String) {
            emitEvent(
                JSONObject().put("type", "ack").put("reqId", reqId ?: JSONObject.NULL).put("ok", false).put("error", code),
            )
            Log.i(TAG, "pgpDecryptInbound result=$code")
        }
        if (reqId == null) return refuse("bad_request")
        val ctx = appContext ?: return refuse("not_ready")
        val vault = NativeWallet.vault(ctx)
        // An unreadable vault is unknown: not_ready, one answer (25.52Y.84), never a gate that allows a decrypt.
        val state = try {
            vault.state()
        } catch (_: Exception) {
            return refuse("not_ready")
        }
        val gate = NoKeyGate.gateOf(state, NativeSessionState.isReady())
        PgpDecryptInbound.gateRefusal(gate, state is NativeWalletVault.State.Locked)?.let { return refuse(it) }
        val eoa = (state as? NativeWalletVault.State.Ready)?.eoa ?: return refuse("locked")
        val pgp = NativeWallet.pgpFor(ctx, eoa)
        val source = object : PgpDecryptInbound.Source {
            // An unreadable key store is unknown: a null subkey is not_ready in PgpDecryptInbound; a failed decrypt is a failed literal.
            override fun subkeyKeyIdHex(): String? = try {
                pgp.identity()?.subkeyKeyId
            } catch (_: Exception) {
                null
            }
            override fun decryptLiteral(armoredMessage: String): NativePgp.LiteralResult = try {
                pgp.decryptInboundLiteral(armoredMessage)
            } catch (_: Exception) {
                NativePgp.LiteralResult.fail("store_unreadable")
            }
        }
        val answer = PgpDecryptInbound.answer(body, eoa, source)
        if (!answer.ok) return refuse(answer.error ?: "decrypt_failed")
        emitEvent(JSONObject().put("type", "ack").put("reqId", reqId).put("ok", true).put("result", answer.result))
        Log.i(TAG, "pgpDecryptInbound result=ok")
    }

    /** N0 `walletAddress` (spec 25.18.2): the account EOA, no signature. */
    private fun walletAddressCommand(body: JSONObject) {
        val reqId = echoId(body)
        val ctx = appContext ?: run {
            ack(reqId, false, error = "not_initialised")
            return
        }
        // A vault that cannot be read is unknown: not_ready, one answer for this reqId (25.52Y.84, Y.104 第 3 条), never no_key.
        val out = try {
            NativeWalletCommands.walletAddress(NativeWallet.vault(ctx))
        } catch (_: Exception) {
            ack(reqId, false, error = "not_ready")
            return
        }
        if (out.code == "ok") ack(reqId, true, result = JSONObject().put("address", out.address))
        else ack(reqId, false, error = out.code)
    }

    /**
     * C2 `gossipSign` (spec 25.23): `{kind, message}`. `message` is the caller's gossip string; it is signed as
     * its UTF-8 bytes. Only `gossip`, `envelope` and `group` are accepted. The reply carries the signature and
     * the signing address, never the key.
     */
    private fun gossipSignCommand(body: JSONObject) {
        val reqId = echoId(body)
        val ctx = appContext ?: run {
            ack(reqId, false, error = "not_initialised")
            return
        }
        val kind = body.optString("kind", "")
        val message = body.optString("message", null) ?: run {
            ack(reqId, false, error = "bad_request")
            return
        }
        // FX.1, FY.1 (r3hy, 25.52FU.1): the request fields are checked before any signature. The page's deferAck comes from init.
        val pageDeferAck = currentSession()?.deferAck == true
        SignRequestRule.check(kind, body, pageDeferAck)?.let { refusal ->
            BridgeCommandTable.countCommandRejected()
            ack(reqId, false, error = refusal)
            return
        }
        val out = NativeMessageSigner.sign(NativeWallet.vault(ctx), kind, message.toByteArray(Charsets.UTF_8))
        if (out.code == "ok") {
            ack(reqId, true, result = JSONObject().put("signature", out.value).put("address", out.address))
        } else {
            // 25.52AW.2, T-53, T-135: a kind or shape refusal of this known command is counted as command_rejected (in-process only). The gate
            // answers (no_key, locked) are not refusals of the kind or shape, so they are not counted.
            if (out.code != "no_key" && out.code != "locked") BridgeCommandTable.countCommandRejected()
            ack(reqId, false, error = out.code)
        }
    }

    /**
     * The shared shape of the three page-open commands (spec r3t §25.41.3, r3x §25.46.10). The decision is
     * [NativeOpenRules]; this sends its ack. A refused field is logged by name only. The reqId is echoed as sent, or null.
     */
    private fun nativeOpenAck(
        body: JSONObject,
        type: String,
        resultType: String? = null,
        decide: (List<String>, Any?) -> NativeOpenRules.Reply,
    ) {
        val fields = body.keys().asSequence().map { it.toString() }.toList()
        NativeOpenRules.firstCredentialField(fields)?.let { Log.w(TAG, "$type refused field: $it") }
        val reqId = PgpDecryptInbound.reqIdOf(body)
        // Any exception on the open path is a closed answer: the page is not left open by a failed decision (review 76706f6d).
        val reply = try {
            decide(fields, reqId)
        } catch (_: Exception) {
            NativeOpenRules.Reply(NativeOpenRules.NOT_AVAILABLE)
        }
        emitEvent(NativeOpenRules.ackPayload(reqId, reply))
        // R1487: the result follows the ack for the same reqId (already_bound or lookup_unavailable: no eoa, no page).
        if (resultType != null && reply.result != null) {
            emitEvent(JSONObject().put("type", resultType).put("reqId", reqId ?: JSONObject.NULL).put("code", reply.result))
        }
    }

    /**
     * `nativeImportOpen` (spec 25.25.1, r3x N-01 to N-07, N-11, N-12, N-15): opens the native import page. The page's result follows as
     * `nativeImportResult` for this reqId (§25.52X.4). Neither the key nor the phrase passes through here.
     */
    private fun nativeImportOpenCommand(body: JSONObject) {
        NativeImportHost.events = { payload -> emitEvent(payload) }
        nativeOpenAck(body, "nativeImportOpen") { fields, reqId ->
            NativeOpenRules.importOpen(fields, reqId, NativeOpenRules.importHost)
        }
    }

    /**
     * `nativeRecoveryOpen` (spec §25.41.3, §25.42.3). The result follows as `nativeRecoveryResult` for this reqId. Neither
     * the code nor the phrase ever passes through here.
     */
    private fun nativeRecoveryOpenCommand(body: JSONObject) {
        NativeRecoveryHost.events = { payload -> emitEvent(payload) }
        nativeOpenAck(body, "nativeRecoveryOpen") { fields, reqId ->
            NativeOpenRules.recoveryOpen(fields, reqId, NativeOpenRules.recoveryHost)
        }
    }

    /**
     * `nativeAccountCreateOpen` (spec r3x §25.46, §25.46.10). The gate is read here and decided in [NativeOpenRules]: G0
     * opens the shell's account page; G1 and G2 answer `not_available` without calling the host; an unregistered page is
     * `not_supported` in every state. It is never `no_key` or `not_ready`.
     */
    private fun nativeAccountCreateOpenCommand(body: JSONObject) {
        val ctx = appContext
        // The result follows as `nativeAccountCreateResult` for this reqId (§25.46.6). No key or phrase passes through here.
        NativeAccountCreateHost.events = { payload -> emitEvent(payload) }
        // The binding lookup may take up to 10 s (§25.52HI.3): the command runs off the caller's thread, and the ack follows the lookup.
        io.execute { nativeAccountCreateOpenRun(ctx, body) }
    }

    private fun nativeAccountCreateOpenRun(ctx: Context?, body: JSONObject) {
        nativeOpenAck(body, "nativeAccountCreateOpen", resultType = "nativeAccountCreateResult") { fields, reqId ->
            // handleCommand sets appContext before dispatch. Without it the gate cannot be read, so the page is not opened.
            // An unreadable gate or vault is a closed answer (not_available), never a page (review 76706f6d).
            val gate = ctx?.let {
                try {
                    NoKeyGate.gateOf(NativeWallet.vault(it).state(), NativeSessionState.isReady())
                } catch (_: Exception) {
                    null
                }
            }
            if (gate == null) {
                NativeOpenRules.Reply(NativeOpenRules.NOT_AVAILABLE)
            } else {
                // Data-safety gate (AccountCreateGuard): only a G0 create can be allowed, and only when the legacy store is confirmed empty,
                // no pointer, no native key, no page copy, and no migration pending. A denial is logged with its code only.
                val denial = if (gate == NoKeyGate.Gate.G0) {
                    ctx?.let { AccountCreateGuard.denialOrClosed { AccountCreateGuard.inputsFor(it) } }
                } else {
                    null
                }
                denial?.let { Log.w(TAG, "nativeAccountCreateOpen refused: $it") }
                val account = body.opt("account") as? String
                NativeOpenRules.accountCreateOpen(
                    fields,
                    reqId,
                    body.opt("account"),
                    gate,
                    NativeOpenRules.accountHost,
                    denial,
                    binding = if (ctx != null && account != null) ({ bindingLookup(ctx, account) }) else null,
                )
            }
        }
    }

    /**
     * The binding lookup before a create (§25.52Z.3, §25.52HH, §25.52HI): one live read of the current registry, then the local sources (HH.2),
     * decided by [BindingDecision]. A tag is looked up by owner; an EOA by account. Nothing is logged here except through the reader's codes.
     */
    private fun bindingLookup(ctx: Context, account: String): BindingCode {
        val kind = if (account.startsWith("0x")) BindingKind.EOA else BindingKind.TAG
        val start = System.nanoTime() / 1_000_000L
        val deadline = RegistryBudget.deadlineFrom(start)
        val reader = ChainRegistryReader()
        val reg = try {
            if (kind == BindingKind.EOA) reader.readAccount(account, deadline) else reader.readOwner(account, deadline)
        } catch (_: Exception) {
            RegistryRead.Invalid("rpc_error")
        }
        val total = System.nanoTime() / 1_000_000L - start
        val (local, device) = bindingLocalSources(ctx, if (kind == BindingKind.EOA) account else null)
        return BindingDecision.decideFromRead(kind, reg, total, local, device)
    }

    /**
     * The local sources of the binding lookup (HH.2, §25.52Y.1, §25.48.4): the wallet key, and K, the SDK account PGP item in the encrypted store
     * (AccountPgpK). Decided by [network.conet.chat.nativekey.BindingLocalSources]. An unreadable keychain or store is fail closed.
     */
    private fun bindingLocalSources(ctx: Context, eoa: String?): Pair<network.conet.chat.nativekey.LocalSource, BindingDevice> {
        val app = ctx.applicationContext
        val vault = try {
            network.conet.chat.nativekey.NativeWallet.vault(app).state()
        } catch (_: Exception) {
            null
        }
        val keyReady = vault is network.conet.chat.nativekey.NativeWalletVault.State.Ready &&
            (eoa == null || vault.eoa.equals(eoa, ignoreCase = true))
        val vaultUnreadable = vault == null || vault is network.conet.chat.nativekey.NativeWalletVault.State.Locked
        val kStore = network.conet.chat.nativekey.AccountPgpK.forDevice(app)
        // The EOA path reads the account's ACTIVE K (a read validates the item: one that names another account is unreadable, fail closed).
        // The tag path has no account, so it asks whether any K exists (kPresent). A non-ACTIVE slot has no store in this build.
        var kActive = false
        var kPresent = false
        var kUnreadable = false
        try {
            if (eoa != null) {
                kActive = kStore.read(eoa, network.conet.chat.nativekey.PgpMigrationPolicy.WORKSPACE) != null
            } else {
                kPresent = kStore.existsAny()
            }
        } catch (_: Exception) {
            kUnreadable = true
        }
        return network.conet.chat.nativekey.BindingLocalSources.of(
            keyReady,
            vaultUnreadable,
            kActive,
            kNonActive = false,
            kUnreadable = kUnreadable,
            kPresent = kPresent,
        )
    }

    private val pgpRestoreWorker = Executors.newSingleThreadExecutor()
    private val PGP_RESTORE_FIELDS = setOf("type", "reqId", "accountKey")
    private val PGP_RESTORE_REFUSED = setOf(
        "privateKeyHex", "privateKeyArmored", "privateKeyArmor", "pgpPrivateKeyArmored", "pgpPassphrase", "passphrase",
        "walletPrivateKey", "mnemonic", "recoveryCode", "pin", "password", "accountPassword",
    )

    /**
     * `pgpRestoreEvaluate` (read only) and `pgpRestore` (evaluate, then write locally on a match; spec §25.35.2 to §25.35.4).
     * The gate has run already, so the wallet is G2. The fields are `type`, `reqId`, `accountKey`. A key or passphrase field
     * is `key_over_bridge_refused`. The chain read and the wallet work run on a worker thread. `pgpRestore` acks `accepted`
     * at once and sends `pgpRestoreResult` when the work is done. Nothing here writes the chain, generates a key, or registers.
     */
    private fun pgpRestoreCommand(body: JSONObject, evaluateOnly: Boolean) {
        val reqId = PgpDecryptInbound.reqIdOf(body)
        fun answer(ok: Boolean, error: String? = null, result: Any? = null) {
            val payload = JSONObject().put("type", "ack").put("reqId", reqId ?: JSONObject.NULL).put("ok", ok)
            if (ok) {
                if (result != null) payload.put("result", result)
            } else {
                payload.put("error", error ?: "error")
            }
            emitEvent(payload)
        }
        val keys = body.keys().asSequence().map { it.toString() }.toList()
        if (keys.any { it in PGP_RESTORE_REFUSED }) return answer(false, "key_over_bridge_refused")
        if (keys.any { it !in PGP_RESTORE_FIELDS }) return answer(false, "bad_request")
        if (reqId == null) return answer(false, "bad_request")
        val ctx = appContext ?: return answer(false, "not_ready")
        // A vault that cannot be read is unknown: not_ready, one answer for this reqId (Y.104 第 3 条), never no_key.
        val state = try {
            NativeWallet.vault(ctx).state()
        } catch (_: Exception) {
            return answer(false, "not_ready")
        }
        if (state is NativeWalletVault.State.Locked) return answer(false, "locked")
        val eoa = (state as? NativeWalletVault.State.Ready)?.eoa ?: return answer(false, "no_key")
        val accountKey = body.optString("accountKey", "")
        val cut = accountKey.lastIndexOf(':')
        if (cut <= 0 || cut == accountKey.length - 1 || !accountKey.substring(0, cut).equals(eoa, ignoreCase = true)) {
            return answer(false, "account_mismatch")
        }
        if (evaluateOnly) {
            val once = SingleReply()
            pgpRestoreWorker.execute {
                // An unreadable store during the evaluation is not_ready: one answer for this reqId, never a silent drop (25.52Y.84).
                // The evaluation and the answer are separate, so a failing emit cannot become a second answer (SingleReply).
                val reply = try {
                    PgpRestoreBridge.evaluate(PgpRestoreBridge.productionMachine(ctx, eoa))
                } catch (e: Exception) {
                    Log.w(TAG, "pgpRestore evaluate failed: ${e.javaClass.simpleName}")
                    null
                }
                once.once { if (reply != null) answer(true, result = reply) else answer(false, "not_ready") }
            }
            return
        }
        answer(true, result = JSONObject().put("accepted", true))
        val resultOnce = SingleReply()
        pgpRestoreWorker.execute {
            // The ack was sent; the result follows once. An unreadable store is not_ready, never a silent drop (25.52Y.84).
            val event = try {
                PgpRestoreBridge.restore(PgpRestoreBridge.productionMachine(ctx, eoa))
            } catch (e: Exception) {
                Log.w(TAG, "pgpRestore restore failed: ${e.javaClass.simpleName}")
                JSONObject().put("code", "not_ready")
            }
            resultOnce.once { emitEvent(event.put("type", "pgpRestoreResult").put("reqId", reqId)) }
            Log.i(TAG, "pgpRestore result=${event.optString("code")}")
        }
    }

    private val pgpMigrateWorker = Executors.newSingleThreadExecutor()
    private val pgpMigrateRunning = AtomicBoolean(false)

    /**
     * `pgpMigrate` (r3at §25.52.4, §25.52.5, §25.52.12): moves the legacy PGP key into the SDK's secure store and verifies it.
     * The request carries no key. The ack is sent at once; the run happens on a worker, and its result is sent as
     * `pgpMigrateResult` with the code and the first 16 characters of the fingerprint. An interrupted run sends nothing; the next
     * `pgpMigrate` resumes it. A second request while a run is in progress is `busy`. Nothing here logs a key or a passphrase.
     */
    private fun pgpMigrateCommand(body: JSONObject) {
        val reqId = PgpDecryptInbound.reqIdOf(body)
        fun answer(ok: Boolean, error: String? = null, fields: List<String>? = null) {
            val payload = JSONObject().put("type", "ack").put("reqId", reqId ?: JSONObject.NULL).put("ok", ok)
            if (!ok) payload.put("error", error ?: "error")
            // 25.52BG.5: the field names are in the result.
            if (fields != null && fields.isNotEmpty()) payload.put("result", JSONObject().put("names", JSONArray(fields)))
            emitEvent(payload)
        }
        val ctx = appContext
        // A vault that cannot be read is unknown: not_ready, one answer for this reqId (Y.104 第 3 条), never a gate that allows a migration.
        val state = try {
            ctx?.let { NativeWallet.vault(it).state() }
        } catch (_: Exception) {
            return answer(false, "not_ready")
        }
        val gate = if (state == null) NoKeyGate.Gate.G1 else NoKeyGate.gateOf(state, NativeSessionState.isReady())
        when (val ack = PgpMigrationBridge.ackFor(body, gate, state is NativeWalletVault.State.Locked, pgpMigrateRunning.get())) {
            is PgpMigrationBridge.Ack.Refused -> return answer(false, ack.code, ack.fields)
            is PgpMigrationBridge.Ack.Busy -> return answer(false, "busy")
            is PgpMigrationBridge.Ack.Accepted -> Unit
        }
        val c = ctx ?: return answer(false, "not_ready")
        val eoa = (state as? NativeWalletVault.State.Ready)?.eoa ?: return answer(false, "locked")
        val id = reqId ?: return answer(false, "bad_request")
        if (!pgpMigrateRunning.compareAndSet(false, true)) return answer(false, "busy")
        answer(true)
        pgpMigrateWorker.execute {
            // The run is computed first, the one result is emitted once (SingleReply): a failing emit is never followed by a second result.
            var event: JSONObject? = null
            try {
                val result = BeamioPgpMigrationImport.run(c, eoa)
                event = PgpMigrationBridge.eventFor(id, result)
                Log.i(TAG, "pgpMigrate result=${result.code.wire}")
            } catch (_: PgpMigrationInterrupted) {
                // Interrupted: no event (§25.52.12). The stored state is resumed by the next request.
                Log.i(TAG, "pgpMigrate interrupted")
            } catch (e: Exception) {
                // A store that cannot be read during the run is unknown: the reread code, never a success or a confirmed none (25.52Y.84).
                event = PgpMigrationBridge.eventFor(id, MigrationResult(MigrationCode.REREAD_FAILED))
                Log.w(TAG, "pgpMigrate failed: ${e.javaClass.simpleName}")
            } finally {
                pgpMigrateRunning.set(false)
            }
            val payload = event ?: return@execute
            SingleReply().once { emitEvent(payload) }
        }
    }

    /**
     * `pgpIdentityCreate` (§25.35.2, §25.35.3, §25.37.4 b): the on-chain registration path is pending approval (§25.44), so
     * the bridge answers `pgpIdentityCreateResult` with `waiting_registration` and writes nothing to the chain. An unknown
     * `reqId` gets the event with a null reqId, as the other results do.
     */
    /**
     * `pgpUpgradeRetry` (25.52Y.63 第 2 项, 25.52Y.64 PR-01..08): the user's click on the upgrade retry. Fields are `type`, `reqId`, `accountKey`;
     * a key, passphrase or armor field is `key_over_bridge_refused` before anything is read. The vault is read on the io executor only, never on the
     * caller's thread. A new key is generated only with the native confirmation, which this build does not have: the click alone never generates
     * (the result is pgp_migration_retry). Every result reaches the page as a pgpUpgradeState event, keep_existing included.
     */
    /** Computes the vault snapshot on the io executor (25.52Y.75): the keystore is never opened on the caller's thread for the gate. */
    private fun scheduleSnapshotRefresh(ctx: Context) {
        network.conet.chat.nativekey.VaultSnapshotRefresh.schedule(ctx)
    }

    /**
     * `accountCleanupOld` (25.52Y.91, Y.100): the page's cleanup after the user's native confirmation, run on the io thread. One ack for this reqId.
     * No key, phrase or confirmation passes through the payload: the confirmation is the native screen's record (CleanupConfirmation).
     */
    private fun accountCleanupOldCommand(body: JSONObject) {
        val ctx = appContext
        io.execute {
            // The dispatch (AccountCleanupDispatch) runs the same AccountCleanupRun the bridge builds; the module only supplies the context.
            val ack = AccountCleanupDispatch.handle(
                reqId = body.opt("reqId"),
                body = body,
                nativeNewAccount = {
                    ctx?.let { (NativeWallet.vault(it).state() as? NativeWalletVault.State.Ready)?.let { ready -> ready.eoa.lowercase() + ":default" } }
                },
                runFor = { ctx?.let { accountCleanupRunFor(it) } },
            )
            emitEvent(ack)
        }
    }

    /** The run of one accountCleanupOld: the production adapters over this app's stores (Y.100, Y.103). */
    private fun accountCleanupRunFor(ctx: Context): CleanupRun {
        val run = accountCleanupRun(ctx)
        return { fields, accountKey, idempotencyKey, newAccountKey, readable ->
            run.run(
                payloadFields = fields,
                accountKey = accountKey,
                idempotencyKey = idempotencyKey,
                gateNotReady = false,
                newAccountKey = newAccountKey,
                newAccountReadable = readable,
            )
        }
    }

    private fun accountCleanupRun(ctx: Context): AccountCleanupRun {
        val state = AndroidVaultFiles(java.io.File(ctx.filesDir, "account_cleanup_v1"))
        return AccountCleanupRun(
            journal = CleanupJournal(state),
            confirmation = CleanupConfirmation(state),
            adapters = AccountCleanupWiring.adapters(
                filesDir = ctx.filesDir,
                noBackupDir = ctx.noBackupFilesDir,
                kPgp = AccountPgpK.cleanupBackend(ctx),
                legacyPgpOwner = { BeamioChatPgpStore.legacyOwnerEoa(ctx) },
                clearLegacyPgp = { BeamioChatPgpStore.clearLegacyRecord(ctx) },
                walletCopyOwner = { BeamioChatWalletKeyStore.ownerEoa(ctx) },
                clearWalletCopy = { BeamioChatWalletKeyStore.clearRecord(ctx) },
                inboxCount = { BeamioConetChatInboxStore.list(ctx).size },
            ),
        )
    }

    private fun pgpUpgradeRetryCommand(body: JSONObject) {
        val reqId = PgpDecryptInbound.reqIdOf(body)
        val keys = body.keys().asSequence().map { it.toString() }.toSet()
        if (keys.any { it in PGP_RESTORE_REFUSED }) { ack(reqId, false, error = "key_over_bridge_refused"); return }
        if (keys.any { it !in PGP_RESTORE_FIELDS }) { ack(reqId, false, error = "bad_request"); return }
        val ctx = appContext
        if (ctx == null) { ack(reqId, false, error = "not_ready"); return }
        val accountKey = body.optString("accountKey", "")
        io.execute {
            val state = try { NativeWallet.vault(ctx).state() } catch (_: Exception) { null }
            // Android has no passcode lock: a storage-derived Locked or no key is not_ready (25.52CS.2).
            val eoa = (state as? NativeWalletVault.State.Ready)?.eoa
            if (eoa == null) { ack(reqId, false, error = "not_ready"); return@execute }
            val cut = accountKey.lastIndexOf(':')
            if (cut <= 0 || cut == accountKey.length - 1 || !accountKey.substring(0, cut).equals(eoa, ignoreCase = true)) {
                ack(reqId, false, error = "account_mismatch")
                return@execute
            }
            // 25.52Y.64 PR-01: the ack is {type, reqId, ok: true, accepted: true} (no result object).
            emitEvent(JSONObject().put("type", "ack").put("reqId", reqId ?: JSONObject.NULL).put("ok", true).put("accepted", true))
            val result = try {
                network.conet.chat.nativekey.KpgpUpgrade.fromDevice(ctx, eoa, userClick = true, nowSec = System.currentTimeMillis() / 1000L, nativeConfirm = false)
            } catch (_: Exception) {
                null
            }
            val code = result?.action ?: "pgp_migration_retry"
            emitEvent(JSONObject().put("type", "pgpUpgradeState").put("code", code))
            Log.i(TAG, "pgpUpgradeRetry result=$code")
        }
    }

    /**
     * `chatRouteRegister` (25.52Y.61 第 2 至 4 项, 25.52Y.66): the native layer builds the registration, submits it itself, and confirms it on chain.
     * The page posts nothing. The answer is {code: "submitted"} on success and only a code on failure; no backup, signature or key field is returned.
     * The vault is read on the io executor only (never on the caller's thread). Route bases: the domain only until the IP roster is wired (see
     * [ROUTE_BASES]); the IP path is not yet live in this build.
     */
    private fun chatRouteRegisterCommand(body: JSONObject) {
        val reqId = PgpDecryptInbound.reqIdOf(body)
        val ctx = appContext
        val parsed = ChatRouteRegister.parse(body)
        if (parsed !is ChatRouteRegister.Parsed.Ok) {
            ack(reqId, false, error = (parsed as ChatRouteRegister.Parsed.Refused).code)
            return
        }
        if (ctx == null) { ack(reqId, false, error = "not_ready"); return }
        val request = parsed.request
        io.execute { registerRouteNative(ctx, reqId, request) }
    }

    private fun registerRouteNative(ctx: Context, reqId: Any?, request: ChatRouteRegister.Request) {
        val vault = NativeWallet.vault(ctx)
        val eoa = (try { vault.state() } catch (_: Exception) { null } as? NativeWalletVault.State.Ready)?.eoa
        if (eoa == null) { ack(reqId, false, error = "not_ready"); return }
        // A vault that cannot be unlocked is a storage-derived failure: not_ready (25.52CS.2). Android has no passcode lock (25.52GQ.3a).
        if (vault.unlock().also { it?.fill(0) } == null) { ack(reqId, false, error = "not_ready"); return }
        var refusal: String? = null
        val outcome = network.conet.chat.nativekey.ChatRouteSubmit.submit(
            bases = ROUTE_BASES,
            bodyFor = { _ ->
                val key = vault.unlock()
                val armor = try { NativeWallet.pgpFor(ctx, eoa).armorForMove()?.toByteArray(Charsets.UTF_8) } catch (_: Exception) { null }
                try {
                    if (key == null) { refusal = "not_ready"; null } else {
                        val nonce = "0x" + ByteArray(16).also { java.security.SecureRandom().nextBytes(it) }.joinToString("") { "%02x".format(it.toInt() and 0xFF) }
                        val iv = ByteArray(12).also { java.security.SecureRandom().nextBytes(it) }
                        when (val built = network.conet.chat.nativekey.ChatRouteRegister.build(
                            request = request,
                            wallet = eoa,
                            eoaPrivateKey = key,
                            pgpPrivateArmor = armor,
                            timestampMs = System.currentTimeMillis(),
                            nonce = nonce,
                            iv = iv,
                        )) {
                            is network.conet.chat.nativekey.ChatRouteRegister.Built.Refused -> { refusal = built.code; null }
                            is network.conet.chat.nativekey.ChatRouteRegister.Built.Ok -> network.conet.chat.nativekey.ChatRouteSubmit.bodyOf(built)
                        }
                    }
                } finally {
                    key?.fill(0)
                    armor?.fill(0)
                }
            },
            poster = network.conet.chat.nativekey.ChatRouteSubmit.HttpPoster,
            chain = network.conet.chat.nativekey.ChatRouteSubmit.ChainCheck { chainRegisteredFor(eoa, request.keyID) },
        )
        when (outcome) {
            is network.conet.chat.nativekey.ChatRouteSubmit.Outcome.Submitted ->
                ack(reqId, true, result = JSONObject().put("code", "submitted"))
            is network.conet.chat.nativekey.ChatRouteSubmit.Outcome.UnverifiedSubmit -> ack(reqId, false, error = "unverified_submit")
            is network.conet.chat.nativekey.ChatRouteSubmit.Outcome.NetworkUnavailable -> ack(reqId, false, error = "network_unavailable")
            is network.conet.chat.nativekey.ChatRouteSubmit.Outcome.Refused ->
                ack(reqId, false, error = refusal ?: outcome.code)
        }
    }

    /** The read-only chain check of a registration (25.52Y.63 第 3 项): true when the directory holds [keyId], false when not, null when unreadable. */
    private fun chainRegisteredFor(eoa: String, keyId: String): Boolean? {
        val chain = network.conet.chat.nativekey.AddressPgpChain.read(eoa) { ep ->
            network.conet.chat.nativekey.AddressPgpRead.HttpRpc(ep.url, ep.timeoutMs)
        }
        if (!chain.chainReadable()) return null
        val id = chain.identity() ?: return false
        return id.subkeyKeyId.equals(keyId, ignoreCase = true)
    }

    private fun pgpIdentityCreateWaiting(body: JSONObject) {
        val reqId = PgpDecryptInbound.reqIdOf(body)
        emitEvent(
            JSONObject().put("type", "pgpIdentityCreateResult").put("reqId", reqId ?: JSONObject.NULL)
                .put("code", "waiting_registration"),
        )
    }

    /**
     * A derivation command (W2 to W4, C5). The account key is unlocked for the call and cleared after it. Only the value the spec
     * allows across the bridge is sent. A vault that is not ready answers `locked`.
     */
    private fun derivationCommand(body: JSONObject, run: (ByteArray, String) -> NativeDerivationCommands.Outcome) {
        val reqId = PgpDecryptInbound.reqIdOf(body)
        val outcome = withUnlockedAccount(run)
        emitEvent(derivationAck(reqId, outcome))
    }

    private fun withUnlockedAccount(run: (ByteArray, String) -> NativeDerivationCommands.Outcome): NativeDerivationCommands.Outcome {
        val locked = NativeDerivationCommands.Outcome.fail(NativeDerivationCommands.LOCKED)
        val ctx = appContext ?: return locked
        val vault = NativeWallet.vault(ctx)
        val ready = vault.state() as? NativeWalletVault.State.Ready ?: return locked
        val key = vault.unlock() ?: return locked
        try {
            return run(key, ready.eoa)
        } finally {
            key.fill(0)
        }
    }

    private fun derivationAck(reqId: Any?, outcome: NativeDerivationCommands.Outcome): JSONObject {
        val payload = JSONObject().put("type", "ack").put("reqId", reqId ?: JSONObject.NULL).put("ok", outcome.ok)
        if (outcome.ok) {
            outcome.result?.let { payload.put("result", it) }
        } else {
            payload.put("error", outcome.error)
        }
        return payload
    }

    /**
     * `identityPublic` (spec r3ae §25.48): the public account material. G0 `no_key` and G1 `not_ready` are answered before the
     * payload is read; in G2 the input is checked, then the result is built from the native public facts only. A refused
     * credential field is logged by name only.
     */
    private fun identityPublicCommand(body: JSONObject) {
        val reqId = PgpDecryptInbound.reqIdOf(body)
        val ctx = appContext
        val reply = if (ctx == null) {
            IdentityPublic.Reply(IdentityPublic.NOT_READY, null)
        } else {
            val snap = NativeWallet.vault(ctx).snapshotState()
            if (snap == null) {
                scheduleSnapshotRefresh(ctx)
                ack(reqId, false, error = NoKeyGate.NOT_READY)
                return
            }
            val gate = NoKeyGate.gateOf(snap, NativeSessionState.isReady())
            IdentityPublic.answer(
                gate,
                { body.keys().asSequence().map { it.toString() }.toList() },
                reqId,
                identityPublicSource(ctx),
            )
        }
        reply.refused?.let { Log.w(TAG, "identityPublic refused field: $it") }
        emitEvent(IdentityPublic.ackPayload(reqId, reply))
    }

    /**
     * The native source of identityPublic. The account is the session's. The PGP record is not read here yet, so the PGP part is
     * `NotRead` and `pgpReady` stays false. That is not an error, and it is not "no identity" (§25.48.9, §25.30.3). The session's
     * PGP copies come from the PWA's init, and are not used here.
     */
    private fun identityPublicSource(app: Context): IdentityPublic.Source = object : IdentityPublic.Source {
        override fun eoa(): String? = currentSession()?.eoa
        override fun pgp(): IdentityPublic.PgpRecord = IdentityPublic.PgpRecord.NotRead

        // 25.48.4, 25.52Y.90: any K_pgp on the device. An unreadable store gives null (unknown), never false.
        override fun kPresent(): Boolean? = try {
            network.conet.chat.nativekey.AccountPgpK.forDevice(app).existsAny()
        } catch (_: Exception) {
            null
        }
    }

    /**
     * `provisionIdentity` (spec 25.19.2): public material only. Any wallet or PGP private field is refused.
     * The reply is `{ready, eoa}`; `ready` is true only when the native vault holds this account's key with a
     * passed readback. The module stores nothing from this call.
     */
    private fun provisionIdentity(body: JSONObject) {
        val reqId = echoId(body)
        val p = body.optJSONObject("payload") ?: body
        // The contract refuses key material and non-canonical input before anything else is read.
        val checked = IdentityProvisionContract.validate(IdentityProvisionContract.Command.PROVISION_IDENTITY, p)
        if (checked is IdentityProvisionContract.Result.Reject) {
            Log.w(TAG, "provisionIdentity refused: ${checked.error}")
            ack(reqId, false, error = checked.error)
            return
        }
        val eoa = (checked as IdentityProvisionContract.Result.Accept).eoa
        val ctx = appContext ?: run {
            ack(reqId, false, error = "not_initialised")
            return
        }
        NativeWallet.migrateLegacy(ctx)
        // 25.52Y.75: the snapshot. Unknown is not_ready: an absent or unknown vault must never look like "no key" (25.52CS.2).
        val snapState = NativeWallet.vault(ctx).snapshotState()
        if (snapState == null) {
            scheduleSnapshotRefresh(ctx)
            ack(reqId, false, error = NoKeyGate.NOT_READY)
            return
        }
        val vaultEoa = (snapState as? NativeWalletVault.State.Ready)?.eoa
        val state = IdentityProvisionContract.nativeKeyState(vaultEoa, eoa)
        val result = IdentityProvisionContract.readyResponse(eoa, state)
        Log.i(TAG, "identity provisioned ready=${result.optBoolean("ready")}")
        ack(reqId, true, result = result)
    }

    // ---- call layer entry (no page involved) ----------------------------------------------

    /**
     * Native call layer: a call push arrived, a call rings or is up, or the app
     * came to the foreground. Opens / resumes the mailbox listen from the stored
     * identity. Same as [startFromStore].
     */
    fun wake(context: Context, reason: String): Boolean {
        val t0 = network.conet.chat.nativekey.DiagTiming.now()
        try {
            return startFromStore(context, reason)
        } finally {
            network.conet.chat.nativekey.DiagTiming.log("wake:$reason", t0)
        }
    }

    /** Native call layer: the call is over. Applies an owed background pause now. */
    fun release(reason: String) {
        main.post {
            if (pauseOwed && keepListenWhile?.invoke() != true) {
                Log.i(TAG, "released ($reason); owed pause applied")
                requestPause()
            }
        }
    }

    // ---- send ---------------------------------------------------------------------

    private fun handleSend(body: JSONObject) {
        val reqId = echoId(body)
        val ctx = appContext
        val s = currentSession()
        val to = body.optJSONObject("to")
        if (ctx == null || s == null || to == null) {
            ack(reqId, false, error = "not_ready")
            return
        }
        val payload = body.optString("payload", "")
        val sendId = body.optString("sendId", "").ifBlank { UUID.randomUUID().toString() }
        val noPush = body.optBoolean("beamioNoPush", false)
        val userPgp = to.optString("userPublicKeyArmored", "").trim()
        val mailboxRoute = to.optString("routerArmoredPublicKey", "").trim()
        if (!userPgp.contains("BEGIN PGP PUBLIC KEY")) {
            ack(reqId, false, error = "missing_recipient_pgp")
            return
        }
        // Every send is wrapped to the recipient's mailbox route key, so the entry
        // never sees the recipient key ID. Without that route: not sent.
        if (!mailboxRoute.contains("BEGIN PGP PUBLIC KEY")) {
            ack(reqId, false, error = "recipient_mailbox_unknown")
            return
        }
        val host = BeamioOpenPgpHost.shared(ctx)
        BeamioConetChatSignBroker.requestEip191(payload) { signResult ->
            val signature = signResult.getOrElse {
                ack(reqId, false, error = it.message ?: "sign_failed")
                return@requestEip191
            }
            val envelope = JSONObject()
                .put("timestamp", System.currentTimeMillis())
                .put("text", payload)
                .put("from", s.eoa)
                .put("signMessage", signature)
            host.encryptUtf8JsonBase64(envelope.toString(), userPgp) { enc ->
                val armor = enc.getOrElse {
                    ack(reqId, false, error = it.message ?: "encrypt_failed")
                    return@encryptUtf8JsonBase64
                }
                val finish = { finalArmor: String ->
                    io.execute {
                        val ok = postToEntries(ctx, finalArmor, mailboxRoute, s)
                        ack(reqId, true, result = JSONObject().put("sent", ok).put("sendId", sendId))
                    }
                }
                host.wrapArmorToMailboxWork(armor, mailboxRoute, noPush) { wrapped ->
                    wrapped.fold(
                        onSuccess = { finish(it) },
                        onFailure = { ack(reqId, false, error = it.message ?: "wrap_failed") },
                    )
                }
            }
        }
    }

    private fun handleGroup(body: JSONObject) {
        val reqId = echoId(body)
        val ctx = appContext
        val s = currentSession()
        val request = body.optJSONObject("request")
        val members = request?.optJSONObject("roster")?.optJSONArray("members")
        if (ctx == null || s == null || request == null || members == null || members.length() == 0) {
            // Roster / tombstone requests without members are acknowledged as a no-op.
            ack(reqId, true, result = JSONObject().put("ok", true))
            return
        }
        val text = request.optString("body", "").ifBlank { request.optString("text", "") }
        val groupId = request.optString("groupId", "")
            .ifBlank { request.optJSONObject("roster")?.optString("groupId", "").orEmpty() }
        val host = BeamioOpenPgpHost.shared(ctx)
        BeamioConetChatSignBroker.requestEip191(text) { signResult ->
            val signature = signResult.getOrElse {
                ack(reqId, false, error = "group_sign_failed")
                return@requestEip191
            }
            val envelope = JSONObject()
                .put("timestamp", System.currentTimeMillis())
                .put("text", text)
                .put("from", s.eoa)
                .put("signMessage", signature)
                .put("groupId", groupId)
            io.execute {
                var delivered = 0
                val latch = CountDownLatch(members.length())
                for (i in 0 until members.length()) {
                    val member = members.optJSONObject(i)
                    val pgp = member?.optString("userPublicKeyArmored", "")
                        ?.ifBlank { member.optString("pgpPublicKeyArmored", "") }.orEmpty()
                    val route = member?.optString("routerArmoredPublicKey", "").orEmpty()
                    // Wrapped to the member's mailbox: no route, no delivery.
                    if (!pgp.contains("BEGIN PGP PUBLIC KEY") || !route.contains("BEGIN PGP PUBLIC KEY")) {
                        latch.countDown()
                        continue
                    }
                    host.encryptUtf8JsonBase64(envelope.toString(), pgp) { enc ->
                        val userArmor = enc.getOrNull()
                        if (userArmor == null) {
                            latch.countDown()
                            return@encryptUtf8JsonBase64
                        }
                        host.wrapArmorToMailboxWork(userArmor, route, false) { wrapped ->
                            io.execute {
                                try {
                                    val armor = wrapped.getOrNull()
                                    if (armor != null && postToEntries(ctx, armor, route, s)) {
                                        synchronized(this) { delivered += 1 }
                                    }
                                } finally {
                                    latch.countDown()
                                }
                            }
                        }
                    }
                }
                latch.await(60, TimeUnit.SECONDS)
                ack(reqId, true, result = JSONObject().put("delivered", delivered).put("members", members.length()))
            }
        }
    }

    // ---- presence / native wake ---------------------------------------------------

    private fun handleQueryPresence(body: JSONObject) {
        val reqId = echoId(body)
        val s = currentSession()
        if (s == null) {
            ack(reqId, false, error = "not_ready")
            return
        }
        val contacts = body.optJSONArray("contacts")?.let { objects(it) }.orEmpty()
        if (contacts.isEmpty()) {
            ack(reqId, true, result = JSONObject())
            return
        }
        io.execute {
            val result = JSONObject()
            val latch = CountDownLatch(contacts.size)
            for (c in contacts) {
                val target = normalizeAddress(c.optString("address", "").ifBlank { c.optString("eoaAddress", "") })
                val route = c.optString("routerArmoredPublicKey", "")
                if (target.isEmpty() || !route.contains("BEGIN PGP PUBLIC KEY")) {
                    latch.countDown()
                    continue
                }
                postSignedMailboxCommand(
                    s, route,
                    JSONObject().put("command", "wallet_online_query").put("targetWallet", target),
                ) { ok, json ->
                    try {
                        if (ok && json != null && json.optBoolean("ok", false)) {
                            val online = json.optBoolean("online", false)
                            synchronized(result) { result.put(target, online) }
                            emitEvent(
                                JSONObject().put("type", "event:presence").put(
                                    "payload",
                                    JSONObject().put("wallet", target).put("online", online).put("ok", true),
                                ),
                            )
                        }
                    } finally {
                        latch.countDown()
                    }
                }
            }
            latch.await(30, TimeUnit.SECONDS)
            ack(reqId, true, result = result)
        }
    }

    private fun handleQueryNativeWake(body: JSONObject) {
        val reqId = echoId(body)
        val s = currentSession()
        val contact = body.optJSONObject("contact")
        if (s == null || contact == null) {
            ack(reqId, false, error = "not_ready")
            return
        }
        val target = normalizeAddress(contact.optString("address", "").ifBlank { contact.optString("eoaAddress", "") })
        val route = contact.optString("routerArmoredPublicKey", "")
        if (target.isEmpty() || !route.contains("BEGIN PGP PUBLIC KEY")) {
            ack(reqId, false, error = "bad_native_wake")
            return
        }
        postSignedMailboxCommand(
            s, route,
            JSONObject().put("command", "wallet_native_wake_query").put("targetWallet", target),
        ) { ok, json ->
            if (ok && json != null && json.optBoolean("ok", false)) {
                ack(
                    reqId, true,
                    result = JSONObject().put("ok", true).put("wallet", target)
                        .put("nativeWakeable", json.optBoolean("nativeWakeable", false)),
                )
            } else {
                ack(reqId, true, result = JSONObject().put("ok", false).put("wallet", target))
            }
        }
    }

    // ---- history ------------------------------------------------------------------

    private fun handleHistoryLoad(body: JSONObject) {
        val reqId = echoId(body)
        val hist = currentSession()?.history
        if (hist == null || !hist.isReady()) {
            // History key derivation (a PWA signature) may still be in flight: not an error.
            ack(reqId, true, result = JSONObject.NULL)
            return
        }
        hist.load(
            body.optJSONObject("options"),
            emitBuffer = { peer, entries, isTail ->
                emitEvent(
                    JSONObject().put("type", "event:historyBuffer").put(
                        "payload",
                        JSONObject()
                            .put("peer", peer)
                            .put("entries", JSONArray().also { arr -> entries.forEach { arr.put(it.toJson()) } })
                            .put("isTail", isTail),
                    ),
                )
            },
            done = { ack(reqId, true, result = JSONObject.NULL) },
        )
    }

    /** Unbounded historyRead calls since start. Phase one (interface spec v0.2 12.2): counted, never refused. */
    private val unboundedHistoryReads = java.util.concurrent.atomic.AtomicInteger(0)

    private fun handleHistoryRead(body: JSONObject) {
        val reqId = echoId(body)
        val options = body.optJSONObject("options")
        if (options == null || !options.has("limit")) {
            // Full result is kept as before. Log the caller label only, never content.
            val n = unboundedHistoryReads.incrementAndGet()
            val caller = options?.optString("caller").orEmpty().ifEmpty { "unknown" }
            Log.i(TAG, "historyRead.unbounded caller=$caller count=$n")
        }
        val hist = currentSession()?.history
        if (hist == null || !hist.isReady()) {
            ack(reqId, true, result = JSONArray())
            return
        }
        hist.read(options) { entries ->
            ack(reqId, true, result = JSONArray().also { arr -> entries.forEach { arr.put(it.toJson()) } })
        }
    }

    private fun handleHistoryAppend(body: JSONObject) {
        val reqId = echoId(body)
        val hist = currentSession()?.history
        val entry = body.optJSONObject("entry")
        if (hist == null || entry == null || !hist.isReady()) {
            ack(reqId, false, error = "history_not_ready")
            return
        }
        hist.append(entry) { ok ->
            ack(reqId, ok, result = JSONObject().put("ok", ok), error = if (ok) null else "append_failed")
        }
    }

    // ---- local read store (interface spec v0.2 6.2–6.4) -----------------------------

    private fun lockedPage(error: String): LocalPage =
        LocalPage(emptyList(), null, false, LocalSource.LOCKED, error)

    private fun viewportOf(o: JSONObject?): LocalViewport? {
        if (o == null) return null
        return try {
            val w = o.getDouble("widthPt")
            val h = o.getDouble("heightPt")
            LocalViewport(
                widthPt = w,
                heightPt = h,
                orientation = o.optString("orientation", if (h >= w) "portrait" else "landscape"),
                fontScale = o.optDouble("fontScale", 1.0),
                layoutVersion = o.optInt("layoutVersion", 1),
            )
        } catch (e: Exception) {
            null
        }
    }

    private fun kindName(kind: LocalMediaKind): String = kind.name.lowercase()

    private fun itemJson(item: PageItem): JSONObject {
        val o = JSONObject()
            .put("stableId", item.stableId)
            .put("sortTs", item.sortTs)
            .put("dir", item.dir)
            .put("sendId", item.sendId ?: JSONObject.NULL)
            // §25.52AC.2: the sendKey, which historyDeleteMessage takes as messageId.
            .put("messageId", item.messageId ?: JSONObject.NULL)
            .put("kind", kindName(item.kind))
            .put("revision", item.revision)
            .put(
                "layout",
                JSONObject().put("wPt", item.layoutW).put("hPt", item.layoutH).put("measured", item.measured),
            )
        item.body?.let { o.put("body", it) }
        if (item.mediaState != null) {
            o.put(
                "media",
                JSONObject()
                    .put("cid", item.mediaCid ?: JSONObject.NULL)
                    .put("mime", item.mediaMime ?: JSONObject.NULL)
                    .put("widthPx", item.widthPx ?: JSONObject.NULL)
                    .put("heightPx", item.heightPx ?: JSONObject.NULL)
                    .put("state", item.mediaState),
            )
        }
        return o
    }

    private fun pageJson(page: LocalPage): JSONObject {
        val items = JSONArray()
        for (item in page.items) items.put(itemJson(item))
        return JSONObject()
            .put("items", items)
            .put("olderCursor", page.olderCursor ?: JSONObject.NULL)
            .put("olderState", page.olderState)
            .put("scanExhausted", page.scanExhausted)
            .put("generation", page.generation)
            .put("syncState", page.syncState)
            .put(
                "source",
                when (page.source) {
                    LocalSource.LOCAL -> "local"
                    LocalSource.MIGRATING -> "migrating"
                    LocalSource.LOCKED -> "locked"
                },
            )
            .put("short", page.short)
            .put("capped", page.capped)
            .put("error", page.error ?: JSONObject.NULL)
    }

    /** Events for the page: `event:historyChange` with `payload.kind` (inserted, updated, deleted, cleared). */
    private fun localEventJson(ev: LocalChatEvent): JSONObject {
        val p = JSONObject()
        when (ev) {
            is LocalChatEvent.Inserted -> {
                val items = JSONArray()
                for (item in ev.items) items.put(itemJson(item))
                p.put("kind", "inserted").put("convKey", ev.convKey).put("position", ev.position).put("items", items)
            }
            is LocalChatEvent.Updated -> p.put("kind", "updated").put("convKey", ev.convKey)
                .put("stableId", ev.stableId).put("revision", ev.revision)
            is LocalChatEvent.Deleted -> p.put("kind", "deleted").put("convKey", ev.convKey).put("stableId", ev.stableId)
            is LocalChatEvent.OlderAvailable -> p.put("kind", "olderAvailable").put("convKey", ev.convKey)
            LocalChatEvent.Locked -> p.put("kind", "locked")
            is LocalChatEvent.Cleared -> p.put("kind", "cleared").put("scope", ev.scope)
                .put("convKey", ev.convKey ?: JSONObject.NULL).put("pendingKept", ev.pendingKept)
        }
        return JSONObject().put("type", "event:historyChange").put("payload", p)
    }

    /** The gate (G0 `no_key`, G1 `not_ready`) and then the answer of [NativeHistoryDelete]: one ack per request, sent through the event channel. */
    private fun historyDeleteCommand(context: Context, type: String, body: JSONObject) {
        // 25.52Y.75: the snapshot. An unknown state is not_ready, and nothing is deleted or read from the payload.
        val snap = NativeWallet.vault(context).snapshotState()
        if (snap == null) scheduleSnapshotRefresh(context)
        val gate = NoKeyGate.gateOf(snap ?: return emitEvent(NativeHistoryDelete.ack(type, body, NoKeyGate.NOT_READY, currentSession()?.history?.localStore())), NativeSessionState.isReady())
        val answer = NoKeyGate.answerFor(type, gate)
        val refusal = if (answer == NoKeyGate.NO_KEY || answer == NoKeyGate.NOT_READY) answer else null
        emitEvent(NativeHistoryDelete.ack(type, body, refusal, currentSession()?.history?.localStore()))
    }

    private fun handleHistoryOpen(body: JSONObject) {
        val reqId = echoId(body)
        val convKey = body.optString("convKey", "").lowercase()
        val vp = viewportOf(body.optJSONObject("viewport"))
        if (convKey.isEmpty() || vp == null) {
            ack(reqId, false, error = "bad_request")
            return
        }
        val store = currentSession()?.history?.localStore()
        ack(reqId, true, result = pageJson(store?.openConversation(convKey, vp) ?: lockedPage("not_ready")))
    }

    private fun handleHistoryLoadOlder(body: JSONObject) {
        val reqId = echoId(body)
        val convKey = body.optString("convKey", "").lowercase()
        val cursor = body.optString("cursor", "")
        val vp = viewportOf(body.optJSONObject("viewport"))
        if (convKey.isEmpty() || cursor.isEmpty() || vp == null) {
            ack(reqId, false, error = "bad_request")
            return
        }
        val store = currentSession()?.history?.localStore()
        ack(reqId, true, result = pageJson(store?.loadOlder(convKey, cursor, vp) ?: lockedPage("not_ready")))
    }

    private fun handleHistoryReportLayout(body: JSONObject) {
        val reqId = echoId(body)
        val hist = currentSession()?.history
        val store = hist?.localStore()
        val convKey = body.optString("convKey", "").lowercase()
        val stableId = body.optString("stableId", "")
        val vp = viewportOf(body.optJSONObject("viewport"))
        val wPt = body.optDouble("wPt", Double.NaN)
        val hPt = body.optDouble("hPt", Double.NaN)
        if (store == null || convKey.isEmpty() || stableId.isEmpty() || vp == null || wPt.isNaN() || hPt.isNaN() || hPt <= 0) {
            ack(reqId, false, error = "bad_request")
            return
        }
        val written = store.reportLayout(convKey, stableId, vp, wPt, hPt)
        ack(reqId, true, result = JSONObject().put("written", written))
    }

    private fun handleHistoryClearCache(body: JSONObject) {
        val reqId = echoId(body)
        val hist = currentSession()?.history
        val store = hist?.localStore()
        if (store == null) {
            ack(reqId, false, error = "not_ready")
            return
        }
        val pendingKept = when (body.optString("scope", "")) {
            "conversation" -> {
                val convKey = body.optString("convKey", "").lowercase()
                if (convKey.isEmpty()) {
                    ack(reqId, false, error = "bad_request")
                    return
                }
                store.clearConversation(convKey)
            }
            "account" -> store.clearAccount()
            else -> {
                ack(reqId, false, error = "bad_request")
                return
            }
        }
        ack(reqId, true, result = JSONObject().put("pendingKept", pendingKept))
    }

    private fun handleHistoryFullSync(body: JSONObject) {
        val reqId = echoId(body)
        val hist = currentSession()?.history
        if (hist == null || !hist.isReady()) {
            ack(reqId, false, error = "not_ready")
            return
        }
        hist.startFullSync { ok -> ack(reqId, ok, result = JSONObject().put("ok", ok), error = if (ok) null else "sync_failed") }
    }

    /** Migration import (spec r2 11.2): at most 200 rows per call. Sendkeys, stable ids, dedupe and sealing are native. */
    private fun handleHistoryImportBatch(body: JSONObject) {
        val reqId = echoId(body)
        val hist = currentSession()?.history
        val store = hist?.localStore()
        if (store == null) {
            ack(reqId, false, error = "not_ready")
            return
        }
        if (body.optString("accountKey", "") != store.accountKey) {
            ack(reqId, false, error = "account_mismatch")
            return
        }
        val arr = body.optJSONArray("rows")
        if (arr == null) {
            ack(reqId, false, error = "bad_request")
            return
        }
        if (arr.length() > 200) {
            ack(reqId, false, error = "batch_too_large")
            return
        }
        val rows = ArrayList<network.conet.chat.localread.ImportRow>(arr.length())
        for (i in 0 until arr.length()) {
            val o = arr.optJSONObject(i)
            val conv = o?.optString("convKey", "")?.lowercase().orEmpty()
            val dir = o?.optString("dir", "").orEmpty()
            if (o == null || conv.isEmpty() || (dir != "in" && dir != "out") || !o.has("ts") || !o.has("body")) {
                ack(reqId, false, error = "bad_request")
                return
            }
            rows.add(
                network.conet.chat.localread.ImportRow(
                    convKey = conv,
                    sendId = o.optString("sendId", "").ifEmpty { null },
                    dir = dir,
                    ts = o.optLong("ts"),
                    body = o.optString("body"),
                    pendingPublish = o.optBoolean("pendingPublish", false),
                    cid = o.optString("cid", "").ifEmpty { null },
                ),
            )
        }
        val r = store.importRows(rows)
        ack(
            reqId,
            true,
            result = JSONObject()
                .put("inserted", r.inserted)
                .put("existing", r.existing)
                .put("collapsed", r.collapsed)
                .put("rejected", r.rejected),
        )
    }

    /** Row count and the M3 digest of the held rows, for the PWA to compare (spec r2 11.1 M3, 11.2). */
    private fun handleHistoryVerifyImport(body: JSONObject) {
        val reqId = echoId(body)
        val store = currentSession()?.history?.localStore()
        if (store == null) {
            ack(reqId, false, error = "not_ready")
            return
        }
        if (body.optString("accountKey", "") != store.accountKey) {
            ack(reqId, false, error = "account_mismatch")
            return
        }
        val v = store.verifyDigest()
        ack(reqId, true, result = JSONObject().put("rows", v.rows).put("digest", v.digest))
    }

    // ---- mailbox commands / voice ----------------------------------------------------

    private fun handleMailboxCommand(body: JSONObject) {
        val reqId = echoId(body)
        val s = currentSession()
        if (s == null) {
            ack(reqId, false, error = "not_ready")
            return
        }
        val routeKey = body.optString("routerArmoredPublicKey", "")
        val command = body.optJSONObject("command")
        if (command == null || !routeKey.contains("BEGIN PGP PUBLIC KEY")) {
            ack(reqId, false, error = "bad_mailbox_command")
            return
        }
        // Voice commands never carry a wallet or wallet signature.
        if (command.optString("command", "").startsWith("voice_")) {
            postOpaqueVoiceCommand(s, routeKey, command) { ok ->
                ack(reqId, true, result = JSONObject().put("ok", ok))
            }
            return
        }
        postSignedMailboxCommand(s, routeKey, command) { ok, _ ->
            ack(reqId, true, result = JSONObject().put("ok", ok))
        }
    }

    private fun handleVoiceListen(body: JSONObject) {
        val reqId = echoId(body)
        val sessionId = body.optString("sessionId", "")
        synchronized(lock) { voiceSessions.add(sessionId) }
        // The shell's native voice signaling owns the voice SSE — never open a second one.
        ack(reqId, true, result = JSONObject().put("ok", true).put("delegated", true).put("sessionId", sessionId))
    }

    private fun handleVoiceUnlisten(body: JSONObject) {
        val reqId = echoId(body)
        synchronized(lock) { voiceSessions.remove(body.optString("sessionId", "")) }
        ack(reqId, true, result = JSONObject().put("ok", true))
    }

    private fun handleVoiceFrame(body: JSONObject) {
        val reqId = echoId(body)
        val s = currentSession()
        if (s == null) {
            ack(reqId, false, error = "not_ready")
            return
        }
        val routeKey = body.optString("routerArmoredPublicKey", "")
        val frame = body.optJSONObject("frame")
        if (frame == null || !routeKey.contains("BEGIN PGP PUBLIC KEY")) {
            ack(reqId, false, error = "bad_voice_frame")
            return
        }
        val command = opaqueVoiceUplinkCommand(frame)
        if (command == null) {
            ack(reqId, false, error = "bad_voice_frame")
            return
        }
        postOpaqueVoiceCommand(s, routeKey, command) { ok ->
            ack(reqId, true, result = JSONObject().put("sent", ok))
        }
    }

    /**
     * Rebuild a PWA voice frame as the route command the peer's mailbox reads.
     *
     * Allow-list only: the PWA frame carries `to` (the peer wallet), and the relay
     * routes by session id alone (CoNET Chat protocol rules 18–21). Same shape as
     * the native shells and the PWA worker SDK send.
     */
    internal fun opaqueVoiceUplinkCommand(frame: JSONObject): JSONObject? {
        val callId = frame.optString("callId", "").trim()
        val sessionId = frame.optString("sessionId", "").trim()
        val targetSessionId = frame.optString("targetSessionId", "").trim()
        val payload = frame.optString("payload", "")
        val seq = frame.optLong("seq", -1L)
        if (callId.isEmpty() || sessionId.isEmpty() || targetSessionId.isEmpty() || payload.isEmpty() || seq < 0) {
            return null
        }
        val nowSec = System.currentTimeMillis() / 1000L
        val command = JSONObject()
            .put("command", "voice_uplink")
            .put("type", "voice_frame_v1")
            .put("callId", callId)
            .put("sessionId", sessionId)
            .put("targetSessionId", targetSessionId)
            .put("direction", frame.optString("direction", "").ifBlank { "uplink" })
            .put("seq", seq)
            .put("frameTimestamp", frame.opt("frameTimestamp") ?: frame.opt("timestamp") ?: nowSec)
            .put("payload", payload)
            .put("timestamp", nowSec)
        for (key in listOf("mediaKind", "frameId", "chunkIndex", "chunkCount")) {
            if (frame.has(key)) command.put(key, frame.get(key))
        }
        return command
    }

    /**
     * Voice route command: unsigned, no wallet. A wallet signature would let the
     * mailbox recover the sender's wallet, and the node does not ask for one
     * (sessionId is the capability). JSON → base64 → route PGP → entry ≠ B.
     */
    private fun postOpaqueVoiceCommand(
        s: Session,
        routerArmoredPublicKey: String,
        command: JSONObject,
        completion: (ok: Boolean) -> Unit,
    ) {
        val ctx = appContext
        if (ctx == null) {
            completion(false)
            return
        }
        val cmd = JSONObject(command.toString())
        for (key in listOf("walletAddress", "billingWallet", "from", "to")) cmd.remove(key)
        if (!cmd.has("timestamp")) cmd.put("timestamp", System.currentTimeMillis() / 1000)
        BeamioOpenPgpHost.shared(ctx).encryptUtf8JsonBase64(cmd.toString(), routerArmoredPublicKey) { enc ->
            val armor = enc.getOrNull()
            if (armor == null || !armor.contains("BEGIN PGP MESSAGE")) {
                completion(false)
                return@encryptUtf8JsonBase64
            }
            io.execute { completion(postToEntries(ctx, armor, routerArmoredPublicKey, s)) }
        }
    }

    // ---- listen lifecycle -------------------------------------------------------------

    private fun startListen(ctx: Context, s: Session) {
        ensureNetworkWatch(ctx)
        listen.start(ctx, s, onStatus = { st, d -> emitStatus(st, d) }, onInbound = { p, h, v, a -> handleInbound(p, h, v, a) })
        main.post {
            // Started while the app is in the background (page reload, call push):
            // it pauses again unless a call needs it.
            if (lifecycleKnown && !appInForeground) {
                pauseOwed = true
                postIdleCheck()
            }
        }
        checkOwnRoute(ctx, s, "listen start")
    }

    // ---- own route vs chain (see BeamioOwnRouteCheck) --------------------------------------

    private val routeCheckGen = java.util.concurrent.atomic.AtomicInteger(0)
    private val routeCheckSignal = Object()

    /** Network back: a check waiting to retry reads the chain now. */
    private fun kickOwnRouteCheck() {
        synchronized(routeCheckSignal) { routeCheckSignal.notifyAll() }
    }

    /**
     * Check the session's route against the chain record. A failed read retries
     * with backoff and never changes the route; a different chain route wins and
     * the listen reopens on it. One check runs at a time; a newer one ends it.
     */
    private fun checkOwnRoute(ctx: Context, s: Session, reason: String) {
        val gen = routeCheckGen.incrementAndGet()
        kickOwnRouteCheck()
        Thread({
            val alive = { routeCheckGen.get() == gen && currentSession() === s && !s.destroyed }
            // Page handoff: a running listen on another route than the session's reopens now.
            val inUse = s.listenRouteKeyId
            val wanted = BeamioOwnRouteCheck.routeKeyId(s.ownRouteArmoredPublicKey)
            if (inUse.isNotEmpty() && wanted.isNotEmpty() && inUse != wanted) {
                Log.w(TAG, "own route: listen on $inUse, session route $wanted ($reason); reopening")
                main.post { if (alive() && listen.isRunning()) reopenListen(ctx, s) }
            }
            val verdict = BeamioOwnRouteCheck.reconcile(
                listenArmor = { s.ownRouteArmoredPublicKey },
                read = { BeamioOwnRouteCheck.readChainRoute(s.conetRpcUrl, s.eoa) },
                sleep = { ms ->
                    synchronized(routeCheckSignal) {
                        try {
                            routeCheckSignal.wait(ms)
                        } catch (_: InterruptedException) {
                        }
                    }
                    alive()
                },
                onRetry = { why, ms ->
                    Log.w(TAG, "own route check: chain read failed ($why); keeping route=$wanted; retry in ${ms / 1000}s")
                },
            )
            if (!alive()) return@Thread
            when (verdict) {
                is BeamioOwnRouteCheck.Verdict.Match ->
                    Log.i(TAG, "own route check: route=$wanted matches chain ($reason)")
                is BeamioOwnRouteCheck.Verdict.NoRoute ->
                    Log.w(TAG, "own route check: chain has no route; keeping route=$wanted")
                is BeamioOwnRouteCheck.Verdict.Switch -> {
                    Log.w(TAG, "own route mismatch: route=$wanted chain=${verdict.routeKeyId} ($reason); reconnecting on the chain route")
                    main.post { if (alive()) applyChainRoute(ctx, s, verdict) }
                }
                is BeamioOwnRouteCheck.Verdict.Retry -> Unit
            }
        }, "conet-chat-route-check").apply { isDaemon = true }.start()
    }

    /** Main thread. The chain route replaces the session's and the stored one. */
    private fun applyChainRoute(ctx: Context, s: Session, v: BeamioOwnRouteCheck.Verdict.Switch) {
        s.ownRouteArmoredPublicKey = v.routeArmor
        val mailboxIp = s.nodes.firstOrNull { it.domain.equals(v.routeKeyId, ignoreCase = true) }?.ip.orEmpty()
        s.mailboxIp = mailboxIp
        try {
            BeamioChatPgpStore.upsertFromWeb(
                ctx,
                JSONObject()
                    .put("routePublicKeyArmor", v.routeArmor),
            )
            val roster = BeamioChatPgpStore.loadSiNodes(ctx)
            if (mailboxIp.isNotEmpty() && roster.isNotEmpty()) {
                BeamioChatPgpStore.storeChainRoster(ctx, roster, mailboxIp)
            }
        } catch (e: Exception) {
            Log.w(TAG, "persist chain route: ${e.message}")
        }
        emitEvent(
            JSONObject().put("type", "event:log").put("level", "warn")
                .put("message", "own route switched to the chain route ${v.routeKeyId}"),
        )
        // A paused listen picks the new route up when it resumes.
        if (listen.isRunning()) reopenListen(ctx, s)
    }

    private fun reopenListen(ctx: Context, s: Session) {
        listen.start(ctx, s, onStatus = { st, d -> emitStatus(st, d) }, onInbound = { p, h, v, a -> handleInbound(p, h, v, a) })
    }

    /**
     * Back in the foreground with no word from the mailbox for this long: reopen
     * the listen. A stream that died while the process was frozen is not always
     * reported, and only a new listen makes the mailbox send what it holds.
     */
    private const val RESUME_STALE_MS = 45_000L

    private fun resumeListen() {
        val ctx = appContext ?: return
        val s = currentSession() ?: return
        if (listen.isRunning()) {
            // Connected (or reconnecting by itself) and recently heard: keep it.
            val quietMs = listen.msSinceLastMailboxFrame()
            if (quietMs < RESUME_STALE_MS) return
            Log.i(TAG, "resume: mailbox quiet ${quietMs / 1000}s; reopening the listen")
        }
        listen.resume(ctx, s, onStatus = { st, d -> emitStatus(st, d) }, onInbound = { p, h, v, a -> handleInbound(p, h, v, a) })
    }

    /**
     * Open a new mailbox listen now (new instance, new stream key) in place of a
     * connected one. The mailbox sends every message not yet ACKed on each new
     * listen, so a message that missed this listen (stored while it was being set
     * up, or written to a dead earlier listen of this device) arrives now instead
     * of at the next reconnect. Messages already handled are deduplicated.
     * The app calls it while a call rings, so the caller's cancel is not held back.
     * Returns false when no listen is connected (one that is connecting gets the
     * stored messages anyway).
     */
    fun refreshListen(reason: String): Boolean {
        val ctx = appContext ?: return false
        val s = currentSession() ?: return false
        if (!listen.isRunning() || !listenConnected) return false
        Log.i(TAG, "listen refreshed for $reason")
        startListen(ctx, s)
        return true
    }

    private fun destroy() {
        // Session gone: G2 -> G1 (25.26.4c). The native record is kept. Voice temporary keys end with the session (X-15).
        NativeSessionState.reset()
        VoiceChannelKeys.clear()
        listen.stop()
        BeamioConetChatSignBroker.cancelAll("destroyed")
        val hadHistory = synchronized(lock) { session?.history != null }
        synchronized(lock) {
            session?.destroyed = true
            session?.history?.destroy()
            session?.history = null
            session = null
            voiceSessions.clear()
        }
        // The history store emits `locked` itself (before its keys are dropped). Without a store, emit it here too.
        if (!hadHistory) emitEvent(JSONObject().put("type", "event:historyChange").put("payload", JSONObject().put("kind", "locked")))
        emitEvent(JSONObject().put("type", "event:status").put("payload", statusPayload("destroyed", null)))
    }

    /** Last listen status was `listening` (connected). */
    @Volatile
    private var listenConnected = false

    private fun emitStatus(status: String, detail: String?) {
        listenConnected = status == "listening"
        emitEvent(JSONObject().put("type", "event:status").put("payload", statusPayload(status, detail)))
    }

    // ---- inbound + dual receipts -------------------------------------------------------

    private fun handleInbound(plaintext: String, armorHash: String, viaDomain: String, armor: String) {
        val ctx = appContext ?: return
        val s = currentSession() ?: return
        // The sender fans one message out to several entries; the mailbox then forwards each
        // copy. Identical armor (same keccak) is one message: no second event, no second receipt.
        if (armorHash.isNotEmpty() && !markSeen(armorHash)) {
            // Redelivered before the app confirmed it (page reloaded or was
            // suspended): hand it over again. The app deduplicates by sendId.
            val pending = s.pendingAcks[armorHash] ?: return
            emitInboundMessage(pending.plaintext, pending.from, armorHash, pending.viaDomain)
            return
        }
        verifyEnvelope(ctx, plaintext) { from ->
            if (from.isNullOrEmpty()) {
                emitEvent(
                    JSONObject().put("type", "event:log").put("level", "warn")
                        .put("message", "inbound verify failed — drop"),
                )
                return@verifyEnvelope
            }
            BeamioConetChatCallControl.parse(plaintext)?.let { sig ->
                main.post {
                    try {
                        callControlObserver?.invoke(sig.type, sig.callId, sig.sessionId, from)
                    } catch (e: Exception) {
                        Log.w(TAG, "call control observer failed: ${e.message}")
                    }
                }
            }
            if (s.deferAck && armorHash.isNotEmpty()) {
                prunePendingAcks(s)
                s.pendingAcks[armorHash] = PendingAck(plaintext, from, viaDomain, System.currentTimeMillis())
                // On disk until the app confirms it: survives the page not running.
                if (armor.isNotEmpty()) BeamioConetChatInboxStore.put(ctx, armorHash, armor, viaDomain)
                emitInboundMessage(plaintext, from, armorHash, viaDomain)
            } else {
                emitInboundMessage(plaintext, from, armorHash, viaDomain)
                emitDualReceipts(ctx, s, plaintext, armorHash, from)
            }
        }
    }

    private fun emitInboundMessage(plaintext: String, from: String, armorHash: String, viaDomain: String) {
        emitEvent(
            JSONObject().put("type", "event:message").put(
                "payload",
                JSONObject()
                    .put("line", plaintext)
                    .put("from", from)
                    .put("armorHash", armorHash)
                    .put("viaDomain", viaDomain)
                    .put("plain", false),
            ),
        )
    }

    /**
     * The app stored these messages: now send the mailbox ACK (deletes the
     * offline copy) and the sender's delivery receipt.
     */
    private fun handleAckInbound(body: JSONObject) {
        val ctx = appContext ?: return
        val s = currentSession() ?: return
        val hashes = ArrayList<String>()
        body.optJSONArray("armorHashes")?.let { arr ->
            for (i in 0 until arr.length()) arr.optString(i, "").takeIf { it.isNotBlank() }?.let { hashes.add(it) }
        }
        body.optString("armorHash", "").takeIf { it.isNotBlank() }?.let { hashes.add(it) }
        BeamioConetChatInboxStore.remove(ctx, hashes)
        for (hash in hashes) {
            val pending = s.pendingAcks.remove(hash) ?: continue
            emitDualReceipts(ctx, s, pending.plaintext, hash, pending.from)
        }
    }

    /** Unconfirmed for 10 minutes: forget it without ACK; the mailbox redelivers it later. */
    private fun prunePendingAcks(s: Session) {
        val cutoff = System.currentTimeMillis() - PENDING_ACK_TTL_MS
        val expired = s.pendingAcks.entries.filter { it.value.at < cutoff }.map { it.key }
        for (hash in expired) {
            s.pendingAcks.remove(hash)
            // Let the mailbox's redelivery through the dedupe again.
            synchronized(seenArmor) { seenArmor.remove(hash) }
        }
    }

    /**
     * Recover the EIP-191 signer. A claimed `from` that differs from the signer is passed on for the app to flag:
     * the recovered address is the only trusted sender identity.
     */
    private fun verifyEnvelope(ctx: Context, plaintext: String, completion: (String?) -> Unit) {
        val obj = try {
            JSONObject(plaintext)
        } catch (_: Exception) {
            completion(null)
            return
        }
        val text = when {
            obj.has("text") && obj.opt("text") is String -> obj.getString("text")
            obj.has("message") && obj.opt("message") is String -> obj.getString("message")
            else -> {
                completion(null)
                return
            }
        }
        val sig = obj.optString("signMessage", "")
        if (sig.isEmpty()) {
            completion(null)
            return
        }
        // The recovered signer is the sender. A claimed `from` that differs is
        // not dropped here: the app keeps the message under the signer and shows
        // a warning for the false claim.
        BeamioOpenPgpHost.shared(ctx).verifyMessage(text, sig) { result ->
            completion(result.getOrNull())
        }
    }

    /** Mailbox ACK (delete offline copy) + sender `beamio_chat_delivery_receipt_v1`. */
    private fun emitDualReceipts(ctx: Context, s: Session, plaintext: String, armorHash: String, from: String) {
        if (s.ownRouteArmoredPublicKey.contains("BEGIN PGP PUBLIC KEY")) {
            postSignedMailboxCommand(
                s, s.ownRouteArmoredPublicKey,
                JSONObject().put("command", "gossip_delivery_ack").put("armorHash", armorHash),
            ) { _, _ -> }
        }
        val fromLower = from.lowercase()
        val route = s.routes.firstOrNull {
            normalizeAddress(it.optString("address", "").ifBlank { it.optString("eoaAddress", "").ifBlank { it.optString("eoa", "") } }) == fromLower
        } ?: return
        if (!route.optString("userPublicKeyArmored", "").contains("BEGIN PGP PUBLIC KEY")) return

        val receipt = JSONObject()
            .put("type", "beamio_chat_delivery_receipt_v1")
            .put("sendId", extractSendId(plaintext).orEmpty())
            .put("armorHash", armorHash)
            .put("deliveredAt", System.currentTimeMillis())
            .put("from", s.eoa)
        val pending = JSONObject()
            .put("sendId", UUID.randomUUID().toString())
            .put("from", "me")
            .put("text", receipt.toString())
            .put("createdAt", System.currentTimeMillis())
        handleSend(
            JSONObject()
                .put("reqId", -1)
                .put("to", route)
                .put("payload", pending.toString())
                .put("sendId", UUID.randomUUID().toString())
                .put("beamioNoPush", true),
        )
    }

    // ---- shared helpers -----------------------------------------------------------------

    /** Sign (via the PWA) + encrypt a mailbox command to [routerArmoredPublicKey], POST via entry ≠ B. */
    private fun postSignedMailboxCommand(
        s: Session,
        routerArmoredPublicKey: String,
        command: JSONObject,
        completion: (ok: Boolean, json: JSONObject?) -> Unit,
    ) {
        val ctx = appContext
        if (ctx == null) {
            completion(false, null)
            return
        }
        val cmd = JSONObject(command.toString())
        if (!cmd.has("walletAddress")) cmd.put("walletAddress", s.eoa)
        if (!cmd.has("timestamp")) cmd.put("timestamp", System.currentTimeMillis() / 1000)
        val message = cmd.toString()
        BeamioConetChatSignBroker.requestEip191(message) { signResult ->
            val signature = signResult.getOrNull()
            if (signature == null) {
                completion(false, null)
                return@requestEip191
            }
            BeamioOpenPgpHost.shared(ctx).encryptSignedRouteCommand(message, signature, routerArmoredPublicKey) { enc ->
                val armor = enc.getOrNull()
                if (armor == null) {
                    completion(false, null)
                    return@encryptSignedRouteCommand
                }
                io.execute {
                    var json: JSONObject? = null
                    val ok = postToEntries(ctx, armor, routerArmoredPublicKey, s) { body ->
                        json = try {
                            JSONObject(body)
                        } catch (_: Exception) {
                            null
                        }
                    }
                    completion(ok, json)
                }
            }
        }
    }

    /**
     * POST via entry ≠ B (blocking). Wraps the armor to each keyed entry's route PGP; an entry whose wrap fails is skipped and never gets the unwrapped armor. Like the
     * TS gossip core (`outerWrap`). [onBody] receives the 2xx response body (mailbox JSON replies).
     */
    private fun postToEntries(
        ctx: Context,
        armor: String,
        mailboxRoute: String,
        s: Session,
        onBody: ((String) -> Unit)? = null,
    ): Boolean {
        val exclude = HashSet<String>()
        BeamioSiCipherPost.normalizeIp(s.mailboxIp)?.let { exclude.add(it) }
        if (mailboxRoute.contains("BEGIN PGP")) {
            for (n in s.nodes) {
                if (n.armoredPublicKey.isNotEmpty() &&
                    BeamioConetChatListenSession.fingerprintsOverlap(mailboxRoute, n.armoredPublicKey)
                ) {
                    BeamioSiCipherPost.normalizeIp(n.ip)?.let { exclude.add(it) }
                }
            }
        }
        val host = BeamioOpenPgpHost.shared(ctx)
        // Only keyed entries. Nodes without a PGP key are skipped, and there is no roster fallback that posts
        // unwrapped armor (the bare roster POST is removed).
        val candidates = BeamioChatPgpStore.keyedEntries(s.nodes.map { it.asStoreNode() }, exclude).values.shuffled()

        // One entry at a time; the next only after a clear failure (connection
        // error or reset, non-2xx, `ok:false`, or no answer in 8 s). A timed-out
        // POST may have arrived: the mailbox keeps one copy per ciphertext and
        // the recipient dedupes by sendId. At most 4 entries, about 25 s.
        val started = System.currentTimeMillis()
        for (entry in candidates.take(4)) {
            if (System.currentTimeMillis() - started > 25_000L) break
            var wrapped: String? = null
            val latch = CountDownLatch(1)
            host.wrapArmorToEntryRoute(armor, entry.armoredPublicKey) { r ->
                wrapped = r.getOrNull()
                latch.countDown()
            }
            latch.await(8, TimeUnit.SECONDS)
            val postArmor = wrapped
            if (postArmor == null) {
                Log.w(TAG, "post_to_entries: wrap failed or timed out for entry=${entry.ip}; entry skipped")
                continue
            }
            val result = BeamioSiCipherPost.post(
                postArmor, listOf(entry), exclude, maxAttempts = 1, timeoutMs = 8_000L,
            )
            if (result.ok) {
                onBody?.invoke(result.body)
                return true
            }
        }
        return false
    }

    /** `true` the first time [armorHash] is seen (bounded, last 512). */
    private const val PENDING_ACK_TTL_MS = 10 * 60 * 1000L

    private fun markSeen(armorHash: String): Boolean = synchronized(seenArmor) {
        if (seenArmor.containsKey(armorHash)) false else {
            seenArmor[armorHash] = true
            true
        }
    }

    private fun currentSession(): Session? = synchronized(lock) {
        session?.takeIf { !it.destroyed }
    }

    private fun emitEvent(payload: JSONObject) {
        val out = JSONObject().put("action", "chatModuleEvent").put("event", payload)
        main.post {
            try {
                nativeObserver?.invoke(out)
            } catch (e: Exception) {
                Log.w(TAG, "observer failed: ${e.message}")
            }
            try {
                emitFn?.invoke(out)
            } catch (e: Exception) {
                Log.w(TAG, "emit failed: ${e.message}")
            }
        }
    }

    /** The reqId as the page sent it (a string or an integer). The envelope has checked it (25.52AW.1); it is echoed unchanged (T-179). */
    private fun echoId(body: JSONObject): Any = body.opt("reqId") ?: JSONObject.NULL

    private fun ack(reqId: Any?, ok: Boolean, result: Any? = null, error: String? = null) {
        val payload = JSONObject().put("type", "ack").put("reqId", reqId ?: JSONObject.NULL).put("ok", ok)
        if (ok && result != null) payload.put("result", result)
        if (!ok) payload.put("error", error ?: "error")
        emitEvent(payload)
    }

    private fun statusPayload(status: String, detail: String?): JSONObject =
        JSONObject().put("status", status).also { if (!detail.isNullOrBlank()) it.put("detail", detail) }

    private fun objects(arr: JSONArray): List<JSONObject> =
        (0 until arr.length()).mapNotNull { arr.optJSONObject(it) }

    private fun parseNodes(raw: JSONArray): List<Node> {
        // The PWA `nodeInfo` carries `ip_addr`, native roster rows carry `ip`. A row with only a
        // domain is resolved through the chain roster in the store; without an IP an entry can
        // never be reached over HTTP.
        val rosterIpByDomain = HashMap<String, String>()
        appContext?.let { ctx ->
            for (kn in BeamioChatPgpStore.loadSiNodes(ctx)) {
                if (kn.domain.isNotEmpty()) rosterIpByDomain[kn.domain.uppercase()] = kn.ip
            }
        }
        val out = ArrayList<Node>()
        for (i in 0 until raw.length()) {
            val n = raw.optJSONObject(i) ?: continue
            var ip = n.optString("ip", "").ifBlank { n.optString("ip_addr", "") }
            val domain = n.optString("domain", "")
            if (BeamioSiCipherPost.normalizeIp(ip) == null && domain.isNotEmpty()) {
                rosterIpByDomain[domain.uppercase()]?.let { ip = it }
            }
            if (ip.isEmpty() && domain.isEmpty()) continue
            out.add(
                Node(
                    ip = ip,
                    domain = domain,
                    region = n.optString("region", ""),
                    armoredPublicKey = n.optString("armoredPublicKey", "")
                        .ifBlank { n.optString("pgpPublicKeyArmored", "") },
                ),
            )
        }
        return out
    }

    private fun normalizeAddress(raw: String): String = raw.trim().lowercase()

    private fun extractSendId(plaintext: String): String? {
        val obj = try {
            JSONObject(plaintext)
        } catch (_: Exception) {
            return null
        }
        obj.optString("sendId", "").takeIf { it.isNotEmpty() }?.let { return it }
        val inner = obj.optString("text", "")
        return try {
            JSONObject(inner).optString("sendId", "").takeIf { it.isNotEmpty() }
        } catch (_: Exception) {
            null
        }
    }
}
