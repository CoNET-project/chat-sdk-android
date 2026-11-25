package network.conet.chat

import org.json.JSONArray
import org.json.JSONObject

/**
 * ChatDaemon protocol v1, Android side. The spec lives in `@conet.project/chat-sdk`
 * (`src/protocol.ts`, `spec/chat-daemon-protocol.v1.schema.json`); this file
 * follows it. Shared conformance vectors: `spec/chat-daemon-vectors.v1.json` in
 * this repo (a copy of the spec's file, see `scripts/sync-protocol-vectors.sh`).
 */
object BeamioConetChatProtocol {
    /** Newest protocol version this module speaks. */
    const val PROTOCOL_VERSION = 1

    /** Oldest protocol version this module still speaks. */
    const val MIN_PROTOCOL_VERSION = 1

    /** Version of this library (keep equal to `chat/build.gradle.kts` `version`). */
    /** The artifact version (spec 25.52Y.45); it must equal chat/build.gradle.kts `version` in the same commit (a test checks it). */
    const val SDK_VERSION = "0.2.32"

    /**
     * The inbound-generation capability. Not implemented in this build: the module sends no `inboundGeneration`
     * event and keeps no generation, so it does not declare it, and [CAPABILITIES] must not list it until it does. The shared hello vector keeps Android
     * without it. A rule that depends on it ([network.conet.chat.nativekey.SignRequestRule]) reads [declaresInboundGeneration], so the declaration and the
     * enforcement can never disagree.
     */
    const val INBOUND_GENERATION_CAPABILITY = "inbound.generation.v1"

    /** True when this module's own capability list declares [INBOUND_GENERATION_CAPABILITY]: the one source of that fact. */
    fun declaresInboundGeneration(): Boolean = CAPABILITIES.contains(INBOUND_GENERATION_CAPABILITY)

    /** Capabilities this module implements (names from the spec's `CHAT_DAEMON_CAPABILITIES`). */
    val CAPABILITIES: List<String> = listOf(
        "identity.provision",
        "signing.local",
        "lifecycle.daemon",
        "inbound.deferAck",
        "history.v2",
        "call.control",
        "voice.delegated",
        "presence.query",
        "mailbox.command",
        "send.mailboxWrap",
        "history.local.v1",
        "history.page.v1",
        "layout.cache.v1",
        KPRESENT_CAPABILITY,
        NATIVE_KEYS_CAPABILITY,
    ) +
        // The delivery-receipt capability: declared only by a build that has the whole receipt implementation (the check runs
        // the pure rules once). It follows the shared hello vector's Android list and comes before the QA-only names.
        listOfNotNull(SenderReceipt.CAPABILITY.takeIf { SenderReceipt.implementationComplete() }) +
        listOfNotNull(
            WALLET_CREDENTIAL_CAPABILITY.takeIf { BuildConfig.WALLET_CREDENTIAL_QA },
            // QA only: the first-identity status event. Not in the shared hello vector.
            network.conet.chat.nativekey.FirstIdentityEvents.CAPABILITY.takeIf { BuildConfig.IDENTITY_STATE_EVENTS_QA },
        )

    /**
     * The kPresent capability (spec 25.52X.5, 25.52Y.90, 25.52Y.93). Declared in every build: `identityPublic` answers `kPresent` on G0 `no_key`,
     * and `already_exists` carries the public `eoa` on the recovery page and on the import page (`nativeImportResult`, 25.52X.4). Without this
     * name a shell that reports `identity.native-keys.v1` is unknown and never gets the new-account entry (25.52Y.93 第 2 条 (c)), so it stays declared.
     */
    const val KPRESENT_CAPABILITY = "identity.kpresent.v1"

    /**
     * The native-keys capability (identity.native-keys.v1). Declared by every build since 2026-11-16: the formal
     * release hello carries it. It is not yet in the shared hello vector; the conformance test appends it until the interface seat
     * updates the vector.
     */
    const val NATIVE_KEYS_CAPABILITY = "identity.native-keys.v1"

    /**
     * The window-channel capability for walletCredential (spec 25.52Y.38 第 2 项 (e), 25.52Y.44). Declared only in a QA build
     * (-PchatWalletCredentialQa=true). The shell's manifest must carry it too; the SDK checks its own declaration before it answers.
     */
    const val WALLET_CREDENTIAL_CAPABILITY = "wallet.credential.v1"

    /**
     * `hello` answer (`ack.result`). [nativeApp] is the host app's installed native version (v156 §176.2), or null when it could not be read or is
     * invalid; then the field is absent and the shell treats the host as old (§176.1).
     */
    fun helloResult(nativeApp: JSONObject? = null): JSONObject = JSONObject()
        .put("protocolVersion", PROTOCOL_VERSION)
        .put("minProtocolVersion", MIN_PROTOCOL_VERSION)
        .put("sdkVersion", SDK_VERSION)
        .put("implementation", "android")
        .put("capabilities", JSONArray(CAPABILITIES))
        .apply { if (nativeApp != null) put("nativeApp", nativeApp) }

    /**
     * The `nativeApp` object (v156 §176.2–176.3) for Android. The version and build are read at run time from the host process's PackageManager
     * (`versionName`, `longVersionCode`; `versionCode` below API 28), never from a compile-time constant, the SDK version or the PWA version.
     * Returns null when the package info cannot be read or the values are not valid.
     */
    fun readHostNativeApp(context: android.content.Context): JSONObject? {
        val info = try {
            context.packageManager.getPackageInfo(context.packageName, 0)
        } catch (_: Exception) {
            return null
        }
        val build = if (android.os.Build.VERSION.SDK_INT >= 28) info.longVersionCode else @Suppress("DEPRECATION") info.versionCode.toLong()
        return nativeAppOf("android", info.versionName, build.toString())
    }

    /**
     * Validates a `nativeApp` object (v156 §176.2, §176.4): platform ios or android; version matches `^\d+(\.\d+){1,3}$`; build matches `^\d+$`.
     * Returns null for any invalid value; the caller then omits the field.
     */
    fun nativeAppOf(platform: String, version: String?, build: String?): JSONObject? {
        if (platform != "ios" && platform != "android") return null
        if (version == null || !NATIVE_VERSION_RE.matches(version)) return null
        if (build == null || !NATIVE_BUILD_RE.matches(build)) return null
        return JSONObject().put("platform", platform).put("version", version).put("build", build)
    }

    private val NATIVE_VERSION_RE = Regex("^\\d+(\\.\\d+){1,3}$")
    private val NATIVE_BUILD_RE = Regex("^\\d+$")
}

/**
 * Plaintext shapes on the wire (before PGP encryption). Same objects as the
 * spec's `src/wire.ts` and iOS `BeamioConetChatWire`.
 */
object BeamioConetChatWire {
    /** Outer chat envelope; `signMessage` = EIP-191(`text`), only inside the user-PGP layer. */
    fun chatEnvelope(timestamp: Long, text: String, from: String, signMessage: String): JSONObject = JSONObject()
        .put("timestamp", timestamp)
        .put("text", text)
        .put("from", from)
        .put("signMessage", signMessage)

    /** The signed middle row `{ sendId, from: "me", text, createdAt }`. */
    fun pendingRow(sendId: String, text: String, createdAt: Long): JSONObject = JSONObject()
        .put("sendId", sendId)
        .put("from", "me")
        .put("text", text)
        .put("createdAt", createdAt)

    /** `gossip_delivery_ack` to the own mailbox. [timestamp] in seconds. */
    fun deliveryAckCommand(eoa: String, armorHash: String, timestamp: Long): JSONObject = JSONObject()
        .put("command", "gossip_delivery_ack")
        .put("walletAddress", eoa)
        .put("armorHash", armorHash)
        .put("timestamp", timestamp)

    /** Receipt sent back to the sender as a NoPush chat message. [deliveredAt] in ms. */
    fun deliveryReceipt(sendId: String, armorHash: String, deliveredAt: Long, eoa: String): JSONObject = JSONObject()
        .put("type", "beamio_chat_delivery_receipt_v1")
        .put("sendId", sendId)
        .put("armorHash", armorHash)
        .put("deliveredAt", deliveredAt)
        .put("from", eoa)

    /** Mailbox work packet; `NoPush` only when true. */
    fun mailboxWork(data: String, noPush: Boolean): JSONObject = JSONObject().put("data", data).also {
        if (noPush) it.put("NoPush", true)
    }
}
