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
    /** The artifact version (spec 25.52Y.45, PM R2054); it must equal chat/build.gradle.kts `version` in the same commit (a test checks it). */
    const val SDK_VERSION = "0.2.23"

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
        listOfNotNull(WALLET_CREDENTIAL_CAPABILITY.takeIf { BuildConfig.WALLET_CREDENTIAL_QA })

    /**
     * The kPresent capability (spec 25.52X.5, 25.52Y.90, 25.52Y.93). Declared in every build: `identityPublic` answers `kPresent` on G0 `no_key`,
     * and `already_exists` carries the public `eoa` on the recovery page and on the import page (`nativeImportResult`, 25.52X.4). Without this
     * name a shell that reports `identity.native-keys.v1` is unknown and never gets the new-account entry (25.52Y.93 第 2 条 (c)), so it stays declared.
     */
    const val KPRESENT_CAPABILITY = "identity.kpresent.v1"

    /**
     * The native-keys capability (identity.native-keys.v1). Declared by every build since 2026-11-16 (project owner decision): the formal
     * release hello carries it. It is not yet in the shared hello vector; the conformance test appends it until the interface seat
     * updates the vector.
     */
    const val NATIVE_KEYS_CAPABILITY = "identity.native-keys.v1"

    /**
     * The window-channel capability for walletCredential (spec 25.52Y.38 第 2 项 (e), 25.52Y.44; PM R2042). Declared only in a QA build
     * (-PchatWalletCredentialQa=true). The shell's manifest must carry it too; the SDK checks its own declaration before it answers.
     */
    const val WALLET_CREDENTIAL_CAPABILITY = "wallet.credential.v1"

    /** `hello` answer (`ack.result`). */
    fun helloResult(): JSONObject = JSONObject()
        .put("protocolVersion", PROTOCOL_VERSION)
        .put("minProtocolVersion", MIN_PROTOCOL_VERSION)
        .put("sdkVersion", SDK_VERSION)
        .put("implementation", "android")
        .put("capabilities", JSONArray(CAPABILITIES))
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
