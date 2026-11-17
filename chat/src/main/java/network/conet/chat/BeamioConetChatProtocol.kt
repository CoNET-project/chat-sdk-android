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
    const val SDK_VERSION = "0.2.8"

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
    )

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
