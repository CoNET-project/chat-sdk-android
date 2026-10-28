# CoNET Chat SDK for Android

Native CoNET Chat module for Android apps. Implements the same `WorkerCommand` / `WorkerOutbound` surface as [`@conet.project/chat-sdk`](https://github.com/CoNET-project/chat-sdk) (TypeScript) and the iOS package [`chat-sdk-ios`](https://github.com/CoNET-project/chat-sdk-ios), without spawning a Web Worker inside the shell.

**Repository:** https://github.com/CoNET-project/chat-sdk-android

| Item | Value |
|---|---|
| **Maven coordinates** | `network.conet:chat:0.2.0` |
| **Namespace** | `network.conet.chat` |
| **minSdk** | 24 |
| **Entry point** | `BeamioConetChatModule.handleCommand(context, body, emit)` |

## What this library owns

| Capability | Native (`network.conet:chat`) | Host / PWA |
|---|---|---|
| OpenPGP encrypt / decrypt / verify | Yes (hidden `WebView` + bundled `openpgp.min.js` / `ethers.umd.min.js`) | — |
| Mailbox listen SSE (`mailbox_listen`, `listenKind: chat`) | Yes (B route PGP; HTTP via entry **C ≠ B**) | — |
| Send / group send / dual delivery receipts | Yes | — |
| Presence / native-wake queries | Yes | — |
| Encrypted IPFS history + `ChatIndexRegistry` | Yes | — |
| User PGP key + SI roster store | Yes (`EncryptedSharedPreferences`) | — |
| **EOA EIP-191 / EIP-712 signing** | Callback only | PWA `chatModuleSignRequest` → `chatModuleSignResponse` |
| Voice media SSE | Delegated | Host voice signaling |

### Hybrid signing (model 1B)

The SDK never holds the EOA private key. Whenever a signature is needed it emits

```json
{ "action": "chatModuleSignRequest", "reqId": "…", "kind": "eip191" | "eip712", "message": "…" | "typedData": { … } }
```

The host PWA signs with its own wallet and replies through `BeamioConetChatSignBroker.fulfill(json)` (`{ "reqId", "ok", "signature" | "error" }`). Signing requests time out after 60 s.

## Protocol (A / B / C)

1. **Send**: the inner envelope `{ timestamp, text, from, signMessage }` is `base64(UTF8(JSON))`, encrypted to the recipient **user PGP** key and POSTed through any healthy entry **A ≠ B**.
2. **Listen**: a signed `mailbox_listen` command is encrypted to the own mailbox **B route PGP** key and sent through a healthy entry **C ≠ B**. SSE frames are raw JSON `{ "data": "<OpenPGP armor>" }`.
3. HTTP JSON bodies are always exactly `{ "data": "<armor>" }`. Mailbox instructions (e.g. `NoPush`) travel inside a mailbox-work package encrypted to B.
4. **Inbound identity** is the EIP-191 recovered signer of the envelope. Messages whose signer does not match the claimed `from` are dropped.
5. **Receipts**: after an inbound message is accepted the module sends a mailbox `gossip_delivery_ack` (encrypted to B) and a `beamio_chat_delivery_receipt_v1` to the sender (`NoPush`).
6. **History**: AES-GCM fragments on IPFS plus an EIP-712 `SetPointer` on `ChatIndexRegistry` (`0x1511Caa71081C84d8a591490D1b83879088EED72`, chain `224422`). Keys derive from an EIP-191 signature of `beamio.chat.history.v1|224422|<eoaLower>`; recovery reads the pointer over RPC and decrypts the chain.

Entry selection uses a score-weighted random choice over the SI roster with a reachability probe (`BeamioSiCipherPost.getRandomNode`); unreachable IPs are quarantined for 120 s and up to four entries are tried per operation.

## Install

### Gradle (Maven repository on GitHub)

```kotlin
// settings.gradle.kts
dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
        maven {
            url = uri("https://raw.githubusercontent.com/CoNET-project/chat-sdk-android/main/maven")
            content { includeGroup("network.conet") }
        }
    }
}

// app/build.gradle.kts
dependencies {
    implementation("network.conet:chat:0.2.0")
}
```

The host app must declare `android.permission.INTERNET`. Plain `http://` to SI entries on port 80 is part of the protocol, so the host needs `android:usesCleartextTraffic="true"` (or an equivalent network security config for CoNET entry hosts).

### Local module

```kotlin
// settings.gradle.kts
include(":chat")

// app/build.gradle.kts
implementation(project(":chat"))
```

## Host integration

```kotlin
// 1) Optional: refresh the SI roster when the PWA upserts the user key.
BeamioChatPgpStore.onRosterUpsertFromWeb = { ctx -> /* host roster refresh */ }

// 2) Expose three bridge methods to the PWA WebView.
@JavascriptInterface fun chatModuleAvailable(): Boolean = BeamioConetChatModule.isAvailable()

@JavascriptInterface fun chatModuleCommand(json: String) {
    val body = JSONObject(json)
    BeamioConetChatModule.handleCommand(applicationContext, body) { payload ->
        runOnUiThread { dispatchToWeb(payload) }   // CustomEvent detail for the PWA
    }
}

@JavascriptInterface fun chatModuleSignResponse(json: String) {
    BeamioConetChatModule.fulfillSign(JSONObject(json))
}
```

`emit` receives two payload kinds:

- `{ "action": "chatModuleEvent", "event": { "type": "ready" | "ack" | "event:message" | "event:status" | "event:presence" | "event:historyBuffer" | "event:log", … } }`
- `{ "action": "chatModuleSignRequest", … }`

### Supported command types

`init`, `setRoutes`, `setNodes`, `send`, `sendGroup`, `issueGroupRoster`, `issueGroupTombstone`, `queryPresence`, `queryNativeWake`, `historyLoad`, `historyRead`, `historyAppend`, `mailboxCommand`, `ownMailboxCommand`, `voiceFrame`, `voiceListen`, `voiceUnlisten`, `pause`, `resume`, `destroy`.

Commands that expect a response carry a `reqId` and are answered with `{ "type": "ack", "reqId", "ok", "result" | "error" }` (`init` answers `{ "type": "ready", … }`).

## iOS parity

| iOS (`ConetChatSDK`) | Android (`network.conet:chat`) |
|---|---|
| `BeamioConetChatModule.handleCommand` | `BeamioConetChatModule.handleCommand` |
| `BeamioConetChatSignBroker` | `BeamioConetChatSignBroker` |
| `BeamioOpenPgpHost` (WKWebView) | `BeamioOpenPgpHost` (WebView) |
| `BeamioSiCipherPost` | `BeamioSiCipherPost` |
| `BeamioChatPgpKeychain` | `BeamioChatPgpStore` (`EncryptedSharedPreferences`) |
| `ListenSession`, `HistoryStore` | `BeamioConetChatListenSession`, `BeamioConetChatHistoryStore` |

## Build, test and publish

```bash
./gradlew :chat:testDebugUnitTest      # keccak / HKDF / AES-GCM / armor parsing vectors
./gradlew :chat:assembleRelease        # chat/build/outputs/aar/chat-release.aar
./scripts/publish-maven.sh             # writes ./maven/network/conet/chat/<version>/…
```

Commit the generated `maven/` directory, tag `v<version>` and push; consumers then resolve from `raw.githubusercontent.com`.

## Acceptance

The module is accepted through the Beamio Consumer Android shell (`src/CaehTrees`, shell `1.0.131`, PWA `0.52.891`): a PWA temp account exchanges text, image and video with the shell in both directions; sender bubbles reach `Delivered`; the on-chain `ChatIndexRegistry` pointer advances with each message; and `historyRead` returns the decrypted chain.

## License

MIT — see `LICENSE`.
