# CoNET Chat SDK for Android

Native CoNET Chat module for Android apps. Implements the same `WorkerCommand` / `WorkerOutbound` surface as [`@conet.project/chat-sdk`](https://github.com/CoNET-project/chat-sdk) (TypeScript) and the iOS package [`chat-sdk-ios`](https://github.com/CoNET-project/chat-sdk-ios), without spawning a Web Worker inside the shell.

**Repository:** https://github.com/CoNET-project/chat-sdk-android

| Item | Value |
|---|---|
| **Maven coordinates** | `network.conet:chat:0.2.8` |
| **Namespace** | `network.conet.chat` |
| **minSdk** | 24 |
| **Entry point** | `BeamioConetChatModule.handleCommand(context, body, emit)` |

## What this library owns

| Capability | Native (`network.conet:chat`) | Host / PWA |
|---|---|---|
| OpenPGP encrypt / decrypt / verify | Yes (hidden `WebView` + bundled `openpgp.min.js` / `ethers.umd.min.js`) | — |
| Mailbox listen SSE (`mailbox_listen`) | Yes, daemon-owned (B route PGP; HTTP via entry **C ≠ B**; sealed stream since 0.2.6) | — |
| Send / group send / dual delivery receipts | Yes (wrapped to the recipient's mailbox since 0.2.6) | — |
| Presence / native-wake queries | Yes | — |
| Encrypted IPFS history + `ChatIndexRegistry` | Yes | — |
| User PGP key + SI roster store | Yes (`EncryptedSharedPreferences`) | — |
| Wallet key custody | Yes since 0.2.5 (`provisionIdentity`; AES-GCM ciphertext under an Android Keystore key, not in backups; wiped by `clearIdentity`) | Hands the keys over once |
| **EOA EIP-191 / EIP-712 signing** | Local since 0.2.5 when a key is provisioned; otherwise callback | PWA `chatModuleSignRequest` → `chatModuleSignResponse` (fallback only) |
| Voice media SSE | Delegated | Host voice signaling |

### Key custody and signing

Since 0.2.5 the page provisions the wallet private key and the user PGP keys once (`provisionIdentity`). The module keeps them in the Keystore, never logs them, signs `mailbox_listen`, ACKs and sends itself, and keeps the mailbox SSE as a daemon. The SSE runs only in the foreground, while a call push is ringing, and during a call (it stays open for the whole call); nothing runs after the app exits, and there is no foreground service for Chat. Messages received with no page loaded are kept as PGP ciphertext until the page takes them, then ACKed. Since 0.2.6 the shell reports the app state (`appForeground` / `appBackground`): the listen pauses about 10 s after the app goes to the background unless a call needs it, and reconnects at once in the foreground.

Without a provisioned key the module falls back to the older hybrid model (**1B**). Whenever a signature is needed it emits

```json
{ "action": "chatModuleSignRequest", "reqId": "…", "kind": "eip191" | "eip712", "message": "…" | "typedData": { … } }
```

The host PWA signs with its own wallet and replies through `BeamioConetChatSignBroker.fulfill(json)` (`{ "reqId", "ok", "signature" | "error" }`). Signing requests time out after 60 s.

## Protocol (A / B / C)

1. **Send**: the inner envelope `{ timestamp, text, from, signMessage }` is `base64(UTF8(JSON))`, encrypted to the recipient **user PGP** key and POSTed through one random entry that is neither the recipient's nor the own mailbox; the next entry only after a clear failure. Since 0.2.6 every send is wrapped as mailbox work to the recipient's mailbox route key (no route key → `recipient_mailbox_unknown`), with an 8 s per-entry timeout.
2. **Listen**: a signed `mailbox_listen` command is encrypted to the own mailbox **B route PGP** key and sent through a healthy entry **C ≠ B**. Since 0.2.6 the command carries a fresh 32-byte `streamKey` (nodes refuse a listen without it, so 0.2.5 and older get no real-time receive), and every frame is `base64(iv ‖ AES-256-GCM ciphertext ‖ tag)` that the session opens (`AES/GCM/NoPadding`) before parsing.
3. HTTP JSON bodies are always exactly `{ "data": "<armor>" }`. Mailbox instructions (e.g. `NoPush`) travel inside a mailbox-work package encrypted to B.
4. **Inbound identity** is the EIP-191 recovered signer of the envelope. A message whose signer differs from the claimed `from` is not dropped: it is passed to the app with the recovered signer and the claim, and the app shows a warning. Only an unrecoverable signature is dropped.
5. **Receipts**: after an inbound message is accepted the module sends a mailbox `gossip_delivery_ack` (encrypted to B) and a `beamio_chat_delivery_receipt_v1` to the sender (`NoPush`).
6. **History**: AES-GCM fragments on IPFS plus an EIP-712 `SetPointer` on `ChatIndexRegistry` (`0x1511Caa71081C84d8a591490D1b83879088EED72`, chain `224422`). Keys derive from an EIP-191 signature of `beamio.chat.history.v1|224422|<eoaLower>`; recovery reads the pointer over RPC and decrypts the chain.

The history store keeps no on-disk manifest: every process start rebuilds the index from the `ChatIndexRegistry` pointer (restore from chain), then decrypts fragments with bounded parallel IPFS fetches. Chain-mutating work (`historyLoad`, `historyAppend`, head sync) runs on one serial lane; `historyRead` is served from an in-memory snapshot on its own lane, so it never waits behind a slow append (a read issued during a restore waits up to 20 s for that restore's head sync).

Entry selection uses a score-weighted random choice over the SI roster with a reachability probe (`BeamioSiCipherPost.getRandomNode`); unreachable IPs are quarantined for 120 s and up to four entries are tried per operation, one at a time. Since 0.2.6 `BeamioEntryPool` keeps about 8 probed healthy entries warm (refreshed every 15 s) while the daemon is active (probes carry no wallet or signature); `getRandomNode` takes from it first, applying the caller's exclusions, and probes on the spot only when it is empty; usable IPs are cached on disk (public node data only) for a push-woken process; and `BeamioGuardianNodeWatch` follows the `GuardianNodesInfoV6` storage root and pulls the full node table only when it changes.

Transport is plain HTTP to entry IPs on port 80 without an extra entry layer (known limitation). `wallet_online_query` / `wallet_native_wake_query` carry and are signed by the querier's wallet (known limitation, to be solved with `web3://`). Call control (cancel, decline, timeout, hang-up) arrives as ordinary Chat messages through the mailbox, and since 0.2.6 the wake receipt `voice_call_ringing_v1` is classified as a call signal; voice commands the module forwards are unsigned and wallet-free, and voice media is delegated to the host, which implements voice channel v3 (the library has no voice channel code of its own).

*Listen health (since 0.2.6):* the session reports `listening` only after the mailbox's sealed handshake frame (`kind: "mailbox"`); idle timeout 200 s; after a stream that heard from the mailbox drops, a new command with a new `instanceId` and `streamKey` is signed; `BeamioOpenPgpHost` rebuilds its WebView on `onRenderProcessGone` or a 25 s JS timeout and retries the call once; an inbound decrypt failure reopens the listen (at most every 30 s); `resumeListen` reopens it when the last sealed frame is more than 45 s old; `refreshListen(reason)` opens a new listen in place of a connected one, so the mailbox resends everything not yet ACKed (the shell calls it while a call rings, so the caller's cancel is not held back; it returns false when no listen is connected).

*Background pause and offline backoff (since 0.2.6):* in the background the listen pauses after a 10 s grace (not while a call rings, dials or is up), and nothing retries while paused. A failed listen retries after 2 s, 4 s, 8 s, 16 s, then every 30 s (±20 % jitter) instead of a fixed wait; a dropped listen that worked reopens after 0.5 s. Coming to the foreground or a default network becoming available (`ConnectivityManager.registerDefaultNetworkCallback`, which needs the normal permission `ACCESS_NETWORK_STATE`, declared in the library manifest) retries at once; without that permission the backoff alone applies.

*Own route vs chain (since 0.2.6):* once a listen starts, the module reads its own AddressPGP record (`searchKey`) and compares the route key ID with the one it listens on. A failed read is retried (5 s up to 300 s) and never counts as "no record"; a different chain route wins and the listen reopens on it; no chain route keeps the current listen (registering is the page's job). Logs carry only route key IDs.

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
    implementation("network.conet:chat:0.2.8")
}
```

The host app must declare `android.permission.INTERNET`; the library manifest also merges in `android.permission.ACCESS_NETWORK_STATE` (normal permission, used to retry the listen when a network comes back). Plain `http://` to SI entries on port 80 is part of the protocol, so the host needs `android:usesCleartextTraffic="true"` (or an equivalent network security config for CoNET entry hosts).

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

Since 0.2.6 the shell also reports the app state with `BeamioConetChatModule.appForeground(context, reason)` / `appBackground(reason)`, and may call `refreshListen(reason)` while a call rings (see *Listen health* above).

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

## ChatDaemon protocol v1

The spec lives in `@conet.project/chat-sdk` (`src/protocol.ts`, `spec/`). This
library answers `hello` with `BeamioConetChatProtocol.helloResult()` (protocol 1,
capabilities `identity.provision`, `signing.local`, `lifecycle.daemon`,
`inbound.deferAck`, `history.v2`, `call.control`, `voice.delegated`,
`presence.query`, `mailbox.command`, `send.mailboxWrap`) and answers unknown commands that carry a
positive `reqId` with `unknown_command`. Wire builders: `BeamioConetChatWire`;
call signals: `BeamioConetChatCallSignal.classify`.

Conformance tests read the shared vectors in `spec/chat-daemon-vectors.v1.json`
(a copy kept in sync with `scripts/sync-protocol-vectors.sh`; never edit it here):

```bash
./gradlew :chat:testDebugUnitTest            # hello, call signals, wire builders, ACK hash
./gradlew :chat:connectedDebugAndroidTest    # on a device: EIP-191, PGP envelopes, module hello
```

## Build, test and publish

```bash
./gradlew :chat:testDebugUnitTest      # keccak / HKDF / AES-GCM / armor parsing vectors
./gradlew :chat:assembleRelease        # chat/build/outputs/aar/chat-release.aar
./scripts/publish-maven.sh             # writes ./maven/network/conet/chat/<version>/…
```

Commit the generated `maven/` directory, tag `v<version>` and push; consumers then resolve from `raw.githubusercontent.com`. The version (latest `0.2.6`, tag `v0.2.6`) is set in `chat/build.gradle.kts` and `BeamioConetChatProtocol.SDK_VERSION`; keep them equal.

## Acceptance

The module is accepted through the Beamio Consumer Android shell (`src/CaehTrees`, shell `1.0.132`):

- A PWA temp account exchanges text, image and video with the shell in both directions; sender bubbles reach `Delivered`.
- The on-chain `ChatIndexRegistry` pointer advances with each message and matches the decrypted index.
- **Restore from chain**: after `am force-stop` + relaunch (empty process state) `historyRead` returns the whole corpus — 111 of 111 records, seq `0…110` contiguous, every fragment decrypted — matching the on-chain pointer.
- `historyRead` stays responsive while an append is in flight (≈0.5 s instead of waiting ~15 s behind the append lane).

## License

MIT — see `LICENSE`.

## Developer knowledge base

Lessons learned across the TypeScript, iOS and Android SDKs (symptom, root cause, rule, how to verify) are kept in one place, in the TypeScript SDK repository: [CoNET-project/chat-sdk docs/knowledge-base](https://github.com/CoNET-project/chat-sdk/tree/main/docs/knowledge-base). Android specifics: [platform-android.md](https://github.com/CoNET-project/chat-sdk/blob/main/docs/knowledge-base/platform-android.md).
