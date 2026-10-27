# CoNET Chat SDK for Android

Standalone Android library that implements the CoNET DePIN Chat **mailbox listen** path compatible with TypeScript [`@conet.project/chat-sdk`](https://github.com/CoNET-project).

Hosts inject OpenPGP + EIP-191 crypto (and optional persistence). The library never embeds a WebView or OpenPGP.js runtime.

| Item | Value |
|---|---|
| **Maven coordinates** | `network.conet:chat:0.1.0` |
| **Namespace** | `network.conet.chat` |
| **minSdk** | 24 |
| **Version** | `0.1.0` |
| **Public API** | `ConetChat` |

## Protocol (A / B / C)

Matches TypeScript `mailbox_listen`:

1. Encrypt the listen command to mailbox **B** route PGP.
2. POST / SSE through a healthy entry **C ≠ B** (never connect to B by default).
3. HTTP JSON body is only `{ "data": "<OpenPGP armor>" }`.
4. Events emit `{ "action": "conetChat", "kind": "status"|"message", … }`.

EOA private-key hex stays **in memory only** for EIP-191. Persistence adapters must never store it.

## Install

### Local module

```kotlin
// settings.gradle.kts
include(":chat")

// app/build.gradle.kts
implementation(project(":chat"))
```

### AAR

```bash
./gradlew :chat:assembleRelease
# → chat/build/outputs/aar/chat-release.aar
```

```kotlin
implementation(files("libs/chat-release.aar"))
```

### Maven (after you publish)

```kotlin
implementation("network.conet:chat:0.1.0")
```

The host app must allow `INTERNET` (declared in this library’s manifest merge).

## Quick start

```kotlin
import network.conet.chat.ConetChat
import network.conet.chat.ConetChatCrypto
import network.conet.chat.ConetChatPersistence

// 1) Install host crypto (required) + optional persistence
ConetChat.install(crypto = myCrypto, persistence = myPersistence)

// 2) Receive events (WebView bridge, Broadcast, or app bus)
ConetChat.bindEmitter { detail ->
    // detail.optString("action") == ConetChat.EVENT_ACTION ("conetChat")
}

// 3) Start mailbox listen
ConetChat.start(context, initJson)

ConetChat.stop()
ConetChat.destroy()
```

### `initJson` fields

Aligned with TypeScript `BeamioChatConfig.identity`:

| Field | Required | Notes |
|---|---|---|
| `privateKeyHex` | yes | EOA key for EIP-191; memory only |
| `pgpPrivateKeyArmored` | yes | User PGP private armor |
| `ownRouteArmoredPublicKey` | yes | Mailbox **B** route public key |
| `nodes` | yes | Entry roster: `ip_addr` / `ip`, `armoredPublicKey`, optional `domain` / `region` |
| `mailboxIp` | no | Prefer excluding this IP when picking entry C |
| `eoa` | no | Display / persistence identity |
| `pgpPublicKeyArmored` | no | For persistence upsert |
| `pgpPassphrase` | no | Default empty |

### Host SPI

| Interface | Role |
|---|---|
| `ConetChatCrypto` | EIP-191 sign + encrypt to B; wrap armor to entry C; decrypt inbound user-PGP |
| `ConetChatPersistence` (optional) | Roster + mailbox IP; **never** persist EOA private-key hex |

## Module layout

```text
chat/
  src/main/java/network/conet/chat/
    ConetChat.kt              # Public facade
    ConetChatCrypto.kt        # Host crypto SPI
    ConetChatPersistence.kt   # Optional persistence SPI
    ConetChatEngine.kt        # Listen session / SSE
    ConetChatNetwork.kt       # HTTP helpers
  src/main/AndroidManifest.xml
  consumer-rules.pro
```

## Scope (v0.1.0)

| Capability | Status |
|---|---|
| Mailbox LISTEN → host emitter | ✅ |
| Status (`connecting` / `listening` / `error` / …) | ✅ |
| Outbound `sendMessage` / presence / delivery ACK | Host / TypeScript SDK |
| Voice / encrypted history / group | Out of scope for this release |

## Build

Requires JDK 17+ and Android SDK.

```bash
./gradlew :chat:assembleRelease
```

## Security

- Do not log private keys, mnemonics, full PGP armor, or plaintext chat payloads.
- Do not default to connecting HTTP/SSE directly to mailbox B.
- Persistence must not write `privateKeyHex`.

## License

See repository license when published. Protocol docs: [gitbook.conet.network](https://gitbook.conet.network/).
