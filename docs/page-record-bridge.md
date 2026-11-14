# Page-record bridge and first-run import (SDK 0.2.16)

This note is the SDK-side reference for the native page-record bridge. It follows spec r3bh (§25.52K, §25.52L) and the vectors
`spec/pgp-migration-vectors.v1.json` (sha256 `9e7e6301e9e04c6848efb5409fae4fcba2bef8e489929bafea077152dc400c7f`).

## Public entries

| Entry | Purpose |
|---|---|
| `BeamioPgpMigrationImport.importFirstRun(context, eoa, walletRecord, pgpSource): ShellImportCode` | First-run import. The only public entry for the first copy. Marks the page's reads and writes as `migrating` while it runs. |
| `BeamioPgpMigrationImport.run(context, eoa, workspace = "default", source: LegacyPgpSource?): MigrationResult` | One PGP migration run. `source == null` reads L; otherwise P is used. |
| `BeamioPgpMigrationImport.state(context, eoa, workspace)` | `none`, `pending`, `failed` or `verified`. Read only. |
| `BeamioPgpMigrationImport.unregister(context, eoa, workspace): MigrationResult` | Removes M, N, the last code and the page copy's W fields, after the recovery check. |
| `BeamioShellRecordImport.handle(context, origin, body, requestBytes): JSONObject` | The page's bridge: `shellRecordRead` and `shellRecordWrite` only. |
| `BeamioShellRecordImport.writeWalletNative(context, record): JSONObject` | Native account creation or recovery. May replace the W fields. The page never calls it. |
| `BeamioShellRecordImport.migrationState(context): String` | Native read-only query. The page does not call it. |
| `BeamioShellRecordImport.setMigrationPending(Boolean)` | Start-up flag set by the shell. `importFirstRun` restores the value it found. |

`context` is the Android `Context`; the spec's signatures omit it. `importFirstRun` is the public name, and `BeamioShellRecordImport` holds
no entry of that name.

## First-run import: input format

- `eoa`: lower-case `0x` followed by 40 hex digits.
- `walletRecord`: `LegacyWalletRecord`.
  - `Found(bytes)`: UTF-8 JSON of the legacy wallet record. The reader strips the PGP fields; the SDK strips them again
    (`chatManager.pgpKey`, `profiles[*].pgpKey`, `pgpPassphrase`, `chats[*].chatData.privateArmored`). The account is the profile whose
    `keyID` equals `eoa` (case-insensitive, first match). Its `privateKeyArmor` must be `0x` + 64 hex digits and must derive `eoa`; otherwise
    the result is `address_mismatch`. The input `schemaVersion` and `rev` are ignored.
  - `Absent`: the legacy store is confirmed absent or empty. Result `absent`.
  - `Unreadable(reason)`: the legacy store is temporarily unreadable. Result `legacy_unreadable`.
  - The byte array is zero-filled after use.
- `pgpSource`: `LegacyPgpSource(privateArmor: ByteArray, publicArmor: ByteArray, keyId: String)`, or `null` to read L. Each armor is at most
  64 KB in UTF-8. The SDK zero-fills the arrays after use.
- Result: `ShellImportCode` with the wire values `import_ok`, `exists`, `absent`, `legacy_unreadable`, `import_failed`, `address_mismatch`.
  The PGP migration runs only after `import_ok`; its result is separate and does not change the import result.

On success the copy is written with `schemaVersion: 2` and `rev: 1`. The copy is not overwritten: an existing copy gives `exists`.

## Page record: file format (§25.52L.2)

| Offset | Length | Content |
|---|---|---|
| 0 | 1 | Version byte `0x01` |
| 1 | 12 | Nonce, random per write |
| 13 | n | AES-256-GCM ciphertext of the UTF-8 JSON copy (W fields included, PGP fields absent) |
| 13 + n | 16 | GCM tag |

The file is `29 + n` bytes. Shorter files, a version byte other than `0x01`, or an AAD mismatch give `record_unreadable`. Such a file is
never read as `absent` and never overwritten.

AAD: the lower-case `eoa:workspace` UTF-8 bytes (workspace `default`), followed by the byte `0x01`.
Example (FM-01): `0xAbC0…01` gives `3078616263…3a64656661756c7401`.

The Keystore key is AES-256-GCM, not exportable, with randomized encryption required. StrongBox is used when available. The key is not
verified on a device in this build.

## W fields and the account slot (§25.52H, §25.52L.4, §25.52L.5)

- W fields: `profiles[k].privateKeyArmor` on the account's record, top-level `mnemonic`, and `walletVault.mnemonic`.
- The account's record is the profile whose `keyID` equals the account, compared without case. Several matches give no slot.
- **Conditional fallback (documented; accepted by the PM under R424):** while no profile of the record carries a `keyID` at all, the
  account's record is `profiles[0]`. This is the "until confirmed" rule of §25.52B.6. It applies to the W placement only. The first-run
  import always matches by `keyID`. Android measurement must confirm the `keyID` match before release.
- A W field in a profile other than the account's record gives `conflict` with `reason: "w_account_unmatched"`. So does a stored W field the
  page cannot place. An omitted W field keeps the stored value. A different value, `null` included, gives `conflict` with `reason: "w_differs"`.
- A stored copy with W fields takes only `schemaVersion` 2 writes. A write with schema 1 or without `schemaVersion` gets
  `wallet_copy_not_approved`, listing the stored W paths, and the store is unchanged.
- `writeWalletNative` may replace the W fields. The page path may not.

## Writes: key-shape scan and whitelist (§25.52L.9)

The checks run in this order:

1. A PGP private-key header in any string value, or a forbidden PGP path: `pgp_private_in_payload`.
2. A key shaped like private key material outside the W paths: `key_shaped_content`, with the paths named. Key names checked:
   prefixes `privateKey`, `pgpPassphrase`, `pgpPrivate`, and the exact names `privateKeyHex`, `privateKeyArmored`, `walletPrivateKey`, `mnemonic`,
   `seed`. The scan covers the container subtrees.
3. Schema checks (above).
4. Whitelist, by exact path: anything else is `bad_request`, with the paths named. PGP public fields under `chatManager.pgpKey` are not
   whitelisted and are `bad_request`.

## Unregister and the W fields (§25.52H.2 rule 5, §25.52J.3, R424)

`unregister` checks the recovery source before any removal: L exists, or P is readable, or a chain backup is registered. If none holds and
M, N or W is present, the result is `unregister_refused` and nothing is removed.

Removal order: M, then N, then the last code, then the W fields. The page copy keeps everything else, and its `rev` is incremented, so a
page holding an older copy gets `conflict` on its next write. An unreadable copy is erased whole. A failed write of the copy gives
`write_failed`; M, N and the last code are already gone, and the next call removes the W fields.

Frozen r3bh §25.52D.12 leaves the page copy's handling open. The W-field removal above follows the PM's R424 instruction and the
unfrozen r3bi §25.52M.2.

## Size limits (§25.52L.10)

The 2 MB limit applies to the whole message envelope in raw UTF-8 bytes, on the request and on the response. The caller passes
`requestBytes` for the request.

## Tests

`./gradlew :chat:testDebugUnitTest --offline` runs the vectors (`ShellRecordVectorsTest`, `PgpMigrationVectorsTest`), the file-format
tests (`ShellRecordFormatTest`), and the review-item tests (`ShellRecordR424Test`). The key-shape mutation (TR-16 disabled) fails
the vector run.
