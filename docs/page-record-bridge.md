# Page-record bridge and first-run import (SDK 0.2.16)

This note is the SDK-side reference for the native page-record bridge. It follows spec r3br (§25.52K to §25.52V) and the vectors
`spec/pgp-migration-vectors.v1.json` (sha256 `fba0ecf167f2b3e86bac7888ea646b25db20a972dcf9ac9914f9326353f92990`, 188 self-checks).

## Public entries

| Entry | Purpose |
|---|---|
| `BeamioPgpMigrationImport.importFirstRun(context, eoa, walletRecord, pgpSource): ShellImportCode` | First-run import. The only public entry for the first copy. Marks the page's reads and writes as `migrating` while it runs. |
| `BeamioPgpMigrationImport.run(context, eoa, workspace = "default", source: LegacyPgpSource?): MigrationResult` | One PGP migration run. `source == null` reads L; otherwise P is used. |
| `BeamioPgpMigrationImport.state(context, eoa, workspace)` | `none`, `pending`, `failed` or `verified`. Read only. |
| `BeamioPgpMigrationImport.unregister(context, eoa, workspace): MigrationResult` | Removes M, N, the last code and the page copy's W fields, after the recovery check. |
| `BeamioShellRecordImport.handle(context, origin, body, requestBytes): JSONObject` | The page's bridge: `shellRecordRead` and `shellRecordWrite` only. Returns the ack envelope (below). |
| `BeamioShellRecordImport.writeWalletNative(context, record): JSONObject` | Native account creation or recovery. May replace the W fields. The page never calls it. |
| `BeamioShellRecordImport.migrationState(context): String` | Native read-only query. The page does not call it. |
| `BeamioShellRecordImport.setMigrationPending(Boolean)` | Start-up flag set by the shell. `importFirstRun` restores the value it found. |

`context` is the Android `Context`; the spec's signatures omit it.

## Ack envelope (§25.28.3, §25.52T.2)

Every answer to `shellRecordRead` and `shellRecordWrite` is an ack. No separate event is sent.

- Reached by the bridge: `{type: "ack", reqId, ok: true, result: {code, ...}}`. The outcome is `result.code`: `ok`, `absent`, `error`
  (with `sub` in `result`), `migrating`, `conflict` (with `currentRev`), `wallet_copy_not_approved`, `pgp_private_in_payload`,
  `key_shaped_content`, `bad_request` (with `names`), `wallet_fields_missing`, `write_failed`.
- Envelope-level refusal: `{type: "ack", reqId, ok: false, error}` with no `result`. `error` is `origin_refused`, `too_large`, or a
  `bad_request` without names (an invalid reqId, a missing record, a non-integer `rev`).
- `reqId` is echoed as sent (a string or an integer), or `null` when it is invalid.
- The response never contains the internal `store`.

Unverified origins through the generic bridge get the same refusal (`origin_refused`) with the reqId echoed.

## First-run import: input format

- `eoa`: lower-case `0x` followed by 40 hex digits.
- `walletRecord`: `LegacyWalletRecord`.
  - `Found(bytes)`: UTF-8 JSON of the legacy wallet record. The reader strips the PGP fields; the SDK strips them again, including the
    PGP public fields (`beamio.pgpPublicKeyArmor`, `beamio.pgpPublicKeyID`, and the `chats[*].chatData` public fields).
    The account is the profile whose `keyID` equals `eoa` (case-insensitive, first match). Its `privateKeyArmor` must be `0x` + 64 hex digits
    and must derive `eoa`. Without a matching profile or without a `privateKeyArmor`: `import_failed` (provisional, §25.52N.6). A key that
    derives another address: `address_mismatch`. `mnemonicPhrase` is kept; its derivation is not checked by the SDK in this build. The input
    `schemaVersion` and `rev` are ignored.
  - `Absent`: the legacy store is confirmed absent or empty. Result `absent`.
  - `Unreadable(reason)`: the legacy store is temporarily unreadable. Result `legacy_unreadable`.
  - The byte array is zero-filled after use.
- `pgpSource`: `LegacyPgpSource(privateArmor: ByteArray, publicArmor: ByteArray, keyId: String)`, or `null` to read L. Each armor is at most
  64 KB in UTF-8. The SDK zero-fills the arrays after use.
- Result: `ShellImportCode` with the wire values `import_ok`, `exists`, `absent`, `legacy_unreadable`, `import_failed`, `address_mismatch`.
  The PGP migration runs only after `import_ok`; its result is separate.

On success the copy is written with `schemaVersion: 2` and `rev: 1`. An existing copy gives `exists` and is never overwritten.

## Absence, the account pointer and the device marker (§25.52T.3 to §25.52T.6)

- `absent` needs all three: the legacy store is confirmed absent or empty, the account pointer is empty, and there is no native record.
- The account pointer (`account_pointer.v1`, no-backup directory, non-secret) is set by the first successful native write (the import or
  the native creation). Reads and writes never clear it. While it is set and no record exists, a read answers `error` with
  `account_record_missing`, never `absent`; a write answers the same error.
- The device marker (`legacy_store_unreadable.v1`) is set when the legacy store is unreadable while no pointer and no record exist. It is
  cleared by a confirmed absence (the next read answers `absent`), by a successful import, or by an existing copy.
- Read with no record, by the import outcome:

| Pointer | Legacy outcome | Marker | Answer |
|---|---|---|---|
| set | any | any | `error`, `account_record_missing` |
| not set | unreadable | any | `error`, `legacy_store_unreadable`; marker set |
| not set | not read again | set | `error`, `legacy_store_unreadable` |
| not set | not read again | not set | `migrating` (§25.52U.3) |
| not set | found, import not done | any | `error`, `import_not_done`; the marker has no effect |
| not set | confirmed absent or empty | any | `absent`; marker cleared |

- A readable record wins over the marker (§25.52U.5): reading it clears the marker, and repairs an empty pointer when a profile matches the
  account. The table above applies only while no record exists.
- `migrating` is the one answer for a legacy store not yet read (no pointer, no marker, no record); `import_not_done` only for a found,
  not yet imported, legacy record.

- Write with no record: `migrating` while the marker is set or the legacy store is unreadable (no first write); the first write goes ahead
  only after a confirmed absence.

A fresh install reaches `absent` through the import's confirmation (`importFirstRun` with `Absent`); before the import runs, a read answers
`migrating`.

## Page record: file format (§25.52L.2)

| Offset | Length | Content |
|---|---|---|
| 0 | 1 | Version byte `0x01` |
| 1 | 12 | Nonce, random per write |
| 13 | n | AES-256-GCM ciphertext of the canonical JSON copy (see below) |
| 13 + n | 16 | GCM tag |

The file is `29 + n` bytes. Shorter files, a version byte other than `0x01`, or an AAD mismatch give `record_unreadable`. Such a file is
never read as `absent` and never overwritten.

AAD: the lower-case `eoa:workspace` UTF-8 bytes (workspace `default`), followed by the byte `0x01`.

Plaintext (§25.52M.4, tentative): the canonical JSON of the copy: UTF-8, object keys in UTF-8 byte order, no whitespace, array order kept.

The Keystore key is AES-256-GCM, not exportable, with randomized encryption required. StrongBox is used when available. The key is not
verified on a device in this build.

## W fields (§25.52N.3, §25.52P.2, §25.52P.4, §25.52R.2)

- W fields: `profiles[*].privateKeyArmor` on the account's record (keyID equal to the account, case-insensitive), top-level
  `mnemonicPhrase`, and top-level `recoveryWords`. They are encrypted, never sent by the page, and kept when the page omits them.
- A different value, `null` included, gives `conflict` with `reason: "w_differs"`. A W field outside the account's record, or a stored one
  the page cannot place, gives `conflict` with `reason: "w_account_unmatched"`. Only native creation or recovery replaces them.
- Read judgement of a schema 2 copy (§25.52U.4, R432), by the profile whose `keyID` equals the account (case-insensitive, no index fallback):
  no matching profile, or more than one: `error`, `account_mismatch` (fail closed, no recovery entry); the matching profile has no
  `privateKeyArmor`: `error`, `needs_native_recovery` (the page offers `nativeRecoveryOpen`). A missing `mnemonicPhrase` is allowed.
- A write that leaves no profile matching the account with a `privateKeyArmor` is refused with `wallet_fields_missing`, and nothing is stored.
- `privateKeyArmorWrap` is not a W field: it is never stored, and a write with it is `key_shaped_content`.
- Non-W fields are replaced as a whole by the payload (§25.52S.5). Non-W fields in the store that the payload does not carry are removed.

## Writes: the check order (§25.52O.5)

1. Size (2 MB raw bytes), `rev` an integer.
2. A PGP private header, or a forbidden PGP private path: `pgp_private_in_payload`.
3. W fields with `schemaVersion` below 2, or a stored copy with W fields written at a lower schema: `wallet_copy_not_approved`.
   A missing or non-integer `schemaVersion`: `bad_request`.
4. Key-shaped content outside the W paths (`privateKey*`, `mnemonic*`, `pgpPassphrase*`, `pgpPrivate*`, `duplicateCode*`, `seed`,
   `recoveryCode`, `recoveryPhrase`, `duplicatePassword`, `duplicateMnemonicPhrase`, `_duplicateCode`, `walletPrivateKey`): `key_shaped_content`,
   path names listed.
5. Anything outside the whitelist, and every PGP public path: `bad_request`, leaf paths listed in UTF-8 byte order.
6. `migrating`, then the device marker and the import outcome for a first write.
7. `rev` differs: `conflict` with `currentRev`.
8. The wallet-field merge: `conflict` as above.
9. A schema 2 copy without a holder of `privateKeyArmor`: `wallet_fields_missing`.
10. Write failure: `write_failed`, the store unchanged.

## Whitelist (§25.52N.4, §25.52O.2, §25.52Q.3)

- The whitelist is capped at the 108 measured paths (§25.52T.7): every entry must be one of them.
- Top level: `schemaVersion`, `rev`, `isReady`, `ver`, `nonce`, `upgradev2`, `webFilter`, `mnemonicPhrase`, `recoveryWords`; containers
  `preferences`, `fx168Order`, `cardRedeems`, `ChannelPartners`, `referrals`, `fragmentClass`, `search`; `beamio` with 15 exact keys;
  `profiles`. `passcode` is not whitelisted at all (`passcode.status` is refused, §25.52T.7).
- Profile: scalars `isPrimary`, `emailAddr`, `hdPath`, `index`, `isNode`, `referrer`, `nodeID`, `nodeIP_address`, `nodeRegion`,
  `vpnTimeUsedInMin`, `webFilter`, `aaAccount`, `keyID`, `type`, `publicKeyArmor`, `privateKeyArmor`; containers `tokens`, `spClub`,
  `SpClubPoints`, `spChannel`, `airdropEvent`, `data`, `activePassport`, `silentPassPassports`, `chats`, `phoneCalls`, `issuedCards`;
  `chatManager` with `router` only (`chatManager.keyID` and `routes` are not whitelisted, §25.52T.7).
- Containers take any subtree; the subtree still goes through the key-shape scan.
- Not whitelisted: `encryptedString`, `keyObj` (whole), `duplicateAccount`, `walletVault`, the non-status keys of `passcode`, and every PGP
  public path.

## PGP fields (§25.52N.5, §25.52P.5, §25.52Q.3, §25.52R.3, §25.52S.2)

- Private (`pgp_private_in_payload`): `chatManager.pgpKey.privateKey`, `chatManager.pgpKey.privateKeyArmor`,
  `chatManager.pgpKey.privateKeyArmorWrap`, `profiles[*].pgpKey.privateKeyArmor`, `profiles[*].pgpKey.privateKeyArmorWrap`, the top-level
  `pgpPassphrase`, `chats[*].chatData.privateArmored`. `privateKeyObj` is a key-shaped name instead.
- Public (write: `bad_request` with the path names; the page refuses to send them): `chatManager.pgpKey.publicKey`, `.keyID`, `.routes`,
  `profiles[*].pgpKey.publicKeyArmor`, `.publicKeyObj`, `beamio.pgpPublicKeyArmor`, `beamio.pgpPublicKeyID`, `chats[*].chatData.publicArmored`,
  `routePgpKeyID`, `routersArmoreds`.
- Read and first import: the public and private PGP fields are removed (`chatManager.pgpKey`, `pgpKey`, `pgpPassphrase`, and the public
  paths above). An emptied `beamio` or `chatManager` is removed. A read never rewrites the store (§25.52V.3): a residual field is stripped on
  every read until the next full page write replaces it.
- Native write (§25.52V.2): a PGP public field is `bad_request` with the path names, even with `nativeWrite` (AK-22). The page record never
  holds PGP material; the account's PGP public material belongs to the SDK account record, written by the native creation flow.
  That flow is not part of this build: the BouncyCastle key generator is not approved for production (`verify_unavailable`).

## Unregister and the W fields (§25.52H.2 rule 5, §25.52M.2, §25.52S.4)

`unregister` checks the recovery source before any removal: L exists, or P is readable, or a chain backup is registered. If none holds and
M, N or W is present, the result is `unregister_refused` and nothing is removed.

Removal order: M, then N, then the last code, then the W fields (`privateKeyArmor`, `mnemonicPhrase`, `recoveryWords`). The page copy keeps
everything else, and its `rev` is incremented, so a page holding an older copy gets `conflict` on its next write. An unreadable copy is erased
whole. A failed write of the copy gives `write_failed`; the next call removes the W fields.

## Size limits (§25.52L.10)

The 2 MB limit applies to the whole message envelope in raw UTF-8 bytes, on the request and on the response. A read answer that would exceed
it is `too_large`, checked before the schema-specific answers.

## Open points

- `mnemonicPhrase` derivation in the first-run import is not checked by the SDK (no BIP-39 derivation in this build). The vector IM-09 uses a
  placeholder phrase, so the check is left for PM.
- The first-run import has no whitelist for legacy fields beyond PGP (`legacy_fields_unknown` is not decided, §25.52N.6).
- `accountSlot` keeps the conditional profile-0 fallback for records with no keyID (PM R424); Android measurement must confirm the keyID match.
- Pending PM (r3bq §25.52U.11): `account_mismatch` (new sub-code, fail closed); the pointer repair on a read.
- Pending PM (earlier): a write with the pointer set and no record answers `account_record_missing` (the spec gives the read only); a marker set
  with a write answers `migrating` (§25.52T.5).
- The read judgement is strict by keyID (§25.52U.4), while the write placement keeps the conditional profile-0 fallback of R424. A schema 2
  record written with no keyIDs at all would therefore read back as `account_mismatch`; measured records carry keyIDs.
- The 108-path cap was checked against the measured manifest (page-record-paths-measured, 108 listed paths): all 62 whitelist paths
  (containers included) are among them. The tests do not read that manifest.

## Tests

`ShellRecordAckVectorsTest` runs AK-01 to AK-20 (the ack group, §25.52T.8, §25.52U.9). `ShellRecordR439Test` covers the r3bq rules
that the vectors do not fix (the first-write guard, the marker and pointer repair, the case-insensitive keyID).

`./gradlew :chat:testDebugUnitTest --offline` runs the vectors (`ShellRecordVectorsTest`, `PgpMigrationVectorsTest`), the file-format tests
(`ShellRecordFormatTest`), the review-item tests (`ShellRecordR424Test`), and the R431 tests (`ShellRecordR431Test`: ack envelope, fresh install,
device marker, canonical JSON).
