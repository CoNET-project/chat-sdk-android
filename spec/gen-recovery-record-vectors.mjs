// Generates recovery-record-vectors.v1.json: the record shape that the PWA's createRecover writes and restoreWithRedeem reads
// (SilentPassUI beamio.ts), with synthetic inputs only.
//
// Usage (paths point at the PWA's node_modules; nothing is installed here):
//   NOBLE_DIR=<.../node_modules/@noble/hashes> UUID62_DIR=<.../node_modules/uuid62> \
//     node gen-recovery-record-vectors.mjs > recovery-record-vectors.v1.json
//
// Record = base64( JSON.stringify({ stored, img }) ), index = keccak256(utf8(code)).
// stored = { algo: 'argon2id', v: 19, m, t, p, salt, hash }. img = base64( iv(12) || AES-GCM(key, base64(mnemonic)) ),
// key = argon2id(password = code, salt, m, t, p, dkLen 32). The mnemonic is the BIP-39 public test vector (entropy 00).
import { createRequire } from 'node:module'

const require = createRequire(import.meta.url)
const { argon2id } = require(`${process.env.NOBLE_DIR}/argon2.js`)
const { keccak_256 } = require(`${process.env.NOBLE_DIR}/sha3.js`)
const uuid62 = require(process.env.UUID62_DIR)
const subtle = globalThis.crypto.subtle

const te = new TextEncoder()
const MNEMONIC = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'

const hex = (s) => Uint8Array.from(s.match(/../g).map((b) => parseInt(b, 16)))
const toHex = (u8) => Buffer.from(u8).toString('hex')
const b64 = (u8) => Buffer.from(u8).toString('base64')
// Same output as the PWA's toBase64(s): btoa of the UTF-8 bytes.
const toBase64 = (s) => Buffer.from(te.encode(s)).toString('base64')

async function makeRecord({ name, codeHex, pinText, m, t, p, saltHex, ivHex }) {
  const code = uuid62.encode(codeHex, 'hex') // 22 base62 characters, as uuid62.v4() produces
  const salt = hex(saltHex)
  const iv = hex(ivHex)
  const pin = te.encode(pinText)

  const stored = {
    algo: 'argon2id',
    v: 19,
    m,
    t,
    p,
    salt: b64(salt),
    hash: b64(argon2id(pin, salt, { m, t, p, dkLen: 32 })),
  }

  const keyBytes = argon2id(te.encode(code), salt, { m, t, p, dkLen: 32 })
  const key = await subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt'])
  const cipher = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv }, key, te.encode(toBase64(MNEMONIC))))
  const combined = new Uint8Array(iv.length + cipher.length)
  combined.set(iv, 0)
  combined.set(cipher, iv.length)
  const img = b64(combined)

  const record = toBase64(JSON.stringify({ stored, img }))
  const index = '0x' + toHex(keccak_256(te.encode(code)))
  return { name, code, index, record, mnemonic: MNEMONIC, params: { m, t, p }, pinForStored: pinText }
}

const cases = []
cases.push(await makeRecord({
  name: 'pwa-default-params',
  codeHex: '5a7f0c3e9b1d4e6a8f2c0b9d7e5a4f31',
  pinText: '2468',
  m: 32 * 1024, t: 3, p: 1,
  saltHex: '00112233445566778899aabbccddeeff',
  ivHex: '0102030405060708090a0b0c',
}))
cases.push(await makeRecord({
  name: 'small-params',
  codeHex: '0f1e2d3c4b5a69788796a5b4c3d2e1f0',
  pinText: '',
  m: 1024, t: 1, p: 1,
  saltHex: 'f0e1d2c3b4a596877869504132231100',
  ivHex: '0c0b0a090807060504030201',
}))

// Negative: the same record with another code must not decrypt. The record is not changed, only the code is.
const wrong = cases[1]
const wrongCode = uuid62.encode('11111111111111111111111111111111', 'hex')

const out = {
  file: 'recovery-record-vectors.v1.json',
  spec: 'spec §25.26.4e.3 path A (synthetic); record layout from SilentPassUI beamio.ts createRecover / restoreWithRedeem',
  generator: 'gen-recovery-record-vectors.mjs',
  synthetic: 'Codes and salts are fixed synthetic values. The mnemonic is the BIP-39 public test vector (entropy 00). Not a real wallet.',
  index: 'keccak256(utf8(code)) (createRecover registers recoverCode.hash; restoreWithRedeem looks up solidityPackedKeccak256([string]))',
  cases,
  negatives: [
    { name: 'wrong-code-does-not-decrypt', code: wrongCode, record: wrong.record, expect: 'record_invalid' },
  ],
}
process.stdout.write(JSON.stringify(out, null, 2) + '\n')
