#!/usr/bin/env node
// gen-native-recovery-vectors.mjs — 原生恢复页与恢复引擎的向量（spec r3u §25.42）
//
// 合成数据：恢复码、口令、账号名、助记词（BIP-39 公开测试助记词）、注册表记录均为生成器内部构造，不对应任何真实账户。
// 记录的加密算法与 PWA 现行实现一致（services/beamio.ts：createRecover、aesGcmEncryptWithStored、deriveAesKeyFromPassword）：
//   Argon2id（v=19，参数取自记录的 m、t、p，salt 为 base64，口令为 UTF-8，dkLen 32）；AES-256-GCM，
//   12 字节 IV 前置，密文后附 16 字节标签；base64 标准字母表；记录为 base64(JSON({stored, img}))。
// 生成器用参考模型逐条执行每个用例，并核对人工写出的期望（expect）。模型用于证明期望与 §25.42 一致，不是实现。
// 不联网，不访问链，不调用任何合约方法。
//
// 用法：node gen-native-recovery-vectors.mjs [--out <路径>]
import fs from 'node:fs'
import path from 'node:path'
import crypto from 'node:crypto'
import { fileURLToPath } from 'node:url'
import { createRequire } from 'node:module'

const here = path.dirname(fileURLToPath(import.meta.url))
const args = process.argv.slice(2)
const outIdx = args.indexOf('--out')
const OUT = outIdx >= 0 ? path.resolve(args[outIdx + 1]) : path.join(here, 'native-recovery-vectors.v1.json')

// The PWA package that provides @noble/hashes is named by an environment variable (no home-directory path in the repository).
const pwaPackageJson = process.env.SILENTPASS_UI_PACKAGE_JSON
if (!pwaPackageJson) throw new Error('set SILENTPASS_UI_PACKAGE_JSON to the SilentPassUI package.json')
const requirePwa = createRequire(path.resolve(pwaPackageJson))
const { argon2id } = requirePwa('@noble/hashes/argon2.js')
const ethers = requirePwa('ethers')
const subtle = globalThis.crypto.subtle

const sha256Hex = (buf) => crypto.createHash('sha256').update(buf).digest('hex')
const b64 = (u8) => Buffer.from(u8).toString('base64')
const unb64 = (s) => new Uint8Array(Buffer.from(s, 'base64'))
const utf8 = (s) => new TextEncoder().encode(s)
const fromUtf8 = (u8) => new TextDecoder().decode(u8)

// ---- 合成常量 ----
const MNEMONIC = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about' // BIP-39 公开测试助记词
const EOA = ethers.HDNodeWallet.fromPhrase(MNEMONIC, undefined, "m/44'/60'/0'/0/0").address.toLowerCase()
const CODE_A_OK = '3kRz8mQ2vLpN7wXy1sTcFh' // 22 位 [0-9A-Za-z]，合成
const CODE_A_CORRUPT = '9qWmT4vYp2NcLx8RbHs3Ge'
const CODE_A_BADMNEMONIC = 'Lw5KbZ2pRq8TmXc3VhNs4D'
const CODE_A_UNKNOWN = '7sDfG2hJk9LzQx4WcVb6Tn'
const PIN_B = 'SYN-pin-2026'
const NAME_B_OK = 'syn_recover_0001'
const NAME_B_LEGACY = 'syn_legacy_0002'
const SALT = utf8('SYN-SALT-0000001') // 16 字节，合成
const IV = utf8('SYNIV-000001') // 12 字节，合成（固定，使向量可复现）

// Argon2id 参数：与 PWA defaultBrowserParams 一致
const PARAMS = { m: 32 * 1024, t: 3, p: 1 }

async function deriveAesKey(password, stored) {
  const keyBytes = argon2id(utf8(password), unb64(stored.salt), { m: stored.m, t: stored.t, p: stored.p, dkLen: 32 })
  return subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt'])
}

async function encryptWithStored(plaintext, password, stored) {
  const key = await deriveAesKey(password, stored)
  const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv: IV }, key, utf8(plaintext)))
  const out = new Uint8Array(IV.length + ct.length)
  out.set(IV, 0)
  out.set(ct, IV.length)
  return b64(out)
}

async function decryptWithStored(cipherB64, password, stored) {
  const key = await deriveAesKey(password, stored)
  const combined = unb64(cipherB64)
  const iv = combined.slice(0, 12)
  const ct = combined.slice(12)
  return fromUtf8(new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv }, key, ct)))
}

// ---- 夹具：注册表与迁移前注册表的记录 ----
const storedPin = (() => {
  const hash = argon2id(utf8(PIN_B), SALT, { m: PARAMS.m, t: PARAMS.t, p: PARAMS.p, dkLen: 32 })
  return { algo: 'argon2id', v: 19, m: PARAMS.m, t: PARAMS.t, p: PARAMS.p, salt: b64(SALT), hash: b64(hash) }
})()
const phraseB64 = b64(utf8(MNEMONIC))
const keccakName = (code) => ethers.solidityPackedKeccak256(['string'], [code])
const recordOf = (stored, img) => b64(utf8(JSON.stringify({ stored, img })))

const registry = {}
const legacyRegistry = {}

{
  // 路径 A：键为 keccak256(恢复码)
  const imgOk = await encryptWithStored(phraseB64, CODE_A_OK, storedPin)
  registry[`nameHash:${keccakName(CODE_A_OK)}`] = recordOf(storedPin, imgOk)

  const imgCorrupt0 = unb64(await encryptWithStored(phraseB64, CODE_A_CORRUPT, storedPin))
  imgCorrupt0[20] ^= 0x01 // 翻转一位密文
  registry[`nameHash:${keccakName(CODE_A_CORRUPT)}`] = recordOf(storedPin, b64(imgCorrupt0))

  const imgBad = await encryptWithStored(b64(utf8('syn not a mnemonic only words here')), CODE_A_BADMNEMONIC, storedPin)
  registry[`nameHash:${keccakName(CODE_A_BADMNEMONIC)}`] = recordOf(storedPin, imgBad)

  // 路径 B：键为账号名（使用 PIN 加密的 img1）
  const imgB = await encryptWithStored(phraseB64, PIN_B, storedPin)
  registry[`name:${NAME_B_OK}`] = recordOf(storedPin, imgB)

  // 迁移前注册表：只有这一个账号名
  legacyRegistry[`name:${NAME_B_LEGACY}`] = recordOf(storedPin, imgB)
}

// ---- 参考模型 ----
const CODE_RE = /^[0-9A-Za-z]{22}$/
const ERROR_CODES = ['ok', 'cancelled', 'invalid_format', 'bad_pin', 'backoff', 'not_found', 'network_error', 'already_exists', 'record_invalid', 'write_failed', 'readback_failed', 'legacy_record']
const cooldownFor = (f) => ({ 5: 30, 6: 60, 7: 300, 8: 900 })[f] ?? (f >= 9 ? 3600 : 0)

function parseRecord(encoded) {
  try {
    const obj = JSON.parse(fromUtf8(unb64(encoded)))
    if (!obj || !obj.stored || obj.stored.algo !== 'argon2id' || typeof obj.img !== 'string' || !obj.img) return null
    return obj
  } catch {
    return null
  }
}

function validMnemonic(phrase) {
  try {
    ethers.Mnemonic.fromPhrase(phrase)
    return true
  } catch {
    return false
  }
}

// 执行一次恢复尝试（引擎步骤，§25.42.4）。返回结果事件的字段与状态变化。
async function attempt(a, env) {
  const dev = env.device
  const out = (code, extra = {}) => ({ type: 'nativeRecoveryResult', reqId: a.reqId, code, ...extra })
  if (a.cancel) return out('cancelled')
  if (dev.hasKey) return out('already_exists') // 步骤 1：已有钥，不读取链上记录
  if (a.path === 'A') {
    const code = (a.code ?? '').trim()
    if (!CODE_RE.test(code)) return out('invalid_format')
    if (env.rpc === 'fail') return out('network_error')
    const rec = registry[`nameHash:${keccakName(code)}`]
    if (!rec) return out('not_found')
    const obj = parseRecord(rec)
    if (!obj) return out('record_invalid')
    let phrase
    try {
      phrase = fromUtf8(unb64(await decryptWithStored(obj.img, code, obj.stored)))
    } catch {
      return out('record_invalid')
    }
    if (!validMnemonic(phrase)) return out('record_invalid')
    const eoa = ethers.HDNodeWallet.fromPhrase(phrase, undefined, "m/44'/60'/0'/0/0").address.toLowerCase()
    if (dev.writeFail) return out('write_failed')
    if (dev.readbackFail) return out('readback_failed')
    dev.hasKey = true
    return out('ok', { eoa })
  }
  // 路径 B
  const name = (a.name ?? '').trim()
  const pwd = a.password ?? ''
  if (!name || !pwd) return out('invalid_format')
  if (dev.cooldownActive) return out('backoff', { cooldownSec: cooldownFor(dev.failures) })
  if (env.rpc === 'fail') return out('network_error')
  const rec = registry[`name:${name}`]
  if (!rec) {
    if (legacyRegistry[`name:${name}`]) return out('legacy_record')
    return out('not_found')
  }
  const obj = parseRecord(rec)
  if (!obj) return out('record_invalid')
  let phrase
  try {
    phrase = fromUtf8(unb64(await decryptWithStored(obj.img, pwd, obj.stored)))
  } catch {
    dev.failures += 1
    if (dev.failures >= 5) dev.cooldownActive = true
    return out('bad_pin')
  }
  if (!validMnemonic(phrase)) return out('record_invalid')
  const eoa = ethers.HDNodeWallet.fromPhrase(phrase, undefined, "m/44'/60'/0'/0/0").address.toLowerCase()
  if (dev.writeFail) return out('write_failed')
  if (dev.readbackFail) return out('readback_failed')
  dev.hasKey = true
  dev.failures = 0
  dev.cooldownActive = false
  return out('ok', { eoa })
}

async function runCase(c) {
  const env = { rpc: c.env?.rpc ?? 'ok', device: { hasKey: false, failures: 0, cooldownActive: false, writeFail: false, readbackFail: false, ...(c.env?.device ?? {}) } }
  const results = []
  for (const step of c.steps) {
    if (step.op === 'attempt') results.push(await attempt(step.a, env))
    else if (step.op === 'elapse') env.device.cooldownActive = false
  }
  return { results, state: { hasKey: env.device.hasKey, failures: env.device.failures, cooldownActive: env.device.cooldownActive } }
}

// ---- 用例（期望人工写出） ----
const A = (reqId, code, extra = {}) => ({ op: 'attempt', a: { path: 'A', reqId, code, ...extra } })
const B = (reqId, name, password) => ({ op: 'attempt', a: { path: 'B', reqId, name, password } })
const res = (reqId, code, extra = {}) => ({ type: 'nativeRecoveryResult', reqId, code, ...extra })
const G0 = {}
const G2 = { device: { hasKey: true } }

const CASES = [
  // 路径 A：恢复码（§25.42.3、§25.42.4）
  { id: 'R-01', group: 'A', title: '路径 A：恢复码正确，恢复成功，写入一次', testIds: ['T-228', 'T-231'], env: G0, steps: [A('R-01', CODE_A_OK)], expect: { results: [res('R-01', 'ok', { eoa: EOA })], state: { hasKey: true, failures: 0, cooldownActive: false } } },
  { id: 'R-02', group: 'A', title: '路径 A：去首尾空白后有效', testIds: ['T-228'], env: G0, steps: [A('R-02', `  ${CODE_A_OK} `)], expect: { results: [res('R-02', 'ok', { eoa: EOA })], state: { hasKey: true, failures: 0, cooldownActive: false } } },
  { id: 'R-03', group: 'A', title: '路径 A：长度 21：invalid_format，不发起读取', testIds: ['T-228'], env: G0, steps: [A('R-03', CODE_A_OK.slice(0, 21))], expect: { results: [res('R-03', 'invalid_format')], state: { hasKey: false, failures: 0, cooldownActive: false } } },
  { id: 'R-04', group: 'A', title: '路径 A：含非字母数字字符（-）：invalid_format', testIds: ['T-228'], env: G0, steps: [A('R-04', 'abcd-' + CODE_A_OK.slice(5))], expect: { results: [res('R-04', 'invalid_format')], state: { hasKey: false, failures: 0, cooldownActive: false } } },
  { id: 'R-05', group: 'A', title: '路径 A：格式有效但注册表无记录：not_found', testIds: ['T-228'], env: G0, steps: [A('R-05', CODE_A_UNKNOWN)], expect: { results: [res('R-05', 'not_found')], state: { hasKey: false, failures: 0, cooldownActive: false } } },
  { id: 'R-06', group: 'A', title: '路径 A：读取失败（RPC 两端都不可用）：network_error，不改变设备状态', testIds: ['T-228'], env: { ...G0, rpc: 'fail' }, steps: [A('R-06', CODE_A_OK)], expect: { results: [res('R-06', 'network_error')], state: { hasKey: false, failures: 0, cooldownActive: false } } },
  { id: 'R-07', group: 'A', title: '路径 A：记录密文被改动：record_invalid', testIds: ['T-230'], env: G0, steps: [A('R-07', CODE_A_CORRUPT)], expect: { results: [res('R-07', 'record_invalid')], state: { hasKey: false, failures: 0, cooldownActive: false } } },
  { id: 'R-08', group: 'A', title: '路径 A：解开后不是有效助记词：record_invalid', testIds: ['T-230'], env: G0, steps: [A('R-08', CODE_A_BADMNEMONIC)], expect: { results: [res('R-08', 'record_invalid')], state: { hasKey: false, failures: 0, cooldownActive: false } } },
  { id: 'R-09', group: 'A', title: '路径 A：设备已有钥（G2）：already_exists，不读取，不覆盖', testIds: ['T-231'], env: G2, steps: [A('R-09', CODE_A_OK)], expect: { results: [res('R-09', 'already_exists')], state: { hasKey: true, failures: 0, cooldownActive: false } } },
  { id: 'R-10', group: 'A', title: '路径 A：设备有记录未就绪（G1）：already_exists', testIds: ['T-231'], env: { device: { hasKey: true } }, steps: [A('R-10', CODE_A_OK)], expect: { results: [res('R-10', 'already_exists')], state: { hasKey: true, failures: 0, cooldownActive: false } } },
  { id: 'R-11', group: 'A', title: '路径 A：写入失败：write_failed，设备无钥', testIds: ['T-231'], env: { device: { writeFail: true } }, steps: [A('R-11', CODE_A_OK)], expect: { results: [res('R-11', 'write_failed')], state: { hasKey: false, failures: 0, cooldownActive: false } } },
  { id: 'R-12', group: 'A', title: '路径 A：读回不一致：readback_failed，回滚，设备无钥', testIds: ['T-231'], env: { device: { readbackFail: true } }, steps: [A('R-12', CODE_A_OK)], expect: { results: [res('R-12', 'readback_failed')], state: { hasKey: false, failures: 0, cooldownActive: false } } },
  { id: 'R-13', group: 'A', title: '用户在提交前取消：cancelled，不读取', testIds: ['T-226'], env: G0, steps: [A('R-13', CODE_A_OK, { cancel: true })], expect: { results: [res('R-13', 'cancelled')], state: { hasKey: false, failures: 0, cooldownActive: false } } },

  // 路径 B：账号名加密码（§25.42.3、§25.42.5）
  { id: 'B-01', group: 'B', title: '路径 B：账号名与密码正确，恢复成功', testIds: ['T-229', 'T-231'], env: G0, steps: [B('B-01', NAME_B_OK, PIN_B)], expect: { results: [res('B-01', 'ok', { eoa: EOA })], state: { hasKey: true, failures: 0, cooldownActive: false } } },
  { id: 'B-02', group: 'B', title: '路径 B：密码错误：bad_pin，错误次数加一，不回显输入', testIds: ['T-229'], env: G0, steps: [B('B-02', NAME_B_OK, 'SYN-wrong-1')], expect: { results: [res('B-02', 'bad_pin')], state: { hasKey: false, failures: 1, cooldownActive: false } } },
  { id: 'B-03', group: 'B', title: '路径 B：账号名不存在（当前与迁移前注册表都无）：not_found', testIds: ['T-229'], env: G0, steps: [B('B-03', 'syn_nobody_9999', PIN_B)], expect: { results: [res('B-03', 'not_found')], state: { hasKey: false, failures: 0, cooldownActive: false } } },
  { id: 'B-04', group: 'B', title: '路径 B：密码为空：invalid_format', testIds: ['T-229'], env: G0, steps: [B('B-04', NAME_B_OK, '')], expect: { results: [res('B-04', 'invalid_format')], state: { hasKey: false, failures: 0, cooldownActive: false } } },
  { id: 'B-05', group: 'B', title: '路径 B：账号名首尾空白被去除后有效（大小写与 @ 不改写）', testIds: ['T-229'], env: G0, steps: [B('B-05', `  ${NAME_B_OK}  `, PIN_B)], expect: { results: [res('B-05', 'ok', { eoa: EOA })], state: { hasKey: true, failures: 0, cooldownActive: false } } },
  { id: 'B-06', group: 'B', title: '路径 B：只在迁移前注册表有记录：legacy_record（v1 不迁移，§25.42.6 RC-3）', testIds: ['T-229'], env: G0, steps: [B('B-06', NAME_B_LEGACY, PIN_B)], expect: { results: [res('B-06', 'legacy_record')], state: { hasKey: false, failures: 0, cooldownActive: false } } },
  { id: 'B-07', group: 'B', title: '路径 B：连续 5 次错误后，第 6 次在冷却中：backoff，cooldownSec 30，不读取不解密', testIds: ['T-229'], env: G0, steps: [B('B-07a', NAME_B_OK, 'x1'), B('B-07b', NAME_B_OK, 'x2'), B('B-07c', NAME_B_OK, 'x3'), B('B-07d', NAME_B_OK, 'x4'), B('B-07e', NAME_B_OK, 'x5'), B('B-07f', NAME_B_OK, PIN_B)], expect: { results: [res('B-07a', 'bad_pin'), res('B-07b', 'bad_pin'), res('B-07c', 'bad_pin'), res('B-07d', 'bad_pin'), res('B-07e', 'bad_pin'), res('B-07f', 'backoff', { cooldownSec: 30 })], state: { hasKey: false, failures: 5, cooldownActive: true } } },
  { id: 'B-08', group: 'B', title: '路径 B：冷却结束后密码正确：恢复成功，错误次数清零', testIds: ['T-229'], env: G0, steps: [B('B-08a', NAME_B_OK, 'x1'), B('B-08b', NAME_B_OK, 'x2'), B('B-08c', NAME_B_OK, 'x3'), B('B-08d', NAME_B_OK, 'x4'), B('B-08e', NAME_B_OK, 'x5'), { op: 'elapse' }, B('B-08f', NAME_B_OK, PIN_B)], expect: { results: [res('B-08a', 'bad_pin'), res('B-08b', 'bad_pin'), res('B-08c', 'bad_pin'), res('B-08d', 'bad_pin'), res('B-08e', 'bad_pin'), res('B-08f', 'ok', { eoa: EOA })], state: { hasKey: true, failures: 0, cooldownActive: false } } },
  { id: 'B-09', group: 'B', title: '路径 B：第 6 次错误后冷却为 60 秒', testIds: ['T-229'], env: G0, steps: [B('B-09a', NAME_B_OK, 'x1'), B('B-09b', NAME_B_OK, 'x2'), B('B-09c', NAME_B_OK, 'x3'), B('B-09d', NAME_B_OK, 'x4'), B('B-09e', NAME_B_OK, 'x5'), { op: 'elapse' }, B('B-09f', NAME_B_OK, 'x6'), B('B-09g', NAME_B_OK, PIN_B)], expect: { results: [res('B-09a', 'bad_pin'), res('B-09b', 'bad_pin'), res('B-09c', 'bad_pin'), res('B-09d', 'bad_pin'), res('B-09e', 'bad_pin'), res('B-09f', 'bad_pin'), res('B-09g', 'backoff', { cooldownSec: 60 })], state: { hasKey: false, failures: 6, cooldownActive: true } } },
  { id: 'B-10', group: 'B', title: '路径 B：读取失败不计入错误次数', testIds: ['T-229'], env: { ...G0, rpc: 'fail' }, steps: [B('B-10', NAME_B_OK, PIN_B)], expect: { results: [res('B-10', 'network_error')], state: { hasKey: false, failures: 0, cooldownActive: false } } },
  { id: 'B-11', group: 'B', title: '路径 B：设备已有钥：already_exists，不计入错误次数', testIds: ['T-231'], env: G2, steps: [B('B-11', NAME_B_OK, 'x1')], expect: { results: [res('B-11', 'already_exists')], state: { hasKey: true, failures: 0, cooldownActive: false } } },
]

// ---- 核对 ----
const canon = (v) => JSON.stringify(v, (k, x) => (x && typeof x === 'object' && !Array.isArray(x) ? Object.fromEntries(Object.keys(x).sort().map((kk) => [kk, x[kk]])) : x))
const RESULT_FORBIDDEN = ['recoveryCode', 'pin', 'password', 'mnemonic', 'privateKey', 'privateKeyHex', 'hash', 'img', 'stored', 'ciphertext', 'key']
const errors = []
for (const c of CASES) {
  const got = await runCase(c)
  if (canon(got) !== canon(c.expect)) errors.push(`${c.id}: differs\n  want ${canon(c.expect)}\n  got  ${canon(got)}`)
  for (const r of got.results) {
    if (!ERROR_CODES.includes(r.code)) errors.push(`${c.id}: unknown code ${r.code}`)
    for (const k of Object.keys(r)) if (RESULT_FORBIDDEN.includes(k)) errors.push(`${c.id}: forbidden field ${k}`)
    if (r.code !== 'ok' && 'eoa' in r) errors.push(`${c.id}: eoa on non-ok`)
    if (r.code !== 'backoff' && 'cooldownSec' in r) errors.push(`${c.id}: cooldownSec on non-backoff`)
  }
}
if (errors.length) {
  console.error(errors.join('\n'))
  process.exit(1)
}

const doc = {
  file: 'native-recovery-vectors.v1.json',
  purpose: '原生恢复页与恢复引擎（spec r3u §25.42）：路径 A（恢复码）与路径 B（账号名加密码）的步骤、错误码、退避，以及记录的解密兼容性。合成数据：恢复码、口令、账号名、注册表记录均为生成器构造，助记词为 BIP-39 公开测试助记词。',
  spec: 'v1.1-r3u §25.42（测试 T-228 至 T-232）',
  generator: 'gen-native-recovery-vectors.mjs',
  sourceAlgorithm: { file: 'src/SilentPassUI（PWA SilentPassUI-v2 工作树 services/beamio.ts）', functions: ['createRecover', 'restoreWithRedeem', 'restoreWithUserPin', 'aesGcmEncryptWithStored', 'aesGcmDecryptWithStored', 'deriveAesKeyFromPassword', 'generateCODE'] },
  kdf: { algo: 'argon2id', version: 19, defaultParams: PARAMS, dkLen: 32, passwordEncoding: 'UTF-8', salt: 'base64', cipher: 'AES-256-GCM', ivBytes: 12, tagBytes: 16, layout: 'base64(iv || ciphertext || tag)' },
  record: { format: 'base64(JSON({stored, img}))', storedFields: ['algo', 'v', 'm', 't', 'p', 'salt', 'hash'] },
  registryKeys: { pathA: 'keccak256(solidityPacked(string, [recoveryCode]))，读取 getBase64ByNameHash(bytes32)', pathB: '账号名字符串，读取 getBase64ByAccountName(string)' },
  recoveryCodeFormat: { regex: '^[0-9A-Za-z]{22}$', source: 'uuid62.v4()（20000 个样本全部符合）' },
  backoff: { table: { '5': 30, '6': 60, '7': 300, '8': 900, '>=9': 3600 }, counted: 'bad_pin only (path B)', reset: 'on ok' },
  fixtures: {
    registry: registry,
    legacyRegistry: legacyRegistry,
    syntheticNote: '注册表记录为合成数据，由上述算法生成；口令与恢复码为合成值；助记词为 BIP-39 公开测试助记词，派生地址 ' + EOA + '。',
  },
  errorCodes: ERROR_CODES,
  cases: CASES.map((c) => ({ id: c.id, group: c.group, title: c.title, testIds: c.testIds, env: c.env ?? {}, steps: c.steps, expect: c.expect })),
  counts: { cases: CASES.length, A: CASES.filter((c) => c.group === 'A').length, B: CASES.filter((c) => c.group === 'B').length },
  toolVersions: { ethers: '6.16.0', node: process.version },
  notCovered: [
    '迁移前注册表的读取与迁移写入（RC-3）：v1 只返回 legacy_record，不迁移。',
    '恢复后 PWA 的 init 与 provisionIdentity 流程（§25.26.4c）：由 PWA 与 SDK 的既有用例覆盖。',
    '原生页的输入、剪贴板、屏幕保护与界面文案：由原生页验收覆盖。',
    '真实注册表的可用性与延迟：不访问链，由 mock 的 rpc 状态覆盖。',
  ],
}
const text = JSON.stringify(doc, null, 2) + '\n'
fs.writeFileSync(OUT, text)
console.log('wrote', OUT, 'cases', CASES.length, 'sha256', sha256Hex(Buffer.from(text)))
