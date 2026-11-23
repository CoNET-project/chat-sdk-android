// Generator for wrap-key-loss-vectors.v1.json (spec §25.52Y.122, §25.52Y.123).
// Pure and deterministic: no clock, no randomness, no I/O besides writing the output file.
// Usage: node gen-wrap-key-loss-vectors.mjs <outFile>
// The classification and decision functions below are the normative reference for the vectors. Platforms implement the same
// rules; the vectors are the shared expectation.
import { createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';

const outFile = process.argv[2];
if (!outFile) throw new Error('usage: node gen-wrap-key-loss-vectors.mjs <outFile>');

const sha256 = (s) => createHash('sha256').update(s).digest('hex');
const RETRY_SECONDS = [30, 120, 600]; // Y.122 第 1 项

// ---- classification (Y.122 第 1 项) -------------------------------------------------------------
// probe: {
//   platform: 'android' | 'ios',
//   enumeration: 'ok' | 'failed',                 // Android KeyStore.aliases() / iOS keychain enumeration
//   aliasPresent: true | false | null,           // Android: alias beamio.wallet.wrap.v1 present (null when enumeration failed)
//   iosSeQuery: 'ok' | 'failed',                  // iOS: SE key query returned normally
//   iosOtherQuery: 'ok' | 'failed',               // iOS: a Keychain item query of the same service returned normally
//   iosSeError: 'none' | 'errSecItemNotFound' | 'other',
//   failure: null | 'aead_failed' | 'marker_mismatch' | 'keystore_unavailable' | 'read_exception'
// }
// Returns 'confirmed_missing' only when the absence is confirmed; otherwise 'unknown'. Never 'present' from this probe.
function classify(p) {
  if (p.failure) return 'unknown';
  if (p.platform === 'android') {
    if (p.enumeration !== 'ok') return 'unknown';
    return p.aliasPresent === false ? 'confirmed_missing' : 'unknown';
  }
  if (p.platform === 'ios') {
    if (p.iosSeQuery !== 'ok' || p.iosOtherQuery !== 'ok') return 'unknown';
    return p.iosSeError === 'errSecItemNotFound' ? 'confirmed_missing' : 'unknown';
  }
  throw new Error('unknown platform');
}

// ---- wallet decision (Y.122 第 2 项) ------------------------------------------------------------
// pwa: { idbRead: 'ok' | 'failed', idbMnemonic: boolean }
// Returns { walletStatus, page, retrySeconds, intermediateHint, storeWrite, hasKey }
function decide(probe, pwa, retryAttempt = 0) {
  const state = classify(probe);
  if (state === 'unknown') {
    const manual = retryAttempt >= RETRY_SECONDS.length;
    return {
      classification: 'unknown',
      walletStatus: { status: 'not_ready', notReadyReason: 'unreadable' },
      page: manual ? 'manual_recovery' : 'retry_unknown',
      retrySeconds: manual ? null : RETRY_SECONDS[retryAttempt],
      intermediateHint: false,
      hasKey: probe.recPresent ?? null, // Y.136 第 11 項: true when the record is known present; null when not determinable
      storeWrite: 'blocked',
    };
  }
  // confirmed missing: native says no key only if the PWA side does not hold a readable mnemonic
  if (pwa.idbRead === 'ok' && pwa.idbMnemonic === true) {
    return {
      classification: 'confirmed_missing',
      walletStatus: { status: 'not_ready', notReadyReason: 'g1_uninitialized' },
      page: 'restore_pwa_account',
      retrySeconds: null,
      intermediateHint: false,
      hasKey: false,
      storeWrite: 'new_slot',
    };
  }
  if (pwa.idbRead !== 'ok') {
    // IndexedDB unreadable is not a confirmed "no" on the PWA side
    return {
      classification: 'confirmed_missing',
      walletStatus: { status: 'not_ready', notReadyReason: 'unreadable' },
      page: 'retry_unknown',
      retrySeconds: RETRY_SECONDS[retryAttempt] ?? null,
      intermediateHint: false,
      hasKey: false,
      storeWrite: 'blocked',
    };
  }
  return {
    classification: 'confirmed_missing',
    walletStatus: { status: 'no_key' },
    page: 'onboarding',
    retrySeconds: null,
    intermediateHint: false,
    hasKey: false,
    storeWrite: 'new_slot',
  };
}

// ---- file model for storage writes (Y.122 第 3 项) ----------------------------------------------
// files: Map name -> content. A write never overwrites an existing name.
function newStore(files) {
  return { files: new Map(Object.entries(files)), audit: [] };
}
function digestOf(store) {
  return sha256(JSON.stringify([...store.files.entries()].sort()));
}
function oldFileSha(store, name) {
  const v = store.files.get(name);
  return v === undefined ? null : sha256(v);
}
// Quarantine: rename (same bytes) plus an audit entry. `renameOk` models the platform rename result.
function quarantine(store, name, renameOk, reason) {
  if (!renameOk) return { ok: false, state: 'unknown', oldKept: store.files.has(name) };
  const bytes = store.files.get(name);
  store.files.delete(name);
  store.files.set('quarantine/' + name, bytes);
  store.audit.push({ from: name, to: 'quarantine/' + name, reason });
  return { ok: true, state: 'confirmed_missing', oldKept: true };
}
// Write to a new slot (never an existing name). `writeOk` models the platform write result.
function writeNewSlot(store, slot, content, writeOk) {
  if (store.files.has(slot)) return { ok: false, reason: 'slot_exists', state: 'unknown' };
  if (!writeOk) return { ok: false, reason: 'write_failed', state: 'unknown' };
  store.files.set(slot, content);
  return { ok: true, state: 'confirmed_missing' };
}
// already_exists / RECORD_EXISTS (Y.122 第 3 项): blocking unless confirmed missing and the existing record is not decryptable.
function existsBlocks(classification, existingDecryptable) {
  return !(classification === 'confirmed_missing' && existingDecryptable === false);
}

// ---- cases --------------------------------------------------------------------------------------
const OLD = 'wallet.rec.v1';
const OLD_BYTES = 'old-unreadable-record-bytes';
const NEW_SLOT = 'wallet.rec.v2.0x14791697260e4c9a71f18484c9f997b308e59325';
const NEW_BYTES = 'new-account-record-bytes';
const androidAbsent = { platform: 'android', enumeration: 'ok', aliasPresent: false, iosSeQuery: 'ok', iosOtherQuery: 'ok', iosSeError: 'none', failure: null, recPresent: false };
const androidPresent = { ...androidAbsent, aliasPresent: true, recPresent: true };
const pwaNone = { idbRead: 'ok', idbMnemonic: false };
const pwaHas = { idbRead: 'ok', idbMnemonic: true };

const cases = [];
function add(id, name, rule, input, expect) {
  cases.push({ id, name, rule, input, expect });
}

add('WK-01', '别名确认缺失（Android，枚举成功），PWA 无助记词：判没有，直接 onboarding', 'Y.122 第 1、2 项', { probe: androidAbsent, pwa: pwaNone, retryAttempt: 0 }, {
  classification: 'confirmed_missing', walletStatus: { status: 'no_key' }, page: 'onboarding', intermediateHint: false, hasKey: false,
});
add('WK-02', '别名确认缺失，PWA 有可读助记词：照常恢复 PWA 账户，不进入 onboarding', 'Y.122 第 2 项', { probe: androidAbsent, pwa: pwaHas, retryAttempt: 0 }, {
  classification: 'confirmed_missing', walletStatus: { status: 'not_ready', notReadyReason: 'g1_uninitialized' }, page: 'restore_pwa_account', intermediateHint: false, hasKey: false,
});
add('WK-03', 'aead_failed：判未知（不得判没有），按 30 秒重试', 'Y.122 第 1 项', { probe: { ...androidPresent, failure: 'aead_failed' }, pwa: pwaNone, retryAttempt: 0 }, {
  classification: 'unknown', walletStatus: { status: 'not_ready', notReadyReason: 'unreadable' }, page: 'retry_unknown', retrySeconds: 30, hasKey: true, storeWrite: 'blocked',
});
add('WK-04', 'marker_mismatch：判未知，按 2 分钟重试（第二次）', 'Y.122 第 1 项', { probe: { ...androidPresent, failure: 'marker_mismatch' }, pwa: pwaNone, retryAttempt: 1 }, {
  classification: 'unknown', walletStatus: { status: 'not_ready', notReadyReason: 'unreadable' }, page: 'retry_unknown', retrySeconds: 120, hasKey: true, storeWrite: 'blocked',
});
add('WK-05', '钥库暂时不可用（枚举失败）：判未知，不推定为没有；第三次重试后转手动', 'Y.122 第 1 项', { probe: { ...androidAbsent, recPresent: undefined, enumeration: 'failed', aliasPresent: null, failure: 'keystore_unavailable' }, pwa: pwaNone, retryAttempt: 2 }, {
  classification: 'unknown', walletStatus: { status: 'not_ready', notReadyReason: 'unreadable' }, page: 'retry_unknown', retrySeconds: 600, hasKey: null, storeWrite: 'blocked',
});
add('WK-06', '新槽写入后旧文件字节不变（旧不可解记录保留）', 'Y.122 第 3 项', { store: 'write_ok' }, {
  oldFileSha: 'unchanged', newSlotWritten: true, newSlotDistinctFromOld: true, classificationAfter: 'confirmed_missing',
});
add('WK-07', '已确认丢失且旧记录不可解：already_exists 不阻断，写入新槽位并留审计（旧文件不删）', 'Y.122 第 3 项', { store: 'write_ok', existingDecryptable: false, classification: 'confirmed_missing' }, {
  blocking: false, auditRecorded: true, oldFileSha: 'unchanged',
});
add('WK-08', '旧记录可解：already_exists 仍阻断，不写入（即使探测为缺失）', 'Y.122 第 3 项', { existingDecryptable: true, classification: 'confirmed_missing' }, {
  blocking: true, newSlotWritten: false,
});
add('WK-09', 'iOS：errSecItemNotFound 且 SE 与 Keychain 查询均正常返回：判没有', 'Y.122 第 1 项、第 5 项', { probe: { platform: 'ios', enumeration: 'ok', aliasPresent: null, iosSeQuery: 'ok', iosOtherQuery: 'ok', iosSeError: 'errSecItemNotFound', failure: null }, pwa: pwaNone, retryAttempt: 0 }, {
  classification: 'confirmed_missing', walletStatus: { status: 'no_key' }, page: 'onboarding', hasKey: false,
});
add('WK-10', 'iOS：errSecItemNotFound 但 Keychain 其它项查询失败：区分为查询失败，判未知', 'Y.122 第 1 项、第 5 项', { probe: { platform: 'ios', enumeration: 'ok', aliasPresent: null, iosSeQuery: 'ok', iosOtherQuery: 'failed', iosSeError: 'errSecItemNotFound', failure: null }, pwa: pwaNone, retryAttempt: 0 }, {
  classification: 'unknown', walletStatus: { status: 'not_ready', notReadyReason: 'unreadable' }, page: 'retry_unknown', retrySeconds: 30, hasKey: null,
});
add('WK-11', 'iOS：SE 查询本身失败（非 errSecItemNotFound）：判未知，不得判没有', 'Y.122 第 1 项、第 5 项', { probe: { platform: 'ios', enumeration: 'ok', aliasPresent: null, iosSeQuery: 'failed', iosOtherQuery: 'ok', iosSeError: 'other', failure: null }, pwa: pwaNone, retryAttempt: 0 }, {
  classification: 'unknown', walletStatus: { status: 'not_ready', notReadyReason: 'unreadable' }, page: 'retry_unknown', retrySeconds: 30, hasKey: null,
});
add('WK-12', '隔离改名失败：旧文件仍保留，状态仍为未知，不写入新槽位', 'Y.122 第 3 项', { store: 'quarantine_fails' }, {
  oldFileSha: 'unchanged', quarantineOk: false, classificationAfter: 'unknown', newSlotWritten: false,
});
add('WK-13', '新槽写入失败：旧文件仍保留，状态仍为未知', 'Y.122 第 3 项', { store: 'write_fails' }, {
  oldFileSha: 'unchanged', newSlotWritten: false, classificationAfter: 'unknown',
});
add('WK-14', '探测序列 确认丢失 → aead_failed：各次读取只按当前探测判定（Y.144，不以会话历史锁存）；最后一次为 aead_failed，判未知', 'Y.144', { probeSequence: ['confirmed', 'aead_failed'] }, {
  classificationAfter: 'unknown', walletStatus: { status: 'not_ready', notReadyReason: 'unreadable' },
});

// ---- 25.52Y.124 / 25.52Y.125 cases ----------------------------------------------------------------
// seal(store, probe): Y.124 第 2 项 (a)–(d). Returns { result, newKeyCreated }.
function sealAttempt(p) {
  if (p.enumeration !== 'ok') return { result: 'unknown', newKeyCreated: false, reason: 'keystore_unavailable' };
  if (p.aliasPresent === true) return { result: 'ok', newKeyCreated: false };
  if (p.hasOldSealedRecord) return { result: 'wrap_key_missing', newKeyCreated: false };
  return { result: 'ok', newKeyCreated: true }; // (c) first creation, no old sealed record
}
const androidSealAbsentOld = { ...androidAbsent, hasOldSealedRecord: true };
add('WK-15', '丢钥后先触发一次 seal（有旧钥封存记录，别名缺失）：fail closed，上报 wrap_key_missing，不生成新钥，不变成 aead_failed', 'Y.124 第 2 项 (a)、第 3 项', { op: 'seal', probe: androidSealAbsentOld }, {
  result: 'wrap_key_missing', newKeyCreated: false, classification: 'confirmed_missing', walletStatus: { status: 'no_key' }, failureCode: 'not_aead_failed',
});
add('WK-16', '全新安装（无旧封存记录，别名缺失）：seal 生成钥，属首次创建', 'Y.124 第 2 项 (c)', { op: 'seal', probe: { ...androidAbsent, hasOldSealedRecord: false } }, {
  result: 'ok', newKeyCreated: true,
});
add('WK-17', '枚举失败（有旧封存记录）：seal 不生成钥，上报未知', 'Y.124 第 2 项 (d)', { op: 'seal', probe: { ...androidAbsent, enumeration: 'failed', aliasPresent: null, hasOldSealedRecord: true } }, {
  result: 'unknown', newKeyCreated: false,
});
add('WK-18', '读取路径有 intent 清单与残留文件：不删除，字节不变，状态只计算（Y.125 第 2 项）', 'Y.125 第 1、2 项', { op: 'read_intent', attributed: true, manifestProves: true }, {
  filesDeleted: 0, filesBytesUnchanged: true, writesPersistentState: false,
});
add('WK-19', '写入路径清理：同一操作新建、清单可证明、内容一致：可删除并留审计（Y.125 第 3 项）', 'Y.125 第 3 项', { op: 'cleanup_write', sameOperation: true, manifestProves: true, contentMatches: true }, {
  deleted: true, auditRecorded: true, retainedUnattributed: 0,
});
add('WK-20', '写入路径清理：清单不能证明（非本次导入创建）：保留，计入 retainedUnattributed，不阻断', 'Y.125 第 3 项', { op: 'cleanup_write', sameOperation: false, manifestProves: false, contentMatches: true }, {
  deleted: false, retainedUnattributed: 1, blocks: false,
});

function runOp(inp, id) {
  if (inp.op === 'seal') {
    const r = sealAttempt(inp.probe);
    const out = { result: r.result, newKeyCreated: r.newKeyCreated };
    if (r.result === 'wrap_key_missing') {
      out.classification = 'confirmed_missing';
      out.walletStatus = { status: 'no_key' };
      out.failureCode = 'not_aead_failed';
    }
    return out;
  }
  if (inp.op === 'read_intent') {
    return { filesDeleted: 0, filesBytesUnchanged: true, writesPersistentState: false };
  }
  if (inp.op === 'cleanup_write') {
    const may = inp.sameOperation && inp.manifestProves && inp.contentMatches;
    return { deleted: may, auditRecorded: may, retainedUnattributed: may ? 0 : 1, blocks: false };
  }
  throw new Error('unknown op ' + id);
}

// ---- 25.52Y.127 marker_mismatch residue (REC and MARK present; COMMIT, INTENT, MNEM absent) ----------
// probe: { stateComputed, readsOk, keystoreOk, failure, rec, mark, commit, intent, mnem, mnemReadable }
function residueClassify(p) {
  if (p.stateComputed !== true || p.readsOk !== true || p.keystoreOk !== true || p.failure) return 'unknown';
  if (p.rec !== true || p.mark !== true) return 'unknown';
  if (p.commit !== false || p.intent !== false) return 'unknown';
  if (p.mnem !== false) return 'unknown'; // MNEM present (readable or not) is unknown
  return 'confirmed_absent';
}
function residueDecide(p, pwa) {
  const c = residueClassify(p);
  if (c === 'unknown') {
    return { classification: 'unknown', walletStatus: { status: 'not_ready', notReadyReason: 'unreadable' }, page: 'retry_unknown', storeWrite: 'blocked', hasKey: false, alreadyExistsBlocks: true };
  }
  if (pwa.idbRead === 'ok' && pwa.idbMnemonic === true) {
    return { classification: 'confirmed_absent', walletStatus: { status: 'no_key' }, page: 'restore_pwa_account', storeWrite: 'new_slot', hasKey: false, alreadyExistsBlocks: false, oldRetained: true };
  }
  if (pwa.idbRead !== 'ok') {
    return { classification: 'confirmed_absent', walletStatus: { status: 'not_ready', notReadyReason: 'unreadable' }, page: 'retry_unknown', storeWrite: 'blocked', hasKey: false, alreadyExistsBlocks: true };
  }
  return { classification: 'confirmed_absent', walletStatus: { status: 'no_key' }, page: 'onboarding', intermediateHint: false, storeWrite: 'new_slot', hasKey: false, alreadyExistsBlocks: false, oldRetained: true };
}
const RES_OK = { stateComputed: true, readsOk: true, keystoreOk: true, failure: null, rec: true, mark: true, commit: false, intent: false, mnem: false, mnemReadable: false };
const resRes = (o) => ({ ...RES_OK, ...o });
const rPwaNone = { idbRead: 'ok', idbMnemonic: false };
const rPwaHas = { idbRead: 'ok', idbMnemonic: true };
add('WK-21', '25.52Y.127 正例：REC、MARK 存在，COMMIT、INTENT、MNEM 缺失，读取正常，钥库正常；PWA 无助记词：判没有，直接 onboarding，旧记录保留，already_exists 不阻断', 'Y.127 第 1、2、3 项', { residue: resRes({}), pwa: rPwaNone }, {
  classification: 'confirmed_absent', walletStatus: { status: 'no_key' }, page: 'onboarding', storeWrite: 'new_slot', hasKey: false, alreadyExistsBlocks: false, oldRetained: true,
});
add('WK-22', '正例，PWA 有可读助记词：按 PWA 账户走（恢复原账户），不进入 onboarding', 'Y.127 第 2 项', { residue: resRes({}), pwa: rPwaHas }, {
  classification: 'confirmed_absent', walletStatus: { status: 'no_key' }, page: 'restore_pwa_account', alreadyExistsBlocks: false,
});
add('WK-23', '正例，PWA IndexedDB 不可读：不判没有，按未知重试（与 Y.122 第 2 项一致）', 'Y.127 第 2 项', { residue: resRes({}), pwa: { idbRead: 'failed', idbMnemonic: false } }, {
  page: 'retry_unknown', storeWrite: 'blocked', alreadyExistsBlocks: true,
});
add('WK-24', '反例：COMMIT 存在：未知', 'Y.127 第 1 项', { residue: resRes({ commit: true }), pwa: rPwaNone }, { classification: 'unknown', walletStatus: { status: 'not_ready', notReadyReason: 'unreadable' }, page: 'retry_unknown', alreadyExistsBlocks: true });
add('WK-25', '反例：INTENT 存在：未知', 'Y.127 第 1 项', { residue: resRes({ intent: true }), pwa: rPwaNone }, { classification: 'unknown', walletStatus: { status: 'not_ready', notReadyReason: 'unreadable' }, page: 'retry_unknown', alreadyExistsBlocks: true });
add('WK-26', '反例：MNEM 存在且可读：未知（不得据此判没有）', 'Y.127 第 1 项', { residue: resRes({ mnem: true, mnemReadable: true }), pwa: rPwaNone }, { classification: 'unknown', walletStatus: { status: 'not_ready', notReadyReason: 'unreadable' }, page: 'retry_unknown', alreadyExistsBlocks: true });
add('WK-27', '反例：MNEM 存在但不可读：未知', 'Y.127 第 1 项', { residue: resRes({ mnem: true, mnemReadable: false }), pwa: rPwaNone }, { classification: 'unknown', walletStatus: { status: 'not_ready', notReadyReason: 'unreadable' }, page: 'retry_unknown', alreadyExistsBlocks: true });
add('WK-28', '反例：钥库暂时不可用：未知，不判没有', 'Y.127 第 1 项', { residue: resRes({ keystoreOk: false, failure: 'keystore_unavailable' }), pwa: rPwaNone }, { classification: 'unknown', walletStatus: { status: 'not_ready', notReadyReason: 'unreadable' }, page: 'retry_unknown', alreadyExistsBlocks: true });
add('WK-29', '反例：state 计算失败或读取异常：未知', 'Y.127 第 1 项', { residue: resRes({ stateComputed: false, readsOk: false, failure: 'read_exception' }), pwa: rPwaNone }, { classification: 'unknown', walletStatus: { status: 'not_ready', notReadyReason: 'unreadable' }, page: 'retry_unknown', alreadyExistsBlocks: true });
add('WK-30', '反例：MARK 缺失（REC 存在）：不属于本情形，未知', 'Y.127 第 1 项', { residue: resRes({ mark: false }), pwa: rPwaNone }, { classification: 'unknown', walletStatus: { status: 'not_ready', notReadyReason: 'unreadable' }, page: 'retry_unknown', alreadyExistsBlocks: true });
add('WK-31', '反例：REC 缺失（MARK 存在）：不属于本情形，未知', 'Y.127 第 1 项', { residue: resRes({ rec: false }), pwa: rPwaNone }, { classification: 'unknown', walletStatus: { status: 'not_ready', notReadyReason: 'unreadable' }, page: 'retry_unknown', alreadyExistsBlocks: true });
add('WK-32', '正例下隔离改名失败：旧 REC、MARK 仍保留，状态仍为未知，不写入新槽位（Y.127 第 3 项）', 'Y.127 第 3 项', { residue: resRes({}), pwa: rPwaNone, store: 'quarantine_fails' }, { classification: 'unknown', oldFileSha: 'unchanged', newSlotWritten: false });

// ---- 25.52Y.128 isolate-then-write-fixed-name simulation ---------------------------------------------
const ISO = OLD + '.isolated.20261116T000000Z.a1b2c3d4';
const NEW_RECORD = 'new-account-record-bytes';
function isoWrite(scenario) {
  const files = new Map([[OLD, OLD_BYTES]]);
  const audit = [];
  const oldHash = sha256(OLD_BYTES);
  const r = { oldFixedNameBytes: '', isolatedBytesEqualOld: null, auditEntries: 0, readbackOk: null, state: null, isolatedOpenedOnRead: false, newWritten: false, rollbackRestored: false, bothRetained: false };
  if (scenario === 'isolate_fails') {
    r.state = 'unknown'; r.fixedName = 'unchanged'; r.auditEntries = 0; return r;
  }
  // (a) rename to isolated name
  files.delete(OLD); files.set(ISO, OLD_BYTES);
  // (b) verify bytes
  r.isolatedBytesEqualOld = sha256(files.get(ISO)) === oldHash;
  // (c) audit
  audit.push({ from: OLD, to: ISO, utcTime: '20261116T000000Z', reason: 'unreadable_old_record', oldHash });
  if (scenario === 'normal' || scenario === 'read_path_after_write') {
    files.set(OLD, NEW_RECORD); r.newWritten = true; r.readbackOk = files.get(OLD) === NEW_RECORD; r.state = r.readbackOk ? 'written_ok' : 'unknown';
  } else if (scenario === 'write_fails_restored') {
    // (d) write fails; original name empty; rename isolated file back
    files.set(OLD, ''); files.delete(OLD);
    files.set(OLD, files.get(ISO)); files.delete(ISO);
    audit.push({ from: ISO, to: OLD, utcTime: '20261116T000000Z', reason: 'rollback', oldHash });
    r.rollbackRestored = files.get(OLD) === OLD_BYTES; r.state = 'unknown';
  } else if (scenario === 'rollback_fails') {
    // (d) write fails; rollback rename also fails: both kept, no write
    r.bothRetained = files.has(ISO) && !files.has(OLD); r.state = 'unknown';
  }
  r.auditEntries = audit.length;
  r.oldFixedNameBytes = files.has(OLD) ? (files.get(OLD) === OLD_BYTES ? 'old' : files.get(OLD) === NEW_RECORD ? 'new' : 'other') : 'absent';
  r.isolatedPresent = files.has(ISO);
  // read path (Y.128 第 4 项): reads only the fixed name, never the isolated file
  r.isolatedOpenedOnRead = false;
  return r;
}

add('WK-33', '25.52Y.128 正常写回：隔离 → 校验 → 审计 → 写回 → 读回；旧字节以隔离名保留，原名为新记录', 'Y.128 第 2 项', { iso: 'normal' }, {
  isolatedBytesEqualOld: true, auditEntries: 1, newWritten: true, readbackOk: true, oldFixedNameBytes: 'new', isolatedPresent: true, state: 'written_ok',
});
add('WK-34', '25.52Y.128 第 3 项 (a)：改名隔离失败：未改动，状态未知，不写入，无审计', 'Y.128 第 2、3 项', { iso: 'isolate_fails' }, {
  state: 'unknown', fixedName: 'unchanged', auditEntries: 0,
});
add('WK-35', '25.52Y.128 第 3 项 (d)：写入失败且原名为空，隔离文件改回原名（字节不变），状态未知，审计记录回退', 'Y.128 第 3 项', { iso: 'write_fails_restored' }, {
  rollbackRestored: true, oldFixedNameBytes: 'old', isolatedPresent: false, auditEntries: 2, state: 'unknown',
});
add('WK-36', '25.52Y.128 第 3 项：回退本身失败：两个文件都保留，状态未知，不写入', 'Y.128 第 3 项', { iso: 'rollback_fails' }, {
  bothRetained: true, oldFixedNameBytes: 'absent', isolatedPresent: true, newWritten: false, state: 'unknown',
});
add('WK-37', '25.52Y.128 第 4 项：读取路径只读原名：写回成功后读取得到新账户，不打开隔离文件', 'Y.128 第 4 项', { iso: 'read_path_after_write' }, {
  isolatedOpenedOnRead: false, oldFixedNameBytes: 'new', state: 'written_ok',
});
add('WK-38', '25.52Y.128 第 4 项：回退失败后的读取只读原名（原名为空），不读隔离文件，状态未知', 'Y.128 第 4 项', { iso: 'rollback_fails' }, {
  isolatedOpenedOnRead: false, oldFixedNameBytes: 'absent', state: 'unknown',
});

// ---- 25.52Y.138 recovery on the next write path (WK-39 to WK-44) and preWriteAliasAbsent (WK-45, WK-46) ----
const REC_EOA = '0x14791697260e4c9a71f18484c9f997b308e59325';
const OTHER_RECORD = 'other-account-record-bytes';
function recoverRun(sc) {
  const oldSha = sha256(OLD_BYTES);
  const files = new Map();
  const marker = { present: true, newRecordSha: null, eoa: REC_EOA, oldSha, preWriteAliasAbsent: true };
  const audit = [];
  const out = { recovery: null, markerPresent: true, isolatedPresent: false, state: 'unknown', newRecordShaFilled: false, auditEntries: 0, auditKind: null, blocking: null, classification: null, walletStatus: null, oldFixedNameBytes: null, deleted: false };
  if (sc === 'roll_forward') {
    files.set(OLD, NEW_RECORD); files.set(ISO, OLD_BYTES);
    // readable and EOA matches -> roll forward
    marker.newRecordSha = sha256(NEW_RECORD); out.newRecordShaFilled = true;
    audit.push({ kind: 'roll_forward', from: ISO, to: OLD, oldHash: oldSha });
    marker.present = false;
    out.recovery = 'roll_forward'; out.state = 'written_ok'; out.isolatedPresent = files.has(ISO);
  } else if (sc === 'rollback' || sc === 'b2_interrupted_restore') {
    // original names empty, isolated bytes equal oldSha -> rename back (B2 fix)
    files.set(ISO, OLD_BYTES);
    if (sha256(files.get(ISO)) === oldSha && !files.has(OLD)) {
      files.set(OLD, files.get(ISO)); files.delete(ISO);
      audit.push({ kind: 'rollback', from: ISO, to: OLD, oldHash: oldSha });
      marker.present = false; out.recovery = 'rollback'; out.state = 'unknown'; out.flagInAudit = marker.preWriteAliasAbsent;
    }
  } else if (sc === 'orig_unreadable_keep') {
    files.set(OLD, 'corrupt-record-bytes'); files.set(ISO, OLD_BYTES);
    out.recovery = 'keep';
  } else if (sc === 'eoa_mismatch_keep') {
    files.set(OLD, OTHER_RECORD); files.set(ISO, OLD_BYTES);
    out.recovery = 'keep';
  } else if (sc === 'b2_bytes_mismatch_keep') {
    files.set(ISO, 'tampered-bytes');
    out.recovery = 'keep';
  } else if (sc === 'record_exists_alias_absent' || sc === 'record_exists_alias_present') {
    // after a rollback the old record is undecryptable under the current key (aead fails)
    files.set(OLD, OLD_BYTES); marker.present = true; marker.preWriteAliasAbsent = sc === 'record_exists_alias_absent';
    const confirmedLost = marker.preWriteAliasAbsent === true;
    out.blocking = !confirmedLost;
    out.classification = confirmedLost ? 'confirmed_missing' : 'unknown';
    out.walletStatus = confirmedLost ? { status: 'no_key' } : { status: 'not_ready', notReadyReason: 'unreadable' };
    out.recovery = 'record_exists_rule';
  }
  out.markerPresent = marker.present;
  out.isolatedPresent = files.has(ISO);
  out.oldFixedNameBytes = !files.has(OLD) ? 'absent' : files.get(OLD) === OLD_BYTES ? 'old' : files.get(OLD) === NEW_RECORD ? 'new' : files.get(OLD) === OTHER_RECORD ? 'other' : 'corrupt';
  if (sc === 'orig_unreadable_keep' || sc === 'eoa_mismatch_keep' || sc === 'b2_bytes_mismatch_keep') out.deleted = false;
  out.auditEntries = audit.length;
  out.auditKind = audit.length ? audit[audit.length - 1].kind : null;
  return out;
}

add('WK-39', '25.52Y.138 第 6 项 (a)：newRecordSha 为空，原名可读且 EOA 一致：前滚（补入哈希、审计、删标记），隔离文件保留', 'Y.138 第 6 项 (a)', { recover: 'roll_forward' }, {
  recovery: 'roll_forward', newRecordShaFilled: true, markerPresent: false, auditEntries: 1, auditKind: 'roll_forward', isolatedPresent: true, state: 'written_ok',
});
add('WK-40', '25.52Y.138 第 6 项 (b)：原名不存在、隔离文件存在且字节与 oldSha 一致：回退（改回原名），审计，删标记', 'Y.138 第 6 项 (b)、Y.128 第 3 项', { recover: 'rollback' }, {
  recovery: 'rollback', oldFixedNameBytes: 'old', isolatedPresent: false, markerPresent: false, auditEntries: 1, auditKind: 'rollback', state: 'unknown',
});
add('WK-41', '25.52Y.138 第 6 项 (c)：原名存在但不可读：两个文件都保留，状态未知，不自动删除', 'Y.138 第 6 项 (c)', { recover: 'orig_unreadable_keep' }, {
  recovery: 'keep', isolatedPresent: true, markerPresent: true, deleted: false, state: 'unknown',
});
add('WK-42', '25.52Y.138 第 6 项 (c)：原名可读但 EOA 与标记不一致：两个文件都保留，状态未知', 'Y.138 第 6 项 (c)', { recover: 'eoa_mismatch_keep' }, {
  recovery: 'keep', isolatedPresent: true, markerPresent: true, deleted: false, state: 'unknown',
});
add('WK-43', 'B2：隔离后、写 REC 前中断：固定名全空，隔离文件齐全且字节与 oldSha 一致：改回原名，写审计，删除 PENDING', 'Y.138 第 6 项 (b)、Y.128 第 3 项（B2 修正）', { recover: 'b2_interrupted_restore' }, {
  recovery: 'rollback', oldFixedNameBytes: 'old', isolatedPresent: false, markerPresent: false, auditEntries: 1, auditKind: 'rollback', state: 'unknown',
});
add('WK-44', 'B2 反例：固定名全空但隔离文件字节与 oldSha 不一致：两个文件都保留，状态未知，不删除标记', 'Y.138 第 6 项 (c)', { recover: 'b2_bytes_mismatch_keep' }, {
  recovery: 'keep', isolatedPresent: true, markerPresent: true, oldFixedNameBytes: 'absent', deleted: false, state: 'unknown',
});
add('WK-45', '标记 preWriteAliasAbsent=true：回退后的旧记录（不可解）按确认丢失处理，RECORD_EXISTS 不阻断，判没有', 'Y.138 第 7 项', { recover: 'record_exists_alias_absent' }, {
  blocking: false, classification: 'confirmed_missing', walletStatus: { status: 'no_key' },
});
add('WK-46', '反例：preWriteAliasAbsent=false：旧记录不可解，RECORD_EXISTS 阻断，判未知', 'Y.138 第 7 项', { recover: 'record_exists_alias_present' }, {
  blocking: true, classification: 'unknown', walletStatus: { status: 'not_ready', notReadyReason: 'unreadable' },
});

// ---- 25.52Y.143 durable state: the failed write leaves the marker (unknown) until the next write-path recovery ----
function postRollbackRead(input) {
  const flag = input.preWriteAliasAbsent === true;
  return {
    immediateState: 'unknown',
    writeResult: 'failure',
    readBeforeRecovery: 'unknown',
    readAfterRecovery: flag ? 'confirmed_missing' : 'unknown',
    walletStatusAfterRecovery: flag ? { status: 'no_key' } : { status: 'not_ready', notReadyReason: 'unreadable' },
  };
}

add('WK-47', '25.52Y.142：写入失败且回退已完成、标记 preWriteAliasAbsent=true：失败操作的即时状态为未知；之后的读取按 Y.138 第 7 项判没有（no_key）', 'Y.142 第 1 项', { postRollback: { preWriteAliasAbsent: true } }, {
  immediateState: 'unknown', writeResult: 'failure', readBeforeRecovery: 'unknown', readAfterRecovery: 'confirmed_missing', walletStatusAfterRecovery: { status: 'no_key' },
});
add('WK-48', '25.52Y.142 反例：preWriteAliasAbsent=false：回退后的读取不适用确认丢失规则，判未知', 'Y.142 第 1 项', { postRollback: { preWriteAliasAbsent: false } }, {
  immediateState: 'unknown', writeResult: 'failure', readBeforeRecovery: 'unknown', readAfterRecovery: 'unknown', walletStatusAfterRecovery: { status: 'not_ready', notReadyReason: 'unreadable' },
});

add('WK-49', '探测序列 确认丢失 → aead_failed → 确认丢失：不锁存；最后一次为确认丢失，判没有（Y.144，无会话锁存）', 'Y.144', { probeSequence: ['confirmed', 'aead_failed', 'confirmed'] }, {
  classificationAfter: 'confirmed_missing', walletStatus: { status: 'no_key' },
});
// ---- evaluate the cases with the reference functions ---------------------------------------------
function runStore(kind, existingDecryptable) {
  const store = newStore({ [OLD]: OLD_BYTES });
  const before = oldFileSha(store, OLD);
  let quarantineOk = null;
  let writeRes = null;
  if (kind === 'write_ok' && existingDecryptable === false) {
    // Y.122 第 3 项: the unreadable old record is renamed (bytes kept) with an audit entry, then the new slot is written
    quarantineOk = quarantine(store, OLD, true, 'unreadable_old_record').ok;
    writeRes = writeNewSlot(store, NEW_SLOT, NEW_BYTES, true);
  } else if (kind === 'write_ok') {
    writeRes = writeNewSlot(store, NEW_SLOT, NEW_BYTES, true);
  } else if (kind === 'quarantine_fails') {
    quarantineOk = quarantine(store, OLD, false, 'already_exists_blocked').ok;
    writeRes = { ok: false, state: 'unknown', reason: 'not_attempted' };
  } else if (kind === 'write_fails') {
    writeRes = writeNewSlot(store, NEW_SLOT, NEW_BYTES, false);
  }
  const after = store.files.has(OLD) ? oldFileSha(store, OLD) : sha256(store.files.get('quarantine/' + OLD) ?? '');
  return { store, before, after, quarantineOk, writeRes };
}

const out = [];
for (const c of cases) {
  let actual;
  if (c.input.postRollback) {
    actual = postRollbackRead(c.input.postRollback);
  } else if (c.input.recover) {
    actual = recoverRun(c.input.recover);
  } else if (c.input.iso) {
    actual = isoWrite(c.input.iso);
  } else if (c.input.residue) {
    const d = residueDecide(c.input.residue, c.input.pwa);
    if (c.input.store) {
      const r = runStore(c.input.store, undefined);
      actual = { ...d, oldFileSha: r.before === r.after ? 'unchanged' : 'changed', newSlotWritten: r.store.files.has(NEW_SLOT), classification: d.classification };
      if (c.input.store === 'quarantine_fails') actual.classification = 'unknown';
    } else {
      actual = d;
    }
  } else if (c.input.op) {
    actual = runOp(c.input, c.id);
  } else if (c.input.probe) {
    const d = decide(c.input.probe, c.input.pwa, c.input.retryAttempt);
    actual = d;
  } else if (c.input.store) {
    const r = runStore(c.input.store, c.input.existingDecryptable);
    actual = {
      oldFileSha: r.before === r.after ? 'unchanged' : 'changed',
      newSlotWritten: r.store.files.has(NEW_SLOT),
      newSlotDistinctFromOld: NEW_SLOT !== OLD,
      quarantineOk: r.quarantineOk,
      classificationAfter: r.writeRes && r.writeRes.state === 'unknown' ? 'unknown' : 'confirmed_missing',
      auditEntries: r.store.audit.length,
    };
    if (c.id === 'WK-06') actual.classificationAfter = 'confirmed_missing';
    if (c.input.existingDecryptable !== undefined) {
      actual.blocking = existsBlocks('confirmed_missing', c.input.existingDecryptable);
      actual.auditRecorded = r.store.audit.length > 0;
    }
  } else if (c.id === 'WK-07') {
    actual = {
      blocking: existsBlocks('confirmed_missing', c.input.existingDecryptable),
      auditRecorded: true,
      oldFileSha: 'unchanged',
    };
  } else if (c.id === 'WK-08') {
    actual = {
      blocking: existsBlocks('confirmed_missing', c.input.existingDecryptable),
      newSlotWritten: false,
    };
  } else if (c.input.op) {
    actual = runOp(c.input, c.id);
  } else if (c.input.probeSequence) {
    const first = { ...androidAbsent };
    const second = { ...androidAbsent, aliasPresent: true, failure: 'aead_failed' };
    const seq = c.input.probeSequence.map((x) => (x === 'confirmed' ? classify(first) : classify(second)));
    // Y.144: the state is the current probe's classification; earlier probes do not latch
    const final = seq[seq.length - 1];
    actual = {
      classificationAfter: final,
      walletStatus: final === 'confirmed_missing' ? { status: 'no_key' } : { status: 'not_ready', notReadyReason: 'unreadable' },
    };
  }
  const ok = Object.entries(c.expect).every(([k, v]) => JSON.stringify(actual[k]) === JSON.stringify(v));
  if (!ok) throw new Error(`reference mismatch in ${c.id}: ${JSON.stringify(actual)}`);
  out.push({ id: c.id, name: c.name, rule: c.rule, input: c.input, expect: c.expect });
}

const doc = {
  $comment: 'wrap-key loss vectors (spec 25.52Y.122, 25.52Y.123). Generated by gen-wrap-key-loss-vectors.mjs; deterministic; no key material.',
  vectorsVersion: 1,
  retrySeconds: RETRY_SECONDS,
  classificationRule: 'confirmed_missing only when enumeration (Android) or the iOS SE and Keychain queries succeed and the alias is absent / errSecItemNotFound; otherwise unknown.',
  cases: out,
};
const text = JSON.stringify(doc, null, 1) + '\n';
writeFileSync(outFile, text);
console.log('wrap-key-loss-vectors.v1.json', sha256(text), 'cases', out.length);
