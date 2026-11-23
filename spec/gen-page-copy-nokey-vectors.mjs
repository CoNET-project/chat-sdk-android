// gen-page-copy-nokey-vectors.mjs (spec 25.52Y.151, 25.52Y.153). Pure and deterministic. No keys, no clock.
// Usage: node gen-page-copy-nokey-vectors.mjs <outFile>
import { createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';
const outFile = process.argv[2];
if (!outFile) throw new Error('usage: node gen-page-copy-nokey-vectors.mjs <outFile>');
const sha256 = (s) => createHash('sha256').update(s).digest('hex');
const W_FIELDS = ['privateKeyArmor', 'mnemonicPhrase', 'recoveryWords'];

// walletEoaAddress: native answer -> PWA mapping (Y.151 第 1、3、4 项)
function walletEoaMapping(inp) {
  if (inp.native !== 'no_key') return { mapping: 'address_reported', pageAction: 'use_native_address' };
  const confirmedNone = inp.walletStatus === 'no_key' && inp.kPresent === false && inp.pageCopyPresent === false;
  if (confirmedNone) return { mapping: 'none', pageAction: 'onboarding' };
  if (inp.kPresent === undefined || inp.kPresent === null) return { mapping: 'needs_native_recovery', pageAction: 'retry_unknown' };
  if (inp.pageCopyPresent === true) return { mapping: 'needs_native_recovery', pageAction: 'native_recovery_entry_only', newAccountDisabled: true, autoRetry: false };
  return { mapping: 'needs_native_recovery', pageAction: 'native_recovery_entry_only', newAccountDisabled: true, autoRetry: false };
}

// shellRecordRead: G0 redacts W fields when a page copy exists (Y.151 第 2 项); other states unchanged (Y.41)
function shellRecordReadResult(inp) {
  // 25.52AD.2 / 25.52AD.4: under G1 shellRecord answers not_ready and returns no fields
  if (inp.walletState === 'G1') return { code: 'not_ready', fieldsReturned: [], redacted: [] };
  // 25.52U.4: schemaVersion 2 record whose matching profile lacks privateKeyArmor -> error needs_native_recovery
  if (inp.schemaVersion === 2 && !inp.copyFields.includes('privateKeyArmor')) return { code: 'error', sub: 'needs_native_recovery', fieldsReturned: [], redacted: [] };
  const fields = inp.copyFields.slice();
  const out = { code: 'ok', fieldsReturned: fields.slice(), redacted: [] };
  if (inp.walletState === 'G0') {
    out.fieldsReturned = fields.filter((f) => !W_FIELDS.includes(f));
    out.redacted = fields.filter((f) => W_FIELDS.includes(f));
  }
  return out;
}

const CASES = [];
function add(id, title, rule, input, expect) { CASES.push({ id, title, rule, input, expect }); }

// walletEoaAddress
add('PNK-01', 'walletEoaAddress no_key，walletStatus no_key，kPresent false，无页面副本：确认无，映射 none，进入 onboarding', 'Y.151 第 2、3 项', { native: 'no_key', walletStatus: 'no_key', kPresent: false, pageCopyPresent: false }, { mapping: 'none', pageAction: 'onboarding' });
add('PNK-02', 'walletEoaAddress no_key，有页面副本：不映射 none，仅显示原生恢复入口，隐藏新建，不自动重试', 'Y.151 第 1、3、4 项', { native: 'no_key', walletStatus: 'no_key', kPresent: false, pageCopyPresent: true }, { mapping: 'needs_native_recovery', pageAction: 'native_recovery_entry_only', newAccountDisabled: true, autoRetry: false });
add('PNK-03', 'walletEoaAddress no_key，kPresent 缺失：不可判无，须恢复（不得 none）', 'Y.151 第 2 项、Y.90', { native: 'no_key', walletStatus: 'no_key', kPresent: null, pageCopyPresent: false }, { mapping: 'needs_native_recovery', pageAction: 'retry_unknown' });
add('PNK-04', 'walletEoaAddress no_key，kPresent 为真：不可判无', 'Y.151 第 2 项', { native: 'no_key', walletStatus: 'no_key', kPresent: true, pageCopyPresent: false }, { mapping: 'needs_native_recovery', pageAction: 'native_recovery_entry_only', newAccountDisabled: true, autoRetry: false });
add('PNK-05', 'walletEoaAddress 返回地址（原生持钥）：照常使用原生地址', 'Y.151 第 3 项', { native: 'address', walletStatus: 'unlocked', kPresent: true, pageCopyPresent: true }, { mapping: 'address_reported', pageAction: 'use_native_address' });
// shellRecordRead G0 redact
add('PNK-06', 'shellRecordRead，原生 G0，页面副本含 W 字段：剥离 privateKeyArmor、mnemonicPhrase、recoveryWords，其余字段返回', 'Y.151 第 2 项、Y.150 第 1 项', { walletState: 'G0', schemaVersion: 2, copyFields: ['privateKeyArmor', 'mnemonicPhrase', 'recoveryWords', 'keyID', 'workspace'] }, { code: 'ok', fieldsReturned: ['keyID', 'workspace'], redacted: ['privateKeyArmor', 'mnemonicPhrase', 'recoveryWords'] });
add('PNK-07', 'shellRecordRead，原生 G0，schema2 副本无 privateKeyArmor：答 error，sub needs_native_recovery，不返回字段（25.52U.4；不是 ok）', 'Y.151 第 2 项、§25.52U.4', { walletState: 'G0', schemaVersion: 2, copyFields: ['keyID', 'workspace'] }, { code: 'error', sub: 'needs_native_recovery', fieldsReturned: [], redacted: [] });
add('PNK-10', 'shellRecordRead，原生 G0，非 schema2（旧格式）副本只含非 W 字段：不触发 U.4，正常返回字段', 'Y.151 第 2 项、§25.52U.4（schema2 限定）', { walletState: 'G0', schemaVersion: 1, copyFields: ['keyID', 'workspace'] }, { code: 'ok', fieldsReturned: ['keyID', 'workspace'], redacted: [] });
add('PNK-08', 'shellRecordRead，原生 G2（持钥）：W 字段按 Y.41 不剥离', 'Y.41 第 4 项（不变）', { walletState: 'G2', schemaVersion: 2, copyFields: ['privateKeyArmor', 'mnemonicPhrase', 'keyID'] }, { code: 'ok', fieldsReturned: ['privateKeyArmor', 'mnemonicPhrase', 'keyID'], redacted: [] });
add('PNK-09', 'shellRecordRead，原生 G1（有记录未 init）：答 not_ready，不返回任何字段（W 字段不泄露）', 'Y.151 第 2 项、§25.52AD.2（G1 下 shellRecord 仍返回 not_ready）', { walletState: 'G1', schemaVersion: 2, copyFields: ['privateKeyArmor'] }, { code: 'not_ready', fieldsReturned: [], redacted: [] });

const CASES_OUT = CASES.map((c) => {
  const actual = c.input.copyFields !== undefined && c.input.walletState ? shellRecordReadResult(c.input) : walletEoaMapping(c.input);
  for (const [k, v] of Object.entries(c.expect)) {
    if (JSON.stringify(actual[k]) !== JSON.stringify(v)) throw new Error(`reference mismatch in ${c.id} field ${k}: ${JSON.stringify(actual[k])}`);
  }
  return { id: c.id, title: c.title, rule: c.rule, input: c.input, expect: c.expect };
});
const doc = {
  file: 'page-copy-nokey-vectors.v1.json',
  spec: '25.52Y.151（第 1 至 6 项），25.52Y.153（批准记录）',
  generator: 'gen-page-copy-nokey-vectors.mjs',
  note: 'Synthetic. No keys. walletEoaAddress mapping and shellRecordRead G0 redaction. Shared by Android, iOS and PWA.',
  cases: CASES_OUT,
};
const text = JSON.stringify(doc, null, 1) + '\n';
writeFileSync(outFile, text);
console.log('page-copy-nokey-vectors.v1.json', sha256(text), 'cases', CASES_OUT.length);
