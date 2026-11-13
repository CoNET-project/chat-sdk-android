// Generates spec/pgp-native-vectors.v1.json: OpenPGP keys, encrypted messages and detached signatures from openpgp.js
// (the same library version the app ships), for the native PGP code in chat/src/main/java/.../nativekey/NativePgp.kt.
//
// Usage (openpgp is taken from a local install; nothing is downloaded):
//   OPENPGP_JS=/path/to/node_modules/openpgp/dist/node/openpgp.min.cjs node scripts/gen-pgp-native-vectors.mjs OUT.json
//
// All keys and messages are synthetic test material. None is a real account key.
import { createRequire } from 'node:module';
import { writeFileSync } from 'node:fs';

const require = createRequire(import.meta.url);
const openpgpPath = process.env.OPENPGP_JS;
if (!openpgpPath) throw new Error('set OPENPGP_JS to the openpgp v6 node CommonJS entry');
const out = process.argv[2];
if (!out) throw new Error('usage: gen-pgp-native-vectors.mjs OUT.json');
const openpgp = require(openpgpPath);

const PASS_ECC = 'synthetic-pass-ecc-1';
const PASS_RSA = 'synthetic-pass-rsa-2';
const PURPOSE = 'syntheticvector';

const userIDs = (n) => [{ name: `synthetic ${n}`, email: `${n}@example.invalid` }];

async function makeKey(id, options) {
  const { privateKey, publicKey } = await openpgp.generateKey({ ...options, userIDs: userIDs(id), format: 'armored' });
  const pub = await openpgp.readKey({ armoredKey: publicKey });
  const priv = await openpgp.readPrivateKey({ armoredKey: privateKey });
  return { id, privateArmored: privateKey, publicArmored: publicKey, fingerprint: priv.getFingerprint(), pubObj: pub, privObj: priv };
}

async function unlock(priv, passphrase) {
  return priv.isDecrypted() ? priv : openpgp.decryptKey({ privateKey: priv, passphrase });
}

const eccPass = await makeKey('ecc-pass', { type: 'ecc', curve: 'curve25519', passphrase: PASS_ECC });
const eccNoPass = await makeKey('ecc-nopass', { type: 'ecc', curve: 'curve25519' });
const rsaPass = await makeKey('rsa-pass', { type: 'rsa', rsaBits: 2048, passphrase: PASS_RSA });

const keys = {};
for (const k of [eccPass, eccNoPass, rsaPass]) {
  keys[k.id] = {
    privateArmored: k.privateArmored,
    publicArmored: k.publicArmored,
    fingerprint: k.fingerprint,
    passphrase: k.id === 'ecc-pass' ? PASS_ECC : k.id === 'rsa-pass' ? PASS_RSA : '',
  };
}

const plain = 'hello 世界 ✓ {"k":"v","n":1}';
const encrypt = async (text, to, extra = {}) =>
  openpgp.encrypt({ message: await openpgp.createMessage({ text }), encryptionKeys: to, format: 'armored', ...extra });

const armorEccPass = await encrypt(plain, eccPass.pubObj);
const armorEccNoPass = await encrypt('no passphrase key', eccNoPass.pubObj);
const armorRsaPass = await encrypt('rsa key message', rsaPass.pubObj);
const armorZlib = await openpgp.encrypt({
  message: await openpgp.createMessage({ text: 'compressed '.repeat(40) }),
  encryptionKeys: eccPass.pubObj,
  format: 'armored',
  config: { preferredCompressionAlgorithm: openpgp.enums.compression.zlib },
});
const signerNoPass = await unlock(eccNoPass.privObj, undefined);
const armorSigned = await openpgp.encrypt({
  message: await openpgp.createMessage({ text: 'signed by another key' }),
  encryptionKeys: eccPass.pubObj,
  signingKeys: signerNoPass,
  format: 'armored',
});
const armorToNoPass = await encrypt('for the other key', eccNoPass.pubObj);

// A message with one character changed in the middle of its base64 body: integrity must fail or decoding must fail.
const corrupt = (() => {
  const lines = armorEccPass.split('\n');
  const body = lines.findIndex((l) => l.length > 40 && !l.startsWith('-----') && !l.includes(':'));
  const row = lines[body];
  const mid = Math.floor(row.length / 2);
  lines[body] = row.slice(0, mid) + (row[mid] === 'A' ? 'B' : 'A') + row.slice(mid + 1);
  return lines.join('\n');
})();

const decrypt = [
  { id: 'D-1', key: 'ecc-pass', passphrase: PASS_ECC, armor: armorEccPass, expect: { code: 'ok', text: plain } },
  { id: 'D-2', key: 'ecc-nopass', passphrase: '', armor: armorEccNoPass, expect: { code: 'ok', text: 'no passphrase key' } },
  { id: 'D-3', key: 'rsa-pass', passphrase: PASS_RSA, armor: armorRsaPass, expect: { code: 'ok', text: 'rsa key message' } },
  { id: 'D-4', key: 'ecc-pass', passphrase: PASS_ECC, armor: armorZlib, expect: { code: 'ok', text: 'compressed '.repeat(40) } },
  { id: 'D-5', key: 'ecc-pass', passphrase: PASS_ECC, armor: armorSigned, expect: { code: 'ok', text: 'signed by another key' } },
  { id: 'D-6', key: 'ecc-pass', passphrase: 'not-the-passphrase', armor: armorEccPass, expect: { code: 'bad_passphrase' } },
  { id: 'D-7', key: 'ecc-pass', passphrase: PASS_ECC, armor: armorToNoPass, expect: { code: 'not_recipient' } },
  { id: 'D-8', key: 'ecc-pass', passphrase: PASS_ECC, armor: corrupt, expect: { codeIn: ['integrity_failed', 'decrypt_failed', 'bad_message'] } },
  { id: 'D-9', key: 'ecc-pass', passphrase: PASS_ECC, armor: 'not a pgp message at all', expect: { code: 'bad_message' } },
];

// Detached document signatures (binary) over label || message, as C4 builds them. Verified with the native code.
const label = `beamio.pgp.${PURPOSE}.v1\n`;
const sigMessage = 'document to sign';
const armoredSig = await openpgp.sign({
  message: await openpgp.createMessage({ binary: new TextEncoder().encode(label + sigMessage) }),
  signingKeys: await unlock(eccPass.privObj, PASS_ECC),
  detached: true,
  format: 'armored',
});
const signatures = [
  { id: 'S-1', key: 'ecc-pass', purpose: PURPOSE, message: sigMessage, armoredSignature: armoredSig, expect: { verify: true } },
  { id: 'S-2', key: 'ecc-pass', purpose: PURPOSE, message: 'a different document', armoredSignature: armoredSig, expect: { verify: false } },
  { id: 'S-3', key: 'ecc-pass', purpose: 'otherpurpose', message: sigMessage, armoredSignature: armoredSig, expect: { verify: false } },
];

const doc = {
  file: 'pgp-native-vectors.v1.json',
  purpose: 'Native OpenPGP (nativekey/NativePgp.kt) against openpgp.js 6.3.0: decryption and document signatures',
  openpgp: openpgp.config && openpgp.config.versions ? openpgp.config.versions.openpgp : 'v6',
  note: 'Synthetic keys and messages only. Not real account keys; not for production.',
  purposeLabelRule: 'beamio.pgp.<purposeId>.v1\\n followed by the message bytes',
  keys,
  decrypt,
  signatures,
};
writeFileSync(out, JSON.stringify(doc, null, 2) + '\n', 'utf8');
console.log('wrote', out, 'keys', Object.keys(keys).length, 'decrypt', decrypt.length, 'signatures', signatures.length);
