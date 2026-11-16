// Generates spec/pgp-native-vectors.v1.json: OpenPGP keys, encrypted messages and detached signatures from openpgp.js
// (the same library version the app ships), for the native PGP code in chat/src/main/java/.../nativekey/NativePgp.kt.
//
// Usage (openpgp is taken from a local install; nothing is downloaded):
//   OPENPGP_JS=/path/to/node_modules/openpgp/dist/node/openpgp.min.cjs node scripts/gen-pgp-native-vectors.mjs OUT.json
//
// Deterministic: every random byte comes from one fixed seed (SEED), the RSA key generator and the RSA PKCS#1 v1.5
// encryption are replaced by seeded equivalents before openpgp is loaded, and every creation date is fixed (DATE). The
// same command with the same openpgp build writes the same bytes, so the output sha256 is reproducible.
//
// All keys and messages are synthetic test material. None is a real account key: user IDs are synthetic names on
// example.invalid addresses, and the passphrases are fixed test strings.
import crypto, { webcrypto } from 'node:crypto';
import { createRequire } from 'node:module';
import { writeFileSync } from 'node:fs';

const require = createRequire(import.meta.url);
const openpgpPath = process.env.OPENPGP_JS;
if (!openpgpPath) throw new Error('set OPENPGP_JS to the openpgp v6 node CommonJS entry');
const out = process.argv[2];
if (!out) throw new Error('usage: gen-pgp-native-vectors.mjs OUT.json');

const SEED = 'beamio.gen-pgp-native-vectors.v1|synthetic test material only';
const DATE = new Date('2026-11-16T00:00:00Z');

// ---- seeded randomness ------------------------------------------------------------------------------------------
// HMAC-SHA256 counter stream keyed by SHA-256(SEED). It feeds every consumer of randomness in this process.
const drbgKey = crypto.createHash('sha256').update(SEED).digest();
let drbgCounter = 0;
let drbgBlock = Buffer.alloc(0);
let drbgPos = 0;
function drbg(n) {
  const outBuf = Buffer.alloc(n);
  let off = 0;
  while (off < n) {
    if (drbgPos >= drbgBlock.length) {
      drbgBlock = crypto.createHmac('sha256', drbgKey).update(`block|${drbgCounter++}`).digest();
      drbgPos = 0;
    }
    const take = Math.min(n - off, drbgBlock.length - drbgPos);
    drbgBlock.copy(outBuf, off, drbgPos, drbgPos + take);
    off += take;
    drbgPos += take;
  }
  return outBuf;
}

// Every entry point that openpgp can reach for randomness reads the seeded stream.
const fillSeeded = (array) => {
  Buffer.from(array.buffer, array.byteOffset, array.byteLength).set(drbg(array.byteLength));
  return array;
};
crypto.randomBytes = (size, callback) => {
  const bytes = drbg(size);
  if (typeof callback === 'function') {
    process.nextTick(callback, null, bytes);
    return undefined;
  }
  return bytes;
};
crypto.randomFillSync = (array) => fillSeeded(array);
crypto.randomFill = (array, callback) => {
  fillSeeded(array);
  process.nextTick(callback, null, array);
};
webcrypto.getRandomValues = (array) => fillSeeded(array);
// WebCrypto key generation for Ed25519, X25519, ECDSA and ECDH draws from OpenSSL's own RNG. Rejecting it with
// OperationError makes openpgp take its JavaScript key path, which draws from the seeded stream above. RSA key pairs
// come from the seeded generator below and are handed back as JWK, which is what openpgp reads from WebCrypto.
const SEEDED_JWK = Symbol('seeded-jwk');
const subtleSeeded = new Proxy(webcrypto.subtle, {
  get(target, prop) {
    if (prop === 'generateKey') {
      return async (algorithm) => {
        if (algorithm && algorithm.name === 'RSASSA-PKCS1-v1_5') {
          const exponent = BigInt('0x' + Buffer.from(algorithm.publicExponent).toString('hex'));
          const { pub, priv } = seededRsaKeyPair(Number(algorithm.modulusLength), exponent);
          return { publicKey: { [SEEDED_JWK]: pub }, privateKey: { [SEEDED_JWK]: priv } };
        }
        const error = new Error('seeded generator: WebCrypto key generation is disabled for this algorithm');
        error.name = 'OperationError';
        throw error;
      };
    }
    if (prop === 'exportKey') {
      return async (format, key) => {
        if (key && key[SEEDED_JWK] && format === 'jwk') return key[SEEDED_JWK];
        return target.exportKey(format, key);
      };
    }
    const value = Reflect.get(target, prop);
    return typeof value === 'function' ? value.bind(target) : value;
  },
});
Object.defineProperty(globalThis, 'crypto', {
  configurable: true,
  writable: true,
  value: { getRandomValues: fillSeeded, subtle: subtleSeeded },
});

// ---- seeded RSA (node's RSA generator and PKCS#1 v1.5 padding draw from OpenSSL's own RNG) ----------------------
const big = (buf) => BigInt('0x' + (buf.toString('hex') || '0'));
const b64u = (v) => {
  let h = v.toString(16);
  if (h.length % 2) h = '0' + h;
  return Buffer.from(h, 'hex').toString('base64url');
};
function modPow(base, exp, mod) {
  let result = 1n;
  let b = base % mod;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % mod;
    b = (b * b) % mod;
    e >>= 1n;
  }
  return result;
}
function gcd(a, b) {
  let x = a;
  let y = b;
  while (y) [x, y] = [y, x % y];
  return x;
}
function modInverse(a, m) {
  let [oldR, r] = [a % m, m];
  let [oldS, s] = [1n, 0n];
  while (r) {
    const q = oldR / r;
    [oldR, r] = [r, oldR - q * r];
    [oldS, s] = [s, oldS - q * s];
  }
  if (oldR !== 1n) throw new Error('no modular inverse');
  return ((oldS % m) + m) % m;
}
const MR_BASES = [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n, 41n, 43n, 47n, 53n];
function isProbablePrime(n) {
  if (n < 2n) return false;
  for (const p of MR_BASES) {
    if (n === p) return true;
    if (n % p === 0n) return false;
  }
  let d = n - 1n;
  let s = 0;
  while ((d & 1n) === 0n) {
    d >>= 1n;
    s++;
  }
  witness: for (const a of MR_BASES) {
    let x = modPow(a, d, n);
    if (x === 1n || x === n - 1n) continue;
    for (let i = 1; i < s; i++) {
      x = (x * x) % n;
      if (x === n - 1n) continue witness;
    }
    return false;
  }
  return true;
}
function seededPrime(bits, e) {
  // Top two bits set: p and q each have `bits` bits, so n has the full modulus length.
  let c = big(drbg(bits / 8)) | (3n << BigInt(bits - 2)) | 1n;
  for (;;) {
    if (isProbablePrime(c) && gcd(c - 1n, e) === 1n) return c;
    c += 2n;
  }
}
function seededRsaKeyPair(modulusBits, e) {
  const p = seededPrime(modulusBits / 2, e);
  let q = seededPrime(modulusBits / 2, e);
  while (q === p) q = seededPrime(modulusBits / 2, e);
  const n = p * q;
  const phi = (p - 1n) * (q - 1n);
  const d = modInverse(e, phi);
  const pub = { kty: 'RSA', n: b64u(n), e: b64u(e) };
  const priv = {
    ...pub,
    d: b64u(d),
    p: b64u(p),
    q: b64u(q),
    dp: b64u(d % (p - 1n)),
    dq: b64u(d % (q - 1n)),
    qi: b64u(modInverse(q, p)),
  };
  return { pub, priv };
}
crypto.generateKeyPair = (type, options, callback) => {
  if (type !== 'rsa') throw new Error('seeded generator: only rsa key pairs are replaced');
  const { pub, priv } = seededRsaKeyPair(Number(options.modulusLength), BigInt(options.publicExponent ?? 65537));
  process.nextTick(callback, null, pub, priv);
};
const originalPublicEncrypt = crypto.publicEncrypt;
crypto.publicEncrypt = (options, buffer) => {
  if (!options || options.format !== 'jwk' || options.padding !== crypto.constants.RSA_PKCS1_PADDING) {
    return originalPublicEncrypt(options, buffer);
  }
  const nBytes = Buffer.from(options.key.n, 'base64url');
  const n = big(nBytes);
  const e = big(Buffer.from(options.key.e, 'base64url'));
  const k = nBytes.length;
  const m = Buffer.from(buffer);
  if (m.length > k - 11) throw new Error('message too long for the modulus');
  const ps = Buffer.alloc(k - m.length - 3);
  for (let i = 0; i < ps.length; ) {
    for (const byte of drbg(ps.length - i + 8)) {
      if (byte !== 0 && i < ps.length) ps[i++] = byte;
    }
  }
  const em = Buffer.concat([Buffer.from([0x00, 0x02]), ps, Buffer.from([0x00]), m]);
  return Buffer.from(modPow(big(em), e, n).toString(16).padStart(k * 2, '0'), 'hex');
};

// ---- openpgp (loaded after the patches above) ---------------------------------------------------------------------
const openpgp = require(openpgpPath);

const PASS_ECC = 'synthetic-pass-ecc-1';
const PASS_RSA = 'synthetic-pass-rsa-2';
const PURPOSE = 'syntheticvector';

const userIDs = (n) => [{ name: `synthetic ${n}`, email: `${n}@example.invalid` }];

async function makeKey(id, options) {
  const { privateKey, publicKey } = await openpgp.generateKey({
    ...options,
    userIDs: userIDs(id),
    format: 'armored',
    date: DATE,
  });
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
const message = (text) => openpgp.createMessage({ text, date: DATE });
const encrypt = async (text, to, extra = {}) =>
  openpgp.encrypt({ message: await message(text), encryptionKeys: to, format: 'armored', date: DATE, ...extra });
const armorEccPass = await encrypt(plain, eccPass.pubObj);
const armorEccNoPass = await encrypt('no passphrase key', eccNoPass.pubObj);
const armorRsaPass = await encrypt('rsa key message', rsaPass.pubObj);
const armorZlib = await openpgp.encrypt({
  message: await message('compressed '.repeat(40)),
  encryptionKeys: eccPass.pubObj,
  format: 'armored',
  date: DATE,
  config: { preferredCompressionAlgorithm: openpgp.enums.compression.zlib },
});
const signerNoPass = await unlock(eccNoPass.privObj, undefined);
const armorSigned = await openpgp.encrypt({
  message: await message('signed by another key'),
  encryptionKeys: eccPass.pubObj,
  signingKeys: signerNoPass,
  format: 'armored',
  date: DATE,
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
  message: await openpgp.createMessage({ binary: new TextEncoder().encode(label + sigMessage), date: DATE }),
  signingKeys: await unlock(eccPass.privObj, PASS_ECC),
  detached: true,
  format: 'armored',
  date: DATE,
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
