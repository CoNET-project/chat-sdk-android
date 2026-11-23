// Generator for chat/src/test/resources/vectors/VECTORS-mnemonic-eoa-random1000.json.
// TEST DATA ONLY: public seed, generated phrases are never funded, never on chain, and not tied to any account.
//
// Entropy: SHA-256("beamio-vec-seed-2026-11-18|" + i), truncated to 16/20/24/28/32 bytes; size index = i mod 5 gives 12/15/18/21/24 words.
// Phrases: ethers 6.16.0 Mnemonic.fromEntropy (English list, BIP-39 checksum).
// Expected EOA: ethers 6.16.0 Wallet.fromPhrase(phrase).address, lower-case, m/44'/60'/0'/0/0.
//
// Usage (ethers 6.16.0 must resolve from NODE_PATH or a local node_modules):
//   node gen-random-mnemonic-vectors.cjs [output.json]
// With no argument the JSON goes to stdout. The file contains no absolute paths.
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { ethers } = require('ethers');

const SEED = 'beamio-vec-seed-2026-11-18';
const SIZES = [16, 20, 24, 28, 32];
const WORDS = [12, 15, 18, 21, 24];
const REPO_PATH = 'chat/tools/test-vectors/gen-random-mnemonic-vectors.cjs';

const cases = [];
for (let i = 0; i < 1000; i++) {
  const k = i % 5;
  const entropy = crypto.createHash('sha256').update(SEED + '|' + i).digest().subarray(0, SIZES[k]);
  const phrase = ethers.Mnemonic.fromEntropy(entropy).phrase;
  const eoa = ethers.Wallet.fromPhrase(phrase).address.toLowerCase();
  if (phrase.split(' ').length !== WORDS[k]) throw new Error('word count mismatch at ' + i);
  cases.push({
    id: 'rnd-' + String(i).padStart(4, '0'),
    input: phrase,
    word_count: WORDS[k],
    sdk_accept: true,
    sdk_canonical: phrase,
    pwa_sync_emits: true,
    expect_behaviour: 'accept',
    expected_canonical: phrase,
    expected_eoa: eoa,
  });
}

const scriptSha = crypto.createHash('sha256').update(fs.readFileSync(path.resolve(__filename))).digest('hex');
const doc = {
  header: {
    purpose: 'TEST ONLY. Public-entropy generated phrases for cross-implementation checks of mnemonic-to-EOA derivation. Not an account, never funded, never on chain.',
    seed: SEED,
    entropy_rule: 'SHA-256(seed + "|" + i) truncated to 16/20/24/28/32 bytes; size index = i mod 5 gives 12/15/18/21/24 words (200 each)',
    derivation: "ethers 6.16.0 Mnemonic.fromEntropy; EOA = ethers.Wallet.fromPhrase(phrase).address lower-case, m/44'/60'/0'/0/0",
    generator: 'gen-random-mnemonic-vectors.cjs',
    generator_path: REPO_PATH,
    generator_sha256: scriptSha,
    columns: 'as VECTORS-mnemonic-eoa-crossimpl.json (sdk_canonical, sdk_accept, pwa_sync_emits = PHRASE_RE on trim)',
    count: cases.length,
    version: 'random1000-v1',
  },
  cases,
};
const text = JSON.stringify(doc, null, 2) + '\n';
const out = process.argv[2];
if (out) fs.writeFileSync(out, text); else process.stdout.write(text);
