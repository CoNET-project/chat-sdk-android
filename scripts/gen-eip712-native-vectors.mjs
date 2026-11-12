// Generates spec/eip712-native-vectors.v1.json: EIP-712 digests and signatures from ethers v6, for the native
// encoder in chat/src/main/java/network/conet/chat/nativekey/Eip712.kt.
//
// Usage (the ethers package is taken from a local install; nothing is downloaded):
//   ETHERS_JS=/path/to/node_modules/ethers/lib.commonjs/index.js node scripts/gen-eip712-native-vectors.mjs OUT.json
//
// The signing key is the chat test key (synthetic; SHA-256 of "chat-local-test-private-key-v1"). Not a real wallet.
import { createRequire } from 'node:module';
import { writeFileSync } from 'node:fs';

const require = createRequire(import.meta.url);
const ethersPath = process.env.ETHERS_JS;
if (!ethersPath) throw new Error('set ETHERS_JS to the ethers v6 CommonJS entry');
const ethers = require(ethersPath);
const out = process.argv[2];
if (!out) throw new Error('usage: gen-eip712-native-vectors.mjs OUT.json');

const KEY = '0x78c08ce2d2b3fcc5674235d61587b11daebeb0bd4b44a263b827f0ba7743b0bd';
const wallet = new ethers.Wallet(KEY);

const cases = [
  {
    id: 'EIP712-MAIL-SPEC',
    note: 'EIP-712 specification example (known digest 0xbe609aee…57bd2)',
    domain: { name: 'Ether Mail', version: '1', chainId: 1, verifyingContract: '0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC' },
    types: {
      Person: [{ name: 'name', type: 'string' }, { name: 'wallet', type: 'address' }],
      Mail: [{ name: 'from', type: 'Person' }, { name: 'to', type: 'Person' }, { name: 'contents', type: 'string' }],
    },
    primaryType: 'Mail',
    message: {
      from: { name: 'Cow', wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826' },
      to: { name: 'Bob', wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB' },
      contents: 'Hello, Bob!',
    },
  },
  {
    id: 'EIP712-SALT-DYNAMIC',
    note: 'domain with salt and no chainId; string[] and bytes; uint256 from a decimal string',
    domain: { name: 'Beamio Chat', version: '2', salt: '0x' + '11'.repeat(32) },
    types: { Ping: [{ name: 'nonce', type: 'uint256' }, { name: 'tags', type: 'string[]' }, { name: 'blob', type: 'bytes' }] },
    primaryType: 'Ping',
    message: { nonce: '12345678901234567890', tags: ['a', 'bé'], blob: '0xdeadbeef' },
  },
  {
    id: 'EIP712-ARRAYS-FIXED-SIGNED',
    note: 'T[] and T[n], bytesN, bool, empty string, negative int256 given as a decimal string',
    domain: { name: 'Beamio', version: '1', chainId: 8453, verifyingContract: '0x1111111111111111111111111111111111111111' },
    types: {
      Item: [{ name: 'id', type: 'bytes32' }, { name: 'amount', type: 'uint128' }, { name: 'delta', type: 'int256' }],
      Batch: [
        { name: 'items', type: 'Item[]' },
        { name: 'fixed', type: 'Item[2]' },
        { name: 'flag', type: 'bool' },
        { name: 'tag', type: 'bytes4' },
        { name: 'memo', type: 'string' },
      ],
    },
    primaryType: 'Batch',
    message: {
      items: [
        { id: '0x' + '22'.repeat(32), amount: '0', delta: '-5' },
        { id: '0x' + '33'.repeat(32), amount: '7', delta: '9' },
        { id: '0x' + '44'.repeat(32), amount: '1000000', delta: '0' },
      ],
      fixed: [
        { id: '0x' + '55'.repeat(32), amount: '1', delta: '1' },
        { id: '0x' + '66'.repeat(32), amount: '2', delta: '-1' },
      ],
      flag: true,
      tag: '0x12345678',
      memo: '',
    },
  },
  {
    id: 'EIP712-SMALL-INTS-NUMBERS',
    note: 'uint8 and int8 given as JSON numbers at the limits; address value',
    domain: { name: 'N', chainId: 10 },
    types: { Num: [{ name: 'a', type: 'uint8' }, { name: 'b', type: 'int8' }, { name: 'c', type: 'address' }] },
    primaryType: 'Num',
    message: { a: 255, b: -128, c: '0x0000000000000000000000000000000000000001' },
  },
  {
    id: 'EIP712-NESTED-STRUCT-ARRAY',
    note: 'struct array of structs; uint256 given as hex and as decimal',
    domain: { name: 'Nested', version: '1', chainId: 1 },
    types: {
      Leaf: [{ name: 'v', type: 'uint256' }],
      Node: [{ name: 'leaves', type: 'Leaf[]' }, { name: 'label', type: 'string' }],
    },
    primaryType: 'Node',
    message: { leaves: [{ v: '1' }, { v: '0x10' }], label: 'x' },
  },
];

const results = [];
for (const c of cases) {
  const { domain, types, primaryType, message } = c;
  const digest = ethers.TypedDataEncoder.hash(domain, types, message);
  const signature = await wallet.signTypedData(domain, types, message);
  results.push({
    id: c.id,
    note: c.note,
    typedData: { domain, types, primaryType, message },
    expect: { digest, signature, address: wallet.address.toLowerCase() },
  });
}

const doc = {
  file: 'eip712-native-vectors.v1.json',
  purpose: 'Native EIP-712 encoder (nativekey/Eip712.kt) against ethers v6 TypedDataEncoder and signTypedData',
  ethers: ethers.version,
  signingKeyNote: 'synthetic chat test key (SHA-256 of "chat-local-test-private-key-v1"); not a real wallet',
  cases: results,
};
writeFileSync(out, JSON.stringify(doc, null, 2) + '\n', 'utf8');
console.log('wrote', out, 'cases', results.length, 'ethers', ethers.version);
