import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  encrypt, decrypt, calculateMAC, hash, deriveSecrets, verifyMAC,
} from '../src/crypto.js';

// Task 2.9, crypto.js: deriveSecrets silently returned 3 blocks for any
// chunks > 3, verifyMAC required an explicit length and always threw without
// one, and assertBuffer rejected a plain Uint8Array.

const KEY = Buffer.alloc(32, 0xAB);
const IV = Buffer.alloc(16, 0xCD);
const SALT = Buffer.alloc(32, 0x02);
const INPUT = Buffer.alloc(32, 0x01);
const INFO = Buffer.from('test');

test('deriveSecrets rejects a chunk count it cannot produce', () => {
  assert.throws(() => deriveSecrets(INPUT, SALT, INFO, 4), /chunk/i,
    'asking for more blocks than HKDF-Expand produces must fail, not truncate');
  assert.throws(() => deriveSecrets(INPUT, SALT, INFO, 0), /chunk/i);
  assert.throws(() => deriveSecrets(INPUT, SALT, INFO, 1.5), /chunk/i);
});

test('deriveSecrets still produces the requested count within range', () => {
  for (const chunks of [1, 2, 3]) {
    assert.equal(deriveSecrets(INPUT, SALT, INFO, chunks).length, chunks);
  }
});

test('verifyMAC works without an explicit length', () => {
  const data = Buffer.from('payload');
  const mac = calculateMAC(KEY, data);
  assert.equal(mac.length, 32);
  assert.doesNotThrow(() => verifyMAC(data, KEY, mac));
  assert.throws(() => verifyMAC(Buffer.from('other'), KEY, mac), /Bad MAC/);
});

test('verifyMAC still rejects a truncated mac when no length is given', () => {
  const data = Buffer.from('payload');
  const mac = calculateMAC(KEY, data).subarray(0, 8);
  assert.throws(() => verifyMAC(data, KEY, mac), /Bad MAC length/,
    'omitting length must not turn into accepting a short mac');
});

test('crypto primitives accept a plain Uint8Array', () => {
  const pt = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
  const key = new Uint8Array(KEY);
  const iv = new Uint8Array(IV);
  const ct = encrypt(key, pt, iv);
  assert.ok(Buffer.isBuffer(ct), 'output must still be a Buffer');
  assert.deepEqual(decrypt(new Uint8Array(KEY), ct, new Uint8Array(IV)), Buffer.from(pt));
  assert.ok(Buffer.isBuffer(calculateMAC(new Uint8Array(KEY), new Uint8Array(pt))));
  assert.ok(Buffer.isBuffer(hash(new Uint8Array(pt))));
});

test('crypto primitives still reject a non-binary input', () => {
  assert.throws(() => calculateMAC('not-a-key', Buffer.alloc(4)), TypeError);
  assert.throws(() => calculateMAC(KEY, 42), TypeError);
});
