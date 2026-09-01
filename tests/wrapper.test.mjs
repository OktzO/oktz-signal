import { QueueJob } from '../src/queue-job.js';
import { ProtocolAddress } from '../src/protocol-address.js';
import { describe, it } from 'node:test';
import assert from 'node:assert';

describe('JS wrapper', () => {
  it('QueueJob serializes', async () => {
    const q = new QueueJob();
    let order = [];
    const fn1 = async () => { await new Promise(r => setTimeout(r, 10)); order.push(1); };
    const fn2 = async () => { order.push(2); };
    q.add('key', fn1); await q.add('key', fn2);
    assert.deepStrictEqual(order, [1, 2]);
  });
  it('ProtocolAddress toString', () => {
    assert.strictEqual(new ProtocolAddress('user', 1).toString(), 'user.1');
  });
  it('ProtocolAddress fromString', () => {
    const addr = ProtocolAddress.fromString('user.1');
    assert.strictEqual(addr.name, 'user');
    assert.strictEqual(addr.deviceId, 1);
  });
  it('crypto encrypt/decrypt roundtrip', async () => {
    const { encrypt, decrypt } = await import('../src/crypto.js');
    const key = Buffer.alloc(32, 0xAB);
    const iv = Buffer.alloc(16, 0xCD);
    const pt = Buffer.from('hello signal');
    const ct = encrypt(key, pt, iv);
    assert.deepStrictEqual(decrypt(key, ct, iv), pt);
  });
  it('crypto deriveSecrets length', async () => {
    const { deriveSecrets } = await import('../src/crypto.js');
    const res = deriveSecrets(Buffer.alloc(32, 1), Buffer.alloc(32, 2), Buffer.from('test'));
    assert.strictEqual(res.length, 3);
    assert.strictEqual(res[0].length, 32);
  });
});