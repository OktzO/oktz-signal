// D1: the shared queue must not deadlock when a storage callback re-enters.
//
// src/queue-job.js chains each job onto the previous promise for the same key.
// A callback that runs INSIDE a job and re-enters the same key therefore waits
// on the promise the running job is itself waiting on, and the pair never
// settles. Since 116e095 the SessionCipher and the SessionBuilder share one
// QueueJob per (storage, addr), so a storage whose storeSession re-enters either
// class for the same address hangs the process permanently — a hung promise
// with no error, no timeout and no log line.
import crypto from 'node:crypto';
import { createRequire } from 'module';
import { describe, it } from 'node:test';
import assert from 'node:assert';
const require = createRequire(import.meta.url);
const native = require('../native/signal/index.cjs');
import { SessionBuilder, SessionCipher, ProtocolAddress } from '../index.js';
import { QueueJob } from '../src/queue-job.js';

const P5 = (b) => Buffer.concat([Buffer.from([5]), b]);
const idOf = (priv) => P5(native.curveGenerateKeypair(priv)[0]);

// 'hung' is the failure this file exists for: a promise that never settles.
function settled(promise, ms = 1500) {
  return Promise.race([
    promise.then(() => 'settled', (e) => `rejected: ${e.message}`),
    new Promise((r) => setTimeout(() => r('hung'), ms)),
  ]);
}

function endpoint(identityPriv, regId, spk, preKeys) {
  let session = null;
  const st = {
    getOurIdentity: async () => ({ privKey: identityPriv, pubKey: idOf(identityPriv) }),
    getOurRegistrationId: async () => regId,
    loadSignedPreKey: async () => spk,
    loadPreKey: async (id) => preKeys.get(id) ?? null,
    removePreKey: async (id) => { preKeys.delete(id); },
    loadSession: async () => session,
    storeSession: async (_id, s) => { session = s; },
    peek: () => session,
  };
  return st;
}

function fixture() {
  const aPriv = crypto.randomBytes(32), bPriv = crypto.randomBytes(32);
  const spkPriv = crypto.randomBytes(32);
  const spkPub = native.curveGenerateKeypair(spkPriv)[0];
  const spkSig = native.curveSign(bPriv, P5(spkPub), null);
  const preKeys = new Map();
  for (let i = 1; i <= 4; i++) {
    const priv = crypto.randomBytes(32);
    preKeys.set(i, { keyId: i, privKey: priv, publicKey: P5(native.curveGenerateKeypair(priv)[0]) });
  }
  return {
    spkPub, spkSig, preKeys, bPriv,
    alice: endpoint(aPriv, 111, null, new Map()),
    bob: endpoint(bPriv, 222, { privKey: spkPriv, pubKey: P5(spkPub) }, preKeys),
    addr: new ProtocolAddress('bob.1', 1),
  };
}

const bundle = (f, preKeyId) => ({
  identityKey: idOf(f.bPriv),
  signedPreKey: { keyId: 5, publicKey: P5(f.spkPub), signature: f.spkSig },
  preKey: preKeyId ? f.preKeys.get(preKeyId) : null,
  registrationId: 42,
});

describe('a storage callback that re-enters the same address', () => {
  for (const [label, reenter] of [
    ['SessionBuilder.initOutgoing', (store, f, addr) => () =>
      new SessionBuilder(store, addr).initOutgoing(bundle(f, 2))],
    ['SessionCipher.encrypt', (store, f, addr) => () =>
      new SessionCipher(store, addr).encrypt(Buffer.from('nested'))],
  ]) {
    it(`from storeSession into ${label} does not hang`, async () => {
      const f = fixture();
      await new SessionBuilder(f.alice, f.addr).initOutgoing(bundle(f, 1));
      assert.ok(f.alice.peek(), 'the first initOutgoing must have stored a session');

      // Arm the hook only after a session exists, so the re-entry is the thing
      // under test rather than the setup. Both the outer call and the nested one
      // are raced: the failure mode is a promise that never settles, so awaiting
      // either one directly would hang the runner instead of failing it.
      const hook = reenter(f.alice, f, f.addr);
      const original = f.alice.storeSession;
      let armed = 0;
      f.alice.storeSession = async (id, s) => {
        await original(id, s);
        if (armed++ === 0) await hook();
      };

      const outer = await settled(new SessionBuilder(f.alice, f.addr).initOutgoing(bundle(f, 2)));
      assert.equal(outer, 'settled',
        `a storage callback re-entering ${label} must not deadlock the queue`);
      assert.equal(armed, 1, 'the re-entry must actually have been attempted');
      assert.equal(await settled(hook()), 'settled',
        `the nested ${label} must return`);
    });
  }

  it('does not fire for a different address', async () => {
    const f = fixture();
    const other = new ProtocolAddress('someone-else.1', 1);
    await new SessionBuilder(f.alice, f.addr).initOutgoing(bundle(f, 1));
    const original = f.alice.storeSession;
    let stores = 0, nested = 0;
    f.alice.storeSession = async (id, s) => {
      await original(id, s);
      // Once only: a nested storeSession re-entering the same address would
      // deadlock on its own and prove nothing about a second address.
      if (stores++ === 0) {
        nested++;
        await new SessionBuilder(f.alice, other).initOutgoing(bundle(f, 3));
      }
    };

    assert.equal(
      await settled(new SessionBuilder(f.alice, f.addr).initOutgoing(bundle(f, 2))), 'settled',
      'a re-entry into a different address has its own queue and must just work');
    assert.equal(nested, 1, 'the nested initOutgoing must actually have run');
    assert.ok(f.alice.peek(), 'the session must still be stored');
  });
});

describe('the queue still serialises genuinely concurrent work', () => {
  it('30 concurrent encrypts and 30 concurrent decryptPreKeyWhisperMessages all round-trip', async () => {
    const f = fixture();
    await new SessionBuilder(f.alice, f.addr).initOutgoing(bundle(f, 1));
    const ca = new SessionCipher(f.alice, f.addr);
    const cb = new SessionCipher(f.bob, new ProtocolAddress('alice.1', 1));

    const out = await Promise.all(
      Array.from({ length: 30 }, (_, i) => ca.encrypt(Buffer.from(`m${i}`))));
    assert.equal(out.length, 30);
    assert.ok(out.every((m) => m.body[0] === 0x33), 'every message must carry the version byte');

    const back = await Promise.all(out.map((m) => cb.decryptPreKeyWhisperMessage(m.body)));
    const texts = back.map((b) => Buffer.from(b).toString()).sort();
    assert.deepStrictEqual(texts,
      Array.from({ length: 30 }, (_, i) => `m${i}`).sort(),
      'a shared queue must not lose or reorder concurrent messages');
  });

  it('QueueJob still serialises, cleans up, and swallows rejections', async () => {
    const q = new QueueJob();
    const order = [];
    await Promise.all([1, 2, 3, 4, 5].map((i) => q.add('k', async () => {
      order.push(`start-${i}`);
      await new Promise((r) => setTimeout(r, 5));
      order.push(`end-${i}`);
    })));
    for (let i = 0; i < 5; i++) {
      assert.equal(order[i * 2], `start-${i + 1}`);
      assert.equal(order[i * 2 + 1], `end-${i + 1}`);
    }
    await new Promise((r) => setTimeout(r, 0));
    assert.equal(q.queues.size, 0, 'the map entry must be cleaned up after settle');

    await assert.rejects(q.add('k', async () => { throw new Error('boom'); }), /boom/);
    assert.equal(await q.add('k', async () => 'after'), 'after',
      'a rejected job must not break the chain');
  });
});
