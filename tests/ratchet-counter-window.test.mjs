// R8: the pre-MAC work bound must be the SKIP DISTANCE from the chain, not an
// absolute position on the wire.
//
// An absolute ceiling on msg.counter rejected every message past counter 2000 of
// an epoch, while a peer is free to keep sending on that chain — so 5 messages
// in a 2005-message epoch were silently lost and only recovered after a
// reverse-direction exchange ratcheted the chain. The relative-distance caps in
// fill_message_keys / peek_message_key are libsignal's own bound
// (session_cipher.js fillMessageKeys: "Over 2000 messages into the future!") and
// are what actually bound the work an unauthenticated sender can buy.
import crypto from 'node:crypto';
import { createRequire } from 'module';
import { describe, it } from 'node:test';
import assert from 'node:assert';
const require = createRequire(import.meta.url);
const native = require('../native/signal/index.cjs');

const P5 = (b) => Buffer.concat([Buffer.from([5]), b]);

function pair() {
  const aPriv = crypto.randomBytes(32), bPriv = crypto.randomBytes(32);
  const spkPriv = crypto.randomBytes(32);
  const idA = P5(native.curveGenerateKeypair(aPriv)[0]);
  const idB = P5(native.curveGenerateKeypair(bPriv)[0]);
  const spkPub = native.curveGenerateKeypair(spkPriv)[0];
  const spk33 = P5(spkPub);
  const alice = native.x3DhBuildInitialSession(
    aPriv, idA, spk33, native.curveSign(bPriv, spk33, null),
    null, null, idB, spk33, 42, 1);
  const aEph = Buffer.from(
    JSON.parse(alice)._sessions[Object.keys(JSON.parse(alice)._sessions)[0]]
      .currentRatchet.ephemeralKeyPair.pubKey, 'base64');
  const bob = native.x3DhBuildRecipientSession(
    bPriv, spkPriv, spkPub, null, idA, aEph, 42);
  return { alice, bob, idA, idB };
}

describe('a long epoch in one ratchet step', () => {
  it('round-trips 2500 messages, delivered out of order', () => {
    const p = pair();
    const total = 2500;
    const wire = [];
    let alice = p.alice, bob = p.bob;
    const opening = native.ratchetEncrypt(alice, Buffer.from('open'), p.idA, 42);
    wire.push(opening.ciphertext);
    alice = opening.sessionJson;
    for (let i = 1; i < total; i++) {
      const e = native.ratchetEncrypt(alice, Buffer.from(`m${i}`), p.idA, 42);
      wire.push(e.ciphertext);
      alice = e.sessionJson;
    }
    // The last messages are the ones an absolute ceiling used to drop.
    assert.equal(wire.length, total);

    // Deliver in shuffled windows: every message arrives after a later one, and
    // none is more than the skip bound ahead of the chain.
    const order = [];
    for (let base = 0; base < total; base += 1500) {
      const window = [];
      for (let i = base; i < Math.min(base + 1500, total); i++) window.push(i);
      for (let i = window.length - 1; i > 0; i--) {
        const j = crypto.randomInt(i + 1);
        [window[i], window[j]] = [window[j], window[i]];
      }
      order.push(...window);
    }

    for (const i of order) {
      const d = native.ratchetDecryptPkmsg(bob, wire[i], p.idB);
      bob = d.sessionJson;
      assert.equal(Buffer.from(d.plaintext).toString(), i === 0 ? 'open' : `m${i}`,
        `message ${i} must decrypt`);
    }
  });

  it('accepts a counter past 2000 and still refuses one far past the chain', () => {
    const p = pair();
    const opening = native.ratchetEncrypt(p.alice, Buffer.from('open'), p.idA, 42);
    const bob = native.ratchetDecryptPkmsg(p.bob, opening.ciphertext, p.idB).sessionJson;
    const entry = Object.values(JSON.parse(bob)._sessions)[0];
    const recvId = Object.keys(entry._chains).find(
      (k) => JSON.parse(bob)._sessions[Object.keys(JSON.parse(bob)._sessions)[0]]
        ._chains[k].chainType !== 1);
    const chain = entry._chains[recvId].chainKey.counter;

    const forge = (counter) => {
      const msgBuf = native.protoEncodeWhisper(
        Buffer.from(recvId, 'base64'), counter, 0, Buffer.alloc(32, 3));
      return Buffer.concat([Buffer.from([0x33]), msgBuf, Buffer.alloc(8, 0xAA)]);
    };

    // 2000 ahead of the chain: bounded, and it reaches the MAC — which is what
    // rejects it. This is the most an unauthenticated sender can buy.
    const before = JSON.stringify(JSON.parse(bob));
    const started = process.hrtime.bigint();
    assert.throws(() => native.ratchetDecryptWhisper(bob, forge(chain + 2000), p.idB), /MAC/,
      'a counter at the skip bound must be reached and rejected on the MAC');
    const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
    assert.ok(elapsedMs < 2000, `the skip bound must stay cheap, took ${elapsedMs}ms`);
    assert.equal(JSON.stringify(JSON.parse(bob)), before,
      'a refused forgery must not move the record');

    // One past the skip bound: refused on distance, before any key derivation.
    assert.throws(
      () => native.ratchetDecryptWhisper(bob, forge(chain + 2001), p.idB), /future/,
      'a counter beyond the skip distance must be refused');
    // A counter far beyond any chain position is refused the same way — there is
    // no absolute ceiling to lean on, and none is needed.
    assert.throws(() => native.ratchetDecryptWhisper(bob, forge(100_000), p.idB), /future/);
  });
});
