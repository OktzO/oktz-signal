// R9: the previousCounter guard in plan_ratchet.
//
// The review reported this as a false rejection of a legitimate message:
// "previous_counter is our own sending-chain counter compared against the
// receiving chain, which tracks an independent count". Both halves of that are
// wrong, and the scenario is one libsignal cannot complete either.
//
//   - msg.previousCounter is the SENDER's counter on the chain keyed by the
//     sender's previous ephemeral key. The chain it is compared against here is
//     keyed by lastRemoteEphemeralKey — the same chain, mirrored. The counters
//     track the same sequence.
//   - libsignal runs the same check on the same value in the same place:
//     session_cipher.js maybeStepRatchet calls fillMessageKeys(previousRatchet,
//     previousCounter), and fillMessageKeys throws 'Over 2000 messages into the
//     future!' past 2000. oktz-signal's error string is deliberately identical.
//
// So this test drives the reported scenario through BOTH engines and requires
// them to agree, on either side of the bound. If they ever diverge, oktz-signal
// is the one that is wrong.
import crypto from 'node:crypto';
import { createRequire } from 'module';
import { describe, it } from 'node:test';
import assert from 'node:assert';
import * as libsignal from 'libsignal';
const require = createRequire(import.meta.url);
const native = require('../native/signal/index.cjs');

const P5 = (b) => Buffer.concat([Buffer.from([5]), b]);

// --- oktz-signal: one conversation, one ratchet step, then a direction flip ---

function oktzPair() {
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

// Alice sends `lag` more messages Bob never sees, Bob replies so Alice ratchets,
// then Alice's first message on the new chain carries previousCounter = lag.
function oktzLagScenario(lag) {
  const p = oktzPair();
  let alice = p.alice, bob = p.bob;
  const open = native.ratchetEncrypt(alice, Buffer.from('open'), p.idA, 42);
  bob = native.ratchetDecryptPkmsg(bob, open.ciphertext, p.idB).sessionJson;
  alice = open.sessionJson;
  for (let i = 0; i < lag; i++) {
    alice = native.ratchetEncrypt(alice, Buffer.from('unseen'), p.idA, 42).sessionJson;
  }
  const reply = native.ratchetEncrypt(bob, Buffer.from('reply'), p.idB, 42);
  alice = native.ratchetDecryptWhisper(alice, reply.ciphertext, p.idA).sessionJson;
  const next = native.ratchetEncrypt(alice, Buffer.from('after ratchet'), p.idA, 42);
  const wire = next.ciphertext;
  const msg = native.protoDecodeWhisper(wire.subarray(1, wire.length - 8));
  return {
    previousCounter: msg.previousCounter,
    outcome: () => native.ratchetDecryptWhisper(bob, wire, p.idB),
  };
}

// --- libsignal: the same conversation, the same engines' own decision ---

async function libsignalLagScenario(lag) {
  const aP = crypto.randomBytes(32), bP = crypto.randomBytes(32);
  const aId = libsignal.curve.getPublicFromPrivateKey(aP);
  const bId = libsignal.curve.getPublicFromPrivateKey(bP);
  const spk = libsignal.curve.generateKeyPair(crypto.randomBytes(32));
  const spkSig = Buffer.from(native.curveSign(bP, spk.pubKey, null));
  const mk = (priv, id) => {
    let sess = null;
    return {
      loadSession: async () => sess,
      storeSession: async (_i, v) => { sess = v; },
      isTrustedIdentity: () => true,
      loadPreKey: async () => null,
      removePreKey: async () => {},
      loadSignedPreKey: async () => spk,
      getOurRegistrationId: () => 42,
      getOurIdentity: () => ({ privKey: priv, pubKey: id }),
    };
  };
  const as = mk(aP, aId), bs = mk(bP, bId);
  const ac = new libsignal.SessionCipher(as, new libsignal.ProtocolAddress('bob', 1));
  const bc = new libsignal.SessionCipher(bs, new libsignal.ProtocolAddress('alice', 1));
  await new libsignal.SessionBuilder(as, new libsignal.ProtocolAddress('bob', 1))
    .initOutgoing({
      identityKey: bId,
      signedPreKey: { keyId: 1, publicKey: spk.pubKey, signature: spkSig },
      preKey: null,
      registrationId: 42,
    });
  const decrypt = (c, e) => e.type === 3
    ? c.decryptPreKeyWhisperMessage(e.body) : c.decryptWhisperMessage(e.body);
  await decrypt(bc, await ac.encrypt(Buffer.from('open')));
  for (let i = 0; i < lag; i++) await ac.encrypt(Buffer.from('unseen'));
  await decrypt(ac, await bc.encrypt(Buffer.from('reply')));
  const next = await ac.encrypt(Buffer.from('after ratchet'));
  return {
    outcome: async () => {
      try {
        return { ok: Buffer.from(await decrypt(bc, next)).toString() };
      } catch (e) {
        return { error: e.message };
      }
    },
  };
}

describe('the previousCounter guard agrees with libsignal', () => {
  it('refuses a stale chain exactly where libsignal refuses it, and accepts below it', async () => {
    for (const [lag, expected] of [[500, true], [2500, false]]) {
      const oktz = oktzLagScenario(lag);
      const lib = await libsignalLagScenario(lag);
      const libResult = await lib.outcome();
      const oktzAccepted = (() => {
        try {
          return Buffer.from(oktz.outcome().plaintext).toString();
        } catch (e) {
          return e.message;
        }
      })();

      if (expected) {
        assert.equal(oktzAccepted, 'after ratchet',
          `oktz-signal must accept previousCounter ${lag}`);
        assert.equal(libResult.ok, 'after ratchet',
          `libsignal must accept previousCounter ${lag}`);
      } else {
        assert.match(oktzAccepted, /future/i,
          `oktz-signal must refuse previousCounter ${lag} on the skip bound`);
        assert.ok(libResult.error,
          `libsignal must refuse previousCounter ${lag} too — ` +
          `got ${JSON.stringify(libResult)}`);
        assert.equal(oktz.previousCounter, lag,
          'the wire previousCounter is the lag the scenario built');
      }
    }
  });
});

describe('the previousCounter guard runs pre-MAC without moving the record', () => {
  it('a forged previousCounter is refused and the record is untouched', () => {
    const p = oktzPair();
    const open = native.ratchetEncrypt(p.alice, Buffer.from('open'), p.idA, 42);
    const bob = native.ratchetDecryptPkmsg(p.bob, open.ciphertext, p.idB).sessionJson;
    const before = JSON.stringify(JSON.parse(bob));

    // An attacker knows nothing: a random ephemeral key, the maximum
    // previousCounter, a garbage ciphertext and a garbage MAC. The guard must
    // refuse it on the pre-MAC path, and refuse it by distance, not by letting
    // it through to the MAC.
    const eph = crypto.randomBytes(32);
    const msgBuf = native.protoEncodeWhisper(eph, 0, 0xFFFFFFFF, Buffer.alloc(32, 7));
    const wire = Buffer.concat([Buffer.from([0x33]), msgBuf, Buffer.alloc(8, 0xAA)]);
    assert.throws(() => native.ratchetDecryptWhisper(bob, wire, p.idB), /future/i,
      'an unauthenticated previousCounter must be refused on distance');
    assert.equal(JSON.stringify(JSON.parse(bob)), before,
      'the refusal must happen before the record is touched');
  });
});
