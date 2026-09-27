import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'module';
import crypto from 'node:crypto';
const require = createRequire(import.meta.url);
const n = require('../native/signal/index.cjs');
import { SessionBuilder, SessionCipher, ProtocolAddress } from '../index.js';

// Task 2.2: archiveAndMerge appended one _sessions entry per unseen baseKey with
// no cap. Every re-init from a peer grew the record without bound, and every
// later encrypt/decrypt parse+serialize the whole record. The cap matches
// libsignal's ARCHIVED_STATES_MAX_LENGTH.

const MAX_ARCHIVED = 40;

const P5 = b => Buffer.concat([Buffer.from([5]), b]);
const idOf = priv => P5(n.curveGenerateKeypair(priv)[0]);

function makeStorage(identity, regId, spk, preKeys = new Map()) {
  let session = null;
  const store = {
    getOurIdentity: async () => identity,
    getOurRegistrationId: async () => regId,
    loadSignedPreKey: async () => spk,
    loadPreKey: async (id) => preKeys.get(id) ?? null,
    removePreKey: async (id) => { preKeys.delete(id); },
    loadSession: async () => session,
    storeSession: async (id, s) => { session = s; },
    peek: () => session,
  };
  return store;
}

// Bob answers RE-INITS: each one carries a fresh baseKey, so each one archives
// the previous open session. All of these decrypt successfully.
async function reinitRoundtrip(alice, ca, bobAddr, cb, spkPub, spkSig, preKey) {
  await new SessionBuilder(alice, bobAddr).initOutgoing({
    identityKey: alice.bobIdentity,
    signedPreKey: { keyId: 5, publicKey: P5(spkPub), signature: spkSig },
    preKey: { keyId: preKey.keyId, publicKey: preKey.pubKey },
    registrationId: 42,
  });
  const { type, body } = await ca.encrypt(Buffer.from('reinit'));
  assert.equal(type, 3, 'each re-init must be a PreKeyWhisperMessage');
  const raw = n.protoDecodePkmsg(body.subarray(1)).baseKey;
  const stripped = raw.length === 33 && raw[0] === 0x05 ? raw.subarray(1) : raw;
  await cb.decryptPreKeyWhisperMessage(body);
  return stripped.toString('base64');
}

test('re-init churn keeps the archived session entries bounded', async () => {
  const alicePriv = crypto.randomBytes(32), bobPriv = crypto.randomBytes(32);
  const spkPriv = crypto.randomBytes(32), spkPub = n.curveGenerateKeypair(spkPriv)[0];
  const spkSig = n.curveSign(bobPriv, P5(spkPub), null);

  const bobPreKeys = new Map();
  for (let id = 1; id <= 64; id++) {
    const priv = crypto.randomBytes(32);
    bobPreKeys.set(id, { privKey: priv, pubKey: P5(n.curveGenerateKeypair(priv)[0]) });
  }

  const alice = makeStorage({ privKey: alicePriv, pubKey: idOf(alicePriv) }, 111, null);
  alice.bobIdentity = idOf(bobPriv);
  const bob = makeStorage({ privKey: bobPriv, pubKey: idOf(bobPriv) }, 222,
    { privKey: spkPriv, pubKey: P5(spkPub) }, bobPreKeys);

  const aliceAddr = new ProtocolAddress('bob.1', 1);
  const bobAddr = new ProtocolAddress('alice.1', 1);
  const ca = new SessionCipher(alice, aliceAddr);
  const cb = new SessionCipher(bob, bobAddr);

  const baseKeys = [];
  for (let i = 1; i <= 60; i++) {
    baseKeys.push(await reinitRoundtrip(
      alice, ca, aliceAddr, cb, spkPub, spkSig,
      { keyId: i, pubKey: bobPreKeys.get(i).pubKey }));
  }

  const rec = JSON.parse(bob.peek().serialize());
  const entries = Object.values(rec._sessions);
  const archived = entries.filter((e) => e.indexInfo.closed !== -1);

  assert.equal(archived.length <= MAX_ARCHIVED, true,
    `archived entries must be capped at ${MAX_ARCHIVED}, got ${archived.length}`);
  assert.equal(entries.filter((e) => e.indexInfo.closed === -1).length, 1,
    'exactly one open session must remain');

  // The last re-init's baseKey is the open session; the ones before it are the
  // archive, oldest first.
  const openKey = baseKeys[baseKeys.length - 1];
  const archiveOrder = baseKeys.slice(0, -1);
  const present = new Set(entries.map((e) => e.indexInfo.baseKey));
  assert.equal(present.has(openKey), true, 'the newest session must stay open');

  const evicted = archiveOrder.slice(0, Math.max(0, archiveOrder.length - MAX_ARCHIVED));
  const kept = archiveOrder.slice(Math.max(0, archiveOrder.length - MAX_ARCHIVED));
  for (const k of evicted) {
    assert.equal(present.has(k), false, 'oldest archived entry must be evicted');
  }
  for (const k of kept) {
    assert.equal(present.has(k), true, 'the newest archived entries must be kept');
  }
});
