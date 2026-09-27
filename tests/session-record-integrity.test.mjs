import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'module';
import crypto from 'node:crypto';
const require = createRequire(import.meta.url);
const n = require('../native/signal/index.cjs');
import { SessionBuilder, SessionCipher, SessionRecord, ProtocolAddress } from '../index.js';

// Task 2.9, session-cipher.js: sessionHasBaseKey's `catch { return false }` made
// an unparseable record indistinguishable from "base key unknown", so corruption
// was answered with a fresh X3DH build instead of being surfaced; and a failing
// removePreKey was swallowed, leaving the caller believing a still-replayable
// one-time prekey had been consumed.

const P5 = b => Buffer.concat([Buffer.from([5]), b]);
const idOf = priv => P5(n.curveGenerateKeypair(priv)[0]);

function makeStorage(identity, regId, spk, preKeys = new Map()) {
  let session = null;
  const store = {
    getOurIdentity: async () => identity,
    getOurRegistrationId: async () => regId,
    loadSignedPreKey: async () => spk,
    loadPreKey: async (id) => { store.preKeyLoads.push(id); return preKeys.get(id) ?? null; },
    removePreKey: async (id) => { store.removed.push(id); preKeys.delete(id); },
    loadSession: async () => session,
    storeSession: async (id, s) => { store.stored.push(s); session = s; },
    preKeyLoads: [],
    removed: [],
    stored: [],
    peek: () => session,
  };
  return store;
}

async function establishedPair() {
  const alicePriv = crypto.randomBytes(32), bobPriv = crypto.randomBytes(32);
  const spkPriv = crypto.randomBytes(32), spkPub = n.curveGenerateKeypair(spkPriv)[0];
  const spkSig = n.curveSign(bobPriv, P5(spkPub), null);
  const preKeys = new Map();
  for (const id of [7, 55]) {
    const priv = crypto.randomBytes(32);
    preKeys.set(id, { privKey: priv, pubKey: P5(n.curveGenerateKeypair(priv)[0]) });
  }
  const alice = makeStorage({ privKey: alicePriv, pubKey: idOf(alicePriv) }, 111, null);
  const bob = makeStorage({ privKey: bobPriv, pubKey: idOf(bobPriv) }, 222,
    { privKey: spkPriv, pubKey: P5(spkPub) }, preKeys);
  const addr = new ProtocolAddress('bob.1', 1);
  await new SessionBuilder(alice, addr).initOutgoing({
    identityKey: idOf(bobPriv),
    signedPreKey: { keyId: 5, publicKey: P5(spkPub), signature: spkSig },
    preKey: { keyId: 7, publicKey: preKeys.get(7).pubKey },
    registrationId: 42,
  });
  return { alice, bob, preKeys, spkPub, spkSig, addr };
}

test('a corrupt stored record is surfaced, not answered with a fresh X3DH build', async () => {
  const { alice, bob, addr } = await establishedPair();
  const ca = new SessionCipher(alice, addr);
  const pkmsg = (await ca.encrypt(Buffer.from('hi'))).body;

  // Replace Bob's record with something unparseable.
  const bobAddr = new ProtocolAddress('alice.1', 1);
  bob.storeSession(bobAddr.toString(), new SessionRecord('{not json'));
  bob.preKeyLoads.length = 0;

  await assert.rejects(() => new SessionCipher(bob, bobAddr).decryptPreKeyWhisperMessage(pkmsg));

  assert.deepEqual(bob.preKeyLoads, [],
    'corruption must not be answered by rebuilding a session and burning a prekey');
  assert.deepEqual(bob.removed, [], 'no prekey may be consumed on a corrupt record');
});

test('a failing removePreKey is reported, not swallowed', async () => {
  const { alice, bob, preKeys, addr } = await establishedPair();
  const bobAddr = new ProtocolAddress('alice.1', 1);
  const ca = new SessionCipher(alice, addr);
  const pkmsg = (await ca.encrypt(Buffer.from('hi'))).body;

  bob.removePreKey = async () => { throw new Error('prekey store offline'); };

  // The caller must learn the one-time prekey is still on disk and replayable.
  await assert.rejects(
    () => new SessionCipher(bob, bobAddr).decryptPreKeyWhisperMessage(pkmsg),
    /prekey store offline/);
  assert.equal(preKeys.has(7), true, 'the prekey must still be present');
});
