import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'module';
import crypto from 'node:crypto';
const require = createRequire(import.meta.url);
const n = require('../native/signal/index.cjs');
import { SessionBuilder, SessionCipher, ProtocolAddress } from '../index.js';

// Task 2.1: a PreKeyWhisperMessage is authenticated only by the MAC checked
// inside native.ratchetDecryptPkmsg. Persisting the built session and burning
// the one-time prekey BEFORE that check let one unauthenticated remote message
// destroy the victim's session for that contact.

const P5 = b => Buffer.concat([Buffer.from([5]), b]);
const idOf = priv => P5(n.curveGenerateKeypair(priv)[0]);
const seeded = tag => crypto.createHash('sha256').update(tag).digest();

function makeStorage(identity, regId, spk, preKeys = new Map()) {
  let session = null;
  const store = {
    getOurIdentity: async () => identity,
    getOurRegistrationId: async () => regId,
    loadSignedPreKey: async () => spk,
    loadPreKey: async (id) => preKeys.get(id) ?? null,
    removePreKey: async (id) => { store.removed.push(id); preKeys.delete(id); },
    loadSession: async () => session,
    storeSession: async (id, s) => { store.stored.push(s); session = s; },
    stored: [],
    removed: [],
    peek: () => session,
  };
  return store;
}

function forgePkmsg(preKeyId, tag) {
  const atkIdentity = P5(n.curveGenerateKeypair(seeded(tag))[0]);
  const atkBase = P5(n.curveGenerateKeypair(seeded(tag + ':base'))[0]);
  return Buffer.concat([Buffer.from([0x33]), n.protoEncodePkmsg(JSON.stringify({
    pre_key_id: preKeyId,
    base_key: [...atkBase],
    identity_key: [...atkIdentity],
    message: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20],
    registration_id: 999,
    signed_pre_key_id: null,
  }))]);
}

async function establishedPair() {
  const alicePriv = crypto.randomBytes(32), bobPriv = crypto.randomBytes(32);
  const spkPriv = crypto.randomBytes(32), spkPub = n.curveGenerateKeypair(spkPriv)[0];
  const spkSig = n.curveSign(bobPriv, P5(spkPub), null);
  const opkPriv = crypto.randomBytes(32), opkPub = n.curveGenerateKeypair(opkPriv)[0];

  const alice = makeStorage({ privKey: alicePriv, pubKey: idOf(alicePriv) }, 111, null);
  const bobPreKeys = new Map();
  for (const id of [7, 101, 102, 103]) {
    const priv = crypto.randomBytes(32);
    bobPreKeys.set(id, { privKey: priv, pubKey: P5(n.curveGenerateKeypair(priv)[0]) });
  }
  const bob = makeStorage({ privKey: bobPriv, pubKey: idOf(bobPriv) }, 222,
    { privKey: spkPriv, pubKey: P5(spkPub) }, bobPreKeys);

  const aliceAddr = new ProtocolAddress('bob.1', 1);
  const bobAddr = new ProtocolAddress('alice.1', 1);

  await new SessionBuilder(alice, aliceAddr).initOutgoing({
    identityKey: idOf(bobPriv),
    signedPreKey: { keyId: 5, publicKey: P5(spkPub), signature: spkSig },
    preKey: { keyId: 7, publicKey: bobPreKeys.get(7).pubKey },
    registrationId: 42,
  });
  const ca = new SessionCipher(alice, aliceAddr);
  const cb = new SessionCipher(bob, bobAddr);
  const first = await ca.encrypt(Buffer.from('hello'));
  await cb.decryptPreKeyWhisperMessage(first.body);

  return { ca, cb, bob };
}

test('a forged pkmsg does not persist a session or burn a prekey', async () => {
  const { ca, cb, bob } = await establishedPair();

  const recordBefore = bob.peek().serialize();
  const openBefore = Object.values(JSON.parse(recordBefore)._sessions)
    .find((e) => e.indexInfo.closed === -1);
  const remoteBefore = openBefore.indexInfo.remoteIdentityKey;
  const storedBefore = bob.stored.length;
  const removedBefore = bob.removed.length;

  for (const id of [101, 102, 103]) {
    await assert.rejects(() => cb.decryptPreKeyWhisperMessage(forgePkmsg(id, `attacker:${id}`)));
  }

  assert.equal(bob.stored.length, storedBefore,
    'a MAC-failed pkmsg must not reach storage.storeSession');
  assert.deepEqual(bob.removed, bob.removed.slice(0, removedBefore),
    'a MAC-failed pkmsg must not consume a one-time prekey');
  assert.equal(bob.peek().serialize(), recordBefore,
    'the stored record must be byte-identical after rejected pkmsgs');

  const openAfter = Object.values(JSON.parse(bob.peek().serialize())._sessions)
    .find((e) => e.indexInfo.closed === -1);
  assert.equal(openAfter.indexInfo.remoteIdentityKey, remoteBefore,
    'the open session must still name the real peer, not the forged identity');
});

test('a forged pkmsg leaves the victim able to send', async () => {
  const { ca, cb, bob } = await establishedPair();

  for (const id of [101, 102, 103]) {
    await assert.rejects(() => cb.decryptPreKeyWhisperMessage(forgePkmsg(id, `attacker2:${id}`)));
  }

  const reply = await cb.encrypt(Buffer.from('victim reply'));
  assert.equal(reply.type, 1, 'the victim must still hold a working sending chain');
  assert.deepEqual(await ca.decryptWhisperMessage(reply.body), Buffer.from('victim reply'));
});
