import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'module';
import crypto from 'node:crypto';
const require = createRequire(import.meta.url);
const n = require('../native/signal/index.cjs');
import { SessionBuilder, SessionCipher, ProtocolAddress } from '../index.js';

// Task 2.8, three defects in session-builder.js:
//   1. an unresolvable pkmsg preKeyId was not rejected, so a session was built
//      and persisted with no DH4 and then died with an opaque MAC failure;
//   2. loadSignedPreKey was feature-detected by function arity (.length > 0),
//      which is 0 for a (...args) or default-param storage;
//   3. initOutgoing called loadSignedPreKey() and discarded the result, so a
//      storage without the method died with a TypeError.

const P5 = b => Buffer.concat([Buffer.from([5]), b]);
const idOf = priv => P5(n.curveGenerateKeypair(priv)[0]);
const keypair = () => {
  const priv = crypto.randomBytes(32);
  return { privKey: priv, pubKey: P5(n.curveGenerateKeypair(priv)[0]) };
};

function baseStorage(identity, regId, spk, preKeys = new Map()) {
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

test('an unresolvable pkmsg preKeyId is rejected instead of building a DH4-less session', async () => {
  const bobPriv = crypto.randomBytes(32);
  const spk = keypair();
  const store = baseStorage({ privKey: bobPriv, pubKey: idOf(bobPriv) }, 222,
    { privKey: spk.privKey, pubKey: spk.pubKey }, new Map([[7, keypair()]]));
  const builder = new SessionBuilder(store, new ProtocolAddress('alice.1', 1));

  const attacker = keypair();
  const base = keypair();
  const pkmsg = {
    preKeyId: 999,                       // never published by this device
    signedPreKeyId: null,
    identityKey: attacker.pubKey,
    baseKey: base.pubKey,
    registrationId: 42,
  };

  await assert.rejects(() => builder.initIncoming(null, pkmsg), /pre[ -]?key/i);
  assert.deepEqual(store.stored, [], 'no session may be built from an unresolvable prekey');
});

test('a pkmsg naming an unpublished prekey fails with a clear error, not a MAC failure', async () => {
  const bobPriv = crypto.randomBytes(32);
  const spk = keypair();
  const store = baseStorage({ privKey: bobPriv, pubKey: idOf(bobPriv) }, 222,
    { privKey: spk.privKey, pubKey: spk.pubKey }, new Map([[7, keypair()]]));
  const addr = new ProtocolAddress('alice.1', 1);
  const cipher = new SessionCipher(store, addr);

  const attacker = keypair();
  const base = keypair();
  const pk = n.protoEncodePkmsg(JSON.stringify({
    pre_key_id: 999,
    base_key: [...base.pubKey],
    identity_key: [...attacker.pubKey],
    message: [1, 2, 3, 4, 5, 6, 7, 8],
    registration_id: 42,
    signed_pre_key_id: null,
  }));

  const err = await cipher
    .decryptPreKeyWhisperMessage(Buffer.concat([Buffer.from([0x33]), pk]))
    .then(() => null, (e) => e);
  assert.ok(err, 'an unresolvable prekey must reject');
  assert.match(err.message, /prekey/i,
    `expected an actionable prekey error, got: ${err.message}`);
  assert.deepEqual(store.removed, [], 'no prekey may be consumed');
  assert.deepEqual(store.stored, [], 'no session may be persisted');
});

test('a rest-arg loadSignedPreKey is given the pkmsg signed-prekey id', async () => {
  const bobPriv = crypto.randomBytes(32);
  const spk = keypair();
  const opk = keypair();
  const byId = new Map([[9, { privKey: spk.privKey, pubKey: spk.pubKey }]]);
  const store = baseStorage({ privKey: bobPriv, pubKey: idOf(bobPriv) }, 222, null,
    new Map([[7, opk]]));
  // .length === 0, exactly like (...args) — arity detection cannot see the id.
  store.loadSignedPreKey = async (...args) => byId.get(args[0]) ?? null;

  const builder = new SessionBuilder(store, new ProtocolAddress('alice.1', 1));
  const rec = await builder.initIncoming(null, {
    preKeyId: 7,
    signedPreKeyId: 9,
    identityKey: keypair().pubKey,
    baseKey: keypair().pubKey,
    registrationId: 42,
  });
  assert.ok(rec.serialize().length > 0, 'the rotated signed prekey must resolve by id');
});

test('initOutgoing does not require a loadSignedPreKey method', async () => {
  const alicePriv = crypto.randomBytes(32), bobPriv = crypto.randomBytes(32);
  const spkPub = n.curveGenerateKeypair(crypto.randomBytes(32))[0];
  const spkSig = n.curveSign(bobPriv, P5(spkPub), null);
  const opk = keypair();

  const store = baseStorage({ privKey: alicePriv, pubKey: idOf(alicePriv) }, 111, null);
  delete store.loadSignedPreKey;

  await new SessionBuilder(store, new ProtocolAddress('bob.1', 1)).initOutgoing({
    identityKey: idOf(bobPriv),
    signedPreKey: { keyId: 5, publicKey: P5(spkPub), signature: spkSig },
    preKey: { keyId: 7, publicKey: opk.pubKey },
    registrationId: 42,
  });
  assert.ok(store.peek(), 'the outgoing session must be stored');
});
