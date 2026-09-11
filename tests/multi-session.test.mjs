import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const native = require('../native/signal/index.cjs');
import { SessionBuilder, SessionCipher, SessionRecord, ProtocolAddress } from '../index.js';

// Regression test for the session-selection fix (audit H1/H2, 0.2.0-rc.1):
// A record holding MULTIPLE entries (archived old session + fresh open one)
// must encrypt/decrypt using the OPEN session — not whichever entry the
// BTreeMap happens to iterate first.

const identityOf = (priv) =>
  Buffer.concat([Buffer.from([0x05]), native.curveGenerateKeypair(priv)[0]]);

function makeStorage(identity, regId, spkPair, preKeys = new Map()) {
  let session = null;
  const store = {
    getOurIdentity: async () => identity,
    getOurRegistrationId: async () => regId,
    loadSignedPreKey: async () => spkPair,
    loadPreKey: async (id) => preKeys.get(id) || null,
    removePreKey: async (id) => { store.removedPreKeys.push(id); preKeys.delete(id); },
    loadSession: async () => session,
    storeSession: async (id, s) => { session = s; store.lastStored = s; },
    removedPreKeys: [],
    peek: () => session,
  };
  return store;
}

test('multi-session record: encrypt picks the OPEN session, not the first entry', async () => {
  const alicePriv = Buffer.alloc(32, 0x11);
  const bobPriv = Buffer.alloc(32, 0x22);
  const spkPriv = Buffer.alloc(32, 0x33), spkPub = native.curveGenerateKeypair(spkPriv)[0];
  const spkSig = native.curveSign(bobPriv, Buffer.concat([Buffer.from([0x05]), spkPub]), null);
  const opkPriv = Buffer.alloc(32, 0x44), opkPub = native.curveGenerateKeypair(opkPriv)[0];

  const aliceStorage = makeStorage({ privKey: alicePriv, pubKey: identityOf(alicePriv) }, 111, null);
  const bobStorage = makeStorage({ privKey: bobPriv, pubKey: identityOf(bobPriv) }, 222,
    { privKey: spkPriv, pubKey: Buffer.concat([Buffer.from([0x05]), spkPub]) },
    new Map([[7, { privKey: opkPriv, pubKey: Buffer.concat([Buffer.from([0x05]), opkPub]) }]]));

  const aliceAddr = new ProtocolAddress('bob-device', 1);
  const bobAddr = new ProtocolAddress('alice-device', 1);

  await new SessionBuilder(aliceStorage, aliceAddr).initOutgoing({
    identityKey: identityOf(bobPriv),
    signedPreKey: { keyId: 5, publicKey: Buffer.concat([Buffer.from([0x05]), spkPub]), signature: spkSig },
    preKey: { keyId: 7, publicKey: Buffer.concat([Buffer.from([0x05]), opkPub]) },
    registrationId: 42,
  });

  const ca = new SessionCipher(aliceStorage, aliceAddr);
  const cb = new SessionCipher(bobStorage, bobAddr);

  // Round 1: establish normally.
  const e1 = await ca.encrypt(Buffer.from('v1'));
  await cb.decryptPreKeyWhisperMessage(e1.body);

  // Round 2: simulate peer RE-INIT — same identities, NEW prekey bundle.
  const opk2Priv = Buffer.alloc(32, 0x55), opk2Pub = native.curveGenerateKeypair(opk2Priv)[0];
  const bobStorage2PreKeys = new Map([[8, { privKey: opk2Priv, pubKey: Buffer.concat([Buffer.from([0x05]), opk2Pub]) }]]);
  const bobStorage2 = makeStorage({ privKey: bobPriv, pubKey: identityOf(bobPriv) }, 222,
    { privKey: spkPriv, pubKey: Buffer.concat([Buffer.from([0x05]), spkPub]) },
    bobStorage2PreKeys);
  // Bob keeps his EXISTING record (with the old session) — re-init arrives on top.
  const existing = bobStorage.peek();
  bobStorage2.storeSession('bob', existing);

  // Alice builds a fresh outgoing session with the new bundle.
  const aliceStorage2 = makeStorage({ privKey: alicePriv, pubKey: identityOf(alicePriv) }, 111, null);
  await new SessionBuilder(aliceStorage2, aliceAddr).initOutgoing({
    identityKey: identityOf(bobPriv),
    signedPreKey: { keyId: 5, publicKey: Buffer.concat([Buffer.from([0x05]), spkPub]), signature: spkSig },
    preKey: { keyId: 8, publicKey: Buffer.concat([Buffer.from([0x05]), opk2Pub]) },
    registrationId: 42,
  });
  const ca2 = new SessionCipher(aliceStorage2, aliceAddr);
  const cb2 = new SessionCipher(bobStorage2, bobAddr);

  const e2 = await ca2.encrypt(Buffer.from('v2-reinit'));
  const raw2 = await cb2.decryptPreKeyWhisperMessage(e2.body);
  assert.equal(raw2.toString(), 'v2-reinit');

  // Multi-entry record: old entry archived (fix H2), exactly one open entry.
  const rec = JSON.parse(bobStorage2.peek().serialize());
  const entries = Object.values(rec._sessions);
  assert.ok(entries.length >= 2, `expected >=2 session entries, got ${entries.length}`);
  const openEntries = entries.filter((e) => e.indexInfo.closed === -1);
  assert.equal(openEntries.length, 1, 'exactly one open session after re-init');

  // Round 3: steady-state through the SAME multi-entry record must use the
  // open session — the path that previously picked the wrong entry and died
  // with "no sending chain" / "message key not found".
  const e3 = await ca2.encrypt(Buffer.from('v3-steady'));
  const raw3 = await cb2.decryptPreKeyWhisperMessage(e3.body);
  assert.equal(raw3.toString(), 'v3-steady');

  // One-time prekey consumed after successful initIncoming (fix M1).
  assert.ok(bobStorage2.removedPreKeys.includes(8), 'removePreKey must be called for the consumed OPK');
});
