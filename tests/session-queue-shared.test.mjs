import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'module';
import crypto from 'node:crypto';
const require = createRequire(import.meta.url);
const n = require('../native/signal/index.cjs');
import { SessionBuilder, SessionCipher, ProtocolAddress } from '../index.js';

// Task 2.7: SessionBuilder used its own per-instance QueueJob, so a
// SessionBuilder and a SessionCipher over the same (storage, addr) record could
// interleave their load/store. That is exactly what the shared queue in
// session-cipher.js exists to prevent, and violating it clobbers the ratchet:
// the next inbound message then fails MAC verification.

const P5 = b => Buffer.concat([Buffer.from([5]), b]);
const idOf = priv => P5(n.curveGenerateKeypair(priv)[0]);

// Every load/store is async with a yield, so any two of them that are not
// serialized by a shared queue will observably overlap.
function makeStorage(identity, regId, spk, preKeys = new Map()) {
  let session = null;
  let inFlight = 0;
  const store = {
    maxInFlight: 0,
    getOurIdentity: async () => identity,
    getOurRegistrationId: async () => regId,
    loadSignedPreKey: async () => spk,
    loadPreKey: async (id) => preKeys.get(id) ?? null,
    removePreKey: async (id) => { preKeys.delete(id); },
    loadSession: async () => enter(async () => session),
    storeSession: async (id, s) => enter(async () => { session = s; }),
    peek: () => session,
  };
  async function enter(fn) {
    inFlight++;
    store.maxInFlight = Math.max(store.maxInFlight, inFlight);
    await new Promise((r) => setTimeout(r, 5));
    try { return await fn(); } finally { inFlight--; }
  }
  return store;
}

function bundle(spkPub, spkSig, preKey) {
  return {
    identityKey: bundle.bobIdentity,
    signedPreKey: { keyId: 5, publicKey: P5(spkPub), signature: spkSig },
    preKey: preKey ? { keyId: preKey.keyId, publicKey: preKey.pubKey } : null,
    registrationId: 42,
  };
}

async function pair() {
  const alicePriv = crypto.randomBytes(32), bobPriv = crypto.randomBytes(32);
  const spkPriv = crypto.randomBytes(32), spkPub = n.curveGenerateKeypair(spkPriv)[0];
  const spkSig = n.curveSign(bobPriv, P5(spkPub), null);
  const preKeys = new Map();
  for (let i = 1; i <= 8; i++) {
    const priv = crypto.randomBytes(32);
    preKeys.set(i, { keyId: i, privKey: priv, pubKey: P5(n.curveGenerateKeypair(priv)[0]) });
  }
  const alice = makeStorage({ privKey: alicePriv, pubKey: idOf(alicePriv) }, 111, null);
  const bob = makeStorage({ privKey: bobPriv, pubKey: idOf(bobPriv) }, 222,
    { privKey: spkPriv, pubKey: P5(spkPub) }, preKeys);
  bundle.bobIdentity = idOf(bobPriv);
  const addr = new ProtocolAddress('bob.1', 1);
  return { alice, bob, spkPub, spkSig, preKeys, addr };
}

test('initOutgoing and encrypt never interleave on the same record', async () => {
  const { alice, spkPub, spkSig, preKeys, addr } = await pair();

  await new SessionBuilder(alice, addr).initOutgoing(bundle(spkPub, spkSig, preKeys.get(1)));
  alice.maxInFlight = 0;

  await Promise.all([
    new SessionBuilder(alice, addr).initOutgoing(bundle(spkPub, spkSig, preKeys.get(2))),
    new SessionCipher(alice, addr).encrypt(Buffer.from('concurrent')),
  ]);

  assert.equal(alice.maxInFlight, 1,
    'SessionBuilder and SessionCipher must share one queue per (storage, addr)');
});

const openBaseKey = (store) => Object.values(JSON.parse(store.peek().serialize())._sessions)
  .find((e) => e.indexInfo.closed === -1).indexInfo.baseKey;

const pkmsgBaseKey = (body) => {
  const raw = n.protoDecodePkmsg(body.subarray(1)).baseKey;
  return (raw.length === 33 && raw[0] === 0x05 ? raw.subarray(1) : raw).toString('base64');
};

test('a re-init concurrent with encrypt is not clobbered', async () => {
  const { alice, spkPub, spkSig, preKeys, addr } = await pair();

  await new SessionBuilder(alice, addr).initOutgoing(bundle(spkPub, spkSig, preKeys.get(1)));
  const staleKey = openBaseKey(alice);
  const ca = new SessionCipher(alice, addr);

  const [, msg] = await Promise.all([
    new SessionBuilder(alice, addr).initOutgoing(bundle(spkPub, spkSig, preKeys.get(2))),
    ca.encrypt(Buffer.from('racing')),
  ]);

  // Without a shared queue the encrypt loads the record before the re-init
  // lands and sends on the session the re-init replaced. The recipient builds a
  // session for the baseKey the sender actually used while the sender's record
  // names the other one, so the NEXT inbound message fails MAC verification.
  assert.notEqual(pkmsgBaseKey(msg.body), staleKey,
    'the racing encrypt must not send on the session the re-init replaced');
  assert.equal(openBaseKey(alice), pkmsgBaseKey(msg.body),
    'the persisted record must be the session the racing message was sent on');
});
