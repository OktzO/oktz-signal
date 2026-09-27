// R2/R3: a session record libsignal wrote must be readable by oktz-signal.
//
// The shapes pinned here are the ones libsignal's own SessionCipher/Builder
// produce, taken from the record it stores — never hand-built. A record
// libsignal writes retires a receiving chain by DELETING its key
// (session_cipher.js: `delete previousRatchet.chainKey.key`) and its serializer
// emits `key: c.chainKey.key && ...`, so JSON.stringify omits the field and the
// record carries `{"chainKey":{"counter":n}}`. That shape used to be a hard
// parse error, which made every bidirectional libsignal session unreadable to
// oktz-signal after its second ratchet step.
import crypto from 'node:crypto';
import { createRequire } from 'module';
import { describe, it } from 'node:test';
import assert from 'node:assert';
import * as libsignal from 'libsignal';
const require = createRequire(import.meta.url);
const native = require('../native/signal/index.cjs');

const H = (k, d) => crypto.createHmac('sha256', k).update(d).digest();
const P5 = (b) => Buffer.concat([Buffer.from([5]), b]);
const entryOf = (json) => Object.values(JSON.parse(json)._sessions)[0];
const chainsOf = (json) => Object.entries(entryOf(json)._chains);

function deriveN(input, salt, info, cnt) {
  const prk = H(salt, input);
  const out = [];
  let prev = Buffer.alloc(0);
  for (let i = 0; i < cnt; i++) {
    prev = H(prk, Buffer.concat([prev, Buffer.from(info), Buffer.from([i + 1])]));
    out.push(prev);
  }
  return out;
}

function endpoint(identityPriv, identityPub, spk, regId) {
  const st = { session: null };
  st.storage = {
    loadSession: async () => st.session,
    storeSession: async (_id, s) => { st.session = s; },
    isTrustedIdentity: () => true,
    loadPreKey: async () => null,
    removePreKey: async () => {},
    loadSignedPreKey: async () => spk,
    loadIdentityKey: async () => identityPub,
    saveIdentity: async () => false,
    loadSenderKey: async () => null,
    storeSenderKey: async () => {},
    getOurRegistrationId: () => regId,
    getOurIdentity: () => ({ privKey: identityPriv, pubKey: identityPub }),
  };
  return st;
}

// A libsignal conversation `turns` round trips long, so Bob's record holds
// receiving chains libsignal has already retired.
async function libsignalConversation(turns) {
  const alicePriv = crypto.randomBytes(32), bobPriv = crypto.randomBytes(32);
  const alicePub = libsignal.curve.getPublicFromPrivateKey(alicePriv);
  const bobPub = libsignal.curve.getPublicFromPrivateKey(bobPriv);
  const spk = libsignal.curve.generateKeyPair(crypto.randomBytes(32));
  const spkSig = Buffer.from(native.curveSign(bobPriv, spk.pubKey, null));
  const alice = endpoint(alicePriv, alicePub, spk, 111);
  const bob = endpoint(bobPriv, bobPub, spk, 222);
  const toBob = new libsignal.ProtocolAddress('bob', 1);
  const toAlice = new libsignal.ProtocolAddress('alice', 1);
  await new libsignal.SessionBuilder(alice.storage, toBob).initOutgoing({
    identityKey: bobPub,
    signedPreKey: { keyId: 1, publicKey: spk.pubKey, signature: spkSig },
    preKey: null,
    registrationId: 42,
  });
  const aliceCipher = new libsignal.SessionCipher(alice.storage, toBob);
  const bobCipher = new libsignal.SessionCipher(bob.storage, toAlice);
  const decrypt = (c, e) => e.type === 3
    ? c.decryptPreKeyWhisperMessage(e.body) : c.decryptWhisperMessage(e.body);
  for (let i = 0; i < turns; i++) {
    await decrypt(bobCipher, await aliceCipher.encrypt(Buffer.from(`alice ${i}`)));
    await decrypt(aliceCipher, await bobCipher.encrypt(Buffer.from(`bob ${i}`)));
  }
  return { alice, bob, bobPub, aliceCipher, bobCipher, decrypt };
}

describe('a session record libsignal wrote', () => {
  it('carries a retired chain whose key libsignal deleted, and oktz-signal reads it', async () => {
    const { bob, bobPub, aliceCipher } = await libsignalConversation(3);
    const record = JSON.stringify(bob.session.serialize());

    assert.ok(chainsOf(record).filter(([, c]) => !('key' in c.chainKey)).length > 0,
      'fixture must contain the chain libsignal retired by deleting its key');
    assert.ok(chainsOf(record).every(([k]) => Buffer.from(k, 'base64').length === 33),
      'fixture must key _chains by libsignal 33-byte wire keys');
    assert.ok(chainsOf(record).some(([, c]) => c.chainType === 2),
      'fixture must contain a libsignal RECEIVING (2) chain');

    // It parses, and the read does not invent a key for the retired chain.
    const round = JSON.parse(native.sessionSerialize(native.sessionDeserialize(record)));
    assert.deepStrictEqual(round, JSON.parse(record),
      'a libsignal record must survive an oktz-signal parse/serialise unchanged');
    assert.ok(!JSON.stringify(round).includes('"key":null'),
      'an absent chain key must not come back as null');

    // And it still decrypts — parsing alone would prove nothing.
    const said = Buffer.from('still readable');
    const out = await aliceCipher.encrypt(said);
    const result = out.type === 3
      ? native.ratchetDecryptPkmsg(record, Buffer.from(out.body), bobPub)
      : native.ratchetDecryptWhisper(record, Buffer.from(out.body), bobPub);
    assert.deepStrictEqual(Buffer.from(result.plaintext), said);
  });

  it('an oktz-signal record is readable by libsignal after several ratchet steps', async () => {
    const { bob, bobPub, aliceCipher, bobCipher, decrypt } = await libsignalConversation(1);
    let oktzBob = JSON.stringify(bob.session.serialize());
    const oktzDecrypt = (type, body) => {
      const wire = Buffer.from(body);
      const r = type === 3
        ? native.ratchetDecryptPkmsg(oktzBob, wire, bobPub)
        : native.ratchetDecryptWhisper(oktzBob, wire, bobPub);
      oktzBob = r.sessionJson;
      return Buffer.from(r.plaintext);
    };

    for (let turn = 0; turn < 3; turn++) {
      const said = Buffer.from(`alice to bob ${turn}`);
      const out = await aliceCipher.encrypt(said);
      assert.deepStrictEqual(oktzDecrypt(out.type, out.body), said,
        `oktz-signal must decrypt libsignal turn ${turn}`);
      // oktz-signal's record goes back into libsignal's storage, so libsignal
      // replies on a chain oktz-signal ratcheted.
      bob.session = libsignal.SessionRecord.deserialize(JSON.parse(oktzBob));
      const reply = Buffer.from(`bob to alice ${turn}`);
      const back = await bobCipher.encrypt(reply);
      assert.deepStrictEqual(Buffer.from(await decrypt(aliceCipher, back)), reply,
        `libsignal must read the record oktz-signal wrote (turn ${turn})`);
    }

    // The record oktz-signal ended on is in libsignal's storage format.
    const chains = chainsOf(oktzBob);
    assert.ok(chains.every(([k]) => Buffer.from(k, 'base64').length === 33),
      'oktz-signal must key new chains by the 33-byte wire key libsignal uses');
    assert.ok(chains.every(([, c]) => c.chainType === 1 || c.chainType === 2),
      'oktz-signal must write libsignal chainType values');
  });
});

describe('the closed-chain forgery is still closed', () => {
  // Making the chain key optional so a libsignal record could be read must not
  // reopen the hole the previous wave closed: a chain with no usable key
  // material must never derive a message key, because HMAC under an empty key
  // is public knowledge and would let a forgery satisfy the real MAC.
  function forged(chainKey) {
    const alice = native.curveGenerateKeypair(crypto.randomBytes(32));
    const bob = native.curveGenerateKeypair(crypto.randomBytes(32));
    const spk = native.curveGenerateKeypair(crypto.randomBytes(32));
    const idA = P5(alice[0]), idB = P5(bob[0]), spk33 = P5(spk[0]);
    const json = native.x3DhBuildInitialSession(
      alice[1], idA, spk33, native.curveSign(bob[1], spk33, null),
      null, null, idB, spk33, 42, 1);
    const rec = JSON.parse(json);
    const entry = rec._sessions[Object.keys(rec._sessions)[0]];
    const chainId = entry.currentRatchet.ephemeralKeyPair.pubKey;
    entry._chains[chainId] = { chainKey, chainType: 0, messageKeys: {} };
    entry.pendingPreKey = null;
    return { rec: JSON.stringify(rec), idB, chainId };
  }

  // A message forged against a chain whose key was emptied, carrying the MAC
  // that empty key really does produce.
  function forgeWire(rec, idB, chainId, counter) {
    let ck = Buffer.alloc(0), messageKey;
    for (let i = 0; i < counter; i++) {
      messageKey = H(ck, Buffer.from([1]));
      ck = H(ck, Buffer.from([2]));
    }
    const keys = deriveN(messageKey, Buffer.alloc(32), 'WhisperMessageKeys', 3);
    const cipher = crypto.createCipheriv('aes-256-cbc', keys[0], keys[2].subarray(0, 16));
    const ct = Buffer.concat([
      cipher.update(Buffer.from('FORGED BY ATTACKER')), cipher.final()]);
    const msgBuf = native.protoEncodeWhisper(Buffer.from(chainId, 'base64'), counter, 0, ct);
    const mac = H(keys[1], Buffer.concat([
      Buffer.from(entryOf(rec).indexInfo.remoteIdentityKey, 'base64'),
      idB, Buffer.from([0x33]), msgBuf])).subarray(0, 8);
    return Buffer.concat([Buffer.from([0x33]), msgBuf, mac]);
  }

  for (const [label, chainKey] of [
    ['an empty chain key', { counter: 0, key: '' }],
    ['a deleted chain key', { counter: 0 }],
  ]) {
    it(`${label} can never derive a message key`, () => {
      const { rec, idB, chainId } = forged(chainKey);
      assert.throws(
        () => native.ratchetDecryptWhisper(rec, forgeWire(rec, idB, chainId, 3), idB),
        /closed/i,
        `${label} must be refused before the MAC can be satisfied`);
    });
  }

  it('a null chain key reads as a closed chain, never as usable key material', () => {
    const { rec, idB, chainId } = forged({ counter: -1, key: null });
    // serde reads null as "no key", the same state as the field being absent —
    // which is what libsignal's serializer produces. Fail closed either way.
    assert.throws(
      () => native.ratchetDecryptWhisper(rec, forgeWire(rec, idB, chainId, 3), idB),
      /closed/i,
      'a null chain key must be refused before the MAC can be satisfied');
    const round = native.sessionSerialize(native.sessionDeserialize(rec));
    assert.ok(!round.includes('"key":null'),
      'a null chain key must not be written back');
  });
});
