import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const native = require('../../native/signal/index.cjs');
import { randomBytes } from 'crypto';
import { describe, it } from 'node:test';
import assert from 'node:assert';
import * as libsignal from 'libsignal';

// ─────────────────────────────────────────────────────────────────────
// Test 1: Curve sign/verify — 100 random cases, both engines agree
//
// The signature BYTES can no longer be compared against libsignal.
// `libsignal.curve.calculateSignature(privKey, message)` takes two
// arguments and hard-codes curve25519-js's `crypto_sign_direct`, whose
// nonce is the deterministic SHA512(sk||m); it exposes no way to inject
// `opt_random`. oktz deliberately draws a CSPRNG nonce when `rnd` is
// absent, so the two engines pick different nonces on purpose (RFC 8032
// hashes a random prefix so that two chosen-message signatures cannot
// recover the identity key). Bit-exactness of the deterministic path is
// pinned instead by `curve::tests::test_xeddsa_known_answer`, whose
// expected signature is taken from curve25519-js.
//
// What this test still proves byte-for-byte is public key derivation, and
// it proves the signing/verifying pair agrees by verifying in BOTH
// directions across 100 random cases.
// ─────────────────────────────────────────────────────────────────────
describe('curve oracle: oktz-signal vs libsignal', () => {
  it('pubkey derivation is byte-identical, signatures cross-verify, 100 random cases', () => {
    for (let i = 0; i < 100; i++) {
      const msg = randomBytes(32 + Math.floor(Math.random() * 64));
      const privKey = randomBytes(32);
      const pubKey = libsignal.curve.getPublicFromPrivateKey(privKey); // 33 bytes with 0x05 prefix

      assert.ok(
        native.curveGenerateKeypair(privKey)[0].equals(pubKey.slice(1)),
        `public key derivation mismatch at case ${i}`);

      const sigLibsignal = libsignal.curve.calculateSignature(privKey, msg);
      const sigOktz = Buffer.from(native.curveSign(privKey, msg, null));

      assert.ok(libsignal.curve.verifySignature(pubKey, msg, sigOktz),
        `libsignal could not verify the oktz signature at case ${i}`);
      assert.ok(native.curveVerify(pubKey.slice(1), msg, sigLibsignal),
        `oktz could not verify the libsignal signature at case ${i}`);
    }
  });
});

// ─────────────────────────────────────────────────────────────────────
// Test 2: a record libsignal produced, decrypted by oktz-signal
//
// The earlier version of this test hand-built the receiver's record in
// oktz's own shape — including its own `chainType: 0` and 32-byte chain
// keys — so it could only ever prove oktz agrees with itself. Here libsignal
// owns BOTH endpoints and writes the receiver's record itself; oktz-signal is
// dropped in as that receiver's SessionCipher. Every field the decrypt path
// reads is a field libsignal chose.
// ─────────────────────────────────────────────────────────────────────

const chainEntries = (json) =>
  Object.entries(Object.values(JSON.parse(json)._sessions)[0]._chains);

// Guards that the record under test really is libsignal's and not something
// oktz-shaped: libsignal keys _chains by the 33-byte wire public key
// (session_record.js addChain/getChain) and marks a receiving chain
// chainType RECEIVING === 2 (chain_type.js).
function assertLibsignalReceiverRecord(json) {
  const chains = chainEntries(json);
  assert.ok(chains.length > 0, 'the receiver record must have chains');
  for (const [key, chain] of chains) {
    assert.strictEqual(Buffer.from(key, 'base64').length, 33,
      `chain key must be libsignal's 33-byte wire key, got ${Buffer.from(key, 'base64').length}`);
    assert.ok(chain.chainType === 1 || chain.chainType === 2,
      `chainType must be a libsignal ChainType, got ${chain.chainType}`);
  }
  assert.ok(chains.some(([, c]) => c.chainType === 2),
    'the receiver record must contain a libsignal RECEIVING (2) chain');
}

// libsignal storages, one per endpoint. `record` is swapped freely so a
// record oktz wrote can be handed straight back to libsignal.
function libStorage(identityPriv, identityPub, spk, regId) {
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

// Two real libsignal identities plus Bob's signed prekey.
function libIdentities() {
  const alicePriv = randomBytes(32), bobPriv = randomBytes(32);
  const alicePub = libsignal.curve.getPublicFromPrivateKey(alicePriv);
  const bobPub = libsignal.curve.getPublicFromPrivateKey(bobPriv);
  const spk = libsignal.curve.generateKeyPair(randomBytes(32));
  const spkSig = Buffer.from(native.curveSign(bobPriv, spk.pubKey, null));
  return { alicePriv, bobPriv, alicePub, bobPub, spk, spkSig };
}

describe('protocol oracle: libsignal → oktz-signal interop', () => {
  it('decrypts a libsignal message with the receiver record libsignal itself stored', async () => {
    const k = libIdentities();
    const alice = libStorage(k.alicePriv, k.alicePub, k.spk, 111);
    const bob = libStorage(k.bobPriv, k.bobPub, k.spk, 222);
    const toBob = new libsignal.ProtocolAddress('bob', 1);
    const toAlice = new libsignal.ProtocolAddress('alice', 1);

    await new libsignal.SessionBuilder(alice.storage, toBob).initOutgoing({
      identityKey: k.bobPub,
      signedPreKey: { keyId: 1, publicKey: k.spk.pubKey, signature: k.spkSig },
      preKey: null,
      registrationId: 42,
    });

    const aliceCipher = new libsignal.SessionCipher(alice.storage, toBob);
    const bobCipher = new libsignal.SessionCipher(bob.storage, toAlice);

    // libsignal's own Bob consumes the first (prekey) message, so the record
    // oktz-signal is about to read is one libsignal wrote and libsignal read.
    const first = await aliceCipher.encrypt(Buffer.from('first, consumed by libsignal'));
    assert.strictEqual(first.type, 3, 'first message must be a PreKeyWhisperMessage');
    assert.deepStrictEqual(await bobCipher.decryptPreKeyWhisperMessage(first.body),
      Buffer.from('first, consumed by libsignal'));

    const bobRecord = JSON.stringify(bob.session.serialize());
    assertLibsignalReceiverRecord(bobRecord);

    // The next message is encrypted by libsignal and decrypted by oktz-signal
    // from that record — no part of the record is synthesised here.
    const plaintext = Buffer.from('hello from libsignal, decrypted by oktz-signal');
    const { type, body } = await aliceCipher.encrypt(plaintext);
    // libsignal's sender keeps pendingPreKey until it receives a reply
    // (session_cipher.js deletes it only in doDecryptWhisperMessage), so every
    // message on this leg is a PreKeyWhisperMessage.
    assert.strictEqual(type, 3, 'sender still wraps as PreKeyWhisperMessage');
    assert.strictEqual(body[0], 0x33, 'version byte must be 0x33');

    const result = native.ratchetDecryptPkmsg(bobRecord, Buffer.from(body), k.bobPub);
    assert.deepStrictEqual(Buffer.from(result.plaintext), plaintext,
      'oktz-signal decrypt mismatch');
  });

  it('completes a bidirectional conversation across DH ratchet steps', async () => {
    const k = libIdentities();
    const alice = libStorage(k.alicePriv, k.alicePub, k.spk, 111);
    const bob = libStorage(k.bobPriv, k.bobPub, k.spk, 222);
    const toBob = new libsignal.ProtocolAddress('bob', 1);
    const toAlice = new libsignal.ProtocolAddress('alice', 1);

    await new libsignal.SessionBuilder(alice.storage, toBob).initOutgoing({
      identityKey: k.bobPub,
      signedPreKey: { keyId: 1, publicKey: k.spk.pubKey, signature: k.spkSig },
      preKey: null,
      registrationId: 42,
    });

    const aliceCipher = new libsignal.SessionCipher(alice.storage, toBob);
    const bobCipher = new libsignal.SessionCipher(bob.storage, toAlice);

    // Decrypt one prekey message with libsignal so the receiver record exists.
    const first = await aliceCipher.encrypt(Buffer.from('bootstrap'));
    await bobCipher.decryptPreKeyWhisperMessage(first.body);

    // oktz-signal takes over Bob's SessionCipher. Every turn: libsignal
    // encrypts with its own record, oktz-signal decrypts and hands the updated
    // record back to libsignal's storage, which encrypts the reply. Each
    // direction change is a DH ratchet step in both engines.
    let oktzBob = JSON.stringify(bob.session.serialize());
    const oktzDecrypt = (type, body) => {
      const wire = Buffer.from(body);
      const result = type === 3
        ? native.ratchetDecryptPkmsg(oktzBob, wire, k.bobPub)
        : native.ratchetDecryptWhisper(oktzBob, wire, k.bobPub);
      oktzBob = result.sessionJson;
      return Buffer.from(result.plaintext);
    };

    for (let turn = 0; turn < 4; turn++) {
      const say = Buffer.from(`alice->bob turn ${turn}`);
      const out = await aliceCipher.encrypt(say);
      assert.deepStrictEqual(oktzDecrypt(out.type, out.body), say,
        `oktz-signal must decrypt libsignal turn ${turn}`);

      // oktz-signal's record goes back into libsignal's storage; libsignal
      // replies from it, so the reply is encrypted on a chain oktz ratcheted.
      bob.session = libsignal.SessionRecord.deserialize(JSON.parse(oktzBob));
      const reply = Buffer.from(`bob->alice turn ${turn}`);
      const back = await bobCipher.encrypt(reply);
      assert.deepStrictEqual(
        Buffer.from(await aliceCipher.decryptWhisperMessage(back.body)), reply,
        `libsignal must decrypt the reply oktz-signal's ratchet produced (turn ${turn})`);
    }

    // Close the loop: the reply libsignal just produced is decrypted by
    // oktz-signal from the record it wrote, not from libsignal's.
    const last = Buffer.from('closing message');
    const out = await aliceCipher.encrypt(last);
    assert.deepStrictEqual(oktzDecrypt(out.type, out.body), last);
  });
});

// ─────────────────────────────────────────────────────────────────────
// Test 3: oktz-signal encrypt → libsignal decrypt
// ─────────────────────────────────────────────────────────────────────
describe('protocol oracle: oktz-signal → libsignal interop', () => {
  it('oktz-signal encrypt → libsignal decrypt', async () => {
    // 1. Deterministic identity keys
    const alicePriv = Buffer.alloc(32, 0x11);
    const bobPriv = Buffer.alloc(32, 0x22);
    const alicePub33 = Buffer.concat([Buffer.from([5]), native.curveGenerateKeypair(alicePriv)[0]]);
    const bobPub33 = Buffer.concat([Buffer.from([5]), native.curveGenerateKeypair(bobPriv)[0]]);

    // 2. Bob's signed prekey
    const spkPriv = Buffer.alloc(32, 0x33);
    const spkPub = native.curveGenerateKeypair(spkPriv)[0]; // 32 bytes
    const spkSig = native.curveSign(bobPriv, Buffer.concat([Buffer.from([5]), spkPub]), null);

    // 3. Bob's one-time prekey
    const opkPriv = Buffer.alloc(32, 0x44);
    const opkPub = native.curveGenerateKeypair(opkPriv)[0];

    // 4. Create Alice session with oktz-native x3dh
    const aliceSessionJson = native.x3DhBuildInitialSession(
      alicePriv, alicePub33,
      Buffer.concat([Buffer.from([5]), spkPub]), spkSig,
      opkPub, 2, // prekeyPub, prekeyId
      bobPub33, spkPub, 42, 1 // signed_key_id
    );

    // 5. Encrypt with oktz-native — returns type 3 (PKMsg) since pendingPreKey set.
    // Remote identity is now derived natively from the session record.
    const plaintext = Buffer.from('hello from oktz-signal');
    const encResult = native.ratchetEncrypt(
      aliceSessionJson, plaintext, alicePub33, 42
    );
    assert.strictEqual(encResult.messageType, 3, 'first message must be type 3 (PKMsg)');

    // encResult.ciphertext is already [0x33] || encode_pkmsg(PreKeyWhisperMessage)
    // which is exactly what libsignal expects — pass it directly.
    const fullWire = Buffer.from(encResult.ciphertext);

    // 7. Decrypt with libsignal SessionCipher via initIncoming
    let bobStored = null;
    const bobStorage = {
      loadSession: async () => bobStored,
      storeSession: async (id, s) => { bobStored = s; },
      isTrustedIdentity: () => true,
      loadPreKey: async (id) => {
        assert.strictEqual(id, 2);
        return { privKey: opkPriv, pubKey: Buffer.concat([Buffer.from([5]), opkPub]) };
      },
      removePreKey: async () => {},
      loadSignedPreKey: async () => ({ privKey: spkPriv, pubKey: Buffer.concat([Buffer.from([5]), spkPub]) }),
      getOurRegistrationId: () => 42,
      getOurIdentity: () => ({ privKey: bobPriv, pubKey: bobPub33 }),
      saveIdentity: async () => false,
      loadSenderKey: async () => null,
      storeSenderKey: async () => {},
    };

    const bobAddr = new libsignal.ProtocolAddress('alice-device', 1);
    const bobCipher = new libsignal.SessionCipher(bobStorage, bobAddr);
    const decrypted = await bobCipher.decryptPreKeyWhisperMessage(fullWire);

    assert.deepStrictEqual(decrypted, plaintext,
      'libsignal decrypt of oktz ciphertext mismatch');
  });
});

// ─────────────────────────────────────────────────────────────────────
// Test 4: Session record roundtrip
// ─────────────────────────────────────────────────────────────────────
describe('session record oracle', () => {
  it('libsignal session serialized → oktz-signal deserialize', async () => {
    const alicePriv = Buffer.alloc(32, 0x55);
    const bobPriv = Buffer.alloc(32, 0x66);
    const alicePub33 = libsignal.curve.getPublicFromPrivateKey(alicePriv);
    const bobPub33 = libsignal.curve.getPublicFromPrivateKey(bobPriv);
    const spkPriv = Buffer.alloc(32, 0x77);
    const spkPub = native.curveGenerateKeypair(spkPriv)[0];
    const spkSig = native.curveSign(bobPriv, Buffer.concat([Buffer.from([5]), spkPub]), null);

    let storedSession = null;
    const storage = {
      loadSession: async () => storedSession,
      storeSession: async (id, s) => { storedSession = s; },
      isTrustedIdentity: () => true,
      loadPreKey: async () => null,
      removePreKey: async () => {},
      loadSignedPreKey: async () => ({ privKey: spkPriv, pubKey: Buffer.concat([Buffer.from([5]), spkPub]) }),
      getOurRegistrationId: () => 12345,
      getOurIdentity: () => ({ privKey: alicePriv, pubKey: alicePub33 }),
    };

    const address = new libsignal.ProtocolAddress('bob-device', 1);
    const builder = new libsignal.SessionBuilder(storage, address);
    await builder.initOutgoing({
      identityKey: bobPub33,
      signedPreKey: { keyId: 1, publicKey: Buffer.concat([Buffer.from([5]), spkPub]), signature: spkSig },
      preKey: null,
      registrationId: 42
    });

    const sessionJson = storedSession.serialize();
    const sessionStr = typeof sessionJson === 'string' ? sessionJson : JSON.stringify(sessionJson);

    const deserialized = JSON.parse(native.sessionDeserialize(sessionStr));
    assert.ok(deserialized._sessions, 'has sessions');
    assert.strictEqual(deserialized.version, 'v1', 'version is v1');
    const entry = Object.values(deserialized._sessions)[0];
    assert.strictEqual(entry.registrationId, 42, 'registrationId matches');
    assert.strictEqual(entry.indexInfo.closed, -1, 'session is open');
    assert.ok(entry.currentRatchet.rootKey, 'has rootKey');
    assert.ok(entry._chains, 'has chains');
    assert.ok(Object.values(entry._chains).length > 0, 'has at least one chain');

    // Verify roundtrip: serialize again
    const serialized2 = native.sessionSerialize(deserialized._sessions ? sessionStr : '{}');
    const parsed2 = JSON.parse(serialized2);
    assert.deepStrictEqual(parsed2, deserialized, 'session roundtrip matches');
  });
});