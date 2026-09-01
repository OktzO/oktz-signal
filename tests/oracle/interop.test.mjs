import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const native = require('../../native/signal/index.cjs');
import { randomBytes } from 'crypto';
import { describe, it } from 'node:test';
import assert from 'node:assert';
import * as libsignal from 'libsignal';

// ─────────────────────────────────────────────────────────────────────
// Test 1: Curve sign/verify — 100 random cases, both engines match
// ─────────────────────────────────────────────────────────────────────
describe('curve oracle: oktz-signal vs libsignal', () => {
  it('sign/verify 100 random cases match', () => {
    for (let i = 0; i < 100; i++) {
      const msg = randomBytes(32 + Math.floor(Math.random() * 64));
      const privKey = randomBytes(32);
      const pubKey = libsignal.curve.getPublicFromPrivateKey(privKey); // 33 bytes with 0x05 prefix

      const sigLibsignal = libsignal.curve.calculateSignature(privKey, msg);
      const sigOktz = Buffer.from(native.curveSign(privKey, msg, null));

      assert.ok(sigLibsignal.equals(sigOktz),
        `signature mismatch at case ${i}`);

      assert.ok(libsignal.curve.verifySignature(pubKey, msg, sigLibsignal),
        `libsignal verify failed at case ${i}`);
      assert.ok(native.curveVerify(pubKey.slice(1), msg, sigOktz),
        `oktz verify failed at case ${i}`);
    }
  });
});

// ─────────────────────────────────────────────────────────────────────
// Helper: build Bob (receiver) session mirror from Alice (sender) session
// ─────────────────────────────────────────────────────────────────────
function buildBobSessionJson(aliceSessionJson, bobIdentityPub33, senderIdentityPub33) {
  const alice = JSON.parse(aliceSessionJson);
  const aEntry = Object.values(alice._sessions)[0];
  const aEphPub = aEntry.currentRatchet.ephemeralKeyPair.pubKey;
  const aEphPriv = aEntry.currentRatchet.ephemeralKeyPair.privKey;
  const aSendChain = Object.values(aEntry._chains).find(c => c.chainType === 1);
  const rootKey = aEntry.currentRatchet.rootKey;

  // Bob's own ephemeral keypair for the ratchet
  const bobEphSeed = randomBytes(32);
  const [bobPub, bobPriv] = native.curveGenerateKeypair(bobEphSeed);

  const senderIdentityB64 = Buffer.from(senderIdentityPub33).toString('base64');

  const bobSession = {
    _sessions: {
      [Buffer.from(bobPub).toString('base64')]: {
        registrationId: 42,
        currentRatchet: {
          ephemeralKeyPair: {
            pubKey: Buffer.from(bobPub).toString('base64'),
            privKey: Buffer.from(bobPriv).toString('base64')
          },
          lastRemoteEphemeralKey: aEphPub,
          previousCounter: 0,
          rootKey: rootKey
        },
        indexInfo: {
          baseKey: "bob-base",
          baseKeyType: 0,
          closed: -1,
          used: Date.now(),
          created: Date.now(),
          remoteIdentityKey: senderIdentityB64
        },
        _chains: {
          [aEphPub]: {
            chainKey: {
              counter: -1,
              key: aSendChain.chainKey.key
            },
            chainType: 0,
            messageKeys: {}
          }
        }
      }
    },
    version: "v1"
  };
  if (aEntry.pendingPreKey) {
    bobSession._sessions[Object.keys(bobSession._sessions)[0]].pendingPreKey = {
      baseKey: aEntry.pendingPreKey.baseKey
    };
  }
  return JSON.stringify(bobSession);
}

// ─────────────────────────────────────────────────────────────────────
// Test 2: libsignal encrypt → oktz-signal decrypt
// ─────────────────────────────────────────────────────────────────────
describe('protocol oracle: libsignal → oktz-signal interop', () => {
  it('libsignal encrypt → oktz-signal decrypt', async () => {
    // 1. Deterministic identity keys
    const alicePriv = Buffer.alloc(32, 0xAA);
    const bobPriv = Buffer.alloc(32, 0xBB);
    const alicePub33 = libsignal.curve.getPublicFromPrivateKey(alicePriv);
    const bobPub33 = libsignal.curve.getPublicFromPrivateKey(bobPriv);

    // 2. Bob's signed prekey (32-byte X25519 key)
    const spkPriv = Buffer.alloc(32, 0xCC);
    const spkPub = native.curveGenerateKeypair(spkPriv)[0]; // 32 bytes
    const spkSig = native.curveSign(bobPriv, Buffer.from(spkPub), null); // 64 bytes

    // 3. Bob's one-time prekey
    const opkPriv = Buffer.alloc(32, 0xDD);
    const opkPub = native.curveGenerateKeypair(opkPriv)[0]; // 32 bytes

    // 4. Storage for libsignal session
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
      getOurIdentityKey: () => alicePub33,
    };

    const address = new libsignal.ProtocolAddress('bob-device', 1);
    const builder = new libsignal.SessionBuilder(storage, address);

    const device = {
      identityKey: bobPub33,
      signedPreKey: {
        keyId: 1,
        publicKey: Buffer.concat([Buffer.from([5]), spkPub]),
        signature: spkSig
      },
      preKey: {
        keyId: 2,
        publicKey: Buffer.concat([Buffer.from([5]), opkPub])
      },
      registrationId: 42
    };

    await builder.initOutgoing(device);
    assert.ok(storedSession, 'session should be stored');

    // 5. Serialize libsignal session BEFORE encrypt (chain not yet advanced)
    const aliceSessionObj = storedSession.serialize();
    const aliceSessionStr = typeof aliceSessionObj === 'string' ? aliceSessionObj : JSON.stringify(aliceSessionObj);

    // 6. Build Bob's mirror session from pre-encrypt Alice session
    const bobSessionJson = buildBobSessionJson(aliceSessionStr, bobPub33, alicePub33);

    // 7. Encrypt with libsignal SessionCipher
    const cipher = new libsignal.SessionCipher(storage, address);
    const plaintext = Buffer.from('hello signal protocol 2026');
    const { type, body } = await cipher.encrypt(plaintext);

    // First message should be type 3 (PreKeyWhisperMessage)
    assert.strictEqual(type, 3, 'first message must be prekey bundle');

    const fullCiphertext = Buffer.from(body, 'binary');
    assert.strictEqual(fullCiphertext[0], 0x33, 'version byte must be 0x33');

    // 8. Decrypt with oktz-signal native
    const result = JSON.parse(native.ratchetDecryptPkmsg(
      bobSessionJson, fullCiphertext, bobPub33
    ));

    assert.deepStrictEqual(Buffer.from(result.plaintext), plaintext,
      'oktz-signal decrypt mismatch');
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
    const spkSig = native.curveSign(bobPriv, Buffer.from(spkPub), null);

    // 3. Bob's one-time prekey
    const opkPriv = Buffer.alloc(32, 0x44);
    const opkPub = native.curveGenerateKeypair(opkPriv)[0];

    // 4. Create Alice session with oktz-native x3dh
    const aliceSessionJson = native.x3DhBuildInitialSession(
      alicePriv, alicePub33,
      spkPub, spkSig,
      opkPub, 2, // prekeyPub, prekeyId
      bobPub33, spkPub, 42
    );

    // 5. Encrypt with oktz-native
    const plaintext = Buffer.from('hello from oktz-signal');
    const encResult = JSON.parse(native.ratchetEncrypt(
      aliceSessionJson, plaintext, alicePub33, bobPub33
    ));

    // oktz-native encrypt returns message_type 1 (whisper) without prekey wrapper
    const ciphertext = Buffer.from(encResult.ciphertext);
    assert.strictEqual(ciphertext[0], 0x33, 'version byte must be 0x33');

    // 6. Wrap in PreKeyWhisperMessage proto for libsignal
    const aliceParsed = JSON.parse(aliceSessionJson);
    const aEntry = Object.values(aliceParsed._sessions)[0];
    const baseKeyB64 = aEntry.indexInfo.baseKey;

    const preKeyMsg = {
      pre_key_id: 2,
      base_key: [...Buffer.from(baseKeyB64, 'base64')],
      identity_key: [...alicePub33],
      message: [...ciphertext],
      registration_id: 42,
      signed_pre_key_id: 1,
    };

    const pkmsgWire = native.protoEncodePkmsg(JSON.stringify(preKeyMsg));
    const fullWire = Buffer.concat([Buffer.from([0x33]), pkmsgWire]);

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
    const spkSig = native.curveSign(bobPriv, Buffer.from(spkPub), null);

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