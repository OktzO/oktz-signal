import { createRequire } from 'module';
import { QueueJob } from '../src/queue-job.js';
import { ProtocolAddress } from '../src/protocol-address.js';
import { SessionBuilder } from '../src/session-builder.js';
import { SessionCipher } from '../src/session-cipher.js';
import { describe, it } from 'node:test';
import assert from 'node:assert';

const require = createRequire(import.meta.url);
const native = require('../native/signal/index.cjs');

describe('JS wrapper', () => {
  it('QueueJob serializes', async () => {
    const q = new QueueJob();
    let order = [];
    const fn1 = async () => { await new Promise(r => setTimeout(r, 10)); order.push(1); };
    const fn2 = async () => { order.push(2); };
    q.add('key', fn1); await q.add('key', fn2);
    assert.deepStrictEqual(order, [1, 2]);
  });
  it('ProtocolAddress toString', () => {
    assert.strictEqual(new ProtocolAddress('user', 1).toString(), 'user.1');
  });
  it('ProtocolAddress fromString', () => {
    const addr = ProtocolAddress.fromString('user.1');
    assert.strictEqual(addr.name, 'user');
    assert.strictEqual(addr.deviceId, 1);
  });
  it('crypto encrypt/decrypt roundtrip', async () => {
    const { encrypt, decrypt } = await import('../src/crypto.js');
    const key = Buffer.alloc(32, 0xAB);
    const iv = Buffer.alloc(16, 0xCD);
    const pt = Buffer.from('hello signal');
    const ct = encrypt(key, pt, iv);
    assert.deepStrictEqual(decrypt(key, ct, iv), pt);
  });
  it('crypto deriveSecrets length', async () => {
    const { deriveSecrets } = await import('../src/crypto.js');
    const res = deriveSecrets(Buffer.alloc(32, 1), Buffer.alloc(32, 2), Buffer.from('test'));
    assert.strictEqual(res.length, 3);
    assert.strictEqual(res[0].length, 32);
  });
});

// ─────────────────────────────────────────────────────────────────────
// Full X3DH roundtrip through the JS wrapper: initOutgoing → encrypt
// (type 3) → initIncoming → decryptPreKeyWhisperMessage → reply (type 1)
// → decryptWhisperMessage. Uses 33-byte (0x05-prefixed) public keys to
// exercise the strip05 normalization on the native boundary.
// ─────────────────────────────────────────────────────────────────────
describe('JS wrapper X3DH roundtrip', () => {
  // In-memory storage for one party.
  function makeStorage(identity, regId, signedPreKeyPair, preKeys = new Map()) {
    let session = null;
    return {
      getOurIdentity: async () => identity,
      getOurRegistrationId: async () => regId,
      loadSignedPreKey: async () => signedPreKeyPair,
      loadPreKey: async (id) => preKeys.get(id) || null,
      loadSession: async () => session,
      storeSession: async (id, s) => { session = s; },
    };
  }

  // 33-byte identity pubkey (0x05-prefixed), 32-byte signed prekey.
  function identityOf(priv) {
    return Buffer.concat([Buffer.from([0x05]), native.curveGenerateKeypair(priv)[0]]);
  }

  it('initOutgoing → encrypt type 3 → initIncoming → decrypt → reply', async () => {
    const alicePriv = Buffer.alloc(32, 0x11);
    const bobPriv = Buffer.alloc(32, 0x22);
    const alicePub33 = identityOf(alicePriv);
    const bobPub33 = identityOf(bobPriv);
    const spkPriv = Buffer.alloc(32, 0x33);
    const spkPub = native.curveGenerateKeypair(spkPriv)[0];
    const spkSig = native.curveSign(bobPriv, Buffer.from(spkPub), null);
    const opkPriv = Buffer.alloc(32, 0x44);
    const opkPub = native.curveGenerateKeypair(opkPriv)[0];

    const aliceStorage = makeStorage(
      { privKey: alicePriv, pubKey: alicePub33 },
      111,
      null,
    );
    const bobStorage = makeStorage(
      { privKey: bobPriv, pubKey: bobPub33 },
      222,
      // signed prekey pair: pub is 33-byte to exercise strip05
      { privKey: spkPriv, pubKey: Buffer.concat([Buffer.from([0x05]), spkPub]) },
      new Map([[7, { privKey: opkPriv, pubKey: Buffer.concat([Buffer.from([0x05]), opkPub]) }]]),
    );

    const aliceAddr = new ProtocolAddress('bob-device', 1);
    const bobAddr = new ProtocolAddress('alice-device', 1);

    // Alice builds outgoing session from Bob's device bundle (33-byte keys).
    const aliceBuilder = new SessionBuilder(aliceStorage, aliceAddr);
    await aliceBuilder.initOutgoing({
      identityKey: bobPub33,
      signedPreKey: {
        keyId: 5,
        publicKey: Buffer.concat([Buffer.from([0x05]), spkPub]),
        signature: spkSig,
      },
      preKey: { keyId: 7, publicKey: Buffer.concat([Buffer.from([0x05]), opkPub]) },
      registrationId: 42,
    });

    // Alice encrypts → first message is type 3 (PreKeyWhisperMessage).
    const aliceCipher = new SessionCipher(aliceStorage, aliceAddr);
    const { type, body } = await aliceCipher.encrypt(Buffer.from('hello bob'));
    assert.strictEqual(type, 3, 'first message must be type 3 (PKMsg)');
    assert.strictEqual(body[0], 0x33);

    // Bob decrypts the PreKeyWhisperMessage → initIncoming builds session.
    const bobCipher = new SessionCipher(bobStorage, bobAddr);
    const plaintext = await bobCipher.decryptPreKeyWhisperMessage(body);
    assert.deepStrictEqual(plaintext, Buffer.from('hello bob'));

    // Bob replies → type 1 (no pendingPreKey on recipient).
    const reply = await bobCipher.encrypt(Buffer.from('hi alice'));
    assert.strictEqual(reply.type, 1, 'recipient reply must be type 1');

    // Alice decrypts the reply.
    const replyPlain = await aliceCipher.decryptWhisperMessage(reply.body);
    assert.deepStrictEqual(replyPlain, Buffer.from('hi alice'));
  });
});
