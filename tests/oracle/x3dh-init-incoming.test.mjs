import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const native = require('../../native/signal/index.cjs');
const { randomBytes } = require('node:crypto');
import { describe, it } from 'node:test';
import assert from 'node:assert';
import * as libsignal from 'libsignal';
import { SessionBuilder, SessionCipher, ProtocolAddress } from '../../index.js';

// The existing oracle suite has a real libsignal Bob do the session
// establishment: libsignal's own initIncoming consumes the prekey message, and
// oktz-signal is handed the record libsignal wrote. That proves the ratchet.
//
// It does not exercise the other direction, and that is the direction production
// depends on. Every session the bot has ever tried to build arrives as a
// libsignal-produced PreKeyWhisperMessage that oktz-signal's own initIncoming
// must consume against a prekey bundle it fetched itself. Nothing in the suite
// covered that call, so a defect in it would pass every test here while making
// session formation impossible in the field.
//
// The evidence from the field is that session formation never succeeds: on a
// live database, session_keys held 837 uploaded prekeys with zero consumed,
// zero identity keys, and one peer session. Those are the numbers this file
// exists to either explain or contradict.

// libsignal.curve already returns 33-byte wire keys, so no prefixing here.
const wire = (k) => Buffer.from(k);

function identities() {
  const alicePriv = randomBytes(32);
  const bobPriv = randomBytes(32);
  const alicePub = libsignal.curve.getPublicFromPrivateKey(alicePriv);
  const bobPub = libsignal.curve.getPublicFromPrivateKey(bobPriv);
  const bobSpk = libsignal.curve.generateKeyPair(randomBytes(32));
  const bobOne = libsignal.curve.generateKeyPair(randomBytes(32));
  const aliceSpk = libsignal.curve.generateKeyPair(randomBytes(32));
  return {
    alicePriv, bobPriv, alicePub, bobPub,
    bobSpk, bobOne,
    bobSpkSig: Buffer.from(native.curveSign(bobPriv, bobSpk.pubKey, null)),
    aliceSpkSig: Buffer.from(native.curveSign(alicePriv, aliceSpk.pubKey, null)),
  };
}

/** oktz-signal storage shaped like the one lib/Signal/libsignal.js builds. */
function oktzStorage({ identityPriv, identityPub, spk, onePreKey, regId, consumed }) {
  const session = { record: null };
  return {
    session,
    storage: {
      loadSession: async () => session.record,
      storeSession: async (_id, rec) => { session.record = rec; },
      isTrustedIdentity: () => true,
      loadPreKey: async (id) => {
        if (id !== undefined && Number(id) !== onePreKey.id) return undefined;
        return consumed.has(Number(id)) ? undefined : onePreKey;
      },
      removePreKey: async (id) => { consumed.add(Number(id)); },
      // Matches libsignal.js: takes no id, returns the current signed prekey.
      loadSignedPreKey: async () => spk,
      loadIdentityKey: async () => identityPub,
      saveIdentity: async () => false,
      getOurRegistrationId: () => regId,
      getOurIdentity: () => ({ privKey: identityPriv, pubKey: identityPub }),
    },
  };
}

// initIncoming takes the DECODED pkmsg object, not the raw wire bytes — the
// production path decodes first in decryptPreKeyWhisperMessage.
const decode = (body) => native.protoDecodePkmsg(Buffer.from(Buffer.from(body).subarray(1)));

describe('X3DH oracle: libsignal sender → oktz-signal session establishment', () => {
  it('oktz initIncoming consumes a libsignal pkmsg against a real prekey bundle', async () => {
    const k = identities();
    const toBob = new libsignal.ProtocolAddress('bob', 1);
    const toAlice = new libsignal.ProtocolAddress('alice', 1);
    const BOB_SPK_ID = 1;
    const BOB_OPK_ID = 7;

    // Alice (libsignal) starts a conversation with a bundle Bob published.
    const aliceStore = { session: null, storage: {
      loadSession: async () => aliceStore.session,
      storeSession: async (_i, s) => { aliceStore.session = s; },
      isTrustedIdentity: () => true,
      loadPreKey: async () => null,
      removePreKey: async () => {},
      loadSignedPreKey: async () => ({ privKey: k.aliceSpk.privKey, pubKey: k.aliceSpk.pubKey }),
      getOurRegistrationId: () => 555,
      getOurIdentity: () => ({ privKey: k.alicePriv, pubKey: k.alicePub }),
    } };

    await new libsignal.SessionBuilder(aliceStore.storage, toBob).initOutgoing({
      identityKey: wire(k.bobPub),
      signedPreKey: { keyId: BOB_SPK_ID, publicKey: wire(k.bobSpk.pubKey), signature: k.bobSpkSig },
      preKey: { keyId: BOB_OPK_ID, publicKey: wire(k.bobOne.pubKey) },
      registrationId: 777,
    });

    const aliceCipher = new libsignal.SessionCipher(aliceStore.storage, toBob);
    const first = await aliceCipher.encrypt(Buffer.from('hello from libsignal'));
    assert.strictEqual(first.type, 3, 'the first message must be a PreKeyWhisperMessage');

    // Bob is oktz-signal, with the bundle it fetched and uploaded itself.
    const consumed = new Set();
    const bob = oktzStorage({
      identityPriv: k.bobPriv,
      identityPub: wire(k.bobPub),
      spk: { privKey: k.bobSpk.privKey, pubKey: k.bobSpk.pubKey },
      onePreKey: { id: BOB_OPK_ID, privKey: k.bobOne.privKey, pubKey: k.bobOne.pubKey },
      regId: 777,
      consumed,
    });
    const bobAddr = new ProtocolAddress('bob', 1);

    // The untested call: oktz-signal establishes the session from the pkmsg.
    const built = await new SessionBuilder(bob.storage, bobAddr).initIncoming(null, decode(first.body));
    assert.ok(built, 'initIncoming must return a record');
    assert.ok(
      JSON.parse(built.serialize())._sessions,
      'the record must contain sessions — an empty one means X3DH silently failed'
    );

    // And the record must actually decrypt the message it was built for. This is
    // also the step that creates the SENDING chain, which is why the record the
    // real path persists is result.sessionJson and not what initIncoming returned.
    const result = native.ratchetDecryptPkmsg(built.serialize(), Buffer.from(first.body), wire(k.bobPub));
    assert.deepStrictEqual(
      Buffer.from(result.plaintext), Buffer.from('hello from libsignal'),
      'oktz initIncoming produced a record that cannot decrypt the pkmsg it came from'
    );

    await bob.storage.storeSession(bobAddr.toString(), new (await import('../../index.js')).SessionRecord(result.sessionJson));

    // Reply must go back to libsignal, proving the two agree on the ratchet state.
    const bobCipher = new SessionCipher(bob.storage, bobAddr);
    const reply = await bobCipher.encrypt(Buffer.from('reply from oktz'));
    const back = await new libsignal.SessionCipher(aliceStore.storage, toAlice)
      .decryptWhisperMessage(reply.body);
    assert.deepStrictEqual(back, Buffer.from('reply from oktz'),
      'libsignal could not decrypt oktz-signal\'s reply — the ratchets diverged');

    // initIncoming must NOT burn the prekey: at this point the pkmsg has not
    // been authenticated — the MAC that proves it is only checked by
    // ratchetDecryptPkmsg. Burning here would let one unauthenticated message
    // destroy a one-time key. The burn belongs to decryptPreKeyWhisperMessage,
    // after the MAC passes.
    assert.ok(!consumed.has(BOB_OPK_ID),
      'initIncoming must not consume the one-time prekey before the pkmsg MAC verifies');
  });

  it('rejects a pkmsg naming a prekey this device never published', async () => {
    const k = identities();
    const toBob = new libsignal.ProtocolAddress('bob', 1);
    const aliceStore = { session: null, storage: {
      loadSession: async () => aliceStore.session,
      storeSession: async (_i, s) => { aliceStore.session = s; },
      isTrustedIdentity: () => true,
      loadPreKey: async () => null,
      removePreKey: async () => {},
      loadSignedPreKey: async () => ({ privKey: k.aliceSpk.privKey, pubKey: k.aliceSpk.pubKey }),
      getOurRegistrationId: () => 555,
      getOurIdentity: () => ({ privKey: k.alicePriv, pubKey: k.alicePub }),
    } };
    await new libsignal.SessionBuilder(aliceStore.storage, toBob).initOutgoing({
      identityKey: wire(k.bobPub),
      signedPreKey: { keyId: 1, publicKey: wire(k.bobSpk.pubKey), signature: k.bobSpkSig },
      preKey: { keyId: 999, publicKey: wire(k.bobOne.pubKey) },
      registrationId: 777,
    });
    const first = await new libsignal.SessionCipher(aliceStore.storage, toBob)
      .encrypt(Buffer.from('hello'));

    // Bob holds a different prekey id, so the bundle does not cover this message.
    const bob = oktzStorage({
      identityPriv: k.bobPriv,
      identityPub: wire(k.bobPub),
      spk: { privKey: k.bobSpk.privKey, pubKey: k.bobSpk.pubKey },
      onePreKey: { id: 4242, privKey: k.bobOne.privKey, pubKey: k.bobOne.pubKey },
      regId: 777,
      consumed: new Set(),
    });
    const bobAddr = new ProtocolAddress('bob', 1);

    // Must fail here with a prekey-specific error, not later as a MAC error
    // against a message that was never going to verify.
    await assert.rejects(
      new SessionBuilder(bob.storage, bobAddr).initIncoming(null, decode(first.body)),
      /Missing prekey/,
      'an unresolvable prekey must be named as such'
    );
  });
});
