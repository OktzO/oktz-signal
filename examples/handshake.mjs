// examples/handshake.mjs — the whole protocol, end to end, with no peer.
//
// Bob publishes a prekey bundle. Alice runs X3DH against it and sends her first
// message. Bob has never seen her before, so his first step is a PreKey
// session built from the incoming message. Bob replies, Alice decrypts, and
// the two are in a Double Ratchet session.
//
//   node examples/handshake.mjs
//
// Import specifier: this file runs from a checkout, so it imports the package
// entry by relative path. From an installed package the specifier is
// 'oktz-signal' and nothing else changes.

import { randomBytes } from 'node:crypto';
import { ProtocolAddress, SessionBuilder, SessionCipher, native } from '../index.js';

// Wire public keys are 33 bytes: a 0x05 prefix followed by the 32-byte X25519
// point. Native X25519 wants the 32 bytes; the wrapper strips the prefix where
// it needs to, so storage hands out the 33-byte form throughout.
const P5 = (raw) => Buffer.concat([Buffer.from([0x05]), raw]);

// The storage interface SessionBuilder and SessionCipher call. Every method
// this package actually invokes is listed; there are no others. Anything a
// libsignal-style store also offers (loadSenderKey, saveIdentity, …) is
// ignored — this package never calls it.
class MemoryStore {
  constructor({ privKey, pubKey, registrationId }) {
    this.identity = { privKey, pubKey };
    this.registrationId = registrationId;
    this.sessions = new Map();
    this.preKeys = new Map();
    this.signedPreKeys = new Map();
    this.currentSignedPreKeyId = null;
    this.burnedPreKeys = [];
  }

  async getOurIdentity() { return this.identity; }
  async getOurRegistrationId() { return this.registrationId; }
  async loadSession(address) { return this.sessions.get(address) ?? null; }
  async storeSession(address, record) { this.sessions.set(address, record); }

  // loadPreKey and loadSignedPreKey are called with the id the incoming message
  // names. session-builder.js falls back to an argument-less call when a store
  // does not take one, so a store that only tracks "the current" key is fine.
  async loadPreKey(id) { return this.preKeys.get(id) ?? null; }
  async loadSignedPreKey(id) {
    const wanted = id == null ? this.currentSignedPreKeyId : id;
    return this.signedPreKeys.get(wanted) ?? null;
  }

  // One-time prekeys are consumed: decryptPreKeyWhisperMessage calls this after
  // a message verifies, so the same prekey can never establish a second
  // session. A failure here is reported, not swallowed — the caller needs to
  // know the prekey is still on disk and replayable.
  async removePreKey(id) {
    if (!this.preKeys.delete(id)) throw new Error(`no prekey ${id} to remove`);
    this.burnedPreKeys.push(id);
  }

  // --- building a bundle to publish ---

  // An X25519 keypair. The 32-byte value is the private key (which is also its
  // seed — generate_keypair is deterministic in it); the public half is what
  // goes on the wire, 0x05-prefixed.
  static makeKeyPair() {
    const privKey = randomBytes(32);
    return { privKey, pubKey: P5(native.curveGenerateKeypair(privKey)[0]) };
  }

  // A signed prekey: an X25519 key whose signature is made with the IDENTITY
  // key, not with itself. X3DH verifies that signature against the identity
  // key in the bundle, which is what binds "this prekey" to "this device".
  publishSignedPreKey(id) {
    const { privKey, pubKey } = MemoryStore.makeKeyPair();
    const signature = native.curveSign(this.identity.privKey, pubKey, null);
    this.signedPreKeys.set(id, { privKey, pubKey });
    this.currentSignedPreKeyId = id;
    return { keyId: id, publicKey: pubKey, signature };
  }

  publishOneTimePreKey(id) {
    const { privKey, pubKey } = MemoryStore.makeKeyPair();
    this.preKeys.set(id, { privKey, pubKey });
    return { keyId: id, publicKey: pubKey };
  }

  // What a real server would hand a client that wants to message this device.
  bundle(oneTimePreKeyId) {
    return {
      identityKey: this.identity.pubKey,
      signedPreKey: this.publishSignedPreKey(1),
      preKey: oneTimePreKeyId == null ? null : this.publishOneTimePreKey(oneTimePreKeyId),
    };
  }
}

const newDevice = (registrationId) => {
  const { privKey, pubKey } = MemoryStore.makeKeyPair();
  return new MemoryStore({ privKey, pubKey, registrationId });
};

const toBob = new ProtocolAddress('6280000000000.0', 0);
const toAlice = new ProtocolAddress('6281111111111.0', 0);

const alice = newDevice(11111);
const bob = newDevice(22222);

// Bob publishes an identity key, a signed prekey and one one-time prekey.
const bobBundle = bob.bundle(7);

// --- Alice: X3DH, then encrypt -------------------------------------------
await new SessionBuilder(alice, toBob).initOutgoing(bobBundle);
console.log('alice  X3DH complete — session established without a round trip');

const first = await new SessionCipher(alice, toBob).encrypt(Buffer.from('halo dari alice'));
console.log('alice  -> type %d, %d bytes (3 = PreKeyWhisperMessage)', first.type, first.body.length);

// --- Bob: first contact, builds the session from the message -------------
const received = await new SessionCipher(bob, toAlice).decryptPreKeyWhisperMessage(first.body);
console.log('bob    <- %j  (one-time prekeys burned: %j)', received.toString(), bob.burnedPreKeys);

// --- Bob replies; from here both sides are ordinary ratchet messages ------
const reply = await new SessionCipher(bob, toAlice).encrypt(Buffer.from('halo dari bob'));
console.log('bob    -> type %d, %d bytes (1 = WhisperMessage)', reply.type, reply.body.length);

const answer = await new SessionCipher(alice, toBob).decryptWhisperMessage(reply.body);
console.log('alice  <- %j', answer.toString());

// A tampered message is rejected, and the record it was tried against comes
// back unchanged — so the genuine message behind it still decrypts. The ratchet
// step a first-time message would trigger is also discarded on failure, which
// is why the forgery leaves no trace at all.
const genuine = await new SessionCipher(alice, toBob).encrypt(Buffer.from('pesan asli'));
const forged = Buffer.from(genuine.body);
forged[forged.length - 1] ^= 0x01;
try {
  await new SessionCipher(bob, toAlice).decryptWhisperMessage(forged);
  console.log('FAIL   a tampered message decrypted');
} catch (error) {
  console.log('bob    tampered message rejected: %s', error.message);
}

const receivedGenuine = await new SessionCipher(bob, toAlice).decryptWhisperMessage(genuine.body);
console.log('bob    <- %j (the real message behind the forgery still decrypts)', receivedGenuine.toString());
