// docs/storage-stub.mjs — the storage interface, in one file.
//
// SessionBuilder and SessionCipher never touch a database. They call a handful
// of async methods on whatever object you hand them, and that object is the
// whole integration surface. This is a complete in-memory implementation of
// it, so the code blocks in docs/ can run without a server, a key store, or a
// fixture file.
//
// The seven methods below are the complete list. src/ calls nothing else on a
// storage object — a libsignal-shaped store also offers loadSenderKey,
// storeSenderKey, saveIdentity and loadIdentityKey, and this package never
// touches any of them (SenderKey / group messaging is not implemented here).
//
// This file is imported by the snippets in docs/, not read by them, so
// docs:verify does not execute it on its own: it runs the blocks that import
// it, which is where the behaviour is actually asserted.

import { randomBytes } from 'node:crypto';
import { native } from '../index.js';

// Wire public keys are 33 bytes — a 0x05 prefix followed by the 32-byte X25519
// point. Native X25519 wants the 32 bytes; the wrapper strips the prefix where
// it needs to, so everything you hand to or get back from this stub carries 33.
const P5 = (raw) => Buffer.concat([Buffer.from([0x05]), raw]);

export class MemoryStore {
  constructor({ privKey, pubKey, registrationId }) {
    this.identity = { privKey, pubKey };
    this.registrationId = registrationId;
    this.sessions = new Map();
    this.preKeys = new Map();
    this.signedPreKeys = new Map();
    this.currentSignedPreKeyId = null;
    // Not part of the interface. Recorded here so the quickstart can show that
    // a one-time prekey really is consumed rather than left replayable.
    this.burnedPreKeys = [];
  }

  // --- the seven methods SessionBuilder and SessionCipher call ---

  async getOurIdentity() {
    // { privKey: Buffer(32), pubKey: Buffer(33) }
    return this.identity;
  }

  async getOurRegistrationId() {
    // A number, used only to fill the registrationId field of outgoing
    // PreKeyWhisperMessages. It is not checked against anything.
    return this.registrationId;
  }

  async loadSession(address) {
    // A SessionRecord, or null/undefined when there is none.
    return this.sessions.get(address) ?? null;
  }

  async storeSession(address, record) {
    // The record is replaced wholesale, and this is the only write path. The
    // library never mutates a record in place, so a store can serialise here
    // and reparse on the next load.
    this.sessions.set(address, record);
  }

  async loadPreKey(id) {
    // { privKey: Buffer(32), pubKey: Buffer(33) } or null.
    // Returning null for an id the message named makes initIncoming throw
    // `Missing prekey <id>` rather than building a session without DH4 that
    // could never verify.
    return this.preKeys.get(id) ?? null;
  }

  async loadSignedPreKey(id) {
    // { privKey: Buffer(32), pubKey: Buffer(33) } or null.
    // session-builder.js calls this with the signedPreKeyId the message names,
    // then falls back to an argument-less call, so a store that only tracks
    // "the current" signed prekey is fine.
    const wanted = id == null ? this.currentSignedPreKeyId : id;
    return this.signedPreKeys.get(wanted) ?? null;
  }

  async removePreKey(id) {
    // Called once a PreKeyWhisperMessage has decrypted. A throw here is NOT
    // swallowed: the caller is told the prekey is still on disk and still
    // replayable, instead of assuming it was consumed.
    if (!this.preKeys.delete(id)) throw new Error(`no prekey ${id} to remove`);
    this.burnedPreKeys.push(id);
  }

  // --- publishing a bundle (server-side, not part of the interface) ---

  // An X25519 keypair. The private key is also the 32-byte seed: Rust's
  // generate_keypair is deterministic in it, so the 32 bytes you keep are the
  // seed and the 32 bytes you publish are the Montgomery public point.
  static makeKeyPair() {
    const privKey = randomBytes(32);
    return { privKey, pubKey: P5(native.curveGenerateKeypair(privKey)[0]) };
  }

  // A signed prekey: an X25519 key whose signature is made with the IDENTITY
  // key, not with itself. X3DH verifies that signature against the identity
  // key in the bundle, which is what binds this prekey to this device.
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

  // What a server hands a client that wants to message this device.
  bundle(oneTimePreKeyId) {
    return {
      identityKey: this.identity.pubKey,
      signedPreKey: this.publishSignedPreKey(1),
      preKey: oneTimePreKeyId == null ? null : this.publishOneTimePreKey(oneTimePreKeyId),
    };
  }
}

// A device with a fresh identity key and registration id.
export const newDevice = (registrationId) => {
  const { privKey, pubKey } = MemoryStore.makeKeyPair();
  return new MemoryStore({ privKey, pubKey, registrationId });
};
