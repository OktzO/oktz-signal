import * as libsignal from 'libsignal';
import { randomBytes } from 'crypto';

let stored = null;
const spk = libsignal.curve.generateKeyPair(randomBytes(32));
const storage = {
  async loadSession() { return stored; },
  async storeSession(id, session) { stored = session; },
  async loadIdentityKey() { return Buffer.concat([Buffer.from([5]), randomBytes(32)]); },
  async saveIdentity() { return false; },
  async loadPreKey() { return null; },
  async removePreKey() {},
  async loadSignedPreKey() { return { privKey: spk.privKey, pubKey: spk.pubKey }; },
  async loadSenderKey() { return null; },
  async storeSenderKey() {},
  getOurRegistrationId() { return 12345; },
  getOurIdentity() {
    const pair = libsignal.curve.generateKeyPair(randomBytes(32));
    return { privKey: pair.privKey, pubKey: pair.pubKey };
  },
  isTrustedIdentity() { return true; }
};

const address = new libsignal.ProtocolAddress('test-user', 1);
const builder = new libsignal.SessionBuilder(storage, address);
const device = {
  identityKey: Buffer.concat([Buffer.from([5]), randomBytes(32)]),
  signedPreKey: { publicKey: spk.pubKey, signature: randomBytes(64) },
  preKey: { publicKey: libsignal.curve.generateKeyPair(randomBytes(32)).pubKey },
  registrationId: 42
};
await builder.initOutgoing(device);
const s = stored.serialize();
import { writeFileSync } from 'fs';
writeFileSync('/home/user/noddjs/oktz-signal/fixtures/libsignal-session.json', JSON.stringify(s, null, 2));
console.log('Fixture saved');
console.log('Top keys:', Object.keys(s));
console.log('Session keys:', Object.keys(Object.values(s._sessions)[0]));
