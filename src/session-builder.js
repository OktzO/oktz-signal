import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const native = require('../native/signal/index.cjs');
import { QueueJob } from './queue-job.js';
import { SessionRecord } from './session-record.js';

// Native X25519 expects 32-byte keys. baileys bundles carry 33-byte
// (0x05-prefixed) public keys; strip the prefix when a 32-byte key is expected.
const strip05 = (b) => b.length === 33 && b[0] === 0x05 ? b.slice(1) : b;

export class SessionBuilder {
  constructor(storage, protocolAddress) {
    this.storage = storage;
    this.addr = protocolAddress;
    this._queue = new QueueJob();
  }

  async initOutgoing(device) {
    return this._queue.add(this.addr.toString(), async () => {
      const identity = await this.storage.getOurIdentity();
      const regId = await this.storage.getOurRegistrationId();
      const signedPreKey = await this.storage.loadSignedPreKey();
      const recipientKey = device.identityKey;
      if (!recipientKey) throw new Error('No identity key for recipient');

      // Initator X3DH: signed_prekey_pub (3rd) and prekey_pub (5th) go to
      // X25519 scalar_multiply → must be 32 bytes (strip 0x05). recipient_pub
      // (7th) is the recipient identity, native strips [1..33] internally so it
      // stays 33-byte. signed_prekey_sig (4th) is 64 bytes.
      const sessionJson = native.x3DhBuildInitialSession(
        Buffer.from(identity.privKey),
        Buffer.from(identity.pubKey),
        Buffer.from(strip05(Buffer.from(device.signedPreKey.publicKey))),
        Buffer.from(device.signedPreKey.signature),
        device.preKey ? Buffer.from(strip05(Buffer.from(device.preKey.publicKey))) : null,
        device.preKey ? (device.preKey.keyId != null ? device.preKey.keyId : null) : null,
        Buffer.from(recipientKey),
        Buffer.from(device.signedPreKey.publicKey),
        regId,
        device.signedPreKey.keyId != null ? device.signedPreKey.keyId : 0
      );
      await this.storage.storeSession(this.addr.toString(), new SessionRecord(sessionJson));
    });
  }

  // Build recipient session from an incoming PreKeyWhisperMessage (no open
  // session yet). Returns a SessionRecord. Caller stores it and decrypts.
  // storage.loadPreKey/loadSignedPreKey return { privKey, pubKey } (libsignal shape).
  // `message` is the JSON from native.protoDecodePkmsg (snake_case fields).
  async initIncoming(record, message) {
    const identity = await this.storage.getOurIdentity();
    const preKeyId = message.pre_key_id != null ? message.pre_key_id : message.preKeyId;
    const preKeyPair = preKeyId != null ? await this.storage.loadPreKey(preKeyId) : null;
    const signedPreKeyPair = await this.storage.loadSignedPreKey();
    if (!signedPreKeyPair) throw new Error('Missing SignedPreKey');

    const sessionJson = native.x3DhBuildRecipientSession(
      Buffer.from(identity.privKey),
      Buffer.from(signedPreKeyPair.privKey),
      Buffer.from(strip05(Buffer.from(signedPreKeyPair.pubKey))),
      preKeyPair ? Buffer.from(preKeyPair.privKey) : null,
      Buffer.from(message.identity_key != null ? message.identity_key : message.identityKey),
      Buffer.from(strip05(Buffer.from(message.base_key != null ? message.base_key : message.baseKey))),
      message.registration_id != null ? message.registration_id : 0
    );
    return new SessionRecord(sessionJson);
  }
}
