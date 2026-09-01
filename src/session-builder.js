import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const native = require('../native/signal/index.cjs');
import { QueueJob } from './queue-job.js';
import { SessionRecord } from './session-record.js';

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

      const sessionJson = native.x3DhBuildInitialSession(
        Buffer.from(identity.privKey),
        Buffer.from(identity.pubKey),
        Buffer.from(device.signedPreKey.publicKey),
        Buffer.from(device.signedPreKey.signature),
        device.preKey ? Buffer.from(device.preKey.publicKey) : null,
        device.preKey ? (device.preKey.keyId != null ? device.preKey.keyId : null) : null,
        Buffer.from(recipientKey),
        Buffer.from(device.signedPreKey.publicKey),
        regId
      );
      await this.storage.storeSession(this.addr.toString(), new SessionRecord(sessionJson));
    });
  }

  async initOutgoingPreKey(device) {
    return this._queue.add(this.addr.toString(), async () => {
      const identity = await this.storage.getOurIdentity();
      const regId = await this.storage.getOurRegistrationId();
      const signedPreKey = await this.storage.loadSignedPreKey();
      const recipientKey = device.identityKey;
      if (!recipientKey) throw new Error('No identity key for recipient');

      const sessionJson = native.x3DhBuildInitialSession(
        Buffer.from(identity.privKey),
        Buffer.from(identity.pubKey),
        Buffer.from(device.signedPreKey.publicKey),
        Buffer.from(device.signedPreKey.signature),
        device.preKey ? Buffer.from(device.preKey.publicKey) : null,
        device.preKey ? (device.preKey.keyId != null ? device.preKey.keyId : null) : null,
        Buffer.from(recipientKey),
        Buffer.from(device.signedPreKey.publicKey),
        regId
      );
      await this.storage.storeSession(this.addr.toString(), new SessionRecord(sessionJson));
    });
  }

  async initIncoming(record, message) {
    throw new Error('X3DH recipient init not yet implemented in JS wrapper');
  }
}