import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const native = require('../native/signal/index.cjs');
import { QueueJob } from './queue-job.js';
import { SessionRecord } from './session-record.js';
import { NoSessionError } from './errors.js';
import { SessionBuilder } from './session-builder.js';

export class SessionCipher {
  constructor(storage, addr) {
    this.storage = storage;
    this.addr = addr;
    this._queue = new QueueJob();
  }

  async encrypt(data) {
    return this._queue.add(this.addr.toString(), async () => {
      const session = await this.storage.loadSession(this.addr.toString());
      if (!session) throw new NoSessionError('no session');
      const ourIdentity = await this.storage.getOurIdentity();
      const ourRegistrationId = await this.storage.getOurRegistrationId();
      const ourIdentityPub = Buffer.from(ourIdentity.pubKey);
      const sessionJson = session.serialize();
      const parsed = JSON.parse(sessionJson);
      const entry = Object.values(parsed._sessions)[0];
      const remoteIdentityPub = Buffer.from(entry.indexInfo.remoteIdentityKey, 'base64');
      const result = JSON.parse(native.ratchetEncrypt(
        sessionJson, Buffer.from(data), ourIdentityPub, remoteIdentityPub, ourRegistrationId
      ));
      const newSession = new SessionRecord(result.session_json);
      await this.storage.storeSession(this.addr.toString(), newSession);
      return { type: result.message_type, body: Buffer.from(result.ciphertext) };
    });
  }

  async decryptWhisperMessage(ciphertext) {
    return this._queue.add(this.addr.toString(), async () => {
      const session = await this.storage.loadSession(this.addr.toString());
      if (!session) throw new NoSessionError('no session');
      const ourIdentity = await this.storage.getOurIdentity();
      const ourIdentityPub = Buffer.from(ourIdentity.pubKey);
      const result = JSON.parse(native.ratchetDecryptWhisper(
        session.serialize(), Buffer.from(ciphertext), ourIdentityPub
      ));
      const newSession = new SessionRecord(result.session_json);
      await this.storage.storeSession(this.addr.toString(), newSession);
      return Buffer.from(result.plaintext);
    });
  }

  async decryptPreKeyWhisperMessage(ciphertext) {
    return this._queue.add(this.addr.toString(), async () => {
      const ourIdentity = await this.storage.getOurIdentity();
      const ourIdentityPub = Buffer.from(ourIdentity.pubKey);

      // Libsignal behavior: pkmsg always rebuilds session from message,
      // regardless of existing session (preKeyProto contains init info).
      const pkmsg = JSON.parse(native.protoDecodePkmsg(
        Buffer.from(ciphertext.slice(1))
      ));
      const builder = new SessionBuilder(this.storage, this.addr);
      let session = await builder.initIncoming(null, pkmsg);
      await this.storage.storeSession(this.addr.toString(), session);

      // Decrypt embedded WhisperMessage (handles ratchet step)
      const result = JSON.parse(native.ratchetDecryptPkmsg(
        session.serialize(), Buffer.from(ciphertext), ourIdentityPub
      ));
      const newSession = new SessionRecord(result.session_json);
      await this.storage.storeSession(this.addr.toString(), newSession);
      return Buffer.from(result.plaintext);
    });
  }
}