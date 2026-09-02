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

      // Libsignal behavior (session_builder.js initIncoming): if a session for
      // this pkmsg's baseKey already exists, KEEP it ("this just means we
      // haven't replied") and decrypt with that session — never rebuild and
      // discard the established sending chain. Only build fresh when the
      // baseKey is new to us.
      const pkmsg = JSON.parse(native.protoDecodePkmsg(
        Buffer.from(ciphertext.slice(1))
      ));
      const baseKeyRaw = Buffer.from(
        pkmsg.base_key != null ? pkmsg.base_key : pkmsg.baseKey
      );
      const baseKey = strip05(baseKeyRaw).toString('base64');

      let session = await this.storage.loadSession(this.addr.toString());
      if (!session || !sessionHasBaseKey(session, baseKey)) {
        const builder = new SessionBuilder(this.storage, this.addr);
        session = await builder.initIncoming(null, pkmsg);
        await this.storage.storeSession(this.addr.toString(), session);
      }

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

// Does the stored SessionRecord already hold an entry whose baseKey matches
// `baseKeyB64`? Mirrors libsignal SessionRecord.getSession(baseKey) lookup.
function sessionHasBaseKey(session, baseKeyB64) {
  try {
    const record = JSON.parse(session.serialize());
    const entries = record._sessions || {};
    return Object.values(entries).some(
      (e) => e.indexInfo && e.indexInfo.baseKey === baseKeyB64
    );
  } catch {
    return false;
  }
}

// Native X25519 expects 32-byte keys. Wire public keys are 33-byte
// (0x05-prefixed); strip the prefix for internal 32-byte representation.
const strip05 = (b) => (b.length === 33 && b[0] === 0x05 ? b.slice(1) : b);