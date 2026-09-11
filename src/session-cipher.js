import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const native = require('../native/signal/index.cjs');
import { QueueJob } from './queue-job.js';
import { SessionRecord } from './session-record.js';
import { NoSessionError } from './errors.js';
import { SessionBuilder } from './session-builder.js';

// Select the ACTIVE session entry — mirrors libsignal getOpenSession():
// prefer `closed === -1`, tie-break by most recently `used`. Falls back to
// the newest entry so single-entry records (the common case) are unaffected.
// Must match Rust `current_session_mut` (session.rs) — both sides now agree
// on which entry is "current" even for multi-entry records.
export function currentSessionEntry(parsed) {
  const entries = Object.values(parsed._sessions || {});
  if (entries.length <= 1) return entries[0];
  return entries.reduce((best, e) => {
    const bestOpen = best.indexInfo.closed === -1;
    const eOpen = e.indexInfo.closed === -1;
    if (eOpen !== bestOpen) return eOpen ? e : best;
    return (e.indexInfo.used || 0) > (best.indexInfo.used || 0) ? e : best;
  });
}

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
      const entry = currentSessionEntry(parsed);
      if (!entry) throw new NoSessionError('no session entry');
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
        const fresh = await builder.initIncoming(null, pkmsg);
        if (session) {
          // libsignal behavior (session_builder.js initIncoming): ARCHIVE the
          // old open session instead of replacing it — out-of-order backlog
          // from the previous session stays decryptable, then the new entry is
          // merged into the same record.
          const merged = archiveAndMerge(session, fresh);
          await this.storage.storeSession(this.addr.toString(), merged);
          session = merged;
        } else {
          await this.storage.storeSession(this.addr.toString(), fresh);
          session = fresh;
        }
        // One-time prekey is consumed (libsignal removes it after successful
        // initIncoming to prevent pkmsg replay from reusing the OPK).
        const preKeyId = pkmsg.pre_key_id != null ? pkmsg.pre_key_id : pkmsg.preKeyId;
        if (preKeyId != null && this.storage.removePreKey) {
          try { await this.storage.removePreKey(preKeyId) } catch { /* best-effort */ }
        }
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

// Archive the existing open session(s) and merge the freshly-built entry into
// the same record — mirrors libsignal SessionRecord.archiveCurrentState() +
// promoteFresh(). Keeps skipped-message keys of the old session so backlog
// messages remain decryptable after the peer re-initiated.
function archiveAndMerge(oldRecord, freshRecord) {
  const old = JSON.parse(oldRecord.serialize());
  const fresh = JSON.parse(freshRecord.serialize());
  const freshEntries = Object.values(fresh._sessions || {});
  for (const key of Object.keys(old._sessions || {})) {
    if (old._sessions[key].indexInfo.closed === -1) {
      old._sessions[key].indexInfo.closed = old._sessions[key].indexInfo.used || Date.now();
    }
  }
  for (const entry of freshEntries) {
    old._sessions[entry.indexInfo.baseKey] = entry;
  }
  return new SessionRecord(JSON.stringify(old));
}

// Native X25519 expects 32-byte keys. Wire public keys are 33-byte
// (0x05-prefixed); strip the prefix for internal 32-byte representation.
const strip05 = (b) => (b.length === 33 && b[0] === 0x05 ? b.slice(1) : b);