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
// Kept for API parity; hot paths use the native `current_session_mut`
// (session.rs) directly, which implements the same selection.
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

// Native errors are plain strings; surface the "no session" family as
// NoSessionError so callers can distinguish broken frames from missing state.
function mapNativeError(e) {
  const msg = e && e.message ? e.message : String(e);
  if (/no session|no session entry|empty record/i.test(msg)) throw new NoSessionError(msg);
  throw e;
}

// Queues are shared per (storage, addr) so two SessionCipher instances over
// the same record can't interleave load/store and duplicate ratchet counters.
const QUEUE_INDEX = new WeakMap(); // storage -> Map<addrKey, QueueJob>
function sharedQueue(storage, addrKey) {
  let byAddr = QUEUE_INDEX.get(storage);
  if (!byAddr) QUEUE_INDEX.set(storage, (byAddr = new Map()));
  let q = byAddr.get(addrKey);
  if (!q) byAddr.set(addrKey, (q = new QueueJob()));
  return q;
}

export class SessionCipher {
  constructor(storage, addr) {
    this.storage = storage;
    this.addr = addr;
  }

  async encrypt(data) {
    return sharedQueue(this.storage, this.addr.toString()).add(this.addr.toString(), async () => {
      const session = await this.storage.loadSession(this.addr.toString());
      if (!session) throw new NoSessionError('no session');
      const ourIdentity = await this.storage.getOurIdentity();
      const ourRegistrationId = await this.storage.getOurRegistrationId();
      let result;
      try {
        // Remote identity + active-entry selection happen natively from the
        // record itself — no per-message JSON.parse or extra boundary copy.
        result = native.ratchetEncrypt(
          session.serialize(), Buffer.from(data),
          Buffer.from(ourIdentity.pubKey), ourRegistrationId
        );
      } catch (e) { mapNativeError(e); }
      await this.storage.storeSession(
        this.addr.toString(), new SessionRecord(result.sessionJson)
      );
      return { type: result.messageType, body: result.ciphertext };
    });
  }

  async decryptWhisperMessage(ciphertext) {
    return sharedQueue(this.storage, this.addr.toString()).add(this.addr.toString(), async () => {
      const session = await this.storage.loadSession(this.addr.toString());
      if (!session) throw new NoSessionError('no session');
      const ourIdentity = await this.storage.getOurIdentity();
      let result;
      try {
        result = native.ratchetDecryptWhisper(
          session.serialize(), Buffer.from(ciphertext), Buffer.from(ourIdentity.pubKey)
        );
      } catch (e) { mapNativeError(e); }
      await this.storage.storeSession(
        this.addr.toString(), new SessionRecord(result.sessionJson)
      );
      return result.plaintext;
    });
  }

  async decryptPreKeyWhisperMessage(ciphertext) {
    const addrKey = this.addr.toString();
    return sharedQueue(this.storage, addrKey).add(addrKey, async () => {
      const ourIdentity = await this.storage.getOurIdentity();
      const ourIdentityPub = Buffer.from(ourIdentity.pubKey);

      // Libsignal behavior (session_builder.js initIncoming): if a session for
      // this pkmsg's baseKey already exists, KEEP it ("this just means we
      // haven't replied") and decrypt with that session — never rebuild and
      // discard the established sending chain. Only build fresh when the
      // baseKey is new to us.
      const pkmsg = native.protoDecodePkmsg(Buffer.from(ciphertext.subarray(1)));
      const baseKeyRaw = pkmsg.baseKey ?? Buffer.alloc(0);
      const baseKey = strip05(baseKeyRaw).toString('base64');

      let session = await this.storage.loadSession(addrKey);
      if (!session || !sessionHasBaseKey(session, baseKey)) {
        const builder = new SessionBuilder(this.storage, this.addr);
        const fresh = await builder.initIncoming(null, pkmsg);
        if (session) {
          // libsignal behavior (session_builder.js initIncoming): ARCHIVE the
          // old open session instead of replacing it — out-of-order backlog
          // from the previous session stays decryptable, then the new entry is
          // merged into the same record.
          const merged = archiveAndMerge(session, fresh);
          await this.storage.storeSession(addrKey, merged);
          session = merged;
        } else {
          await this.storage.storeSession(addrKey, fresh);
          session = fresh;
        }
        // One-time prekey is consumed (libsignal removes it after successful
        // initIncoming to prevent pkmsg replay from reusing the OPK).
        if (pkmsg.preKeyId != null && this.storage.removePreKey) {
          try { await this.storage.removePreKey(pkmsg.preKeyId) } catch { /* best-effort */ }
        }
      }

      // Decrypt embedded WhisperMessage (handles ratchet step)
      let result;
      try {
        result = native.ratchetDecryptPkmsg(
          session.serialize(), Buffer.from(ciphertext), ourIdentityPub
        );
      } catch (e) { mapNativeError(e); }
      await this.storage.storeSession(addrKey, new SessionRecord(result.sessionJson));
      return result.plaintext;
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
const strip05 = (b) => (b.length === 33 && b[0] === 0x05 ? b.subarray(1) : b);
