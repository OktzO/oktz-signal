import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const native = require('../native/signal/index.cjs');

export class SessionRecord {
  constructor(data) {
    // Strings are stored raw: every string reaching here comes from the
    // native layer (x3dh/ratchet/serialize output) which already emits the
    // canonical libsignal-compatible form. The old deserialize+serialize
    // round-trip per message cost ~20-40 µs for pure re-normalization.
    this._json = typeof data === 'string' ? data : native.sessionSerialize(JSON.stringify(data || {}));
  }
  static deserialize(data) {
    return new SessionRecord(typeof data === 'string' ? data : JSON.stringify(data));
  }
  serialize() { return this._json; }
  haveOpenSession() { return native.sessionHaveOpenSession(this._json); }
}
