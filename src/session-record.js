import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const native = require('../native/signal/index.cjs');

export class SessionRecord {
  constructor(data) {
    if (typeof data === 'string') {
      this._json = native.sessionDeserialize(data);
    } else {
      this._json = native.sessionDeserialize(JSON.stringify(data || {}));
    }
  }
  static deserialize(data) { return new SessionRecord(data); }
  serialize() { return native.sessionSerialize(this._json); }
  haveOpenSession() { return native.sessionHaveOpenSession(this._json); }
}