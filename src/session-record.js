import { createRequire } from 'module';
import { QueueJob } from './queue-job.js';
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

// Queues are shared per (storage, addr) so every path that read-modify-writes a
// record — SessionCipher and SessionBuilder alike — can't interleave load/store
// and duplicate ratchet counters.
const QUEUE_INDEX = new WeakMap(); // storage -> Map<addrKey, QueueJob>
export function sharedQueue(storage, addrKey) {
  let byAddr = QUEUE_INDEX.get(storage);
  if (!byAddr) QUEUE_INDEX.set(storage, (byAddr = new Map()));
  let q = byAddr.get(addrKey);
  if (!q) byAddr.set(addrKey, (q = new QueueJob()));
  return q;
}
