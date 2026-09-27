// Task 2.4 — session_deserialize must actually deserialize.
//
// `sessionDeserialize` was a byte-identical copy of `sessionSerialize`: it did
// not parse, it re-serialized a lossy projection. With no `deny_unknown_fields`
// in session.rs that silently deleted every field the structs do not model —
// top level, per entry, per chain and `pendingPreKey.extraKey` — and the record
// the caller then persisted was missing them.
//
// The ruling is fail-closed with no migration layer: unknown state is rejected
// rather than quietly eaten. These tests assert it is refused, and that a
// record libsignal actually produces still round-trips unchanged.
import { createRequire } from 'module';
import { readFileSync } from 'fs';
import { test } from 'node:test';
import assert from 'node:assert/strict';
const require = createRequire(import.meta.url);
const n = require('../native/signal/index.cjs');

const FIXTURE = readFileSync(
  new URL('../fixtures/libsignal-session.json', import.meta.url),
  'utf-8',
);

const base = () => JSON.parse(FIXTURE);
const entryKey = v => Object.keys(v._sessions)[0];
const chainKey = v => Object.keys(v._sessions[entryKey(v)]._chains)[0];

test('a well-formed record still round-trips unchanged', () => {
  // Guards against over-rejection: strictness must not cost lossless
  // round-tripping of state this build does model.
  const out = JSON.parse(n.sessionDeserialize(FIXTURE));
  assert.deepEqual(out, base());
  assert.deepEqual(JSON.parse(n.sessionSerialize(FIXTURE)), base());
});

test('an unmodelled top-level field is rejected, not dropped', () => {
  const v = base();
  v.futureField = 'unmodelled';
  // Before the fix this returned a record with `futureField` silently gone.
  assert.throws(() => n.sessionDeserialize(JSON.stringify(v)), /futureField/,
    'an unmodelled top-level field must be refused, not silently deleted');
  assert.throws(() => n.sessionSerialize(JSON.stringify(v)), /futureField/,
    'sessionSerialize must fail closed on unrecognized state too');
});

test('an unmodelled session-entry field is rejected, not dropped', () => {
  const v = base();
  v._sessions[entryKey(v)].futureField = 'unmodelled';
  assert.throws(() => n.sessionDeserialize(JSON.stringify(v)), /futureField/);
});

test('an unmodelled chain field is rejected, not dropped', () => {
  const v = base();
  v._sessions[entryKey(v)]._chains[chainKey(v)].futureField = 'unmodelled';
  assert.throws(() => n.sessionDeserialize(JSON.stringify(v)), /futureField/);
});

test('an unmodelled currentRatchet field is rejected, not dropped', () => {
  const v = base();
  v._sessions[entryKey(v)].currentRatchet.futureRatchetField = 'unmodelled';
  assert.throws(() => n.sessionDeserialize(JSON.stringify(v)), /futureRatchetField/);
});

test('pendingPreKey.extraKey is rejected, not dropped', () => {
  // The exact field the audit reported being silently deleted.
  const v = base();
  v._sessions[entryKey(v)].pendingPreKey.extraKey = 'unmodelled';
  assert.throws(() => n.sessionDeserialize(JSON.stringify(v)), /extraKey/);
});

test('a version this build does not model is rejected', () => {
  const v = base();
  v.version = 'v2';
  assert.throws(() => n.sessionDeserialize(JSON.stringify(v)), /version/,
    'a record labelled with an unknown version must not be used as v1');
});

test('an absent version still defaults to v1', () => {
  const v = base();
  delete v.version;
  assert.equal(JSON.parse(n.sessionDeserialize(JSON.stringify(v))).version, 'v1');
});

test('a record with no unmodelled state is not rejected by the new checks', () => {
  // sessionHaveOpenSession shares the parse, so the strictness must not break
  // the read-only query the JS wrapper uses on every message.
  assert.equal(n.sessionHaveOpenSession(n.sessionDeserialize(FIXTURE)), true);
});
