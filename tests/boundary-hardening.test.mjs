// Task 2.6 — arithmetic and input hardening in proto.rs / session.rs.
//
// Two classes of defect, both of which turned hostile or corrupt input into a
// silently wrong result rather than an error:
//
//   a) every wire varint is declared u32, but the decoder cast with `as u32`.
//      A previous_counter of 2^33 became 0, which flows into fill_message_keys,
//      so the receiver never derives the previous chain's skipped keys and
//      those messages become permanently undecryptable.
//   b) serde reads a struct from a JSON array positionally and both
//      SessionRecord fields are `default`, so "[]" parsed to an empty record
//      with no error — state silently reset.
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

// Written with division rather than bitwise ops: JS bitwise operators are
// 32-bit, so `v & 0x7f` is wrong for exactly the values under test.
function varint(v) {
  const out = [];
  let rest = v;
  for (;;) {
    const b = rest % 128;
    rest = Math.floor(rest / 128);
    if (rest === 0) { out.push(b); break; }
    out.push(b | 0x80);
  }
  return Buffer.from(out);
}

const tag = (field, wire) => varint(field * 8 + wire);
const lenDelim = (field, payload) =>
  Buffer.concat([tag(field, 2), varint(payload.length), payload]);

// ephemeral_key="abc", counter=1, previous_counter=`counterValue`, ciphertext="xyz"
const whisper = counterValue =>
  Buffer.concat([
    lenDelim(1, Buffer.from('abc')),
    tag(2, 0), varint(1),
    tag(3, 0), varint(counterValue),
    lenDelim(4, Buffer.from('xyz')),
  ]);

// base_key=[0xEE], identity_key=[0xFF], message=[0x10], registration_id=42,
// then `field` carrying `value` last so it wins under last-occurrence-wins.
const pkmsg = (field, value) =>
  Buffer.concat([
    lenDelim(2, Buffer.from([0xEE])),
    lenDelim(3, Buffer.from([0xFF])),
    lenDelim(4, Buffer.from([0x10])),
    tag(5, 0), varint(42),
    tag(field, 0), varint(value),
  ]);

test('a varint that does not fit u32 is rejected, not truncated', () => {
  // 2^33 is the audit's example: it truncated to 0 under `as u32`.
  assert.throws(() => n.protoDecodeWhisper(whisper(2 ** 33)), /previous_counter/,
    'previous_counter of 2^33 must be refused, not become 0');
  assert.throws(() => n.protoDecodeWhisper(whisper(2 ** 32)), /previous_counter/,
    'previous_counter of 2^32 must be refused, not become 0');
  assert.throws(() => n.protoDecodeWhisper(whisper(2 ** 33 - 1)), /previous_counter/,
    'a value one above u32::MAX must be refused');
});

test('pkmsg varints that do not fit u32 are rejected', () => {
  for (const [field, name] of [[1, 'pre_key_id'], [5, 'registration_id'], [6, 'signed_pre_key_id']]) {
    assert.throws(() => n.protoDecodePkmsg(pkmsg(field, 2 ** 33)), new RegExp(name),
      `${name} of 2^33 must be refused, not truncated`);
  }
});

test('u32::MAX is still accepted', () => {
  // The check is a range check, not a rejection of large values.
  const m = n.protoDecodeWhisper(whisper(2 ** 32 - 1));
  assert.equal(m.previousCounter, 2 ** 32 - 1);
});

test('a JSON array is not a session record', () => {
  for (const input of ['[]', '[ ]', '["v1"]', '[1,2,3]']) {
    assert.throws(() => n.sessionDeserialize(input), /JSON object/,
      `${input} must not deserialize to an empty record`);
    assert.throws(() => n.sessionSerialize(input), /JSON object/,
      `${input} must not serialize to an empty record`);
  }
});

test('an empty object is still a valid empty record', () => {
  // The ratchet relies on this: decrypt_pkmsg("{}") must reach the
  // "no open session" check, not die in the parser.
  assert.equal(n.sessionHaveOpenSession('{}'), false);
  assert.deepEqual(JSON.parse(n.sessionDeserialize('{}')), { _sessions: {}, version: 'v1' });
});

test('the libsignal fixture is unaffected', () => {
  assert.deepEqual(JSON.parse(n.sessionDeserialize(FIXTURE)), JSON.parse(FIXTURE));
});
