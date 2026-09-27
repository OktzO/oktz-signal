// Task 2.3 — protobuf structural validation at the JS boundary.
//
// proto.rs now refuses a message that is missing a required field, carries one
// with the wrong wire type, or presents a zero-length key or payload. These
// are the same defects seen from JS, where before the fix each of them decoded
// into a plausible-looking message and the caller could not tell it from a
// real one.
import { createRequire } from 'module';
import { test } from 'node:test';
import assert from 'node:assert/strict';
const require = createRequire(import.meta.url);
const n = require('../native/signal/index.cjs');

const unhex = s => Buffer.from(s.replace(/\s+/g, ''), 'hex');

const throws = (fn, re, what) => assert.throws(fn, re, what);

// A well-formed WhisperMessage: ephemeral_key="abc", counter=1,
// previous_counter=0, ciphertext="xyz".
const WHISPER_OK = '0a0361626310011800220378797a';
// A well-formed PreKeyWhisperMessage: pre_key_id=1, base_key=[0xEE],
// identity_key=[0xFF], message=[0x10], registration_id=42.
const PKMSG_OK = '08011201ee1a01ff220110282a';

test('protoDecodeWhisper accepts a well-formed message', () => {
  const m = n.protoDecodeWhisper(unhex(WHISPER_OK));
  assert.equal(Buffer.from(m.ephemeralKey).toString(), 'abc');
  assert.equal(m.counter, 1);
  assert.equal(Buffer.from(m.ciphertext).toString(), 'xyz');
});

test('protoDecodePkmsg accepts a well-formed message', () => {
  const m = n.protoDecodePkmsg(unhex(PKMSG_OK));
  assert.equal(m.preKeyId, 1);
  assert.equal(m.registrationId, 42);
});

test('whisper missing a required field is rejected', () => {
  throws(() => n.protoDecodeWhisper(unhex('10011800220378797a')), /ephemeral_key/,
    'absent ephemeral_key must not decode to an empty key');
  throws(() => n.protoDecodeWhisper(unhex('0a0361626310011800')), /ciphertext/,
    'absent ciphertext must not decode to an empty payload');
  throws(() => n.protoDecodeWhisper(unhex('0a03616263100118002200')), /ciphertext/,
    'a zero-length ciphertext must be rejected');
});

test('whisper known field at the wrong wire type is rejected', () => {
  // ephemeral_key sent as a varint: before the fix this was routed to
  // skip_field and the key silently defaulted to empty.
  throws(() => n.protoDecodeWhisper(unhex('082a10011800220378797a')), /ephemeral_key/,
    'a wire-type mismatch on a known field must be a hard error');
  // counter sent as length-delimited.
  throws(() => n.protoDecodeWhisper(unhex('0a036162631201051800220378797a')), /counter/,
    'a wire-type mismatch on a known field must be a hard error');
});

test('a message of only unknown fields is rejected', () => {
  // field 7, wire type 2, length 0. This used to decode to an all-default
  // WhisperMessage, so a JS caller could not distinguish it from a real one.
  throws(() => n.protoDecodeWhisper(unhex('3a00')), /ephemeral_key|ciphertext/,
    'a message with no required field present must be rejected');
});

test('a group wire type is refused clearly rather than mis-parsed', () => {
  throws(() => n.protoDecodeWhisper(unhex(WHISPER_OK + '3b3c')), /group/,
    'a legal proto2 group must be refused, not silently skipped');
});

test('pkmsg missing a required field is rejected', () => {
  throws(() => n.protoDecodePkmsg(unhex('08011201ee1a01ff220110')), /registration_id/,
    'an absent registrationId must not silently become 0');
  throws(() => n.protoDecodePkmsg(unhex('08011a01ff220110282a')), /base_key/,
    'absent base_key must be rejected');
  throws(() => n.protoDecodePkmsg(unhex('08011201ee1a01ff282a')), /message/,
    'absent message must be rejected');
});

test('a pkmsg naming a prekey but carrying no payload is rejected', () => {
  throws(() => n.protoDecodePkmsg(unhex('08011201ee1a01ff2200282a')), /message/,
    'pre_key_id set with an empty message must be rejected');
});

test('a pkmsg of only unknown fields is rejected', () => {
  throws(() => n.protoDecodePkmsg(unhex('3a00')), /base_key|message/,
    'a pkmsg with no required field present must be rejected');
});

test('pkmsg known field at the wrong wire type is rejected', () => {
  // registration_id sent as length-delimited.
  throws(() => n.protoDecodePkmsg(unhex('08011201ee1a01ff2201102a012a')), /registration_id/,
    'a wire-type mismatch on a known field must be a hard error');
});

test('a real pkmsg with unknown trailing fields still decodes', () => {
  // Forward compatibility is preserved: an unknown field alongside every
  // required field is skipped, not fatal.
  const m = n.protoDecodeWhisper(Buffer.concat([unhex(WHISPER_OK), unhex('3800')]));
  assert.equal(m.counter, 1);
  const p = n.protoDecodePkmsg(Buffer.concat([unhex(PKMSG_OK), unhex('3a00')]));
  assert.equal(p.registrationId, 42);
});
