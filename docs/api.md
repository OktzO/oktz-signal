# API

Every export of the package, with the signature the source actually declares.
Each section has a runnable block that calls the thing it describes, so this
page cannot describe an API that no longer exists — `npm run docs:verify`
executes all of them.

The eight exports, verified by reading `index.js`:

```js
import * as oktz from '../index.js';

console.log('exports: %j', Object.keys(oktz).sort());
for (const [name, value] of Object.entries(oktz)) {
  console.log('  %s %s', name.padEnd(22), typeof value);
}
```

`QueueJob` and `currentSessionEntry` are **not** exports. They exist in
`src/queue-job.js` and `src/session-cipher.js` and are used internally;
`sharedQueue` in `src/session-record.js` wires the queue to a `(storage,
address)` pair. If you were told `QueueJob` is part of the surface, it is not.

---

## `SessionCipher`

`src/session-cipher.js:34`

```js nonrunnable
new SessionCipher(storage, addr)
```

| method | returns | notes |
|---|---|---|
| `await encrypt(data)` | `{ type: number, body: Buffer }` | `data` is Buffer/Uint8Array/string-Buffer. `type` is `3` while the session carries `pendingPreKey`, `1` afterwards. |
| `await decryptWhisperMessage(ciphertext)` | `Buffer` | a bare `WhisperMessage` (type 1). |
| `await decryptPreKeyWhisperMessage(ciphertext)` | `Buffer` | a `PreKeyWhisperMessage` (type 3), including first contact. |

All three are serialised per `(storage, addr)`: a `SessionCipher` and a
`SessionBuilder` pointed at the same record cannot interleave a load/store and
duplicate a ratchet counter (`src/session-record.js:25`).

`encrypt` throws `NoSessionError` if `loadSession` returns nothing. It never
starts a session implicitly — call `SessionBuilder.initOutgoing` first.

```js
import { ProtocolAddress, SessionBuilder, SessionCipher } from '../index.js';
import { newDevice } from './storage-stub.mjs';

const toBob = new ProtocolAddress('6280000000000.0', 0);
const toAlice = new ProtocolAddress('6281111111111.0', 0);
const alice = newDevice(11111);
const bob = newDevice(22222);

await new SessionBuilder(alice, toBob).initOutgoing(bob.bundle(7));

const cipher = new SessionCipher(alice, toBob);
const out = await cipher.encrypt(Buffer.from('hai'));
console.log('encrypt -> keys %j, type %d, body is a Buffer: %s',
  Object.keys(out).sort(), out.type, Buffer.isBuffer(out.body));

const back = await new SessionCipher(bob, toAlice).decryptPreKeyWhisperMessage(out.body);
console.log('decryptPreKeyWhisperMessage -> %j', back.toString());

// The next message is still type 3: pendingPreKey is deleted on decrypt.
const out2 = await cipher.encrypt(Buffer.from('lagi'));
console.log('second type %d (pendingPreKey is cleared when the REPLY arrives)', out2.type);

// No session for this address: encrypt refuses rather than starting one.
const stranger = newDevice(55555);
try {
  await new SessionCipher(stranger, new ProtocolAddress('6289999999999.0', 0)).encrypt(Buffer.from('x'));
} catch (error) {
  console.log('no session -> %s / %s', error.constructor.name, error.name);
}
```

### `decryptPreKeyWhisperMessage`, in order

This is the most interesting method in the package, and the ordering is the
whole point (`src/session-cipher.js:80`):

1. Decode the pkmsg off the wire to read its `baseKey`.
2. If the stored record already has an entry with that `baseKey`, **reuse it**.
   The peer simply has not seen your reply; rebuilding would discard an
   established sending chain.
3. Otherwise build a candidate session **in memory** via
   `SessionBuilder.initIncoming`. Nothing is written yet.
4. Decrypt, which is where the MAC is checked. On failure the record and the
   one-time prekey are both untouched.
5. Only then `storeSession`, then `removePreKey`.

Steps 3–4 are why one unauthenticated `type-3` message cannot destroy a
session, substitute an attacker-chosen remote identity, or burn a prekey. That
was a real vulnerability; it is fixed and pinned by
`tests/session-pkmsg-auth.test.mjs`.

If the record already had a session, the fresh entry is **archived** into the
same record (`closed` set, up to 40 entries, oldest evicted first) instead of
replacing it, so a backlog from the previous session stays decryptable.

---

## `SessionBuilder`

`src/session-builder.js:10`

```js nonrunnable
new SessionBuilder(storage, protocolAddress)
```

| method | returns | notes |
|---|---|---|
| `await initOutgoing(device)` | `undefined` | the session is written to `storage.storeSession`. |
| `await initIncoming(record, message)` | `SessionRecord` | does **not** store; the caller decides. |

`device` is a prekey bundle:

```js nonrunnable
{
  identityKey: Buffer,                       // 33 bytes, 0x05-prefixed
  signedPreKey: { keyId, publicKey, signature },
  // publicKey 33 bytes (0x05-prefixed), signature 64 bytes
  preKey: { keyId, publicKey } | null,       // 33 bytes; null is allowed
  registrationId,                            // accepted, not checked
}
```

`initIncoming(record, message)` takes the object `native.protoDecodePkmsg`
returns — camelCase `Buffer` fields — and also accepts the snake_case spelling
for hand-built payloads. `record` is accepted for libsignal signature parity
and unused.

Three checks happen before any key is derived, and each has a test:

- the signed-prekey signature must verify against the bundle's identity key;
- the identity public key must be the one your identity private key produces
  (`x3dh.rs:108`);
- the signed prekey must be the one the signature was made over
  (`x3dh.rs:111`).

```js
import { ProtocolAddress, SessionBuilder } from '../index.js';
import { newDevice } from './storage-stub.mjs';

const toBob = new ProtocolAddress('6280000000000.0', 0);
const bob = newDevice(22222);

// initOutgoing returns undefined: the session went into storage.
const result = await new SessionBuilder(newDevice(11111), toBob).initOutgoing(bob.bundle(7));
console.log('initOutgoing returns %s', result);

const bobSignedPreKey = { ...bob.bundle(7).signedPreKey };
console.log('bundle signedPreKey keys: %j', Object.keys(bobSignedPreKey).sort());

// A bundle with no one-time prekey is legal: X3DH just omits DH4.
const withoutOpk = bob.bundle(null);
console.log('bundle without a one-time prekey: preKey = %s', withoutOpk.preKey);
const alice = newDevice(11111);
await new SessionBuilder(alice, toBob).initOutgoing(withoutOpk);
console.log('  session built anyway, entries: %d',
  Object.keys(JSON.parse(alice.sessions.get(toBob.toString()).serialize())._sessions).length);
```

---

## `SessionRecord`

`src/session-record.js:6`

```js nonrunnable
new SessionRecord(data)      // data: string | object
SessionRecord.deserialize(data)
record.serialize()           // -> string
record.haveOpenSession()     // -> boolean
```

A thin holder over the serialized JSON. A string is stored **verbatim** — no
re-normalisation round-trip, because every string that reaches it came from
the native layer already in canonical form. A plain object is normalised once
through `native.sessionSerialize` (`src/session-record.js:12`).

Storage that keeps records on disk should hold the string from `serialize()`
and hand it back to `new SessionRecord(...)`. Constructing from the object
libsignal's `SessionRecord.serialize()` returns is also supported.

```js
import { SessionBuilder, SessionRecord } from '../index.js';
import { newDevice } from './storage-stub.mjs';
import { ProtocolAddress } from '../index.js';

const toBob = new ProtocolAddress('6280000000000.0', 0);
const alice = newDevice(11111);
const bob = newDevice(22222);
await new SessionBuilder(alice, toBob).initOutgoing(bob.bundle(7));

const json = alice.sessions.get(toBob.toString()).serialize();
console.log('serialize() -> %s, %d bytes', typeof json, json.length);

const copy = new SessionRecord(json);
console.log('a string is stored verbatim: %s', copy.serialize() === json);
console.log('deserialize() is equivalent: %s', SessionRecord.deserialize(json).serialize() === json);
console.log('haveOpenSession(): %s', copy.haveOpenSession());

// A libsignal-shaped object normalises to the same JSON.
const asObject = JSON.parse(json);
const fromObject = new SessionRecord(asObject);
console.log('an object normalises to the same JSON: %s', fromObject.serialize() === json);

// The record shape, and what a rejected one looks like.
console.log('top-level keys: %j', Object.keys(JSON.parse(json)));
console.log('version: %s', JSON.parse(json).version);
try {
  new SessionRecord('{"version":"v2","_sessions":{}}').haveOpenSession();
} catch (error) {
  console.log('a record this build does not model is refused: %s', error.message);
}
```

Anything the parser does not model is **rejected, never dropped**: an
unmodelled field at any level, a `version` other than `"v1"`, or a JSON array
in place of an object. Silently dropping a field destroys state that the next
write would then persist as if it had never existed. See
`tests/session-strict.test.mjs` and `tests/boundary-hardening.test.mjs`.

---

## `ProtocolAddress`

`src/protocol-address.js:1`

```js nonrunnable
new ProtocolAddress(name, deviceId)
address.toString()                      // -> `${name}.${deviceId}`
ProtocolAddress.fromString(str)         // -> ProtocolAddress
```

`toString()` is the key used for `loadSession`/`storeSession`, so it must
round-trip: the name may not contain a `.`, since `fromString` splits on the
**last** one.

```js
import { ProtocolAddress } from '../index.js';

const a = new ProtocolAddress('6280000000000.0', 0);
console.log('%s -> deviceId %d', a.toString(), ProtocolAddress.fromString(a.toString()).deviceId);
console.log('a dot in the name survives: %j',
  ProtocolAddress.fromString('user.name.7').toString());
console.log('deviceId is parsed as a number, not kept as a string: %s',
  typeof ProtocolAddress.fromString('x.7').deviceId);
```

---

## `PreKeyWhisperMessage`

`index.js:14` — a single method, for inspecting a frame you have not decrypted.

```js nonrunnable
decode(bytes) // Buffer -> { identityKey, baseKey, message, registrationId, preKeyId?, signedPreKeyId? }
```

All values are `Buffer` except `registrationId` (number). `preKeyId` and
`signedPreKeyId` are `undefined` when the field was absent, not `null`. Pass
the frame **without** the leading `0x33`; the wrapper's own decrypt path strips
it at `src/session-cipher.js:91`.

This calls the strict protobuf decoder, so a malformed frame throws rather than
decoding to defaults. `message` is the inner `WhisperMessage`, still wrapped
with its own `0x33` and 8-byte MAC.

```js
import { PreKeyWhisperMessage, SessionBuilder, SessionCipher } from '../index.js';
import { newDevice } from './storage-stub.mjs';
import { ProtocolAddress } from '../index.js';

const addr = new ProtocolAddress('6281111111111.0', 0);
const alice = newDevice(11111);
const bob = newDevice(22222);
await new SessionBuilder(alice, addr).initOutgoing(bob.bundle(7));
const { body } = await new SessionCipher(alice, addr).encrypt(Buffer.from('x'));

const decoded = PreKeyWhisperMessage.decode(body.subarray(1));
console.log('keys: %j', Object.keys(decoded).sort());
console.log('registrationId is a %s, preKeyId is a %s',
  typeof decoded.registrationId, typeof decoded.preKeyId);
console.log('with the version byte it throws: %s', (() => {
  try { PreKeyWhisperMessage.decode(body); return 'no'; } catch (e) { return e.message; }
})());
```

---

## `errors`

`src/errors.js` — all six classes extend `SignalError` extends `Error`, and
`name` is set to the class name.

| class | thrown by |
|---|---|
| `NoSessionError` | `encrypt`/`decrypt*` when no session exists. Native errors matching `/no session|no session entry|empty record/i` are mapped to it (`src/session-cipher.js:26`). |
| `UntrustedIdentityKeyError` | **never** — see below. |
| `InvalidMessageTypeError` | **never** — the type is decided by which method you call. |
| `InvalidKeyError` | **never** — Rust returns a plain `Error` with a string message. |
| `InvalidMessageLengthError` | **never** — same. |

That three of the six are unreachable is worth stating plainly rather than
listing them as if they were part of the contract. They are exported for
`instanceof` compatibility with libsignal-shaped code.

`UntrustedIdentityKeyError` is the interesting one: this package never calls
`storage.isTrustedIdentity`, so a peer's identity key changing is **not**
detected here. If you need trust-on-first-use enforcement you must implement it
in your `storage`, or compare `indexInfo.remoteIdentityKey` yourself.

```js
import { errors } from '../index.js';

console.log('classes: %j', Object.keys(errors).sort());
for (const name of Object.keys(errors).sort()) {
  const e = new errors[name]('x');
  console.log('  %s extends SignalError: %s, name: %s',
    name.padEnd(26), e instanceof errors.SignalError, e.name);
}
```

---

## `crypto`

`src/crypto.js` — plain Node `crypto` wrappers kept for API parity. **None of
them is used by the protocol path**; X3DH and the ratchet derive everything in
Rust. They are exported because removing them would break consumers.

| function | notes |
|---|---|
| `encrypt(key, data, iv)` | `aes-256-cbc`, **unauthenticated** — see below. |
| `decrypt(key, data, iv)` | `aes-256-cbc`, **unauthenticated** — see below. |
| `calculateMAC(key, data)` | HMAC-SHA256, full 32 bytes. |
| `hash(data)` | SHA-512. |
| `deriveSecrets(input, salt, info, chunks = 3)` | HKDF, 1–3 chunks. `salt` must be 32 bytes. Throws on any other count. |
| `verifyMAC(data, key, mac, length = 32)` | constant-time compare; throws `Bad MAC` or `Bad MAC length`. |

> **`encrypt`/`decrypt` are not a security primitive.** They are
> `createCipheriv('aes-256-cbc')` with no MAC. A ciphertext can be modified
> bitwise and the padding changed without detection — the classic CBC failure.
> Use `SessionCipher` for anything that needs integrity; the protocol path
> authenticates every message with an 8-byte truncated MAC before decrypting.
> `calculateMAC`, `hash`, `deriveSecrets` and `verifyMAC` have no such problem.

All six accept a plain `Uint8Array` as well as a `Buffer`, and reject anything
else with a `TypeError`.

```js
import { crypto } from '../index.js';
import { randomBytes } from 'node:crypto';

console.log('exports: %j', Object.keys(crypto).sort());

const key = randomBytes(32);
const iv = randomBytes(16);
const data = Buffer.from('bukan primitive keamanan yang terautentikasi');

const ct = crypto.encrypt(key, data, iv);
console.log('encrypt/decrypt round-trip: %s', crypto.decrypt(key, ct, iv).toString() === data.toString());
console.log('ciphertext is a multiple of 16 bytes: %s', ct.length % 16 === 0);

// A bit flipped in the ciphertext is not detected: there is no MAC. Padding
// still has to be well formed, so the failure mode is a decrypt error, not
// silent corruption -- but nothing here authenticates the plaintext.
const flipped = Buffer.from(ct); flipped[0] ^= 0x01;
let undetected = false;
try { crypto.decrypt(key, flipped, iv); undetected = true; } catch { /* padding rejected it */ }
console.log('a flipped ciphertext bit was accepted: %s', undetected);

// The authenticated primitives behave.
console.log('deriveSecrets(3): %j', crypto.deriveSecrets(data, key, Buffer.from('WhisperMessageKeys'))
  .map((c) => c.length));
try { crypto.deriveSecrets(data, key, Buffer.from('x'), 4); } catch (e) { console.log('4 chunks: %s', e.message); }
crypto.verifyMAC(data, key, crypto.calculateMAC(key, data));
console.log('verifyMAC accepts a good tag');
try { crypto.verifyMAC(data, key, crypto.calculateMAC(key, Buffer.from('other'))); }
catch (e) { console.log('verifyMAC rejects a bad one: %s', e.message); }
```

---

## `native`

The raw napi binding. All 16 functions are **synchronous** and run on the
calling thread — an X3DH is four X25519 operations and will block the event
loop for its duration. Every export is wrapped in `#[napi(catch_unwind)]`, so a
Rust panic becomes a JS exception rather than aborting the process.

Prefer the wrapper. Reach for `native` when you need the wire bytes, the exact
error string, or a record field the wrapper does not surface.

```js
import { native } from '../index.js';

const fns = Object.keys(native).filter((k) => typeof native[k] === 'function' && k !== 'default');
console.log('%d functions:', fns.length);
for (const name of fns.sort()) console.log('  %s', name);
console.log('every one is synchronous: %s', fns.every((n) => native[n].constructor.name === 'Function'));
console.log('native.default === native: %s', native.default === native);
```

### curve

| function | signature | behaviour |
|---|---|---|
| `curveGenerateKeypair` | `(seed: Buffer) => [pub: Buffer, priv: Buffer]` | Both 32 bytes. Deterministic in `seed`. Rejects a seed with too little entropy (a constant or near-constant seed clamps to a publicly known scalar) — `curve.rs:189`. |
| `curveScalarMultiply` | `(secretKey: Buffer, publicKey: Buffer) => Buffer` | X25519. Both 32 bytes. A 33-byte `0x05`-prefixed key is **not** accepted; strip the prefix first. Throws when the shared secret comes out all-zero — a small-order peer key would discard this side's private key entirely and leave the result derivable from public data (`curve.rs:230`). |
| `curveSign` | `(secretKey: Buffer, message: Buffer, random?: Buffer \| null) => Buffer` | XEdDSA, 64 bytes. `random` is 64 bytes and pins the nonce; omit it and 64 bytes come from `OsRng`. |
| `curveVerify` | `(publicKey: Buffer, message: Buffer, signature: Buffer) => boolean` | `verify_strict`, so a low-order public key cannot authenticate a forgery (`curve.rs:178`). |

```js
import { native } from '../index.js';
import { randomBytes } from 'node:crypto';

const seed = randomBytes(32);
const [pub, priv] = native.curveGenerateKeypair(seed);
console.log('generate_keypair -> pub %dB, priv %dB', pub.length, priv.length);
console.log('deterministic in the seed: %s', native.curveGenerateKeypair(seed)[0].equals(pub));

const msg = Buffer.from('known answer');
const sig = native.curveSign(priv, msg, null);
console.log('sign -> %dB, verify: %s', sig.length, native.curveVerify(pub, msg, sig));
console.log('a tampered message fails: %s', native.curveVerify(pub, Buffer.from('other'), sig));

// Omitting the nonce gives a different signature each time; supplying one pins it.
const a = native.curveSign(priv, msg, null);
const b = native.curveSign(priv, msg, null);
console.log('two signatures differ (CSPRNG nonce): %s', !a.equals(b));
const pinned = Buffer.alloc(64, 0xef);
console.log('a pinned nonce is reproducible: %s',
  native.curveSign(priv, msg, pinned).equals(native.curveSign(priv, msg, pinned)));

try { native.curveGenerateKeypair(Buffer.alloc(32, 0x41)); }
catch (e) { console.log('a constant seed is refused: %s', e.message); }
```

### proto

| function | signature |
|---|---|
| `protoEncodeWhisper` | `(ephemeralKey, counter, previousCounter, ciphertext) => Buffer` |
| `protoDecodeWhisper` | `(bytes) => { ephemeralKey, counter, previousCounter, ciphertext }` |
| `protoEncodePkmsg` | `(json: string) => Buffer` — byte fields as **arrays of numbers**, not base64 |
| `protoDecodePkmsg` | `(bytes) => { preKeyId, baseKey, identityKey, message, registrationId, signedPreKeyId }` |

Decoding is strict: a required field that is missing or empty, a known field at
the wrong wire type, an oversized varint, and a group wire type are all errors.
Unknown fields are skipped, as proto3 requires. See
[protocol.md](./protocol.md#protobuf-codec).

```js
import { native } from '../index.js';

const encoded = native.protoEncodeWhisper(
  Buffer.from('abc'), 300, 0, Buffer.from('xyz'),
);
console.log('whisper bytes: %s', encoded.toString('hex'));
console.log('decode round-trips: %j', native.protoDecodeWhisper(encoded));

// protoEncodePkmsg is the odd one out: it takes JSON, and Vec<u8> means arrays.
const pk = native.protoEncodePkmsg(JSON.stringify({
  pre_key_id: 1,
  base_key: [0xee],
  identity_key: [0xff],
  message: [0x10],
  registration_id: 0,
}));
console.log('pkmsg bytes: %s', pk.toString('hex'));
console.log('decoded: %j', (() => { const d = native.protoDecodePkmsg(pk);
  return { preKeyId: d.preKeyId, baseKey: Buffer.from(d.baseKey).toString('hex'), registrationId: d.registrationId }; })());

for (const [what, bytes] of [
  ['missing ephemeral_key', Buffer.from('10011800220378797a', 'hex')],
  ['counter at the wrong wire type', Buffer.from('0a036162631201051800220378797a', 'hex')],
  ['only unknown fields', Buffer.from('3a00', 'hex')],
]) {
  try { native.protoDecodeWhisper(bytes); } catch (e) { console.log('  %s -> %s', what.padEnd(34), e.message); }
}
```

### session

| function | signature | behaviour |
|---|---|---|
| `sessionSerialize` | `(json) => string` | Parse, validate, re-serialise. Rejects anything unmodelled. |
| `sessionDeserialize` | `(json) => string` | Same today; the two differ only in intent. |
| `sessionHaveOpenSession` | `(json) => boolean` | True if any entry has `closed === -1`. |

```js
import { native } from '../index.js';
import { SessionBuilder } from '../index.js';
import { newDevice } from './storage-stub.mjs';
import { ProtocolAddress } from '../index.js';

const alice = newDevice(11111);
const bob = newDevice(22222);
await new SessionBuilder(alice, new ProtocolAddress('6280000000000.0', 0)).initOutgoing(bob.bundle(7));
const json = alice.sessions.get('6280000000000.0.0').serialize();

console.log('haveOpenSession: %s', native.sessionHaveOpenSession(json));
console.log('serialize is a fixed point: %s', native.sessionSerialize(json) === json);
console.log('an empty record has no open session: %s', native.sessionHaveOpenSession('{}'));

for (const [what, input] of [
  ['a JSON array', '[]'],
  ['an unmodelled version', '{"version":"v2","_sessions":{}}'],
  ['an unmodelled field', '{"version":"v1","_sessions":{},"future":1}'],
]) {
  try { native.sessionSerialize(input); } catch (e) { console.log('  %s -> %s', what.padEnd(26), e.message); }
}
```

### x3dh

```js nonrunnable
native.x3DhBuildInitialSession(
  identityPriv, identityPub, signedPreKeyPub, signedPreKeySig,
  preKeyPub, preKeyId,
  recipientPub, recipientPreKey,
  registrationId, signedKeyId,
) // -> string (serialized SessionRecord)

native.x3DhBuildRecipientSession(
  ourIdentityPriv, ourSignedPreKeyPriv, ourSignedPreKeyPub, ourPreKeyPriv,
  senderIdentity, senderEphemeral, registrationId,
) // -> string
```

Mixed 32/33-byte conventions, straight from the source: the *public* keys on
the wire are 33-byte `0x05`-prefixed, the *private* keys are 32 bytes, and the
`0x05` is stripped internally where X25519 needs the 32 bytes. `preKeyPub` and
`preKeyId` may be `null`/`null` together for a bundle with no one-time prekey.

```js
import { native } from '../index.js';
import { randomBytes } from 'node:crypto';

const P5 = (raw) => Buffer.concat([Buffer.from([0x05]), raw]);
const kp = () => { const privKey = randomBytes(32); return { privKey, pubKey: P5(native.curveGenerateKeypair(privKey)[0]) }; };

const alice = kp();
const bob = kp();
const spk = kp();
const opk = kp();

const json = native.x3DhBuildInitialSession(
  alice.privKey, alice.pubKey,
  spk.pubKey, native.curveSign(bob.privKey, spk.pubKey, null),
  opk.pubKey, 7,
  bob.pubKey, spk.pubKey,
  22222, 1,
);
console.log('initiator record built: %s', typeof json === 'string');

const baseKey = Buffer.from(
  Object.values(JSON.parse(json)._sessions)[0].currentRatchet.ephemeralKeyPair.pubKey, 'base64',
);
const recipient = native.x3DhBuildRecipientSession(
  bob.privKey, spk.privKey, spk.pubKey.slice(1), opk.privKey,
  alice.pubKey, baseKey, 22222,
);
console.log('recipient record built: %s', typeof recipient === 'string');
console.log('recipient baseKeyType 0 (THEIRS): %s',
  Object.values(JSON.parse(recipient)._sessions)[0].indexInfo.baseKeyType === 0);

// A public key that the private key does not produce is refused.
try {
  native.x3DhBuildRecipientSession(bob.privKey, spk.privKey, randomBytes(32), null, alice.pubKey, baseKey, 1);
} catch (e) { console.log('mismatched signed prekey -> %s', e.message); }
```

### ratchet

```js nonrunnable
native.ratchetEncrypt(sessionJson, plaintext, ourIdentityPub, ourRegistrationId)
  // -> { sessionJson, messageType: 1 | 3, ciphertext }

native.ratchetDecryptWhisper(sessionJson, ciphertext, ourIdentityPub)
  // -> { sessionJson, plaintext }

native.ratchetDecryptPkmsg(sessionJson, ciphertext, ourIdentityPub)
  // -> { sessionJson, plaintext }
```

The remote identity key is read from the record's `indexInfo`, not passed in.
`decryptPkmsg` requires an open session to already exist; building one from
nothing is the wrapper's job (`ratchet.rs:626`).

```js
import { native } from '../index.js';
import { randomBytes } from 'node:crypto';

const P5 = (raw) => Buffer.concat([Buffer.from([0x05]), raw]);
const kp = () => { const privKey = randomBytes(32); return { privKey, pubKey: P5(native.curveGenerateKeypair(privKey)[0]) }; };
const baseKeyOf = (j) => Buffer.from(Object.values(JSON.parse(j)._sessions)[0].currentRatchet.ephemeralKeyPair.pubKey, 'base64');

const alice = kp();
const bob = kp();
const spk = kp();
const opk = kp();
let a = native.x3DhBuildInitialSession(alice.privKey, alice.pubKey, spk.pubKey,
  native.curveSign(bob.privKey, spk.pubKey, null), opk.pubKey, 7, bob.pubKey, spk.pubKey, 22222, 1);
const b = native.x3DhBuildRecipientSession(bob.privKey, spk.privKey, spk.pubKey.slice(1),
  opk.privKey, alice.pubKey, baseKeyOf(a), 22222);

const enc = native.ratchetEncrypt(a, Buffer.from('halo'), alice.pubKey, 22222);
console.log('encrypt -> type %d, frame %d bytes starting 0x%s',
  enc.messageType, enc.ciphertext.length, enc.ciphertext[0].toString(16).padStart(2, '0'));
const dec = native.ratchetDecryptPkmsg(b, enc.ciphertext, bob.pubKey);
console.log('decrypt -> %j', Buffer.from(dec.plaintext).toString());
console.log('the sender record advanced: %s', enc.sessionJson !== a);

// decryptPkmsg refuses an empty record: that is the wrapper's job, not Rust's.
try { native.ratchetDecryptPkmsg('{}', enc.ciphertext, bob.pubKey); }
catch (e) { console.log('no open session -> %s', e.message); }
```
