# Quickstart

A complete X3DH handshake between two peers, then a ratchet conversation, with
no server and no network. Every code block on this page is executed by
`npm run docs:verify`, so it is a test, not a picture.

Run them yourself:

```bash nonrunnable
node docs/quickstart.mjs      # once this page's blocks are extracted, or
npm run docs:verify           # just run all of them, which is the point
```

## The shape of the thing

There are two classes you drive and one plain object you supply.

| | what it is | where |
|---|---|---|
| `SessionBuilder` | runs X3DH: `initOutgoing` from a published bundle, `initIncoming` from an incoming message | `src/session-builder.js` |
| `SessionCipher` | runs the Double Ratchet: `encrypt`, `decryptWhisperMessage`, `decryptPreKeyWhisperMessage` | `src/session-cipher.js` |
| your `storage` | 7 async methods; the whole integration surface | [api.md](./api.md#storage) |

A session is identified by an address, and both classes need one:

```js
import { ProtocolAddress } from '../index.js';

const toBob = new ProtocolAddress('6280000000000.0', 0);
console.log(toBob.toString());            // '6280000000000.0'
console.log(ProtocolAddress.fromString('6280000000000.0').deviceId); // 0
```

## The full handshake

`docs/storage-stub.mjs` holds an in-memory `storage` implementing all seven
methods, so this block is the whole program. It is the annotated version of
[`examples/handshake.mjs`](../examples/handshake.mjs).

```js
import { randomBytes } from 'node:crypto';
import { ProtocolAddress, SessionBuilder, SessionCipher, native } from '../index.js';
import { newDevice } from './storage-stub.mjs';

const P5 = (raw) => Buffer.concat([Buffer.from([0x05]), raw]);
const hex = (b) => `0x${b.toString(16).padStart(2, '0')}`;
const toBob = new ProtocolAddress('6280000000000.0', 0);
const toAlice = new ProtocolAddress('6281111111111.0', 0);

const alice = newDevice(11111);
const bob = newDevice(22222);

// --- Bob publishes what a server would hand out ---------------------------
// identityKey (33B) + signedPreKey (keyId, 33B, 64B signature) + one-time
// prekey (keyId, 33B). The signature is made with Bob's IDENTITY key over the
// 33-byte prekey, which is what X3DH checks before it derives anything.
const bobBundle = bob.bundle(7);
console.log('bob published identityKey %dB, spk %dB, sig %dB, opk %dB',
  bobBundle.identityKey.length,
  bobBundle.signedPreKey.publicKey.length,
  bobBundle.signedPreKey.signature.length,
  bobBundle.preKey.publicKey.length);

// --- Alice: X3DH, no round trip -------------------------------------------
// initOutgoing verifies the signature, checks that the bundle's identity and
// prekey are the keys they claim to be, derives the shared secret, and stores
// a session. It returns undefined; the session is in storage now.
await new SessionBuilder(alice, toBob).initOutgoing(bobBundle);
const stored = JSON.parse(alice.sessions.get(toBob.toString()).serialize());
console.log('alice X3DH done, session entries: %d', Object.keys(stored._sessions).length);

// --- Alice: encrypt. The first message is a PreKeyWhisperMessage -----------
const first = await new SessionCipher(alice, toBob).encrypt(Buffer.from('halo dari alice'));
console.log('alice -> type %d (%d = PreKeyWhisperMessage), %d bytes',
  first.type, 3, first.body.length);
console.log('alice -> version byte %s', hex(first.body[0]));

// --- Bob: first contact. He builds the session from the message itself ----
const received = await new SessionCipher(bob, toAlice).decryptPreKeyWhisperMessage(first.body);
console.log('bob   <- %j', received.toString());
console.log('bob   one-time prekeys burned: %j', bob.burnedPreKeys);

// --- Bob replies. pendingPreKey was set on him? No, so this is type 1 ------
const reply = await new SessionCipher(bob, toAlice).encrypt(Buffer.from('halo dari bob'));
console.log('bob   -> type %d (%d = WhisperMessage), %d bytes', reply.type, 1, reply.body.length);

const answer = await new SessionCipher(alice, toBob).decryptWhisperMessage(reply.body);
console.log('alice <- %j', answer.toString());
```

Two things in that output are worth stopping on.

**The one-time prekey is gone.** `bob.burnedPreKeys` is `[7]`.
`decryptPreKeyWhisperMessage` calls `storage.removePreKey` only after the
message's MAC has verified, so a failed decrypt cannot burn a prekey — and if
`removePreKey` itself throws, the error reaches you instead of being swallowed.
Without that, one intercepted message could establish two sessions from a
single prekey.

**Alice's first three messages are all type 3.** `pendingPreKey` is deleted on
*decrypt*, not on encrypt (`ratchet.rs:608`), so a sender keeps wrapping as a
`PreKeyWhisperMessage` until it hears back. Only the recipient's first reply is
a bare `WhisperMessage`. This surprises people who count message types.

## Receiving a message you have never seen

`decryptPreKeyWhisperMessage` is the one to call when you do not know whether
the sender already has a session. It handles both cases: if the record already
holds a session for the incoming `baseKey` it reuses it (the peer simply has
not seen your reply yet), and only builds a fresh one when the `baseKey` is new.

```js
import { ProtocolAddress, SessionCipher, PreKeyWhisperMessage } from '../index.js';
import { newDevice } from './storage-stub.mjs';

const toAlice = new ProtocolAddress('6281111111111.0', 0);
const bob = newDevice(22222);
bob.bundle(7);

// With no stored session, this is a first contact — and a frame that is not a
// real PreKeyWhisperMessage is refused by the protobuf decoder, before X3DH
// runs and before anything is written to storage.
try {
  await new SessionCipher(bob, toAlice).decryptPreKeyWhisperMessage(
    Buffer.concat([Buffer.from([0x33]), Buffer.from('0a00', 'hex')]),
  );
} catch (error) {
  console.log('first contact refused a degenerate frame: %s', error.message);
}
console.log('nothing was stored: %s', !bob.sessions.has(toAlice.toString()));
console.log('no prekey was burned: %j', bob.burnedPreKeys);

// Peek at a PreKeyWhisperMessage without decrypting it. This is how you learn
// which prekey ids and which identity key the sender used — for routing, or
// for deciding which of your devices should answer.
const { SessionBuilder } = await import('../index.js');
const sender = newDevice(11111);
await new SessionBuilder(sender, toAlice).initOutgoing(bob.bundle(7));
const wire = (await new SessionCipher(sender, toAlice).encrypt(Buffer.from('peek at me'))).body;

const decoded = PreKeyWhisperMessage.decode(wire.subarray(1));
console.log('preKeyId %s, signedPreKeyId %s, registrationId %d',
  decoded.preKeyId, decoded.signedPreKeyId, decoded.registrationId);
console.log('identityKey %dB (prefix 0x%02x), baseKey %dB (prefix 0x%02x)',
  decoded.identityKey.length, decoded.identityKey[0],
  decoded.baseKey.length, decoded.baseKey[0]);
```

`PreKeyWhisperMessage.decode` takes the frame *without* the leading `0x33`
version byte — the wrapper's own decrypt path strips it before calling
(`session-cipher.js:91`). Pass it the version byte and the protobuf decoder
reads the `0x33` as a field tag and fails.

If you already have a session and know the message is a plain ratchet message,
use `decryptWhisperMessage`. The two are genuinely different wire formats and
neither accepts the other.

## What happens when something is wrong

Every one of these is a real code path, not a hypothetical. The first is the
one that matters most.

```js
import { ProtocolAddress, SessionBuilder, SessionCipher, native } from '../index.js';
import { newDevice } from './storage-stub.mjs';

const toBob = new ProtocolAddress('6280000000000.0', 0);
const toAlice = new ProtocolAddress('6281111111111.0', 0);
const alice = newDevice(11111);
const bob = newDevice(22222);

const bundle = bob.bundle(7);
await new SessionBuilder(alice, toBob).initOutgoing(bundle);
const genuine = await new SessionCipher(alice, toBob).encrypt(Buffer.from('pesan asli'));

// 1. A forged MAC is rejected, and nothing is persisted: no session, no burned
//    prekey. The genuine frame behind it still decrypts afterwards.
//
//    The MAC is the last 8 bytes of the INNER WhisperMessage, which lives in
//    field 4 of the outer protobuf — and field 4 is not the last field, so
//    flipping a byte at the end of the frame would only corrupt
//    registration_id. Rebuild the frame to hit the MAC where it is.
const outer = native.protoDecodePkmsg(genuine.body.subarray(1));
const inner = Buffer.from(outer.message);
inner[inner.length - 1] ^= 0x01;
// protoEncodePkmsg takes a JSON string whose byte fields are ARRAYS OF
// NUMBERS, not base64: it goes through serde and Vec<u8>. protoDecodePkmsg
// hands back real Buffers, so a decode/encode round-trip is not symmetric.
const bytes = (b) => Array.from(b);
const forgedWire = Buffer.concat([
  Buffer.from([0x33]),
  Buffer.from(native.protoEncodePkmsg(JSON.stringify({
    pre_key_id: outer.preKeyId,
    base_key: bytes(outer.baseKey),
    identity_key: bytes(outer.identityKey),
    message: bytes(inner),
    registration_id: outer.registrationId,
    signed_pre_key_id: outer.signedPreKeyId,
  }))),
]);
try {
  await new SessionCipher(bob, toAlice).decryptPreKeyWhisperMessage(forgedWire);
  console.log('1. UNEXPECTED: the forgery decrypted');
} catch (error) {
  console.log('1. forged MAC: %s', error.message);
}
console.log('   session persisted: %s, prekeys burned: %j',
  bob.sessions.has(toAlice.toString()), bob.burnedPreKeys);
const ok = await new SessionCipher(bob, toAlice).decryptPreKeyWhisperMessage(genuine.body);
console.log('   the genuine frame still decrypts: %j', ok.toString());

// 2. No session at all. encrypt refuses rather than starting one implicitly.
try {
  await new SessionCipher(alice, new ProtocolAddress('6289999999999.0', 0)).encrypt(Buffer.from('x'));
} catch (error) {
  console.log('2. encrypt with no session: %s (%s)', error.message, error.name);
}

// 3. A bundle whose signed prekey was swapped. X3DH rejects it before it
//    derives anything.
const swapped = bundle.signedPreKey.publicKey;
const tamperedBundle = {
  ...bundle,
  signedPreKey: {
    ...bundle.signedPreKey,
    publicKey: Buffer.concat([swapped.subarray(0, 1), Buffer.from([swapped[1] ^ 0xff]), swapped.subarray(2)]),
  },
};
try {
  await new SessionBuilder(newDevice(33333), toBob).initOutgoing(tamperedBundle);
  console.log('3. UNEXPECTED: a bad signature was accepted');
} catch (error) {
  console.log('3. bad signed-prekey signature: %s', error.message);
}

// 4. A one-time prekey id the recipient does not have. loadPreKey returns
//    null and initIncoming throws, rather than building a session without DH4
//    that could never verify.
const stranger = newDevice(44444);
console.log('4. unknown prekey id resolves to: %j (initIncoming then throws)', await stranger.loadPreKey(999));
```

The error classes are exported as `errors` from the package. `NoSessionError` is
what you get for the "no session" family; everything else surfaces as the
native error, which is a plain `Error` whose `message` is a string from Rust.

## Ordering and epochs

Out-of-order delivery works inside one ratchet epoch and does not work across
one. Both halves are demonstrated, with output, in
[`examples/ratchet-epochs.mjs`](../examples/ratchet-epochs.mjs); the short
version:

```js
import { randomBytes } from 'node:crypto';
import { native } from '../index.js';

const P5 = (raw) => Buffer.concat([Buffer.from([0x05]), raw]);
const keyPair = () => {
  const privKey = randomBytes(32);
  return { privKey, pubKey: P5(native.curveGenerateKeypair(privKey)[0]) };
};
const baseKeyOf = (json) => Buffer.from(
  Object.values(JSON.parse(json)._sessions)[0].currentRatchet.ephemeralKeyPair.pubKey, 'base64',
);

const alice = keyPair();
const bob = keyPair();
const spk = keyPair();
const opk = keyPair();
let a = native.x3DhBuildInitialSession(
  alice.privKey, alice.pubKey, spk.pubKey,
  native.curveSign(bob.privKey, spk.pubKey, null),
  opk.pubKey, 7, bob.pubKey, spk.pubKey, 22222, 1,
);
const b = native.x3DhBuildRecipientSession(
  bob.privKey, spk.privKey, spk.pubKey.slice(1), opk.privKey,
  alice.pubKey, baseKeyOf(a), 22222,
);

const encrypt = (json, text) => {
  const out = native.ratchetEncrypt(json, Buffer.from(text), alice.pubKey, 22222);
  return { json: out.sessionJson, wire: Buffer.from(out.ciphertext), type: out.messageType };
};
const decrypt = (json, m) => (m.type === 3
  ? native.ratchetDecryptPkmsg(json, m.wire, bob.pubKey)
  : native.ratchetDecryptWhisper(json, m.wire, bob.pubKey));

// Three messages in one epoch, delivered in reverse. All three decrypt.
const m1 = encrypt(a, 'satu'); a = m1.json;
const m2 = encrypt(a, 'dua');  a = m2.json;
const m3 = encrypt(a, 'tiga'); a = m3.json;
let receiver = b;
for (const m of [m3, m2, m1]) {
  const out = decrypt(receiver, m);
  receiver = out.sessionJson;
  console.log('delivered out of order -> %j', Buffer.from(out.plaintext).toString());
}
```

A message that arrives *after* a DH ratchet step has retired its chain is
rejected with `MAC verification failed`. That is not a shortcut: the step
removes the previous receiving chain from the record instead of blanking its
key, which is what libsignal does too. See
[protocol.md](./protocol.md#what-is-not-covered) for the consequences.

## Where to go next

- [api.md](./api.md) — every export, with its real signature.
- [protocol.md](./protocol.md) — what the implementation does, cited to
  `file:line`.
- [`examples/`](../examples) — three runnable programs, all executed by
  `npm run docs:verify`.
