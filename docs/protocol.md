# Protocol

What the implementation actually does, cited to `file:line`. Every `path:line`
below was read from the tree this page ships with; where a claim rests on a
test rather than on reading, the test is named.

The version this describes is `0.3.0-rc.1` plus the unreleased work on `main`
(see [CHANGELOG.md](../CHANGELOG.md) for exactly what that means).

---

## X3DH

`native/signal/src/x3dh.rs`. Two info strings, both hard-coded:

| info string | used for | line |
|---|---|---|
| `"WhisperText"` | the initial root key | `x3dh.rs:146`, `x3dh.rs:260` |
| `"WhisperRatchet"` | the sending ratchet, and every DH ratchet step | `x3dh.rs:181`, `ratchet.rs:306`, `ratchet.rs:322` |

### Shared secret layout

`0xff * 32 || a1 || a2 || a3 [|| a4]` — 128 bytes without a one-time prekey,
160 with one (`x3dh.rs:125-142`). `a1..a4` are 32-byte X25519 outputs.

The two sides compute the **same four values in a different order**, and the
order is what makes them agree:

| | initiator (`x3dh.rs:119-121`) | recipient (`x3dh.rs:238-242`) |
|---|---|---|
| `a1` | `DH(IK_A_priv, SPK_B_pub)` | `DH(IK_B_priv, EK_A_pub)` |
| `a2` | `DH(EK_A_priv, IK_B_pub)` | `DH(SPK_B_priv, IK_A_pub)` |
| `a3` | `DH(EK_A_priv, SPK_B_pub)` | `DH(SPK_B_priv, EK_A_pub)` |
| `a4` | `DH(EK_A_priv, OPK_pub)` | `DH(OPK_priv, EK_A_pub)` |

The recipient writes them into the buffer in the *initiator's* order —
`shared[32..64] = a2`, `shared[64..96] = a1` (`x3dh.rs:250-253`) — so both
sides feed identical bytes to HKDF. Getting this backwards produces a shared
secret that looks fine and decrypts nothing.

The root key is then `derive_secrets(shared, zeros(32), "WhisperText")[0]`
(`x3dh.rs:145-147`, `x3dh.rs:259-261`). `derive_secrets` is HKDF-Extract then
three HKDF-Expand rounds with a one-byte counter (`x3dh.rs:34-52`); chunk 0 is
the root key and chunk 1 the sending chain key.

### The two sides do not hold the same root key, and should not

After `initOutgoing` the initiator immediately advances its root key: it
computes `DH(EK_A_priv, SPK_B_pub)`, derives with `"WhisperRatchet"` using the
`WhisperText` root as the salt, and **overwrites** the stored root key with
`mk_ratchet[0]` while `mk_ratchet[1]` becomes the sending chain key
(`x3dh.rs:180-194`). The recipient stops at the `WhisperText` root
(`x3dh.rs:259-261`) and has no chains at all.

So the root keys differ at rest, and they still differ after the first
exchange. That is correct — the Double Ratchet does not keep the two sides'
root keys equal. What has to line up is the *chain key* for a given ratchet
key, and that is exactly what the `a1`/`a2` swap buys: the initiator's SENDING
chain key equals the receiver's RECEIVING chain key, once the receiver's first
decrypt has performed its ratchet step.

```js
import { native } from '../index.js';
import { randomBytes } from 'node:crypto';

const P5 = (raw) => Buffer.concat([Buffer.from([0x05]), raw]);
const kp = () => { const privKey = randomBytes(32); return { privKey, pubKey: P5(native.curveGenerateKeypair(privKey)[0]) }; };
const baseKeyOf = (j) => Buffer.from(Object.values(JSON.parse(j)._sessions)[0].currentRatchet.ephemeralKeyPair.pubKey, 'base64');
const entryOf = (j) => Object.values(JSON.parse(j)._sessions)[0];
const chainKeyOf = (json, type) =>
  Object.values(entryOf(json)._chains).find((c) => c.chainType === type).chainKey.key;

const alice = kp(), bob = kp(), spk = kp(), opk = kp();
const sig = native.curveSign(bob.privKey, spk.pubKey, null);
const initiator = native.x3DhBuildInitialSession(
  alice.privKey, alice.pubKey, spk.pubKey,
  sig, opk.pubKey, 7, bob.pubKey, spk.pubKey, 22222, 1,
);
const recipient = native.x3DhBuildRecipientSession(
  bob.privKey, spk.privKey, spk.pubKey.slice(1), opk.privKey, alice.pubKey, baseKeyOf(initiator), 22222,
);

console.log('baseKeyType initiator %d (OURS), recipient %d (THEIRS)',
  entryOf(initiator).indexInfo.baseKeyType, entryOf(recipient).indexInfo.baseKeyType);
console.log('indexInfo.baseKey is the ephemeral PUBLIC key: %s',
  entryOf(initiator).indexInfo.baseKey === entryOf(initiator).currentRatchet.ephemeralKeyPair.pubKey);
console.log('root keys are NOT equal at rest: %s',
  entryOf(initiator).currentRatchet.rootKey !== entryOf(recipient).currentRatchet.rootKey);
console.log('recipient starts with no chains: %s', Object.keys(entryOf(recipient)._chains).length === 0);
console.log('initiator starts with one SENDING (1) chain: %j',
  Object.values(entryOf(initiator)._chains).map((c) => c.chainType));
console.log('pendingPreKey is set on the initiator only: %s / %s',
  entryOf(initiator).pendingPreKey !== undefined, entryOf(recipient).pendingPreKey !== undefined);

// The invariant that actually matters.
const sent = native.ratchetEncrypt(initiator, Buffer.from('satu'), alice.pubKey, 22222);
const decrypted = native.ratchetDecryptPkmsg(recipient, sent.ciphertext, bob.pubKey);
console.log('after the first decrypt, the SENDING and RECEIVING chain keys match: %s',
  chainKeyOf(sent.sessionJson, 1) === chainKeyOf(decrypted.sessionJson, 2));

// Each of the three checks rejects its own bad input, in order.
try {
  native.x3DhBuildInitialSession(alice.privKey, kp().pubKey, spk.pubKey, sig, opk.pubKey, 7, bob.pubKey, spk.pubKey, 1, 1);
} catch (e) { console.log('identity_pub not matching identity_priv -> %s', e.message); }
// A valid signature over a prekey, but a different key named as the recipient
// prekey: this is what reaches the third check.
try {
  native.x3DhBuildInitialSession(alice.privKey, alice.pubKey, spk.pubKey, sig, opk.pubKey, 7, bob.pubKey, kp().pubKey, 1, 1);
} catch (e) { console.log('recipient_prekey not the signed prekey -> %s', e.message); }
try {
  native.x3DhBuildInitialSession(alice.privKey, alice.pubKey, spk.pubKey, randomBytes(64), opk.pubKey, 7, bob.pubKey, spk.pubKey, 1, 1);
} catch (e) { console.log('bad signature -> %s', e.message); }
```

### Checks before anything is derived

Three, in this order, all before the first X25519:

1. the signed-prekey signature must verify against the recipient's identity
   key, over the **33-byte** `0x05`-prefixed prekey (`x3dh.rs:98`);
2. `identity_pub` must be what `identity_priv` actually produces
   (`x3dh.rs:108`);
3. `recipient_prekey` must be the same key the signature was made over
   (`x3dh.rs:111`).

The recipient side has its own: `our_signed_prekey_pub` must match
`our_signed_prekey_priv`, because that keypair is what derives the receiving
chains (`x3dh.rs:232`).

### One inefficiency, stated plainly

`a3 = DH(EK_A_priv, SPK_B_pub)` is computed at `x3dh.rs:121` and then computed
**again** at `x3dh.rs:180` as `shared_ratchet` for the sending ratchet. It is
the same scalar multiply on the same inputs. It costs one extra X25519 per
session build and is not fixed. It is not a correctness problem.

---

## Double Ratchet

`native/signal/src/ratchet.rs`.

### Message keys

Per message, from the sending chain key (`ratchet.rs:195-218`):

```text nonrunnable
message_key = HMAC-SHA256(chain_key, 0x01)
next_key    = HMAC-SHA256(chain_key, 0x02)
```

`fill_message_keys` recurses to fill every counter between the chain's current
position and the requested one, retaining each derived message key, and the
consumed one is removed after use (`ratchet.rs:600-603`). That retention is
why reordering works inside an epoch.

Three guards, all of which fail closed:

| guard | line | why |
|---|---|---|
| counter behind the chain → stop | `ratchet.rs:196` | already derived |
| **chain key absent or blank → error** | `ratchet.rs:202` | HMAC under an empty key is public knowledge, so a forgery would satisfy the real MAC |
| more than 2000 ahead → error | `ratchet.rs:205` | the same bound libsignal uses, as a *distance from the chain*, not an absolute counter |

`peek_message_key` (`ratchet.rs:225-243`) is a read-only twin with identical
guards and key schedule. Decrypt uses it to read the key for the MAC **without
stepping the chain**, so a MAC failure leaves the record untouched.

### The bound is a distance, not a position

`MAX_SKIP = 2000` (`ratchet.rs:41`). An earlier version capped the absolute
wire counter, which silently dropped every message past 2000 of an epoch while
the peer was still entitled to send them. The relative distance is what actually
bounds the work an unauthenticated sender can buy. Pinned by
`the_counter_bound_is_skip_distance_not_absolute_position` and, in JS,
`tests/ratchet-counter-window.test.mjs`.

```js
import { native } from '../index.js';
import { randomBytes } from 'node:crypto';

const P5 = (raw) => Buffer.concat([Buffer.from([0x05]), raw]);
const kp = () => { const privKey = randomBytes(32); return { privKey, pubKey: P5(native.curveGenerateKeypair(privKey)[0]) }; };
const baseKeyOf = (j) => Buffer.from(Object.values(JSON.parse(j)._sessions)[0].currentRatchet.ephemeralKeyPair.pubKey, 'base64');

const alice = kp(), bob = kp(), spk = kp(), opk = kp();
const a = native.x3DhBuildInitialSession(alice.privKey, alice.pubKey, spk.pubKey,
  native.curveSign(bob.privKey, spk.pubKey, null), opk.pubKey, 7, bob.pubKey, spk.pubKey, 22222, 1);
let b = native.x3DhBuildRecipientSession(bob.privKey, spk.privKey, spk.pubKey.slice(1),
  opk.privKey, alice.pubKey, baseKeyOf(a), 22222);

// The recipient session has no chains until its first decrypt does the ratchet
// step, so establish one before forging against the chain's position.
const opening = native.ratchetEncrypt(a, Buffer.from('buka'), alice.pubKey, 22222);
b = native.ratchetDecryptPkmsg(b, opening.ciphertext, bob.pubKey).sessionJson;
const entry = Object.values(JSON.parse(b)._sessions)[0];
const recvId = Object.keys(entry._chains).find((k) => entry._chains[k].chainType === 2);
const at = entry._chains[recvId].chainKey.counter;
console.log('receiving chain is at counter %d', at);

// Forge a frame: a real ephemeral key, a chosen counter, a wrong MAC.
const forge = (counter) => Buffer.concat([
  Buffer.from([0x33]),
  native.protoEncodeWhisper(Buffer.from(recvId, 'base64'), counter, 0, Buffer.alloc(32, 3)),
  Buffer.alloc(8, 0xaa),
]);

for (const [label, counter, expect] of [
  ['2000 ahead, reaches the MAC', at + 2000, /MAC/],
  ['2001 ahead, refused on distance', at + 2001, /future/],
  ['far beyond any chain position', 100000, /future/],
]) {
  try { native.ratchetDecryptWhisper(b, forge(counter), bob.pubKey); console.log('%s -> DECRYPTED', label); }
  catch (e) { console.log('%s -> %s (%s)', label, e.message, expect.test(e.message) ? 'as expected' : 'UNEXPECTED'); }
}

// A refused forgery must not move the record.
const before = JSON.stringify(JSON.parse(b));
try { native.ratchetDecryptWhisper(b, forge(at + 2001), bob.pubKey); } catch { /* expected */ }
console.log('a refused forgery left the record untouched: %s',
  JSON.stringify(JSON.parse(b)) === before);
```

### Encryption

Per message (`ratchet.rs:440-478`):

1. step the sending chain to the next counter, take its message key;
2. `derive_secrets(message_key, zeros(32), "WhisperMessageKeys", 3)`
   (`ratchet.rs:453`) → `[0]` AES-256 key, `[1]` MAC key, `[2][0..16]` IV;
3. AES-256-CBC with PKCS#7 padding (`ratchet.rs:44-62`);
4. encode a `WhisperMessage` protobuf;
5. `MAC = HMAC-SHA256(mac_key, ourIdentity(33) || remoteIdentity(33) || 0x33 || protobuf)`
   (`ratchet.rs:466-472`) — **our identity first**;
6. frame = `0x33 || protobuf || MAC[0..8]` (`ratchet.rs:475-478`).

The remote identity key is read from the record's `indexInfo`
(`ratchet.rs:419`), not passed in by the caller.

### Decryption

`decrypt_entry` (`ratchet.rs:542-610`) is deliberately ordered:

1. **plan** the DH ratchet step without applying it (`ratchet.rs:558`);
2. read the message key with `peek_message_key` — no mutation;
3. derive the AES/MAC keys;
4. `MAC = HMAC-SHA256(mac_key, remoteIdentity(33) || ourIdentity(33) || 0x33 || protobuf)`
   (`ratchet.rs:576-579`) — **reversed versus encrypt**;
5. `verify_truncated_left` — constant-time, prefix, matching the 8-byte wire
   MAC (`ratchet.rs:585`);
6. **only now** apply the plan, step the chain, consume the key
   (`ratchet.rs:593-603`);
7. clear `pendingPreKey` (`ratchet.rs:608`).

The sender is unauthenticated until step 5, so no part of the record moves
before it. A forged message cannot install a sending chain, rewrite the root
key, or burn a message key. Pinned by `bad_mac_leaves_the_record_untouched`
and `bad_mac_does_not_step_the_ratchet`.

### DH ratchet step

`plan_ratchet` (`ratchet.rs:271-362`) runs only when no chain exists for the
incoming remote ephemeral key. It computes:

1. the id of the receiving chain to retire, keyed by
   `currentRatchet.lastRemoteEphemeralKey` (`ratchet.rs:290-300`);
2. a receiving chain from `DH(ratchet_priv, remoteKey)`, with the root key
   updated via `derive_secrets(..., "WhisperRatchet", 2)` (`ratchet.rs:304-306`);
3. a fresh ephemeral keypair from `OsRng`, and the old sending chain's counter
   as the new `previousCounter` (`ratchet.rs:309-318`);
4. a sending chain from `DH(new_priv, remoteKey)`, salted with the **already
   updated** root key (`ratchet.rs:321-322`).

`apply_ratchet` (`ratchet.rs:364-389`) then performs the four writes. The
retired receiving chain is **removed**, not blanked. That is what closed a real
message-forgery hole: a chain left in the map with an empty key derived every
message key from a zero-length HMAC key, which is public knowledge. See
[CHANGELOG.md](../CHANGELOG.md) and `session.rs:161-176`.

```js
import { native } from '../index.js';
import { randomBytes } from 'node:crypto';

const P5 = (raw) => Buffer.concat([Buffer.from([0x05]), raw]);
const kp = () => { const privKey = randomBytes(32); return { privKey, pubKey: P5(native.curveGenerateKeypair(privKey)[0]) }; };
const baseKeyOf = (j) => Buffer.from(Object.values(JSON.parse(j)._sessions)[0].currentRatchet.ephemeralKeyPair.pubKey, 'base64');

const alice = kp(), bob = kp(), spk = kp(), opk = kp();
let a = native.x3DhBuildInitialSession(alice.privKey, alice.pubKey, spk.pubKey,
  native.curveSign(bob.privKey, spk.pubKey, null), opk.pubKey, 7, bob.pubKey, spk.pubKey, 22222, 1);
let b = native.x3DhBuildRecipientSession(bob.privKey, spk.privKey, spk.pubKey.slice(1),
  opk.privKey, alice.pubKey, baseKeyOf(a), 22222);

const eph = (j) => Buffer.from(Object.values(JSON.parse(j)._sessions)[0].currentRatchet.ephemeralKeyPair.pubKey, 'base64');
const ids = (j) => Object.entries(Object.values(JSON.parse(j)._sessions)[0]._chains)
  .map(([k, c]) => `${Buffer.from(k, 'base64').length}B:t${c.chainType}`);

const first = native.ratchetEncrypt(a, Buffer.from('satu'), alice.pubKey, 22222); a = first.sessionJson;
b = native.ratchetDecryptPkmsg(b, first.ciphertext, bob.pubKey).sessionJson;
console.log('after the first decrypt, bob has: %j', ids(b));

const reply = native.ratchetEncrypt(b, Buffer.from('dua'), bob.pubKey, 22222); b = reply.sessionJson;
a = native.ratchetDecryptWhisper(first.sessionJson, reply.ciphertext, alice.pubKey).sessionJson;
console.log('after the ratchet step, alice has: %j', ids(a));
console.log('alice swapped her ratchet key: %s', !eph(a).equals(baseKeyOf(first.sessionJson)));
console.log('alice now holds a RECEIVING (2) chain: %s',
  Object.values(JSON.parse(a)._sessions)[0]._chains &&
  Object.values(Object.values(JSON.parse(a)._sessions)[0]._chains).some((c) => c.chainType === 2));
```

### Chain map keys

`_chains` is keyed by the **33-byte wire public key** — the `0x05`-prefixed
form, which is what libsignal stores (`ratchet.rs:11-14`). Releases before the
alignment keyed it by the 32-byte X25519 key, so a lookup tries the 33-byte
form first and falls back to the stripped one (`ratchet.rs:114-123`). Nothing
is migrated: a record is read as found, and the first successful message
advances it to the canonical form.

`chainType` is `SENDING: 1`, `RECEIVING: 2` (`session.rs:116-117`). A legacy
`0` is still read as receiving (`session.rs:118`, `session.rs:126`).

---

## Protobuf codec

`native/signal/src/proto.rs`, hand-written, no schema compiler.

```text nonrunnable
WhisperMessage         1 ephemeral_key (bytes)   2 counter (varint)
                       3 previous_counter (varint)  4 ciphertext (bytes)
PreKeyWhisperMessage   1 pre_key_id (varint, optional)  2 base_key (bytes)
                       3 identity_key (bytes)     4 message (bytes)
                       5 registration_id (varint)  6 signed_pre_key_id (varint, optional)
```

`proto.rs:17-22`. Fields are written in ascending number order
(`proto.rs:306-325`).

### Decoding is strict

Unknown fields are skipped, as proto3 requires (`skip_field`,
`proto.rs:124-151`). Everything else is an error:

- a required field that is absent **or present but empty**
  (`proto.rs:204-215`, `proto.rs:282-303`);
- a known field at the wrong wire type (`expect_wire`, `proto.rs:156-164`) —
  skipping it would leave the field at its default, so a malformed message
  would decode into a well-formed one carrying a silently wrong value;
- a varint that does not fit `u32` (`read_varint_u32`, `proto.rs:94-98`) — a
  `previous_counter` of 2^33 truncating to 0 would stop the receiver deriving
  the previous chain's skipped keys, and those messages would become
  permanently undecryptable;
- a group wire type (3 or 4), which is not implemented
  (`proto.rs:141`);
- field number 0, or one above 2^29-1 (`proto.rs:113`).

Presence is tracked with explicit `seen_*` flags rather than inferred from a
default, so a missing field and a field legitimately carrying its default stay
distinguishable.

### Known-answer vectors

External bytes, not self-consistency. `proto.rs:421-433` pins
`WhisperMessage{ephemeral_key: "abc", counter: 300, previous_counter: 0,
ciphertext: "xyz"}` to `0a0361626310ac021800220378797a`, and
`proto.rs:667-685` pins a `PreKeyWhisperMessage` to
`08011201ee1a01ff2201102800`.

```js
import { native } from '../index.js';

console.log('WhisperMessage KAT: %s',
  native.protoEncodeWhisper(Buffer.from('abc'), 300, 0, Buffer.from('xyz')).toString('hex'));
console.log('PreKeyWhisperMessage KAT: %s', native.protoEncodePkmsg(JSON.stringify({
  pre_key_id: 1, base_key: [0xee], identity_key: [0xff], message: [0x10], registration_id: 0,
})).toString('hex'));
```

---

## Session record

`native/signal/src/session.rs`, libsignal v6's `_sessions` / `_chains` shape.

```text nonrunnable
{ "_sessions": { <baseKey b64>: SessionEntry }, "version": "v1" }

SessionEntry  registrationId, currentRatchet, indexInfo, _chains, pendingPreKey?
Ratchet       ephemeralKeyPair { pubKey, privKey }, lastRemoteEphemeralKey,
              previousCounter, rootKey
IndexInfo     baseKey, baseKeyType, closed, used, created, remoteIdentityKey
Chain         chainKey { counter, key? }, chainType, messageKeys
```

- `chainKey.key` is **optional** (`session.rs:147-159`): libsignal retires a
  chain by deleting its key and its serialiser omits the undefined field, so a
  record it wrote carries `{"chainKey":{"counter":n}}`. Reading that shape is
  mandatory or every bidirectional libsignal session becomes unreadable after
  its second ratchet step.
- `indexInfo.closed === -1` means open (`session.rs:228`).
- `chainType` is 1 or 2, with 0 read as receiving (`session.rs:116-118`).
- The active entry is chosen by `current_session_mut` (`session.rs:237-254`):
  prefer `closed === -1`, tie-break on the most recent `used`, and fall back to
  the newest entry. Taking the first `BTreeMap` value instead meant a
  multi-entry record could encrypt through an archived session.

Parsing rejects anything it does not model: `deny_unknown_fields` at every
level, a `version` other than `"v1"` (`session.rs:207-215`), and a JSON array
in place of an object (`session.rs:196-201` — serde would otherwise read `[]`
positionally into two defaulted fields and silently produce an empty record).

```js
import { native } from '../index.js';
import { SessionBuilder } from '../index.js';
import { newDevice } from './storage-stub.mjs';
import { ProtocolAddress } from '../index.js';

const alice = newDevice(11111);
const bob = newDevice(22222);
await new SessionBuilder(alice, new ProtocolAddress('6280000000000.0', 0)).initOutgoing(bob.bundle(7));
const json = alice.sessions.get('6280000000000.0.0').serialize();
const entry = Object.values(JSON.parse(json)._sessions)[0];

console.log('chainKey.key is optional: %s',
  native.sessionSerialize(JSON.stringify({ version: 'v1', _sessions: {} })) !== undefined);
console.log('a record with an absent chain key still round-trips as closed: %s', (() => {
  const r = JSON.parse(json);
  const e = Object.values(r._sessions)[0];
  for (const c of Object.values(e._chains)) delete c.chainKey.key;
  return !native.sessionSerialize(JSON.stringify(r)).includes('"key":null');
})());
console.log('indexInfo: %j', entry.indexInfo);
console.log('currentRatchet.previousCounter: %d', entry.currentRatchet.previousCounter);

for (const [what, input] of [
  ['JSON array', '[]'],
  ['version v2', '{"version":"v2","_sessions":{}}'],
  ['unmodelled top-level field', '{"version":"v1","_sessions":{},"x":1}'],
]) {
  try { native.sessionSerialize(input); console.log('%s ACCEPTED (unexpected)', what); }
  catch (e) { console.log('  %s -> %s', what.padEnd(30), e.message); }
}
```

---

## What is not covered

Stated because the absence matters, not to pad the list.

**No SenderKey, no group messaging.** There is no group support in this
package. `loadSenderKey` / `storeSenderKey` are never called on a storage
object — the seven methods in [api.md](./api.md#storage) are the complete
list. Multi-device group E2EE needs a SenderKey implementation the consumer
supplies.

**No `isTrustedIdentity`.** Never called. A peer changing its identity key is
not detected here; enforce it in your own storage if you need TOFU.

**Everything is synchronous.** All 16 `native` exports run on the calling
thread. An X3DH is four X25519 operations and blocks the event loop for its
duration. Moving them to napi async tasks is a real option nobody has taken.

**A retired chain's messages are unrecoverable.** By design, and shared with
libsignal. The previous receiving chain is removed on a ratchet step, so a
message held back across one is rejected with `MAC verification failed`. If
you need older messages, they have to arrive before you reply.

**One redundant X25519 per session build.** `x3dh.rs:121` and `x3dh.rs:180`
compute the same scalar multiply twice.

**`napi` is built with `features = ["full"]`** in `Cargo.toml`. Overkill for
what is used, and not cleaned up.

**The XEdDSA nonce is random.** With no `rnd` argument, 64 bytes come from
`OsRng` (`curve.rs:128-138`). That is the correct behaviour under RFC 8032 and
it makes byte-exact signature comparison against libsignal impossible — see
[the README](../README.md#what-is-actually-verified) for the narrower claim
that replaced it.
