# Changelog

Every entry below is traceable to a commit in this repository. Where a fix has
a test, the test is named.

## Unreleased — on `main`, after `v0.3.0-rc.1`

`v0.3.0-rc.1` is tagged at `8dfc4d3`. **The 51 commits after it are not
released.** `package.json` already says `0.3.0-rc.1`, so the version on npm
today is `8dfc4d3` and contains none of the security work below. If you are
running the published package, every item under "Security" applies to you.

### Security

**Message forgery through a retired chain** (`88f8173`, `38fd6da`). A
receiving chain retired by a DH ratchet step was left in the chain map with
its key blanked. `fill_message_keys` then derived every message key from that
zero-length key — and HMAC under an empty key is public knowledge, so a forged
ciphertext satisfied the real 8-byte MAC. A chain whose key is absent or blank
now fails closed (`session.rs:161-176`, `ratchet.rs:202`, `ratchet.rs:229`),
and the ratchet step removes the retired chain instead of emptying it
(`ratchet.rs:365-367`). Regression tests:
`closed_receiving_chain_is_rejected`, `tests/forgery.test.mjs`.

**Low-order public keys could authenticate a forged signature** (`60bfdb8`).
Signature verification used `ed25519-dalek`'s cofactorless `verify`, which
accepts a low-order public key. A bundle-supplied `u = 0` maps to an order-2
Edwards point whose lax equation `R = A, S = 0` satisfies trivially — and that
is the gate for signed-prekey authentication in X3DH. Now `verify_strict`
(`curve.rs:178`). Test: `test_verify_rejects_low_order_public_key`, which
constructs the forgery and shows it verified before the change.

**Pre-authentication session commit and one-time-prekey burn** (`20da159`).
`decryptPreKeyWhisperMessage` built an incoming session from the pkmsg's
attacker-supplied `identityKey`/`baseKey`, wrote it with `storeSession`, and
removed the one-time prekey — all *before* `ratchetDecryptPkmsg` checked the
MAC. One unauthenticated `type-3` message permanently destroyed the victim's
session for that contact, substituted an attacker-chosen remote identity as
the open session, and burned a prekey. The candidate is now built in memory and
storage is only touched after the MAC verifies (`src/session-cipher.js:99-127`).
Tests: `tests/session-pkmsg-auth.test.mjs`.

**A ratchet step was applied before the MAC was checked** (`ba8c087`). Decrypt
performed the DH ratchet step — swapping the ephemeral keypair, rewriting the
root key, installing a fresh sending chain — and consumed a message key
*before* verifying. A forged message could therefore move the record, and the
genuine message it displaced could no longer be retried. The step is now
planned and only applied after `verify_truncated_left` succeeds
(`ratchet.rs:558`, `ratchet.rs:593-603`). Tests:
`bad_mac_leaves_the_record_untouched`, `bad_mac_does_not_step_the_ratchet`.

**Deterministic XEdDSA nonce** (`968a586`). With no `rnd` argument the nonce
was `SHA512(sk ‖ m)`, so signing was deterministic. RFC 8032 hashes a CSPRNG
prefix precisely so that two chosen-message signatures cannot recover the
identity key via a hidden-number-problem lattice attack. 64 bytes now come
from `OsRng` (`curve.rs:128-138`); `rnd` stays injectable so known-answer
vectors and the oracle can still pin a fixed nonce. Test:
`test_sign_nonce_is_random_without_rnd`.

**Degenerate keypair seeds produced a publicly known private key** (`3c7fbd5`).
Clamping turns an all-zero seed into a valid scalar, so
`curveGenerateKeypair(Buffer.alloc(32))` returned a private key anyone could
compute. Seeds with no usable entropy are now rejected
(`curve.rs:189-203`). Test: `test_generate_keypair_rejects_degenerate_seeds`.

**X3DH accepted keys that contradicted each other** (`79ace8a`). The caller's
own identity pair was never checked against the public key it supplied, and
the signed prekey was never checked against the key the signature covered — so
a caller could pair a private key with someone else's public identity, or name
a prekey the recipient never signed (`x3dh.rs:107-113`). The recipient side
gained the matching check on its own signed-prekey pair (`x3dh.rs:232`).

**A panic could abort the host process** (`b549747`). napi-derive emits a bare
`extern "C"` shim, so a panic anywhere under it unwound across the FFI
boundary and took the whole Node process with it — every in-memory session, not
just the failing call. Every export now carries `#[napi(catch_unwind)]`
(`lib.rs:6-12`).

**Constant-time MAC comparison and PKCS#7 unpadding** (`2144163`,
`8dfc4d3`). MAC verification used a non-constant-time path; it is now
`verify_truncated_left`, the constant-time prefix check that matches the 8-byte
wire tag (`ratchet.rs:585`). Unpadding read only the final pad byte, so a
forged padding block was accepted; every pad byte is now compared and all
failures return one indistinguishable error (`ratchet.rs:82-98`). Tests:
`unpad_rejects_inconsistent_pad_bytes`, `unpad_failures_share_one_error_string`.

**Key material is now scrubbed on drop** (`1099270`, `3bda87f`). The root key,
the ratchet private key, every chain key and every derived message key are
zeroized when the record is released (`session.rs:33-45`), and every derived
key and IV is a `Zeroizing` buffer (`x3dh.rs:34`, `ratchet.rs:161`).

### Correctness

**libsignal interop was one-directional, and the oracle test was tautological
about it** (`fc0d234`). oktz-signal could not receive a single message from a
session libsignal had established. Three record-format mismatches:

- `chainType`: oktz-signal wrote `0` for a receiving chain;
  `chain_type.js` is `RECEIVING: 2`. `2` is written now, `0` is still read
  (`session.rs:116-118`).
- `_chains` key width: oktz-signal keyed the map by the stripped 32-byte
  X25519 key; libsignal keys it by the 33-byte wire key. A lookup now tries the
  33-byte form first and falls back (`ratchet.rs:114-123`), and new chains are
  written the libsignal way.
- retired-chain shape: libsignal deletes the key and its serialiser omits the
  field, so the record carries `{"chainKey":{"counter":n}}`. `ChainKey.key` is
  now optional, which is what made every bidirectional session unreadable after
  its second ratchet step (`session.rs:147-159`).

The oracle that should have caught this built the receiver's record *by hand*,
in oktz-signal's own shape, `chainType: 0` and 32-byte keys included — so the
test named "libsignal → oktz-signal interop" never let libsignal produce a
receiver record. It is now a record libsignal's own `SessionCipher` stored,
guarded by assertions on its shape, plus a four-turn bidirectional conversation
across DH ratchet steps in both engines.

**Malformed messages decoded into well-formed ones** (`d7722cc`, `c69ccc5`).
A missing or empty required field, a known field at the wrong wire type, a
varint that did not fit `u32`, and a group wire type are now errors instead of
silent defaults (`proto.rs:94-98`, `proto.rs:156-164`, `proto.rs:204-215`).
A `previous_counter` of 2^33 previously truncated to 0, which stopped the
receiver deriving the previous chain's skipped keys and made those messages
permanently undecryptable.

**Unrecognised session state was deleted instead of refused** (`f94ee58`).
A record with an unmodelled field at any level, a `version` other than `"v1"`,
or a JSON array in place of an object now fails to parse. `[]` in particular
used to satisfy serde positionally into two defaulted fields and produce an
empty record with no error — a silent state reset (`session.rs:196-215`).

**The 2000-message bound was an absolute counter** (`2144163`, `23b0572`).
An absolute ceiling on the wire counter dropped every message past 2000 of an
epoch while the peer was still entitled to send it, losing them silently until
the next ratchet step. The bound is now the *distance* from the chain, which is
libsignal's own bound and the thing that actually limits the work an
unauthenticated sender can buy (`ratchet.rs:32-41`).

**Prekey replay and rotation** (`4fbd22b`). A pkmsg naming an unresolvable
one-time prekey is now rejected in `initIncoming` instead of building a
session without DH4 that could never verify. `loadSignedPreKey` is called with
the id the message names, with an argument-less fallback, and the old
`Function.length` arity-sniffing is gone.

**Session lifecycle** (`8561782`, `116e095`, `fdc390d`). Archived session
entries are capped at 40, oldest evicted first, so repeated re-initiation
cannot grow a record without bound (`session-cipher.js:169`). The per-address
queue is shared with `SessionBuilder`, so a re-init cannot interleave an
encrypt's load/store. Self-reentrant jobs are dropped rather than deadlocking
the queue forever.

**`crypto` helpers** (`8e1d96d`). `deriveSecrets` silently returned three
chunks when asked for more; it now throws for any count it cannot produce.
The primitives accept a plain `Uint8Array` and reject anything else.

### Packaging, CI and release

- **`npm test` was broken on Node 22** (`110f700`). `node --test tests/` fails
  with `ERR_MODULE_NOT_FOUND`: Node ≥ 22 treats `--test` positional arguments
  as globs, so a bare directory is no longer a search root. `engines` promises
  `>=20`, so the project's own test command broke on a supported runtime.
  `scripts.test` is now bare `node --test`, which works on both.
- **A publish could ship a reverted loader** (`b3733a3`, `98a2d05`, `bfbac31`).
  `prepublishOnly` ran the same `napi build` over the committed
  `native/signal/index.cjs`, so publishing regenerated it and silently reverted
  every hand-maintained hardening fix. The build now patches the generated
  loader into the committed one, refuses to proceed if an anchor has moved, and
  `verify:loader` runs before anything can ship.
- **The release gate was a human-typed boolean** (`7966378`,
  `e3ee1e7`). Publishing was gated on a `workflow_dispatch` input standing in
  for a Termux run that does not exist. The Android artifact is no longer
  published at all, and the publish job now needs a job that actually runs
  both test suites.
- **The release gate rebuilt the loader it asserted on** (`c9fbac1`,
  `0bf3905`).
- **CI never ran the Rust suite** (`e3629b7`); the 39 `#[test]` functions had
  no entry point. Every platform job now runs `cargo test --locked`.
- **`cargo` re-resolved the lock during a release build** (`d012c65`);
  every `napi build` forwards `--locked`.
- **Loader hardening** (`fa41ac6`, `0585369`, `7797064`, `34d2e38`,
  `f40c979`): the binding version check is enforced unconditionally instead of
  behind an opt-in flag that buried the error under `MODULE_NOT_FOUND`; a bad
  `NAPI_RS_NATIVE_LIBRARY_PATH` no longer disables every platform fallback;
  absent WASI candidates no longer bury the real load failure; requiring the
  loader no longer leaves `process.report.excludeNetwork` mutated in the host
  process; and the libc probe no longer writes to the host's stderr.
- **Platform packages** (`db2f118`, `ec6d90d`, `52faff2`, `31cf9f9`,
  `bcf9fdc`): the binary is published as four per-platform optional packages
  and the main tarball carries no `.node` at all. The Android package was
  dropped from `optionalDependencies`.

### Not in this repository

The merge commit for this work also summarises fixes to group-sender-key slot
collisions and to a certificate/signature path that does not exist here. There
is no SenderKey code in `native/signal/src` or `src/`, and `loadSenderKey` /
`storeSenderKey` are never called. Those items are out of scope for this
package and are not listed as fixes.

## 0.3.0-rc.1 — `8dfc4d3`, 2026-09-12

- Decoded results cross the napi boundary as objects of `Buffer`s instead of
  JSON strings; the receiving chain is stepped in place rather than cloned
  (which had copied up to 2000 skipped message keys per message); the remote
  identity key is read natively from the record instead of being passed in and
  `JSON.parse`d on the JS side.
- MAC comparison made constant-time (`verify_truncated_left`), `verifyMAC` in
  `src/crypto.js` made constant-time (`timingSafeEqual`), the per-address queue
  shared between `SessionCipher` and `SessionBuilder`.
- Protobuf decoding made strict on varint range and field wire type.
- Dead `block-modes` and `hkdf` dependencies and two dead tests removed.

## 0.2.0-rc.2 — `d28880d`, 2026-09-11

Never tagged; the version string was never bumped.

- The active session entry is the open one (`closed === -1`, then most recent
  `used`), not the first `BTreeMap`/object value.
- A re-init archives the old session instead of replacing it, so its backlog
  stays decryptable.
- The one-time prekey is removed after a successful `initIncoming`.
- Signed prekeys are looked up by id, so rotation no longer produces a
  misleading MAC failure.

## 0.2.0-rc.1 — `3bfa614`, `558489a`

Never tagged.

- Queue map entries are deleted when the queue settles, so a long-lived process
  does not accumulate one entry per address forever.
- A benchmark write-up and an audit summary were added to the README.

> Both benchmark tables and most of that audit list were later withdrawn. The
> benchmark numbers cannot be reproduced from this repository — no benchmark
> script exists here or ever did — and the audit findings had been fixed
> already, so leaving them would have been misleading. See
> [the README](./README.md#known-limitations).

## 0.1.7 — `e392994`

- The wire ephemeral key is 33 bytes (`0x05` prefix, libsignal's form) rather
  than 32.
- `decryptPreKeyWhisperMessage` reuses an existing session by `baseKey` instead
  of always rebuilding, which had produced a spurious "waiting for this
  message" state.

## 0.1.6 — `517e930`

- `decryptPreKeyWhisperMessage` always rebuilt the session from the pkmsg,
  matching libsignal's behaviour at the time. Superseded by 0.1.7.

## 0.1.5 — `789f33a`

- The signed prekey public key is kept 33 bytes for signature verification and
  stripped only for the DH; the same for the one-time prekey.

## 0.1.4 — `0eeb507`

- Release rebuild of the binary with the 0.1.3 strip fix.

## 0.1.3 — `7f3a708`

- Strip the `0x05` prefix from the ephemeral key when decrypting. WhatsApp sends
  33 bytes and `scalar_multiply` requires 32, so every message failed with
  "wrong public key length: 33".

## 0.1.2 — `a81018a`

- `SessionRecord` accepts a plain object, which is what libsignal's
  `serialize()` returns.

## 0.1.1 — `04646ce`

- `PreKeyWhisperMessage.decode` helper.

## 0.1.0 — `94f53fc`

- First release: Rust X3DH, Double Ratchet, protobuf codec, session record, JS
  wrapper, and the `libsignal` oracle.
