<div align="center">

# ⚡ oktz-signal

### Signal Protocol native Rust — MIT replacement for `libsignal` (GPL)

[![Version](https://img.shields.io/badge/npm-0.2.0--rc.1-339933?style=for-the-badge&logo=npm&logoColor=white)](https://www.npmjs.com/package/oktz-signal)
[![Node](https://img.shields.io/badge/Node.js-%3E%3D20.0.0-339933?style=for-the-badge&logo=node.js&logoColor=white)](https://nodejs.org)
[![Rust](https://img.shields.io/badge/Rust-native%20napi--rs-red?style=for-the-badge&logo=rust&logoColor=white)](https://www.rust-lang.org)
[![Benchmark](https://img.shields.io/benchmark/E2EE%20session%20build%209%C3%97%20vs%20libsignal-9cf?style=for-the-badge)](#-benchmark-vs-libsignal)
[![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)](LICENSE)

</div>

**oktz-signal** adalah implementasi ulang (clean-room) dari Signal Protocol (X3DH + Double Ratchet + session record + protobuf codec) untuk WhatsApp Multi-Device, ditulis dalam **Rust** via **napi-rs** dan dibungkus JS. Dibuat sebagai pengganti `libsignal` (GPL-3.0) yang **license-safe** (MIT).

Wire format dan kriptografi diverifikasi bit-exact terhadap oracle `libsignal` v6 (WhiskeySockets/libsignal-node) lewat test interop dua arah.

---

## ⚠️ Status: UNSTABLE / EXPERIMENTAL

> **Proyek ini masih dalam tahap produksi awal (alpha).** Dipakai di `oktz-baileys` dan bot `ourin-md` untuk menggantikan `libsignal`, namun:

- **Wire compatibility** terhadap klien WhatsApp resmi **belum 100% terjamin** di semua edge case (perangkat lama, iOS versi lawas, re-sync session, backlog message).
- Bug interop ditemukan & diperbaiki terus (lihat [Changelog](#-changelog)) — **upgrade minor disarankan**.
- **Belum diaudit keamanan pihak ketiga.** Jangan pakai untuk skenario yang butuh jaminan audit formal.
- API masih bisa berubah antar minor version.

---

## Fitur

- **X3DH** — build session initiator & recipient (identity key, signed prekey, one-time prekey).
- **Double Ratchet** — message keys, chain stepping, skipped-message keys, DH ratchet, MAC.
- **SessionRecord** — serialize/deserialize format `libsignal` v6 (`_sessions`, `_chains`).
- **Protobuf codec** — `WhisperMessage` & `PreKeyWhisperMessage` wire format, hand-written.
- **Curve** — X25519 DH, XEdDSA sign/verify, generate keypair (Rust, `curve25519-dalek`).
- **JS wrapper** — `SessionCipher`, `SessionBuilder`, `SessionRecord`, `ProtocolAddress`, `QueueJob`.

## Instalasi

```bash
npm install oktz-signal
```

Native binary disertakan untuk **`linux-x64-gnu`** (`signal.linux-x64-gnu.node`). Build dari source untuk platform lain:

```bash
npm run build:native   # butuh Rust + gcc (nix-shell -p gcc)
```

### Manual build commands (untuk developer & host tidak didukung)

Prasyarat per target:
- **Linux x64 GNU (default)**: Rust stable + `gcc` / `clang`
- **Linux x64 musl (Alpine)**: Rust stable + `musl-gcc` + **Zig** (cross-compile via `zig cc`)
- **Linux ARM64 GNU**: Rust stable + `aarch64-linux-gnu-gcc` + **Zig** (cross-compile via `zig cc`)
- **Linux ARM64 musl (Alpine)**: Rust stable + **Zig** (cross-compile via `zig cc`)
- **Android ARM64 (Termux)**: Rust stable + **Android NDK** + `rustup target add aarch64-linux-android`

Commands (dijalankan dari root repo `oktz-signal`):

```bash
# Linux x64 GNU (native build)
cargo build --manifest-path native/signal/Cargo.toml --release --target x86_64-unknown-linux-gnu

# Linux x64 musl (cross-compile, butuh Zig)
rustup target add x86_64-unknown-linux-musl
cargo build --manifest-path native/signal/Cargo.toml --release --target x86_64-unknown-linux-musl

# Linux ARM64 GNU (cross-compile, butuh Zig + aarch64-linux-gnu toolchain)
rustup target add aarch64-unknown-linux-gnu
cargo build --manifest-path native/signal/Cargo.toml --release --target aarch64-unknown-linux-gnu

# Linux ARM64 musl (cross-compile, butuh Zig)
rustup target add aarch64-unknown-linux-musl
cargo build --manifest-path native/signal/Cargo.toml --release --target aarch64-unknown-linux-musl

# Android ARM64 (butuh Android NDK di $ANDROID_NDK_HOME atau $ANDROID_HOME/ndk/...)
rustup target add aarch64-linux-android
cargo build --manifest-path native/signal/Cargo.toml --release --target aarch64-linux-android
```

> **Catatan**: Command di atas memakai `cargo` langsung (bukan `napi build`) untuk build dari source tanpa napi-rs CLI. Hasil binary ada di `native/signal/target/<target>/release/libsignal.{so|dylib|dll}`. Untuk publish ke npm, gunakan `napi build --release --target <target> ...` seperti di CI.

### Platform install verification

Setelah install (via npm atau build lokal), verifikasi native module load:

```bash
# Verifikasi native API tersedia
node -e "import('oktz-signal').then(({ native }) => console.log(typeof native.ratchetEncrypt))"
# Output: function

# Verifikasi curve25519 (dependency terpisah)
node -e "console.log(typeof require('oktz-curve25519').sign)"
# Output: function
```

Kedua command harus mengeluarkan `function`. Jika error/undefined, native binary tidak cocok platform atau gagal load.

## Penggunaan

```js
import { SessionCipher, SessionBuilder, SessionRecord, ProtocolAddress } from 'oktz-signal';

const addr = new ProtocolAddress('628xxxxxxx.0', 0);
const cipher = new SessionCipher(storage, addr);

// Decrypt incoming
const plaintext = await cipher.decryptPreKeyWhisperMessage(ciphertext);
// atau
const plaintext = await cipher.decryptWhisperMessage(ciphertext);

// Encrypt outgoing
const { type, body } = await cipher.encrypt(data); // type: 1 = msg, 3 = pkmsg
```

`storage` harus mengimplementasikan antarmuka yang sama dengan libsignal (`loadSession`, `storeSession`, `getOurIdentity`, `getOurRegistrationId`, `loadPreKey`, `loadSignedPreKey`, `loadSenderKey`, `storeSenderKey`).

## Testing

```bash
npm test                                   # unit + wrapper
node --test tests/oracle/interop.test.mjs  # oracle vs libsignal (butuh libsignal terinstall)
```

---

## ⏱️ Benchmark vs libsignal

Diukur pada Node v20.19.1, Linux x64, in-process loop, kunci acak per iterasi (bukan kunci deterministik). Script benchmark tersedia di repo test suite dan bisa direproduksi langsung.

### 1. Sesi penuh (X3DH + PKMsg encrypt + decrypt)

Satu siklus lengkap membangun session baru: initOutgoing (X3DH: 3× X25519 + HKDF) → encrypt pkmsg → initIncoming → decrypt.

| Implementasi | µs/op | Speedup |
|---|---:|---:|
| **oktz-signal (Rust native)** | **3.519** | — |
| libsignal v6 (JS, WhiskeySockets) | 31.849 | **oktz-signal 9,0× lebih cepat** |

### 2. Steady-state (Double Ratchet encrypt + decrypt per pesan)

Session sudah ter-establish, satu pesan bolak-balik (ratchet step + AES-256-CBC + MAC di kedua arah):

| Implementasi | µs/op | Speedup |
|---|---:|---:|
| **oktz-signal (via JS wrapper)** | **195–330*** | — |
| libsignal v6 (JS) | 570–695 | **oktz-signal 2–3,5× lebih cepat** |

\* Rentang antar-run; raw native call tanpa wrapper JS = **278 µs** — wrapper (QueueJob + serialize + JSON.parse) menambah ±110 µs/op. Ini target optimasi berikutnya (lihat [Audit](#-audit-internal--known-limitations)).

### 3. Crypto primitive (via `oktz-curve25519` / `curve.rs`)

| Operasi | oktz-signal (Rust) | libsignal (JS) | Speedup |
|---|---:|---:|---:|
| XEdDSA sign (64-byte) | 165,6 µs | 30.724 µs | **186×** |
| XEdDSA verify (64-byte) | 138,9 µs | 32.295 µs | **233×** |
| X25519 DH | 330,8 µs | 308,2 µs | ~par (keduanya native) |

### Verifikasi kebenaran (bukan cuma cepat)

- ✅ **Oracle interop 2-arah** vs libsignal v6 — wire format bit-exact (X25519 RFC 7748 KAT, XEdDSA, layout shared secret, info strings, message key derivation, AES-CBC+MAC, protobuf WhisperMessage/PKMsg, format session record).
- ✅ **Out-of-order delivery**: pesan diterima terbalik (#3 → #2 → #1) semuanya ter-decrypt benar (skipped-message keys bekerja).
- ✅ **Replay & reuse session by baseKey** — pesan PKMsg kedua dengan baseKey sama tidak memicu rebuild session (fix 0.1.7 terverifikasi).
- ✅ **pendingPreKey semantics** — pesan type-3 persist sampai recipient membalas, **match perilaku libsignal** (diverifikasi side-by-side).

---

## 🔍 Audit internal & Known Limitations

Audit baris-per-baris penuh (Rust + JS + binding napi) — September 2026. Ringkasan temuan yang relevan bagi pengguna:

### Yang sudah benar

- **Memory safety Rust**: seluruh file `#![deny(unsafe_code)]`, stateless (tanpa Mutex/thread/Arc/static mut) — **tidak ada leak di production path**.
- Semua cache internal (di consumer) memakai LRU + TTL dan di-cleanup di `close()`.

### HIGH — direkomendasikan diperbaiki sebelum skala besar

1. **Pemilihan session entry**: `values_mut().next()` (Rust) / `Object.values(_sessions)[0]` (JS wrapper) mengambil entry *pertama* BTreeMap/object, bukan entry `closed == -1` (session aktif). Record dengan ≥2 entry (migrasi dari libsignal, LID migration, retry-receipt) berisiko encrypt/decrypt dengan session terarsip. *Mitigasi sementara: pastikan record hanya berisi 1 session open (prune di consumer).*
2. **Session lama di-replace, bukan diarsipkan** saat `initIncoming` dengan baseKey baru — backlog pesan dari session lama gagal decrypt (libsignal mengarsipkan di `_sessions`).
3. **Serialisasi JSON berlapis** di hot path (4–6 roundtrip JSON + base64 per pesan; ciphertext sebagai array-angka JSON ±4× bloat). Fix kandidat: return `Buffer` + hapus roundtrip `session_serialize`/`SessionRecord` — estimasi mendekati raw native 278 µs.
4. **`isTrustedIdentity` tidak pernah dipanggil wrapper** — perubahan identity key lawan tidak terdeteksi (libsignal throw `UntrustedIdentityKeyError` di titik ini). Implementasikan di `initIncoming` + decrypt path bila butuh TOFU enforcement.

### MEDIUM (ringkas)

- One-time prekey tidak dihapus setelah `initIncoming` (replay possible bila record hilang) — libsignal memanggil `removePreKey`.
- `loadSignedPreKey()` tanpa argumen ID — signed prekey rotasi menyebabkan MAC fail dengan error menyesatkan.
- Semua operasi napi **sync** di main thread JS — X3DH (3–4× X25519) memblok event loop; kandidat pindah ke napi async Task.
- Key material tidak di-zeroize (`zeroize` crate sudah ada di dependency tree); MAC compare non-constant-time (`subtle` tersedia via dalek).
- Duplikasi X25519 di X3DH (`a3` == `shared_ratchet`, dihitung 2×).

### Tidak ada di cakupan (by design)

- **Sender Key / group E2EE** tidak diimplementasi — hanya X3DH + Double Ratchet 1:1. Consumer multi-device group (baileys fork) perlu implementasi SenderKey sendiri atau konsumen bertanggung jawab.

### Dead code & dependency (dihapus di rilis berikutnya)

`block-modes` + `hkdf` crates (orphan, tidak pernah dipakai), `napi features = ["full"]` overkill, duplikat binary `.node` 1MB di root repo, `src/crypto.js` (re-implementasi JS dari yang sudah ada di Rust).

---

## Changelog

| Versi | Isi |
|-------|-----|
| **0.2.0-rc.1** | Upstream dari 0.1.7 (audit internal: memory safety Rust bersih — zero `unsafe`, stateless, no leak production; oracle interop 2-arah bit-exact; out-of-order decrypt terverifikasi). Known issues & roadmap fix didokumentasikan di [Audit](#-audit-internal--known-limitations) |
| **0.1.7** | Wire ephemeral key → **33-byte** (`0x05` prefix, format libsignal). `decryptPreKeyWhisperMessage` reuse session by baseKey (jangan selalu rebuild) — fix "Menunggu pesan ini" |
| 0.1.6 | `decryptPreKeyWhisperMessage` selalu rebuild session dari pkmsg |
| 0.1.5 | Signed prekey 33-byte utk verifikasi signature; prekey_pub strip internal utk DH |
| 0.1.3 | Strip `0x05` prefix dari ephemeral key saat decrypt |
| 0.1.2 | `SessionRecord` terima input object (libsignal serialize return object) |
| 0.1.0 | Rilis pertama — full rewrite Rust + oracle test |

## Lisensi

**MIT** — bebas dipakai, dimodifikasi, dan disebarluaskan, termasuk untuk komersial. Tidak seperti `libsignal` (GPL-3.0) yang membatasi distribusi.

> ⚠️ **Disclaimer:** "Signal Protocol" adalah trademark dari Signal Foundation. Proyek ini independen, tidak berafiliasi dengan Signal, dan hanya implementasi ulang dari spesifikasi protokol yang sudah publik.
