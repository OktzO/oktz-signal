#![deny(unsafe_code)]
// curve25519-rs — native Rust untuk curve25519 DH (X25519) dan XEdDSA
// sign/verify. generate_keypair + scalar_multiply dipakai oleh X3DH dan
// double ratchet (Rust, bukan node:crypto). XEdDSA sign/verify tetap
// Rust (tidak ada di Node), napi wrapper ditambahkan Task 7+.
//
// Implementasi XEdDSA = BUKAN Ed25519 standar: konversi Montgomery↔Edwards,
// secret key dipakai langsung di hash (r = SHA512(sk||m)), sign bit di byte
// signature[63]. Port manual bit-exact di atas curve25519-dalek (constant-time).

use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::MontgomeryPoint;

use ed25519_dalek::{VerifyingKey, Signature};

use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha512};

/// B-poin Edwards (base point) yang sama dengan B di curve25519-js.
const B: EdwardsPoint = ED25519_BASEPOINT_POINT;

// --- helpers ---

fn check_len(v: &[u8], n: usize, what: &str) -> Result<(), String> {
    if v.len() != n {
        return Err(format!(
            "wrong {} length: {} (expected {})",
            what,
            v.len(),
            n
        ));
    }
    Ok(())
}

/// Clamping secret key versi curve25519-js (RFC 7748).
/// edsk[0] &= 248; edsk[31] &= 127; edsk[31] |= 64
fn clamp_scalar(sk: &[u8; 32]) -> [u8; 32] {
    let mut a = *sk;
    a[0] &= 248;
    a[31] &= 127;
    a[31] |= 64;
    a
}

/// r = SHA512(0xfe 0xff*31 || sk || m || rnd) mod L (crypto_sign_direct_rnd)
fn nonce_rnd(sk: &[u8; 32], msg: &[u8], rnd: &[u8]) -> Scalar {
    let mut h = Sha512::new();
    h.update([0xfeu8]);
    h.update([0xffu8; 31]);
    h.update(sk);
    h.update(msg);
    h.update(rnd);
    let digest: [u8; 64] = h.finalize().into();
    Scalar::from_bytes_mod_order_wide(&digest)
}

/// A = a*B (Edwards), compressed → byte-32 (scalarbase + pack di JS)
fn base_mult_scalar(a: &Scalar) -> [u8; 32] {
    let p = B * a;
    p.compress().to_bytes()
}

/// h = SHA512(R || A || msg) mod L
fn challenge(r: &[u8; 32], a: &[u8; 32], msg: &[u8]) -> Scalar {
    let mut h = Sha512::new();
    h.update(r);
    h.update(a);
    h.update(msg);
    let digest: [u8; 64] = h.finalize().into();
    Scalar::from_bytes_mod_order_wide(&digest)
}

/// Sign inti. sk = clamped secret (32B). Mengembalikan signature 64 byte
/// (R || S), dengan sign bit dari pubkey di byte ke-63 (persis curve25519-js).
fn sign_internal(sk_raw: &[u8; 32], msg: &[u8], rnd: &[u8; 64]) -> [u8; 64] {
    let sk = clamp_scalar(sk_raw);
    // scalar a untuk pubkey & S. JS pakai byte mentah (mod L), sama saja.
    let a = Scalar::from_bytes_mod_order(sk);
    // A = a*B (Edwards), packed. signBit = A[31] & 128.
    let a_bytes = base_mult_scalar(&a);
    let sign_bit = a_bytes[31] & 128;

    // r (nonce) = SHA512(0xfe 0xff*31 || sk || m || rnd) mod L
    let r = nonce_rnd(&sk, msg, rnd);

    // R = r*B, packed
    let r_bytes = base_mult_scalar(&r);

    // h = SHA512(R || A || msg)
    let h = challenge(&r_bytes, &a_bytes, msg);

    // S = r + h*a mod L
    let s = r + h * a;
    let s_bytes = s.to_bytes();

    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&r_bytes);
    sig[32..64].copy_from_slice(&s_bytes);
    // salurkan sign bit pubkey ke byte terakhir signature
    sig[63] |= sign_bit;
    sig
}

/// convertPublicKey di JS: montgomery u → edwards y = (u-1)/(u+1),
/// lalu restore sign bit dari sig[63]. Pakai dalek MontgomeryPoint::to_edwards.
fn pubkey_montgomery_to_edwards(pk: &[u8; 32], sign_bit: u8) -> Option<EdwardsPoint> {
    let mp = MontgomeryPoint(*pk);
    mp.to_edwards(sign_bit)
}

// --- public API (murni Rust; napi wrapper di lib.rs, Task 7) ---
// CATATAN: generate_keypair + scalar_multiply (X25519 DH) dipakai oleh
// X3DH dan double ratchet (Rust). XEdDSA sign/verify tetap Rust — napi
// wrapper ditambahkan Task 7+.

/// sign(secretKey, msg, opt_random?) → signature 64 byte (XEdDSA)
pub fn sign(secret_key: &[u8], msg: &[u8], opt_random: Option<&[u8]>) -> Result<[u8; 64], String> {
    check_len(secret_key, 32, "secret key")?;
    // The nonce must come from a CSPRNG. Deriving it as SHA512(sk||m) made it
    // deterministic, so two signatures over chosen messages recovered the
    // identity key (hidden-number-problem lattice attack). rnd stays
    // injectable so the libsignal-parity oracle and known-answer vectors can
    // still pin a fixed nonce.
    let mut generated = [0u8; 64];
    let rnd: [u8; 64] = match opt_random {
        Some(r) => {
            check_len(r, 64, "random data")?;
            r[..64].try_into().unwrap()
        }
        None => {
            OsRng.fill_bytes(&mut generated);
            generated
        }
    };
    let sk: [u8; 32] = secret_key[..32].try_into().unwrap();
    let sig = sign_internal(&sk, msg, &rnd);
    Ok(sig)
}

/// verify(publicKey, msg, signature) → bool (XEdDSA verify)
///
/// XEdDSA verify = Ed25519 verify standar setelah:
///   1. convertPublicKey: montgomery u → edwards y = (u-1)/(u+1)
///   2. restore sign bit dari signature[63] ke pubkey
///   3. hapus sign bit dari signature[63] (kembalikan S asli)
/// Pakai ed25519-dalek verify (R = S*B + h*A), bukan manual — dalek lebih
/// aman + sudah divalidasi. Nonce di verify memang standard (h = SHA512(R||A||m));
/// yang custom cuma di sisi sign.
pub fn verify(public_key: &[u8], msg: &[u8], signature: &[u8]) -> Result<bool, String> {
    check_len(public_key, 32, "public key")?;
    check_len(signature, 64, "signature")?;
    let pk: [u8; 32] = public_key[..32].try_into().unwrap();
    let sig: [u8; 64] = signature[..64].try_into().unwrap();

    // Restore sign bit dari signature ke pubkey (edwards).
    let sign_bit = sig[63] & 128;
    let a_bytes = match pubkey_montgomery_to_edwards(&pk, sign_bit >> 7) {
        Some(p) => p.compress().to_bytes(),
        None => return Ok(false),
    };

    // Hapus sign bit dari signature → S asli.
    let mut sig_clean = sig;
    sig_clean[63] &= 127;

    let signature = Signature::from_bytes(&sig_clean);
    let vk = match VerifyingKey::from_bytes(&a_bytes) {
        Ok(v) => v,
        Err(_) => return Ok(false),
    };
    // verify_strict, not verify: the cofactorless equation accepts low-order
    // keys and low-order R, which lets a forged signature pass. A bundle-supplied
    // identity key must never be able to authenticate that way.
    Ok(vk.verify_strict(msg, &signature).is_ok())
}

// --- X25519 DH (untuk X3DH/double ratchet di signal) ---
// CATATAN: dalek 4.1.x menghapus modul `x25519` (StaticSecret dkk). Pakai
// MontgomeryPoint::mul_base_clamped / mul_clamped — clamping RFC 7748 sama.

/// Seed carries no usable entropy. Clamping maps a constant seed to a valid
/// scalar, so it yields a publicly known private key. A random 32-byte seed
/// averages 128 bits set (sd ~8); reject the two constant bit patterns and
/// anything with too little weight to be entropy.
fn seed_is_degenerate(seed: &[u8; 32]) -> bool {
    let bits: u32 = seed.iter().map(|b| b.count_ones()).sum();
    bits <= 32 || bits == 256
}

/// generate_keypair(seed) → (public_key, secret_key) 32 byte (X25519)
///
/// Sesuai ruling plan: generate keypair untuk X3DH (identity key, signed
/// prekey, one-time prekeys). Deterministik dari seed (test-friendly).
pub fn generate_keypair(seed: &[u8]) -> Result<([u8; 32], [u8; 32]), String> {
    check_len(seed, 32, "seed")?;
    let seed32: [u8; 32] = seed[..32].try_into().unwrap();
    if seed_is_degenerate(&seed32) {
        return Err("seed is degenerate: not enough entropy for a private key".to_string());
    }
    let public = MontgomeryPoint::mul_base_clamped(seed32);
    Ok((public.to_bytes(), seed32))
}

/// scalar_multiply(secret_key, public_key) → shared secret 32 byte (X25519 DH)
///
/// Sesuai ruling plan: DH(priv, pub) untuk X3DH (IKa·SPKb, EKa·IKb, EKa·SPKb)
/// dan double ratchet root key.
pub fn scalar_multiply(secret_key: &[u8], public_key: &[u8]) -> Result<[u8; 32], String> {
    check_len(secret_key, 32, "secret key")?;
    check_len(public_key, 32, "public key")?;
    let sk32: [u8; 32] = secret_key[..32].try_into().unwrap();
    let pk32: [u8; 32] = public_key[..32].try_into().unwrap();
    let shared = MontgomeryPoint(pk32).mul_clamped(sk32);
    let bytes = shared.to_bytes();
    // Contributory behaviour. A small-order peer key makes the output all-zero
    // and discards this side's private key entirely, which would let anyone
    // derive the same root key and chain key from public data alone. RFC 7748
    // §6.1 allows this abort and names the OR-fold as the constant-time form;
    // RFC 8418 §2 requires it for X25519. curve25519-dalek does not do it for
    // us — MontgomeryPoint::IDENTITY exists so the caller can.
    let mut acc = 0u8;
    for b in bytes.iter() {
        acc |= *b;
    }
    if acc == 0 {
        return Err("non-contributory X25519 shared secret: peer key is small-order".to_string());
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_to_bytes(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }

    fn bytes_to_hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{:02x}", x)).collect()
    }

    #[test]
    fn test_rfc7748_x25519_known_answer() {
        // RFC 7748 §5.2 — vektor eksternal, bukan self-consistency.
        let alice_sk = hex_to_bytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let alice_pk_expected =
            hex_to_bytes("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        let bob_pk =
            hex_to_bytes("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        let shared_expected =
            hex_to_bytes("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

        let (pk, sk) = generate_keypair(&alice_sk).unwrap();
        assert_eq!(bytes_to_hex(&pk), bytes_to_hex(&alice_pk_expected), "public key");
        assert_eq!(sk, alice_sk, "secret key passthrough");

        let shared = scalar_multiply(&alice_sk, &bob_pk).unwrap();
        assert_eq!(bytes_to_hex(&shared), bytes_to_hex(&shared_expected), "shared secret");
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let sk = [0xABu8; 32];
        let msg = b"hello signal";
        let sig = sign(&sk, msg, None).unwrap();
        assert_eq!(sig.len(), 64);
        let (pk, _) = generate_keypair(&sk).unwrap();
        assert!(verify(&pk, msg, &sig).unwrap());
    }

    #[test]
    fn test_sign_verify_roundtrip_rnd() {
        let sk = [0xCDu8; 32];
        let rnd = [0xEFu8; 64];
        let msg = b"message with random";
        let sig = sign(&sk, msg, Some(&rnd)).unwrap();
        let (pk, _) = generate_keypair(&sk).unwrap();
        assert!(verify(&pk, msg, &sig).unwrap());
    }

    #[test]
    fn test_verify_rejects_tampered() {
        // [0x01; 32] is a degenerate seed (one bit per byte) and is now
        // rejected by generate_keypair; the assertion under test is about
        // tampering, not about the seed.
        let sk = [0x37u8; 32];
        let msg = b"integrity check";
        let sig = sign(&sk, msg, None).unwrap();
        let (pk, _) = generate_keypair(&sk).unwrap();
        assert!(!verify(&pk, b"tampered", &sig).unwrap());
    }

    #[test]
    fn test_generate_keypair_rejects_degenerate_seeds() {
        // Clamping turns a constant seed into a valid scalar, so
        // curveGenerateKeypair(Buffer.alloc(32)) returns a publicly known
        // private key. The same holds for any seed carrying no usable entropy.
        let mut low_bit = [0u8; 32];
        low_bit[0] = 0x01;
        let mut high_bit = [0u8; 32];
        high_bit[31] = 0x80;
        for (name, seed) in [
            ("all-zero", [0u8; 32]),
            ("all-0xFF", [0xFFu8; 32]),
            ("one bit at the bottom", low_bit),
            ("one bit at the top", high_bit),
            ("one bit per byte", [1u8; 32]),
        ] {
            match generate_keypair(&seed) {
                Ok(_) => panic!("{} seed must be rejected", name),
                Err(e) => assert!(e.contains("seed"), "{}: error must name the seed, got: {}", name, e),
            }
        }
    }

    #[test]
    fn test_generate_keypair_roundtrip() {
        let seed = [0x33u8; 32];
        let (pk, sk) = generate_keypair(&seed).unwrap();
        assert_eq!(pk.len(), 32);
        assert_eq!(sk.len(), 32);
        // deterministik
        let (pk2, sk2) = generate_keypair(&seed).unwrap();
        assert_eq!(pk, pk2);
        assert_eq!(sk, sk2);
    }

    #[test]
    fn test_scalar_multiply_dh_agreement() {
        let (alice_pk, alice_sk) = generate_keypair(&[0xAAu8; 32]).unwrap();
        let (bob_pk, bob_sk) = generate_keypair(&[0xBBu8; 32]).unwrap();
        let s_alice = scalar_multiply(&alice_sk, &bob_pk).unwrap();
        let s_bob = scalar_multiply(&bob_sk, &alice_pk).unwrap();
        assert_eq!(s_alice, s_bob);
        assert_ne!(s_alice, [0u8; 32]);
    }

    #[test]
    fn test_bad_lengths() {
        assert!(sign(&[0u8; 31], b"x", None).is_err());
        assert!(sign(&[0u8; 32], b"x", Some(&[0u8; 63])).is_err());
        assert!(verify(&[0u8; 31], b"x", &[0u8; 64]).is_err());
        assert!(verify(&[0u8; 32], b"x", &[0u8; 63]).is_err());
        assert!(generate_keypair(&[0u8; 31]).is_err());
        assert!(scalar_multiply(&[0u8; 31], &[0u8; 32]).is_err());
        assert!(scalar_multiply(&[0u8; 32], &[0u8; 31]).is_err());
    }

    #[test]
    fn test_verify_rejects_low_order_public_key() {
        // u = 0 is a low-order Montgomery point; the Edwards point it maps to has
        // order 2. The cofactorless equation is satisfiable there with a
        // signature forged without the real key, so the signed-prekey check at
        // x3dh would accept any bundle naming this public key.
        let a_point = pubkey_montgomery_to_edwards(&[0u8; 32], 0).unwrap();
        let a_bytes = a_point.compress().to_bytes();
        assert!(a_point.is_small_order(), "u=0 must map to a small-order point");

        // R = A with S = 0 satisfies [S]B == R + [h]A whenever h is odd.
        let mut msg: Vec<u8> = Vec::new();
        let mut found = false;
        for i in 0..64u8 {
            msg = [b"forged prekey bundle".as_slice(), &[i]].concat();
            if challenge(&a_bytes, &a_bytes, &msg).to_bytes()[0] & 1 == 1 {
                found = true;
                break;
            }
        }
        assert!(found, "expected an odd challenge for some probe message");

        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&a_bytes);
        assert!(
            !verify(&[0u8; 32], &msg, &sig).unwrap(),
            "a low-order public key must never accept a forged signature"
        );
    }

    #[test]
    fn test_sign_nonce_is_random_without_rnd() {
        // RFC 8032 hashes a CSPRNG 32-byte prefix precisely so that two
        // signatures over chosen messages cannot recover the identity key via a
        // hidden-number-problem lattice attack. rnd = None must therefore not
        // fall back to the deterministic SHA512(sk||m) nonce.
        let sk = [0x77u8; 32];
        let msg = b"deterministic nonce leak";
        let s1 = sign(&sk, msg, None).unwrap();
        let s2 = sign(&sk, msg, None).unwrap();
        assert_ne!(s1, s2, "rnd = None must not derive a deterministic nonce");

        let rnd = [0xEFu8; 64];
        let a = sign(&sk, msg, Some(&rnd)).unwrap();
        let b = sign(&sk, msg, Some(&rnd)).unwrap();
        assert_eq!(a, b, "an explicit rnd must still reproduce a fixed signature");
    }

    /// Every one of these forces X25519(sk, u) to all-zero, discarding the local
    /// private key's contribution entirely (cofactor 8). curve25519-js@0.0.4
    /// returns 0000..00 for each and raises nothing; RFC 7748 §6.1 permits
    /// aborting, RFC 8418 §2 requires it.
    ///
    /// This is the complete set of u in F_p whose point has order dividing 8,
    /// which is what the ladder needs since a clamped scalar is always a
    /// multiple of 8: the order-2 point u = 0, the two order-4 points
    /// u in {1, -1}, and the two order-8 points. u = p and u = p + 1 are extra
    /// byte strings a peer can send that RFC 7748 decodeUCoordinate folds onto
    /// 0 and 1, so a check written against the canonical encodings alone would
    /// miss them.
    const LOW_ORDER_POINTS: [&str; 7] = [
        // order 2
        "0000000000000000000000000000000000000000000000000000000000000000", // u = 0
        // order 4
        "0100000000000000000000000000000000000000000000000000000000000000", // u = 1
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // u = p - 1
        // order 8
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        // non-canonical encodings of u = 0 and u = 1
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // u = p
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // u = p + 1
    ];

    #[test]
    fn a_low_order_peer_key_is_rejected() {
        let sk = [7u8; 32];
        for p in LOW_ORDER_POINTS.iter() {
            let u = hex_to_bytes(p);
            assert!(
                scalar_multiply(&sk, &u).is_err(),
                "low-order point {} produced an accepted shared secret",
                p
            );
        }
    }

    #[test]
    fn a_valid_peer_key_still_computes() {
        let (pk_a, sk_a) = generate_keypair(&[3u8; 32]).unwrap();
        let (pk_b, sk_b) = generate_keypair(&[9u8; 32]).unwrap();
        assert_ne!(scalar_multiply(&sk_a, &pk_b).unwrap(), [0u8; 32]);
        assert_ne!(scalar_multiply(&sk_b, &pk_a).unwrap(), [0u8; 32]);
    }

    #[test]
    fn test_xeddsa_known_answer() {
        // Vektor tetap dari curve25519-js (implementasi yang dipakai libsignal):
        // sign(alice_sk, b"known answer test", rnd = 0xEF*64). Dihasilkan dari
        // curve25519-js, bukan dari kode ini — tetap vektor eksternal, kini
        // melalui jalur rnd karena nonce tanpa rnd sudah diacak.
        let sk = hex_to_bytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let expected_sig = "7b5664ddd65206b6e4f72926c4b8095e5639f2d706491e59dc8a9948ad81c67ccb5e9ed8e285b8136cea2a015639be2bb89042ec34816aaa7becfca726415981";
        let msg = b"known answer test";
        let sig = sign(&sk, msg, Some(&[0xEFu8; 64])).unwrap();
        assert_eq!(bytes_to_hex(&sig), expected_sig);
        let (pk, _) = generate_keypair(&sk).unwrap();
        assert!(verify(&pk, msg, &sig).unwrap());
    }
}
