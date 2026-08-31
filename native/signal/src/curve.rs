// curve25519-rs — native Rust untuk fungsi curve25519 yang TIDAK ada native di
// Node.js: XEdDSA sign/verify (Signal). generateKeyPair + sharedKey sudah
// native node:crypto (x25519 keygen + diffieHellman) → TIDAK dibuat ulang,
// zero binary tambahan untuk yang Node sudah punya.
//
// Implementasi XEdDSA = BUKAN Ed25519 standar: konversi Montgomery↔Edwards,
// secret key dipakai langsung di hash (r = SHA512(sk||m)), sign bit di byte
// signature[63]. Port manual bit-exact di atas curve25519-dalek (constant-time).

use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::MontgomeryPoint;

use ed25519_dalek::{VerifyingKey, Signature, Verifier};

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

/// r = SHA512(sk || m) mod L  → Scalar (crypto_sign_direct)
fn nonce_direct(sk: &[u8; 32], msg: &[u8]) -> Scalar {
    let mut h = Sha512::new();
    h.update(sk);
    h.update(msg);
    let digest: [u8; 64] = h.finalize().into();
    Scalar::from_bytes_mod_order_wide(&digest)
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
fn sign_internal(sk_raw: &[u8; 32], msg: &[u8], rnd: Option<&[u8; 64]>) -> [u8; 64] {
    let sk = clamp_scalar(sk_raw);
    // scalar a untuk pubkey & S. JS pakai byte mentah (mod L), sama saja.
    let a = Scalar::from_bytes_mod_order(sk);
    // A = a*B (Edwards), packed. signBit = A[31] & 128.
    let a_bytes = base_mult_scalar(&a);
    let sign_bit = a_bytes[31] & 128;

    // r (nonce) — beda jalur: direct vs rnd (hash separation).
    let r = match rnd {
        Some(rnd) => nonce_rnd(&sk, msg, rnd),
        None => nonce_direct(&sk, msg),
    };

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
// CATATAN: generateKeyPair + sharedKey TIDAK dibuat di Rust — Node 20/22
// sudah native (node:crypto generateKeyPairSync('x25519') + diffieHellman).
// Hanya XEdDSA sign/verify (yang tidak ada di Node) yang dibuat native.

/// sign(secretKey, msg, opt_random?) → signature 64 byte (XEdDSA)
pub fn sign(secret_key: &[u8], msg: &[u8], opt_random: Option<&[u8]>) -> Result<[u8; 64], String> {
    check_len(secret_key, 32, "secret key")?;
    let mut rnd: Option<[u8; 64]> = None;
    if let Some(r) = opt_random {
        check_len(r, 64, "random data")?;
        rnd = Some(r[..64].try_into().unwrap());
    }
    let sk: [u8; 32] = secret_key[..32].try_into().unwrap();
    let sig = sign_internal(&sk, msg, rnd.as_ref());
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
    Ok(vk.verify(msg, &signature).is_ok())
}

// --- X25519 DH (untuk X3DH/double ratchet di signal) ---
// CATATAN: dalek 4.1.x menghapus modul `x25519` (StaticSecret dkk). Pakai
// MontgomeryPoint::mul_base_clamped / mul_clamped — clamping RFC 7748 sama.

/// generate_keypair(seed) → (public_key, secret_key) 32 byte (X25519)
///
/// Sesuai ruling plan: generate keypair untuk X3DH (identity key, signed
/// prekey, one-time prekeys). Deterministik dari seed (test-friendly).
pub fn generate_keypair(seed: &[u8]) -> Result<([u8; 32], [u8; 32]), String> {
    check_len(seed, 32, "seed")?;
    let seed32: [u8; 32] = seed[..32].try_into().unwrap();
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
    Ok(shared.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let sk = [0x01u8; 32];
        let msg = b"integrity check";
        let sig = sign(&sk, msg, None).unwrap();
        let (pk, _) = generate_keypair(&sk).unwrap();
        assert!(!verify(&pk, b"tampered", &sig).unwrap());
    }

    #[test]
    fn test_sign_deterministic() {
        let sk = [0x22u8; 32];
        let msg = b"same input same sig";
        let s1 = sign(&sk, msg, None).unwrap();
        let s2 = sign(&sk, msg, None).unwrap();
        assert_eq!(s1, s2);
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
}
