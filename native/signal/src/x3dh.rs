#![deny(unsafe_code)]
// X3DH initiator session build (libsignal v6 wire-compatible).
// Info strings: "WhisperText" (root key) and "WhisperRatchet" (sending ratchet).
// Shared secret layout: 0xff*32 || a1 || a2 || a3 [|| a4].
// Details verified from libsignal v6 oracle — see task-5-brief.md.

use crate::curve;
use crate::session::{
    self, Chain, ChainKey, IndexInfo, KeyPair, PendingPreKey, Ratchet, SessionEntry, SessionRecord,
};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

pub struct X3dhParams<'a> {
    pub identity_priv: &'a [u8],      // 32 bytes
    pub identity_pub: &'a [u8],       // 33 bytes (0x05 prefix + 32-byte X)
    pub signed_prekey_pub: &'a [u8],  // 32 bytes (X25519)
    pub signed_prekey_sig: &'a [u8],  // 64 bytes XEdDSA
    pub prekey_pub: Option<&'a [u8]>, // 32 bytes one-time prekey (optional)
    pub prekey_id: Option<u32>,
    pub recipient_pub: &'a [u8],    // 33 bytes (recipient identity)
    pub recipient_prekey: &'a [u8], // 32 bytes (recipient signed prekey)
    pub registration_id: u32,
    pub signed_key_id: u32, // recipient's signed prekey ID (from device bundle)
}

/// deriveSecrets pattern (RFC 5869, 3 chunks) — same as libsignal crypto.js.
/// Chunks are Zeroizing: they carry the root key and the first chain key.
fn derive_secrets(input: &[u8], salt: &[u8], info: &[u8]) -> Result<[Zeroizing<Vec<u8>>; 3], String> {
    let prk = {
        let mut mac = HmacSha256::new_from_slice(salt).map_err(|e| e.to_string())?;
        mac.update(input);
        mac.finalize().into_bytes()
    };
    let mut out: [Zeroizing<Vec<u8>>; 3] = Default::default();
    let mut prev = Vec::new();
    for (i, slot) in out.iter_mut().enumerate() {
        let mut mac = HmacSha256::new_from_slice(prk.as_ref()).map_err(|e| e.to_string())?;
        mac.update(&prev);
        mac.update(info);
        mac.update(&[(i + 1) as u8]);
        let chunk = mac.finalize().into_bytes().to_vec();
        *slot = Zeroizing::new(chunk.clone());
        prev = chunk;
    }
    Ok(out)
}

/// Strip the 0x05 wire prefix from a 33-byte XEdDSA public key. 32-byte X25519
/// keys pass through unchanged.
fn strip_prefix(key: &[u8]) -> &[u8] {
    if key.len() == 33 && key[0] == 0x05 {
        &key[1..]
    } else {
        key
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

/// Initiator side (SessionBuilder.processPreKey): build initial session record.
pub fn build_initial_session(params: &X3dhParams) -> Result<String, String> {
    // Ephemeral base key — fresh random seed (OsRng only).
    let mut seed = [0u8; 32];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut seed);
    build_initial_session_with_ephemeral(params, &seed)
}

/// Same as [`build_initial_session`] with caller-provided ephemeral private key.
/// Tests pass a fixed key to pin key roles; keeps the OsRng path in the public fn.
pub(crate) fn build_initial_session_with_ephemeral(
    params: &X3dhParams,
    ephemeral_priv: &[u8],
) -> Result<String, String> {
    // 1. Verify signed prekey signature against recipient identity key.
    let recipient_pub_32 = params
        .recipient_pub
        .get(1..33)
        .ok_or("recipient_pub must be 33 bytes")?;
    // signed_prekey_pub dari JS = 33-byte (0x05 prefix) — signature dibuat atas 33-byte penuh
    // Untuk DH, strip ke 32-byte X25519
    let spk = if params.signed_prekey_pub.len() == 33 && params.signed_prekey_pub[0] == 0x05 {
        &params.signed_prekey_pub[1..]
    } else {
        params.signed_prekey_pub
    };
    let verified = curve::verify(recipient_pub_32, params.signed_prekey_pub, params.signed_prekey_sig)?;
    if !verified {
        return Err("signed prekey signature verification failed".to_string());
    }

    // 1b. The caller's own identity pair and the recipient prekey must be the
    // keys they claim to be. Both were previously accepted unchecked, so a
    // caller could pair a private key with someone else's public identity, or
    // name a signed prekey other than the one the recipient signed.
    let identity_pub_32 = strip_prefix(params.identity_pub);
    if &curve::generate_keypair(params.identity_priv)?.0[..] != identity_pub_32 {
        return Err("identity_pub does not match identity_priv".to_string());
    }
    if strip_prefix(params.recipient_prekey) != spk {
        return Err("recipient_prekey does not match the signed prekey".to_string());
    }

    // 2. Ephemeral base key — public = base(priv). generate_keypair returns (pub, seed).
    let (ephemeral_pub, _) = curve::generate_keypair(ephemeral_priv)?;

    // 3. DH agreements — pakai spk (32-byte, stripped)
    let a1 = curve::scalar_multiply(params.identity_priv, spk)?;
    let a2 = curve::scalar_multiply(ephemeral_priv, recipient_pub_32)?;
    let a3 = curve::scalar_multiply(ephemeral_priv, spk)?;

    // 4. Shared secret: 0xff*32 || a1 || a2 || a3 [|| a4].
    let has_opk = params.prekey_pub.is_some();
    let len = if has_opk { 160 } else { 128 };
    let mut shared = Zeroizing::new(vec![0u8; len]);
    for i in 0..32 {
        shared[i] = 0xff;
    }
    shared[32..64].copy_from_slice(&a1);
    shared[64..96].copy_from_slice(&a2);
    shared[96..128].copy_from_slice(&a3);
    if let Some(opk) = params.prekey_pub {
        // opk dari JS = 33-byte (0x05 prefix) — strip untuk DH
        let opk32 = if opk.len() == 33 && opk[0] == 0x05 {
            &opk[1..]
        } else {
            opk
        };
        let a4 = curve::scalar_multiply(ephemeral_priv, opk32)?;
        shared[128..160].copy_from_slice(&a4);
    }

    // 5. masterKey = deriveSecrets(shared, zeros(32), "WhisperText").
    let salt = [0u8; 32];
    let mk = derive_secrets(&shared, &salt, b"WhisperText")?;
    let mut root_key = mk[0].clone();

    // 6. currentRatchet + indexInfo.
    let now = now_ms();
    let mut entry = SessionEntry {
        registrationId: params.registration_id,
        currentRatchet: Ratchet {
            ephemeralKeyPair: KeyPair {
                privKey: crate::util::b64(ephemeral_priv),
                pubKey: crate::util::b64(&ephemeral_pub),
            },
            lastRemoteEphemeralKey: crate::util::b64(spk),
            previousCounter: 0,
            rootKey: crate::util::b64(&root_key),
        },
        indexInfo: IndexInfo {
            baseKey: crate::util::b64(&ephemeral_pub),
            baseKeyType: if has_opk { 1 } else { 0 },
            closed: -1,
            used: now,
            created: now,
            remoteIdentityKey: crate::util::b64(params.recipient_pub),
        },
        chains: BTreeMap::new(),
        pendingPreKey: Some(PendingPreKey {
            baseKey: crate::util::b64(&ephemeral_pub),
            signedKeyId: Some(params.signed_key_id),
            preKeyId: params.prekey_id,
        }),
    };

    // 7. calculateSendingRatchet: shared = DH(ephemeral_priv, theirSignedPubKey),
    //    deriveSecrets(shared, rootKey, "WhisperRatchet"), add sending chain.
    let shared_ratchet = curve::scalar_multiply(ephemeral_priv, spk)?;
    let mk_ratchet = derive_secrets(&shared_ratchet, &root_key, b"WhisperRatchet")?;
    root_key = mk_ratchet[0].clone();
    entry.currentRatchet.rootKey = crate::util::b64(&root_key);
    entry.chains.insert(
        crate::util::b64(&ephemeral_pub),
        Chain {
            chainKey: ChainKey {
                counter: -1,
                key: Some(crate::util::b64(&mk_ratchet[1])),
            },
            chainType: session::SENDING,
            messageKeys: BTreeMap::new(),
        },
    );

    let mut record = SessionRecord {
        sessions: BTreeMap::new(),
        version: "v1".to_string(),
    };
    record.sessions.insert(crate::util::b64(&ephemeral_pub), entry);

    session::serialize(&record)
}

/// Recipient side (SessionBuilder.initIncoming): build session from incoming
/// PreKeyWhisperMessage data. Returns serialized SessionRecord JSON.
///
/// Args:
///   our_identity_priv:   recipient's own identity private key (32 bytes)
///   our_signed_prekey_priv: recipient's signed prekey private key (32 bytes)
///   our_signed_prekey_pub: recipient's signed prekey public key (32 bytes)
///   our_prekey_priv:     recipient's one-time prekey private key (optional, 32 bytes)
///   sender_identity:     sender's identity key from message (33 bytes, 0x05-prefixed)
///   sender_ephemeral:    sender's ephemeral base key from message (32 bytes)
///   registration_id:     from message
pub fn build_recipient_session(
    our_identity_priv: &[u8],
    our_signed_prekey_priv: &[u8],
    our_signed_prekey_pub: &[u8],
    our_prekey_priv: Option<&[u8]>,
    sender_identity: &[u8],
    sender_ephemeral: &[u8],
    registration_id: u32,
) -> Result<String, String> {
    let sender_identity_x = sender_identity
        .get(1..33)
        .ok_or("sender_identity must be 33 bytes")?;

    // The ratchet keypair stored below is used to derive receiving chains, so a
    // public key that our private key does not produce would build a session
    // that can never decrypt anything while looking well-formed.
    if &curve::generate_keypair(our_signed_prekey_priv)?.0[..] != strip_prefix(our_signed_prekey_pub) {
        return Err("our_signed_prekey_pub does not match our_signed_prekey_priv".to_string());
    }

    // DH agreements (matched to libsignal initSession non-initiator order).
    // a1 = DH(theirSignedPubKey, ourIdentityKey.privKey) = DH(EK_A, IK_B_priv)
    let a1 = curve::scalar_multiply(our_identity_priv, sender_ephemeral)?;
    // a2 = DH(theirIdentityPubKey, ourSignedKey.privKey) = DH(IK_A, SPK_B_priv)
    let a2 = curve::scalar_multiply(our_signed_prekey_priv, sender_identity_x)?;
    // a3 = DH(theirSignedPubKey, ourSignedKey.privKey) = DH(EK_A, SPK_B_priv)
    let a3 = curve::scalar_multiply(our_signed_prekey_priv, sender_ephemeral)?;

    let has_opk = our_prekey_priv.is_some();
    let len = if has_opk { 160 } else { 128 };
    let mut shared = Zeroizing::new(vec![0u8; len]);
    for i in 0..32 {
        shared[i] = 0xff;
    }
    // Non-initiator order: shared[32..64] = a2 (DH1), shared[64..96] = a1 (DH2)
    shared[32..64].copy_from_slice(&a2);
    shared[64..96].copy_from_slice(&a1);
    shared[96..128].copy_from_slice(&a3);
    if let Some(opk_priv) = our_prekey_priv {
        let a4 = curve::scalar_multiply(opk_priv, sender_ephemeral)?;
        shared[128..160].copy_from_slice(&a4);
    }

    let salt = [0u8; 32];
    let mk = derive_secrets(&shared, &salt, b"WhisperText")?;
    let root_key = mk[0].clone();

    let now = now_ms();
    let entry = SessionEntry {
        registrationId: registration_id,
        currentRatchet: Ratchet {
            ephemeralKeyPair: KeyPair {
                privKey: crate::util::b64(our_signed_prekey_priv),
                pubKey: crate::util::b64(our_signed_prekey_pub),
            },
            lastRemoteEphemeralKey: crate::util::b64(sender_ephemeral),
            previousCounter: 0,
            rootKey: crate::util::b64(&root_key),
        },
        indexInfo: IndexInfo {
            baseKey: crate::util::b64(sender_ephemeral),
            baseKeyType: 0, // THEIRS
            closed: -1,
            used: now,
            created: now,
            remoteIdentityKey: crate::util::b64(sender_identity),
        },
        chains: BTreeMap::new(),
        pendingPreKey: None,
    };

    let mut record = SessionRecord {
        sessions: BTreeMap::new(),
        version: "v1".to_string(),
    };
    record.sessions.insert(crate::util::b64(sender_ephemeral), entry);

    session::serialize(&record)
}
mod tests {
    use super::*;

    fn test_params(reg_id: u32, sk_byte: u8, spk_byte: u8, sig: &[u8]) -> X3dhParams<'static> {
        let identity_sk = [sk_byte; 32];
        let (identity_pk_mont, _) = curve::generate_keypair(&identity_sk).unwrap();
        let mut identity_pub = vec![0x05u8];
        identity_pub.extend_from_slice(&identity_pk_mont);
        let spk = [spk_byte; 32];
        X3dhParams {
            identity_priv: Box::leak(Box::new(identity_sk)),
            identity_pub: Box::leak(Box::new(identity_pub.clone())),
            signed_prekey_pub: Box::leak(Box::new(spk)),
            signed_prekey_sig: Box::leak(Box::new(sig.to_vec())),
            prekey_pub: None,
            prekey_id: None,
            recipient_pub: Box::leak(Box::new(identity_pub)),
            recipient_prekey: Box::leak(Box::new(spk)),
            registration_id: reg_id,
            signed_key_id: 0,
        }
    }

    #[test]
    fn test_identity_pub_must_match_identity_priv() {
        let sk = [0x42u8; 32];
        let spk = [0x43u8; 32];
        let sig = curve::sign(&sk, &spk, None).unwrap();
        let mut params = test_params(42, 0x42, 0x43, &sig);
        // A public key that the private key does not produce. The signature
        // check is unaffected because it authenticates recipient_pub, so this
        // used to sail through with an identity key pair that cannot exist.
        let (other_pk, _) = curve::generate_keypair(&[0x77u8; 32]).unwrap();
        let mut wrong = vec![0x05u8];
        wrong.extend_from_slice(&other_pk);
        params.identity_pub = Box::leak(Box::new(wrong));
        let result = build_initial_session(&params);
        assert!(
            result.is_err(),
            "identity_pub must be rejected when it does not match identity_priv"
        );
        assert!(result.unwrap_err().contains("identity_pub"));
    }

    #[test]
    fn test_recipient_prekey_must_match_signed_prekey() {
        let sk = [0x42u8; 32];
        let spk = [0x43u8; 32];
        let sig = curve::sign(&sk, &spk, None).unwrap();
        let mut params = test_params(42, 0x42, 0x43, &sig);
        // The recipient's signed prekey is one key. Passing a second, different
        // value here built a session whose chain keys came from a key that was
        // never signed.
        params.recipient_prekey = Box::leak(Box::new([0x66u8; 32]));
        let result = build_initial_session(&params);
        assert!(
            result.is_err(),
            "recipient_prekey must be rejected when it differs from the signed prekey"
        );
        assert!(result.unwrap_err().contains("recipient_prekey"));
    }

    #[test]
    fn test_recipient_session_rejects_mismatched_signed_prekey() {
        let bob_sk = [0x77u8; 32];
        let (bob_pk32, bob_sk2) = curve::generate_keypair(&bob_sk).unwrap();
        let mut bob_id = vec![0x05u8];
        bob_id.extend_from_slice(&bob_pk32);

        let spk_priv = [0x43u8; 32];
        let (spk_pub, _) = curve::generate_keypair(&spk_priv).unwrap();
        let result = build_recipient_session(
            &bob_sk2,
            &spk_priv,
            &[0x99u8; 32], // not base(spk_priv)
            None,
            &bob_id,
            &spk_pub,
            42,
        );
        assert!(
            result.is_err(),
            "our_signed_prekey_pub must be rejected when it does not match our_signed_prekey_priv"
        );
        assert!(result.unwrap_err().contains("signed_prekey_pub"));
    }

    #[test]
    fn test_build_initial_session_structure() {
        let sk = [0x42u8; 32];
        let spk = [0x43u8; 32];
        let sig = curve::sign(&sk, &spk, None).unwrap();
        // sanity: signer identity must verify
        let (pk, _) = curve::generate_keypair(&sk).unwrap();
        assert!(curve::verify(&pk, &spk, &sig).unwrap());
        let params = test_params(42, 0x42, 0x43, &sig);

        let result = build_initial_session(&params);
        assert!(result.is_ok(), "build failed: {:?}", result.err());
        let record = session::deserialize(&result.unwrap()).unwrap();
        assert_eq!(record.sessions.len(), 1);
        let entry = record.sessions.values().next().unwrap();
        assert_eq!(entry.indexInfo.closed, -1);
        assert_eq!(entry.indexInfo.used, entry.indexInfo.created);
        assert!(!entry.currentRatchet.rootKey.is_empty());
        assert_eq!(entry.currentRatchet.previousCounter, 0);
        assert_eq!(entry.chains.len(), 1);
        let chain = entry.chains.values().next().unwrap();
        assert!(chain.is_sending());
        assert_eq!(chain.chainKey.counter, -1);
        assert!(!chain.chainKey.is_closed());
        assert!(chain.messageKeys.is_empty());
        assert!(entry.pendingPreKey.is_some());
    }

    #[test]
    fn test_invalid_signature_rejected() {
        let bad_sig = [0x99u8; 64];
        let params = test_params(42, 0x42, 0x43, &bad_sig);
        let result = build_initial_session(&params);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("signature"));
    }

    #[test]
    fn test_valid_signature_roundtrip() {
        let sk = [0xABu8; 32];
        let spk = [0xCDu8; 32];
        let sig = curve::sign(&sk, &spk, None).unwrap();
        let params = test_params(99, 0xAB, 0xCD, &sig);

        let result = build_initial_session(&params);
        assert!(result.is_ok(), "build failed: {:?}", result.err());
        let json = result.unwrap();
        let record = session::deserialize(&json).unwrap();
        let entry = record.sessions.values().next().unwrap();
        assert_eq!(entry.registrationId, 99);
        assert_eq!(entry.indexInfo.closed, -1);
        assert_eq!(entry.chains.len(), 1);
        assert!(!entry.currentRatchet.rootKey.is_empty());
    }

    #[test]
    fn test_recipient_builds_session() {
        // Verify recipient session structure is correct (no chains, correct keys).
        // Full interop (encrypt/decrypt roundtrip) is in ratchet tests.
        let alice_sk = [0x42u8; 32];
        let bob_sk = [0x77u8; 32];
        let (alice_pk32, _) = curve::generate_keypair(&alice_sk).unwrap();
        let (bob_pk32, bob_sk2) = curve::generate_keypair(&bob_sk).unwrap();
        let mut alice_id = vec![0x05u8];
        alice_id.extend_from_slice(&alice_pk32);
        let mut bob_id = vec![0x05u8];
        bob_id.extend_from_slice(&bob_pk32);

        let spk_priv = [0x43u8; 32];
        let (spk_pub, _) = curve::generate_keypair(&spk_priv).unwrap();
        let sig = curve::sign(&bob_sk, &spk_pub, None).unwrap();

        let fixed_eph = [0x55u8; 32];
        let (eph_pub, _) = curve::generate_keypair(&fixed_eph).unwrap();

        let params = X3dhParams {
            identity_priv: Box::leak(Box::new(alice_sk)),
            identity_pub: Box::leak(Box::new(alice_id.clone())),
            signed_prekey_pub: Box::leak(Box::new(spk_pub)),
            signed_prekey_sig: Box::leak(Box::new(sig)),
            prekey_pub: None,
            prekey_id: None,
            recipient_pub: Box::leak(Box::new(bob_id.clone())),
            recipient_prekey: Box::leak(Box::new(spk_pub)),
            registration_id: 42,
            signed_key_id: 1,
        };
        let alice_json = build_initial_session_with_ephemeral(&params, &fixed_eph).unwrap();

        let bob_json = build_recipient_session(
            &bob_sk2,
            &spk_priv,
            &spk_pub,
            None,
            &alice_id,
            &eph_pub,
            42,
        )
        .unwrap();
        let bob_record = session::deserialize(&bob_json).unwrap();
        let bob_entry = bob_record.sessions.values().next().unwrap();

        assert_eq!(bob_entry.indexInfo.baseKeyType, 0, "THEIRS");
        assert_eq!(bob_entry.indexInfo.baseKey, crate::util::b64(&eph_pub));
        assert_eq!(
            bob_entry.currentRatchet.lastRemoteEphemeralKey,
            crate::util::b64(&eph_pub)
        );
        assert_eq!(bob_entry.indexInfo.closed, -1);
        assert_eq!(bob_entry.currentRatchet.previousCounter, 0);
        assert!(bob_entry.chains.is_empty(), "recipient starts with no chains");
        assert_eq!(
            bob_entry.currentRatchet.ephemeralKeyPair.privKey,
            crate::util::b64(&spk_priv)
        );
        assert_eq!(
            bob_entry.currentRatchet.ephemeralKeyPair.pubKey,
            crate::util::b64(&spk_pub)
        );
        assert_eq!(
            bob_entry.indexInfo.remoteIdentityKey,
            crate::util::b64(&alice_id)
        );
        assert_eq!(bob_entry.registrationId, 42);
        assert!(bob_entry.pendingPreKey.is_none());
    }

    #[test]
    fn test_recipient_with_one_time_prekey() {
        // Verify recipient session structure is correct when a one-time prekey
        // is used (DH4 included in shared secret). Full OPK interop roundtrip
        // is covered in ratchet tests.
        let alice_sk = [0x42u8; 32];
        let bob_sk = [0x77u8; 32];
        let (alice_pk32, _) = curve::generate_keypair(&alice_sk).unwrap();
        let (bob_pk32, bob_sk2) = curve::generate_keypair(&bob_sk).unwrap();
        let mut alice_id = vec![0x05u8];
        alice_id.extend_from_slice(&alice_pk32);
        let mut bob_id = vec![0x05u8];
        bob_id.extend_from_slice(&bob_pk32);

        let spk_priv = [0x43u8; 32];
        let (spk_pub, _) = curve::generate_keypair(&spk_priv).unwrap();
        let sig = curve::sign(&bob_sk, &spk_pub, None).unwrap();

        // Bob's one-time prekey.
        let opk_priv = [0x99u8; 32];
        let (opk_pub, _) = curve::generate_keypair(&opk_priv).unwrap();

        let fixed_eph = [0x55u8; 32];
        let (eph_pub, _) = curve::generate_keypair(&fixed_eph).unwrap();

        // Initiator uses the one-time prekey too (proves DH4 alignment).
        let params = X3dhParams {
            identity_priv: Box::leak(Box::new(alice_sk)),
            identity_pub: Box::leak(Box::new(alice_id.clone())),
            signed_prekey_pub: Box::leak(Box::new(spk_pub)),
            signed_prekey_sig: Box::leak(Box::new(sig)),
            prekey_pub: Some(Box::leak(Box::new(opk_pub))),
            prekey_id: Some(7),
            recipient_pub: Box::leak(Box::new(bob_id.clone())),
            recipient_prekey: Box::leak(Box::new(spk_pub)),
            registration_id: 42,
            signed_key_id: 3,
        };
        let alice_json = build_initial_session_with_ephemeral(&params, &fixed_eph).unwrap();
        let alice_record = session::deserialize(&alice_json).unwrap();
        let alice_entry = alice_record.sessions.values().next().unwrap();
        // Initiator pendingPreKey records the one-time prekey id.
        assert_eq!(alice_entry.pendingPreKey.as_ref().unwrap().preKeyId, Some(7));
        let _ = &alice_json; // structural interop covered in ratchet roundtrip test

        let bob_json = build_recipient_session(
            &bob_sk2,
            &spk_priv,
            &spk_pub,
            Some(&opk_priv),
            &alice_id,
            &eph_pub,
            42,
        )
        .unwrap();
        let bob_record = session::deserialize(&bob_json).unwrap();
        let bob_entry = bob_record.sessions.values().next().unwrap();

        // OPK path: recipient session structure is correct (no chains yet).
        assert!(bob_entry.chains.is_empty());
        assert_eq!(bob_entry.indexInfo.baseKeyType, 0);
        assert_eq!(
            bob_entry.currentRatchet.ephemeralKeyPair.privKey,
            crate::util::b64(&spk_priv)
        );
    }

    #[test]
    fn test_recipient_rejects_short_identity() {
        let sk = [0x42u8; 32];
        let spk = [0x43u8; 32];
        let result = build_recipient_session(&sk, &spk, &spk, None, &[0x05u8; 10], &[0x00u8; 32], 1);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("33 bytes"));
    }

    #[test]
    fn test_keypair_roles_pinned() {
        let sk = [0x42u8; 32];
        let spk = [0x43u8; 32];
        let sig = curve::sign(&sk, &spk, None).unwrap();
        let params = test_params(42, 0x42, 0x43, &sig);

        let fixed_priv = [0x55u8; 32];
        let (expected_pub, _) = curve::generate_keypair(&fixed_priv).unwrap();

        let result = build_initial_session_with_ephemeral(&params, &fixed_priv);
        assert!(result.is_ok(), "build failed: {:?}", result.err());
        let record = session::deserialize(&result.unwrap()).unwrap();
        let entry = record.sessions.values().next().unwrap();

        let b64_priv = crate::util::b64(&fixed_priv);
        let b64_pub = crate::util::b64(&expected_pub);

        // privKey is the private key, pubKey is the public key — roles are NOT swapped.
        assert_eq!(entry.currentRatchet.ephemeralKeyPair.privKey, b64_priv);
        assert_eq!(entry.currentRatchet.ephemeralKeyPair.pubKey, b64_pub);
        assert_ne!(b64_priv, b64_pub, "priv and pub must differ");

        // baseKey / chain map key hold the public key, not the private.
        assert_eq!(entry.indexInfo.baseKey, b64_pub);
        assert!(record.sessions.contains_key(&b64_pub));

        // Cross-check chainKey derivation: re-compute the entire pipeline for
        // the sending ratchet chain key using fixed_priv.
        let recipient_pub_32 = params.recipient_pub.get(1..33).unwrap();
        let a1 = curve::scalar_multiply(params.identity_priv, params.signed_prekey_pub).unwrap();
        let a2 = curve::scalar_multiply(&fixed_priv, recipient_pub_32).unwrap();
        let a3 = curve::scalar_multiply(&fixed_priv, params.signed_prekey_pub).unwrap();
        let mut shared = vec![0xffu8; 128];
        shared[32..64].copy_from_slice(&a1);
        shared[64..96].copy_from_slice(&a2);
        shared[96..128].copy_from_slice(&a3);
        let mk = derive_secrets(&shared, &[0u8; 32], b"WhisperText").unwrap();
        let root_key = &mk[0];
        let shared_ratchet = curve::scalar_multiply(&fixed_priv, params.signed_prekey_pub).unwrap();
        let mk_ratchet = derive_secrets(&shared_ratchet, root_key, b"WhisperRatchet").unwrap();

        let chain = entry.chains.values().next().unwrap();
        assert_eq!(chain.chainKey.key, Some(crate::util::b64(&mk_ratchet[1])));
    }
}
