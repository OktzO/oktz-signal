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
}

/// deriveSecrets pattern (RFC 5869, 3 chunks) — same as libsignal crypto.js.
fn derive_secrets(input: &[u8], salt: &[u8], info: &[u8]) -> Result<[Vec<u8>; 3], String> {
    let prk = {
        let mut mac = HmacSha256::new_from_slice(salt).map_err(|e| e.to_string())?;
        mac.update(input);
        mac.finalize().into_bytes()
    };
    let mut out = [Vec::new(), Vec::new(), Vec::new()];
    let mut prev = Vec::new();
    for (i, slot) in out.iter_mut().enumerate() {
        let mut mac = HmacSha256::new_from_slice(prk.as_ref()).map_err(|e| e.to_string())?;
        mac.update(&prev);
        mac.update(info);
        mac.update(&[(i + 1) as u8]);
        let chunk = mac.finalize().into_bytes().to_vec();
        *slot = chunk.clone();
        prev = chunk;
    }
    Ok(out)
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
    let verified = curve::verify(recipient_pub_32, params.signed_prekey_pub, params.signed_prekey_sig)?;
    if !verified {
        return Err("signed prekey signature verification failed".to_string());
    }

    // 2. Ephemeral base key — public = base(priv). generate_keypair returns (pub, seed).
    let (ephemeral_pub, _) = curve::generate_keypair(ephemeral_priv)?;

    // 3. DH agreements.
    let a1 = curve::scalar_multiply(params.identity_priv, params.signed_prekey_pub)?;
    let a2 = curve::scalar_multiply(ephemeral_priv, recipient_pub_32)?;
    let a3 = curve::scalar_multiply(ephemeral_priv, params.signed_prekey_pub)?;

    // 4. Shared secret: 0xff*32 || a1 || a2 || a3 [|| a4].
    let has_opk = params.prekey_pub.is_some();
    let len = if has_opk { 160 } else { 128 };
    let mut shared = vec![0u8; len];
    for i in 0..32 {
        shared[i] = 0xff;
    }
    shared[32..64].copy_from_slice(&a1);
    shared[64..96].copy_from_slice(&a2);
    shared[96..128].copy_from_slice(&a3);
    if let Some(opk) = params.prekey_pub {
        let a4 = curve::scalar_multiply(ephemeral_priv, opk)?;
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
            lastRemoteEphemeralKey: crate::util::b64(params.signed_prekey_pub),
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
        }),
    };

    // 7. calculateSendingRatchet: shared = DH(ephemeral_priv, theirSignedPubKey),
    //    deriveSecrets(shared, rootKey, "WhisperRatchet"), add sending chain.
    let shared_ratchet = curve::scalar_multiply(ephemeral_priv, params.signed_prekey_pub)?;
    let mk_ratchet = derive_secrets(&shared_ratchet, &root_key, b"WhisperRatchet")?;
    root_key = mk_ratchet[0].clone();
    entry.currentRatchet.rootKey = crate::util::b64(&root_key);
    entry.chains.insert(
        crate::util::b64(&ephemeral_pub),
        Chain {
            chainKey: ChainKey {
                counter: -1,
                key: crate::util::b64(&mk_ratchet[1]),
            },
            chainType: 1, // SENDING
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

#[cfg(test)]
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
        }
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
        assert_eq!(chain.chainType, 1);
        assert_eq!(chain.chainKey.counter, -1);
        assert!(!chain.chainKey.key.is_empty());
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
        assert_eq!(chain.chainKey.key, crate::util::b64(&mk_ratchet[1]));
    }
}
