// Double Ratchet encrypt/decrypt (Signal Protocol, v6 wire-compatible).
// Symmetric ratchet: chain key → message key per message (HMAC steps).
// Asymmetric ratchet: DH ratchet step on new remote ephemeral key.

use crate::curve;
use crate::proto;
use crate::session::{self, Chain, ChainKey, KeyPair, SessionRecord};
use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use std::collections::BTreeMap;

type HmacSha256 = Hmac<Sha256>;

// AES-128-CBC (16-byte key per spec; AES-256 label in brief was a bug) encrypt (manual, since block-modes 0.9.1 is deprecated-empty).
fn aes_cbc_encrypt(key: &[u8], iv: &[u8; 16], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = Aes128::new_from_slice(key).map_err(|e| format!("AES key: {}", e))?;
    let pad_len = 16 - (plaintext.len() % 16);
    let mut padded = plaintext.to_vec();
    padded.resize(plaintext.len() + pad_len, pad_len as u8);

    let mut ct = Vec::with_capacity(padded.len());
    let mut prev = *iv;
    for chunk in padded.chunks(16) {
        let mut block = GenericArray::clone_from_slice(chunk);
        for (b, p) in block.iter_mut().zip(prev.iter()) {
            *b ^= p;
        }
        cipher.encrypt_block(&mut block);
        ct.extend_from_slice(&block);
        prev = block.into();
    }
    Ok(ct)
}

// AES-128-CBC (16-byte key per spec; AES-256 label in brief was a bug) decrypt (manual).
fn aes_cbc_decrypt(key: &[u8], iv: &[u8; 16], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    if ciphertext.len() % 16 != 0 || ciphertext.is_empty() {
        return Err("invalid ciphertext length".to_string());
    }
    let cipher = Aes128::new_from_slice(key).map_err(|e| format!("AES key: {}", e))?;
    let mut out = Vec::with_capacity(ciphertext.len());
    let mut prev = *iv;
    for chunk in ciphertext.chunks(16) {
        let block = GenericArray::clone_from_slice(chunk);
        let mut dec = block;
        cipher.decrypt_block(&mut dec);
        for (d, p) in dec.iter_mut().zip(prev.iter()) {
            *d ^= p;
        }
        out.extend_from_slice(&dec);
        prev = block.into();
    }
    // PKCS7 unpad
    let pad = *out.last().ok_or("empty decrypt")? as usize;
    if pad == 0 || pad > 16 || out.len() < pad {
        return Err("invalid padding".to_string());
    }
    out.truncate(out.len() - pad);
    Ok(out)
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("hmac key");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

// 3-chunk HKDF (RFC 5869, Extract-then-Expand, 3 × 32-byte output chunks).
// Same pattern as x3dh::derive_secrets (private there, replicated here).
fn derive_secrets(input: &[u8], salt: &[u8], info: &[u8]) -> Result<[Vec<u8>; 3], String> {
    let prk = {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(salt).map_err(|e| e.to_string())?;
        mac.update(input);
        mac.finalize().into_bytes()
    };
    let mut out = [Vec::new(), Vec::new(), Vec::new()];
    let mut prev = Vec::new();
    for (i, slot) in out.iter_mut().enumerate() {
        let mut mac =
            <HmacSha256 as Mac>::new_from_slice(prk.as_ref()).map_err(|e| e.to_string())?;
        mac.update(&prev);
        mac.update(info);
        mac.update(&[(i + 1) as u8]);
        let chunk = mac.finalize().into_bytes().to_vec();
        *slot = chunk.clone();
        prev = chunk;
    }
    Ok(out)
}

// Derive AES key (first 16 bytes) + MAC key (full 32 bytes) from message key.
fn derive_message_keys(message_key: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let aes_key = hmac_sha256(message_key, &[0x01])[..16].to_vec();
    let mac_key = hmac_sha256(message_key, &[0x02]);
    (aes_key, mac_key)
}

pub struct EncryptResult {
    pub session_json: String,
    pub message_type: u8,
    pub ciphertext: Vec<u8>,
}

pub struct DecryptResult {
    pub session_json: String,
    pub plaintext: Vec<u8>,
}

/// Double Ratchet encrypt.
/// 1. Advance sending chain, derive message key + next chain key
/// 2. AES-128-CBC (16-byte key per spec; AES-256 label in brief was a bug) encrypt + HMAC-SHA256
/// 3. Serialize WhisperMessage, update session
pub fn encrypt(session_json: &str, plaintext: &[u8]) -> Result<EncryptResult, String> {
    let mut record: SessionRecord = session::deserialize(session_json)?;
    let entry = record
        .sessions
        .values_mut()
        .next()
        .ok_or("no session entry")?;

    let ephemeral_key = crate::util::unb64(&entry.currentRatchet.ephemeralKeyPair.pubKey)?;
    let previous_counter = entry.currentRatchet.previousCounter;

    let chain = entry
        .chains
        .values_mut()
        .find(|c| c.chainType == 1)
        .ok_or("no sending chain")?;

    chain.chainKey.counter += 1;
    let ck_bytes = crate::util::unb64(&chain.chainKey.key)?;

    let message_key = hmac_sha256(&ck_bytes, &[0x01]);
    let next_chain_key = hmac_sha256(&ck_bytes, &[0x02]);

    let (aes_key, mac_key) = derive_message_keys(&message_key);

    let mut iv = [0u8; 16];
    OsRng.fill_bytes(&mut iv);

    let ct = aes_cbc_encrypt(&aes_key, &iv, plaintext)?;

    let mut mac_input = Vec::new();
    mac_input.extend_from_slice(&ct);
    mac_input.extend_from_slice(&iv);
    let mac_tag = hmac_sha256(&mac_key, &mac_input);

    let mut payload = Vec::new();
    payload.extend_from_slice(&ct);
    payload.extend_from_slice(&iv);
    payload.extend_from_slice(&mac_tag);

    let counter = chain.chainKey.counter as u32;
    let whisper_msg = proto::WhisperMessage {
        ephemeral_key,
        counter,
        previous_counter,
        ciphertext: payload,
    };
    let message_bytes = proto::encode_whisper(&whisper_msg)?;

    chain.chainKey.key = crate::util::b64(&next_chain_key);

    let session_json = session::serialize(&record)?;
    Ok(EncryptResult {
        session_json,
        message_type: 1,
        ciphertext: message_bytes,
    })
}

/// Decrypt a WhisperMessage.
/// 1. Parse WhisperMessage
/// 2. DH ratchet if remote ephemeral key changed (new receiving chain)
/// 3. Skip ahead on receiving chain, derive message key
/// 4. Verify MAC, AES-128-CBC (16-byte key per spec; AES-256 label in brief was a bug) decrypt
/// 5. Update session
pub fn decrypt_whisper(session_json: &str, ciphertext: &[u8]) -> Result<DecryptResult, String> {
    let mut record: SessionRecord = session::deserialize(session_json)?;
    let msg = proto::decode_whisper(ciphertext)?;
    let entry = record
        .sessions
        .values_mut()
        .next()
        .ok_or("no session entry")?;

    let last_remote = crate::util::unb64(&entry.currentRatchet.lastRemoteEphemeralKey)?;
    let chain_id = crate::util::b64(&msg.ephemeral_key);

    if msg.ephemeral_key != last_remote {
        // DH ratchet step: new remote ephemeral → new receiving chain
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let (new_pub, new_priv) = curve::generate_keypair(&seed)?;

        let shared = curve::scalar_multiply(&new_priv, &msg.ephemeral_key)?;
        let root_key = crate::util::unb64(&entry.currentRatchet.rootKey)?;
        let mk = derive_secrets(&shared, &root_key, b"WhisperRatchet")?;

        entry.currentRatchet.rootKey = crate::util::b64(&mk[0]);
        entry.currentRatchet.ephemeralKeyPair = KeyPair {
            pubKey: crate::util::b64(&new_pub),
            privKey: crate::util::b64(&new_priv),
        };
        entry.currentRatchet.lastRemoteEphemeralKey = chain_id.clone();
        entry.currentRatchet.previousCounter = msg.previous_counter;

        entry.chains.insert(
            chain_id.clone(),
            Chain {
                chainKey: ChainKey {
                    counter: -1,
                    key: crate::util::b64(&mk[1]),
                },
                chainType: 0,
                messageKeys: BTreeMap::new(),
            },
        );
    }

    let mut chain = entry
        .chains
        .get(&chain_id)
        .cloned()
        .filter(|c| c.chainType == 0)
        .ok_or("no receiving chain")?;

    // Skip ahead: derive + store message keys for skipped counters
    if (msg.counter as i64) > chain.chainKey.counter {
        for c in (chain.chainKey.counter + 1)..=(msg.counter as i64) {
            let ck = crate::util::unb64(&chain.chainKey.key)?;
            let mk = hmac_sha256(&ck, &[0x01]);
            chain.messageKeys.insert(c, crate::util::b64(&mk));
            let next = hmac_sha256(&ck, &[0x02]);
            chain.chainKey.key = crate::util::b64(&next);
        }
        chain.chainKey.counter = msg.counter as i64;
    }

    // Get message key for this counter
    let message_key: Vec<u8> = if let Some(b64mk) = chain.messageKeys.remove(&(msg.counter as i64))
    {
        crate::util::unb64(&b64mk)?
    } else if (msg.counter as i64) == chain.chainKey.counter {
        let ck = crate::util::unb64(&chain.chainKey.key)?;
        hmac_sha256(&ck, &[0x01])
    } else {
        return Err("message key not found".to_string());
    };

    let (aes_key, mac_key) = derive_message_keys(&message_key);

    // Parse payload: ciphertext || iv (16) || mac (32)
    let payload = &msg.ciphertext;
    if payload.len() < 48 {
        return Err("ciphertext too short".to_string());
    }
    let ct_len = payload.len() - 48;
    let ct = &payload[..ct_len];
    let iv: &[u8; 16] = payload[ct_len..ct_len + 16]
        .try_into()
        .map_err(|_| "iv length")?;
    let mac_tag = &payload[ct_len + 16..];

    // Verify MAC
    let mut mac_input = Vec::new();
    mac_input.extend_from_slice(ct);
    mac_input.extend_from_slice(iv);
    let expected = hmac_sha256(&mac_key, &mac_input);
    if expected != mac_tag {
        return Err("MAC verification failed".to_string());
    }

    let plaintext = aes_cbc_decrypt(&aes_key, iv, ct)?;

    entry.chains.insert(chain_id, chain);

    let session_json = session::serialize(&record)?;
    Ok(DecryptResult {
        session_json,
        plaintext,
    })
}

/// Decrypt a PreKeyWhisperMessage.
/// If session has open session → extract embedded WhisperMessage, decrypt.
/// If no open session → Err (X3DH recipient init deferred to JS wrapper).
pub fn decrypt_pkmsg(session_json: &str, ciphertext: &[u8]) -> Result<DecryptResult, String> {
    let pkmsg = proto::decode_pkmsg(ciphertext)?;
    let record = session::deserialize(session_json)?;
    if !session::have_open_session(&record) {
        return Err(
            "no open session — X3DH recipient init deferred to JS wrapper".to_string(),
        );
    }
    decrypt_whisper(session_json, &pkmsg.message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x3dh;

    fn build_alice_session() -> String {
        let sk = [0x42u8; 32];
        let (identity_pk_mont, _) = curve::generate_keypair(&sk).unwrap();
        let mut identity_pub = vec![0x05u8];
        identity_pub.extend_from_slice(&identity_pk_mont);
        let spk = [0x43u8; 32];
        let sig = curve::sign(&sk, &spk, None).unwrap();
        let params = x3dh::X3dhParams {
            identity_priv: &sk,
            identity_pub: &identity_pub,
            signed_prekey_pub: &spk,
            signed_prekey_sig: &sig,
            prekey_pub: None,
            prekey_id: None,
            recipient_pub: &identity_pub,
            recipient_prekey: &spk,
            registration_id: 42,
        };
        // Build with fixed ephemeral for deterministic output
        let fixed_eph = [0x55u8; 32];
        // Use the with_ephemeral variant to keep tests deterministic
        x3dh::build_initial_session_with_ephemeral(&params, &fixed_eph).unwrap()
    }

    // Build a receiver (Bob) session that mirrors Alice's sending chain as
    // Bob's receiving chain.  This is mathematically equivalent to what a real
    // X3DH recipient would derive (DH(SPK_B_priv, A_eph_pub) = DH(A_eph_priv,
    // SPK_B_pub) → same shared secret → same chain key).
    fn build_bob_session(alice_json: &str) -> String {
        let alice: SessionRecord = session::deserialize(alice_json).unwrap();
        let a_entry = alice.sessions.values().next().unwrap();
        let a_eph_pub = a_entry.currentRatchet.ephemeralKeyPair.pubKey.clone();
        let a_send_chain = a_entry
            .chains
            .values()
            .find(|c| c.chainType == 1)
            .unwrap();
        let root_key = a_entry.currentRatchet.rootKey.clone();

        let bob_seed = [0x77u8; 32];
        let (bob_pub, bob_priv) = curve::generate_keypair(&bob_seed).unwrap();

        let mut chains = BTreeMap::new();
        chains.insert(
            a_eph_pub.clone(),
            Chain {
                chainKey: ChainKey {
                    counter: -1,
                    key: a_send_chain.chainKey.key.clone(),
                },
                chainType: 0,
                messageKeys: BTreeMap::new(),
            },
        );

        let entry = session::SessionEntry {
            registrationId: 42,
            currentRatchet: session::Ratchet {
                ephemeralKeyPair: KeyPair {
                    pubKey: crate::util::b64(&bob_pub),
                    privKey: crate::util::b64(&bob_priv),
                },
                lastRemoteEphemeralKey: a_eph_pub,
                previousCounter: 0,
                rootKey: root_key,
            },
            indexInfo: session::IndexInfo {
                baseKey: "bob-base".to_string(),
                baseKeyType: 0,
                closed: -1,
                used: 0,
                created: 0,
                remoteIdentityKey: a_entry.indexInfo.remoteIdentityKey.clone(),
            },
            chains,
            pendingPreKey: None,
        };
        let mut record = SessionRecord {
            sessions: BTreeMap::new(),
            version: "v1".to_string(),
        };
        record.sessions.insert("bob-session".to_string(), entry);
        session::serialize(&record).unwrap()
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let alice = build_alice_session();
        let bob = build_bob_session(&alice);
        let plaintext = b"hello signal";

        let enc = encrypt(&alice, plaintext).unwrap();
        assert_eq!(enc.message_type, 1);
        assert!(!enc.ciphertext.is_empty());

        let dec = decrypt_whisper(&bob, &enc.ciphertext).unwrap();
        assert_eq!(dec.plaintext, plaintext);
    }

    #[test]
    fn test_multi_message_ratchet() {
        let alice0 = build_alice_session();
        let bob0 = build_bob_session(&alice0);
        let mut alice = alice0;
        let mut bob = bob0;
        let msgs: Vec<Vec<u8>> = (0..5)
            .map(|i| format!("msg {}", i).into_bytes())
            .collect();

        for (i, m) in msgs.iter().enumerate() {
            let enc = encrypt(&alice, m).unwrap();
            alice = enc.session_json;
            let dec = decrypt_whisper(&bob, &enc.ciphertext).unwrap();
            bob = dec.session_json;
            assert_eq!(&dec.plaintext, m);

            // Verify counter increments
            let rec: SessionRecord = session::deserialize(&alice).unwrap();
            let entry = rec.sessions.values().next().unwrap();
            let chain = entry.chains.values().find(|c| c.chainType == 1).unwrap();
            assert_eq!(chain.chainKey.counter, i as i64);
        }
    }

    #[test]
    fn test_tamper_fails() {
        let alice = build_alice_session();
        let bob = build_bob_session(&alice);
        let plaintext = b"integrity check";

        let enc = encrypt(&alice, plaintext).unwrap();
        let mut tampered = enc.ciphertext.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;

        let result = decrypt_whisper(&bob, &tampered);
        match result {
            Ok(_) => panic!("tampered message must fail"),
            Err(err) => assert!(
                err.contains("MAC") || err.contains("ciphertext"),
                "expected MAC or ciphertext error, got: {}",
                err
            ),
        }
    }

    #[test]
    fn test_chain_key_advances() {
        let alice = build_alice_session();

        let enc1 = encrypt(&alice, b"first").unwrap();
        let rec1: SessionRecord = session::deserialize(&enc1.session_json).unwrap();
        let e1 = rec1.sessions.values().next().unwrap();
        let c1 = e1.chains.values().find(|c| c.chainType == 1).unwrap();
        assert_eq!(c1.chainKey.counter, 0);

        let enc2 = encrypt(&enc1.session_json, b"second").unwrap();
        let rec2: SessionRecord = session::deserialize(&enc2.session_json).unwrap();
        let e2 = rec2.sessions.values().next().unwrap();
        let c2 = e2.chains.values().find(|c| c.chainType == 1).unwrap();
        assert_eq!(c2.chainKey.counter, 1);
    }

    #[test]
    fn test_decrypt_pkmsg_with_session() {
        let alice = build_alice_session();
        let bob = build_bob_session(&alice);
        let plaintext = b"pkmsg payload";

        let enc = encrypt(&alice, plaintext).unwrap();
        let pkmsg = proto::PreKeyWhisperMessage {
            pre_key_id: Some(123),
            base_key: vec![0x01; 32],
            identity_key: vec![0x02; 33],
            message: enc.ciphertext,
            registration_id: 42,
            signed_pre_key_id: Some(1),
        };
        let pk_bytes = proto::encode_pkmsg(&pkmsg).unwrap();

        let dec = decrypt_pkmsg(&bob, &pk_bytes).unwrap();
        assert_eq!(dec.plaintext, plaintext);
    }

    #[test]
    fn test_decrypt_pkmsg_no_session_fails() {
        let alice = build_alice_session();
        let plaintext = b"pkmsg payload";
        let enc = encrypt(&alice, plaintext).unwrap();
        let pkmsg = proto::PreKeyWhisperMessage {
            pre_key_id: Some(123),
            base_key: vec![0x01; 32],
            identity_key: vec![0x02; 33],
            message: enc.ciphertext,
            registration_id: 42,
            signed_pre_key_id: Some(1),
        };
        let pk_bytes = proto::encode_pkmsg(&pkmsg).unwrap();

        let result = decrypt_pkmsg("{}", &pk_bytes);
        assert!(result.is_err());
    }
}