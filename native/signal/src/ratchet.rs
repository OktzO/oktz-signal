#![deny(unsafe_code)]
// Double Ratchet encrypt/decrypt (Signal Protocol, v6 wire-compatible).
// Wire format verified against libsignal v6 oracle:
//   - Message key: HMAC-SHA256(chainKey.key, [0x01]); chain step HMAC [0x02].
//   - Encryption keys: deriveSecrets(messageKey, zeros(32), "WhisperMessageKeys")
//     → [0] AES-256 key (32B), [1] MAC key (32B), [2][0..16] IV.
//   - WhisperMessage = [0x33] || protobuf || MAC[0..8] (8-byte MAC, version byte).
//   - MAC input (encrypt): ourIdentity(33) || remoteIdentity(33) || [0x33] || proto.
//   - MAC input (decrypt): remoteIdentity(33) || ourIdentity(33) || [0x33] || proto.
//   - DH ratchet: deriveSecrets(shared, rootKey, "WhisperRatchet", 2).

use crate::curve;
use crate::proto;
use crate::session::{self, Chain, ChainKey, KeyPair, SessionEntry, SessionRecord};
use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes256;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use std::collections::BTreeMap;

type HmacSha256 = Hmac<Sha256>;

// AES-256-CBC (32-byte key) encrypt, manual (block-modes 0.9.1 is deprecated-empty).
fn aes_cbc_encrypt(key: &[u8], iv: &[u8; 16], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = Aes256::new_from_slice(key).map_err(|e| format!("AES key: {}", e))?;
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

// AES-256-CBC decrypt (manual).
fn aes_cbc_decrypt(key: &[u8], iv: &[u8; 16], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    if ciphertext.len() % 16 != 0 || ciphertext.is_empty() {
        return Err("invalid ciphertext length".to_string());
    }
    let cipher = Aes256::new_from_slice(key).map_err(|e| format!("AES key: {}", e))?;
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

// N-chunk HKDF (RFC 5869 Extract-then-Expand) — same as libsignal deriveSecrets.
pub(crate) fn derive_secrets_n(input: &[u8], salt: &[u8], info: &[u8], n: usize) -> Result<Vec<Vec<u8>>, String> {
    let prk = {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(salt).map_err(|e| e.to_string())?;
        mac.update(input);
        mac.finalize().into_bytes()
    };
    let mut out = Vec::with_capacity(n);
    let mut prev = Vec::new();
    for i in 0..n {
        let mut mac =
            <HmacSha256 as Mac>::new_from_slice(prk.as_ref()).map_err(|e| e.to_string())?;
        mac.update(&prev);
        mac.update(info);
        mac.update(&[(i + 1) as u8]);
        let chunk = mac.finalize().into_bytes().to_vec();
        out.push(chunk.clone());
        prev = chunk;
    }
    Ok(out)
}

// Derive + store message keys for skipped counters (recursive chain key step).
// Per oracle:
//   if counter <= chainKey.counter → return
//   if counter - chainKey.counter > 2000 → Err("Over 2000 messages into the future!")
//   messageKeys[counter+1] = HMAC(chainKey.key, [0x01])  (index = counter being filled)
//   chainKey.key = HMAC(chainKey.key, [0x02])
//   chainKey.counter += 1
//   recurse
fn fill_message_keys(chain: &mut Chain, counter: i64) -> Result<(), String> {
    if counter <= chain.chainKey.counter {
        return Ok(());
    }
    if counter - chain.chainKey.counter > 2000 {
        return Err("Over 2000 messages into the future!".to_string());
    }
    let ck = crate::util::unb64(&chain.chainKey.key)?;
    let message_key = hmac_sha256(&ck, &[0x01]);
    let next_chain_key = hmac_sha256(&ck, &[0x02]);
    chain.messageKeys.insert(
        chain.chainKey.counter + 1,
        crate::util::b64(&message_key),
    );
    chain.chainKey.key = crate::util::b64(&next_chain_key);
    chain.chainKey.counter += 1;
    fill_message_keys(chain, counter)
}

// DH ratchet step: only when no chain exists for the remote ephemeral key.
// Mirrors libsignal maybeStepRatchet (session_cipher.js):
//   1. Close previous receiving chain (if any): fill to previousCounter, drop key.
//   2. receiving chain from current_ratchet_priv x remoteKey (rootKey update).
//   3. Swap ephemeral keypair to a fresh key; previousCounter = old sending chain counter.
//   4. sending chain from new_ratchet_priv x remoteKey (rootKey update).
pub(crate) fn maybe_step_ratchet(
    entry: &mut SessionEntry,
    remote_key_b64: &str,
    previous_counter: u32,
) -> Result<(), String> {
    if entry.chains.contains_key(remote_key_b64) {
        return Ok(());
    }
    let remote_key = crate::util::unb64(remote_key_b64)?;

    // 1. Close previous receiving chain (keyed by lastRemoteEphemeralKey).
    if !entry.currentRatchet.lastRemoteEphemeralKey.is_empty() {
        let prev_b64 = entry.currentRatchet.lastRemoteEphemeralKey.clone();
        if let Some(prev_chain) = entry.chains.get_mut(&prev_b64) {
            if prev_chain.chainType == 0 {
                fill_message_keys(prev_chain, previous_counter as i64)?;
                prev_chain.chainKey.key = String::new(); // closed
            }
        }
    }

    // 2. Receiving chain.
    let ratchet_priv = crate::util::unb64(&entry.currentRatchet.ephemeralKeyPair.privKey)?;
    let shared = curve::scalar_multiply(&ratchet_priv, &remote_key)?;
    let root_key = crate::util::unb64(&entry.currentRatchet.rootKey)?;
    let mk_recv = derive_secrets_n(&shared, &root_key, b"WhisperRatchet", 2)?;
    entry.currentRatchet.rootKey = crate::util::b64(&mk_recv[0]);

    entry.chains.insert(
        remote_key_b64.to_string(),
        Chain {
            chainKey: ChainKey {
                counter: -1,
                key: crate::util::b64(&mk_recv[1]),
            },
            chainType: 0, // RECEIVING
            messageKeys: BTreeMap::new(),
        },
    );

    // 3. Swap ephemeral keypair; delete old sending chain, snapshot its counter.
    let old_eph_pub = entry.currentRatchet.ephemeralKeyPair.pubKey.clone();
    if let Some(old_send) = entry.chains.remove(&old_eph_pub) {
        if old_send.chainType == 1 {
            entry.currentRatchet.previousCounter = old_send.chainKey.counter.max(0) as u32;
        }
    }
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let (new_pub, new_priv) = curve::generate_keypair(&seed)?;
    entry.currentRatchet.ephemeralKeyPair = KeyPair {
        pubKey: crate::util::b64(&new_pub),
        privKey: crate::util::b64(&new_priv),
    };
    entry.currentRatchet.lastRemoteEphemeralKey = remote_key_b64.to_string();

    // 4. Sending chain: DH(new_priv, remoteKey) with the updated root key.
    let shared_send = curve::scalar_multiply(&new_priv, &remote_key)?;
    let root_send = crate::util::unb64(&entry.currentRatchet.rootKey)?;
    let mk_send = derive_secrets_n(&shared_send, &root_send, b"WhisperRatchet", 2)?;
    entry.currentRatchet.rootKey = crate::util::b64(&mk_send[0]);

    entry.chains.insert(
        crate::util::b64(&new_pub),
        Chain {
            chainKey: ChainKey {
                counter: -1,
                key: crate::util::b64(&mk_send[1]),
            },
            chainType: 1, // SENDING
            messageKeys: BTreeMap::new(),
        },
    );
    Ok(())
}

#[derive(serde::Serialize)]
pub struct EncryptResult {
    pub session_json: String,
    pub message_type: u8,
    pub ciphertext: Vec<u8>,
}

#[derive(serde::Serialize)]
pub struct DecryptResult {
    pub session_json: String,
    pub plaintext: Vec<u8>,
}

/// Double Ratchet encrypt (v6 oracle wire format).
/// result = [0x33] || WhisperMessage(ephemeralKey, counter, previousCounter, ct) || MAC[0..8]
/// If pendingPreKey is set, wraps as PreKeyWhisperMessage (message_type=3, ciphertext =
/// [0x33] || encode_pkmsg). pendingPreKey persists until first decrypt (oracle behavior).
pub fn encrypt(
    session_json: &str,
    plaintext: &[u8],
    our_identity_pub: &[u8],    // 33 bytes, sender identity
    remote_identity_pub: &[u8], // 33 bytes, recipient identity
    our_registration_id: u32,   // sender's own registration ID (for PKMsg)
) -> Result<EncryptResult, String> {
    let mut record: SessionRecord = session::deserialize(session_json)?;
    let entry = record
        .sessions
        .values_mut()
        .next()
        .ok_or("no session entry")?;

    // Wire ephemeral keys are 33-byte (0x05 prefix) in WhisperMessage — same as
    // libsignal curve.generateKeyPair (prefixKeyInPublicKey). Internal chain
    // keys stay 32-byte; prefix only at the wire boundary.
    let eph_pub = crate::util::unb64(&entry.currentRatchet.ephemeralKeyPair.pubKey)?;
    let ephemeral_key = if eph_pub.len() == 32 {
        let mut pk = vec![0x05u8];
        pk.extend_from_slice(&eph_pub);
        pk
    } else {
        eph_pub
    };
    let previous_counter = entry.currentRatchet.previousCounter;

    let chain = entry
        .chains
        .values_mut()
        .find(|c| c.chainType == 1)
        .ok_or("no sending chain")?;

    let target_counter = chain.chainKey.counter + 1;
    fill_message_keys(chain, target_counter)?;
    let message_key_b64 = chain
        .messageKeys
        .remove(&target_counter)
        .ok_or("message key not found")?;
    let message_key = crate::util::unb64(&message_key_b64)?;

    // keys = deriveSecrets(messageKey, zeros(32), "WhisperMessageKeys") → 3 chunks.
    let keys = derive_secrets_n(&message_key, &[0u8; 32], b"WhisperMessageKeys", 3)?;
    let iv: [u8; 16] = keys[2][..16].try_into().map_err(|_| "iv length")?;
    let ciphertext = aes_cbc_encrypt(&keys[0], &iv, plaintext)?;

    let whisper_msg = proto::WhisperMessage {
        ephemeral_key,
        counter: target_counter as u32,
        previous_counter,
        ciphertext,
    };
    let msg_buf = proto::encode_whisper(&whisper_msg)?;

    // macInput = ourIdentityKey || remoteIdentityKey || [0x33] || msgBuf
    let mut mac_input = Vec::new();
    mac_input.extend_from_slice(our_identity_pub);
    mac_input.extend_from_slice(remote_identity_pub);
    mac_input.push(0x33);
    mac_input.extend_from_slice(&msg_buf);
    let mac = hmac_sha256(&keys[1], &mac_input);

    // result = [0x33] || msgBuf || mac[0..8]
    let mut result = Vec::with_capacity(1 + msg_buf.len() + 8);
    result.push(0x33);
    result.extend_from_slice(&msg_buf);
    result.extend_from_slice(&mac[..8]);

    let pending = entry.pendingPreKey.clone();
    let session_json = session::serialize(&record)?;

    if let Some(pk) = pending {
        let pk_bk = crate::util::unb64(&pk.baseKey)?;
        let base_key = if pk_bk.len() == 32 {
            let mut b = vec![0x05u8];
            b.extend_from_slice(&pk_bk);
            b
        } else {
            pk_bk
        };
        let pkmsg = proto::PreKeyWhisperMessage {
            pre_key_id: pk.preKeyId,
            base_key,
            identity_key: our_identity_pub.to_vec(),
            message: result.clone(),
            registration_id: our_registration_id,
            signed_pre_key_id: pk.signedKeyId,
        };
        let pk_bytes = proto::encode_pkmsg(&pkmsg)?;
        let mut wrapped = Vec::with_capacity(1 + pk_bytes.len());
        wrapped.push(0x33);
        wrapped.extend_from_slice(&pk_bytes);
        return Ok(EncryptResult {
            session_json,
            message_type: 3,
            ciphertext: wrapped,
        });
    }
    Ok(EncryptResult {
        session_json,
        message_type: 1,
        ciphertext: result,
    })
}

/// Decrypt a WhisperMessage (v6 oracle wire format).
pub fn decrypt_whisper(
    session_json: &str,
    ciphertext: &[u8],
    our_identity_pub: &[u8], // 33 bytes, local receiver identity
) -> Result<DecryptResult, String> {
    if ciphertext.len() < 9 || ciphertext[0] != 0x33 {
        return Err("bad version byte or truncated message".to_string());
    }
    let msg_buf = &ciphertext[1..ciphertext.len() - 8];
    let mac_bytes = &ciphertext[ciphertext.len() - 8..];
    let msg = proto::decode_whisper(msg_buf)?;

    let mut record: SessionRecord = session::deserialize(session_json)?;
    let entry = record
        .sessions
        .values_mut()
        .next()
        .ok_or("no session entry")?;

    // Real WhatsApp ephemeral keys are 33 bytes (0x05 prefix) in WhisperMessage.
    // Strip to 32-byte X25519 — scalar_multiply + chain lookup expect 32 bytes.
    // (JS wrapper strips base_key the same way when building recipient session.)
    let eph_key = if msg.ephemeral_key.len() == 33 && msg.ephemeral_key[0] == 0x05 {
        &msg.ephemeral_key[1..]
    } else {
        msg.ephemeral_key.as_slice()
    };

    let chain_id = crate::util::b64(eph_key);
    maybe_step_ratchet(entry, &chain_id, msg.previous_counter)?;

    let mut chain = entry
        .chains
        .get(&chain_id)
        .cloned()
        .filter(|c| c.chainType == 0)
        .ok_or("no receiving chain")?;

    fill_message_keys(&mut chain, msg.counter as i64)?;
    let message_key_b64 = chain
        .messageKeys
        .remove(&(msg.counter as i64))
        .ok_or("message key not found")?;
    let message_key = crate::util::unb64(&message_key_b64)?;

    let keys = derive_secrets_n(&message_key, &[0u8; 32], b"WhisperMessageKeys", 3)?;

    // macInput = remoteIdentityKey || ourIdentityKey || [0x33] || messageProto
    // (remote first, ours second — reversed vs encrypt).
    let remote_identity = crate::util::unb64(&entry.indexInfo.remoteIdentityKey)?;
    let mut mac_input = Vec::new();
    mac_input.extend_from_slice(&remote_identity);
    mac_input.extend_from_slice(our_identity_pub);
    mac_input.push(0x33);
    mac_input.extend_from_slice(msg_buf);
    let expected = hmac_sha256(&keys[1], &mac_input);
    if &expected[..8] != mac_bytes {
        return Err("MAC verification failed".to_string());
    }

    let iv: [u8; 16] = keys[2][..16].try_into().map_err(|_| "iv length")?;
    let plaintext = aes_cbc_decrypt(&keys[0], &iv, &msg.ciphertext)?;

    entry.chains.insert(chain_id, chain);
    entry.pendingPreKey = None; // delete pendingPreKey

    let session_json = session::serialize(&record)?;
    Ok(DecryptResult {
        session_json,
        plaintext,
    })
}

/// Decrypt a PreKeyWhisperMessage.
/// version = data[0] (must be 0x33); pkmsg = decode_pkmsg(data[1..]).
/// Open session → extract embedded WhisperMessage, decrypt_whisper.
/// No open session → Err (X3DH recipient init deferred to JS wrapper).
pub fn decrypt_pkmsg(
    session_json: &str,
    ciphertext: &[u8],
    our_identity_pub: &[u8],
) -> Result<DecryptResult, String> {
    if ciphertext.is_empty() || ciphertext[0] != 0x33 {
        return Err("bad version byte".to_string());
    }
    let pkmsg = proto::decode_pkmsg(&ciphertext[1..])?;
    let record = session::deserialize(session_json)?;
    if !session::have_open_session(&record) {
        return Err(
            "no open session — X3DH recipient init deferred to JS wrapper".to_string(),
        );
    }
    decrypt_whisper(session_json, &pkmsg.message, our_identity_pub)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x3dh;

    fn identity_keypair(seed: &[u8; 32]) -> Vec<u8> {
        let (mont, _) = curve::generate_keypair(seed).unwrap();
        let mut pk = vec![0x05u8];
        pk.extend_from_slice(&mont);
        pk
    }

    // Build Alice (sender) session via x3dh + Bob (receiver) mirror session,
    // with distinct identities. Returns (alice, bob, alice_id, bob_id).
    fn build_pair() -> (String, String, Vec<u8>, Vec<u8>) {
        let alice_sk = [0x42u8; 32];
        let bob_sk = [0x77u8; 32];
        let alice_identity = identity_keypair(&alice_sk);
        let bob_identity = identity_keypair(&bob_sk);
        let spk = [0x43u8; 32];
        // Signed prekey must be signed by the recipient's (Bob's) identity.
        let sig = curve::sign(&bob_sk, &spk, None).unwrap();
        let params = x3dh::X3dhParams {
            identity_priv: &alice_sk,
            identity_pub: &alice_identity,
            signed_prekey_pub: &spk,
            signed_prekey_sig: &sig,
            prekey_pub: None,
            prekey_id: None,
            recipient_pub: &bob_identity,
            recipient_prekey: &spk,
            registration_id: 42,
            signed_key_id: 1,
        };
        let fixed_eph = [0x55u8; 32];
        let mut alice = x3dh::build_initial_session_with_ephemeral(&params, &fixed_eph).unwrap();
        // Clear pendingPreKey so bare-ratchet tests exercise the WhisperMessage
        // path (type 1). Type-3 PKMsg wrapping is tested separately.
        let mut alice_record = session::deserialize(&alice).unwrap();
        for entry in alice_record.sessions.values_mut() {
            entry.pendingPreKey = None;
        }
        alice = session::serialize(&alice_record).unwrap();
        let bob = build_bob_session(&alice, &alice_identity);
        (alice, bob, alice_identity, bob_identity)
    }

    // Build a receiver (Bob) session that mirrors Alice's sending chain as
    // Bob's receiving chain (mathematically equivalent to a real X3DH
    // recipient: DH(SPK_B_priv, A_eph_pub) = DH(A_eph_priv, SPK_B_pub)).
    fn build_bob_session(alice_json: &str, alice_identity: &[u8]) -> String {
        let alice: SessionRecord = session::deserialize(alice_json).unwrap();
        let a_entry = alice.sessions.values().next().unwrap();
        let a_eph_pub = a_entry.currentRatchet.ephemeralKeyPair.pubKey.clone();
        let a_send_chain = a_entry
            .chains
            .values()
            .find(|c| c.chainType == 1)
            .unwrap();
        let root_key = a_entry.currentRatchet.rootKey.clone();

        let bob_seed = [0x11u8; 32];
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
                remoteIdentityKey: crate::util::b64(alice_identity),
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
        let (alice, bob, alice_id, bob_id) = build_pair();
        let plaintext = b"hello signal";

        let enc = encrypt(&alice, plaintext, &alice_id, &bob_id, 42).unwrap();
        assert_eq!(enc.message_type, 1);
        assert_eq!(enc.ciphertext[0], 0x33, "version byte");
        assert!(enc.ciphertext.len() >= 1 + 8, "version + msgBuf + 8B mac");
        // Parsable as WhisperMessage between version byte and 8-byte MAC.
        proto::decode_whisper(&enc.ciphertext[1..enc.ciphertext.len() - 8]).unwrap();

        let dec = decrypt_whisper(&bob, &enc.ciphertext, &bob_id).unwrap();
        assert_eq!(dec.plaintext, plaintext);
    }

    #[test]
    fn test_multi_message_ratchet() {
        let (alice0, bob0, alice_id, bob_id) = build_pair();
        let mut alice = alice0;
        let mut bob = bob0;
        let msgs: Vec<Vec<u8>> = (0..5)
            .map(|i| format!("msg {}", i).into_bytes())
            .collect();

        for (i, m) in msgs.iter().enumerate() {
            let enc = encrypt(&alice, m, &alice_id, &bob_id, 42).unwrap();
            alice = enc.session_json;
            let dec = decrypt_whisper(&bob, &enc.ciphertext, &bob_id).unwrap();
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
        let (alice, bob, alice_id, bob_id) = build_pair();
        let plaintext = b"integrity check";

        let enc = encrypt(&alice, plaintext, &alice_id, &bob_id, 42).unwrap();
        let mut tampered = enc.ciphertext.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;

        let result = decrypt_whisper(&bob, &tampered, &bob_id);
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
        let (alice, _, alice_id, bob_id) = build_pair();

        let enc1 = encrypt(&alice, b"first", &alice_id, &bob_id, 42).unwrap();
        let rec1: SessionRecord = session::deserialize(&enc1.session_json).unwrap();
        let e1 = rec1.sessions.values().next().unwrap();
        let c1 = e1.chains.values().find(|c| c.chainType == 1).unwrap();
        assert_eq!(c1.chainKey.counter, 0);

        let enc2 = encrypt(&enc1.session_json, b"second", &alice_id, &bob_id, 42).unwrap();
        let rec2: SessionRecord = session::deserialize(&enc2.session_json).unwrap();
        let e2 = rec2.sessions.values().next().unwrap();
        let c2 = e2.chains.values().find(|c| c.chainType == 1).unwrap();
        assert_eq!(c2.chainKey.counter, 1);
    }

    #[test]
    fn test_decrypt_pkmsg_with_session() {
        let (alice, bob, alice_id, bob_id) = build_pair();
        let plaintext = b"pkmsg payload";

let enc = encrypt(&alice, plaintext, &alice_id, &bob_id, 42).unwrap();
        let pkmsg = proto::PreKeyWhisperMessage {
            pre_key_id: Some(123),
            base_key: vec![0x01; 32],
            identity_key: alice_id.clone(),
            message: enc.ciphertext,
            registration_id: 42,
            signed_pre_key_id: Some(1),
        };
        let pk_bytes = proto::encode_pkmsg(&pkmsg).unwrap();

        let mut wire = vec![0x33];
        wire.extend_from_slice(&pk_bytes);
        let dec = decrypt_pkmsg(&bob, &wire, &bob_id).unwrap();
        assert_eq!(dec.plaintext, plaintext);
    }

    #[test]
    fn test_decrypt_pkmsg_no_session_fails() {
        let (alice, _, alice_id, bob_id) = build_pair();
        let plaintext = b"pkmsg payload";
        let enc = encrypt(&alice, plaintext, &alice_id, &bob_id, 42).unwrap();
        let pkmsg = proto::PreKeyWhisperMessage {
            pre_key_id: Some(123),
            base_key: vec![0x01; 32],
            identity_key: alice_id,
            message: enc.ciphertext,
            registration_id: 42,
            signed_pre_key_id: Some(1),
        };
        let pk_bytes = proto::encode_pkmsg(&pkmsg).unwrap();

        let mut wire = vec![0x33];
        wire.extend_from_slice(&pk_bytes);
        let result = decrypt_pkmsg("{}", &wire, &bob_id);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_then_decrypt_as_self() {
        // Self-session: same identity as both sender and recipient. The record
        // keeps a sending chain (chainType 1) and a mirrored receiving chain
        // (chainType 0) so the SAME session can decrypt its own output.
        let sk = [0x42u8; 32];
        let identity = identity_keypair(&sk);
        let spk = [0x43u8; 32];
        let sig = curve::sign(&sk, &spk, None).unwrap();
        let params = x3dh::X3dhParams {
            identity_priv: &sk,
            identity_pub: &identity,
            signed_prekey_pub: &spk,
            signed_prekey_sig: &sig,
            prekey_pub: None,
            prekey_id: None,
            recipient_pub: &identity,
            recipient_prekey: &spk,
            registration_id: 42,
            signed_key_id: 1,
        };
        let fixed_eph = [0x55u8; 32];
        let alice = x3dh::build_initial_session_with_ephemeral(&params, &fixed_eph).unwrap();

        let mut record = session::deserialize(&alice).unwrap();
        let entry = record.sessions.values_mut().next().unwrap();
        entry.pendingPreKey = None; // bare-ratchet self test (no type-3 wrap)
        let eph_pub = entry.currentRatchet.ephemeralKeyPair.pubKey.clone();
        let send_chain = entry.chains.remove(&eph_pub).unwrap();
        let recv_chain = Chain {
            chainKey: send_chain.chainKey.clone(),
            chainType: 0,
            messageKeys: BTreeMap::new(),
        };
        entry.chains.insert(eph_pub.clone() + ":send", send_chain);
        entry.chains.insert(eph_pub, recv_chain);
        let self_session = session::serialize(&record).unwrap();

        let plaintext = b"self roundtrip";
        let enc = encrypt(&self_session, plaintext, &identity, &identity, 42).unwrap();
        let dec = decrypt_whisper(&self_session, &enc.ciphertext, &identity).unwrap();
        assert_eq!(dec.plaintext, plaintext);
    }

    #[test]
    fn test_full_x3dh_roundtrip_with_recipient_session() {
        // Alice initiates X3DH, Bob builds session as recipient from the wire
        // message. Alice's first message is type-3 (pendingPreKey set). Bob
        // decrypts it (sending chain created by ratchet step) and replies.
        let (alice, bob, alice_id, bob_id) = build_handshake(None);

        // Alice's first message → type 3 (PreKeyWhisperMessage).
        let enc1 = encrypt(&alice, b"first", &alice_id, &bob_id, 42).unwrap();
        assert_eq!(enc1.message_type, 3, "first message wraps as PKMsg");
        assert_eq!(enc1.ciphertext[0], 0x33);

        // Bob decrypts the PKMsg directly (enc1.ciphertext is [0x33] || pkmsg).
        let dec1 = decrypt_pkmsg(&bob, &enc1.ciphertext, &bob_id).unwrap();
        assert_eq!(dec1.plaintext, b"first");

        // Bob's session now has a sending chain (created by ratchet step).
        let bob_rec: SessionRecord = session::deserialize(&dec1.session_json).unwrap();
        let bob_entry = bob_rec.sessions.values().next().unwrap();
        assert!(
            bob_entry.chains.values().any(|c| c.chainType == 1),
            "recipient must have a sending chain after first decrypt"
        );
        // And a receiving chain.
        assert!(
            bob_entry.chains.values().any(|c| c.chainType == 0),
            "recipient must have a receiving chain after first decrypt"
        );

        // Bob replies → type 1 (no pendingPreKey on recipient).
        let enc2 = encrypt(&dec1.session_json, b"reply", &bob_id, &alice_id, 42).unwrap();
        assert_eq!(enc2.message_type, 1, "recipient reply is plain WhisperMessage");

        // Alice decrypts the reply — her pendingPreKey is now cleared.
        let dec2 = decrypt_whisper(&enc1.session_json, &enc2.ciphertext, &alice_id).unwrap();
        assert_eq!(dec2.plaintext, b"reply");
        let alice_rec: SessionRecord = session::deserialize(&dec2.session_json).unwrap();
        let alice_entry = alice_rec.sessions.values().next().unwrap();
        assert!(alice_entry.pendingPreKey.is_none(), "pendingPreKey cleared on decrypt");
    }

    #[test]
    fn test_full_x3dh_roundtrip_with_one_time_prekey() {
        // Same as above, but Alice uses Bob's one-time prekey (DH4 in X3DH).
        let opk_priv = [0x99u8; 32];
        let (alice, bob, alice_id, bob_id) = build_handshake(Some(opk_priv));

        let enc1 = encrypt(&alice, b"opk first", &alice_id, &bob_id, 42).unwrap();
        assert_eq!(enc1.message_type, 3);
        let dec1 = decrypt_pkmsg(&bob, &enc1.ciphertext, &bob_id).unwrap();
        assert_eq!(dec1.plaintext, b"opk first");

        let enc2 = encrypt(&dec1.session_json, b"opk reply", &bob_id, &alice_id, 42).unwrap();
        let dec2 = decrypt_whisper(&enc1.session_json, &enc2.ciphertext, &alice_id).unwrap();
        assert_eq!(dec2.plaintext, b"opk reply");
    }

    // Build Alice (initiator) + Bob (recipient) sessions via real X3DH paths.
    // Returns (alice, bob, alice_id, bob_id).
    fn build_handshake(opk_priv: Option<[u8; 32]>) -> (String, String, Vec<u8>, Vec<u8>) {
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

        // One-time prekey (optional).
        let opk_seed = [0x99u8; 32];
        let (opk_pub, _) = curve::generate_keypair(&opk_seed).unwrap();
        let use_opk = opk_priv.is_some();

        let params = x3dh::X3dhParams {
            identity_priv: &alice_sk,
            identity_pub: &alice_id,
            signed_prekey_pub: &spk_pub,
            signed_prekey_sig: &sig,
            prekey_pub: if use_opk { Some(&opk_pub) } else { None },
            prekey_id: if use_opk { Some(7) } else { None },
            recipient_pub: &bob_id,
            recipient_prekey: &spk_pub,
            registration_id: 42,
            signed_key_id: 4,
        };
        let alice = x3dh::build_initial_session_with_ephemeral(&params, &fixed_eph).unwrap();

        let bob = x3dh::build_recipient_session(
            &bob_sk2,
            &spk_priv,
            &spk_pub,
            if use_opk { Some(&opk_seed) } else { None },
            &alice_id,
            &eph_pub,
            42,
        )
        .unwrap();
        (alice, bob, alice_id, bob_id)
    }
}
