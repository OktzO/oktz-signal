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
fn derive_secrets_n(input: &[u8], salt: &[u8], info: &[u8], n: usize) -> Result<Vec<Vec<u8>>, String> {
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
//   shared = scalar_multiply(current_ratchet_priv, remoteKey)
//   mk = deriveSecrets(shared, rootKey, "WhisperRatchet", 2)  // 2 chunks
//   rootKey = mk[0]; new ratchet keypair; receiving chain key = mk[1].
fn maybe_step_ratchet(
    entry: &mut SessionEntry,
    remote_key_b64: &str,
    previous_counter: u32,
) -> Result<(), String> {
    if entry.chains.contains_key(remote_key_b64) {
        return Ok(());
    }
    let remote_key = crate::util::unb64(remote_key_b64)?;
    let ratchet_priv = crate::util::unb64(&entry.currentRatchet.ephemeralKeyPair.privKey)?;
    let shared = curve::scalar_multiply(&ratchet_priv, &remote_key)?;
    let root_key = crate::util::unb64(&entry.currentRatchet.rootKey)?;
    let mk = derive_secrets_n(&shared, &root_key, b"WhisperRatchet", 2)?;

    entry.currentRatchet.rootKey = crate::util::b64(&mk[0]);

    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let (new_pub, new_priv) = curve::generate_keypair(&seed)?;
    entry.currentRatchet.ephemeralKeyPair = KeyPair {
        pubKey: crate::util::b64(&new_pub),
        privKey: crate::util::b64(&new_priv),
    };
    entry.currentRatchet.lastRemoteEphemeralKey = remote_key_b64.to_string();
    entry.currentRatchet.previousCounter = previous_counter;

    entry.chains.insert(
        remote_key_b64.to_string(),
        Chain {
            chainKey: ChainKey {
                counter: -1,
                key: crate::util::b64(&mk[1]),
            },
            chainType: 0, // RECEIVING
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
pub fn encrypt(
    session_json: &str,
    plaintext: &[u8],
    our_identity_pub: &[u8],    // 33 bytes, sender identity
    remote_identity_pub: &[u8], // 33 bytes, recipient identity
) -> Result<EncryptResult, String> {
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

    let session_json = session::serialize(&record)?;
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

    let chain_id = crate::util::b64(&msg.ephemeral_key);
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
        };
        let fixed_eph = [0x55u8; 32];
        let alice = x3dh::build_initial_session_with_ephemeral(&params, &fixed_eph).unwrap();
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

        let enc = encrypt(&alice, plaintext, &alice_id, &bob_id).unwrap();
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
            let enc = encrypt(&alice, m, &alice_id, &bob_id).unwrap();
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

        let enc = encrypt(&alice, plaintext, &alice_id, &bob_id).unwrap();
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

        let enc1 = encrypt(&alice, b"first", &alice_id, &bob_id).unwrap();
        let rec1: SessionRecord = session::deserialize(&enc1.session_json).unwrap();
        let e1 = rec1.sessions.values().next().unwrap();
        let c1 = e1.chains.values().find(|c| c.chainType == 1).unwrap();
        assert_eq!(c1.chainKey.counter, 0);

        let enc2 = encrypt(&enc1.session_json, b"second", &alice_id, &bob_id).unwrap();
        let rec2: SessionRecord = session::deserialize(&enc2.session_json).unwrap();
        let e2 = rec2.sessions.values().next().unwrap();
        let c2 = e2.chains.values().find(|c| c.chainType == 1).unwrap();
        assert_eq!(c2.chainKey.counter, 1);
    }

    #[test]
    fn test_decrypt_pkmsg_with_session() {
        let (alice, bob, alice_id, bob_id) = build_pair();
        let plaintext = b"pkmsg payload";

        let enc = encrypt(&alice, plaintext, &alice_id, &bob_id).unwrap();
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
        let enc = encrypt(&alice, plaintext, &alice_id, &bob_id).unwrap();
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
        };
        let fixed_eph = [0x55u8; 32];
        let alice = x3dh::build_initial_session_with_ephemeral(&params, &fixed_eph).unwrap();

        let mut record = session::deserialize(&alice).unwrap();
        let entry = record.sessions.values_mut().next().unwrap();
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
        let enc = encrypt(&self_session, plaintext, &identity, &identity).unwrap();
        let dec = decrypt_whisper(&self_session, &enc.ciphertext, &identity).unwrap();
        assert_eq!(dec.plaintext, plaintext);
    }
}
