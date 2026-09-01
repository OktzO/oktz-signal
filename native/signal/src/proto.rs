#![deny(unsafe_code)]

use serde::{Deserialize, Serialize};
// proto.rs — hand-written minimal protobuf wire codec
// WhisperMessage + PreKeyWhisperMessage (Signal protocol wire format).
//
// Wire encoding (protobuf.dev/programming-guides/encoding):
//   tag      = (field_number << 3) | wire_type
//   wire 0   = varint (uint32 fields)
//   wire 2   = length-delimited (bytes fields)
//   wire 1/5 = fixed64/fixed32 (only needed to skip unknown fields)
//   Unknown fields are skipped (proto3 semantics).
//
// WhisperMessage:        1 ephemeral_key (bytes), 2 counter (varint),
//                        3 previous_counter (varint), 4 ciphertext (bytes)
// PreKeyWhisperMessage:  1 pre_key_id (varint, optional), 2 base_key (bytes),
//                        3 identity_key (bytes), 4 message (bytes, serialized
//                        WhisperMessage), 5 registration_id (varint),
//                        6 signed_pre_key_id (varint, optional)

#[derive(Serialize, Deserialize)]
pub struct WhisperMessage {
    pub ephemeral_key: Vec<u8>,
    pub counter: u32,
    pub previous_counter: u32,
    pub ciphertext: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct PreKeyWhisperMessage {
    pub pre_key_id: Option<u32>,
    pub base_key: Vec<u8>,
    pub identity_key: Vec<u8>,
    pub message: Vec<u8>, // serialized WhisperMessage
    pub registration_id: u32,
    pub signed_pre_key_id: Option<u32>,
}

// --- wire helpers ---

fn read_varint(bytes: &[u8], pos: &mut usize) -> Result<u64, String> {
    let mut result: u64 = 0;
    let mut shift: u32 = 0;
    loop {
        if *pos >= bytes.len() {
            return Err(format!("varint truncated at byte {}", *pos));
        }
        let b = bytes[*pos];
        *pos += 1;
        result |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            return Ok(result);
        }
        shift += 7;
        if shift >= 64 {
            return Err("varint too long".into());
        }
    }
}

fn write_varint(buf: &mut Vec<u8>, value: u64) {
    let mut v = value;
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            buf.push(byte);
            break;
        }
        buf.push(byte | 0x80);
    }
}

fn read_bytes(bytes: &[u8], pos: &mut usize) -> Result<Vec<u8>, String> {
    let len = read_varint(bytes, pos)? as usize;
    if len > bytes.len().saturating_sub(*pos) {
        return Err(format!("bytes field truncated at byte {}", *pos));
    }
    let out = bytes[*pos..*pos + len].to_vec();
    *pos += len;
    Ok(out)
}

fn write_bytes(buf: &mut Vec<u8>, data: &[u8]) {
    write_varint(buf, data.len() as u64);
    buf.extend_from_slice(data);
}

fn read_tag(bytes: &[u8], pos: &mut usize) -> Result<(u32, u32), String> {
    let tag = read_varint(bytes, pos)?;
    let field = (tag >> 3) as u32;
    let wire = (tag & 0x07) as u32;
    if field == 0 {
        return Err("invalid field number 0".into());
    }
    Ok((field, wire))
}

fn write_tag(buf: &mut Vec<u8>, field: u32, wire: u32) {
    write_varint(buf, ((field as u64) << 3) | (wire as u64));
}

// Skip an unknown field's payload based on its wire type (proto3 semantics).
fn skip_field(bytes: &[u8], pos: &mut usize, wire: u32) -> Result<(), String> {
    match wire {
        0 => {
            read_varint(bytes, pos)?;
            Ok(())
        }
        1 => {
            if bytes.len().saturating_sub(*pos) < 8 {
                return Err("fixed64 field truncated".into());
            }
            *pos += 8;
            Ok(())
        }
        2 => {
            read_bytes(bytes, pos)?;
            Ok(())
        }
        5 => {
            if bytes.len().saturating_sub(*pos) < 4 {
                return Err("fixed32 field truncated".into());
            }
            *pos += 4;
            Ok(())
        }
        _ => Err(format!("unsupported wire type {}", wire)),
    }
}

// --- WhisperMessage ---

pub fn decode_whisper(bytes: &[u8]) -> Result<WhisperMessage, String> {
    let mut msg = WhisperMessage {
        ephemeral_key: Vec::new(),
        counter: 0,
        previous_counter: 0,
        ciphertext: Vec::new(),
    };
    let mut pos = 0;
    while pos < bytes.len() {
        let (field, wire) = read_tag(bytes, &mut pos)?;
        match (field, wire) {
            (1, 2) => msg.ephemeral_key = read_bytes(bytes, &mut pos)?,
            (2, 0) => msg.counter = read_varint(bytes, &mut pos)? as u32,
            (3, 0) => msg.previous_counter = read_varint(bytes, &mut pos)? as u32,
            (4, 2) => msg.ciphertext = read_bytes(bytes, &mut pos)?,
            (_, w) => skip_field(bytes, &mut pos, w)?,
        }
    }
    Ok(msg)
}

pub fn encode_whisper(msg: &WhisperMessage) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    write_tag(&mut buf, 1, 2);
    write_bytes(&mut buf, &msg.ephemeral_key);
    write_tag(&mut buf, 2, 0);
    write_varint(&mut buf, msg.counter as u64);
    write_tag(&mut buf, 3, 0);
    write_varint(&mut buf, msg.previous_counter as u64);
    write_tag(&mut buf, 4, 2);
    write_bytes(&mut buf, &msg.ciphertext);
    Ok(buf)
}

// --- PreKeyWhisperMessage ---

pub fn decode_pkmsg(bytes: &[u8]) -> Result<PreKeyWhisperMessage, String> {
    let mut msg = PreKeyWhisperMessage {
        pre_key_id: None,
        base_key: Vec::new(),
        identity_key: Vec::new(),
        message: Vec::new(),
        registration_id: 0,
        signed_pre_key_id: None,
    };
    let mut pos = 0;
    while pos < bytes.len() {
        let (field, wire) = read_tag(bytes, &mut pos)?;
        match (field, wire) {
            (1, 0) => msg.pre_key_id = Some(read_varint(bytes, &mut pos)? as u32),
            (2, 2) => msg.base_key = read_bytes(bytes, &mut pos)?,
            (3, 2) => msg.identity_key = read_bytes(bytes, &mut pos)?,
            (4, 2) => msg.message = read_bytes(bytes, &mut pos)?,
            (5, 0) => msg.registration_id = read_varint(bytes, &mut pos)? as u32,
            (6, 0) => msg.signed_pre_key_id = Some(read_varint(bytes, &mut pos)? as u32),
            (_, w) => skip_field(bytes, &mut pos, w)?,
        }
    }
    Ok(msg)
}

pub fn encode_pkmsg(msg: &PreKeyWhisperMessage) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    if let Some(id) = msg.pre_key_id {
        write_tag(&mut buf, 1, 0);
        write_varint(&mut buf, id as u64);
    }
    write_tag(&mut buf, 2, 2);
    write_bytes(&mut buf, &msg.base_key);
    write_tag(&mut buf, 3, 2);
    write_bytes(&mut buf, &msg.identity_key);
    write_tag(&mut buf, 4, 2);
    write_bytes(&mut buf, &msg.message);
    write_tag(&mut buf, 5, 0);
    write_varint(&mut buf, msg.registration_id as u64);
    if let Some(id) = msg.signed_pre_key_id {
        write_tag(&mut buf, 6, 0);
        write_varint(&mut buf, id as u64);
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn test_whisper_roundtrip() {
        let msg = WhisperMessage {
            ephemeral_key: vec![0xAB; 32],
            counter: 42,
            previous_counter: 7,
            ciphertext: vec![0xCD; 64],
        };
        let encoded = encode_whisper(&msg).unwrap();
        let decoded = decode_whisper(&encoded).unwrap();
        assert_eq!(decoded.ephemeral_key, msg.ephemeral_key);
        assert_eq!(decoded.counter, 42);
        assert_eq!(decoded.previous_counter, 7);
        assert_eq!(decoded.ciphertext, msg.ciphertext);
    }

    #[test]
    fn test_pkmsg_roundtrip_with_optionals() {
        let msg = PreKeyWhisperMessage {
            pre_key_id: Some(1234),
            base_key: vec![0x11; 33],
            identity_key: vec![0x22; 33],
            message: vec![0x33; 50],
            registration_id: 555,
            signed_pre_key_id: Some(9),
        };
        let encoded = encode_pkmsg(&msg).unwrap();
        let decoded = decode_pkmsg(&encoded).unwrap();
        assert_eq!(decoded.pre_key_id, Some(1234));
        assert_eq!(decoded.base_key, msg.base_key);
        assert_eq!(decoded.identity_key, msg.identity_key);
        assert_eq!(decoded.message, msg.message);
        assert_eq!(decoded.registration_id, 555);
        assert_eq!(decoded.signed_pre_key_id, Some(9));
    }

    #[test]
    fn test_pkmsg_roundtrip_no_optionals() {
        let msg = PreKeyWhisperMessage {
            pre_key_id: None,
            base_key: vec![0xAA; 33],
            identity_key: vec![0xBB; 33],
            message: vec![0xCC; 20],
            registration_id: 1,
            signed_pre_key_id: None,
        };
        let encoded = encode_pkmsg(&msg).unwrap();
        let decoded = decode_pkmsg(&encoded).unwrap();
        assert_eq!(decoded.pre_key_id, None);
        assert_eq!(decoded.signed_pre_key_id, None);
        assert_eq!(decoded.base_key, msg.base_key);
        assert_eq!(decoded.identity_key, msg.identity_key);
        assert_eq!(decoded.message, msg.message);
        assert_eq!(decoded.registration_id, 1);
    }

    #[test]
    fn test_whisper_skips_unknown_field() {
        let msg = WhisperMessage {
            ephemeral_key: vec![0x01; 8],
            counter: 100,
            previous_counter: 0,
            ciphertext: vec![0x02; 12],
        };
        let encoded = encode_whisper(&msg).unwrap();
        // Append unknown field 7 (varint): tag = (7<<3)|0 = 0x38, value 123.
        let mut with_unknown = encoded.clone();
        with_unknown.extend_from_slice(&[0x38, 123]);
        let decoded = decode_whisper(&with_unknown).unwrap();
        assert_eq!(decoded.ephemeral_key, msg.ephemeral_key);
        assert_eq!(decoded.counter, 100);
        assert_eq!(decoded.previous_counter, 0);
        assert_eq!(decoded.ciphertext, msg.ciphertext);
    }

    // Known-answer: exact protobuf wire bytes for a fixed message.
    #[test]
    fn test_whisper_known_answer_bytes() {
        let msg = WhisperMessage {
            ephemeral_key: b"abc".to_vec(),
            counter: 300, // varint multi-byte: 0xAC 0x02
            previous_counter: 0,
            ciphertext: b"xyz".to_vec(),
        };
        let encoded = encode_whisper(&msg).unwrap();
        let expected = hex("0a0361626310ac021800220378797a");
        assert_eq!(encoded, expected);
    }

    #[test]
    fn test_pkmsg_known_answer_bytes() {
        // pre_key_id=1, base_key=[0xEE], identity_key=[0xFF], message=[0x10],
        // registration_id=0, signed_pre_key_id=NONE
        let msg = PreKeyWhisperMessage {
            pre_key_id: Some(1),
            base_key: vec![0xEE],
            identity_key: vec![0xFF],
            message: vec![0x10],
            registration_id: 0,
            signed_pre_key_id: None,
        };
        let encoded = encode_pkmsg(&msg).unwrap();
        // field1 varint: 0x08 01; field2 bytes: 0x12 01 ee;
        // field3 bytes: 0x1a 01 ff; field4 bytes: 0x22 01 10;
        // field5 varint: 0x28 00; field6 absent.
        let expected = hex("08011201ee1a01ff2201102800");
        assert_eq!(encoded, expected);
    }
}
