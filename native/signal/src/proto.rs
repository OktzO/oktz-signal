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
// Unknown fields are skipped (proto3 semantics), but a known field at the wrong
// wire type is an error rather than a skip, and the fields below marked
// "required" must be present and non-empty — otherwise a malformed message
// would decode into a well-formed one with silently defaulted values.
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
        // Reject overlong/non-canonical varints BEFORE shifting: at the 10th
        // byte (shift == 63) only value bits 0 or 1 are legal, and any further
        // continuation byte would silently truncate with `<< 63`.
        if shift >= 63 && b > 1 {
            return Err("varint too long".into());
        }
        result |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            return Ok(result);
        }
        shift += 7;
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

// Every varint field on the wire is declared u32. `as u32` truncates silently:
// a previous_counter of 2^33 becomes 0, which flows into fill_message_keys so
// the receiver never derives the previous chain's skipped keys and those
// messages become permanently undecryptable. Range-check instead.
fn read_varint_u32(bytes: &[u8], pos: &mut usize, name: &str) -> Result<u32, String> {
    let value = read_varint(bytes, pos)?;
    u32::try_from(value)
        .map_err(|_| format!("{} of {} does not fit the u32 wire field", name, value))
}

fn write_bytes(buf: &mut Vec<u8>, data: &[u8]) {
    write_varint(buf, data.len() as u64);
    buf.extend_from_slice(data);
}

fn read_tag(bytes: &[u8], pos: &mut usize) -> Result<(u32, u32), String> {
    let tag = read_varint(bytes, pos)?;
    if tag > u32::MAX as u64 {
        return Err("tag overflow".into());
    }
    let field = (tag as u32) >> 3;
    let wire = (tag & 0x07) as u32;
    // proto3: field numbers 1..=536870911; field 0 is invalid.
    if field == 0 || field > 0x1fff_ffff {
        return Err("invalid field number".into());
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
        3 | 4 => Err("group wire type is not supported".into()),
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

// A known field sent at the wrong wire type is a hard error. Skipping it would
// leave the field at its default, so a malformed message would decode into a
// well-formed one carrying a silently wrong value.
fn expect_wire(field: u32, name: &str, got: u32, want: u32) -> Result<(), String> {
    if got != want {
        return Err(format!(
            "field {} ({}) has wire type {}, expected {}",
            field, name, got, want
        ));
    }
    Ok(())
}

// --- WhisperMessage ---

pub fn decode_whisper(bytes: &[u8]) -> Result<WhisperMessage, String> {
    let mut msg = WhisperMessage {
        ephemeral_key: Vec::new(),
        counter: 0,
        previous_counter: 0,
        ciphertext: Vec::new(),
    };
    // Presence is tracked, not inferred from the default: a missing field and a
    // field legitimately carrying its default must not be indistinguishable.
    let mut seen_ephemeral_key = false;
    let mut seen_ciphertext = false;
    let mut pos = 0;
    while pos < bytes.len() {
        let (field, wire) = read_tag(bytes, &mut pos)?;
        match field {
            1 => {
                expect_wire(field, "ephemeral_key", wire, 2)?;
                msg.ephemeral_key = read_bytes(bytes, &mut pos)?;
                seen_ephemeral_key = true;
            }
            2 => {
                expect_wire(field, "counter", wire, 0)?;
                msg.counter = read_varint_u32(bytes, &mut pos, "counter")?;
            }
            3 => {
                expect_wire(field, "previous_counter", wire, 0)?;
                msg.previous_counter = read_varint_u32(bytes, &mut pos, "previous_counter")?;
            }
            4 => {
                expect_wire(field, "ciphertext", wire, 2)?;
                msg.ciphertext = read_bytes(bytes, &mut pos)?;
                seen_ciphertext = true;
            }
            _ => skip_field(bytes, &mut pos, wire)?,
        }
    }
    if !seen_ephemeral_key {
        return Err("WhisperMessage.ephemeral_key is required".into());
    }
    if msg.ephemeral_key.is_empty() {
        return Err("WhisperMessage.ephemeral_key is empty".into());
    }
    if !seen_ciphertext {
        return Err("WhisperMessage.ciphertext is required".into());
    }
    if msg.ciphertext.is_empty() {
        return Err("WhisperMessage.ciphertext is empty".into());
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
    let mut seen_base_key = false;
    let mut seen_identity_key = false;
    let mut seen_message = false;
    let mut seen_registration_id = false;
    let mut pos = 0;
    while pos < bytes.len() {
        let (field, wire) = read_tag(bytes, &mut pos)?;
        match field {
            1 => {
                expect_wire(field, "pre_key_id", wire, 0)?;
                msg.pre_key_id = Some(read_varint_u32(bytes, &mut pos, "pre_key_id")?);
            }
            2 => {
                expect_wire(field, "base_key", wire, 2)?;
                msg.base_key = read_bytes(bytes, &mut pos)?;
                seen_base_key = true;
            }
            3 => {
                expect_wire(field, "identity_key", wire, 2)?;
                msg.identity_key = read_bytes(bytes, &mut pos)?;
                seen_identity_key = true;
            }
            4 => {
                expect_wire(field, "message", wire, 2)?;
                msg.message = read_bytes(bytes, &mut pos)?;
                seen_message = true;
            }
            5 => {
                expect_wire(field, "registration_id", wire, 0)?;
                msg.registration_id = read_varint_u32(bytes, &mut pos, "registration_id")?;
                seen_registration_id = true;
            }
            6 => {
                expect_wire(field, "signed_pre_key_id", wire, 0)?;
                msg.signed_pre_key_id = Some(read_varint_u32(bytes, &mut pos, "signed_pre_key_id")?);
            }
            _ => skip_field(bytes, &mut pos, wire)?,
        }
    }
    if !seen_base_key {
        return Err("PreKeyWhisperMessage.base_key is required".into());
    }
    if msg.base_key.is_empty() {
        return Err("PreKeyWhisperMessage.base_key is empty".into());
    }
    if !seen_identity_key {
        return Err("PreKeyWhisperMessage.identity_key is required".into());
    }
    if msg.identity_key.is_empty() {
        return Err("PreKeyWhisperMessage.identity_key is empty".into());
    }
    if !seen_message {
        return Err("PreKeyWhisperMessage.message is required".into());
    }
    if msg.message.is_empty() {
        return Err("PreKeyWhisperMessage.message is empty".into());
    }
    if !seen_registration_id {
        return Err("PreKeyWhisperMessage.registration_id is required".into());
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

    // No Debug on the message structs, so unwrap_err() is unavailable.
    fn decode_err<T>(r: Result<T, String>) -> String {
        match r {
            Ok(_) => panic!("the message must be rejected"),
            Err(e) => e,
        }
    }

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

    // --- structural validation ---

    // --- structural validation ---
    //
    // The wire bytes below are written out in full so a reader can check them
    // against protobuf.dev by eye. A well-formed message is:
    //   WhisperMessage   field1 ephemeral_key="abc"   field2 counter=1
    //                     field3 previous_counter=0   field4 ciphertext="xyz"
    //   PreKeyWhisper    field1 pre_key_id=1          field2 base_key=[0xEE]
    //                     field3 identity_key=[0xFF]  field4 message=[0x10]
    //                     field5 registration_id=42

    #[test]
    fn whisper_without_ephemeral_key_is_rejected() {
        let err = decode_err(decode_whisper(&hex("10011800220378797a")));
        assert!(
            err.contains("ephemeral_key"),
            "a missing ephemeral_key must be named, got: {}",
            err
        );
    }

    #[test]
    fn whisper_without_ciphertext_is_rejected() {
        let err = decode_err(decode_whisper(&hex("0a0361626310011800")));
        assert!(
            err.contains("ciphertext"),
            "a missing ciphertext must be named, got: {}",
            err
        );
    }

    #[test]
    fn whisper_with_empty_ciphertext_is_rejected() {
        let err = decode_err(decode_whisper(&hex("0a03616263100118002200")));
        assert!(
            err.contains("ciphertext"),
            "a zero-length ciphertext must be named, got: {}",
            err
        );
    }

    #[test]
    fn whisper_ephemeral_key_at_wrong_wire_type_is_rejected() {
        // field1 at wire type 0 (varint) rather than 2 (length-delimited).
        let err = decode_err(decode_whisper(&hex("082a10011800220378797a")));
        assert!(
            err.contains("ephemeral_key"),
            "a known field at the wrong wire type must be named, not defaulted, got: {}",
            err
        );
    }

    #[test]
    fn whisper_known_field_at_wrong_wire_type_is_rejected() {
        // field2 (counter, a varint) sent at wire type 2.
        let err = decode_err(decode_whisper(&hex("0a036162631201051800220378797a")));
        assert!(
            err.contains("counter"),
            "a known field at the wrong wire type must be a hard error, not a skip, got: {}",
            err
        );
    }

    #[test]
    fn whisper_of_only_unknown_fields_is_rejected() {
        // field7 at wire type 2, length 0: a legal unknown field, and no message.
        let err = decode_err(decode_whisper(&hex("3a00")));
        assert!(
            err.contains("ephemeral_key") || err.contains("ciphertext"),
            "a message with no required field present must be rejected, got: {}",
            err
        );
    }

    #[test]
    fn whisper_group_wire_type_is_rejected_clearly() {
        // field7 at wire type 3 (start group), closed by wire type 4. Skipping a
        // group is not implemented, so the message must be refused outright
        // rather than mis-parsed as if the group were absent.
        let err = decode_err(decode_whisper(&hex("0a0361626310011800220378797a3b3c")));
        assert!(
            err.contains("group"),
            "an unsupported group must be refused with a clear error, got: {}",
            err
        );
    }

    #[test]
    fn pkmsg_without_registration_id_is_rejected() {
        let err = decode_err(decode_pkmsg(&hex("08011201ee1a01ff220110")));
        assert!(
            err.contains("registration_id"),
            "an absent registration_id must not silently become 0, got: {}",
            err
        );
    }

    #[test]
    fn pkmsg_without_base_key_is_rejected() {
        let err = decode_err(decode_pkmsg(&hex("08011a01ff220110282a")));
        assert!(
            err.contains("base_key"),
            "a missing base_key must be named, got: {}",
            err
        );
    }

    #[test]
    fn pkmsg_without_message_is_rejected() {
        let err = decode_err(decode_pkmsg(&hex("08011201ee1a01ff282a")));
        assert!(
            err.contains("message"),
            "a missing message must be named, got: {}",
            err
        );
    }

    #[test]
    fn pkmsg_with_pre_key_id_and_empty_message_is_rejected() {
        let err = decode_err(decode_pkmsg(&hex("08011201ee1a01ff2200282a")));
        assert!(
            err.contains("message"),
            "a pkmsg carrying no payload must be named, got: {}",
            err
        );
    }

    #[test]
    fn pkmsg_of_only_unknown_fields_is_rejected() {
        let err = decode_err(decode_pkmsg(&hex("3a00")));
        assert!(
            err.contains("base_key") || err.contains("message"),
            "a pkmsg with no required field present must be rejected, got: {}",
            err
        );
    }

    #[test]
    fn pkmsg_known_field_at_wrong_wire_type_is_rejected() {
        // field5 (registration_id, a varint) sent at wire type 2.
        let err = decode_err(decode_pkmsg(&hex("08011201ee1a01ff2201102a012a")));
        assert!(
            err.contains("registration_id"),
            "a known field at the wrong wire type must be a hard error, not a skip, got: {}",
            err
        );
    }

    // --- varint range ---
    //
    // The writers below are the module's own, so the varint under test is
    // exactly the value named rather than a hand-counted byte string. The
    // writers are pinned independently by the two known-answer tests above.

    fn whisper_with(field: u32, value: u64) -> Vec<u8> {
        let mut out = Vec::new();
        write_tag(&mut out, 1, 2);
        write_bytes(&mut out, b"abc");
        write_tag(&mut out, 2, 0);
        write_varint(&mut out, 1);
        write_tag(&mut out, 3, 0);
        write_varint(&mut out, 0);
        write_tag(&mut out, field, 0);
        write_varint(&mut out, value);
        write_tag(&mut out, 4, 2);
        write_bytes(&mut out, b"xyz");
        out
    }

    fn pkmsg_with(field: u32, value: u64) -> Vec<u8> {
        let mut out = Vec::new();
        write_tag(&mut out, 2, 2);
        write_bytes(&mut out, &[0xEE]);
        write_tag(&mut out, 3, 2);
        write_bytes(&mut out, &[0xFF]);
        write_tag(&mut out, 4, 2);
        write_bytes(&mut out, &[0x10]);
        write_tag(&mut out, 5, 0);
        write_varint(&mut out, 42);
        // Every required field is present, and the oversized varint comes last
        // so it wins under last-occurrence-wins. Without this the presence
        // check trips first and the range check is never reached.
        write_tag(&mut out, field, 0);
        write_varint(&mut out, value);
        out
    }

    #[test]
    fn whisper_varint_beyond_u32_is_rejected() {
        // 2^33 truncates to 0 under `as u32`, and previous_counter feeds
        // fill_message_keys, so the receiver never derives the previous
        // chain's skipped keys and those messages become permanently
        // undecryptable. A counter of u64::MAX truncates to u32::MAX.
        for (field, name, value) in [
            (2u32, "counter", u64::MAX),
            (2, "counter", 1u64 << 33),
            (3, "previous_counter", 1u64 << 33),
            (3, "previous_counter", u64::MAX),
        ] {
            let err = decode_err(decode_whisper(&whisper_with(field, value)));
            assert!(
                err.contains(name),
                "{} of {} does not fit the u32 wire field and must be named, got: {}",
                name,
                value,
                err
            );
        }
    }

    #[test]
    fn pkmsg_varint_beyond_u32_is_rejected() {
        for (field, name) in [(1u32, "pre_key_id"), (5, "registration_id"), (6, "signed_pre_key_id")]
        {
            let err = decode_err(decode_pkmsg(&pkmsg_with(field, 1u64 << 33)));
            assert!(
                err.contains(name),
                "{} of 2^33 does not fit the u32 wire field and must be named, got: {}",
                name,
                err
            );
        }
    }

    #[test]
    fn whisper_varint_at_the_u32_boundary_is_accepted() {
        // The check must be a range check, not a rejection of large values.
        let decoded = decode_whisper(&whisper_with(3, u32::MAX as u64)).unwrap();
        assert_eq!(decoded.previous_counter, u32::MAX);
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
