#![deny(unsafe_code)]

use base64::{Engine as _, engine::general_purpose::STANDARD};

pub fn b64(data: &[u8]) -> String {
    STANDARD.encode(data)
}

pub fn unb64(data: &str) -> Result<Vec<u8>, String> {
    STANDARD.decode(data).map_err(|e| e.to_string())
}
