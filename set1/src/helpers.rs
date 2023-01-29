use crate::convert_hex_to_base64::base64decode;
use std::fs::read_to_string;
use std::path::PathBuf;

pub fn filename_fullpath(filename: &str) -> PathBuf {
    [env!("CARGO_MANIFEST_DIR"), "data", filename]
        .iter()
        .collect()
}

pub fn read_b64_encoded(filename: PathBuf) -> Vec<u8> {
    let encoded: Vec<String> = read_to_string(filename)
        .expect("cannot read file")
        .split_whitespace()
        .map(|s| s.to_string())
        .collect();
    base64decode(encoded.join("").as_bytes())
}
