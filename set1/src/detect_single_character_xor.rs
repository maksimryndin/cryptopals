/// https://cryptopals.com/sets/1/challenges/4
use crate::convert_hex_to_base64::hex_str2bytes_inplace;
use crate::single_byte_xor_cipher::single_byte_xor_decipher_inplace;
use std::fs::File;
use std::io::{self, BufRead};
use std::path::PathBuf;

const LINE_LENGTH: usize = 60;

pub fn detect_ciphered() -> String {
    let path: PathBuf = [
        env!("CARGO_MANIFEST_DIR"),
        "data",
        "detect_single_character_xor.txt",
    ]
    .iter()
    .collect();
    let f = File::open(path).expect("cannot open text");
    const DECODED_SIZE: usize = LINE_LENGTH / 2 as usize;
    let mut encrypted = [0_u8; DECODED_SIZE];
    let mut best_decrypted = [0_u8; DECODED_SIZE];
    let mut score = f32::MIN;
    let mut key = 0_u8;
    io::BufReader::new(f).lines().for_each(|line| {
        // hex to bytes
        hex_str2bytes_inplace(line.as_ref().unwrap(), &mut encrypted);
        let (new_score, new_key) = single_byte_xor_decipher_inplace(&mut encrypted);

        if new_score > score {
            key = new_key;
            score = new_score;
            best_decrypted.clone_from_slice(&encrypted);
        }
    });
    String::from_utf8(best_decrypted.to_vec()).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic() {
        assert_eq!(
            "Now that the party is jumping\n".to_string(),
            detect_ciphered()
        );
    }
}
