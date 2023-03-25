/// https://cryptopals.com/sets/3/challenges/20
use crate::ctr::{AESKeyStream, BLOCK_SIZE};
use set1::convert_hex_to_base64::base64decode;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

fn encrypt_texts(key: [u8; BLOCK_SIZE]) -> Vec<Vec<u8>> {
    let file: PathBuf = [env!("CARGO_MANIFEST_DIR"), "data", "ctr_fixed_nonce.txt"]
        .iter()
        .collect();
    let mut file = File::open(file).expect("failed to open {file:?}");
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .expect("failed to read file");
    contents
        .split('\n')
        .map(|p| {
            let keystream = AESKeyStream::new(0, 0, key);
            println!("{}", String::from_utf8_lossy(&base64decode(p.as_bytes())));
            base64decode(p.as_bytes())
                .into_iter()
                .zip(keystream)
                .map(|(b, k)| b ^ k)
                .collect()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use set1::single_byte_xor_cipher::score_english_text;
    use set2::ecb_cbc_oracle::random_aes_key;

    #[test]
    fn break_same_nonce_ctr() {
        let key = random_aes_key();

        let ciphertexts = encrypt_texts(key);

        let min_len = ciphertexts.iter().map(|c| c.len()).min().unwrap();
        let mut keystream = vec![0_u8; min_len];
        let mut max_score = f32::MIN;

        for i in 0..min_len {
            for k in 0_u8..=255 {
                let mut text = vec![];
                for c in &ciphertexts {
                    text.push(c[i] ^ k);
                }
                let score = score_english_text(&text);
                if score > max_score {
                    max_score = score;
                    keystream[i] = k;
                }
            }
        }

        // discover first letters
        println!("===== first 3 letters =====");
        for (i, c) in ciphertexts.iter().enumerate() {
            let plain: Vec<u8> = c.iter().zip(&keystream).map(|(c, k)| c ^ k).collect();
            println!("{i:0>2}: {}", String::from_utf8_lossy(&plain));
        }
        println!("===========================");
    }
}
