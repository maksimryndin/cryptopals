use crate::ecb_cbc_oracle::encrypt_aes_ecb;
/// https://cryptopals.com/sets/2/challenges/12
use set1::convert_hex_to_base64::base64decode;

pub const SECRET_STRING: &str = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
pub const BLOCK_SIZE: usize = 16;

pub fn ecb_encryption_oracle(plaintext: &[u8], key: [u8; BLOCK_SIZE]) -> Vec<u8> {
    let plain: Vec<u8> = plaintext
        .iter()
        .chain(base64decode(SECRET_STRING.as_bytes()).iter())
        .cloned()
        .collect();
    encrypt_aes_ecb(&plain, key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecb_cbc_oracle::random_aes_key;
    use set1::aes_ecb_mode::remove_pad;
    use set1::detect_aes_ecb::detect_aes_ecb_pattern;

    fn block_size() -> usize {
        let key = random_aes_key();
        let base = String::from_utf8_lossy(&ecb_encryption_oracle(b"", key)).into_owned();
        for i in 1..base.len() {
            let plain = "A".repeat(i);
            let encrypted =
                String::from_utf8_lossy(&ecb_encryption_oracle(plain.as_bytes(), key)).into_owned();
            if encrypted.ends_with(&base) {
                return plain.len();
            }
        }
        0
    }

    #[test]
    fn detect_block_size() {
        assert_eq!(block_size(), BLOCK_SIZE);
    }

    #[test]
    fn detect_ecb() {
        let key = random_aes_key();
        let plain = b"A".repeat(block_size() * 2);
        let encrypted = ecb_encryption_oracle(&plain, key);
        assert!(detect_aes_ecb_pattern(&encrypted));
    }

    fn bruteforce_block(needle: &[u8], template: &mut [u8], key: [u8; BLOCK_SIZE]) -> Option<u8> {
        let b_size = needle.len();
        for b in 0..=255 {
            template[b_size - 1] = b;
            let encrypted_with_byte = ecb_encryption_oracle(template, key);
            if &encrypted_with_byte[..b_size] == needle {
                return Some(b);
            }
        }
        // if we cannot find anything, then padding started which varies its value
        None
    }

    #[test]
    fn discover_secret() {
        let key = random_aes_key();
        let encrypted = ecb_encryption_oracle(b"", key);
        let b_size = block_size();
        let mut decrypted = Vec::with_capacity(b_size + encrypted.len());
        decrypted.extend(b"A".repeat(b_size - 1));
        let mut block = vec![0_u8; b_size];

        for i in 0..encrypted.len() {
            (&mut block[..b_size - 1]).copy_from_slice(&decrypted[i..i + b_size - 1]);
            let block_number = i / b_size;
            let new_encrypted = ecb_encryption_oracle(&block[..b_size - 1 - i % b_size], key);
            let encrypted_block =
                &new_encrypted[block_number * b_size..(block_number + 1) * b_size];
            if let Some(b) = bruteforce_block(encrypted_block, &mut block, key) {
                decrypted.push(b);
            } else {
                break;
            }
        }
        // account for first 15 bytes stub and last artefact byte from padding
        let s = String::from_utf8_lossy(remove_pad(&decrypted[b_size - 1..]));
        println!("{}", s);
        let original = &base64decode(SECRET_STRING.as_bytes());
        assert_eq!(String::from_utf8_lossy(original), s);
    }
}
