use aes::cipher::{generic_array::GenericArray, BlockDecrypt, KeyInit};
/// https://cryptopals.com/sets/1/challenges/7
use aes::Aes128;

const BLOCK_SIZE: usize = 16;

pub fn aes_ecb_decrypt(encrypted: &mut [u8], key: [u8; BLOCK_SIZE]) {
    // data is padded properly
    assert_eq!(0, encrypted.len() % BLOCK_SIZE);
    let key = GenericArray::from(key);
    let cipher = Aes128::new(&key);
    (0..encrypted.len()).step_by(BLOCK_SIZE).for_each(|i| {
        let block: [u8; BLOCK_SIZE] = encrypted[i..i + BLOCK_SIZE].try_into().unwrap();
        let mut block = GenericArray::from(block);
        cipher.decrypt_block(&mut block);
        encrypted[i..i + BLOCK_SIZE].swap_with_slice(&mut block);
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helpers::{filename_fullpath, read_b64_encoded};
    use std::process::Command;

    #[test]
    fn aes_ecb_mode() {
        let mut decoded = read_b64_encoded("aes_ecb.txt");
        let openssl_decoded_output = Command::new("openssl")
            .arg("base64")
            .arg("-d")
            .arg("-in")
            .arg(filename_fullpath("aes_ecb.txt"))
            .output()
            .expect("failed to decode b64 with openssl")
            .stdout;

        assert_eq!(openssl_decoded_output, decoded);

        aes_ecb_decrypt(&mut decoded, *b"YELLOW SUBMARINE");

        let openssl_output = Command::new("openssl")
            .arg("enc")
            .arg("-aes-128-ecb")
            .arg("-a")
            .arg("-d")
            .arg("-K")
            .arg("59454c4c4f57205355424d4152494e45")
            .arg("-in")
            .arg(filename_fullpath("aes_ecb.txt"))
            .output()
            .expect("failed to decipher with openssl")
            .stdout;

        // AES rust implementation outputs also 4 last bytes with value 4_u8. Why?
        decoded.truncate(openssl_output.len());
        assert_eq!(
            String::from_utf8(openssl_output).unwrap(),
            String::from_utf8(decoded).unwrap()
        );
    }
}
