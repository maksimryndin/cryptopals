/// https://cryptopals.com/sets/4/challenges/26

pub const BLOCK_SIZE: usize = 16;

#[cfg(test)]
mod tests {
    use super::*;
    use set2::ecb_cbc_oracle::random_aes_key;
    use set3::ctr::AESKeyStream;

    fn encrypt_userdata(userdata: &str, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
        let input = userdata.replace(";", "%3B").replace("=", "%3D");
        let plaintext = format!(
            "comment1=cooking%20MCs;userdata={input};comment2=%20like%20a%20pound%20of%20bacon"
        );
        let keystream = AESKeyStream::new(0, 0, key);
        plaintext
            .as_bytes()
            .into_iter()
            .zip(keystream)
            .map(|(p, k)| *p ^ k)
            .collect()
    }

    fn check_admin(ciphertext: &[u8], key: [u8; BLOCK_SIZE]) -> Result<bool, String> {
        let keystream = AESKeyStream::new(0, 0, key);
        let decrypted: Vec<u8> = ciphertext
            .iter()
            .zip(keystream)
            .map(|(c, k)| *c ^ k)
            .collect();
        let plaintext = String::from_utf8_lossy(&decrypted);
        Ok(plaintext.find(";admin=true;").is_some())
    }

    #[test]
    fn ctr_attack() {
        let key = random_aes_key();

        fn get_common_len<'a>(first: &[u8], second: &[u8]) -> usize {
            first
                .iter()
                .zip(second.iter())
                .take_while(|(&a, &b)| a == b)
                .count()
        }

        let prefix_len = get_common_len(&encrypt_userdata("a", key), &encrypt_userdata("b", key));
        assert_eq!(b"comment1=cooking%20MCs;userdata=".len(), prefix_len);
        // prefix length is 32.
        let input = format!("{}admin{}true", (b';' ^ 1) as char, (b'=' ^ 1) as char);
        let mut encrypted = encrypt_userdata(&input, key);
        encrypted[32] = encrypted[32] ^ 1;
        encrypted[38] = encrypted[38] ^ 1;
        assert!(check_admin(&encrypted, key).unwrap())
    }
}
