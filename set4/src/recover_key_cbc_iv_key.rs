/// https://cryptopals.com/sets/2/challenges/16

pub const BLOCK_SIZE: usize = 16;

#[cfg(test)]
mod tests {
    use super::*;
    use set1::fixed_xor::xor;
    use set2::cbc_mode::{cbc, cbc_decrypt_inplace};
    use set2::ecb_cbc_oracle::random_aes_key;
    use set2::pkcs7_padding_validation::validate_pkcs7_padding;

    fn encrypt_userdata(userdata: &str, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
        let input = userdata.replace(";", "%3B").replace("=", "%3D");
        let plaintext = format!(
            "comment1=cooking%20MCs;userdata={input};comment2=%20like%20a%20pound%20of%20bacon"
        );
        cbc(plaintext.as_bytes(), key, key)
    }

    // Verify each byte of the plaintext for ASCII compliance (ie, look for high-ASCII values).
    // Noncompliant messages should raise an exception or return an error that includes the decrypted plaintext
    fn check_admin(ciphertext: &[u8], key: [u8; BLOCK_SIZE]) -> Result<bool, String> {
        let mut decrypted = ciphertext.to_vec();
        cbc_decrypt_inplace(&mut decrypted, key, key);
        let without_pad = validate_pkcs7_padding(&decrypted)?;
        if decrypted.iter().find(|&&p| p >= 128u8).is_some() {
            return Err(format!("{:?}", decrypted));
        }
        let plaintext = String::from_utf8_lossy(&without_pad);
        Ok(plaintext.find(";admin=true;").is_some())
    }

    #[test]
    fn cbc_key_iv_attack() {
        let key = random_aes_key();

        fn discover_block_size() -> usize {
            let key = random_aes_key();
            let length = encrypt_userdata("", key).len();
            let mut curr_length = length;
            let mut i = 0;
            while curr_length == length {
                i += 1;
                curr_length = encrypt_userdata(&"A".repeat(i), key).len();
            }
            curr_length - length
        }

        let block_size = discover_block_size();
        assert_eq!(BLOCK_SIZE, block_size);

        fn discover_prefix_len(block_size: usize) -> usize {
            fn get_common_len<'a>(first: &[u8], second: &[u8]) -> usize {
                first
                    .iter()
                    .zip(second.iter())
                    .take_while(|(&a, &b)| a == b)
                    .count()
            }

            let key = random_aes_key();
            let mut max_common_len: usize = 0;
            let mut pad = 0;
            for i in 0..block_size {
                let common = "A".repeat(i);
                let left = encrypt_userdata(&format!("{common}X"), key);
                let right = encrypt_userdata(&format!("{common}Y"), key);
                let common_len = get_common_len(&left, &right);
                if common_len > max_common_len {
                    max_common_len = common_len;
                    pad = i;
                }
            }
            assert_eq!(max_common_len % block_size, 0);
            max_common_len - pad
        }

        // encryption
        // iv ^ p1 -> c1
        // p1 ^ p2 -> c2
        // p2 ^ p3 -> c3

        // decryption of the original ciphertext
        // c1 -> ^ iv = p1
        // c2 -> ^ c1 = p2
        // c3 -> ^ c2 = p3

        // decryption of the modified ciphertext
        // c1 -> ^ iv = p1
        // 0 -> ^ c1 = p2'
        // c1 -> ^ 0 = p3'

        // p1 ^ p3' = (c1 -> ^ iv) ^ (c1 -> ^ 0) = (c1 ->) ^ iv ^ (c1 ->) ^ 0 = iv

        let prefix_len = discover_prefix_len(block_size);
        assert_eq!(b"comment1=cooking%20MCs;userdata=".len(), prefix_len);
        println!("prefix length: {prefix_len}");
        // prefix length is 32.
        // so our input starts the third block
        let third_block = "A".repeat(block_size);
        let mut encrypted = encrypt_userdata(&third_block, key);
        // filling the second block with 0s
        (block_size..2 * block_size).for_each(|i| {
            encrypted[i] = 0u8;
        });
        // setting the third block equal to the first one
        (2 * block_size..3 * block_size).for_each(|i| {
            encrypted[i] = encrypted[i - 2 * block_size];
        });
        if let Err(text) = check_admin(&encrypted, key) {
            let decrypted: Vec<u8> = text
                .strip_prefix('[')
                .unwrap()
                .strip_suffix(']')
                .unwrap()
                .split(", ")
                .map(|c| c.parse::<_>().unwrap())
                .collect();
            let iv = xor(
                &decrypted[..block_size],
                &decrypted[2 * block_size..3 * block_size],
            );
            assert_eq!(iv, key);
        } else {
            panic!("error should be raised!");
        }
    }
}
