/// https://cryptopals.com/sets/2/challenges/14
use crate::byte_at_a_time_ecb::{BLOCK_SIZE, SECRET_STRING};
use crate::ecb_cbc_oracle::encrypt_aes_ecb;
use set1::convert_hex_to_base64::base64decode;

pub fn ecb_encryption_oracle(
    random_prefix: &[u8],
    attacker_input: &[u8],
    key: [u8; BLOCK_SIZE],
) -> Vec<u8> {
    let plain: Vec<u8> = random_prefix
        .iter()
        .chain(attacker_input.iter())
        .chain(base64decode(SECRET_STRING.as_bytes()).iter())
        .cloned()
        .collect();
    encrypt_aes_ecb(&plain, key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecb_cbc_oracle::{rand_range, random_aes_key};
    use set1::aes_ecb_mode::remove_pad;
    use set1::detect_aes_ecb::detect_aes_ecb_pattern;
    use std::collections::HashMap;

    fn get_random_prefix() -> Vec<u8> {
        let random_prefix_len = rand_range(0, 30) as usize;
        let mut buf = [0u8; 30];
        getrandom::getrandom(&mut buf).expect("failed to obtain random data");
        buf[..random_prefix_len].to_vec()
    }

    #[test]
    fn discover_plaintext_with_random_prefix() {
        let discover_block_size = || {
            let random_prefix = get_random_prefix();
            let key = random_aes_key();
            let initial_length = ecb_encryption_oracle(&random_prefix, b"", key).len();
            let mut current_len = initial_length;
            let mut input_size = 0;
            while initial_length == current_len {
                let input = b"A".repeat(input_size);
                let encrypted = ecb_encryption_oracle(&random_prefix, &input, key);
                current_len = encrypted.len();
                input_size += 1;
            }
            current_len - initial_length
        };

        let block_size = discover_block_size();
        assert_eq!(block_size, BLOCK_SIZE);

        let random_prefix = get_random_prefix();
        let key = random_aes_key();

        let no_input_encrypted = ecb_encryption_oracle(&random_prefix, b"", key);
        let no_input_encrypted_len = no_input_encrypted.len();
        // we didn't discover any two equal blocks
        assert!(!detect_aes_ecb_pattern(&no_input_encrypted));

        // so we can try to feed input byte by byte
        // till we get two equal blocks
        // than we know that before the first repeating block
        // is the prefix with pad
        fn detect_first_repeating_block(encrypted: &[u8], block_size: usize) -> Option<usize> {
            let mut dict = HashMap::<&[u8], usize>::new();
            for (i, chunk) in encrypted.chunks_exact(block_size).enumerate() {
                match dict.get(chunk) {
                    None => dict.insert(chunk, i),
                    Some(&num) => return Some(num),
                };
            }
            None
        }

        let mut input_size = 0;
        let mut encrypted = no_input_encrypted;
        while detect_first_repeating_block(&encrypted, block_size).is_none() {
            input_size += 1;
            let input = b"A".repeat(input_size);
            encrypted = ecb_encryption_oracle(&random_prefix, &input, key);
        }
        let block_number = detect_first_repeating_block(&encrypted, block_size).unwrap();
        let pad_size = input_size - 2 * block_size;
        let prefix_len = block_number * block_size;
        assert_eq!(random_prefix.len(), prefix_len - pad_size);

        fn bruteforce_block(
            target_block: &[u8],
            input: &mut [u8],
            random_prefix: &[u8],
            key: [u8; BLOCK_SIZE],
            prefix_len: usize,
        ) -> Option<u8> {
            let block_size = target_block.len();
            for b in 0..=255 {
                *input.last_mut().unwrap() = b;
                let encrypted = ecb_encryption_oracle(&random_prefix, input, key);

                if &encrypted[prefix_len..prefix_len + block_size] == target_block {
                    return Some(b);
                }
            }
            None
        }

        // now we can ingore the first blocks (random prefix + `pad_size` bytes)
        // and repeat the challenge 12 procedure
        let mut decrypted = b"A".repeat(pad_size + block_size - 1);
        let mut input = vec![0_u8; pad_size + block_size];
        for i in 0..no_input_encrypted_len {
            (&mut input[..pad_size + block_size - 1])
                .copy_from_slice(&decrypted[i..i + pad_size + block_size - 1]);
            let block_number = i / block_size + prefix_len / block_size; //first blocks contain prefix
            let encrypted = ecb_encryption_oracle(
                &random_prefix,
                &input[..pad_size + block_size - 1 - i % block_size],
                key,
            );
            let target_block =
                &encrypted[block_number * block_size..(block_number + 1) * block_size];

            if let Some(b) =
                bruteforce_block(target_block, &mut input, &random_prefix, key, prefix_len)
            {
                decrypted.push(b);
                println!("discovered {b}");
            } else {
                break;
            }
        }
        let secret = remove_pad(&decrypted[pad_size + block_size - 1..]);
        println!("{}", String::from_utf8_lossy(secret));
        assert_eq!(secret, base64decode(SECRET_STRING.as_bytes()));
    }
}
