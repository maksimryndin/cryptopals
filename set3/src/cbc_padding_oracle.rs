/// https://cryptopals.com/sets/3/challenges/17
/// see more about similar attack https://joyofcryptography.com/pdf/chap9.pdf
use set1::convert_hex_to_base64::base64decode;
use set2::cbc_mode::{cbc, cbc_decrypt_inplace, BLOCK_SIZE};
use set2::ecb_cbc_oracle::{rand_range, random_aes_key};
use set2::pkcs7_padding_validation::validate_pkcs7_padding;

const STRINGS: [&'static str; 10] = [
    "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
    "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
    "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
    "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
    "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
    "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
    "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
    "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
    "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
    "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
];

pub fn encrypt(key: [u8; BLOCK_SIZE]) -> (Vec<u8>, [u8; BLOCK_SIZE]) {
    let iv = random_aes_key();
    let string_number = rand_range(0, 10) as usize;
    let data = base64decode(STRINGS[string_number].as_bytes());
    (cbc(&data, key, iv), iv)
}

pub fn padding_oracle(ciphertext: &[u8], key: [u8; BLOCK_SIZE], iv: [u8; BLOCK_SIZE]) -> bool {
    let mut data = ciphertext.to_vec();
    cbc_decrypt_inplace(&mut data, key, iv);
    validate_pkcs7_padding(&data).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use set1::aes_ecb_mode::remove_pad;
    use std::sync::Arc;
    use std::thread;

    // xors destination pad-1 bytes with target bytes and pad
    fn xor_pad(destination: &mut [u8], plaintext_reversed: &[u8], pad: u8) -> Result<(), String> {
        let size = destination.len();
        let number_replaced = pad as usize - 1;
        if size < number_replaced {
            return Err(format!(
                "destination size should be greater or equal pad - 1 ({number_replaced})"
            ));
        }
        if plaintext_reversed.len() < number_replaced {
            return Err(format!(
                "plaintext_reversed size should be greater or equal pad - 1 ({number_replaced})"
            ));
        }
        (0..number_replaced).for_each(|index| {
            destination[size - index - 1] ^= plaintext_reversed[index] ^ pad;
        });
        Ok(())
    }

    #[test]
    fn test_xor_padder() {
        let mut destination = vec![1_u8, 2, 3, 4, 5];
        let plaintext_reversed = vec![5_u8, 4, 3, 2, 1];
        xor_pad(&mut destination, &plaintext_reversed, 3).expect("failed to xor pad");
        assert_eq!(destination, vec![1_u8, 2, 3, 3, 3]);

        let mut destination = vec![1_u8, 2, 3, 4, 5];
        let plaintext_reversed = vec![5_u8, 4, 3, 2, 1];
        xor_pad(&mut destination, &plaintext_reversed, 5).expect("failed to xor pad");
        assert_eq!(destination, vec![1_u8, 5, 5, 5, 5]);
    }

    #[test]
    fn test_xor_padder_error_cases() {
        let mut destination = vec![1_u8, 2, 3];
        let plaintext_reversed = vec![5_u8, 4, 3, 2, 1];
        assert!(xor_pad(&mut destination, &plaintext_reversed, 5).is_err());

        let mut destination = vec![1_u8, 2, 3, 4];
        let plaintext_reversed = vec![5_u8, 4, 3];
        assert!(xor_pad(&mut destination, &plaintext_reversed, 5).is_err());
    }

    #[test]
    fn cbc_padding_experiments() {
        let iv = [0_u8; BLOCK_SIZE];
        let key = [0_u8; BLOCK_SIZE];
        let data = b"some text to encrypt";
        let encrypted = cbc(data, key, iv);

        let num_of_blocks = encrypted.len() / BLOCK_SIZE;
        let mut plain: Vec<u8> = vec![];

        (0..num_of_blocks).rev().for_each(|block_number| {
            let discovered = if block_number == 0 {
                discover_first_block(key, iv, &encrypted[..BLOCK_SIZE * (block_number + 1)])
            } else {
                discover_block(key, iv, &encrypted[..BLOCK_SIZE * (block_number + 1)])
            };
            plain.extend(discovered);
        });

        plain.reverse();
        assert_eq!(
            String::from_utf8_lossy(data),
            String::from_utf8_lossy(remove_pad(&plain))
        );
    }

    fn discover_block(key: [u8; BLOCK_SIZE], iv: [u8; BLOCK_SIZE], encrypted: &[u8]) -> Vec<u8> {
        let mut plaintext = vec![];
        for pad in 1..=16_u8 {
            // pad value should go the last one as it is mere 0 and always satisfies.
            // we should try non-zero values first
            for b in (0..pad).chain(pad + 1..=255).chain(pad..pad + 1) {
                let mut data = encrypted.to_vec();
                let size = data.len();
                xor_pad(&mut data[..size - BLOCK_SIZE], &plaintext, pad).unwrap();
                data[size - BLOCK_SIZE - pad as usize] ^= pad ^ b;
                if padding_oracle(&data, key, iv) {
                    plaintext.push(b);
                    break;
                }
            }
        }
        plaintext
    }

    fn discover_first_block(
        key: [u8; BLOCK_SIZE],
        iv: [u8; BLOCK_SIZE],
        encrypted: &[u8],
    ) -> Vec<u8> {
        let mut plaintext = vec![];
        for pad in 1..=16_u8 {
            // pad value should go the last one as it is mere 0 and always satisfies.
            // we should try non-zero values first
            for b in (0..pad).chain(pad + 1..=255).chain(pad..pad + 1) {
                let mut tampered_iv = iv;
                xor_pad(&mut tampered_iv, &plaintext, pad).unwrap();
                tampered_iv[BLOCK_SIZE - pad as usize] ^= pad ^ b;
                if padding_oracle(&encrypted, key, tampered_iv) {
                    plaintext.push(b);
                    break;
                }
            }
        }
        plaintext
    }

    #[test]
    fn cbc_padding_attack() {
        let key = random_aes_key();
        let (encrypted, iv) = encrypt(key);

        let num_of_blocks = encrypted.len() / BLOCK_SIZE;
        let encrypted = Arc::new(encrypted);

        let handles: Vec<thread::JoinHandle<Vec<u8>>> = (0..num_of_blocks)
            .rev()
            .map(|block_number| {
                let builder = thread::Builder::new().name(format!("block-{block_number}"));
                let encrypted = Arc::clone(&encrypted);
                if block_number == 0 {
                    builder
                        .spawn(move || {
                            discover_first_block(
                                key,
                                iv,
                                &encrypted[..BLOCK_SIZE * (block_number + 1)],
                            )
                        })
                        .unwrap()
                } else {
                    builder
                        .spawn(move || {
                            discover_block(key, iv, &encrypted[..BLOCK_SIZE * (block_number + 1)])
                        })
                        .unwrap()
                }
            })
            .collect();

        let mut plain: Vec<u8> = handles
            .into_iter()
            .flat_map(|h| h.join().unwrap())
            .collect();
        plain.reverse();
        println!("plain: {:?}", plain);
        let plaintext = String::from_utf8_lossy(remove_pad(&plain));
        println!("plaintext: {plaintext:?}");
        assert!(plaintext.starts_with("0000"));
    }
}
