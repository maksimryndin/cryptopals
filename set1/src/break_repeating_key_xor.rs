/// https://cryptopals.com/sets/1/challenges/6
use crate::repeating_key_xor::repeated_xor_cipher_inplace;
use crate::single_byte_xor_cipher::{score_english_text, single_byte_xor_decipher_inplace};

const MAX_KEYSIZE: usize = 40;

pub fn vigenere_decipher_keys(encrypted: &[u8]) -> Vec<Vec<u8>> {
    let mut buffer = vec![0_u8; encrypted.len() / 2 + 1];
    let mut keys = Vec::with_capacity(MAX_KEYSIZE - 1);
    for keysize in 2..=MAX_KEYSIZE {
        let mut key = Vec::with_capacity(keysize);
        for offset in 0..keysize {
            let mut block = transpose_by_keysize(encrypted, keysize, offset, &mut buffer);
            let (_, byte_key) = single_byte_xor_decipher_inplace(&mut block);
            key.push(byte_key);
        }
        keys.push(key);
    }
    keys
}

pub fn vigenere_decipher(encrypted: &[u8]) -> (String, String) {
    let mut buffer = Vec::from(encrypted);
    let mut score = f32::MIN;
    let mut best_key = vec![];
    for key in vigenere_decipher_keys(encrypted) {
        repeated_xor_cipher_inplace(&key, &mut buffer);
        let new_score = score_english_text(&buffer);
        if new_score > score {
            score = new_score;
            best_key = key;
        }
        buffer.clear();
        buffer.extend_from_slice(encrypted);
    }
    buffer.clear();
    buffer.extend_from_slice(encrypted);
    repeated_xor_cipher_inplace(&best_key, &mut buffer);
    (
        String::from_utf8(best_key).unwrap(),
        String::from_utf8(buffer).unwrap(),
    )
}

pub fn hamming_distance(first: &[u8], second: &[u8]) -> usize {
    if first.len() != second.len() {
        panic!("bytes buffers should have the same length");
    }
    first
        .iter()
        .zip(second.iter())
        .map(|(&a, &b)| (a ^ b).count_ones() as usize)
        .sum()
}

pub fn score_keysize_bytes(encrypted: &[u8], keysize: usize) -> f64 {
    let dist = encrypted
        .chunks_exact(keysize)
        .zip(encrypted.chunks_exact(keysize).skip(1))
        .fold(0, |score, (prev_block, curr_block)| {
            score + hamming_distance(prev_block, curr_block)
        });
    dist as f64 / keysize as f64
}

pub fn get_keysizes(encrypted: &[u8]) -> Vec<(usize, f64)> {
    let mut result: Vec<(usize, f64)> = (2..=MAX_KEYSIZE)
        .into_iter()
        .map(|keysize| (keysize, score_keysize_bytes(encrypted, keysize)))
        .collect();
    result.sort_by(|a, b| a.1.total_cmp(&b.1));
    result
}

fn transpose_by_keysize<'a>(
    encrypted: &[u8],
    keysize: usize,
    offset: usize,
    buffer: &'a mut [u8],
) -> &'a mut [u8] {
    let n = encrypted
        .iter()
        .skip(offset)
        .step_by(keysize)
        .enumerate()
        .fold(0_usize, |acc, (i, b)| {
            buffer[i] = *b;
            acc + 1
        });
    &mut buffer[..n]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helpers::{filename_fullpath, read_b64_encoded};

    #[test]
    fn vigenere() {
        let file = filename_fullpath("break_repeating_key_xor.txt");
        let decoded = read_b64_encoded(file);
        let (key, text) = vigenere_decipher(&decoded);
        println!("{text}");
        assert_eq!("Terminator X: Bring the noise".to_string(), key);
        println!("key len {}", key.len());
        println!("{:?}", get_keysizes(&decoded));
    }

    #[test]
    fn bit_distance() {
        assert_eq!(37, hamming_distance(b"this is a test", b"wokka wokka!!!"));
    }

    #[test]
    fn transposing() {
        let mut v = vec![0_u8; 10];
        let encrypted: [u8; 5] = [1, 2, 3, 4, 5];
        let block = transpose_by_keysize(&encrypted, 2, 0, &mut v);
        assert_eq!(&[1_u8, 3, 5], block);

        let block = transpose_by_keysize(&encrypted, 2, 1, &mut v);
        assert_eq!(&[2_u8, 4], block);
    }
}
