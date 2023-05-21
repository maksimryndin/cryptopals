/// https://cryptopals.com/sets/4/challenges/30
/// see also https://en.wikipedia.org/wiki/Length_extension_attack
use std::iter::once;

pub fn md4_padding(message: &[u8]) -> Vec<u8> {
    let bit_len = message.len() * 8;
    let suffix = bit_len.to_le_bytes();
    let required_length = 1 + suffix.len(); // delimiter (0x80) and message lengths in bits
    let available_block_capacity = 64 - message.len() % 64;
    let zeros_quantity = if available_block_capacity < required_length {
        available_block_capacity + 64 - required_length
    } else {
        available_block_capacity - required_length
    };
    message
        .into_iter()
        .copied()
        .chain(once(0x80))
        .chain((0..zeros_quantity).map(|_| 0_u8))
        .chain(suffix.into_iter())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::md4::Md4;
    use std::process::Command;

    const ORIGINAL_MESSAGE: &str =
        "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";

    #[test]
    fn test_md4_length_extension_attack_with_random_secret() {
        let (state, benchmark) = {
            let secret = Command::new("shuf")
                .arg("-n1")
                .arg("/usr/share/dict/words")
                .output()
                .expect("failed to fetch a random word")
                .stdout;
            let mut mac = Md4::new();
            mac.update(&secret);
            mac.update(ORIGINAL_MESSAGE.as_bytes());
            let original_digest = mac.finalize();

            let state: Vec<u32> = original_digest
                .chunks_exact(4)
                .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
                .collect();
            let state: [u32; 4] = state.try_into().unwrap();

            let full: Vec<u8> = secret
                .iter()
                .chain(ORIGINAL_MESSAGE.as_bytes().iter())
                .copied()
                .collect();
            let padded = md4_padding(&full);
            let message: Vec<u8> = padded[secret.len()..]
                .iter()
                .chain(b";admin=true".iter())
                .copied()
                .collect();

            let mut mac = Md4::new();
            mac.update(&secret);
            mac.update(&message);
            let benchmark = mac.finalize();
            (state, benchmark)
        };

        let mut hash = [0_u8; 16];
        let mut block_len = 0;
        while hash != benchmark {
            let mut hasher = Md4::from_state(state, block_len);
            hasher.update(b";admin=true");
            hash = hasher.finalize();
            block_len += 1;
        }

        assert_eq!(hash, benchmark);
    }
}
