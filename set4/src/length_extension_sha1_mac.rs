/// https://cryptopals.com/sets/4/challenges/29
/// see also https://en.wikipedia.org/wiki/Length_extension_attack
use std::iter::once;

pub fn sha1_padding(message: &[u8]) -> Vec<u8> {
    let bit_len = message.len() * 8;
    let suffix = bit_len.to_be_bytes();
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
    use crate::sha1::Sha1;
    use crate::sha1_keyed_mac::Sha1Mac;
    use std::process::Command;

    const ORIGINAL_MESSAGE: &str =
        "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";

    #[test]
    fn test_sha1_padding() {
        let msg = b"a".repeat(55);
        let mut padded = msg.clone();
        padded.push(0x80);
        padded.extend((55_u64 * 8).to_be_bytes());
        assert_eq!(sha1_padding(&msg), padded);

        let msg = b"a".repeat(62);
        let mut padded = msg.clone();
        padded.push(0x80);
        padded.extend([0; 57]);
        padded.extend((62_u64 * 8).to_be_bytes());
        assert_eq!(sha1_padding(&msg), padded);
    }

    #[test]
    fn test_sha1_length_extension_attack_with_known_secret() {
        let secret = b"yellow submarine";
        let mac = Sha1Mac::new(secret);
        let original_digest = mac.digest(b"hello cryptopals");

        let state: Vec<u32> = original_digest
            .chunks_exact(4)
            .map(|c| u32::from_be_bytes(c.try_into().unwrap()))
            .collect();
        let state: [u32; 5] = state.try_into().unwrap();

        let full: Vec<u8> = secret
            .iter()
            .chain(b"hello cryptopals".iter())
            .copied()
            .collect();
        let padded = sha1_padding(&full);

        let mut hasher = Sha1::from_state(state, padded.len() / 64);
        hasher.update(b"new suffix");
        let message: Vec<u8> = padded[secret.len()..]
            .iter()
            .chain(b"new suffix".iter())
            .copied()
            .collect();
        assert_eq!(Sha1Mac::new(secret).digest(&message), hasher.finalize());
    }

    #[test]
    fn test_sha1_length_extension_attack_with_random_secret() {
        let (state, benchmark) = {
            let secret = Command::new("shuf")
                .arg("-n1")
                .arg("/usr/share/dict/words")
                .output()
                .expect("failed to fetch a random word")
                .stdout;
            let mac = Sha1Mac::new(&secret);
            let original_digest = mac.digest(ORIGINAL_MESSAGE.as_bytes());

            let state: Vec<u32> = original_digest
                .chunks_exact(4)
                .map(|c| u32::from_be_bytes(c.try_into().unwrap()))
                .collect();
            let state: [u32; 5] = state.try_into().unwrap();

            let full: Vec<u8> = secret
                .iter()
                .chain(ORIGINAL_MESSAGE.as_bytes().iter())
                .copied()
                .collect();
            let padded = sha1_padding(&full);
            let message: Vec<u8> = padded[secret.len()..]
                .iter()
                .chain(b";admin=true".iter())
                .copied()
                .collect();
            let benchmark = Sha1Mac::new(&secret).digest(&message);
            (state, benchmark)
        };

        let mut hash = [0_u8; 20];
        let mut block_len = 0;
        while hash != benchmark {
            let mut hasher = Sha1::from_state(state, block_len);
            hasher.update(b";admin=true");
            hash = hasher.finalize();
            block_len += 1;
        }

        assert_eq!(hash, benchmark);
    }
}
