/// https://cryptopals.com/sets/4/challenges/28
use crate::sha1::Sha1;

pub struct Sha1Mac<'a> {
    secret: &'a [u8],
}

impl<'a> Sha1Mac<'a> {
    pub fn new<'b: 'a>(secret: &'b [u8]) -> Self {
        Self { secret }
    }

    pub fn digest(&self, message: &[u8]) -> [u8; 20] {
        let hashed: Vec<u8> = self.secret.iter().chain(message.iter()).cloned().collect();
        let mut hasher = Sha1::new();
        hasher.update(&hashed);
        hasher.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use set2::ecb_cbc_oracle::random_aes_key;

    #[test]
    fn test_sha1_mac() {
        let secret = random_aes_key();
        let mac = Sha1Mac::new(&secret);
        let digest1 = mac.digest(b"hello cryptopals");
        let digest2 = mac.digest(b"hello cryptopaly");
        assert_ne!(digest1, digest2);
        let crafted_secret = random_aes_key();
        let crafted_mac = Sha1Mac::new(&crafted_secret);
        let crafted_digest = crafted_mac.digest(b"hello cryptopals");
        assert_ne!(digest1, crafted_digest);
    }
}
