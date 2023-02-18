/// https://cryptopals.com/sets/3/challenges/18
use aes::cipher::{
    generic_array::{typenum, GenericArray, GenericArrayIter},
    BlockEncrypt, KeyInit,
};
use aes::Aes128;
use std::iter::Iterator;

pub const BLOCK_SIZE: usize = 16;

pub struct AESKeyStream {
    nonce: u64,
    block_count: u64,
    counter: usize,
    cipher: Aes128,
    block_iterator: GenericArrayIter<u8, typenum::U16>,
}

impl AESKeyStream {
    pub fn new(nonce: u64, block_count: u64, key: [u8; BLOCK_SIZE]) -> Self {
        let key = GenericArray::from(key);
        let cipher = Aes128::new(&key);
        let block_iterator = GenericArray::from([0_u8; BLOCK_SIZE]).into_iter();
        Self {
            nonce,
            block_count,
            counter: 0,
            cipher,
            block_iterator,
        }
    }
}

pub fn transmute_pair_u64(first: u64, second: u64) -> [u8; BLOCK_SIZE] {
    let mut res = [0_u8; BLOCK_SIZE];
    (&mut res[..8]).copy_from_slice(&first.to_le_bytes());
    (&mut res[8..]).copy_from_slice(&second.to_le_bytes());
    res
}

impl Iterator for AESKeyStream {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        if self.counter % BLOCK_SIZE == 0 {
            let b = transmute_pair_u64(self.nonce, self.block_count);
            let mut b = GenericArray::from(b);
            self.cipher.encrypt_block(&mut b);
            self.block_iterator = b.into_iter();
            self.block_count += 1;
        }
        self.counter += 1;
        self.block_iterator.next()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use set1::convert_hex_to_base64::base64decode;

    #[test]
    fn transform_numbers_to_array() {
        let (nonce, block_count) = (1_u64, 2_u64);
        let target: [u8; BLOCK_SIZE] = [
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        assert_eq!(target, transmute_pair_u64(nonce, block_count));
    }

    #[test]
    fn basic_ctr_aes_stream() {
        let encrypted = base64decode(
            "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==".as_bytes(),
        );
        let keystream = AESKeyStream::new(0, 0, *b"YELLOW SUBMARINE");
        let plain: Vec<u8> = encrypted
            .into_iter()
            .zip(keystream)
            .map(|(c, k)| c ^ k)
            .collect();
        let plaintext = String::from_utf8_lossy(&plain);
        println!("{}", plaintext);
        assert_eq!(
            plaintext.into_owned(),
            "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby "
        );
    }
}
