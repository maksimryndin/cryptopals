/// https://cryptopals.com/sets/3/challenges/24
use crate::mersenne_twister::{MersenneTwister, Output, WORDSIZE};
use std::iter::Iterator;

const CYCLE: u8 = (WORDSIZE / 8) as u8;

pub struct MersenneCipher {
    rng: MersenneTwister,
    index: u8,
    value: Output,
}

impl MersenneCipher {
    pub fn new(seed: u16) -> Self {
        let mut rng = MersenneTwister::new(seed as Output);
        let value = rng.next().unwrap();
        Self {
            rng,
            index: 0,
            value,
        }
    }
}

impl Iterator for MersenneCipher {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index == CYCLE {
            self.value = self.rng.next().unwrap();
            self.index = 0;
        }
        let shift = (CYCLE - self.index - 1) * 8;
        let val = (self.value >> shift) as u8;
        self.index += 1;
        Some(val)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use set2::ecb_cbc_oracle::rand_range;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc::channel;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn mersenne_stream_cipher() {
        let seed = 0u16;
        let mut rng = MersenneTwister::new(seed as Output);
        let value1 = rng.next().unwrap().to_be_bytes();
        let value2 = rng.next().unwrap().to_be_bytes();
        let values: Vec<u8> = value1.into_iter().chain(value2.into_iter()).collect();
        let cipher = MersenneCipher::new(seed);
        let key: Vec<u8> = cipher.take(2 * CYCLE as usize).collect();
        assert_eq!(key, values);
    }

    #[test]
    fn mersenne_break_stream_cipher() {
        let mut buf = [0u8; 2];
        getrandom::getrandom(&mut buf).expect("failed to obtain random data");
        let seed = u16::from_le_bytes(buf);
        let cipher = MersenneCipher::new(seed);
        let rand_prefix_len = rand_range(5, 100);
        let plaintext: Vec<u8> = (0..rand_prefix_len)
            .map(|_| rand_range(b'A', b'Z'))
            .chain([b'A'; 14].into_iter())
            .collect();
        let ciphertext: Vec<u8> = plaintext.iter().zip(cipher).map(|(&p, k)| p ^ k).collect();

        // let mut possible_seed = None;
        // let mut decrypted_buffer = vec![0u8; ciphertext.len()];
        // for s in 0..=u16::MAX {
        //     let cipher = MersenneCipher::new(s);
        //     let decrypted = ciphertext.iter().zip(cipher).map(|(&c, k)| c^k);
        //     decrypted_buffer.extend(decrypted);
        //     if decrypted_buffer.windows(14).find(|&w| w == [b'A'; 14]).is_some() {
        //         possible_seed = Some(s);
        //         break;
        //     }
        //     decrypted_buffer.clear();
        // }
        // assert_eq!(possible_seed, Some(seed));

        let ciphertext_ref = Arc::new(ciphertext);
        let num_threads = thread::available_parallelism().unwrap().get() as usize;
        let step = (u16::MAX as usize + 1) / num_threads;
        let (tx, rx) = channel();
        let found = Arc::new(AtomicBool::new(false));
        (0..num_threads).for_each(|i| {
            let tx = tx.clone();
            let found = found.clone();
            let ciphertext_ref = ciphertext_ref.clone();
            let start = i * step;
            let end = (u16::MAX as usize + 1).min((i + 1) * step);
            thread::spawn(move || {
                let mut decrypted_buffer = vec![0u8; ciphertext_ref.len()];
                for s in start..end {
                    if found.load(Ordering::SeqCst) {
                        return;
                    }
                    let cipher = MersenneCipher::new(s as u16);
                    let decrypted = ciphertext_ref.iter().zip(cipher).map(|(&c, k)| c ^ k);
                    decrypted_buffer.extend(decrypted);
                    if decrypted_buffer
                        .windows(14)
                        .find(|&w| w == [b'A'; 14])
                        .is_some()
                    {
                        tx.send(s as u16).unwrap();
                        found.store(true, Ordering::SeqCst);
                        return;
                    }
                    decrypted_buffer.clear();
                }
            });
        });

        let s = rx.recv().unwrap();
        assert_eq!(s, seed);
    }
}
