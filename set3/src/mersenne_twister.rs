/// https://cryptopals.com/sets/3/challenges/21
use std::iter::Iterator;

#[cfg(feature = "mersenne64")]
pub(crate) const RECURRENCE_DEGREE: usize = 312; // n
#[cfg(not(feature = "mersenne64"))]
pub(crate) const RECURRENCE_DEGREE: usize = 624; // n

#[cfg(feature = "mersenne64")]
pub(crate) type Output = u64;
#[cfg(not(feature = "mersenne64"))]
pub(crate) type Output = u32;

#[cfg(feature = "mersenne64")]
pub(crate) const WORDSIZE: u32 = 64; // w
#[cfg(not(feature = "mersenne64"))]
pub(crate) const WORDSIZE: u32 = 32;

#[cfg(feature = "mersenne64")]
pub(crate) const INITIALIZATION_VALUE: u64 = 6364136223846793005;
#[cfg(not(feature = "mersenne64"))]
pub(crate) const INITIALIZATION_VALUE: u32 = 1812433253;

pub(crate) const LOWER_MASK: u32 = (1_u32 << 31) - 1;
pub(crate) const UPPER_MASK: u32 = !LOWER_MASK;

#[cfg(feature = "mersenne64")]
pub(crate) const U: u64 = 29;
#[cfg(not(feature = "mersenne64"))]
pub(crate) const U: u32 = 11;

#[cfg(feature = "mersenne64")]
pub(crate) const D: u64 = 0x5555_5555_5555_5555;
#[cfg(not(feature = "mersenne64"))]
pub(crate) const D: u32 = 0xFFFFFFFF;

#[cfg(feature = "mersenne64")]
pub(crate) const S: u64 = 17;
#[cfg(not(feature = "mersenne64"))]
pub(crate) const S: u32 = 7;

#[cfg(feature = "mersenne64")]
pub(crate) const B: u64 = 0x71D67FFFEDA60000;
#[cfg(not(feature = "mersenne64"))]
pub(crate) const B: u32 = 0x9D2C5680;

#[cfg(feature = "mersenne64")]
pub(crate) const T: u64 = 37;
#[cfg(not(feature = "mersenne64"))]
pub(crate) const T: u32 = 15;

#[cfg(feature = "mersenne64")]
pub(crate) const C: u64 = 0xFFF7EEE_000_000_000;
#[cfg(not(feature = "mersenne64"))]
pub(crate) const C: u32 = 0xEFC60000;

#[cfg(feature = "mersenne64")]
pub(crate) const L: u64 = 43;
#[cfg(not(feature = "mersenne64"))]
pub(crate) const L: u32 = 18;

#[cfg(feature = "mersenne64")]
pub(crate) const A: u64 = 0xB5026F5AA96619E9;
#[cfg(not(feature = "mersenne64"))]
pub(crate) const A: u32 = 0x9908B0DF;

#[cfg(feature = "mersenne64")]
pub(crate) const M: usize = 156;
#[cfg(not(feature = "mersenne64"))]
pub(crate) const M: usize = 397;

pub struct MersenneTwister {
    state: [Output; RECURRENCE_DEGREE],
    index: usize,
}

pub fn temper(y: Output) -> Output {
    let y = y ^ ((y >> U) & D);
    let y = y ^ ((y << S) & B);
    let y = y ^ ((y << T) & C);
    y ^ (y >> L)
}

// https://en.wikipedia.org/wiki/Mersenne_Twister
impl MersenneTwister {
    pub fn new(seed: Output) -> Self {
        let mut state = [0; RECURRENCE_DEGREE];
        state[0] = seed;
        for i in 1..RECURRENCE_DEGREE {
            state[i] = INITIALIZATION_VALUE
                .wrapping_mul(state[i - 1] ^ (state[i - 1] >> (WORDSIZE - 2)))
                .wrapping_add(i as Output);
        }
        Self {
            state,
            index: RECURRENCE_DEGREE,
        }
    }

    pub fn from_state(state: [Output; RECURRENCE_DEGREE]) -> Self {
        Self { state, index: 0 }
    }

    fn extract_number(&mut self) -> Output {
        if self.index >= RECURRENCE_DEGREE {
            self.twist()
        }
        let y = self.state[self.index];
        self.index += 1;
        temper(y)
    }

    fn twist(&mut self) {
        for i in 0..RECURRENCE_DEGREE {
            let x = (self.state[i] & UPPER_MASK as Output)
                | (self.state[(i + 1) % RECURRENCE_DEGREE] & LOWER_MASK as Output);

            let mut xa = x >> 1;
            if (x % 2) != 0 {
                xa ^= A;
            }
            self.state[i] = self.state[(i + M) % RECURRENCE_DEGREE] ^ xa;
        }
        self.index = 0;
    }
}

impl Iterator for MersenneTwister {
    type Item = Output;

    fn next(&mut self) -> Option<Self::Item> {
        Some(self.extract_number())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // test against reference C-implementation
    // http://www.math.sci.hiroshima-u.ac.jp/m-mat/MT/MT2002/CODES/mt19937ar.c
    #[test]
    fn mersenne_reference_target() {
        let mut rng = MersenneTwister::new(5489);
        assert_eq!(Some(2500741117), rng.nth(1000));
    }

    #[test]
    fn mersenne_same_seed_same_output() {
        let mut rng1 = MersenneTwister::new(85747892);
        let mut rng2 = MersenneTwister::new(85747892);
        assert_eq!(rng1.nth(1000), rng2.nth(1000));
    }
}
