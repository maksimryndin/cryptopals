/// https://cryptopals.com/sets/3/challenges/23
use crate::mersenne_twister::{Output, B, C, D, L, S, T, U, WORDSIZE};

fn untemper(y: Output) -> Output {
    let y = revert_xor_right_shift(y, L, Output::MAX);
    let y = revert_xor_left_shift(y, T, C);
    let y = revert_xor_left_shift(y, S, B);
    revert_xor_right_shift(y, U, D)
}

fn revert_xor_right_shift(result: Output, shift: Output, and: Output) -> Output {
    // when we shift to right, first `shift` bits are 0s so `bit and` with some constant
    // doesn't touch first `shift` bits of the original value
    // let's shift is 5 and wordsize is 32. Then first 5 bits of the result are the same as for original
    // as for shift-and value first 5 bits are zero
    // let's consider bit 6. If the corresponding bit for `and` is 1 then we are xoring
    // 6th bit of the original and 1st bit of the shifted original (which is known already)
    // so to get the 6th bit of the original we need to xor 6th bit of the result
    // and 1st bit of the shifted result
    // if corresponding bit of the `and` is 0 then we just take the bit of the result as an original
    // this way we obtain first 5+5 bits
    // for bit 11 we discovered already 10 bits of the original.
    // so we take bit 11 of the original xoring with bit 6 of the original which results in bit 11
    // of the result. Thus we should xor bit 6 of the original with bit 11 of the result assuming
    // that 11th bit of the mask is 1. otherwise 11th bit of the original is 11th bit of the result.
    // that way we discovered 10 + 10
    // For bit 21st we use already discovered bit 16th and so on up to bit 32.
    // so at every iteration we double the number of discovered bits 5 -> 10 -> 20 -> 40
    // 5 * (1 + 2 + 4 + 8)
    let mut original = result;
    let mut discovered = shift;
    while discovered < WORDSIZE {
        original = result ^ ((original >> shift) & and);
        discovered *= 2;
    }
    result ^ ((original >> shift) & and)
}

fn revert_xor_left_shift(result: Output, shift: Output, and: Output) -> Output {
    // let y = y ^ ((y << S) & B);
    // as we shift left, last `shift` bits are 0s so xoring with original produces
    // the same last `shift` bits in the result
    // let's assume shift is 7. Then last 7 bits are 0s for shifted original anded with a constant
    // so we already know 7 last bits
    // consider 8th bit from the end. if constant has corresponding bit 1 then we are xoring 8th (from the end)
    // original bit with the last original bit in the shifted original
    // thus we can discover bits 8 - 14th from the end.
    // 7 -> 14 -> 28 -> 56
    let mut original = result;
    let mut discovered = shift;
    while discovered < WORDSIZE {
        original = result ^ ((original << shift) & and);
        discovered *= 2;
    }
    result ^ ((original << shift) & and)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mersenne_twister::{temper, MersenneTwister, RECURRENCE_DEGREE};

    #[test]
    fn mersenne_clone_state() {
        let mut buf = [0u8; 4];
        getrandom::getrandom(&mut buf).expect("failed to obtain random data");
        let seed: u32 = u32::from_le_bytes(buf);

        let mut rng = MersenneTwister::new(seed as Output);

        let state: Vec<Output> = rng
            .by_ref()
            .take(RECURRENCE_DEGREE)
            .map(|s| untemper(s))
            .collect();
        let mut cloned_rng = MersenneTwister::from_state(state.try_into().unwrap());
        assert_eq!(rng.next(), cloned_rng.nth(RECURRENCE_DEGREE));
    }

    #[test]
    fn mersenne_revert_xor_right_shift() {
        let y: Output = 45;
        let and: Output = 1 << WORDSIZE - 1;
        let z = y ^ ((y >> L) & and);
        assert_eq!(revert_xor_right_shift(z, L, and), 45);

        let y: Output = 45;
        let z = y ^ ((y >> U) & D);
        assert_eq!(revert_xor_right_shift(z, U, D), 45);

        let y: Output = 21345;
        let and: Output = 0x9D2C5680;
        let z = y ^ ((y >> U) & and);
        assert_eq!(revert_xor_right_shift(z, U, and), 21345);

        let y: Output = 13;
        let and: Output = 3;
        let z = y ^ ((y >> 3) & and);
        assert_eq!(revert_xor_right_shift(z, 3, and), 13);
    }

    #[test]
    fn mersenne_revert_xor_left_shift() {
        let y: Output = 45;
        let and: Output = 1 << WORDSIZE - 1;
        let z = y ^ ((y << L) & and);
        assert_eq!(revert_xor_left_shift(z, L, and), 45);

        let y: Output = 45;
        let z = y ^ ((y << S) & B);
        assert_eq!(revert_xor_left_shift(z, S, B), 45);

        let y: Output = 45;
        let z = y ^ ((y << T) & C);
        assert_eq!(revert_xor_left_shift(z, T, C), 45);

        let y: Output = 13;
        let and: Output = 3;
        let z = y ^ ((y << 3) & and);
        assert_eq!(revert_xor_left_shift(z, 3, and), 13);
    }

    #[test]
    fn mersenne_revert_temper() {
        assert_eq!(45, untemper(temper(45)));
    }
}
