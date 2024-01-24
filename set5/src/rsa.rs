/// https://cryptopals.com/sets/5/challenges/39
/// See also 
/// CLRS Introduction to Algorithms, Number-Theoretic Algorithms chapter
/// Montgomery arithmetic https://eprint.iacr.org/2017/1057.pdf
/// reference rust RSA implementation https://github.com/RustCrypto/RSA
/// audit for RSA https://delta.chat/assets/1907-otf-deltachat-rpgp-rustrsa-gb-reportv1.pdf
/// Chinese Remainder Theorem (https://kconrad.math.uconn.edu/blurbs/ugradnumthy/crt.pdf)

use crypto_bigint::{NonZero, Integer, Uint, Random, RandomMod, modular::runtime_mod::{DynResidue, DynResidueParams}};
use crypto_bigint::rand_core::{CryptoRngCore, OsRng};
use core::cmp::Ordering;


/// Naive implementation for learning purposes
/// See also https://github.com/RustCrypto/crypto-bigint/pull/279
pub fn is_prime_miller_rabin_vartime<const LIMBS: usize>(n: &Uint<LIMBS>, rng: &mut impl CryptoRngCore, k: usize) -> bool {
    if k == 0 {
        panic!("number of rounds should be greater than 0");
    }

    if n.cmp_vartime(&Uint::ONE) != Ordering::Greater {
        return false;
    }
    // Safe to wrap as we check that `self` is greater than 1 above
    let minus_one = n.wrapping_sub(&Uint::ONE);
    // special case `self` is 2
    if minus_one.cmp_vartime(&Uint::ONE) == Ordering::Equal {
        return true;
    }

    // all even are composite
    if (!n.is_odd()).into() {
        return false;
    }

    // Decompose `self - 1 = d * 2^t` where `d` is odd
    let t = minus_one.trailing_zeros();
    let d = minus_one.shr(t);

    #[inline]
    fn get_random_base<const LIMBS: usize>(
        rng: &mut impl CryptoRngCore,
        upper: &NonZero<Uint<LIMBS>>,
    ) -> Uint<LIMBS> {
        loop {
            let base = Uint::random_mod(rng, upper);
            if base.cmp_vartime(&Uint::ONE) == Ordering::Greater {
                return base;
            }
        }
    }

    #[inline]
    fn mod_pow<const LIMBS: usize>(
        base: &Uint<LIMBS>,
        exponent: &Uint<LIMBS>,
        modulus: &Uint<LIMBS>,
    ) -> Uint<LIMBS> {
        let modulus = DynResidueParams::new(modulus);
        let base = DynResidue::new(base, modulus);
        base.pow(exponent).retrieve()
    }

    // Safe as `self` is greater than 2
    let minus_two = NonZero::new(minus_one.wrapping_sub(&Uint::ONE)).unwrap();
    // Special case 3 as random base is drawn from 2 to `self - 2` interval
    if minus_two.cmp_vartime(&Uint::ONE) == Ordering::Equal {
        return true;
    }
    for _ in 0..k {
        let base = get_random_base(rng, &minus_two);
        let mut x = mod_pow(&base, &d, n);
        let mut y = x;
        for _ in 0..t {
            y = mod_pow(&x, &Uint::from(2u8), n);
            if y.cmp_vartime(&Uint::ONE) == Ordering::Equal
                && x.cmp_vartime(&Uint::ONE) != Ordering::Equal
                && x.cmp_vartime(&minus_one) != Ordering::Equal
            {
                return false;
            }
            x = y;
        }
        if y.cmp_vartime(&Uint::ONE) != Ordering::Equal {
            return false;
        }
    }
    true // probably
}

pub fn generate_random_prime<const LIMBS: usize>() -> Uint<LIMBS> {
    loop {
        let candidate = Uint::random(&mut OsRng);
        let candidate = candidate | Uint::ONE; // make it odd
        if is_prime_miller_rabin_vartime(&candidate, &mut OsRng, 50) {
            return candidate;
        }
    }
}

fn try_cast_to_i64<const LIMBS: usize>(n: &Uint<LIMBS>) -> Result<i64, &str> {
    if LIMBS > 1 && n.as_words()[1] != 0u64 {
        return Err("number is more than 64 bits");
    }
    let r: i64 = n.as_words()[0].try_into().unwrap();
    Ok(r)
}

pub fn extended_gcd<const LIMBS: usize>(m: Uint<LIMBS>, n: Uint<LIMBS>) -> (Uint<LIMBS>, i64, i64) {
    let nonzero = NonZero::new(n);

    if nonzero.is_none().into() {
        return (m, 1, 0);
    }
    let (quotient, rem) = m.div_rem(&nonzero.unwrap());
    let (d, x, y) = extended_gcd(n, rem);
    let quotient = try_cast_to_i64(&quotient).expect("cannot calculate coefficients for egcd");
    (d, y, x - quotient * y)
}

pub fn invmod<const LIMBS: usize>(m: Uint<LIMBS>, n: Uint<LIMBS>) -> i64 {
    let (gcd, inverse, _) = extended_gcd(m, n);
    assert_eq!(gcd, Uint::from(1u8), "modulo {:?} is not relatively prime to {:?}", n, m);
    inverse.rem_euclid(try_cast_to_i64(&n).unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_bigint::{U64, U1024, U2048};
    use crypto_primes::generate_prime;

    #[cfg(feature = "rand_core")]
    #[test]
    fn test_miller_rabin() {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(1);
        assert!(!U64::from(0u8).is_prime_miller_rabin_vartime(&mut rng, 2));
        assert!(!U64::from(1u8).is_prime_miller_rabin_vartime(&mut rng, 2));
        assert!(U64::from(2u8).is_prime_miller_rabin_vartime(&mut rng, 2));
        assert!(U64::from(3u8).is_prime_miller_rabin_vartime(&mut rng, 2));
        assert!(!U64::from(4u8).is_prime_miller_rabin_vartime(&mut rng, 2));
        assert!(U64::from(5u8).is_prime_miller_rabin_vartime(&mut rng, 2));
        assert!(!U64::from(6u8).is_prime_miller_rabin_vartime(&mut rng, 2));
        assert!(U64::from(7u8).is_prime_miller_rabin_vartime(&mut rng, 2));
        assert!(U64::from(89u8).is_prime_miller_rabin_vartime(&mut rng, 2));
        // Carmichael number is composite (see https://en.wikipedia.org/wiki/Carmichael_number)
        assert!(!U64::from(561u16).is_prime_miller_rabin_vartime(&mut rng, 2));
        assert!(!U64::from(9_746_347_772_161u64).is_prime_miller_rabin_vartime(&mut rng, 2));
        // https://en.wikipedia.org/wiki/Largest_known_prime_number
        assert!(U64::from(67_280_421_310_721u64).is_prime_miller_rabin_vartime(&mut rng, 2));
        assert!(!U64::from(67_280_421_310_722u64).is_prime_miller_rabin_vartime(&mut rng, 2));
        assert!(!U64::from(67_280_421_310_723u64).is_prime_miller_rabin_vartime(&mut rng, 2));
    }

    #[cfg(feature = "rand_core")]
    #[test]
    fn test_miller_rabin_many_rounds() {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(1);
        assert!(U64::from(67_280_421_310_721u64).is_prime_miller_rabin_vartime(&mut rng, 50));
    }

    #[cfg(feature = "rand_core")]
    #[should_panic(expected = "number of rounds should be greater than 0")]
    #[test]
    fn test_miller_rabin_incorrect_rounds() {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(1);
        assert!(!U64::from(0u8).is_prime_miller_rabin_vartime(&mut rng, 0));
    }

    #[test]
    fn extended_gcd_check() {
        let m = U1024::from(8u8);
        let n = U1024::from(12u8);
        let (d, x, y) = extended_gcd(m, n);
        assert_eq!(U1024::from(4u8), d);
        assert_eq!(-1, x);
        assert_eq!(1, y);

        let m = U1024::from(21u8);
        let n = U1024::from(14u8);
        let (d, _, _) = extended_gcd(m, n);
        assert_eq!(U1024::from(7u8), d);

        let m = U1024::from(23u8);
        let n = U1024::from(17u8);
        let (d, x, y) = extended_gcd(m, n);
        assert_eq!(U1024::from(1u8), d);
        assert_eq!(3, x);
        assert_eq!(-4, y);
    }

    #[test]
    fn inverse_modulo() {
        let (inverse, _) = U64::from(17u64).inv_mod(&U64::from(3120u64));
        assert_eq!(U64::from(2753u64), inverse);
        assert_eq!(2753, invmod(U64::from(17u64), U64::from(3120u64)));
        assert_eq!(2753, invmod(U64::from(17u64), U64::from(3120u64)));
    }

    #[test]
    fn rsa_flow() {
        let p: U1024 = generate_prime(None); //generate_random_prime();
        let q: U1024 = generate_prime(None); //generate_random_prime();
        println!("prime generation finished:\np={p:?}\nq={q:?}!");
        let n = p.mul(&q);
        let modulus = DynResidueParams::new(&n);
        let p_minus_one = p.wrapping_sub(&Uint::ONE);
        let q_minus_one = q.wrapping_sub(&Uint::ONE);
        let et: U2048 = p_minus_one.mul(&q_minus_one);
        let e = U2048::from(3u8);
        // replace with lib algo to test first
        // then check the lib implementation
        // check crypto-primes repo for gcd
        // read Montogomery and crt
        // check RSA repo
        let d1 = invmod(U2048::from(3u8), et);
        let (d, exists) = e.inv_mod(&et);
        println!("d1 {d1}, d {d}");
        //assert!(Into::<bool>::into(exists), "inverse modulo et for e doesn't exist");
        let msg = U2048::from(42u8);

        // encryption
        let base = DynResidue::new(&msg, modulus);
        let encrypted = base.pow(&e).retrieve();

        // decryption
        let base = DynResidue::new(&encrypted, modulus);
        let decrypted = base.pow(&d).retrieve();
        assert_eq!(decrypted, msg);
    }
}
