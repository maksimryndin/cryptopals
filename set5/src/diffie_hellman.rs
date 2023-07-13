/// https://cryptopals.com/sets/5/challenges/33
/// see also
/// https://en.wikipedia.org/wiki/Exponentiation_by_squaring
use crypto_bigint::{
    const_residue, impl_modulus, modular::constant_mod::ResidueParams, rand_core::OsRng, NonZero,
    RandomMod, U1536,
};

pub const MODULUS: &str = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff";
impl_modulus!(Modulus, U1536, MODULUS);

pub fn generate_private_key() -> U1536 {
    U1536::random_mod(
        &mut OsRng,
        &NonZero::new(U1536::from_be_hex(MODULUS)).unwrap(),
    )
}

pub fn derive_public_key(private_key: U1536) -> U1536 {
    let base = U1536::from(2u8);
    derive_public_key_with_g(private_key, base)
}

pub fn derive_public_key_with_g(private_key: U1536, g: U1536) -> U1536 {
    let base_mod = const_residue!(g, Modulus);
    let res = base_mod.pow(&private_key);
    res.retrieve()
}

pub fn derive_session_key(public_key: U1536, private_key: U1536) -> U1536 {
    let base_mod = const_residue!(public_key, Modulus);
    let res = base_mod.pow(&private_key);
    res.retrieve()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_bigint::{CheckedAdd, CheckedMul};
    use num_bigint::BigUint;
    use set2::ecb_cbc_oracle::rand_range;

    #[test]
    #[allow(non_snake_case)]
    fn small_numbers_dh() {
        let g = 5_u128;
        let p = 7_u128;
        let a = rand_range(0, p as u8) as u32;
        let b = rand_range(0, p as u8) as u32;
        println!("a={a} b={b}");
        let A: u128 = g.pow(a) % p;
        let B: u128 = g.pow(b) % p;
        println!("A={A} B={B}");
        assert_eq!(B.pow(a) % p, A.pow(b) % p);
    }

    #[test]
    fn crypto_lib() {
        let exp = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000077117F1273373C26C700D076B3F780074D03339F56DD0EFB60E7F58441FD3685";
        let exponent = U1536::from_be_hex(exp);
        let pub_key = derive_public_key(exponent);

        let bench_exp = BigUint::parse_bytes(exp.as_bytes(), 16).unwrap();
        let bench_mod = BigUint::parse_bytes(MODULUS.as_bytes(), 16).unwrap();
        let bench_base = BigUint::from(2u8);
        let bench_expected = bench_base.modpow(&bench_exp, &bench_mod);

        let expected = U1536::from_be_hex(&bench_expected.to_str_radix(16));

        assert_eq!(pub_key, expected);
    }

    #[test]
    fn crypto_lib_arithmetic() {
        let a = U1536::from(2u8);
        let b = U1536::from(3u8);
        let c = U1536::from(4u8);
        assert_eq!(
            U1536::from(10u8),
            a.checked_mul(&b).unwrap().checked_add(&c).unwrap()
        );
    }

    #[test]
    fn basic_dh() {
        let private1 = generate_private_key();
        let public1 = derive_public_key(private1);
        let private2 = generate_private_key();
        let public2 = derive_public_key(private2);
        assert_eq!(
            derive_session_key(public1, private2),
            derive_session_key(public2, private1)
        );
    }
}
