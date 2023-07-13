use crate::diffie_hellman::*;
use crypto_bigint::{const_residue, rand_core::OsRng, Encoding, Random, U1536, U256};
use sha2::{Digest, Sha256};

const SHA256_BLOCK_SIZE: usize = 64;

fn generate_salt() -> U256 {
    U256::random(&mut OsRng)
}

fn pad_key(key: &[u8]) -> [u8; SHA256_BLOCK_SIZE] {
    if key.len() == SHA256_BLOCK_SIZE {
        return key.try_into().unwrap();
    }

    // On all other cases allocate memory
    let mut modified_key = [0_u8; SHA256_BLOCK_SIZE];

    // Keys longer than blockSize are shortened by hashing them
    // Keys shorter than blockSize are padded to blockSize by padding with zeros on the right
    if key.len() > SHA256_BLOCK_SIZE {
        let key_hash = sha256_mac(b"", key);
        modified_key[..key_hash.len()].copy_from_slice(&key_hash);
    } else {
        modified_key[..key.len()].copy_from_slice(key);
    }

    modified_key
}

fn xor_key(mut key: [u8; 64], p: u8) -> [u8; 64] {
    key.iter_mut().for_each(|b| {
        *b = *b ^ p;
    });
    key
}

fn sha256_hmac(key: &[u8], message: &[u8]) -> [u8; 32] {
    let key = pad_key(key);

    let outer_key = xor_key(key, 0x5c);
    let inner_key = xor_key(key, 0x36);
    let inner = sha256_mac(&inner_key, message);
    sha256_mac(&outer_key, &inner)
}

fn sha256_mac(secret: &[u8], message: &[u8]) -> [u8; 32] {
    let data: Vec<u8> = secret
        .into_iter()
        .chain(message.into_iter())
        .copied()
        .collect();
    sha256(&data)
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

fn salt_password(salt: &U256, password: &str) -> U256 {
    let hash = sha256_mac(&salt.to_be_bytes(), password.as_bytes());
    U256::from_be_slice(&hash)
}

pub fn server_create_verifier(password: &str) -> (U256, U1536) {
    let salt = generate_salt();
    let salted = salt_password(&salt, password);
    let salted = convert_u256_to_u1536(&salted);
    let verifier = derive_public_key(salted);
    (salt, verifier)
}

fn convert_u256_to_u1536(n: &U256) -> U1536 {
    let mut arr = [0u8; 192];
    (&mut arr[160..]).copy_from_slice(&n.to_be_bytes());
    U1536::from_be_slice(&arr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_bigint::modular::constant_mod::ResidueParams;

    #[test]
    fn basic_srp_flow() {
        // C & S
        // C & S agree on N=[NIST Prime], g=2, k=3, I (email@email.com), P (my_secret
        let k = U1536::from(3u8);
        let k = const_residue!(k, Modulus);
        let g = U1536::from(2u8);
        let g = const_residue!(g, Modulus);

        // S
        // Generate salt as random integer
        // Generate string xH=SHA256(salt|password)
        // Convert xH to integer x somehow (put 0x on hexdigest)
        // Generate v=g**x % N
        // Save everything but x, xH
        let (server_salt, server_verifier) = server_create_verifier("my_secret");

        // C->S
        // Send I, A=g**a % N (a la Diffie Hellman)
        let client_private_key = generate_private_key();
        let (client_identifier, client_pubkey) =
            ("email@email.com", derive_public_key(client_private_key));

        // S->C
        // Send salt, B=kv + g**b % N
        let server_private_key = generate_private_key();
        let v = const_residue!(server_verifier, Modulus);
        let server_pubkey_like = k.mul(&v).add(&g.pow(&server_private_key)).retrieve();

        // S, C
        // Compute string uH = SHA256(A|B), u = integer of uH
        let uh = sha256_mac(
            &client_pubkey.to_be_bytes(),
            &server_pubkey_like.to_be_bytes(),
        );
        let u = convert_u256_to_u1536(&U256::from_be_bytes(uh));

        // C
        // Generate string xH=SHA256(salt|password)
        // Convert xH to integer x somehow (put 0x on hexdigest)
        let x = salt_password(&server_salt, "my_secret");
        // Generate S = (B - k * g**x)**(a + u * x) % N
        // g**x
        let x_ext = convert_u256_to_u1536(&x);
        let gx = g.pow(&x_ext);
        // B - k * g**x
        let base = const_residue!(server_pubkey_like, Modulus).sub(&k.mul(&gx));
        // a + u * x
        let x_ext = const_residue!(x_ext, Modulus);
        let pow = const_residue!(client_private_key, Modulus)
            .add(&const_residue!(u, Modulus).mul(&x_ext));
        // S
        let sc = base.pow(&pow.retrieve()).retrieve();
        let kc = sha256(&sc.to_be_bytes());

        // S
        // Generate S = (A * v**u) ** b % N
        let ss = const_residue!(client_pubkey, Modulus)
            .mul(&v.pow(&u))
            .pow(&server_private_key)
            .retrieve();
        let ks = sha256(&ss.to_be_bytes());
        assert_eq!(sc, ss);

        // C->S
        // Send HMAC-SHA256(K, salt)
        let client_challenge = sha256_hmac(&kc, &server_salt.to_be_bytes());

        // S->C
        // Send "OK" if HMAC-SHA256(K, salt) validates
        let server_verification = sha256_hmac(&ks, &server_salt.to_be_bytes());
        assert_eq!(client_challenge, server_verification);
    }
}
