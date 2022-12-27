use set1::break_repeating_key_xor::get_keysizes;
use set1::convert_hex_to_base64::{base64decode, hex_str2bytes};
use set1::detect_single_character_xor::detect_ciphered;
use set1::repeating_key_xor::{repeated_xor_cipher, repeated_xor_decipher};
use set1::single_byte_xor_cipher::score_english_text;

fn main() {
    //let s = "Encrypt a bunch of stuff using your repeating-key XOR function. Encrypt your mail. Encrypt your password file. Your .sig file. Get a feel for it. I promise, we aren't wasting your time with this.";
    //println!("{:02x?}", repeated_xor_cipher(b"ICE", s));
    // let mut encrypted = repeated_xor_cipher(b"ICE", s);
    // println!("{:?}", repeated_xor_decipher(b"ICE", &mut encrypted));
    println!("{:02x?}", b"YELLOW SUBMARINE");
}
