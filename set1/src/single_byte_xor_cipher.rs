/// https://cryptopals.com/sets/1/challenges/3
use std::collections::btree_map::BTreeMap;
use std::fmt;
use std::fs;
use std::iter::Iterator;
use std::ops::Index;
use std::sync::Once;

const ENGLISH_ALPHABET_SIZE: usize = 27; // including space
static mut FREQUENCIES: EnglishFrequencies = EnglishFrequencies([0_f32; ENGLISH_ALPHABET_SIZE]);
static INIT: Once = Once::new();

fn get_frequencies() -> &'static EnglishFrequencies {
    unsafe {
        INIT.call_once(|| {
            FREQUENCIES = frequencies();
            //println!("{}", FREQUENCIES);
        });
        &FREQUENCIES
    }
}

#[derive(Debug)]
pub struct EnglishCounter([u32; ENGLISH_ALPHABET_SIZE]);

fn get_by_char<T>(array: &[T; ENGLISH_ALPHABET_SIZE], letter: char) -> &T {
    if letter == b' ' as char {
        return &array[ENGLISH_ALPHABET_SIZE - 1];
    }
    &array[(letter.to_ascii_lowercase() as u8 - b'a') as usize]
}

impl EnglishCounter {
    pub fn new() -> Self {
        Self([0_u32; ENGLISH_ALPHABET_SIZE])
    }

    pub fn add(&mut self, letter: u8) {
        if letter == b' ' {
            self.0[ENGLISH_ALPHABET_SIZE - 1] += 1;
            return;
        }
        if !letter.is_ascii_alphabetic() {
            panic!("letter {letter} is not an english character");
        }
        self.0[(letter.to_ascii_lowercase() - b'a') as usize] += 1;
    }

    pub fn frequencies(&self) -> EnglishFrequencies {
        EnglishFrequencies::new(&self)
    }
}

impl Index<char> for EnglishCounter {
    type Output = u32;

    fn index(&self, letter: char) -> &Self::Output {
        if !letter.is_ascii_alphabetic() && letter != (b' ' as char) {
            return &0;
        }
        get_by_char(&self.0, letter)
    }
}

impl fmt::Display for EnglishCounter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0[..ENGLISH_ALPHABET_SIZE - 1]
            .iter()
            .enumerate()
            .for_each(|(i, c)| {
                write!(f, "`{}`: {}, ", (i as u8 + b'a' as u8) as char, c).unwrap();
            });
        write!(f, "` `: {}", self.0[ENGLISH_ALPHABET_SIZE - 1])
    }
}

pub struct EnglishFrequencies([f32; ENGLISH_ALPHABET_SIZE]);

impl EnglishFrequencies {
    pub fn new(counter: &EnglishCounter) -> Self {
        let total: u32 = counter.0.iter().sum();
        let mut frequencies = [0.0; ENGLISH_ALPHABET_SIZE];
        counter
            .0
            .iter()
            .enumerate()
            .for_each(|(i, &n)| frequencies[i] = n as f32 / total as f32);
        Self(frequencies)
    }
}

impl Index<char> for EnglishFrequencies {
    type Output = f32;

    fn index(&self, letter: char) -> &Self::Output {
        if !letter.is_ascii_alphabetic() && letter != b' ' as char {
            return &0.0;
        }
        get_by_char(&self.0, letter)
    }
}

impl fmt::Display for EnglishFrequencies {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0[..ENGLISH_ALPHABET_SIZE - 1]
            .iter()
            .enumerate()
            .for_each(|(i, c)| {
                write!(f, "`{}`: {:.3}, ", (i as u8 + b'a' as u8) as char, c).unwrap();
            });
        write!(f, "` `: {:.3}", self.0[ENGLISH_ALPHABET_SIZE - 1])
    }
}

pub fn frequencies() -> EnglishFrequencies {
    let base_dir = env!("CARGO_MANIFEST_DIR");
    let text =
        fs::read_to_string(format!("{base_dir}/data/english_text.txt")).expect("cannot open text");
    english_characters_counter(text.as_bytes()).frequencies()
}

pub fn english_characters_counter(text: &[u8]) -> EnglishCounter {
    let mut frequencies = EnglishCounter::new();
    text.iter()
        .filter(|c| c.is_ascii_alphabetic() || **c == b' ')
        .map(|c| c.to_ascii_lowercase())
        .for_each(|c| frequencies.add(c));
    frequencies
}

pub fn score_english_text(text: &[u8]) -> f32 {
    let benchmark_frequencies = get_frequencies();
    let text_frequencies = english_characters_counter(text).frequencies();
    -(0_u8..=255).into_iter().fold(0.0, |acc, c| {
        acc + (benchmark_frequencies[c as char] - text_frequencies[c as char]).abs()
    })
}

pub fn apply_single_byte_key<F>(key: u8, data: &mut [u8], application: F)
where
    F: Fn(u8, u8) -> u8,
{
    data.iter_mut().for_each(|d| {
        *d = application(key, *d);
    });
}

pub fn single_byte_xor_decipher_inplace(encrypted: &mut [u8]) -> (f32, u8) {
    let mut score = f32::MIN;
    let mut previous_key = 0_u8;
    let mut key = 0_u8;
    for k in 0..=u8::MAX {
        // We use XOR property of cancelling out effect with the same key
        // to avoid the copying of the encrypted to the buffer
        // at every iteration
        apply_single_byte_key(k, encrypted, |k, b| b ^ previous_key ^ k);

        let text_score = score_english_text(encrypted);
        if text_score > score {
            key = k;
            score = text_score;
        }
        previous_key = k;
    }
    apply_single_byte_key(key, encrypted, |k, b| b ^ previous_key ^ k);
    (score, key)
}

pub fn single_byte_xor_decipher(encrypted: &[u8]) -> String {
    let mut buffer = Vec::from(encrypted);
    single_byte_xor_decipher_inplace(&mut buffer);
    String::from_utf8(buffer).unwrap()
}

pub fn characters_counter(text: &[u8]) -> BTreeMap<char, u32> {
    let text = String::from_utf8(text.to_vec()).expect("text should be utf8 encoded");
    let mut frequencies = BTreeMap::new();
    text.chars()
        .filter(|c| c.is_alphabetic())
        .map(|c| c.to_lowercase())
        .flatten()
        .for_each(|c| {
            *frequencies.entry(c).or_insert(0) += 1;
        });
    frequencies
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::convert_hex_to_base64::hex_str2bytes;

    #[test]
    fn vec_swap() {
        let arr: [u8; 3] = [1, 2, 3];
        let mut v = Vec::from(&arr[..]);
        println!("BEFORE {v:?}");
        apply_single_byte_key(4, &mut v[..], |k, b| k ^ b);
        println!("AFTER {v:?}");
        assert_ne!(Vec::from(arr), v);
        v.clear();
        v.extend_from_slice(&arr[..]);
        assert_eq!(Vec::from(arr), v);
    }

    #[test]
    fn single_byte_xor_cipher() {
        let text =
            hex_str2bytes("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
        assert_eq!(
            "Cooking MC's like a pound of bacon".to_string(),
            single_byte_xor_decipher(&text)
        );
    }

    #[test]
    fn english_char_counter() {
        let counts = english_characters_counter(b"hello word");
        assert_eq!(1_u32, counts['h']);
        assert_eq!(2_u32, counts['l']);
        assert_eq!(2_u32, counts['o']);

        let counts = english_characters_counter(b"heLlo word 123 #");
        assert_eq!(1_u32, counts['h']);
        assert_eq!(2_u32, counts['l']);
        assert_eq!(2_u32, counts['o']);
    }

    #[test]
    fn char_counter() {
        let counts = characters_counter(b"hello word");
        assert_eq!(&1_u32, counts.get(&'h').unwrap());
        assert_eq!(&2_u32, counts.get(&'l').unwrap());
        assert_eq!(&2_u32, counts.get(&'o').unwrap());

        let counts = characters_counter(b"heLlo word 123 #");
        assert_eq!(&1_u32, counts.get(&'h').unwrap());
        assert_eq!(&2_u32, counts.get(&'l').unwrap());
        assert_eq!(&2_u32, counts.get(&'o').unwrap());

        let counts = characters_counter("привЕт мИр 123 #".to_string().as_bytes());
        assert_eq!(&1_u32, counts.get(&'е').unwrap());
        assert_eq!(&2_u32, counts.get(&'и').unwrap());
        assert_eq!(&2_u32, counts.get(&'р').unwrap());
    }
}
