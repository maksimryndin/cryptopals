/// https://github.com/RustCrypto/hashes/blob/master/md4/src/lib.rs
pub use digest::{self, Digest};

use core::{convert::TryInto, fmt};
use digest::{
    block_buffer::Eager,
    core_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, CoreWrapper, FixedOutputCore,
        OutputSizeUser, Reset, UpdateCore,
    },
    typenum::{Unsigned, U16, U64},
    HashMarker, Output,
};

#[derive(Clone)]
pub struct Md4Core {
    block_len: u64,
    state: [u32; 4],
}

impl Md4Core {
    pub fn from_state(state: [u32; 4], block_len: u64) -> Self {
        Self { state, block_len }
    }
}

impl HashMarker for Md4Core {}

impl BlockSizeUser for Md4Core {
    type BlockSize = U64;
}

impl BufferKindUser for Md4Core {
    type BufferKind = Eager;
}

impl OutputSizeUser for Md4Core {
    type OutputSize = U16;
}

impl UpdateCore for Md4Core {
    #[inline]
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        self.block_len = self.block_len.wrapping_add(blocks.len() as u64);
        for block in blocks {
            compress(&mut self.state, block);
        }
    }
}

impl FixedOutputCore for Md4Core {
    #[inline]
    fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        let bit_len = self
            .block_len
            .wrapping_mul(Self::BlockSize::U64)
            .wrapping_add(buffer.get_pos() as u64)
            .wrapping_mul(8);
        let mut state = self.state;
        buffer.len64_padding_le(bit_len, |block| compress(&mut state, block));

        for (chunk, v) in out.chunks_exact_mut(4).zip(state.iter()) {
            chunk.copy_from_slice(&v.to_le_bytes());
        }
    }
}

impl Default for Md4Core {
    #[inline]
    fn default() -> Self {
        let state = [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476];
        Self {
            state,
            block_len: 0,
        }
    }
}

impl Reset for Md4Core {
    #[inline]
    fn reset(&mut self) {
        *self = Default::default();
    }
}

impl AlgorithmName for Md4Core {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Md4")
    }
}

impl fmt::Debug for Md4Core {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Md4Core { ... }")
    }
}

/// MD4 hasher state.
pub type Md4Original = CoreWrapper<Md4Core>;
pub struct Md4(CoreWrapper<Md4Core>);

impl Md4 {
    pub fn new() -> Self {
        Self(Default::default())
    }

    pub fn from_state(state: [u32; 4], block_len: usize) -> Self {
        let core = Md4Core::from_state(state, block_len as u64);
        Self(CoreWrapper::from_core(core))
    }

    pub fn update(&mut self, msg: &[u8]) {
        self.0.update(msg);
    }

    pub fn finalize(self) -> [u8; 16] {
        self.0.finalize().into()
    }
}

fn compress(state: &mut [u32; 4], input: &Block<Md4Core>) {
    fn f(x: u32, y: u32, z: u32) -> u32 {
        (x & y) | (!x & z)
    }

    fn g(x: u32, y: u32, z: u32) -> u32 {
        (x & y) | (x & z) | (y & z)
    }

    fn h(x: u32, y: u32, z: u32) -> u32 {
        x ^ y ^ z
    }

    fn op1(a: u32, b: u32, c: u32, d: u32, k: u32, s: u32) -> u32 {
        a.wrapping_add(f(b, c, d)).wrapping_add(k).rotate_left(s)
    }

    fn op2(a: u32, b: u32, c: u32, d: u32, k: u32, s: u32) -> u32 {
        a.wrapping_add(g(b, c, d))
            .wrapping_add(k)
            .wrapping_add(0x5A82_7999)
            .rotate_left(s)
    }

    fn op3(a: u32, b: u32, c: u32, d: u32, k: u32, s: u32) -> u32 {
        a.wrapping_add(h(b, c, d))
            .wrapping_add(k)
            .wrapping_add(0x6ED9_EBA1)
            .rotate_left(s)
    }

    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];

    // load block to data
    let mut data = [0u32; 16];
    for (o, chunk) in data.iter_mut().zip(input.chunks_exact(4)) {
        *o = u32::from_le_bytes(chunk.try_into().unwrap());
    }

    // round 1
    for &i in &[0, 4, 8, 12] {
        a = op1(a, b, c, d, data[i], 3);
        d = op1(d, a, b, c, data[i + 1], 7);
        c = op1(c, d, a, b, data[i + 2], 11);
        b = op1(b, c, d, a, data[i + 3], 19);
    }

    // round 2
    for i in 0..4 {
        a = op2(a, b, c, d, data[i], 3);
        d = op2(d, a, b, c, data[i + 4], 5);
        c = op2(c, d, a, b, data[i + 8], 9);
        b = op2(b, c, d, a, data[i + 12], 13);
    }

    // round 3
    for &i in &[0, 2, 1, 3] {
        a = op3(a, b, c, d, data[i], 3);
        d = op3(d, a, b, c, data[i + 8], 9);
        c = op3(c, d, a, b, data[i + 4], 11);
        b = op3(b, c, d, a, data[i + 12], 15);
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compare_extended_md4_with_original() {
        let original_digest: [u8; 16] = Md4Original::digest(b"yellow submarine").into();
        let mut hasher = Md4::from_state([0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476], 0);
        hasher.update(b"yellow submarine");
        assert_eq!(original_digest, hasher.finalize());
    }
}
