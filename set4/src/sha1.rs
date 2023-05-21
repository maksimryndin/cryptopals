/// A little bit extended version of https://github.com/RustCrypto/hashes/blob/master/sha1/src/lib.rs
/// Core SHA-1 hasher state.
pub use digest::{self, Digest};

use core::{fmt, slice::from_ref};
pub use digest::core_api::CoreWrapper;
use digest::{
    block_buffer::Eager,
    core_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, FixedOutputCore,
        OutputSizeUser, Reset, UpdateCore,
    },
    typenum::{Unsigned, U20, U64},
    HashMarker, Output,
};

use sha1::compress;

const STATE_LEN: usize = 5;

/// Core SHA-1 hasher state.
#[derive(Clone)]
pub struct Sha1Core {
    h: [u32; STATE_LEN],
    block_len: u64,
}

impl Sha1Core {
    pub fn from_state(state: [u32; STATE_LEN], block_len: u64) -> Self {
        Self {
            h: state,
            block_len,
        }
    }
}

impl HashMarker for Sha1Core {}

impl BlockSizeUser for Sha1Core {
    type BlockSize = U64;
}

impl BufferKindUser for Sha1Core {
    type BufferKind = Eager;
}

impl OutputSizeUser for Sha1Core {
    type OutputSize = U20;
}

impl UpdateCore for Sha1Core {
    #[inline]
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        self.block_len += blocks.len() as u64;
        compress(&mut self.h, blocks);
    }
}

impl FixedOutputCore for Sha1Core {
    #[inline]
    fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        let bs = Self::BlockSize::U64;
        let bit_len = 8 * (buffer.get_pos() as u64 + bs * self.block_len);

        let mut h = self.h;
        buffer.len64_padding_be(bit_len, |b| compress(&mut h, from_ref(b)));
        for (chunk, v) in out.chunks_exact_mut(4).zip(h.iter()) {
            chunk.copy_from_slice(&v.to_be_bytes());
        }
    }
}

impl Default for Sha1Core {
    #[inline]
    fn default() -> Self {
        Self {
            h: [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0],
            block_len: 0,
        }
    }
}

impl Reset for Sha1Core {
    #[inline]
    fn reset(&mut self) {
        *self = Default::default();
    }
}

impl AlgorithmName for Sha1Core {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Sha1")
    }
}

impl fmt::Debug for Sha1Core {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Sha1Core { ... }")
    }
}

/// SHA-1 hasher state.
pub type Sha1Original = CoreWrapper<Sha1Core>;
pub struct Sha1(CoreWrapper<Sha1Core>);

impl Sha1 {
    pub fn new() -> Self {
        Self(Default::default())
    }

    pub fn from_state(state: [u32; STATE_LEN], block_len: usize) -> Self {
        let core = Sha1Core::from_state(state, block_len as u64);
        Self(CoreWrapper::from_core(core))
    }

    pub fn update(&mut self, msg: &[u8]) {
        self.0.update(msg);
    }

    pub fn finalize(self) -> [u8; 20] {
        self.0.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compare_extended_sha1_with_original() {
        let original_digest: [u8; 20] = Sha1Original::digest(b"yellow submarine").into();
        let mut hasher = Sha1::from_state(
            [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0],
            0,
        );
        hasher.update(b"yellow submarine");
        assert_eq!(original_digest, hasher.finalize());
    }
}
