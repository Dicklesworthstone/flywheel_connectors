//! BLAKE3 dispatch helpers.
//!
//! The upstream `blake3` crate owns the low-level SIMD implementation and
//! runtime CPU dispatch. This module keeps the FCP-facing tier selection,
//! operator override, and byte-equivalence contract explicit so future
//! acceleration work can replace an individual tier without changing callers.

use std::{env, error::Error, fmt};

use serde::{Deserialize, Serialize};

use crate::cpuid::HwFeatureSet;

/// BLAKE3 implementation tier selected by FCP dispatch policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Blake3Tier {
    /// Portable reference path.
    Portable,
    /// x86 AVX2-capable path.
    X86Avx2,
    /// x86 AVX-512-capable path.
    X86Avx512,
    /// `AArch64` NEON-capable path.
    Neon,
}

impl Blake3Tier {
    /// Stable string form for logs, docs, and JSON evidence.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Portable => "portable",
            Self::X86Avx2 => "x86_avx2",
            Self::X86Avx512 => "x86_avx512",
            Self::Neon => "neon",
        }
    }

    /// Parse a stable tier name.
    ///
    /// # Errors
    ///
    /// Returns [`Blake3DispatchError::UnknownTier`] when `value` is not one of
    /// the stable operator-facing tier names.
    pub fn parse(value: &str) -> Result<Self, Blake3DispatchError> {
        match value {
            "portable" => Ok(Self::Portable),
            "x86_avx2" | "avx2" => Ok(Self::X86Avx2),
            "x86_avx512" | "avx512" | "avx512f" => Ok(Self::X86Avx512),
            "neon" | "aarch64_neon" => Ok(Self::Neon),
            other => Err(Blake3DispatchError::UnknownTier {
                value: other.to_owned(),
            }),
        }
    }
}

/// Error returned while selecting a BLAKE3 dispatch tier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Blake3DispatchError {
    /// The requested override was not a known stable tier name.
    UnknownTier {
        /// Raw operator-provided tier name.
        value: String,
    },
    /// `FCP_FORCE_BLAKE3_TIER` was present but not valid Unicode.
    InvalidOverrideUnicode,
}

impl fmt::Display for Blake3DispatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownTier { value } => {
                write!(f, "unknown BLAKE3 dispatch tier override: {value}")
            }
            Self::InvalidOverrideUnicode => {
                f.write_str("FCP_FORCE_BLAKE3_TIER is not valid Unicode")
            }
        }
    }
}

impl Error for Blake3DispatchError {}

/// FCP-facing BLAKE3 hasher with an explicit selected tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Blake3Hasher {
    tier: Blake3Tier,
}

impl Blake3Hasher {
    /// Create a hasher from detected hardware features.
    #[must_use]
    pub fn from_features(features: HwFeatureSet) -> Self {
        let tier = select_blake3_tier(features);
        tracing::info!(
            tier_selected = tier.as_str(),
            isa_features = ?features,
            "selected BLAKE3 hardware dispatch tier"
        );
        Self { tier }
    }

    /// Create a hasher from detected features and an optional operator override.
    ///
    /// # Errors
    ///
    /// Returns [`Blake3DispatchError::UnknownTier`] when `override_value`
    /// contains an unsupported tier name.
    pub fn from_features_with_override(
        features: HwFeatureSet,
        override_value: Option<&str>,
    ) -> Result<Self, Blake3DispatchError> {
        let tier = match override_value {
            Some(value) if !value.trim().is_empty() => Blake3Tier::parse(value.trim())?,
            _ => select_blake3_tier(features),
        };
        tracing::info!(
            tier_selected = tier.as_str(),
            isa_features = ?features,
            override_applied = override_value.is_some_and(|v| !v.trim().is_empty()),
            "selected BLAKE3 hardware dispatch tier"
        );
        Ok(Self { tier })
    }

    /// Create a hasher from detected features and `FCP_FORCE_BLAKE3_TIER`.
    ///
    /// # Errors
    ///
    /// Returns [`Blake3DispatchError::UnknownTier`] when the environment value
    /// names an unsupported tier. Returns
    /// [`Blake3DispatchError::InvalidOverrideUnicode`] when the environment
    /// variable is present but not valid Unicode.
    pub fn from_env(features: HwFeatureSet) -> Result<Self, Blake3DispatchError> {
        match env::var("FCP_FORCE_BLAKE3_TIER") {
            Ok(value) => Self::from_features_with_override(features, Some(&value)),
            Err(env::VarError::NotPresent) => Ok(Self::from_features(features)),
            Err(env::VarError::NotUnicode(_)) => Err(Blake3DispatchError::InvalidOverrideUnicode),
        }
    }

    /// Create a hasher for an explicit tier.
    #[must_use]
    pub const fn with_tier(tier: Blake3Tier) -> Self {
        Self { tier }
    }

    /// Return the selected dispatch tier.
    #[must_use]
    pub const fn tier(self) -> Blake3Tier {
        self.tier
    }

    /// Hash bytes through the selected BLAKE3 tier.
    #[must_use]
    pub fn hash(self, input: &[u8]) -> [u8; 32] {
        let _span = tracing::debug_span!(
            "fcp.crypto.blake3.hash",
            tier = self.tier.as_str(),
            input_len = input.len()
        )
        .entered();
        tracing::debug!(
            tier = self.tier.as_str(),
            input_len = input.len(),
            "executing BLAKE3 hash"
        );
        match self.tier {
            Blake3Tier::Portable => hash_portable(input),
            Blake3Tier::X86Avx2 => hash_x86_avx2(input),
            Blake3Tier::X86Avx512 => hash_x86_avx512(input),
            Blake3Tier::Neon => hash_neon(input),
        }
    }

    /// Return every BLAKE3 tier that is safe to exercise for a feature set.
    #[must_use]
    pub fn available_tiers(features: HwFeatureSet) -> Vec<Blake3Tier> {
        let mut tiers = vec![Blake3Tier::Portable];
        if features.has_avx2 {
            tiers.push(Blake3Tier::X86Avx2);
        }
        if features.has_avx512f {
            tiers.push(Blake3Tier::X86Avx512);
        }
        if features.has_aarch64_aes || features.has_aarch64_sha2 || features.has_aarch64_sve {
            tiers.push(Blake3Tier::Neon);
        }
        tiers
    }
}

/// Hash bytes with the runtime-selected BLAKE3 dispatch path.
#[must_use]
pub fn hash_auto(input: &[u8]) -> [u8; 32] {
    hash_with_upstream_runtime(input)
}

/// Hash bytes with the independent `#![forbid(unsafe_code)]` portable scalar BLAKE3 tier.
#[must_use]
pub fn hash_portable(input: &[u8]) -> [u8; 32] {
    scalar_blake3::hash(input)
}

/// Hash bytes with the x86 AVX2 BLAKE3 tier.
#[must_use]
pub fn hash_x86_avx2(input: &[u8]) -> [u8; 32] {
    hash_with_upstream_runtime(input)
}

/// Hash bytes with the x86 AVX-512 BLAKE3 tier.
#[must_use]
pub fn hash_x86_avx512(input: &[u8]) -> [u8; 32] {
    hash_with_upstream_runtime(input)
}

/// Hash bytes with the `AArch64` NEON BLAKE3 tier.
#[must_use]
pub fn hash_neon(input: &[u8]) -> [u8; 32] {
    hash_with_upstream_runtime(input)
}

const fn select_blake3_tier(features: HwFeatureSet) -> Blake3Tier {
    if features.has_avx512f {
        Blake3Tier::X86Avx512
    } else if features.has_avx2 {
        Blake3Tier::X86Avx2
    } else if features.has_aarch64_sve || features.has_aarch64_aes || features.has_aarch64_sha2 {
        Blake3Tier::Neon
    } else {
        Blake3Tier::Portable
    }
}

fn hash_with_upstream_runtime(input: &[u8]) -> [u8; 32] {
    *::blake3::hash(input).as_bytes()
}

/// Pure-Rust `#![forbid(unsafe_code)]` scalar BLAKE3 implementation per the official
/// BLAKE3 specification. Provides a genuinely distinct scalar reference path from the
/// SIMD-accelerated `::blake3` crate so cross-tier parity tests and Criterion benchmarks
/// compare independent implementations.
mod scalar_blake3 {
    const OUT_LEN: usize = 32;
    const BLOCK_LEN: usize = 64;
    const CHUNK_LEN: usize = 1024;

    const CHUNK_START: u32 = 1 << 0;
    const CHUNK_END: u32 = 1 << 1;
    const PARENT: u32 = 1 << 2;
    const ROOT: u32 = 1 << 3;

    const IV: [u32; 8] = [
        0x6A09_E667,
        0xBB67_AE85,
        0x3C6E_F372,
        0xA54F_F53A,
        0x510E_527F,
        0x9B05_688C,
        0x1F83_D9AB,
        0x5BE0_CD19,
    ];

    const MSG_PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

    #[inline]
    fn g(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, mx: u32, my: u32) {
        state[a] = state[a].wrapping_add(state[b]).wrapping_add(mx);
        state[d] = (state[d] ^ state[a]).rotate_right(16);
        state[c] = state[c].wrapping_add(state[d]);
        state[b] = (state[b] ^ state[c]).rotate_right(12);
        state[a] = state[a].wrapping_add(state[b]).wrapping_add(my);
        state[d] = (state[d] ^ state[a]).rotate_right(8);
        state[c] = state[c].wrapping_add(state[d]);
        state[b] = (state[b] ^ state[c]).rotate_right(7);
    }

    #[inline]
    fn round(state: &mut [u32; 16], m: &[u32; 16]) {
        g(state, 0, 4, 8, 12, m[0], m[1]);
        g(state, 1, 5, 9, 13, m[2], m[3]);
        g(state, 2, 6, 10, 14, m[4], m[5]);
        g(state, 3, 7, 11, 15, m[6], m[7]);
        g(state, 0, 5, 10, 15, m[8], m[9]);
        g(state, 1, 6, 11, 12, m[10], m[11]);
        g(state, 2, 7, 8, 13, m[12], m[13]);
        g(state, 3, 4, 9, 14, m[14], m[15]);
    }

    #[inline]
    fn permute(m: &mut [u32; 16]) {
        let mut permuted = [0u32; 16];
        for i in 0..16 {
            permuted[i] = m[MSG_PERMUTATION[i]];
        }
        *m = permuted;
    }

    #[allow(clippy::cast_possible_truncation)]
    fn compress(
        chaining_value: &[u32; 8],
        block_words: &[u32; 16],
        counter: u64,
        block_len: u32,
        flags: u32,
    ) -> [u32; 16] {
        let mut state = [
            chaining_value[0],
            chaining_value[1],
            chaining_value[2],
            chaining_value[3],
            chaining_value[4],
            chaining_value[5],
            chaining_value[6],
            chaining_value[7],
            IV[0],
            IV[1],
            IV[2],
            IV[3],
            counter as u32,
            (counter >> 32) as u32,
            block_len,
            flags,
        ];
        let mut block = *block_words;

        round(&mut state, &block);
        permute(&mut block);
        round(&mut state, &block);
        permute(&mut block);
        round(&mut state, &block);
        permute(&mut block);
        round(&mut state, &block);
        permute(&mut block);
        round(&mut state, &block);
        permute(&mut block);
        round(&mut state, &block);
        permute(&mut block);
        round(&mut state, &block);

        for i in 0..8 {
            state[i] ^= state[i + 8];
            state[i + 8] ^= chaining_value[i];
        }
        state
    }

    fn first_8_words(compression_output: [u32; 16]) -> [u32; 8] {
        let mut out = [0u32; 8];
        out.copy_from_slice(&compression_output[..8]);
        out
    }

    fn words_from_le_bytes_64(bytes: &[u8; BLOCK_LEN]) -> [u32; 16] {
        let mut words = [0u32; 16];
        for (idx, chunk) in bytes.chunks_exact(4).enumerate() {
            words[idx] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        words
    }

    fn words_from_le_bytes_32(bytes: &[u8; OUT_LEN]) -> [u32; 8] {
        let mut words = [0u32; 8];
        for (idx, chunk) in bytes.chunks_exact(4).enumerate() {
            words[idx] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        words
    }

    fn words_to_le_bytes_32(words: &[u32; 8]) -> [u8; OUT_LEN] {
        let mut out = [0u8; OUT_LEN];
        for (idx, &word) in words.iter().enumerate() {
            out[idx * 4..(idx + 1) * 4].copy_from_slice(&word.to_le_bytes());
        }
        out
    }

    #[derive(Clone, Copy)]
    struct Output {
        input_chaining_value: [u32; 8],
        block_words: [u32; 16],
        counter: u64,
        block_len: u32,
        flags: u32,
    }

    impl Output {
        fn chaining_value(&self) -> [u8; OUT_LEN] {
            words_to_le_bytes_32(&first_8_words(compress(
                &self.input_chaining_value,
                &self.block_words,
                self.counter,
                self.block_len,
                self.flags,
            )))
        }

        fn root_output_bytes(&self) -> [u8; OUT_LEN] {
            let words = compress(
                &self.input_chaining_value,
                &self.block_words,
                0,
                self.block_len,
                self.flags | ROOT,
            );
            words_to_le_bytes_32(&first_8_words(words))
        }
    }

    #[derive(Clone)]
    struct ChunkState {
        chaining_value: [u32; 8],
        chunk_counter: u64,
        block: [u8; BLOCK_LEN],
        block_len: u8,
        blocks_compressed: u8,
        flags: u32,
    }

    impl ChunkState {
        const fn new(key_words: [u32; 8], chunk_counter: u64, flags: u32) -> Self {
            Self {
                chaining_value: key_words,
                chunk_counter,
                block: [0; BLOCK_LEN],
                block_len: 0,
                blocks_compressed: 0,
                flags,
            }
        }

        const fn len(&self) -> usize {
            BLOCK_LEN * (self.blocks_compressed as usize) + (self.block_len as usize)
        }

        const fn start_flag(&self) -> u32 {
            if self.blocks_compressed == 0 {
                CHUNK_START
            } else {
                0
            }
        }

        #[allow(clippy::cast_possible_truncation)]
        fn update(&mut self, mut input: &[u8]) {
            while !input.is_empty() {
                if self.block_len as usize == BLOCK_LEN {
                    let block_words = words_from_le_bytes_64(&self.block);
                    self.chaining_value = first_8_words(compress(
                        &self.chaining_value,
                        &block_words,
                        self.chunk_counter,
                        BLOCK_LEN as u32,
                        self.flags | self.start_flag(),
                    ));
                    self.blocks_compressed += 1;
                    self.block = [0; BLOCK_LEN];
                    self.block_len = 0;
                }

                let want = BLOCK_LEN - (self.block_len as usize);
                let take = want.min(input.len());
                self.block[self.block_len as usize..self.block_len as usize + take]
                    .copy_from_slice(&input[..take]);
                self.block_len += take as u8;
                input = &input[take..];
            }
        }

        fn output(&self) -> Output {
            Output {
                input_chaining_value: self.chaining_value,
                block_words: words_from_le_bytes_64(&self.block),
                counter: self.chunk_counter,
                block_len: u32::from(self.block_len),
                flags: self.flags | self.start_flag() | CHUNK_END,
            }
        }
    }

    #[allow(clippy::cast_possible_truncation)]
    fn parent_output(
        left_child_cv: &[u8; OUT_LEN],
        right_child_cv: &[u8; OUT_LEN],
        key_words: &[u32; 8],
        flags: u32,
    ) -> Output {
        let mut block_words = [0u32; 16];
        block_words[..8].copy_from_slice(&words_from_le_bytes_32(left_child_cv));
        block_words[8..].copy_from_slice(&words_from_le_bytes_32(right_child_cv));
        Output {
            input_chaining_value: *key_words,
            block_words,
            counter: 0,
            block_len: BLOCK_LEN as u32,
            flags: PARENT | flags,
        }
    }

    fn parent_cv(
        left_child_cv: &[u8; OUT_LEN],
        right_child_cv: &[u8; OUT_LEN],
        key_words: &[u32; 8],
        flags: u32,
    ) -> [u8; OUT_LEN] {
        parent_output(left_child_cv, right_child_cv, key_words, flags).chaining_value()
    }

    pub(super) fn hash(mut input: &[u8]) -> [u8; OUT_LEN] {
        let mut chunk_state = ChunkState::new(IV, 0, 0);
        let mut cv_stack = [[0u8; OUT_LEN]; 54];
        let mut cv_stack_len = 0usize;

        while !input.is_empty() {
            if chunk_state.len() == CHUNK_LEN {
                let mut new_cv = chunk_state.output().chaining_value();
                let mut total_chunks = chunk_state.chunk_counter + 1;
                while total_chunks & 1 == 0 {
                    cv_stack_len -= 1;
                    new_cv = parent_cv(&cv_stack[cv_stack_len], &new_cv, &IV, 0);
                    total_chunks >>= 1;
                }
                cv_stack[cv_stack_len] = new_cv;
                cv_stack_len += 1;
                chunk_state = ChunkState::new(IV, chunk_state.chunk_counter + 1, 0);
            }

            let want = CHUNK_LEN - chunk_state.len();
            let take = want.min(input.len());
            chunk_state.update(&input[..take]);
            input = &input[take..];
        }

        let mut output = chunk_state.output();
        while cv_stack_len > 0 {
            cv_stack_len -= 1;
            output = parent_output(&cv_stack[cv_stack_len], &output.chaining_value(), &IV, 0);
        }
        output.root_output_bytes()
    }
}
