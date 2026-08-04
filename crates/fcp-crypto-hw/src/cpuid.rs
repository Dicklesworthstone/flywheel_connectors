//! Runtime hardware feature detection for crypto dispatch.

use serde::{Deserialize, Serialize};
use tracing::info;

/// Hardware features relevant to FCP cryptographic dispatch.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct HwFeatureSet {
    /// x86 AVX2 vector support.
    pub has_avx2: bool,
    /// x86 SSE3 vector support.
    pub has_sse3: bool,
    /// x86 AVX-512 foundation support.
    pub has_avx512f: bool,
    /// x86 AVX-512 plus VAES support.
    pub has_avx512_vaes: bool,
    /// x86 AES-NI support.
    pub has_aes_ni: bool,
    /// x86 carry-less multiply support.
    pub has_clmul: bool,
    /// `AArch64` AES instruction support.
    pub has_aarch64_aes: bool,
    /// `AArch64` SHA-2 instruction support.
    pub has_aarch64_sha2: bool,
    /// `AArch64` SVE support.
    pub has_aarch64_sve: bool,
    /// Apple platform with Secure Enclave availability expected.
    pub has_apple_secure_enclave: bool,
}

impl HwFeatureSet {
    /// Return a feature set with every bit disabled.
    #[must_use]
    pub const fn all_false() -> Self {
        Self {
            has_avx2: false,
            has_sse3: false,
            has_avx512f: false,
            has_avx512_vaes: false,
            has_aes_ni: false,
            has_clmul: false,
            has_aarch64_aes: false,
            has_aarch64_sha2: false,
            has_aarch64_sve: false,
            has_apple_secure_enclave: false,
        }
    }

    /// Return stable string names for every detected feature.
    #[must_use]
    pub fn detected_feature_names(&self) -> Vec<&'static str> {
        let mut names = Vec::new();
        push_if(&mut names, self.has_avx2, "avx2");
        push_if(&mut names, self.has_sse3, "sse3");
        push_if(&mut names, self.has_avx512f, "avx512f");
        push_if(&mut names, self.has_avx512_vaes, "avx512_vaes");
        push_if(&mut names, self.has_aes_ni, "aes_ni");
        push_if(&mut names, self.has_clmul, "clmul");
        push_if(&mut names, self.has_aarch64_aes, "aarch64_aes");
        push_if(&mut names, self.has_aarch64_sha2, "aarch64_sha2");
        push_if(&mut names, self.has_aarch64_sve, "aarch64_sve");
        push_if(
            &mut names,
            self.has_apple_secure_enclave,
            "apple_secure_enclave",
        );
        names
    }
}

/// Detect hardware features for the current process and emit the startup log.
#[must_use]
pub fn detect() -> HwFeatureSet {
    let features = detect_without_logging();
    let features_detected = features.detected_feature_names();
    info!(
        target: "fcp_crypto_hw",
        arch = std::env::consts::ARCH,
        ?features_detected,
        "crypto hardware feature detection complete"
    );
    features
}

fn push_if(names: &mut Vec<&'static str>, enabled: bool, name: &'static str) {
    if enabled {
        names.push(name);
    }
}

// Only const-eligible on targets where every arch-specific detector compiles
// to an empty stub; the x86 path uses runtime CPUID feature detection.
#[allow(clippy::missing_const_for_fn)]
fn detect_without_logging() -> HwFeatureSet {
    let mut features = HwFeatureSet::all_false();
    detect_x86(&mut features);
    detect_aarch64(&mut features);
    detect_macos_secure_enclave(&mut features);
    features
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn detect_x86(features: &mut HwFeatureSet) {
    features.has_avx2 = std::arch::is_x86_feature_detected!("avx2");
    features.has_sse3 = std::arch::is_x86_feature_detected!("sse3");
    features.has_avx512f = std::arch::is_x86_feature_detected!("avx512f");
    features.has_aes_ni = std::arch::is_x86_feature_detected!("aes");
    features.has_clmul = std::arch::is_x86_feature_detected!("pclmulqdq");
    features.has_avx512_vaes = features.has_avx512f && std::arch::is_x86_feature_detected!("vaes");
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
const fn detect_x86(_features: &mut HwFeatureSet) {}

#[cfg(all(
    target_arch = "aarch64",
    any(target_os = "linux", target_os = "android")
))]
fn detect_aarch64(features: &mut HwFeatureSet) {
    features.has_aarch64_aes = std::arch::is_aarch64_feature_detected!("aes");
    features.has_aarch64_sha2 = std::arch::is_aarch64_feature_detected!("sha2");
    features.has_aarch64_sve = std::arch::is_aarch64_feature_detected!("sve");
}

#[cfg(all(
    target_arch = "aarch64",
    not(any(target_os = "linux", target_os = "android"))
))]
const fn detect_aarch64(features: &mut HwFeatureSet) {
    features.has_aarch64_aes = cfg!(target_feature = "aes") || cfg!(target_vendor = "apple");
    features.has_aarch64_sha2 = cfg!(target_feature = "sha2") || cfg!(target_vendor = "apple");
    features.has_aarch64_sve = cfg!(target_feature = "sve");
}

#[cfg(not(target_arch = "aarch64"))]
const fn detect_aarch64(_features: &mut HwFeatureSet) {}

#[cfg(all(target_os = "macos", target_vendor = "apple"))]
const fn detect_macos_secure_enclave(features: &mut HwFeatureSet) {
    features.has_apple_secure_enclave = cfg!(target_arch = "aarch64");
}

#[cfg(not(all(target_os = "macos", target_vendor = "apple")))]
const fn detect_macos_secure_enclave(_features: &mut HwFeatureSet) {}
