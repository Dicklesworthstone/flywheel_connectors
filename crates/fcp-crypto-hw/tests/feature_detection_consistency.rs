use fcp_crypto_hw::{
    Blake3DispatchError, Blake3Hasher, Blake3Tier, HwFeatureSet, build_function_table, detect,
};

#[test]
fn test_blake3_available_tiers_include_portable() {
    let tiers = Blake3Hasher::available_tiers(HwFeatureSet::all_false());
    assert_eq!(tiers, vec![Blake3Tier::Portable]);
}

#[test]
fn test_blake3_tier_selection_prefers_strongest_feature() {
    let mut features = HwFeatureSet::all_false();
    features.has_avx2 = true;
    assert_eq!(
        Blake3Hasher::from_features(features).tier(),
        Blake3Tier::X86Avx2
    );

    features.has_avx512f = true;
    assert_eq!(
        Blake3Hasher::from_features(features).tier(),
        Blake3Tier::X86Avx512
    );

    let mut neon = HwFeatureSet::all_false();
    neon.has_aarch64_aes = true;
    neon.has_aarch64_sha2 = true;
    assert_eq!(Blake3Hasher::from_features(neon).tier(), Blake3Tier::Neon);
}

#[test]
fn test_force_portable_tier_overrides_dispatch() {
    let mut features = HwFeatureSet::all_false();
    features.has_avx512f = true;
    features.has_avx2 = true;

    let hasher = Blake3Hasher::from_features_with_override(features, Some("portable"))
        .expect("portable override should be accepted");
    assert_eq!(hasher.tier(), Blake3Tier::Portable);
}

#[test]
fn test_unknown_tier_override_is_rejected() {
    let err = Blake3Hasher::from_features_with_override(
        HwFeatureSet::all_false(),
        Some("quantum_confetti"),
    )
    .unwrap_err();
    assert_eq!(
        err,
        Blake3DispatchError::UnknownTier {
            value: "quantum_confetti".to_owned()
        }
    );
}

#[test]
fn test_blake3_portable_matches_reference_on_test_vectors() {
    assert_tier_matches_reference_on_test_vectors(Blake3Tier::Portable);
}

#[test]
fn test_blake3_x86_avx2_matches_reference_on_test_vectors() {
    assert_tier_matches_reference_on_test_vectors(Blake3Tier::X86Avx2);
}

#[test]
fn test_blake3_x86_avx512_matches_reference_on_test_vectors() {
    assert_tier_matches_reference_on_test_vectors(Blake3Tier::X86Avx512);
}

#[test]
fn test_blake3_neon_matches_reference_on_test_vectors() {
    assert_tier_matches_reference_on_test_vectors(Blake3Tier::Neon);
}

#[test]
fn test_each_declared_blake3_tier_matches_reference_on_test_vectors() {
    for tier in declared_tiers() {
        assert_tier_matches_reference_on_test_vectors(tier);
    }
}

fn assert_tier_matches_reference_on_test_vectors(tier: Blake3Tier) {
    for input in test_vectors() {
        let reference = blake3::hash(&input);
        assert_eq!(
            Blake3Hasher::with_tier(tier).hash(&input),
            *reference.as_bytes(),
            "tier {} diverged for {} bytes",
            tier.as_str(),
            input.len()
        );
    }
}

#[test]
fn test_available_runner_tiers_match_reference_on_test_vectors() {
    let features = detect();
    let tiers = Blake3Hasher::available_tiers(features);
    assert!(
        tiers.contains(&Blake3Tier::Portable),
        "portable tier is always available"
    );

    for input in test_vectors() {
        let reference = blake3::hash(&input);
        for tier in &tiers {
            assert_eq!(
                Blake3Hasher::with_tier(*tier).hash(&input),
                *reference.as_bytes()
            );
        }
    }
}

#[test]
fn test_all_tiers_produce_identical_output() {
    for seed in 0_u64..1000 {
        let input = deterministic_bytes(seed, usize::try_from(seed % 4097).unwrap());
        let mut outputs = declared_tiers()
            .into_iter()
            .map(|tier| (tier, Blake3Hasher::with_tier(tier).hash(&input)));
        let (reference_tier, reference) = outputs.next().expect("declared tiers are non-empty");
        for (tier, output) in outputs {
            assert_eq!(
                output,
                reference,
                "{} diverged from {} for seed {seed}",
                tier.as_str(),
                reference_tier.as_str()
            );
        }
    }
}

#[test]
fn test_all_declared_tiers_produce_identical_output_for_generated_inputs() {
    test_all_tiers_produce_identical_output();
}

#[test]
fn test_function_table_blake3_matches_hasher_tier_selection() {
    let mut features = HwFeatureSet::all_false();
    features.has_avx2 = true;
    let table = build_function_table(features);
    assert_eq!(
        (table.blake3)(b"function-table"),
        Blake3Hasher::from_features(features).hash(b"function-table")
    );
}

fn declared_tiers() -> Vec<Blake3Tier> {
    vec![
        Blake3Tier::Portable,
        Blake3Tier::X86Avx2,
        Blake3Tier::X86Avx512,
        Blake3Tier::Neon,
    ]
}

fn test_vectors() -> Vec<Vec<u8>> {
    vec![
        Vec::new(),
        vec![0x42; 64],
        deterministic_bytes(0x1, 4096),
        deterministic_bytes(0x2, 65_536),
        deterministic_bytes(0x3, 1_048_576),
        deterministic_bytes(0xa11ce, 17),
        deterministic_bytes(0xb0b, 3333),
        deterministic_bytes(0xcafe, 98_765),
    ]
}

fn deterministic_bytes(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed ^ 0x9e37_79b9_7f4a_7c15;
    let mut bytes = Vec::with_capacity(len);
    while bytes.len() < len {
        state ^= state << 7;
        state ^= state >> 9;
        state = state.wrapping_mul(0xa24b_aed4_963e_e407);
        bytes.extend_from_slice(&state.to_le_bytes());
    }
    bytes.truncate(len);
    bytes
}
