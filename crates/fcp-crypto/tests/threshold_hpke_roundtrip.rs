//! Threshold HPKE roundtrip conformance (`flywheel_connectors-angoc.11.6.1`).
//!
//! Exercises the four normative properties from
//! `docs/architecture/threshold_hpke_kem.md` against a real 2-of-3 FROST
//! DKG:
//!
//! 1. 2-of-3 encap/decap roundtrip (any 2-element subset of {1,2,3}
//!    recovers the plaintext — the golden fixture's roundtrip property),
//! 2. `t-1` shares fail with `InsufficientShares`,
//! 3. shares from different ciphertexts fail with `InconsistentShares`,
//! 4. share order does not affect the recovered plaintext.

use fcp_crypto::{
    FrostKeyPackage, FrostPublicKeyPackage, ThresholdHpkeError, ThresholdHpkePublicKey,
    combine_decap, decap_share, encap, encap_with_rng,
};
use rand::SeedableRng;

const INFO: &[u8] = b"z:work:ef72e";
const AAD: &[u8] = b"obj_id";
const PLAINTEXT: &[u8] = b"Hello mesh-threshold KEM!";

/// Deterministic 2-of-3 DKG (mirrors threshold_owner_key_e2e's
/// execute_dkg; seeding keeps repeated runs stable).
fn execute_dkg_2_of_3() -> (BTreeMap<u16, FrostKeyPackage>, FrostPublicKeyPackage) {
    let max_signers: u16 = 3;
    let min_signers: u16 = 2;
    let mut round1_secrets = std::collections::BTreeMap::new();
    let mut round1_public = std::collections::BTreeMap::new();
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0x0f6_1ce_5eed);

    for participant in 1..=max_signers {
        let (secret, package) =
            fcp_crypto::dkg_part1_with_rng(participant, max_signers, min_signers, &mut rng)
                .expect("dkg_part1");
        round1_secrets.insert(participant, secret);
        round1_public.insert(participant, package);
    }

    let mut round2_secrets = std::collections::BTreeMap::new();
    let mut inbound_round2: std::collections::BTreeMap<
        u16,
        std::collections::BTreeMap<u16, fcp_crypto::FrostDkgRound2Package>,
    > = (1..=max_signers)
        .map(|p| (p, std::collections::BTreeMap::new()))
        .collect();

    for participant in 1..=max_signers {
        let received = round1_public
            .iter()
            .filter(|(s, _)| **s != participant)
            .map(|(s, p)| (*s, p.clone()))
            .collect::<std::collections::BTreeMap<_, _>>();
        let (secret, outbound) =
            fcp_crypto::dkg_part2(round1_secrets.get(&participant).unwrap(), &received)
                .expect("dkg_part2");
        round2_secrets.insert(participant, secret);
        for (recipient, package) in outbound {
            inbound_round2
                .get_mut(&recipient)
                .unwrap()
                .insert(participant, package);
        }
    }

    let mut key_packages = std::collections::BTreeMap::new();
    let mut public_packages = std::collections::BTreeMap::new();
    for participant in 1..=max_signers {
        let received_round1 = round1_public
            .iter()
            .filter(|(s, _)| **s != participant)
            .map(|(s, p)| (*s, p.clone()))
            .collect::<std::collections::BTreeMap<_, _>>();
        let (key_package, public_package) = fcp_crypto::dkg_part3(
            round2_secrets.get(&participant).unwrap(),
            &received_round1,
            &inbound_round2[&participant],
        )
        .expect("dkg_part3");
        key_packages.insert(participant, key_package);
        public_packages.insert(participant, public_package);
    }

    // All participants must agree on the group public material.
    for (_, package) in public_packages.iter().skip(1) {
        assert_eq!(
            &public_packages[&1], package,
            "DKG participants must agree on the group public key package"
        );
    }

    (key_packages, public_packages[&1].clone())
}

use std::collections::BTreeMap;

#[test]
fn test_2_of_3_encap_decap_roundtrip() {
    let (key_packages, public_package) = execute_dkg_2_of_3();
    let public_key =
        ThresholdHpkePublicKey::from_frost_pkpkg(&public_package).expect("group key derivation");

    let ciphertext = encap(&public_key, INFO, PLAINTEXT, AAD).expect("encap");
    assert_eq!(
        ciphertext.ephemeral_pk.len(),
        32,
        "encapsulated key is 32 bytes"
    );

    // Every 2-element subset of {1, 2, 3} must recover the plaintext
    // (the golden fixture's roundtrip_property).
    for subset in [[1u16, 2u16], [1, 3], [2, 3]] {
        let shares: Vec<fcp_crypto::DecapShare> = subset
            .iter()
            .map(|p| decap_share(&key_packages[p], &ciphertext).expect("decap_share"))
            .collect();
        let recovered = combine_decap(&shares, 2, &ciphertext, INFO, AAD).expect("combine_decap");
        assert_eq!(
            recovered, PLAINTEXT,
            "subset {subset:?} must recover the plaintext"
        );
    }
}

#[test]
fn test_decap_with_only_t_minus_1_shares_fails() {
    let (key_packages, public_package) = execute_dkg_2_of_3();
    let public_key =
        ThresholdHpkePublicKey::from_frost_pkpkg(&public_package).expect("group key derivation");
    let ciphertext = encap(&public_key, INFO, PLAINTEXT, AAD).expect("encap");

    let single = vec![decap_share(&key_packages[&1], &ciphertext).expect("decap_share")];
    let error =
        combine_decap(&single, 2, &ciphertext, INFO, AAD).expect_err("t-1 shares MUST be rejected");
    assert!(
        matches!(
            error,
            fcp_crypto::CryptoError::ThresholdHpke(ThresholdHpkeError::InsufficientShares { .. })
        ),
        "expected InsufficientShares, got {error:?}"
    );

    // Zero shares likewise.
    let error =
        combine_decap(&[], 2, &ciphertext, INFO, AAD).expect_err("empty shares MUST be rejected");
    assert!(matches!(
        error,
        fcp_crypto::CryptoError::ThresholdHpke(ThresholdHpkeError::InsufficientShares { .. })
    ));
}

#[test]
fn test_decap_with_inconsistent_shares_fails() {
    let (key_packages, public_package) = execute_dkg_2_of_3();
    let public_key =
        ThresholdHpkePublicKey::from_frost_pkpkg(&public_package).expect("group key derivation");

    let ct_a = encap(&public_key, INFO, PLAINTEXT, AAD).expect("encap a");
    let ct_b = encap(&public_key, INFO, b"different plaintext", AAD).expect("encap b");

    let good = decap_share(&key_packages[&1], &ct_a).expect("decap_share a");
    let bad = decap_share(&key_packages[&2], &ct_b).expect("decap_share b");

    let error = combine_decap(&[good, bad], 2, &ct_a, INFO, AAD)
        .expect_err("mixed-ciphertext shares MUST be rejected");
    assert!(
        matches!(
            error,
            fcp_crypto::CryptoError::ThresholdHpke(ThresholdHpkeError::InconsistentShares)
        ),
        "expected InconsistentShares, got {error:?}"
    );
}

#[test]
fn test_decap_share_order_does_not_matter() {
    let (key_packages, public_package) = execute_dkg_2_of_3();
    let public_key =
        ThresholdHpkePublicKey::from_frost_pkpkg(&public_package).expect("group key derivation");
    let ciphertext = encap(&public_key, INFO, PLAINTEXT, AAD).expect("encap");

    let share_1 = decap_share(&key_packages[&1], &ciphertext).expect("decap_share 1");
    let share_2 = decap_share(&key_packages[&2], &ciphertext).expect("decap_share 2");

    let forward = combine_decap(
        &[share_1.clone(), share_2.clone()],
        2,
        &ciphertext,
        INFO,
        AAD,
    )
    .expect("forward order");
    let backward =
        combine_decap(&[share_2, share_1], 2, &ciphertext, INFO, AAD).expect("backward order");

    assert_eq!(forward, PLAINTEXT);
    assert_eq!(backward, PLAINTEXT);
    assert_eq!(forward, backward);
}

#[test]
fn deterministic_encap_is_reproducible_with_seeded_rng() {
    let (key_packages, public_package) = execute_dkg_2_of_3();
    let public_key =
        ThresholdHpkePublicKey::from_frost_pkpkg(&public_package).expect("group key derivation");

    let mut rng_a = rand_chacha::ChaCha20Rng::seed_from_u64(42);
    let mut rng_b = rand_chacha::ChaCha20Rng::seed_from_u64(42);
    let ct_a = encap_with_rng(&public_key, INFO, PLAINTEXT, AAD, &mut rng_a).expect("encap a");
    let ct_b = encap_with_rng(&public_key, INFO, PLAINTEXT, AAD, &mut rng_b).expect("encap b");
    assert_eq!(ct_a, ct_b, "same seed MUST reproduce the same ciphertext");
}
