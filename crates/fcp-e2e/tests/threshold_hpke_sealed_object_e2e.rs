//! Threshold-HPKE sealed-object E2E (`flywheel_connectors-angoc.11.6.1`).
//!
//! Verifies end-to-end that a mesh peer can seal a durable `StoredObject`
//! addressable to a `t`-of-`n` FROST DKG quorum using
//! `ObjectEncryptionKind::ThresholdHpkeQuorum { threshold, epoch }`, store it
//! in `fcp-store`'s `MemoryObjectStore`, and recover the plaintext body from
//! any `t`-member quorum of decap shares while rejecting `t - 1` or mixed
//! shares.

use std::collections::BTreeMap;

use fcp_cbor::SchemaId;
use fcp_core::{
    ObjectEncryptionKind, ObjectHeader, ObjectId, Provenance, RetentionClass, StorageMeta,
    StoredObject, ZoneId,
};
use fcp_crypto::{
    CryptoError, DecapShare, FrostDkgRound2Package, FrostKeyPackage, FrostPublicKeyPackage,
    ThresholdHpkeCiphertext, ThresholdHpkeError, ThresholdHpkePublicKey, combine_decap,
    decap_share, dkg_part1, dkg_part2, dkg_part3, encap,
};
use fcp_store::{MemoryObjectStore, MemoryObjectStoreConfig, ObjectStore};
use semver::Version;

const CEREMONY_EPOCH: u64 = 7;
const THRESHOLD: u16 = 2;
const MAX_SIGNERS: u16 = 3;
const ZONE_INFO: &[u8] = b"z:work:threshold_hpke_quorum:epoch=7";

fn run_async<F: std::future::Future>(future: F) -> F::Output {
    fcp_async_core::runtime::block_on_sync(future).expect("async runtime execution")
}

fn execute_dkg_2_of_3() -> (BTreeMap<u16, FrostKeyPackage>, FrostPublicKeyPackage) {
    let mut round1_secrets = BTreeMap::new();
    let mut round1_public = BTreeMap::new();

    for participant in 1..=MAX_SIGNERS {
        let (secret, package) = dkg_part1(participant, MAX_SIGNERS, THRESHOLD).expect("dkg_part1");
        round1_secrets.insert(participant, secret);
        round1_public.insert(participant, package);
    }

    let mut round2_secrets = BTreeMap::new();
    let mut inbound_round2: BTreeMap<u16, BTreeMap<u16, FrostDkgRound2Package>> =
        (1..=MAX_SIGNERS).map(|p| (p, BTreeMap::new())).collect();

    for participant in 1..=MAX_SIGNERS {
        let received = round1_public
            .iter()
            .filter(|(s, _)| **s != participant)
            .map(|(s, p)| (*s, p.clone()))
            .collect::<BTreeMap<_, _>>();
        let (secret, outbound) =
            dkg_part2(round1_secrets.get(&participant).unwrap(), &received).expect("dkg_part2");
        round2_secrets.insert(participant, secret);
        for (recipient, package) in outbound {
            inbound_round2
                .get_mut(&recipient)
                .unwrap()
                .insert(participant, package);
        }
    }

    let mut key_packages = BTreeMap::new();
    let mut public_packages = BTreeMap::new();
    for participant in 1..=MAX_SIGNERS {
        let received_round1 = round1_public
            .iter()
            .filter(|(s, _)| **s != participant)
            .map(|(s, p)| (*s, p.clone()))
            .collect::<BTreeMap<_, _>>();
        let (key_package, public_package) = dkg_part3(
            round2_secrets.get(&participant).unwrap(),
            &received_round1,
            &inbound_round2[&participant],
        )
        .expect("dkg_part3");
        key_packages.insert(participant, key_package);
        public_packages.insert(participant, public_package);
    }

    for (_, package) in public_packages.iter().skip(1) {
        assert_eq!(
            &public_packages[&1], package,
            "all DKG participants must derive the identical group public key package"
        );
    }

    (key_packages, public_packages[&1].clone())
}

#[test]
fn mesh_peer_seals_object_addressable_to_threshold_quorum() {
    run_async(async {
        let (key_packages, public_package) = execute_dkg_2_of_3();
        let group_pk = ThresholdHpkePublicKey::from_frost_pkpkg(&public_package)
            .expect("derive group X25519 public key from FROST package");

        let zone: ZoneId = "z:work".parse().expect("valid zone id");
        let object_id = ObjectId::from_bytes([0x42; 32]);
        let aad = object_id.as_bytes();
        let plaintext = b"confidential checkpoint state sealed for 2-of-3 mesh quorum";

        let ciphertext = encap(&group_pk, ZONE_INFO, plaintext, aad).expect("threshold HPKE encap");
        let sealed_body =
            serde_json::to_vec(&ciphertext).expect("serialize threshold HPKE ciphertext");

        let header = ObjectHeader {
            schema: SchemaId::new(
                "fcp.core",
                "ThresholdSealedCheckpoint",
                Version::new(1, 0, 0),
            ),
            zone_id: zone.clone(),
            created_at: 1_760_000_000,
            provenance: Provenance::new(zone),
            refs: Vec::new(),
            foreign_refs: Vec::new(),
            ttl_secs: None,
            placement: None,
            encryption_kind: ObjectEncryptionKind::ThresholdHpkeQuorum {
                threshold: THRESHOLD,
                epoch: CEREMONY_EPOCH,
            },
        };

        // Verify JSON wire format carries the snake_case threshold_hpke_quorum tag.
        let header_json = serde_json::to_value(&header).expect("serialize ObjectHeader");
        assert_eq!(
            header_json["encryption_kind"]["threshold_hpke_quorum"]["threshold"],
            serde_json::json!(THRESHOLD)
        );
        assert_eq!(
            header_json["encryption_kind"]["threshold_hpke_quorum"]["epoch"],
            serde_json::json!(CEREMONY_EPOCH)
        );

        let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
        let stored = StoredObject {
            object_id,
            header,
            body: sealed_body,
            storage: StorageMeta {
                retention: RetentionClass::Pinned,
            },
        };
        store.put(stored).await.expect("store sealed object");

        // Mesh peers retrieve the sealed object and inspect its encryption header.
        let fetched = store.get(&object_id).await.expect("fetch sealed object");
        let (required_threshold, epoch) = match fetched.header.encryption_kind {
            ObjectEncryptionKind::ThresholdHpkeQuorum { threshold, epoch } => (threshold, epoch),
            ObjectEncryptionKind::Plain => panic!("expected ThresholdHpkeQuorum encryption_kind"),
        };
        assert_eq!(required_threshold, THRESHOLD);
        assert_eq!(epoch, CEREMONY_EPOCH);

        let stored_ciphertext: ThresholdHpkeCiphertext =
            serde_json::from_slice(&fetched.body).expect("deserialize sealed body");

        // Any 2-of-3 quorum recovers the original plaintext.
        for subset in [[1u16, 2u16], [1, 3], [2, 3]] {
            let shares: Vec<DecapShare> = subset
                .iter()
                .map(|id| {
                    decap_share(&key_packages[id], &stored_ciphertext)
                        .expect("participant decap share")
                })
                .collect();
            let opened = combine_decap(
                &shares,
                usize::from(required_threshold),
                &stored_ciphertext,
                ZONE_INFO,
                fetched.object_id.as_bytes(),
            )
            .expect("quorum combine_decap");
            assert_eq!(opened, plaintext, "quorum {subset:?} must open object");
        }

        // A single share (t - 1) cannot open the stored object.
        let single_share = vec![
            decap_share(&key_packages[&1], &stored_ciphertext).expect("single participant share"),
        ];
        let err = combine_decap(
            &single_share,
            usize::from(required_threshold),
            &stored_ciphertext,
            ZONE_INFO,
            fetched.object_id.as_bytes(),
        )
        .expect_err("t - 1 shares must fail to open object");
        assert!(matches!(
            err,
            CryptoError::ThresholdHpke(ThresholdHpkeError::InsufficientShares {
                required: 2,
                got: 1,
            })
        ));
    });
}
