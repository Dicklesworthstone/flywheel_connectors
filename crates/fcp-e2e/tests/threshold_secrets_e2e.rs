//! Threshold secrets E2E (br-qjcg0, [E.7] Threshold Secrets proof gap).
//!
//! No mocks. This drives the real `fcp_crypto::shamir` implementation:
//! Shamir GF(2^8) splitting, HPKE sealing to per-node X25519 keys, AAD-bound
//! share opening, interpolation reconstruction, and a BLAKE3 commitment proof
//! over production-shaped application secrets.
//!
//! Coverage matrix:
//! - 3-of-5 database credential reconstructs from exactly K opened shares.
//! - 3-of-5 API key reconstructs from a disjoint K-share quorum.
//! - K-1 shares fail closed before interpolation.
//! - Tampered share material reconstructs to the wrong bytes and is rejected by
//!   the cryptographic commitment proof.
//! - Wrong AAD/node binding cannot open a sealed share.
//! - Reconstructed `ZeroizingSecret` debug output never exposes secret bytes.

use chrono::Utc;
use fcp_core::{SecretSharingScheme, SecretType};
use fcp_crypto::{
    SealedShamirShare, ShamirError, ShamirShare, X25519SecretKey, ZeroizingSecret, open_share,
    reconstruct_secret, split_and_seal,
};
use serde_json::json;

const K: u8 = 3;
const N: u8 = 5;
const ISSUED_AT: u64 = 1_760_000_000;
const ZONE_ID: &[u8] = b"z:project:qjcg0-threshold-secrets";

fn log_event(scenario_id: &str, phase: &str, outcome: &str, detail: Option<&str>) {
    let entry = json!({
        "ts": Utc::now().to_rfc3339(),
        "scenario_id": scenario_id,
        "bead": "qjcg0",
        "phase": phase,
        "outcome": outcome,
        "detail": detail,
    });
    println!("{entry}");
}

fn commitment_for(secret_type: SecretType, k: u8, n: u8, secret: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new();
    let secret_type_label = format!("{secret_type:?}");
    hasher.update(b"fcp.threshold-secret.application-proof.v1");
    hasher.update(secret_type_label.as_bytes());
    hasher.update(&[k, n]);
    hasher.update(secret);
    hasher.finalize().to_hex().to_string()
}

#[derive(Debug, Clone)]
struct ThresholdProof {
    secret_type: SecretType,
    k: u8,
    n: u8,
    commitment: String,
}

impl ThresholdProof {
    fn new(secret_type: SecretType, k: u8, n: u8, secret: &[u8]) -> Self {
        Self {
            secret_type,
            k,
            n,
            commitment: commitment_for(secret_type, k, n, secret),
        }
    }

    fn verify(&self, secret: &[u8]) -> Result<(), ThresholdSecretError> {
        let actual = commitment_for(self.secret_type, self.k, self.n, secret);
        if actual == self.commitment {
            Ok(())
        } else {
            Err(ThresholdSecretError::CommitmentMismatch {
                expected: self.commitment.clone(),
                actual,
            })
        }
    }
}

struct ApplicationSecretFixture {
    scenario_id: &'static str,
    secret_type: SecretType,
    plaintext: &'static [u8],
    proof: ThresholdProof,
}

impl ApplicationSecretFixture {
    fn database_credential() -> Self {
        let plaintext =
            b"postgres://flywheel_app:qjcg0-db-proof@db.internal:5432/flywheel?sslmode=require";
        Self {
            scenario_id: "qjcg0.database_credential",
            secret_type: SecretType::DatabasePassword,
            plaintext,
            proof: ThresholdProof::new(SecretType::DatabasePassword, K, N, plaintext),
        }
    }

    fn api_key() -> Self {
        let plaintext = b"fcp_e2e_qjcg0_api_key_material_v1_52_bytes_long";
        Self {
            scenario_id: "qjcg0.api_key",
            secret_type: SecretType::ApiKey,
            plaintext,
            proof: ThresholdProof::new(SecretType::ApiKey, K, N, plaintext),
        }
    }
}

struct NodeShare {
    node_id: Vec<u8>,
    secret_key: X25519SecretKey,
    sealed_share: SealedShamirShare,
}

struct ThresholdSecretEngine {
    secret_type: SecretType,
    scheme: SecretSharingScheme,
    k: u8,
    n: u8,
    issued_at: u64,
    zone_id: Vec<u8>,
    nodes: Vec<NodeShare>,
}

#[derive(Debug)]
enum ThresholdSecretError {
    InsufficientShares { required: u8, provided: usize },
    MissingNode { index: usize },
    SplitAndSeal(String),
    OpenShare(String),
    Reconstruct(ShamirError),
    CommitmentMismatch { expected: String, actual: String },
    UnexpectedSuccess(&'static str),
}

impl std::fmt::Display for ThresholdSecretError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InsufficientShares { required, provided } => {
                write!(
                    formatter,
                    "insufficient shares: required {required}, provided {provided}"
                )
            }
            Self::MissingNode { index } => write!(formatter, "missing node at index {index}"),
            Self::SplitAndSeal(message) => {
                write!(formatter, "failed to split and seal secret: {message}")
            }
            Self::OpenShare(message) => write!(formatter, "failed to open share: {message}"),
            Self::Reconstruct(error) => write!(formatter, "failed to reconstruct secret: {error}"),
            Self::CommitmentMismatch { expected, actual } => write!(
                formatter,
                "commitment mismatch: expected {expected}, actual {actual}"
            ),
            Self::UnexpectedSuccess(scenario) => {
                write!(formatter, "expected failure but succeeded: {scenario}")
            }
        }
    }
}

impl std::error::Error for ThresholdSecretError {}

impl ThresholdSecretEngine {
    fn issue(
        secret_type: SecretType,
        plaintext: &[u8],
        k: u8,
        n: u8,
    ) -> Result<Self, ThresholdSecretError> {
        let node_ids = (1..=n)
            .map(|index| format!("node-qjcg0-{index}").into_bytes())
            .collect::<Vec<_>>();
        let secret_keys = (1..=n)
            .map(deterministic_node_secret_key)
            .collect::<Vec<_>>();
        let public_keys = secret_keys
            .iter()
            .map(X25519SecretKey::public_key)
            .collect::<Vec<_>>();
        let recipients = node_ids
            .iter()
            .zip(public_keys.iter())
            .map(|(node_id, public_key)| (node_id.as_slice(), public_key))
            .collect::<Vec<_>>();

        let sealed_shares = split_and_seal(plaintext, k, &recipients, ZONE_ID, ISSUED_AT)
            .map_err(|err| ThresholdSecretError::SplitAndSeal(err.to_string()))?;
        let nodes = node_ids
            .into_iter()
            .zip(secret_keys)
            .zip(sealed_shares)
            .map(|((node_id, secret_key), sealed_share)| NodeShare {
                node_id,
                secret_key,
                sealed_share,
            })
            .collect::<Vec<_>>();

        Ok(Self {
            secret_type,
            scheme: SecretSharingScheme::ShamirGf256,
            k,
            n,
            issued_at: ISSUED_AT,
            zone_id: ZONE_ID.to_vec(),
            nodes,
        })
    }

    fn open_selected_shares(
        &self,
        selected_nodes: &[usize],
    ) -> Result<Vec<ShamirShare>, ThresholdSecretError> {
        selected_nodes
            .iter()
            .map(|index| {
                let node = self
                    .nodes
                    .get(*index)
                    .ok_or(ThresholdSecretError::MissingNode { index: *index })?;
                open_share(
                    &node.sealed_share,
                    &node.secret_key,
                    &self.zone_id,
                    &node.node_id,
                    self.issued_at,
                )
                .map_err(|err| ThresholdSecretError::OpenShare(err.to_string()))
            })
            .collect()
    }

    fn reconstruct_selected(
        &self,
        selected_nodes: &[usize],
        proof: &ThresholdProof,
    ) -> Result<ZeroizingSecret, ThresholdSecretError> {
        let opened = self.open_selected_shares(selected_nodes)?;
        self.reconstruct_opened(&opened, proof)
    }

    fn reconstruct_opened(
        &self,
        opened: &[ShamirShare],
        proof: &ThresholdProof,
    ) -> Result<ZeroizingSecret, ThresholdSecretError> {
        if opened.len() < usize::from(self.k) {
            return Err(ThresholdSecretError::InsufficientShares {
                required: self.k,
                provided: opened.len(),
            });
        }
        assert_eq!(proof.k, self.k, "proof threshold must match secret record");
        assert_eq!(
            proof.n, self.n,
            "proof total shares must match secret record"
        );
        assert_eq!(
            proof.secret_type, self.secret_type,
            "proof secret type must match secret record"
        );
        assert_eq!(
            self.scheme,
            SecretSharingScheme::ShamirGf256,
            "E2E must exercise the normative Shamir GF(2^8) scheme"
        );

        let reconstructed =
            reconstruct_secret(opened).map_err(ThresholdSecretError::Reconstruct)?;
        reconstructed.with_bytes(|bytes| proof.verify(bytes))?;
        Ok(reconstructed)
    }
}

fn deterministic_node_secret_key(index: u8) -> X25519SecretKey {
    let mut bytes = [0_u8; 32];
    bytes.fill(index);
    bytes[0] = 0xA7;
    bytes[30] = 0xE7;
    bytes[31] = index;
    X25519SecretKey::from_bytes(bytes)
}

fn assert_secret_debug_redacted(secret: &ZeroizingSecret, plaintext: &[u8]) {
    let debug = format!("{secret:?}");
    // ZeroizingSecret Debug emits "ZeroizingSecret(<redacted, len=N>)".
    assert!(
        debug.contains("<redacted"),
        "ZeroizingSecret debug output must mark the material redacted, got: {debug}"
    );
    if let Ok(raw) = std::str::from_utf8(plaintext) {
        assert!(
            !debug.contains(raw),
            "ZeroizingSecret debug output must not contain raw secret material"
        );
    }
}

#[test]
fn threshold_secrets_e2e_reconstructs_database_credential_with_k_shares()
-> Result<(), ThresholdSecretError> {
    let fixture = ApplicationSecretFixture::database_credential();
    log_event(fixture.scenario_id, "setup", "started", None);

    let engine = ThresholdSecretEngine::issue(fixture.secret_type, fixture.plaintext, K, N)?;
    assert_eq!(engine.nodes.len(), usize::from(N));
    log_event(
        fixture.scenario_id,
        "split_and_seal",
        "passed",
        Some(&format!(
            "scheme={:?} k={K} n={N} commitment={}",
            engine.scheme, fixture.proof.commitment
        )),
    );

    let recovered = engine.reconstruct_selected(&[0, 1, 2], &fixture.proof)?;
    assert!(recovered.ct_eq_bytes(fixture.plaintext));
    assert_secret_debug_redacted(&recovered, fixture.plaintext);
    log_event(
        fixture.scenario_id,
        "reconstruct_and_verify",
        "passed",
        Some("selected_nodes=node-qjcg0-1,node-qjcg0-2,node-qjcg0-3"),
    );
    Ok(())
}

#[test]
fn threshold_secrets_e2e_reconstructs_api_key_from_disjoint_k_quorum()
-> Result<(), ThresholdSecretError> {
    let fixture = ApplicationSecretFixture::api_key();
    log_event(fixture.scenario_id, "setup", "started", None);

    let engine = ThresholdSecretEngine::issue(fixture.secret_type, fixture.plaintext, K, N)?;
    let recovered = engine.reconstruct_selected(&[0, 2, 4], &fixture.proof)?;
    assert!(recovered.ct_eq_bytes(fixture.plaintext));
    recovered.with_bytes(|bytes| fixture.proof.verify(bytes))?;
    log_event(
        fixture.scenario_id,
        "reconstruct_disjoint_quorum",
        "passed",
        Some("selected_nodes=node-qjcg0-1,node-qjcg0-3,node-qjcg0-5"),
    );
    Ok(())
}

#[test]
fn threshold_secrets_e2e_rejects_k_minus_one_shares() -> Result<(), ThresholdSecretError> {
    let fixture = ApplicationSecretFixture::api_key();
    let scenario = "qjcg0.k_minus_one";
    log_event(scenario, "setup", "started", None);

    let engine = ThresholdSecretEngine::issue(fixture.secret_type, fixture.plaintext, K, N)?;
    let Err(err) = engine.reconstruct_selected(&[0, 1], &fixture.proof) else {
        return Err(ThresholdSecretError::UnexpectedSuccess(
            "K-1 reconstruction",
        ));
    };
    match err {
        ThresholdSecretError::InsufficientShares { required, provided } => {
            assert_eq!(required, K);
            assert_eq!(provided, usize::from(K - 1));
        }
        other => return Err(other),
    }
    log_event(
        scenario,
        "reject_k_minus_one",
        "passed",
        Some("required=3 provided=2"),
    );
    Ok(())
}

#[test]
fn threshold_secrets_e2e_cryptographic_proof_rejects_tampered_share()
-> Result<(), ThresholdSecretError> {
    let fixture = ApplicationSecretFixture::database_credential();
    let scenario = "qjcg0.tampered_share";
    log_event(scenario, "setup", "started", None);

    let engine = ThresholdSecretEngine::issue(fixture.secret_type, fixture.plaintext, K, N)?;
    let mut opened = engine.open_selected_shares(&[0, 1, 2])?;
    let tampered_index = opened[1].index();
    let mut tampered_data = opened[1].data().to_vec();
    tampered_data[0] ^= 0x5A;
    opened[1] = ShamirShare::new(tampered_index, tampered_data);

    let Err(err) = engine.reconstruct_opened(&opened, &fixture.proof) else {
        return Err(ThresholdSecretError::UnexpectedSuccess(
            "tampered share proof",
        ));
    };
    match err {
        ThresholdSecretError::CommitmentMismatch { expected, actual } => {
            assert_eq!(expected, fixture.proof.commitment);
            assert_ne!(actual, expected);
        }
        other => return Err(other),
    }
    log_event(
        scenario,
        "verify_commitment",
        "passed",
        Some("tampered_share_index=2"),
    );
    Ok(())
}

#[test]
fn threshold_secrets_e2e_wrong_aad_cannot_open_wrapped_share() -> Result<(), ThresholdSecretError> {
    let fixture = ApplicationSecretFixture::api_key();
    let scenario = "qjcg0.aad_binding";
    log_event(scenario, "setup", "started", None);

    let engine = ThresholdSecretEngine::issue(fixture.secret_type, fixture.plaintext, K, N)?;
    let node = &engine.nodes[0];
    let Err(err) = open_share(
        &node.sealed_share,
        &node.secret_key,
        b"z:project:qjcg0-wrong-zone",
        &node.node_id,
        engine.issued_at,
    ) else {
        return Err(ThresholdSecretError::UnexpectedSuccess(
            "wrong AAD share open",
        ));
    };
    log_event(
        scenario,
        "aad_binding",
        "passed",
        Some(&format!("error={err}")),
    );
    Ok(())
}
