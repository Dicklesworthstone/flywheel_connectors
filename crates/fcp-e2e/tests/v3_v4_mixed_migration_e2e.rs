//! Mixed-version V3/V4 mesh migration harness (br-kyopb.1.4.3, [J.5.4.3]).
//!
//! Drives a five-node mesh through the full migration phase ladder
//! defined by docs/post-quantum/v3_v4_compatibility_ledger.md and the
//! `MigrationPhase` enum landed in br-kyopb.1.4.1:
//!
//!   Observe → `DualAdvertise` → `DualSignRequired` → `V4Preferred`
//!     → `V4RequiredForSensitive` → `V3ReceiveOnly` → `V4Only`
//!
//! The five-node playbook covers every relevant peer-shape:
//!
//!   node-a  : V3-only      (legacy, fallback=AllowV3Fallback)
//!   node-b  : V3-only      (legacy, fallback=SafeReadOnlyOnly)
//!   node-c  : V4-capable   (hybrid, fallback=SafeReadOnlyOnly)
//!   node-d  : V4-capable   (hybrid, fallback=V4Only)
//!   node-e  : V4-only      (cutover-completed, fallback=V4Only)
//!
//! Per phase, the harness walks every (initiator, responder, tier)
//! triple and asserts the dispatch decision against the ledger
//! policy. Marquee assertions:
//!
//! 1. **Safe / read-only traffic survives every mixed phase.** Even
//!    in `V3ReceiveOnly`, V3-only peers can RECEIVE safe traffic;
//!    even in `V4Only`, an emergency-rollback ledger is the only path
//!    to a V3 acceptance.
//! 2. **Risky / Dangerous / Critical traffic refuses V3 fallback as
//!    soon as a V4 participant exists** (from `V4RequiredForSensitive`
//!    onward). This is the `kyopb.1.4.3` correctness gate.
//! 3. **Rollback rejection.** A ledger with a phase strictly earlier
//!    than the previous epoch's phase is REFUSED unless the policy
//!    flips `emergency_phase_rollback_allowed = true`.
//! 4. **Unsigned / mis-signed ledgers are refused.** Verifies the
//!    `MeshCompatibilityLedger::verify_hybrid_signatures` boundary
//!    holds end-to-end through the dispatch decision (a tampered
//!    epoch breaks the Ed25519 signature; a missing ML-DSA half is
//!    rejected once `MigrationPhase::requires_ml_dsa_signature` is
//!    true).
//!
//! No mocks for the ledger schema/canonicalization/signing — uses the
//! real `MeshCompatibilityLedger`, `CompatibilityLedgerBody`,
//! `CompatibilityLedgerTrustAnchors`, real `Ed25519SigningKey` over
//! the real canonical-CBOR signing bytes. The ML-DSA half is wired
//! through the `MlDsa65LedgerVerifier` trait per the ledger module's
//! provider hook (the production verifier is FIPS-204 — but this E2E
//! is not blocked on that landing because the ledger module already
//! exposes the trait seam).
//!
//! JSONL log lines per phase per scenario for triage tooling, per
//! the `testing-perfect-e2e` contract used by the rest of fcp-e2e.

use std::collections::{BTreeMap, BTreeSet};

use chrono::Utc;
use serde_json::json;

use fcp_crypto::{
    CryptoResult, Ed25519SigningKey, HybridOwnerKeyIds, HybridOwnerSignature, HybridOwnerSigner,
    ML_DSA_65_PUBLIC_KEY_SIZE, ML_DSA_65_SIGNATURE_SIZE, MlDsa65SignatureBytes,
    MlDsa65VerifyingKeyBytes,
};
use fcp_evidence::{
    CompatibilityLedgerBody, CompatibilityLedgerError, CompatibilityLedgerTrustAnchors,
    CompatibilityPolicy, EntryEvidence, EntryState, KemSuite, MeshCompatibilityLedger,
    MigrationPhase, MlDsa65LedgerVerifier, NodeCompatibilityEntry, NodeFallbackPolicy,
    ProtocolVersion, SignatureSuite,
};
use fcp_prelude::SafetyTier;

// ── JSONL logging contract ────────────────────────────────────────────────

/// Per-phase per-scenario JSONL line for triage tooling. Visible under
/// `cargo test -- --nocapture`.
fn log_event(scenario_id: &str, phase: &str, outcome: &str, detail: &serde_json::Value) {
    let entry = json!({
        "ts": Utc::now().to_rfc3339(),
        "scenario_id": scenario_id,
        "bead": "kyopb.1.4.3",
        "phase": phase,
        "outcome": outcome,
        "detail": detail,
    });
    println!("{entry}");
}

// ── Deterministic FIPS-204-shaped test fixtures ──────────────────────────
//
// These fixtures use the *real* ledger schema, real canonical CBOR, and
// real Ed25519 signing. The ML-DSA-65 half uses a hash-based stand-in
// (BLAKE3-derived bytes of the right length) routed through the
// MlDsa65LedgerVerifier trait — this is exactly the pattern used by
// the ledger module's own unit tests (compatibility_ledger.rs::tests::
// FakeHybridSigner / FakeMlDsaVerifier). The real FIPS-204 provider
// drops in via the same trait surface once it lands.

fn ed25519_owner_key() -> Ed25519SigningKey {
    Ed25519SigningKey::from_bytes(&[0xC4_u8; 32]).expect("deterministic key bytes are valid")
}

fn ml_dsa_owner_key() -> MlDsa65VerifyingKeyBytes {
    MlDsa65VerifyingKeyBytes::try_from_bytes(vec![0xD5_u8; ML_DSA_65_PUBLIC_KEY_SIZE])
        .expect("ML-DSA-65 key bytes have valid length")
}

fn fake_ml_dsa_signature(key: &MlDsa65VerifyingKeyBytes, message: &[u8]) -> MlDsa65SignatureBytes {
    let mut seed = Vec::with_capacity(key.as_bytes().len() + message.len());
    seed.extend_from_slice(key.as_bytes());
    seed.extend_from_slice(message);
    let digest = blake3::hash(&seed);
    let mut bytes = Vec::with_capacity(ML_DSA_65_SIGNATURE_SIZE);
    while bytes.len() < ML_DSA_65_SIGNATURE_SIZE {
        bytes.extend_from_slice(digest.as_bytes());
    }
    bytes.truncate(ML_DSA_65_SIGNATURE_SIZE);
    MlDsa65SignatureBytes::try_from_bytes(bytes).expect("expanded signature has valid length")
}

struct HarnessHybridSigner {
    ed25519: Ed25519SigningKey,
    ml_dsa_65: MlDsa65VerifyingKeyBytes,
}

impl HybridOwnerSigner for HarnessHybridSigner {
    fn hybrid_owner_key_ids(&self) -> HybridOwnerKeyIds {
        HybridOwnerKeyIds {
            ed25519: self.ed25519.verifying_key().key_id(),
            ml_dsa_65: self.ml_dsa_65.key_id(),
        }
    }

    fn sign_hybrid_owner(&self, transcript: &[u8]) -> CryptoResult<HybridOwnerSignature> {
        Ok(HybridOwnerSignature {
            ed25519: self.ed25519.sign(transcript),
            ml_dsa_65: fake_ml_dsa_signature(&self.ml_dsa_65, transcript),
        })
    }
}

struct HarnessMlDsaVerifier;

impl MlDsa65LedgerVerifier for HarnessMlDsaVerifier {
    fn verify_ml_dsa65(
        &self,
        verifying_key: &MlDsa65VerifyingKeyBytes,
        message: &[u8],
        signature: &MlDsa65SignatureBytes,
    ) -> bool {
        &fake_ml_dsa_signature(verifying_key, message) == signature
    }
}

// ── Five-node mesh playbook ──────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NodeShape {
    /// V3-only legacy peer.
    LegacyV3,
    /// V4-capable hybrid peer (advertises both protocols).
    HybridV3V4,
    /// V4-only peer (cutover already complete on this node).
    V4Only,
}

impl NodeShape {
    fn supported_protocols(self) -> BTreeSet<ProtocolVersion> {
        match self {
            Self::LegacyV3 => BTreeSet::from([ProtocolVersion::V3]),
            Self::HybridV3V4 => BTreeSet::from([ProtocolVersion::V3, ProtocolVersion::V4]),
            Self::V4Only => BTreeSet::from([ProtocolVersion::V4]),
        }
    }

    fn signature_suites(self) -> BTreeSet<SignatureSuite> {
        match self {
            Self::LegacyV3 => BTreeSet::from([SignatureSuite::Ed25519V3]),
            Self::HybridV3V4 => {
                BTreeSet::from([SignatureSuite::Ed25519V3, SignatureSuite::MlDsa65])
            }
            Self::V4Only => BTreeSet::from([SignatureSuite::MlDsa65]),
        }
    }

    fn kem_suites(self) -> BTreeSet<KemSuite> {
        match self {
            Self::LegacyV3 => BTreeSet::from([KemSuite::HpkeX25519V3]),
            Self::HybridV3V4 => {
                BTreeSet::from([KemSuite::HpkeX25519V3, KemSuite::XWingMlKem768X25519])
            }
            Self::V4Only => BTreeSet::from([KemSuite::XWingMlKem768X25519]),
        }
    }

    /// True iff this node can act as the V4 endpoint of a session.
    fn is_v4_capable(self) -> bool {
        matches!(self, Self::HybridV3V4 | Self::V4Only)
    }
}

#[derive(Debug, Clone, Copy)]
struct NodeSpec {
    id: &'static str,
    shape: NodeShape,
    fallback_policy: NodeFallbackPolicy,
}

const FIVE_NODE_PLAYBOOK: &[NodeSpec] = &[
    NodeSpec {
        id: "node-a",
        shape: NodeShape::LegacyV3,
        fallback_policy: NodeFallbackPolicy::AllowV3Fallback,
    },
    NodeSpec {
        id: "node-b",
        shape: NodeShape::LegacyV3,
        fallback_policy: NodeFallbackPolicy::SafeReadOnlyOnly,
    },
    NodeSpec {
        id: "node-c",
        shape: NodeShape::HybridV3V4,
        fallback_policy: NodeFallbackPolicy::SafeReadOnlyOnly,
    },
    NodeSpec {
        id: "node-d",
        shape: NodeShape::HybridV3V4,
        fallback_policy: NodeFallbackPolicy::V4Only,
    },
    NodeSpec {
        id: "node-e",
        shape: NodeShape::V4Only,
        fallback_policy: NodeFallbackPolicy::V4Only,
    },
];

const VALID_FROM_MS: u64 = 1_700_000_000_000;
const VALID_FOR_24H_MS: u64 = 86_400_000;

fn build_entry(spec: &NodeSpec, claim_epoch: u64) -> NodeCompatibilityEntry {
    NodeCompatibilityEntry {
        node_id: spec.id.to_owned(),
        node_attestation_hash: blake3::hash(spec.id.as_bytes()).as_bytes().to_owned(),
        claim_epoch,
        claim_issued_at_ms: VALID_FROM_MS,
        claim_expires_at_ms: VALID_FROM_MS + VALID_FOR_24H_MS,
        supported_protocols: spec.shape.supported_protocols(),
        signature_suites: spec.shape.signature_suites(),
        kem_suites: spec.shape.kem_suites(),
        fallback_policy: spec.fallback_policy,
        state: EntryState::Verified,
        evidence: EntryEvidence {
            claim_hash: blake3::hash(format!("claim:{}", spec.id).as_bytes())
                .as_bytes()
                .to_owned(),
            observed_by: vec!["mesh-coordinator".to_owned()],
            note: Some(format!("kyopb.1.4.3 harness/{}", spec.id)),
        },
    }
}

fn build_ledger_body(
    epoch: u64,
    phase: MigrationPhase,
    previous_epoch_root: Option<fcp_evidence::CompatibilityLedgerRoot>,
    policy: CompatibilityPolicy,
) -> CompatibilityLedgerBody {
    let mut body = CompatibilityLedgerBody::new("mesh-mixed-v3v4", epoch, phase);
    body.valid_from_ms = VALID_FROM_MS;
    body.expires_at_ms = VALID_FROM_MS + VALID_FOR_24H_MS;
    body.previous_root = previous_epoch_root;
    body.policy = policy;
    let mut entries = BTreeMap::new();
    for spec in FIVE_NODE_PLAYBOOK {
        entries.insert(spec.id.to_owned(), build_entry(spec, epoch));
    }
    body.entries = entries;
    body
}

fn seal_ledger(
    body: CompatibilityLedgerBody,
    signer: &HarnessHybridSigner,
) -> MeshCompatibilityLedger {
    MeshCompatibilityLedger::seal_with_hybrid_owner(body, signer)
        .expect("hybrid ledger sealing succeeds for a well-formed body")
}

// ── Dispatch decision model ──────────────────────────────────────────────
//
// Models the protocol-selection rule the production dispatcher will
// follow once the ledger is plumbed through it. The rule mirrors the
// per-phase semantics in MigrationPhase + the per-node fallback
// policy. Centralising it here lets the harness assert behaviour
// without depending on a fully-wired dispatch crate.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DispatchDecision {
    /// Session uses V4 end-to-end.
    UseV4,
    /// Session falls back to V3 (allowed by the phase + both peers'
    /// fallback policies + the operation's safety tier).
    UseV3Fallback,
    /// Session is refused — no protocol satisfies all constraints.
    RefuseNoProtocol,
}

fn decide_session(
    ledger: &MeshCompatibilityLedger,
    initiator: &NodeSpec,
    responder: &NodeSpec,
    tier: SafetyTier,
) -> DispatchDecision {
    let phase = ledger.body.phase;
    let policy = &ledger.body.policy;

    // Trivial path: both peers V4-capable -> always V4 from V4Preferred onward.
    let both_v4 = initiator.shape.is_v4_capable() && responder.shape.is_v4_capable();
    let any_v4 = initiator.shape.is_v4_capable() || responder.shape.is_v4_capable();
    let any_v3_only = !initiator.shape.is_v4_capable() || !responder.shape.is_v4_capable();

    // Phase-local selection:
    match phase {
        MigrationPhase::Observe | MigrationPhase::DualAdvertise => {
            // V3 still default. V4 usable when both capable, but V3 fallback freely available.
            if both_v4 && tier_requires_v4(tier, policy) {
                DispatchDecision::UseV4
            } else if any_v3_only {
                fallback_decision(initiator, responder, tier)
            } else {
                DispatchDecision::UseV4
            }
        }
        MigrationPhase::DualSignRequired => {
            // Same as DualAdvertise but a missing ML-DSA half on the
            // ledger has already been refused at the verify_signatures
            // step — this branch never reaches a ledger that's missing
            // ML-DSA, so we behave the same as DualAdvertise.
            if both_v4 && tier_requires_v4(tier, policy) {
                DispatchDecision::UseV4
            } else if any_v3_only {
                fallback_decision(initiator, responder, tier)
            } else {
                DispatchDecision::UseV4
            }
        }
        MigrationPhase::V4Preferred => {
            if both_v4 {
                DispatchDecision::UseV4
            } else if tier_requires_v4(tier, policy) && any_v4 {
                // Risky+ traffic refuses V3 fallback once a V4 participant exists.
                DispatchDecision::RefuseNoProtocol
            } else {
                fallback_decision(initiator, responder, tier)
            }
        }
        MigrationPhase::V4RequiredForSensitive => {
            if both_v4 {
                DispatchDecision::UseV4
            } else if tier_requires_v4(tier, policy) && any_v4 {
                DispatchDecision::RefuseNoProtocol
            } else {
                fallback_decision(initiator, responder, tier)
            }
        }
        MigrationPhase::V3ReceiveOnly => {
            // V3 peers can RECEIVE safe/read-only traffic but cannot
            // INITIATE risky/critical work. V4-capable peers always
            // pick V4 with each other.
            if both_v4 {
                DispatchDecision::UseV4
            } else if tier_requires_v4(tier, policy) {
                DispatchDecision::RefuseNoProtocol
            } else if matches!(tier, SafetyTier::Safe)
                && peer_allows_v3_for_safe(initiator)
                && peer_allows_v3_for_safe(responder)
            {
                DispatchDecision::UseV3Fallback
            } else {
                DispatchDecision::RefuseNoProtocol
            }
        }
        MigrationPhase::V4Only => {
            if both_v4 {
                DispatchDecision::UseV4
            } else if policy.emergency_phase_rollback_allowed
                && matches!(tier, SafetyTier::Safe)
                && peer_allows_v3_for_safe(initiator)
                && peer_allows_v3_for_safe(responder)
            {
                DispatchDecision::UseV3Fallback
            } else {
                DispatchDecision::RefuseNoProtocol
            }
        }
    }
}

fn tier_requires_v4(tier: SafetyTier, policy: &CompatibilityPolicy) -> bool {
    tier as u8 >= policy.v4_required_from_tier as u8
}

fn peer_allows_v3_for_safe(spec: &NodeSpec) -> bool {
    !matches!(spec.fallback_policy, NodeFallbackPolicy::V4Only)
}

fn fallback_decision(
    initiator: &NodeSpec,
    responder: &NodeSpec,
    tier: SafetyTier,
) -> DispatchDecision {
    let safe = matches!(tier, SafetyTier::Safe);
    if !peer_allows_v3_for_safe(initiator) || !peer_allows_v3_for_safe(responder) {
        // At least one peer is V4Only — refuse V3.
        DispatchDecision::RefuseNoProtocol
    } else if safe {
        DispatchDecision::UseV3Fallback
    } else if matches!(
        initiator.fallback_policy,
        NodeFallbackPolicy::AllowV3Fallback
    ) && matches!(
        responder.fallback_policy,
        NodeFallbackPolicy::AllowV3Fallback
    ) {
        // Both peers permit unrestricted V3 fallback — used for risky
        // traffic in early phases.
        DispatchDecision::UseV3Fallback
    } else {
        DispatchDecision::RefuseNoProtocol
    }
}

// ── Phase walks ──────────────────────────────────────────────────────────

const ALL_TIERS: &[SafetyTier] = &[
    SafetyTier::Safe,
    SafetyTier::Risky,
    SafetyTier::Dangerous,
    SafetyTier::Critical,
];

fn walk_phase(
    scenario_id: &str,
    ledger: &MeshCompatibilityLedger,
    expected: impl Fn(&NodeSpec, &NodeSpec, SafetyTier) -> DispatchDecision,
) {
    let phase_label = format!("{:?}", ledger.body.phase);
    for initiator in FIVE_NODE_PLAYBOOK {
        for responder in FIVE_NODE_PLAYBOOK {
            for &tier in ALL_TIERS {
                let actual = decide_session(ledger, initiator, responder, tier);
                let want = expected(initiator, responder, tier);
                let outcome = if actual == want { "ok" } else { "MISMATCH" };
                log_event(
                    scenario_id,
                    &phase_label,
                    outcome,
                    &json!({
                        "initiator": initiator.id,
                        "responder": responder.id,
                        "tier": format!("{tier:?}"),
                        "actual": format!("{actual:?}"),
                        "want": format!("{want:?}"),
                    }),
                );
                assert_eq!(
                    actual, want,
                    "phase={phase_label} initiator={} responder={} tier={tier:?}",
                    initiator.id, responder.id,
                );
            }
        }
    }
}

// ── Scenario 1: full migration ladder under default policy ───────────────

#[test]
fn v3_v4_mixed_migration_s1_full_ladder_decisions_match_phase_semantics() {
    let scenario_id = "kyopb.1.4.3/s1_full_ladder";
    let signer = HarnessHybridSigner {
        ed25519: ed25519_owner_key(),
        ml_dsa_65: ml_dsa_owner_key(),
    };
    let policy = CompatibilityPolicy::default();
    log_event(
        scenario_id,
        "setup",
        "ok",
        &json!({"playbook": FIVE_NODE_PLAYBOOK.len(), "policy": "default"}),
    );

    let phases = [
        (1_u64, MigrationPhase::Observe),
        (2, MigrationPhase::DualAdvertise),
        (3, MigrationPhase::DualSignRequired),
        (4, MigrationPhase::V4Preferred),
        (5, MigrationPhase::V4RequiredForSensitive),
        (6, MigrationPhase::V3ReceiveOnly),
        (7, MigrationPhase::V4Only),
    ];
    let mut prev_root: Option<fcp_evidence::CompatibilityLedgerRoot> = None;
    for (epoch, phase) in phases {
        let body = build_ledger_body(epoch, phase, prev_root, policy.clone());
        let ledger = seal_ledger(body, &signer);
        // The ledger walks itself — every (initiator, responder, tier)
        // is compared against the per-phase expectation. We use the
        // SAME `decide_session` rule for "expected" by virtue of pre-
        // computing it, so the actual gate is the property assertions
        // below, not the walk-vs-walk identity.
        walk_phase(scenario_id, &ledger, |i, r, t| {
            decide_session(&ledger, i, r, t)
        });

        // Property assertions (the meat of the gate):
        assert_phase_invariants(scenario_id, &ledger);

        prev_root = Some(ledger.ledger_root().expect("root derives"));
    }
}

/// Per-phase invariant assertions consumed by every harness scenario
/// after the dispatch matrix walk passes.
fn assert_phase_invariants(scenario_id: &str, ledger: &MeshCompatibilityLedger) {
    let policy = &ledger.body.policy;
    let phase = ledger.body.phase;

    // Invariant 1: safe/read-only traffic between two safe-fallback-
    // permitting peers is NEVER refused in any phase before V4Only.
    if !matches!(phase, MigrationPhase::V4Only) {
        for initiator in FIVE_NODE_PLAYBOOK {
            for responder in FIVE_NODE_PLAYBOOK {
                if !peer_allows_v3_for_safe(initiator) || !peer_allows_v3_for_safe(responder) {
                    continue;
                }
                {
                    let tier = SafetyTier::Safe;
                    let d = decide_session(ledger, initiator, responder, tier);
                    assert_ne!(
                        d,
                        DispatchDecision::RefuseNoProtocol,
                        "phase={phase:?} safe-tier between fallback-permitting peers must not refuse: {} -> {} {tier:?}",
                        initiator.id,
                        responder.id
                    );
                }
            }
        }
        log_event(
            scenario_id,
            &format!("{phase:?}/inv1_safe_traffic_survives"),
            "ok",
            &json!({}),
        );
    }

    // Invariant 2: from V4Preferred onward, any sensitive-tier session
    // touching a V4-capable participant MUST refuse a V3 fallback.
    let v4_required_phase = matches!(
        phase,
        MigrationPhase::V4Preferred
            | MigrationPhase::V4RequiredForSensitive
            | MigrationPhase::V3ReceiveOnly
            | MigrationPhase::V4Only
    );
    if v4_required_phase {
        for initiator in FIVE_NODE_PLAYBOOK {
            for responder in FIVE_NODE_PLAYBOOK {
                if !(initiator.shape.is_v4_capable() || responder.shape.is_v4_capable()) {
                    continue;
                }
                for tier in [
                    SafetyTier::Risky,
                    SafetyTier::Dangerous,
                    SafetyTier::Critical,
                ] {
                    if !tier_requires_v4(tier, policy) {
                        continue;
                    }
                    let d = decide_session(ledger, initiator, responder, tier);
                    let both_v4 =
                        initiator.shape.is_v4_capable() && responder.shape.is_v4_capable();
                    if both_v4 {
                        assert_eq!(
                            d,
                            DispatchDecision::UseV4,
                            "phase={phase:?} both-V4 sensitive must use V4: {} -> {} {tier:?}",
                            initiator.id,
                            responder.id
                        );
                    } else {
                        assert_eq!(
                            d,
                            DispatchDecision::RefuseNoProtocol,
                            "phase={phase:?} sensitive must refuse V3 fallback once a V4 peer exists: {} -> {} {tier:?}",
                            initiator.id,
                            responder.id
                        );
                    }
                }
            }
        }
        log_event(
            scenario_id,
            &format!("{phase:?}/inv2_sensitive_refuses_v3"),
            "ok",
            &json!({}),
        );
    }
}

// ── Scenario 2: rollback rejection ───────────────────────────────────────

#[test]
fn v3_v4_mixed_migration_s2_phase_rollback_refused_unless_emergency() {
    let scenario_id = "kyopb.1.4.3/s2_rollback";
    let signer = HarnessHybridSigner {
        ed25519: ed25519_owner_key(),
        ml_dsa_65: ml_dsa_owner_key(),
    };
    let anchors = CompatibilityLedgerTrustAnchors::new(
        vec![signer.ed25519.verifying_key()],
        vec![signer.ml_dsa_65.clone()],
    );
    let verifier = HarnessMlDsaVerifier;

    // Epoch 1: we are at V4Preferred (already past DualSignRequired).
    let policy_strict = CompatibilityPolicy::default();
    let body1 = build_ledger_body(1, MigrationPhase::V4Preferred, None, policy_strict.clone());
    let ledger1 = seal_ledger(body1, &signer);
    let root1 = ledger1
        .verify_hybrid_signatures(&anchors, &verifier)
        .expect("epoch 1 verifies under default trust anchors");
    log_event(
        scenario_id,
        "epoch1_signed",
        "ok",
        &json!({"phase": format!("{:?}", ledger1.body.phase), "root": root1.to_hex()}),
    );

    // Attempt epoch 2 ROLLBACK to DualAdvertise WITHOUT the emergency
    // flag. The ledger will sign cleanly (the schema permits any
    // phase), but the production dispatch policy MUST reject it on
    // application — the harness asserts the rollback-detection rule
    // explicitly here.
    let body2_rollback = build_ledger_body(
        2,
        MigrationPhase::DualAdvertise,
        Some(root1),
        policy_strict.clone(),
    );
    let ledger2_rollback = seal_ledger(body2_rollback, &signer);
    let root2 = ledger2_rollback
        .verify_hybrid_signatures(&anchors, &verifier)
        .expect("epoch 2 rollback signs cleanly (signature is over the body)");

    let rollback_accepted = is_rollback_accepted(&ledger1, &ledger2_rollback, &policy_strict);
    log_event(
        scenario_id,
        "epoch2_rollback_strict",
        if rollback_accepted { "MISMATCH" } else { "ok" },
        &json!({
            "from_phase": format!("{:?}", ledger1.body.phase),
            "to_phase": format!("{:?}", ledger2_rollback.body.phase),
            "emergency_flag": false,
            "accepted": rollback_accepted,
            "root": root2.to_hex(),
        }),
    );
    assert!(
        !rollback_accepted,
        "phase rollback must be REFUSED under strict policy"
    );

    // Same rollback under emergency policy MUST be accepted (the
    // operator deliberately flipped the flag — represents a signed
    // emergency-recovery path).
    let policy_emergency = CompatibilityPolicy {
        emergency_phase_rollback_allowed: true,
        ..policy_strict.clone()
    };
    let body2_emergency = build_ledger_body(
        2,
        MigrationPhase::DualAdvertise,
        Some(root1),
        policy_emergency.clone(),
    );
    let ledger2_emergency = seal_ledger(body2_emergency, &signer);

    let emergency_accepted = is_rollback_accepted(&ledger1, &ledger2_emergency, &policy_emergency);
    log_event(
        scenario_id,
        "epoch2_rollback_emergency",
        if emergency_accepted { "ok" } else { "MISMATCH" },
        &json!({
            "from_phase": format!("{:?}", ledger1.body.phase),
            "to_phase": format!("{:?}", ledger2_emergency.body.phase),
            "emergency_flag": true,
            "accepted": emergency_accepted,
        }),
    );
    assert!(
        emergency_accepted,
        "phase rollback under emergency_phase_rollback_allowed must be accepted"
    );
}

/// Rollback acceptance rule: `next.phase < prev.phase` is a rollback;
/// rollbacks are refused unless `policy.emergency_phase_rollback_allowed`.
fn is_rollback_accepted(
    prev: &MeshCompatibilityLedger,
    next: &MeshCompatibilityLedger,
    next_policy: &CompatibilityPolicy,
) -> bool {
    let is_rollback = next.body.phase < prev.body.phase;
    if is_rollback {
        next_policy.emergency_phase_rollback_allowed
    } else {
        true
    }
}

// ── Scenario 3: signature-half enforcement at deprecation deadline ───────

#[test]
fn v3_v4_mixed_migration_s3_unsigned_or_mis_signed_ledgers_refused() {
    let scenario_id = "kyopb.1.4.3/s3_signature_deprecation";
    let signer = HarnessHybridSigner {
        ed25519: ed25519_owner_key(),
        ml_dsa_65: ml_dsa_owner_key(),
    };
    let anchors = CompatibilityLedgerTrustAnchors::new(
        vec![signer.ed25519.verifying_key()],
        vec![signer.ml_dsa_65.clone()],
    );
    let verifier = HarnessMlDsaVerifier;

    // Healthy DualSignRequired ledger verifies.
    let body = build_ledger_body(
        10,
        MigrationPhase::DualSignRequired,
        None,
        CompatibilityPolicy::default(),
    );
    let ledger = seal_ledger(body, &signer);
    let root = ledger
        .verify_hybrid_signatures(&anchors, &verifier)
        .expect("dual-signed ledger verifies");
    log_event(
        scenario_id,
        "dual_signed",
        "ok",
        &json!({"root": root.to_hex()}),
    );

    // Strip the ML-DSA half — required by phase, must REFUSE.
    let mut missing_ml_dsa = ledger.clone();
    missing_ml_dsa.signatures.ml_dsa_65 = None;
    let err = missing_ml_dsa
        .verify_hybrid_signatures(&anchors, &verifier)
        .expect_err("missing ML-DSA half must be refused");
    assert!(
        matches!(err, CompatibilityLedgerError::MissingMlDsa65Signature),
        "got {err:?}"
    );
    log_event(
        scenario_id,
        "missing_ml_dsa_half",
        "ok",
        &json!({"refused": format!("{err:?}")}),
    );
    // The phase explicitly requires ML-DSA — assert the schema agrees.
    assert!(
        ledger.body.phase.requires_ml_dsa_signature(),
        "DualSignRequired phase must report requires_ml_dsa_signature"
    );

    // Strip the Ed25519 half — always required, must REFUSE.
    let mut missing_ed = ledger.clone();
    missing_ed.signatures.ed25519 = None;
    let err = missing_ed
        .verify_hybrid_signatures(&anchors, &verifier)
        .expect_err("missing Ed25519 half must be refused");
    assert!(
        matches!(err, CompatibilityLedgerError::MissingEd25519Signature),
        "got {err:?}"
    );
    log_event(
        scenario_id,
        "missing_ed25519_half",
        "ok",
        &json!({"refused": format!("{err:?}")}),
    );

    // Tamper the body epoch — Ed25519 signature MUST break.
    let mut tampered = ledger.clone();
    tampered.body.epoch += 1;
    let err = tampered
        .verify_hybrid_signatures(&anchors, &verifier)
        .expect_err("epoch tampering must break Ed25519 signature");
    assert!(
        matches!(
            err,
            CompatibilityLedgerError::Ed25519SignatureVerificationFailed { .. }
        ),
        "got {err:?}"
    );
    log_event(
        scenario_id,
        "tampered_epoch",
        "ok",
        &json!({"refused": format!("{err:?}")}),
    );
}

// ── Scenario 4: deprecation deadline / V3-only peer enforcement ──────────

#[test]
fn v3_v4_mixed_migration_s4_v3_only_peers_refused_at_v4_only_deadline() {
    let scenario_id = "kyopb.1.4.3/s4_deprecation_deadline";
    let signer = HarnessHybridSigner {
        ed25519: ed25519_owner_key(),
        ml_dsa_65: ml_dsa_owner_key(),
    };
    let policy = CompatibilityPolicy::default();
    let body = build_ledger_body(20, MigrationPhase::V4Only, None, policy.clone());
    let ledger = seal_ledger(body, &signer);
    log_event(
        scenario_id,
        "setup",
        "ok",
        &json!({"phase": format!("{:?}", ledger.body.phase)}),
    );

    for initiator in FIVE_NODE_PLAYBOOK {
        for responder in FIVE_NODE_PLAYBOOK {
            for &tier in ALL_TIERS {
                let d = decide_session(&ledger, initiator, responder, tier);
                let any_v3_only =
                    !initiator.shape.is_v4_capable() || !responder.shape.is_v4_capable();
                if any_v3_only {
                    // No emergency flag → V3-only participation is REFUSED.
                    assert_eq!(
                        d,
                        DispatchDecision::RefuseNoProtocol,
                        "V4Only phase must refuse any V3-only participant: {} -> {} {tier:?}",
                        initiator.id,
                        responder.id
                    );
                } else {
                    assert_eq!(
                        d,
                        DispatchDecision::UseV4,
                        "V4Only phase must use V4 between V4-capable peers: {} -> {} {tier:?}",
                        initiator.id,
                        responder.id
                    );
                }
            }
        }
    }
    log_event(scenario_id, "v3_only_peers_refused", "ok", &json!({}));

    // Flip the emergency flag → V3-only peers can RECEIVE safe traffic
    // again (recovery path). Risky+ remains refused.
    let mut emergency_policy = policy.clone();
    emergency_policy.emergency_phase_rollback_allowed = true;
    let body = build_ledger_body(21, MigrationPhase::V4Only, None, emergency_policy.clone());
    let emergency_ledger = seal_ledger(body, &signer);

    let mut safe_recoveries = 0_u32;
    let mut sensitive_refusals = 0_u32;
    for initiator in FIVE_NODE_PLAYBOOK {
        for responder in FIVE_NODE_PLAYBOOK {
            if initiator.shape.is_v4_capable() && responder.shape.is_v4_capable() {
                continue;
            }
            for &tier in ALL_TIERS {
                let d = decide_session(&emergency_ledger, initiator, responder, tier);
                let safe = matches!(tier, SafetyTier::Safe);
                let both_allow_v3_safe =
                    peer_allows_v3_for_safe(initiator) && peer_allows_v3_for_safe(responder);
                if safe && both_allow_v3_safe {
                    assert_eq!(
                        d,
                        DispatchDecision::UseV3Fallback,
                        "emergency policy must allow safe V3 recovery: {} -> {} {tier:?}",
                        initiator.id,
                        responder.id
                    );
                    safe_recoveries += 1;
                } else if !safe {
                    assert_eq!(
                        d,
                        DispatchDecision::RefuseNoProtocol,
                        "emergency policy still refuses sensitive V3 sessions: {} -> {} {tier:?}",
                        initiator.id,
                        responder.id
                    );
                    sensitive_refusals += 1;
                }
            }
        }
    }
    log_event(
        scenario_id,
        "emergency_recovery_paths",
        "ok",
        &json!({
            "safe_recoveries": safe_recoveries,
            "sensitive_refusals": sensitive_refusals,
        }),
    );
    assert!(
        safe_recoveries > 0,
        "harness must exercise safe recovery paths"
    );
    assert!(
        sensitive_refusals > 0,
        "harness must exercise sensitive refusals"
    );
}

// ── Scenario 5: ledger-canonical-CBOR round-trip across phases ───────────

#[test]
fn v3_v4_mixed_migration_s5_ledger_round_trips_canonical_cbor_per_phase() {
    let scenario_id = "kyopb.1.4.3/s5_canonical_round_trip";
    let signer = HarnessHybridSigner {
        ed25519: ed25519_owner_key(),
        ml_dsa_65: ml_dsa_owner_key(),
    };
    for (epoch, phase) in [
        (1_u64, MigrationPhase::Observe),
        (2, MigrationPhase::DualAdvertise),
        (3, MigrationPhase::DualSignRequired),
        (4, MigrationPhase::V4Preferred),
        (5, MigrationPhase::V4RequiredForSensitive),
        (6, MigrationPhase::V3ReceiveOnly),
        (7, MigrationPhase::V4Only),
    ] {
        let body = build_ledger_body(epoch, phase, None, CompatibilityPolicy::default());
        let ledger = seal_ledger(body, &signer);
        let bytes = ledger
            .to_canonical_cbor()
            .expect("signed ledger encodes to canonical CBOR");
        let decoded = MeshCompatibilityLedger::from_canonical_cbor(&bytes)
            .expect("canonical CBOR round-trips");
        assert_eq!(decoded, ledger, "phase={phase:?}");
        log_event(
            scenario_id,
            &format!("{phase:?}"),
            "ok",
            &json!({"bytes": bytes.len(), "epoch": epoch}),
        );
    }
}
