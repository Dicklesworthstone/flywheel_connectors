# Master Reachability Ledger

> Generated 2026-05-12 as part of `flywheel_connectors-angoc.15.1` (Phase U.1).
> Maps every README status-table row to its enforcing code path, test path, and
> proof artifact. The conformance test
> `crates/fcp-conformance/tests/master_reachability_ledger.rs` asserts this
> ledger stays in sync with the README and that every cited path exists.

## Format

Each row records:

- **claim**: the README status-table feature name
- **status**: the README label (`PROVEN`, `LIMITED`, `STEADY-STATE TARGET`, etc.)
- **code_path**: the production code that enforces the claim
- **test_path**: the test file that exercises it (the test fn name follows in `test_fn`)
- **test_fn**: a named test function inside `test_path` that the ledger
  conformance test will grep for
- **proof_path**: a Lean proof, golden vector, or formal model that closes the
  claim. If no formal model exists yet, `no_formal_model_reason` is set.

## Rows

### 1. Host-First Control Plane

- claim: Host-First Control Plane
- status: PROVEN
- code_path: `crates/fcp-host/src/supervisor.rs`
- test_path: `crates/fcp-conformance/tests/host_invoke_loop_conformance.rs`
- test_fn: `conformance_invoke_loop_a_happy_path_with_valid_capability`
- proof_path: (none — operational claim)
- no_formal_model_reason: "operational provisioning path; proven by integration test"

### 2. Truthful Runtime Resolution

- claim: Truthful Runtime Resolution
- status: PROVEN
- code_path: `crates/fwc/src/truth.rs`
- test_path: `crates/fwc/tests/readme_status_pinning.rs`
- test_fn: `fwc_production_invoke_still_routes_through_host_rpc_invoke`
- proof_path: (none — gating test pins README claim)
- no_formal_model_reason: "README-pinning test guards against silent drift"

### 3. Zone Isolation

- claim: Zone Isolation
- status: PROVEN
- code_path: `crates/fcp-core/src/zone_keys.rs`
- test_path: `crates/fcp-e2e/tests/zone_isolation_full_e2e.rs`
- test_fn: `test_audit_chain_continuity_under_rejection`
- proof_path: `lean/Fcp/Zone/Lattice.lean`
- no_formal_model_reason: "Lean 4.29.1 zone-lattice proof + 5-zone cross-zone E2E JSONL artifact pinned in docs/formal/zone-isolation-closeout-evidence.json"

### 4. Capability Tokens (CWT/COSE)

- claim: Capability Tokens (CWT/COSE)
- status: PROVEN
- code_path: `crates/fcp-crypto/src/cose.rs`
- test_path: `crates/fcp-core/tests/capability_verifier_predicate_matrix.rs`
- test_fn: `capability_verifier_accepts_documented_entrypoint_matrix`
- proof_path: `crates/fcp-core/tests/typestate_compile_fail.rs`
- no_formal_model_reason: "typestate compile-fail tests + predicate matrix golden vectors"

### 5. Tamper-Evident Audit + HLC

- claim: Tamper-Evident Audit + HLC
- status: PROVEN
- code_path: `crates/fcp-core/src/audit.rs`
- test_path: `crates/fcp-core/tests/audit_chain_golden_vectors.rs`
- test_fn: `test_audit_event_genesis_has_no_prev`
- proof_path: `crates/fcp-core/tests/audit_chain_golden_vectors.rs`
- no_formal_model_reason: "golden vectors pin hash-linked chain shape"

### 6. Revocation

- claim: Revocation
- status: PROVEN
- code_path: `crates/fcp-core/src/revocation.rs`
- test_path: `crates/fcp-e2e/tests/revocation_cascade_e2e.rs`
- test_fn: `revocation_cascade_e2e_happy_path`
- proof_path: (none — operational E2E)
- no_formal_model_reason: "RevocationRegistry uses exact HashMap; freshness verified by E2E"

### 7. Egress Proxy

- claim: Egress Proxy
- status: PROVEN
- code_path: `crates/fcp-sandbox/src/egress.rs`
- test_path: `crates/fcp-e2e/tests/egress_proxy_e2e.rs`
- test_fn: `egress_proxy_e2e_disallowed_host_denied_with_host_not_allowed`
- proof_path: (none — operational E2E)
- no_formal_model_reason: "manifest-aware guardrails + CIDR-deny defaults verified end-to-end"

### 8. Secretless Connectors

- claim: Secretless Connectors
- status: PROVEN
- code_path: `crates/fcp-crypto/src/secret_fetch.rs`
- test_path: `crates/fcp-e2e/tests/secretless_connector_e2e.rs`
- test_fn: `connector_receives_only_credential_id_not_secret_bytes`
- proof_path: `crates/fcp-e2e/tests/secretless_github_e2e.rs`
- no_formal_model_reason: "three connector-family E2Es prove SecretFetchHook injection"

### 9. Threshold Owner Key

- claim: Threshold Owner Key
- status: PROVEN
- code_path: `crates/fcp-bootstrap/src/ceremony.rs`
- test_path: `crates/fcp-e2e/tests/threshold_owner_key_e2e.rs`
- test_fn: `threshold_owner_key_e2e_two_of_three_produces_valid_ed25519_signature`
- proof_path: (none — Lean proof body deferred)
- pending: "Lean FROST DKG safety proof tracked by flywheel_connectors-angoc.9 Phase O.6"

### 10. Threshold Secrets (Shamir)

- claim: Threshold Secrets (Shamir)
- status: PROVEN
- code_path: `crates/fcp-core/src/secret.rs`
- test_path: `crates/fcp-e2e/tests/threshold_secrets_e2e.rs`
- test_fn: `threshold_secrets_e2e_reconstructs_database_credential_with_k_shares`
- proof_path: (none — operational E2E)
- no_formal_model_reason: "ZeroizingSecret + golden-vector share reconstruction"

### 11. Supply Chain Attestations

- claim: Supply Chain Attestations
- status: PROVEN
- code_path: `crates/fcp-registry/src/lib.rs`
- test_path: `crates/fcp-e2e/tests/supply_chain_attestation_e2e.rs`
- test_fn: `supply_chain_attestation_e2e`
- proof_path: (none — TUF/cosign adapters operational)
- no_formal_model_reason: "TUF/cosign adapters proven by phase-ordered JSONL log assertions"

### 12. Offline Access

- claim: Offline Access
- status: PROVEN
- code_path: `crates/fcp-store/src/offline.rs`
- test_path: `crates/fcp-e2e/tests/offline_access_e2e.rs`
- test_fn: `online_read_populates_cache_and_returns_live_source`
- proof_path: (none — operational E2E)
- no_formal_model_reason: "ResponseSource branching + drain-on-restore verified end-to-end"

### 13. Mesh-Stored Policy Objects

- claim: Mesh-Stored Policy Objects
- status: PROVEN
- code_path: `crates/fcp-core/src/policy.rs`
- test_path: `crates/fcp-e2e/tests/mesh_policy_object_e2e.rs`
- test_fn: `mesh_policy_object_lifecycle_gossip_admission_revocation_and_integrity`
- proof_path: (none — owner-signed policy objects)
- no_formal_model_reason: "owner-signed objects with gossip + evaluation E2E"

### 14. Symbol-First Protocol

- claim: Symbol-First Protocol
- status: PROVEN
- code_path: `crates/fcp-raptorq/src/lib.rs`
- test_path: `crates/fcp-e2e/tests/symbol_first_protocol_e2e.rs`
- test_fn: `symbol_first_e2e_happy_path_round_trip`
- proof_path: `crates/fcp-raptorq/src/golden.rs`
- no_formal_model_reason: "BLAKE3 golden hashes + round-trip byte-equivalence"

### 15. Mesh-Native Architecture

- claim: Mesh-Native Architecture
- status: STEADY-STATE TARGET (NOT YET OPERATIONAL)
- code_path: `crates/fcp-mesh/src/node.rs`
- test_path: `crates/fwc/tests/readme_status_pinning.rs`
- test_fn: `fwc_production_invoke_still_routes_through_host_rpc_invoke`
- proof_path: `crates/fcp-e2e/tests/v2_cutover_mechanism_e2e.rs`
- pending: "operational cutover tracked by flywheel_connectors-hr0rr.2 (Phase A) + angoc.17 (Phase A.bis)"

### 16. Computation Migration

- claim: Computation Migration
- status: PROVEN
- code_path: `crates/fcp-kernel/src/computation_migration.rs`
- test_path: `crates/fcp-e2e/tests/computation_migration_reference.rs`
- test_fn: `migrate_resume_whisper_transcribe_criu_checkpoint_migration_resume_completion`
- proof_path: (none — operational reference proof)
- no_formal_model_reason: "CRIU checkpoint handoff + byte-equivalent completion proven end-to-end"

### 17. Capability Token Typestate

- claim: Capability Token Typestate
- status: PROVEN
- code_path: `crates/fcp-core/src/capability.rs`
- test_path: `crates/fcp-conformance/tests/capability_typestate_connector_boundary_dja9u.rs`
- test_fn: `dja9u_no_new_connectors_use_legacy_verify_alias_at_invoke_boundary`
- proof_path: `crates/fcp-core/tests/typestate_compile_fail.rs`
- no_formal_model_reason: "forward-only ratchet + compile-fail tests enforce the typestate ladder"

### 18. Post-Quantum Zone Keys

- claim: Post-Quantum Zone Keys
- status: PROVEN
- code_path: `crates/fcp-core/src/zone_keys.rs`
- test_path: `crates/fcp-e2e/tests/v3_v4_mixed_migration_e2e.rs`
- test_fn: `v3_v4_mixed_migration_s1_full_ladder_decisions_match_phase_semantics`
- proof_path: (none — KAT + mixed-migration E2E)
- no_formal_model_reason: "X-Wing/ML-DSA-65 KATs + V3/V4 mixed-migration harness"

### 19. Multi-Method Provider Auth

- claim: Multi-Method Provider Auth
- status: PROVEN
- code_path: `crates/fcp-provider-auth/src/lib.rs`
- test_path: `crates/fcp-provider-auth/src/lib.rs`
- test_fn: `provider_helpers_build_device_code_profiles_and_validate_inputs`
- proof_path: (none — unit-test matrix over auth methods)
- no_formal_model_reason: "API key, SigV4, JWT refresh, device-code, PKCE, refresh-token, setup-token unit matrix"

### 20. Credential Pooling

- claim: Credential Pooling
- status: PROVEN
- code_path: `crates/fcp-host/src/credentials.rs`
- test_path: `crates/fcp-e2e/tests/credential_pool_e2e.rs`
- test_fn: `credential_pool_e2e_emits_redacted_round_robin_cooldown_and_exhaustion_evidence`
- proof_path: (none — operational E2E)
- no_formal_model_reason: "priority/strategy/cooldown/lease pooling verified by redaction-safe E2E"

### 21. Multi-Host Singleton Writers (HRW)

- claim: Multi-Host Singleton Writers (HRW)
- status: PROVEN
- code_path: `crates/fcp-core/src/lease.rs`
- test_path: `crates/fcp-e2e/tests/multi_node_failover.rs`
- test_fn: `deterministic_local_mesh_failover_smoke_covers_all_a4_chaos_modes`
- proof_path: (none — operational failover replay harness)
- no_formal_model_reason: "rendezvous-hashed lease holder + launch/flush/invoke fencing proven by failover replay"

### 22. Browser Real-CDP Control Plane

- claim: Browser Real-CDP Control Plane
- status: PROVEN
- code_path: `connectors/browser/src/connector.rs`
- test_path: `connectors/browser/tests/real_browser_e2e.rs`
- test_fn: `prerequisite_detection_accepts_env_binary_and_loopback_control_worker`
- proof_path: (none — real-browser operation-matrix closeout)
- no_formal_model_reason: "Rust-owned CDP control worker + direct-CDP routing exercised against real-browser harness"

### 23. Voice-Call Multi-Provider Parity

- claim: Voice-Call Multi-Provider Parity
- status: PROVEN
- code_path: `crates/fcp-voice-call/src/lib.rs`
- test_path: `crates/fcp-voice-call/src/lib.rs`
- test_fn: `replay_keys_are_provider_prefixed_and_isolated`
- proof_path: (none — shared session/replay primitives + no-live-credential loopback)
- no_formal_model_reason: "CallAuthToken/SessionStore/replay-cache shared across Twilio, Telnyx, Plivo"

### 24. Manifest Operations Conformance

- claim: Manifest Operations Conformance
- status: PROVEN
- code_path: `crates/fcp-conformance/tests/manifest_operations_conformance.rs`
- test_path: `crates/fcp-conformance/tests/manifest_operations_conformance.rs`
- test_fn: `raw_manifest_operation_harness_rejects_zero_operation_connectors`
- proof_path: (none — manifest/source drift scanner)
- no_formal_model_reason: "typed `[provides.operations.*]` coverage + runtime-const drift scanner"

## Coverage summary

- Total README rows: 24
- Rows with `code_path` + `test_path` + (`proof_path` OR `no_formal_model_reason`): 24
- Rows with formal-model proof artifact: 3 (Zone Isolation lean lattice, Capability Tokens typestate compile-fail, Symbol-First golden vectors); plus 2 pending (Threshold Owner Key, Mesh-Native cutover) tracked by named angoc beads
- Rows still `STEADY-STATE TARGET`: 1 (Mesh-Native Architecture) — has an explicit pending bead pointer (`23 PROVEN`, `0 LIMITED`, `1 STEADY-STATE TARGET`)

## Cross-references

- Formal coverage matrix: tracked by `flywheel_connectors-angoc.9.2`. The proof_path column here aligns with that matrix.
- Quarterly debiasing artifact: most recent at `docs/quarterly/2026-Q2-claims-vs-reality.md`. The K cadence epic (`flywheel_connectors-angoc.5`) keeps it current.
- Reality-check bridge plan: `docs/reality/2026-05-12-reality-check-bridge-plan.md`. Each phase epic anchors a subset of the rows above.

## Maintenance

The conformance test `master_reachability_ledger.rs` fails CI if:

- The README status table grows a new row not present here
- A cited `code_path` no longer exists on disk
- A cited `test_path` no longer exists or no longer contains the named `test_fn`
- A row has neither `proof_path` nor `no_formal_model_reason`

When the README adds a row, update this ledger in the same commit. When a status flips PROVEN ↔ LIMITED ↔ TARGET, update the `status` line here in the same commit.
