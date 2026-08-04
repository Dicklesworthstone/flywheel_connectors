# BLS12-381 Threshold-Aggregate Quorum Signatures

**Bead:** `flywheel_connectors-angoc.17.4` (Phase A.bis.4)
**Modules:** `crates/fcp-crypto/src/bls/{mod,aggregate,pop}.rs`, `crates/fcp-mesh/src/quorum.rs`
**Conformance:** `crates/fcp-conformance/tests/bls_aggregate_conformance.rs`

## Problem

Quorum decisions (zone admission, capability revocation) are carried today as
per-signer Ed25519 signatures in `fcp_core::quorum::SignatureSet`: `k` signers
mean `k × (node_id + 64-byte signature + timestamp)` on the wire and `k`
verifications at every hop. For gossip-distributed quorum objects this cost is
paid per peer, per round.

## Construction

Multi-signature with proof of possession, per Boneh–Drijvers–Neven, *Compact
Multi-Signatures for Smaller Blockchains* (ASIACRYPT 2018), in the profile
standardized by draft-irtf-cfrg-bls-signature (`POP` ciphersuite):

- **Curve:** BLS12-381 via the pure-Rust `bls12_381` crate (zkcrypto, v0.8).
- **Variant:** minimal-pubkey-size — public keys in G1 (48-byte compressed),
  signatures and PoPs in G2 (96-byte compressed).
- **Hashing:** hash-to-curve XMD:SHA-256 SSWU RO with the standard DSTs:
  - signatures: `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`
  - proofs of possession: `BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`
- **Sign:** `sig_i = H_sig(msg) · sk_i`
- **Aggregate:** `sig_agg = Σ sig_i` (G2 point addition); the aggregate object
  carries the *distinct* signer-ID set (`BTreeSet`) alongside the point.
- **Verify:** `e(-g1, sig_agg) · e(Σ pk_i, H_sig(msg)) == 1` — two pairings
  and `k-1` G1 additions, independent of `k` in pairing count.

## Rogue-key defense (the PoP registry)

Plain aggregation is broken by rogue-key attacks: publishing
`pk' = g1·sk_atk − pk_victim` lets the attacker "aggregate" a signature that
implicates the victim. The defense is structural, not advisory:

1. A key becomes usable **only** by entering a `PopRegistry`, and
   `PopRegistry::register` verifies the proof of possession
   `pop = H_pop(pk_compressed) · sk` before admitting the key. A rogue key's
   PoP cannot be produced without its discrete log.
2. `aggregate()` and `verify_aggregate()` resolve signer IDs through the
   registry and return `BlsError::PopMissing` for any signer without a
   verified key. There is no code path that aggregates or verifies an
   unproven key.
3. A signer ID cannot be silently re-bound: re-registration with a different
   key returns `SignerAlreadyRegistered`; rotation requires an explicit
   `remove` (an auditable act).

Domain separation between the two DSTs means a message signature over the pk
bytes is not a valid PoP and vice versa (pinned by
`test_pop_is_domain_separated_from_signatures`).

## Quorum semantics (`fcp_mesh::quorum`)

`BlsQuorumCertificate = QuorumDecision + AggregateSignature`. Verification is
cheapest-first and fail-closed:

1. **Eligibility:** every listed signer must be in the zone's eligible set.
2. **Threshold:** the distinct-signer count (structurally distinct — the set
   is a `BTreeSet`, so one key signing N times cannot inflate the count, the
   same property enforced for the Ed25519 path in `31ed83fbd`) must satisfy
   the unchanged `fcp_core::quorum::QuorumPolicy` at the decision's
   `RiskTier`: `ZoneAdmission → Dangerous (n−f)`,
   `CapabilityRevocation → CriticalWrite (n−f)`.
3. **Pairing check** over the decision's canonical signing bytes
   (domain-prefixed, length-prefixed fields, caller-supplied nonce).

## Relationship to the Ed25519 path

This is an **additive compact path**, not a replacement. The per-signer
`SignatureSet` remains the authoritative fallback: a decision whose BLS
certificate fails verification must be re-validated through per-signer
Ed25519 signatures (or rejected). The conformance test
`failure_injection_falls_back_to_ed25519_path` pins exactly this: one
corrupted share ⇒ BLS verification fails closed ⇒ the same canonical decision
bytes still authorize via `SignatureSet` + individual Ed25519 verification.

Reasons not to hard-cut: (a) BLS verification is ~10× slower than Ed25519 per
single signature (pairings); the win is aggregate size and constant pairing
count, which only pays off for gossiped multi-signer objects; (b) ML-DSA-65
hybrid signing (`fcp-crypto/src/hybrid.rs`) covers the PQ story for
single-signer objects — BLS12-381 is *not* post-quantum, so PQ-critical zones
should keep per-signer hybrid envelopes.

## Performance targets (bead numeric targets)

| Operation | Target (p99) | Where measured |
|-----------|--------------|----------------|
| `sign` | < 800 µs | `crates/fcp-crypto/benches/bls_aggregate.rs` |
| Aggregate verify, 32 signers | < 3 ms | same bench |

Targets are release-profile numbers via Criterion (pairing math is 10–50×
slower in debug builds, so unit tests assert correctness only — never wall
time). Verification emits `verify_us` on the `fcp.crypto.bls` tracing target,
so production drift is observable (doctor-probe threshold: 8 ms).

## Logging contract

- Target `fcp.crypto.bls`: `operation` (`aggregate` / `verify_aggregate` /
  `pop_register`), `n_signers`, `agg_size_bytes` (96), `verify_us`,
  `accepted`.
- Span `fcp.crypto.bls.pop_register` around PoP verification, with
  `registry_size` as the PoP-registry size gauge (observability hook).
- Target `fcp.mesh.quorum`: `operation=verify_certificate`, `kind`,
  `zone_id`, `n_signers`, `verify_us`.

## Wire sizes (pinned by `wire_sizes_are_pinned`)

| Object | Size |
|--------|------|
| Public key (G1 compressed) | 48 B |
| Signature share / aggregate / PoP (G2 compressed) | 96 B |
| Secret key (scalar, LE canonical) | 32 B |

All byte decoders are length-invariant (wrong length rejected before point
parsing) and reject identity points; the secret-key scalar is zeroized on
drop and `[REDACTED]` in `Debug` output.

## Deferred (follow-on work)

- `fwc doctor --probe bls` (`registered_pop_count`, `missing_pop_signers`,
  `last_verify_p99_us`) and `fwc quorum pop register` / `fwc quorum verify`
  operator commands.
- Wiring `BlsQuorumCertificate` into live gossip objects (zone admission /
  emergency revocation message shapes) once the mesh-native cutover
  (`hr0rr.2`) reaches those surfaces.
