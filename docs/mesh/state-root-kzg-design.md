# State-Root Vector Commitments (KZG + IPA)

**Bead:** `flywheel_connectors-angoc.17.1` (Phase A.bis.1)
**Modules:** `crates/fcp-crypto/src/vector_commit/{mod,kzg,ipa}.rs`, `crates/fcp-mesh/src/state_root.rs`
**Conformance:** `crates/fcp-conformance/tests/state_root_kzg_conformance.rs`

## Problem

A `ConnectorStateRoot` summarizes a zone's connector state slots. To prove
that slot `i` holds a specific value without shipping the whole vector, FCP
uses a **vector commitment**: one short commitment, and a per-slot inclusion
proof that is either constant-size (KZG) or logarithmic (IPA).

## Two interchangeable schemes

Both implement `fcp_crypto::vector_commit::VectorCommitmentScheme` over a
fixed power-of-two domain, committing to a vector of 32-byte slot values.

### KZG10 over BLS12-381 (`kzg.rs`)

The vector is interpreted as evaluations of a polynomial `f` over the `n`-th
roots of unity: `values[i] = f(ω^i)`. An inverse NTT (`O(n log n)`) recovers
the coefficients; committing is `C = [f(τ)]₁` (one G1 element). An inclusion
proof for slot `i` is the KZG opening `π = [q(τ)]₁` with
`q(X) = (f(X) − values[i])/(X − ω^i)`. Verification is the pairing check

```
e(C − values[i]·[1]₁, [1]₂) = e(π, [τ]₂ − ω^i·[1]₂)
```

— **two pairings, independent of `n`**. Commitment and proof are each 48
bytes.

**Trusted setup.** KZG needs a structured reference string (powers of a
secret τ). `KzgSrs::from_ceremony` ingests a real powers-of-tau transcript;
`KzgSrs::insecure_deterministic` derives τ from a seed for tests only (τ is
recoverable, so it is explicitly marked insecure). Anyone who knows τ can
forge openings — hence the transparent fallback below for zones that ban
ceremonies.

### Bulletproofs IPA over ristretto255 (`ipa.rs`)

Transparent — **no trusted setup**. Generators `G_i`, `H_i`, `Q` are hashed
from domain-separated labels (nothing-up-my-sleeve). A commitment is a
ristretto Pedersen vector commitment `C = Σ values[i]·G_i` (32 bytes).
Proving slot `index = y` reduces to the inner product `⟨values, e_index⟩ = y`,
argued in `⌈log2 n⌉` folding rounds (Bünz et al., "Bulletproofs", IEEE S&P
2018 §3 — the same argument underlies Halo2's polynomial commitment). The
proof is `2·⌈log2 n⌉` 32-byte points plus two 32-byte scalars; the
logarithmic (round) part is exactly `2·⌈log2 n⌉·32` bytes. Verification uses
the standard single-MSM check with the `s_i` product vector
(`1/s_i = s_{n−1−i}`).

## Cross-tier behavior

`StateRootScheme` selects a scheme per zone. A proof produced under one
scheme does **not** verify under the other: `StateRootCommitter::verify`
returns `VcError::SchemeMismatch` when the commitment/proof scheme differs
from the verifier's. The holder then re-proves over the same slot bytes
under the verifier's scheme. Slot values are shared as bytes; each scheme
reduces them into its own scalar field deterministically, so the underlying
data is identical while the cryptographic objects are not.

## Failure-injection fallback

Every `StateRootCommitment` carries an always-present BLAKE3 **Merkle root**
alongside the vector commitment. If the vector commitment fails to decode (a
corrupted byte), `verify` returns `VcError::BadCommit`; the caller falls back
to the per-slot `MerkleTree` inclusion proof and emits an audit-chain alert.
The vector commitment is an availability/size optimization layered over the
Merkle root, never the sole integrity anchor.

## Performance targets

| Operation | Target (p99) | Notes |
|-----------|--------------|-------|
| KZG verify | < 2 ms | two pairings, `n`-independent |
| IPA verify | < 12 ms | single MSM of `~2n` points |

Targets are release-profile numbers (`crates/fcp-crypto/benches/vector_commit.rs`).
Pairing and ristretto MSM arithmetic is 10–50× slower at `opt-level = 0`, so
unit tests assert correctness only; the `n = 1024` IPA unit test is
deliberately the slowest. Verification emits `verify_us` on the
`fcp.mesh.state_root` tracing target so production drift is observable
(doctor thresholds: KZG > 5 ms, IPA > 25 ms).

## Logging contract

- `INFO` per commit on `fcp.mesh.state_root`: `{scheme, n_slots, commit_hash}`.
- Per-verify debug on `fcp.mesh.state_root`:
  `{scheme, n_slots, proof_size_bytes, verify_us, accepted}`.

## Wire sizes

| Object | KZG | IPA |
|--------|-----|-----|
| Commitment | 48 B (one G1) | 32 B (one ristretto point) |
| Inclusion proof | 48 B (one G1) | `2·⌈log2 n⌉·32 + 64` B |

## Deferred (follow-on work)

- `fwc doctor --probe state_root_vc` (`scheme_in_use`, `recent_verify_p99_us`,
  `fallback_active`) and `fwc mesh state-root recompute` /
  `fwc mesh state-root scheme --show` operator commands.
- A real powers-of-tau ceremony transcript for production KZG zones (the
  code path `KzgSrs::from_ceremony` exists; the ceremony artifact is an
  operational deliverable outside this repo). IPA zones need none.
- Wiring `StateRootCommitment` into the live `ConnectorStateRoot` object and
  its gossip path once the mesh-native cutover (`hr0rr.2`) reaches that
  surface.
