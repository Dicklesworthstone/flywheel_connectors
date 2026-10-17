# Wesolowski VDF Rate-Limiting on Owner-Key Operations

Bead: `flywheel_connectors-angoc.17.5` (Phase A.bis.5)

## Problem & Motivation

Owner-key operations (`z:owner` key rotation, emergency policy overrides, root capability grants) are the highest-privilege mutations in the Flywheel Connector Protocol. Even if an attacker compromises an active owner session or signing proxy, we want a mechanical, cryptographic rate limit capping owner-key actions at $\le 100$ actions/hour without relying solely on mutable wall-clock counters.

## Cryptographic Construction (Wesolowski EUROCRYPT 2019)

Implemented in [`crates/fcp-crypto/src/vdf/wesolowski.rs`](../../crates/fcp-crypto/src/vdf/wesolowski.rs) as a pure-Rust `#![forbid(unsafe_code)]` module with zero external C/GMP dependencies:

1. **Group representation:** 512-bit signed quadratic-residue quotient $(\mathbb{Z}/N\mathbb{Z})^\times / \{\pm 1\}$ with $N = 2^{512} - 569$, where each equivalence class $\{x, N - x\}$ is canonically represented by $\min(x, N - x)$ in 64 bytes (`VDF_ELEMENT_BYTES = 64`).
2. **Evaluation (`WesolowskiVdf::eval`):**
   - Deterministically map challenge $x$ via `blake3` XOF (`FCP-WESOLOWSKI-VDF-GROUP-GEN-V1`) to generator $g \in G$.
   - Perform $T$ sequential squarings: $y = g^{2^T} \bmod N$.
   - Derive a 64-bit Fiat-Shamir prime challenge $\ell = \text{HashToPrime}(g, y, T)$ using `blake3` (`FCP-WESOLOWSKI-VDF-FIAT-SHAMIR-PRIME-V1`) and deterministic 12-base Miller-Rabin primality testing.
   - Compute witness $\pi = g^{\lfloor 2^T / \ell \rfloor} \bmod N$ via streaming long division.
   - Output `VdfProof` where witness $\pi$ is 64 bytes and compact bundle $(y \parallel \pi)$ is 128 bytes (`<= 128B` cap).
3. **Verification (`WesolowskiVdf::verify`):**
   - Reject degenerate or non-canonical group elements.
   - Recompute $\ell = \text{HashToPrime}(g, y, T)$ and $r = 2^T \bmod \ell$ in $O(\log T)$ steps.
   - Check $\pi^\ell \cdot g^r \equiv \pm y \pmod N$ using 64-step Shamir simultaneous exponentiation (< 1ms on x86_64 baseline, well below the `< 5ms` p99 budget).

## Host Rate-Limit Gate (`OwnerKeyVdfRateGate`)

Implemented in [`crates/fcp-host/src/owner_key/vdf_gate.rs`](../../crates/fcp-host/src/owner_key/vdf_gate.rs):

- Maintains a sliding 1-hour window (`3600s`) of accepted owner-key operations and a replay set of consumed challenge digests.
- Enforces `DEFAULT_OWNER_KEY_HOURLY_CAP = 100` operations/hour.
- On burst attacks exceeding 100 ops/hour, rejects excess submissions with `OwnerKeyGateDecision::RejectedRateCapExceeded` and emits an `OwnerKeyRateAuditAlert` (`kind: "rate_cap_exceeded"`).
- On mutated or invalid VDF proofs, rejects with `OwnerKeyGateDecision::RejectedInvalidVdf { fallback_manual_approve: true, .. }` and emits an audit alert (`kind: "invalid_vdf_proof"`).
- Surfaces `VdfRateDoctorReport` for `fwc doctor --probe vdf_rate` with `{ops_last_hour, vdf_T_required, baseline_eval_ms, gate_triggered_count}` and remediation commands `["fwc owner-key audit --since 1h", "fwc vdf recalibrate"]`.
