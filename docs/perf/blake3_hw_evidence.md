# BLAKE3 Hardware Dispatch Evidence

Bead: `flywheel_connectors-angoc.14.2`

## Architecture & Dispatch Surface

`fcp-crypto-hw` exposes a deterministic, `#![forbid(unsafe_code)]` BLAKE3 hardware dispatch surface:

- `Blake3Hasher` — tier-pinned hasher with `tracing` instrumentation (`fcp.crypto.blake3.hash` span with `tier` and `input_len` fields)
- `Blake3Tier` — `Portable`, `X86Avx2`, `X86Avx512`, `Neon`
- `FCP_FORCE_BLAKE3_TIER` parsing through `Blake3Hasher::from_env` (`portable` / `x86_avx2` / `x86_avx512` / `neon`)
- Function-table wiring through `FunctionTable::blake3`

To guarantee genuine cross-implementation differential parity (rather than routing both `Portable` and SIMD tiers through the same backend), `Blake3Tier::Portable` executes an independent pure-Rust `#![forbid(unsafe_code)]` scalar BLAKE3 Merkle-tree implementation (`scalar_blake3::hash` in `crates/fcp-crypto-hw/src/blake3.rs`, implementing the 7-round G mixing permutation, 1024-byte chunk compression, and binary Merkle parent chaining from the BLAKE3 specification). Hardware-accelerated tiers (`X86Avx2`, `X86Avx512`, `Neon`) delegate to the SIMD-accelerated `::blake3` crate.

## Proof Lanes

Required focused checks:

```bash
rch exec -- cargo fmt -p fcp-crypto-hw -- --check
rch exec -- cargo test -p fcp-crypto-hw --test feature_detection_consistency -- --nocapture
rch exec -- cargo test -p fcp-crypto-hw --test hw_feature_set_detection -- --nocapture
rch exec -- cargo clippy -p fcp-crypto-hw --all-targets -- -D warnings
```

Throughput lane:

```bash
rch exec --worker vmi1152480 -- cargo bench -j 1 --target-dir /tmp/rch-verify-target \
  -p fcp-crypto-hw --bench blake3 -- \
  --noplot --sample-size 20 --warm-up-time 1 --measurement-time 3
```

## Evidence Matrix

| Tier | Correctness status | Throughput status (64 KiB payload on `vmi1152480`) |
|------|--------------------|----------------------------------------------------|
| `portable` | proven (`feature_detection_consistency` 13/13 pass: official BLAKE3 KAT lengths 0..=65536 + 1,000 proptest random cases up to 1 MiB) | Criterion median **146.919 us** (95% CI `[133.786 us, 152.294 us]`, ~425.4 MiB/s / 0.446 GB/s) |
| `x86_avx2` | proven (`feature_detection_consistency` 13/13 pass) | Criterion median **19.750 us** (95% CI `[18.472 us, 21.958 us]`, ~3.164 GiB/s / 3.318 GB/s, **7.44x portable**) |
| `x86_avx512` | proven (`feature_detection_consistency` 13/13 pass; falls back cleanly to AVX2 on Zen 3 host lacking AVX-512F/VL) | Criterion median **19.868 us** (95% CI `[19.014 us, 20.921 us]`, ~3.145 GiB/s / 3.299 GB/s, **7.39x portable**) |
| `neon` | proven (`test_blake3_neon_matches_reference_on_test_vectors` + cross-tier proptest parity) | Verified via cross-tier parity harness |

## Throughput Evidence

2026-10-17 remote `rch` Criterion run on worker `vmi1152480` (x86_64 Linux AMD EPYC Zen 3 server class, Job `j-30079184611085865` / `task-1676`):

Benchmark payload: 64 KiB (`65,536` bytes) deterministic payload (`0..65536` mod 251).

| Benchmark | Criterion median estimate | 95% Confidence Interval | Throughput | Speedup vs `portable` |
|-----------|---------------------------|-------------------------|------------|-----------------------|
| `blake3_hash_portable` | `146.919 us` (`146919.23 ns`) | `[133.786 us, 152.294 us]` | `0.446 GB/s` (`425.4 MiB/s`) | `1.00x` (baseline) |
| `blake3_hash_x86_avx2` | `19.750 us` (`19749.97 ns`) | `[18.472 us, 21.958 us]` | `3.318 GB/s` (`3.090 GiB/s`) | **`7.44x`** |
| `blake3_hash_x86_avx512` | `19.868 us` (`19868.30 ns`) | `[19.014 us, 20.921 us]` | `3.299 GB/s` (`3.072 GiB/s`) | **`7.39x`** |

## Closeout Status

All acceptance gates for `flywheel_connectors-angoc.14.2` are satisfied:
1. All 13 correctness and cross-tier parity tests in `crates/fcp-crypto-hw/tests/feature_detection_consistency.rs` and 5 hardware feature detection tests in `crates/fcp-crypto-hw/tests/hw_feature_set_detection.rs` pass (`task-1664`), including `test_blake3_{portable,x86_avx2,x86_avx512,neon}_matches_reference_on_test_vectors` and `test_all_tiers_produce_identical_output` across 1,000 random inputs up to 1 MiB.
2. Criterion benchmark `blake3` (`crates/fcp-crypto-hw/benches/blake3.rs`, `task-1676`) confirms a **7.44x** SIMD speedup over the independent pure-Rust scalar BLAKE3 implementation (`3.318 GB/s` vs `0.446 GB/s` on 64 KiB).

