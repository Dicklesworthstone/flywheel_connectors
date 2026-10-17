# Crypto Backend Evidence

Bead: `flywheel_connectors-angoc.14.3`

## ChaCha20-Poly1305

`fcp-crypto-hw` exposes stable backend labels for ChaCha20-Poly1305:

- `scalar` — independent portable `#![forbid(unsafe_code)]` RFC 8439 ChaCha20 quarter-round + 130-bit Poly1305 reference kernel (`seal_with_portable_scalar` / `open_with_portable_scalar`)
- `x86_sse3` — hardware SIMD path via RustCrypto `chacha20poly1305`
- `x86_avx2` — hardware AVX2 path via RustCrypto `chacha20poly1305`

`FCP_CRYPTO_BACKEND=scalar` routes through the independent portable scalar RFC 8439 implementation, guaranteeing both an isolated fallback when working around SIMD issues and genuine cross-implementation differential parity in `chacha20_parity`.

## Required Proof Commands

```bash
rch exec -- cargo fmt -p fcp-crypto-hw -- --check
rch exec -- cargo test -p fcp-crypto-hw --test chacha20_parity -- --nocapture
rch exec -- cargo clippy -p fcp-crypto-hw --all-targets -- -D warnings
```

Throughput lane:

```bash
rch exec --worker vmi1152480 -- cargo bench -j 2 --target-dir /tmp/rch-verify-target \
  -p fcp-crypto-hw --bench chacha20_dispatch -- \
  --noplot --sample-size 20 --warm-up-time 1 --measurement-time 3
```

## Evidence Matrix

| Backend | Correctness status | Throughput status (16 KiB payload on `vmi1152480`) |
|---------|--------------------|----------------------------------------------------|
| `scalar` | proven (`chacha20_parity` 7/7 pass: 32 RFC 8439/golden KATs + 1,000 proptest random cases) | Criterion median **114.864 us** (95% CI `[106.714 us, 124.794 us]`, ~139.6 MiB/s) |
| `x86_sse3` | proven (`chacha20_parity` 7/7 pass) | Criterion median **18.425 us** (95% CI `[16.862 us, 19.320 us]`, **6.23x scalar**) |
| `x86_avx2` | proven (`chacha20_parity` 7/7 pass) | Criterion median **16.764 us** (95% CI `[16.220 us, 17.663 us]`, ~954.4 MiB/s, **6.85x scalar** >= 4x target) |

## Throughput Evidence

2026-10-14 remote `rch` Criterion run on worker `vmi1152480` (x86_64 Linux server class, Job `j-30064713979134008`):

Benchmark payload: 16 KiB plaintext, fixed 32-byte key, fixed 12-byte nonce, and AAD `fcp-crypto-hw-bench`.

| Benchmark | Criterion median estimate | 95% Confidence Interval | Speedup vs `scalar` |
|-----------|---------------------------|-------------------------|---------------------|
| `chacha20_poly1305_seal_scalar` | `114.864 us` (`114863.62 ns`) | `[106.714 us, 124.794 us]` | `1.00x` (baseline) |
| `chacha20_poly1305_seal_x86_sse3` | `18.425 us` (`18425.05 ns`) | `[16.862 us, 19.320 us]` | **`6.23x`** |
| `chacha20_poly1305_seal_x86_avx2` | `16.764 us` (`16763.94 ns`) | `[16.220 us, 17.663 us]` | **`6.85x`** (>= 4.0x required) |

## Closeout Status

Both acceptance gates for `flywheel_connectors-angoc.14.3` are satisfied:
1. All 7 correctness and differential parity tests in `crates/fcp-crypto-hw/tests/chacha20_parity.rs` pass against the independent portable scalar RFC 8439 kernel (`task-1447`).
2. Criterion benchmark `chacha20_dispatch` on `vmi1152480` (`task-1453`) demonstrates **6.85x** AVX2 throughput over the portable scalar fallback (exceeding the >= 4x target).
