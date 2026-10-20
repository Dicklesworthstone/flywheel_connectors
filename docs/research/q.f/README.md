# Phase Q.F — `io_uring` Dispatch & `AF_XDP` RaptorQ Symbol Shipping

- **Bead**: `flywheel_connectors-angoc.11.10` (Parent: `flywheel_connectors-angoc.11`)
- **EV Score**: `61 / 100` (Rank 7 — `2026-Q4 Deferred` per [`docs/architecture/alien_graveyard_q3_2026.md`](../../architecture/alien_graveyard_q3_2026.md))
- **Status**: Deferred to 2026-Q4; cross-platform `asupersync` reactor active in production.

## Scope & Deferral Rationale

`Q.F` proposes Linux-specific `io_uring` JSON-RPC dispatch and `AF_XDP` kernel-bypass RaptorQ symbol shipping. Per [`docs/architecture/alien_graveyard_q3_2026.md`](../../architecture/alien_graveyard_q3_2026.md), `Q.F` scored `61/100` and was deferred to 2026-Q4 because FCP targets cross-platform parity across Linux, macOS, and Windows (`fcp-async-core` + `asupersync`).

## Active Fallback & Rollback Contract

- **Production Fallback**: `fcp-async-core` (`asupersync` reactor) provides portable, zero-unsafe-app-code async I/O dispatch across Linux (`epoll`), macOS (`kqueue`), and Windows (`IOCP`), meeting all README p99 local and tailnet invoke latency targets.
- **Conformance Gate**: [`crates/fcp-conformance/tests/alien_graveyard_q3_completeness.rs`](../../../crates/fcp-conformance/tests/alien_graveyard_q3_completeness.rs).
