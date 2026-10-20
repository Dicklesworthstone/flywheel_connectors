# PQ Signing Overhead Evidence

Bead: `flywheel_connectors-angoc.8.2` / `flywheel_connectors-angoc.8.3`

This document pins the `pq_signing` StatPack schema and the conformance gate
for the hybrid verifier budget. The gate validates live artifacts from
`artifacts/perf/pq_signing/<machine-class>-<date>-<sha>.json`. All three
required machine classes (`csd`, `contabo`, and `laptop`) now have live
10,000-sample `fcp.pq-signing-overhead.v1` StatPack artifacts committed under
`artifacts/perf/pq_signing/`.

Budget: hybrid verify p99 <= 2.0 ms for `csd`, `contabo`, and `laptop`.

Live evidence status:

| Machine class | Status | Evidence |
| --- | --- | --- |
| `csd` | live, 2026-10-20 UTC | `artifacts/perf/pq_signing/csd-20261020-2320d4e17.json`: p99 0.13448551 ms, p99 CI upper 0.13669661000000016 ms, verdict `pass` |
| `contabo` | live, 2026-10-20 UTC | `artifacts/perf/pq_signing/contabo-20261020-2320d4e17.json`: p99 0.1528341 ms, p99 CI upper 0.15360551 ms, verdict `pass` |
| `laptop` | live, 2026-10-20 UTC | `artifacts/perf/pq_signing/laptop-20261020-2320d4e17.json`: p99 1.6252200000000003 ms, p99 CI upper 1.8435000000000001 ms, verdict `pass` |

Reproduction command:

```bash
env -u CARGO_TARGET_DIR RCH_REQUIRE_REMOTE=1 RCH_BUILD_TIMEOUT_SEC=2400 \
  rch exec -- env CARGO_INCREMENTAL=0 \
  cargo bench -j 2 -p fcp-crypto --bench hybrid_verify -- \
    --samples 10000 \
    --machine-class <machine-class> \
    --git-sha "$(git rev-parse --short HEAD)" \
    --statpack-out "artifacts/perf/pq_signing/<machine-class>-$(date -u +%Y%m%d)-$(git rev-parse --short HEAD).json"
```

<!-- statpack:csd -->

```json
{
  "artifact_path": "artifacts/perf/pq_signing/csd-20261020-2320d4e17.json",
  "baseline_classical_verify": {
    "bootstrap_ci": [
      0.036927281399999866,
      0.03710938960000016
    ],
    "mean": 0.03701756740000005,
    "p50": 0.035077000000000004,
    "p99": 0.05790070000000001,
    "p999": 0.06909379600000057,
    "sample_count": 10000,
    "std": 0.004881172882999401,
    "tail_amp": 0.49041548916260513,
    "welch_t": 0.0
  },
  "bootstrap_p99_ci_ms": [
    0.1308727000000001,
    0.13669661000000016
  ],
  "git_sha": "2320d4e17",
  "machine_class": "csd",
  "sample_count": 10000,
  "schema": "fcp.pq-signing-overhead.v1",
  "verdict": "pass",
  "verify_hybrid": {
    "bootstrap_ci": [
      0.0966230663000013,
      0.09696661680000171
    ],
    "mean": 0.09679705090000112,
    "p50": 0.09408799999999999,
    "p99": 0.13448551,
    "p999": 0.18331927500000048,
    "sample_count": 10000,
    "std": 0.009109402366393562,
    "tail_amp": 1.208831064092823,
    "welch_t": 578.4318224016649
  },
  "welch_p": 0.0
}
```

<!-- statpack:contabo -->

```json
{
  "artifact_path": "artifacts/perf/pq_signing/contabo-20261020-2320d4e17.json",
  "baseline_classical_verify": {
    "bootstrap_ci": [
      0.04819210739999934,
      0.04825790029999914
    ],
    "mean": 0.04822497169999536,
    "p50": 0.047799,
    "p99": 0.056575410000000007,
    "p999": 0.059901011000000004,
    "sample_count": 10000,
    "std": 0.0017365031405715394,
    "tail_amp": 0.378924981854767,
    "welch_t": 0.0
  },
  "bootstrap_p99_ci_ms": [
    0.152394,
    0.15360551
  ],
  "git_sha": "2320d4e17",
  "machine_class": "contabo",
  "sample_count": 10000,
  "schema": "fcp.pq-signing-overhead.v1",
  "verdict": "pass",
  "verify_hybrid": {
    "bootstrap_ci": [
      0.14107872849999956,
      0.14125746889999855
    ],
    "mean": 0.14117285760000015,
    "p50": 0.13970000000000002,
    "p99": 0.1528341,
    "p999": 0.17457512000000003,
    "sample_count": 10000,
    "std": 0.004071613060644868,
    "tail_amp": 1.6553109843841647,
    "welch_t": 2099.828233321852
  },
  "welch_p": 0.0
}
```

<!-- statpack:laptop -->

```json
{
  "artifact_path": "artifacts/perf/pq_signing/laptop-20261020-2320d4e17.json",
  "baseline_classical_verify": {
    "bootstrap_ci": [
      0.17289876,
      0.20250508000000111
    ],
    "mean": 0.1872506099999998,
    "p50": 0.1308,
    "p99": 1.2900710000000037,
    "p999": 5.903370700000504,
    "sample_count": 10000,
    "std": 0.7421188698297084,
    "tail_amp": 3.9794833994816443,
    "welch_t": 0.0
  },
  "bootstrap_p99_ci_ms": [
    1.412227000000005,
    1.8435000000000001
  ],
  "git_sha": "2320d4e17",
  "machine_class": "laptop",
  "sample_count": 10000,
  "schema": "fcp.pq-signing-overhead.v1",
  "verdict": "pass",
  "verify_hybrid": {
    "bootstrap_ci": [
      0.41080600000000184,
      0.44559432000000015
    ],
    "mean": 0.4300166299999999,
    "p50": 0.3498,
    "p99": 1.6252200000000003,
    "p999": 18.377342800000093,
    "sample_count": 10000,
    "std": 0.8648901936900183,
    "tail_amp": 13.134593153627895,
    "welch_t": 21.302023557253303
  },
  "welch_p": 0.0
}
```

Redaction note: all committed StatPack artifacts contain aggregate numeric
fields only, with no raw samples, no hostnames, and no user paths.
