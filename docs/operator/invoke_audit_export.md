# Retained invoke-journal export

`fwc-audit-export` reads the host's existing `FCPAUD1` length-framed journal
without entering writer recovery. It is a companion executable in the `fwc`
package; it does not change the existing `fwc audit tail` command or add a
remote admin endpoint. It uses the public `fcp-host` snapshot reader and the
existing request-scoped `fcp-audit` explainer.

Build and run from a checked-out workspace:

```sh
cargo build -p fwc --bin fwc-audit-export
./target/debug/fwc-audit-export --journal /path/to/invoke.journal --zone z:work
```

The default output is a JSON replay bundle. Its `audit_entries` can be read by
`fwc audit explain`; `source` reports the sampled byte extent, its raw-prefix
BLAKE3 fingerprint, record counts, and whether filters selected only part of
that snapshot. No source path is included in the exported provenance.

To export a request or explain it directly:

```sh
fwc-audit-export --journal /path/to/invoke.journal \
  --zone z:work --request-id SERVER_REQUEST_ID --format jsonl

fwc-audit-export --journal /path/to/invoke.journal \
  --zone z:work --request-id SERVER_REQUEST_ID --format explanation
```

`--request-id` means the host's server-assigned `operation_id`, not the client
correlation and not the connector method. Client correlations can be shared by
several requests. Both request selection and `--from-seq N` require `--zone`.
The sequence lower bound is inclusive. Explanations require an explicit zone
and request, and reject a sequence filter rather than silently omit causal
history. Captured denials, dispatch errors and mesh-relay uncertainty retain the
existing explainer's distinct outcomes.

JSONL sends only one reserialized `AuditEntry` per stdout line. Its provenance
is a single JSON line on stderr. Bundle and explanation formats include their
provenance in stdout JSON. The original framed byte representation is not the
output representation: the fingerprint describes the raw input prefix, not the
JSON export. Request-filtered exports are partial histories, not complete
zone-chain proofs.

## Observation and safety boundaries

The reader samples the already-open file's length once, verifies **every record
in that extent before applying any output filter**, and returns nothing if a
sampled header, frame, canonical ID, sequence, hash link or clock lineage is
invalid. Corruption in a different zone cannot be filtered away. It uses the
production limits: 256 MiB per journal, 64 KiB per record, 262,144 records. These
are input bounds, not exact allocator or total process-memory ceilings.

The source is opened read-only. No directories or journals are created; no
source bytes are written, repaired, truncated, synchronized or evicted. Final
path-component symlinks and special files are refused. Unix opens also prevent
FIFO substitution from blocking before the regular-file check. The open handle
pins one source even if its pathname is later replaced. Parent-directory path
resolution remains the operator's responsibility.

On Unix, advisory writer ownership can coexist with read-only observation.
Platforms whose exclusive locks deny reads may require stopping the host or
supplying an independently obtained copy. This command does not work around
such OS refusals. It is not a follow loop: later appends are outside the sampled
extent. A sample ending inside an active append fails as incomplete; an
operator can repeat the command after the append finishes. Nothing is trimmed
or silently recovered.

Canonical IDs and lineage establish internal integrity, **not authenticity**.
The reader does not approve the writer's durable projection or lifecycle policy.
A complete observed frame is not proof that its writer's fsync completed. A
self-consistent forged or rolled-back file is not detected by its self-derived
fingerprint. Output therefore says `live: false`, `authenticity: not-verified`
and `durability: not-assessed`. It never claims a signed checkpoint, current
authority, confirmed external effects or safe retry.

Exports contain captured identities and metadata. Treat them as sensitive. Do
not redirect stdout onto the source journal: a shell can truncate its output
target before the program starts. The program itself opens no output files.
Validation failures emit no stdout; output I/O failures exit nonzero and can
leave a partial export that must be discarded. Diagnostic errors omit supplied
paths, parser input and provider text.

## Verification commands

```sh
rch exec -- cargo test -p fcp-host --lib invoke_audit_snapshot
rch exec -- cargo test -p fwc --bin fwc-audit-export
rch exec -- cargo fmt --check
```

Tests use the real `InvokeAuditChain` writer as well as malformed framed inputs.
They cover writer ownership, closed journals, sampled boundaries, interleaved
zones, corruption, request filtering, JSONL/bundle consumer compatibility and
direct explanations. They were authored but not executed in the editing
session because Cargo/Rust/RCH were unavailable there.
