# Retained invoke-journal export and follow

`fwc-audit-export` reads the host's existing `FCPAUD1` length-framed journal
without entering writer recovery. It is a companion executable in the `fwc`
package; it does not change the existing `fwc audit tail` command or add a
remote admin endpoint. It uses the public `fcp-host` snapshot/follower readers
and the existing request-scoped `fcp-audit` explainer.

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

JSONL sends only one reserialized `AuditEntry` per stdout line. Snapshot
provenance is a single JSON line on stderr. Bundle and explanation formats
include their provenance in stdout JSON. The original framed byte
representation is not the output representation: the fingerprint describes the
raw input prefix, not the JSON export. Request-filtered exports are partial
histories, not complete zone-chain proofs.

## Follow complete appends

```sh
fwc-audit-export --journal /path/to/invoke.journal \
  --zone z:work --request-id SERVER_REQUEST_ID \
  --follow --format jsonl --limit 100 --idle-timeout-ms 30000
```

Following starts at genesis and drains existing records before waiting for new
ones. `--from-seq` filters output; it never skips the integrity checks on earlier
records. The reader keeps the same open file, checks independent per-zone
lineage across polls, and decodes/hashes complete frames once. It retains small
per-zone tips rather than all previous payloads, and returns at most 128 records
per batch. Input bounds remain those of the production journal, not an exact
process-memory ceiling.

`--limit N` counts matching output records, including existing history. A record
limit can stop before later history is read; it is not evidence that the entire
source is valid. Without a limit or idle timeout, the command follows until
interrupted or an error occurs. The default polling interval is 250 ms;
`--poll-interval-ms` accepts 1 through 60000. Ready backlog drains without a
polling sleep. Output is flushed before waiting so pipe consumers see progress.

The idle timeout measures monotonic time without matching records, not arbitrary
byte growth or activity in other requests. A quiet stream with previously
matched records exits successfully at this boundary. No matching records, or an
incomplete header/final frame at the boundary, exits nonzero. The check runs
between bounded polls and output writes; it is not a hard filesystem or pipe
I/O timeout. Zero limits/timeouts and follow options without `--follow` are
rejected before opening the source. Following requires JSONL, not bundle or
explanation format.

Follow provenance uses `fcp.fwc.invoke_audit_follow.v1` JSON lines on stderr,
separate from the clean entry stream on stdout. It reports the validated prefix
length/fingerprint, sampled length, cumulative validated/emitted record counts,
pending-frame state, selection, and the final `record-limit` or `idle-timeout`
stop reason. Unchanged idle polls do not repeatedly print progress.

A partial append is awaited without retaining, emitting or hashing its partial
payload. A complete malformed record, broken lineage, observed truncation or
read failure permanently stops that follower. Nothing is repaired or retried
as a new source. Earlier batches may already have been emitted: they describe
observed prefixes, not successful validation of the unread remainder. Discard
incomplete output when a downstream task requires a complete export.

Following assumes an append-only source. It does not rescan historical bytes,
so same-length rewrites or truncate-and-regrow between polls are not detected.
The fingerprint describes observed bytes over time, not guaranteed current file
contents. Rotation/replacement does not switch the pinned handle: it continues
observing the original file and may become idle. Starting another command is an
explicit new observation, not automatic continuation from a trusted checkpoint.

## Snapshot observation and safety boundaries

The snapshot reader samples the already-open file's length once, verifies
**every record in that extent before applying any output filter**, and returns
nothing if a sampled header, frame, canonical ID, sequence, hash link or clock
lineage is invalid. Corruption in a different zone cannot be filtered away. It
uses the production limits: 256 MiB per journal, 64 KiB per record, 262,144
records. These are input bounds, not exact allocator or total process-memory
ceilings. Follow mode instead validates each incremental batch before filtering
that batch, as described above.

The source is opened read-only. No directories or journals are created; no
source bytes are written, repaired, truncated, synchronized or evicted. Final
path-component symlinks and special files are refused. Unix opens also prevent
FIFO substitution from blocking before the regular-file check. The open handle
pins one source even if its pathname is later replaced. Parent-directory path
resolution remains the operator's responsibility.

On Unix, advisory writer ownership can coexist with read-only observation.
Platforms whose exclusive locks deny reads may require stopping the host or
supplying an independently obtained copy. This command does not work around
such OS refusals. Snapshot mode is finite: later appends are outside its sampled
extent. A snapshot ending inside an active append fails as incomplete; an
operator can repeat it after the append finishes or explicitly choose follow
mode. Nothing is trimmed or silently recovered.

Canonical IDs and lineage establish internal integrity, **not authenticity**.
The reader does not approve the writer's durable projection or lifecycle policy.
A complete observed frame is not proof that its writer's fsync completed. A
self-consistent forged or rolled-back file is not detected by its self-derived
fingerprint. Both modes therefore say `live: false`, `authenticity: not-verified`
and `durability: not-assessed`. They never claim a signed checkpoint, current
authority, confirmed external effects or safe retry.

Exports contain captured identities and metadata. Treat them as sensitive. Do
not redirect stdout onto the source journal: a shell can truncate its output
target before the program starts. The program itself opens no output files.
Snapshot validation failures emit no stdout; follow failures may occur after
earlier prefixes were emitted. Output I/O failures exit nonzero and can leave a
partial export that must be discarded. Diagnostic errors omit supplied paths,
parser input and provider text.

## Verification commands

```sh
rch exec -- cargo test -p fcp-host --lib invoke_audit_snapshot
rch exec -- cargo test -p fwc --bin fwc-audit-export
rch exec -- cargo fmt --check
```

Tests use the real `InvokeAuditChain` writer as well as malformed framed inputs.
They cover writer ownership, closed journals, sampled boundaries, interleaved
zones, corruption, request filtering, JSONL/bundle consumer compatibility and
direct explanations. Follower tests also cover fragmented appends, bounded
backlog, cumulative fingerprint parity, cross-poll lineage, sticky failures,
path replacement and deterministic idle scheduling. They were authored but not
executed in the editing session because Cargo/Rust/RCH were unavailable there.
