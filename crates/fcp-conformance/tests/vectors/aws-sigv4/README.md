# AWS SigV4 signing test vectors (vendored)

Consumed by `crates/fcp-conformance/tests/aws_sigv4_official_vectors.rs` (bead
`br-3wt77`).

## Provenance

| | |
|---|---|
| Upstream | [`awslabs/aws-c-auth`](https://github.com/awslabs/aws-c-auth) — AWS's own C signing library |
| Path | `tests/aws-signing-test-suite/v4` |
| Commit | `3281f8692e6fd10562c4585a4dded5c16b322698` |
| Vendored | 2026-07-26 |
| Cases | 38 |

Files are copied **verbatim**. Nothing here is hand-written, reformatted, or
derived from our own implementations — a vector generated from the code under
test proves nothing. If a case needs to change, re-vendor from upstream and
update the commit above; do not edit the fixtures in place.

## Why vendored rather than fetched

Tests must not depend on network reachability, and a signing corpus that can
change under you is not a fixture. Pinning the upstream commit also means a
divergence is always attributable: either our signer changed or the pin moved.

## Per-case layout

Only the files the harness consumes are vendored:

| File | Role |
|---|---|
| `request.txt` | Raw HTTP/1.1 request: request line, `Name:value` headers, blank line, body |
| `context.json` | Credentials, `region`, `service`, `timestamp`, `normalize`, `sign_body` |
| `header-canonical-request.txt` | Expected canonical request (AWS "Task 1") |
| `header-string-to-sign.txt` | Expected string to sign (AWS "Task 2") |
| `header-signature.txt` | Expected hex signature (AWS "Task 3") |

The upstream cases also carry `query-*` variants (presigned/query-string
signing) and `header-signed-request.txt`. Those are deliberately **not**
vendored yet: nothing exercises them, and vendoring fixtures no test reads
would misrepresent the coverage. Add them together with the presigning
assertions that consume them.

## Reading the fixtures

Two `context.json` fields carry most of the semantics:

- **`normalize`** — whether AWS applies RFC 3986 dot-segment removal to the
  path before encoding. `false` is the S3 profile. The corpus has 31 `true` and
  7 `false`; a test asserts both remain represented.
- **`sign_body`** — whether `x-amz-content-sha256` belongs in the signed header
  set. Only the two `post-x-www-form-urlencoded*` cases set it.

Getting either mapping wrong makes every downstream assertion weaker while
still looking green, so the harness checks its own parser against a
hand-verified case before it checks any signer.
