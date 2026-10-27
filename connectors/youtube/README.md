# YouTube Connector V3 Contract

> **Status**: runtime contract documented with transcript, quota, upload, and auth-mode drift
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **YouTube Data API upstream**: https://developers.google.com/youtube/v3/docs/
> **YouTube OAuth upstream**: https://developers.google.com/youtube/v3/guides/authentication
> **YouTube quota upstream**: https://developers.google.com/youtube/v3/determine_quota_cost
> **YouTube search upstream**: https://developers.google.com/youtube/v3/docs/search/list

## Purpose

This document fixes the operator-facing contract for `fcp.youtube`. The connector exposes the YouTube Data API v3 surface implemented in this crate: search, video/channel/playlist reads, comment reads and writes, caption listing/download/upload, normalized transcript extraction, a lightweight channel analytics summary, and video upload.

The connector is intentionally a bounded YouTube Data API bridge. It is not a YouTube Studio client, Content ID client, Live Streaming workflow, channel management suite, subscriber/member manager, analytics reporting API replacement, web scraper, transcript bypass, or connector-local credential vault.

## Current Runtime Snapshot

The current crate exposes these operations:

- `youtube.search`
- `youtube.get_video`
- `youtube.list_videos`
- `youtube.get_channel`
- `youtube.list_playlists`
- `youtube.list_playlist_items`
- `youtube.list_comments`
- `youtube.post_comment`
- `youtube.get_captions`
- `youtube.get_caption_transcript`
- `youtube.get_transcript`
- `youtube.upload_caption`
- `youtube.get_analytics`
- `youtube.upload_video`

Important runtime truths the contract preserves:

- Package and binary name are `fcp-youtube`.
- Runtime `BaseConnector` ID is `youtube`.
- Manifest connector ID is `fcp.youtube`.
- Configuration accepts exactly one auth family:
  - direct `api_key`
  - shared Google auth source (`credential_id`, access token/refresh token fields, credentials file, encrypted local profile, or default/application-default credentials)
- `service_selector` defaults to `youtube` and must resolve to `youtube:v3` through `fcp-google-discovery`.
- Default API URL is `https://www.googleapis.com/youtube/v3`.
- `base_url` may be overridden for deterministic loopback tests.
- Direct API-key mode appends `key` as a query parameter.
- Shared Google auth mode uses the shared Google executor and may be bearer-token backed or secretless `credential_id` backed.
- `credential_id` mode performs no local live provider check; `self_check()` degrades with `credential_injection_required` until the host egress proxy injects credentials.
- Runtime HTTP and request-context timeouts are `30 seconds` for ordinary requests and `600 seconds` for bounded video uploads.
- Runtime retry policy uses `max_retries = 2`.
- Runtime handshake returns a SHA-256 hash of the bundled `manifest.toml`.
- Runtime handshake advertises no streaming and no replay.
- Runtime verifies a bound capability token before provider dispatch.
- Runtime `invoke` uses `operation`, not `operation_id`.
- `health()` is local configuration/metrics state.
- `self_check()` calls `search?part=id&maxResults=1&q=test` in direct-checkable auth modes.
- Transcript operations return taint/provenance metadata because captions and transcripts are provider/user-generated content.

## Drift Visible In This Checkout

This README documents runtime truth and keeps current drift visible:

- `youtube.upload_video` sends real `multipart/related` metadata and decoded video bytes to `/upload/youtube/v3/videos` on the configured origin. It supports files up to 16 MiB in one request; resumable sessions and larger-file streaming are not implemented.
- Manifest allows `youtubeanalytics.googleapis.com` for `youtube.get_analytics`, but runtime currently aggregates channel/video statistics from Data API calls instead of using the full YouTube Analytics API.
- `youtube.upload_video` rejects API-key mode locally during invoke and simulate. Comment and caption writes still rely on the provider to reject insufficient credentials. All three write operations require user-authorized OAuth in real YouTube operation.
- Runtime approval metadata marks write operations as dangerous/interactive in the manifest and introspection, but connector-local invoke enforcement is capability-token based rather than an approval workflow.
- There is no tracked connector verification shell script yet.
- `youtube.get_transcript` uses official caption list/download paths and SRT normalization. It does not scrape watch pages, use unofficial transcript endpoints, or bypass YouTube Data API auth/quota behavior.

A follow-up parity bead should add a tracked verification bundle, implement resumable upload sessions for larger videos, decide whether `youtube.get_analytics` should integrate the Analytics API or remain a Data API summary, and make approval enforcement responsibilities explicit.

## First-Slice Scope

The current YouTube README slice documents the existing runtime surface:

- direct API-key and shared Google auth configuration
- service-selector validation, base URL policy, timeout, retry, provider error, and secretless credential-injection behavior
- Data API search, video, channel, playlist, comments, captions, transcript, summary analytics, caption upload, comment post, and video upload operations
- bound capability-token verification and resource URI derivation during `invoke` and `simulate`
- doctor, health, self-check, simulate, introspect, shutdown, redaction posture, and deterministic tests
- drift around OAuth-only mutations, quota cost, upload protocol, and the analytics summary facade

## Auth And Zone Boundary

- Authentication mechanisms: YouTube Data API key, shared Google bearer credentials, or host credential reference.
- Runtime does not implement OAuth onboarding, consent screens, token refresh UX, Google Cloud project provisioning, quota increase workflow, service-account linking, channel ownership checks, Content ID auth, or connector-local credential storage.
- YouTube Data API OAuth docs state that private user-data operations use OAuth 2.0 and that service-account auth is not supported for YouTube accounts.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden source zone: `z:public`.
- Capability families:
  - `youtube.read`
  - `youtube.write`
- YouTube search results, comments, captions, transcripts, channel metadata, video metadata, analytics summaries, uploaded captions, uploaded video bytes, and provider errors can expose public but hostile content, private account state, or PII. Do not log API keys, bearer tokens, credential IDs, raw uploaded videos, raw transcripts/comments in shared artifacts, provider response bodies, or Google account identifiers.

## Network And Runtime Invariants

- Default runtime API URL: `https://www.googleapis.com/youtube/v3`.
- Live production hosts in manifest:
  - `www.googleapis.com`
  - `youtubeanalytics.googleapis.com` for the analytics summary operation
  - `upload.googleapis.com` for upload-video policy
- Live port: `443`.
- Runtime endpoint families:
  - `GET /search`
  - `GET /videos`
  - `GET /channels`
  - `GET /playlists`
  - `GET /playlistItems`
  - `GET /commentThreads`
  - `POST /commentThreads`
  - `GET /captions`
  - `GET /captions/{caption_id}`
  - `POST /captions`
  - `POST /videos?uploadType=multipart&part=snippet,status`
- Runtime URL construction percent-encodes query and path inputs where implemented.
- Runtime video URL parsing accepts standard YouTube watch, mobile, shorts, embed, live, and youtu.be shapes and extracts an 11-character video ID.
- Transcript normalization enforces `max_bytes` and `max_segments` bounds and parses SRT-style timestamp blocks.
- Runtime maps unauthorized/forbidden provider errors, not found, rate limit, retryable transport/server failures, JSON errors, and API failures through the connector error taxonomy.
- Manifest live-operation policy requires TLS/SNI, denies localhost, private ranges, tailnet ranges, and IP literals, and permits no redirects.
- Sandbox profile is `strict`, with `256 MB` memory, `50%` CPU, `660000 ms` wall-clock timeout, no exec, and no ptrace. The wall-clock budget accommodates the ten-minute video-upload deadline and shutdown.
- The connector does not open inbound sockets.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `youtube.read` | Search, read video/channel/playlist/comment metadata, inspect captions, download/normalize transcripts, and produce a Data API based channel summary. |
| `youtube.write` | Post public comments, upload caption tracks, and upload videos. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Required input |
|-----------|----------------|------------|------------|-----------|-------------|----------------|
| `youtube.search` | `GET /search?part=snippet&q=...` | `youtube.read` | `Safe` | `Low` | `Strict` | `query`; optional `max_results`, `type`. |
| `youtube.get_video` | `GET /videos?id=...` | `youtube.read` | `Safe` | `Low` | `Strict` | `video_id`. |
| `youtube.list_videos` | `GET /videos?id=a,b` | `youtube.read` | `Safe` | `Low` | `Strict` | Non-empty `video_ids`. |
| `youtube.get_channel` | `GET /channels?id=...` | `youtube.read` | `Safe` | `Low` | `Strict` | `channel_id`. |
| `youtube.list_playlists` | `GET /playlists?channelId=...` | `youtube.read` | `Safe` | `Low` | `Strict` | `channel_id`; optional `max_results`, `page_token`. |
| `youtube.list_playlist_items` | `GET /playlistItems?playlistId=...` | `youtube.read` | `Safe` | `Low` | `Strict` | `playlist_id`; optional `max_results`, `page_token`. |
| `youtube.list_comments` | `GET /commentThreads?videoId=...` | `youtube.read` | `Safe` | `Low` | `Strict` | `video_id`; optional `max_results`. |
| `youtube.post_comment` | `POST /commentThreads` | `youtube.write` | `Dangerous` | `High` | `None` | `video_id`, `text`. |
| `youtube.get_captions` | `GET /captions?videoId=...` | `youtube.read` | `Safe` | `Low` | `Strict` | `video_id`. |
| `youtube.get_caption_transcript` | `GET /captions/{caption_id}?tfmt=...` | `youtube.read` | `Safe` | `Low` | `Strict` | `caption_id`; optional `format` (`srt`, `vtt`, `ttml`). |
| `youtube.get_transcript` | `GET /captions` plus `GET /captions/{caption_id}` and local normalization | `youtube.read` | `Safe` | `Low` | `Strict` | One of `video_id` or `video_url`; optional language and bounds. |
| `youtube.upload_caption` | `POST /captions` | `youtube.write` | `Dangerous` | `High` | `None` | `video_id`, `language`, `transcript`; optional `name`. |
| `youtube.get_analytics` | `GET /channels`, `GET /playlistItems`, `GET /videos` summary chain | `youtube.read` | `Safe` | `Low` | `Strict` | `channel_id`; optional `max_videos`. |
| `youtube.upload_video` | `POST /upload/youtube/v3/videos?uploadType=multipart&part=snippet,status` | `youtube.write` | `Dangerous` | `High` | `None` | `title`, `description`, `video_data_base64`; optional `privacy`, `tags`, `category_id`. OAuth required; at most 16 MiB decoded. |

### Video Upload Contract

The connector uses the single-request multipart form of [`videos.insert`](https://developers.google.com/youtube/v3/docs/videos/insert). Google accepts `application/octet-stream` media, so callers do not need a MIME-type or filename field. Metadata is the first MIME part and the exact decoded binary video is the second.

- `video_data_base64` must use canonical standard padded base64 and decode to at least one byte and at most 16 MiB. URL-safe base64, embedded whitespace, invalid padding, and nonzero trailing padding bits are rejected before HTTP.
- `title` must contain 1 to 100 characters and cannot be blank. `description` is limited to 5000 UTF-8 bytes. Up to 100 nonblank string tags are accepted, and the serialized metadata is limited to 64 KiB. YouTube can apply additional metadata and media-format restrictions.
- `privacy` defaults to `private` and accepts `private`, `unlisted`, or `public`. `category_id` defaults to `22` and must be a string of decimal digits. Optional fields with the wrong JSON type are rejected. The connector does not set an audience declaration on the caller's behalf.
- Configure an OAuth access token or a host credential reference with an applicable YouTube upload scope. Direct API keys cannot authorize video uploads and are rejected locally. Both invoke and simulate also retain bound `youtube.write` capability checks.
- Uploads have a ten-minute request budget, a ten-second connection timeout, a 10 MiB response limit, and no redirects. Ordinary read operations retain their existing transport settings. The configured base path is preserved under the upload prefix for explicit loopback fixtures.
- Only explicit 429 refusals and connection failures proven to precede transmission may be retried automatically. A timeout, cancellation, 5xx, oversized response, or malformed success produces a **non-retryable unknown outcome**. Inspect the authenticated channel before resubmitting to avoid duplicate videos.
- A successful call returns the existing flat object with `videoId`, `title`, `privacyStatus`, and `uploadStatus`, all obtained from the provider response. Missing or unusable identity/status metadata is not replaced with fabricated success values. An upload result does not promise that YouTube has finished processing the video.

Resumable sessions, chunk progress, and recovery across process restarts are outside this buffered operation. Tests in `tests/video_upload.rs` inspect the actual upload URI, authorization, metadata, and arbitrary binary content, as well as local refusals, rate limits, redirects, and uncertain completion.

## Quota And Provider Cost Notes

- Official YouTube quota docs assign a minimum cost of one unit to every API request, including invalid requests.
- `search.list` costs 100 quota units per page.
- `captions.list` costs 50 units and `captions.insert` costs 400 units.
- `commentThreads.list` and `comments.list` cost 1 unit; comment insert/update/delete style calls cost more.
- `videos.list` costs 1 unit. Video uploads use the provider's separately documented upload quota; consult the current `videos.insert` limits when planning upload volume.
- The connector does not currently surface live quota budgets, quota reset time, or per-operation provider cost counters. Operators should keep search, captions, and upload paths bounded.

## Explicit Non-Goals

The current implementation does not include:

- YouTube Studio channel management, Content ID, copyright claims, monetization, memberships, subscriptions, live streaming, playlists mutation, thumbnails, ratings, moderation status updates, comment deletion, video deletion, or channel branding updates
- YouTube Analytics API dimensions/metrics/reporting, bulk export, retention analysis, or revenue reporting
- OAuth onboarding, consent-screen management, Google Cloud project provisioning, API enablement, quota increase requests, or service-account fallback
- webhook/PubSub subscription management or push notifications
- scraping watch pages, bypassing unavailable captions, downloading arbitrary video media, or using unofficial transcript APIs
- connector-local persistence of videos, comments, captions, transcripts, uploaded media, provider responses, quota counters, or credentials beyond process memory

These are excluded on purpose:

- Comments, captions, and uploads create public or account-visible side effects.
- Transcripts and comments are untrusted text and must remain tainted.
- YouTube quota costs can be high enough that broad search/caption loops need explicit operator policy.
- Live upload parity needs a dedicated proof lane before this connector should claim production-grade media upload behavior.

## Readiness And Verification Surface

`handle_doctor()`, `handle_health()`, `handle_self_check()`, `handle_simulate()`, and `handle_introspect()` are part of the public closeout contract. They surface:

- configuration, client, service selector, auth mode, base URL, credential-injection, and handshake state
- in-memory request/error counters
- direct-auth self-check through `GET /search?part=id&maxResults=1&q=test`
- degraded credential-reference self-check until an egress proxy injects credentials
- operation metadata, schemas, capabilities, risk levels, safety tiers, idempotency classes, and agent hints
- bound capability-token verification during `invoke` and `simulate`
- provider/FCP error mapping and secret redaction

The deterministic integration evidence is anchored on connector-local tests covering:

- search, video, channel, playlist, comments, captions, transcript, caption upload, and upload-like fixture paths
- provider 401, 403, 404, 429, transport, retryable, and input-validation behavior
- default-deny capability tokens, wrong capability rejection, missing constraints, resource URI derivation, simulation, unknown operation rejection, and lifecycle handlers
- transcript parsing, video URL parsing, max segment/byte bounds, credential-reference degradation, doctor, health, self-check, introspection, and shutdown behavior

## Source Notes

- `connectors/youtube/src/connector.rs` defines configuration parsing, service selector validation, lifecycle handlers, diagnostics, introspection, simulation, input validation, transcript normalization, resource URI binding, bound capability-token verification, and invoke dispatch.
- `connectors/youtube/src/client.rs` defines YouTube Data API request construction, API-key and shared-Google auth behavior, retry dispatch, timeout configuration, transcript download, caption upload, real bounded multipart video upload, and provider error mapping.
- `connectors/youtube/src/types.rs` defines YouTube response/resource shapes, captions, transcript output, analytics summary, and upload result types.
- `connectors/youtube/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/youtube/manifest.toml` defines the operation catalog, network constraints, sandbox boundary, zone policy, and state claim.
- `connectors/youtube/tests/integration.rs` and `connectors/youtube/tests/migration_acceptance.rs` cover deterministic HTTP behavior, lifecycle behavior, capability-token behavior, transcript helpers, and migration acceptance.

## Verification Bundle

Run these after changing this connector contract:

```bash
git diff --check -- connectors/youtube/README.md
ubs connectors/youtube/README.md
LC_ALL=C rg -n '[^ -~]' connectors/youtube/README.md
rg -n '\bmaster\b' connectors/youtube/README.md
```

For source or behavior changes, use an `rch`-offloaded connector proof lane:

```bash
fwc manifest fix connectors/youtube/manifest.toml --check --json
rch exec -- cargo fmt --manifest-path connectors/youtube/Cargo.toml --check
rch exec -- cargo check -p fcp-youtube --all-targets
rch exec -- cargo test -p fcp-youtube --test integration -- --nocapture
rch exec -- cargo test -p fcp-youtube -- --nocapture
rch exec -- cargo clippy -p fcp-youtube --all-targets -- -D warnings
```

There is no tracked `scripts/e2e/youtube_connector_verification.sh` in this checkout. Add one before claiming a full scripted closeout bundle.

## Operator Guidance

Prerequisites:

- Enable the YouTube Data API v3 on a Google Cloud project before live verification.
- Use a direct API key only for public read-style calls that YouTube permits with API-key auth.
- Use OAuth/shared Google credentials for user-authorized operations, private resources, comment writes, captions writes, and video uploads.
- Use a disposable channel or localhost fixture for mutations. Public comments, caption uploads, and video uploads are live user-visible side effects.

Dedicated environment:

- Prefer a localhost mock server for deterministic proof.
- For live smoke tests, use a dedicated Google Cloud project and disposable YouTube channel with strict quota budgets.
- Do not run upload or comment write operations against a production channel unless public side effects are acceptable.

Redaction rules:

- Redact API keys, bearer tokens, refresh tokens, credential IDs, credentials-file paths, OAuth client secrets, `Authorization` headers, and copied request logs before sharing evidence.
- Treat channel IDs, video IDs, playlist IDs, caption IDs, comment IDs, uploaded media bytes, transcripts, comment text, channel names, analytics summaries, and provider error bodies as sensitive operational data.
- Treat all returned comment, caption, transcript, title, and description text as untrusted prompt-injection input.

Common remediation:

- If `health` or `self_check` reports `not_configured`, call `configure` with either `api_key` or a shared Google auth source, not both.
- If configuration reports an invalid `service_selector`, use the default `youtube` selector or another alias that resolves to `youtube:v3`.
- If `self_check` reports `credential_injection_required`, run behind the configured egress proxy or use direct credentials for deterministic live probes.
- If write operations fail with authorization errors in API-key mode, switch to OAuth/shared Google credentials with scopes appropriate for the operation.
- If search or caption operations start returning quota errors, reduce pagination/search fanout and inspect the Google Cloud quota dashboard.
- If transcript operations return not found or empty output, confirm the video has a downloadable caption track and that the auth mode is allowed to download it.
- If upload behavior matters, verify the live upload protocol in a dedicated follow-up before relying on the current mock-oriented upload path.

Rerun commands:

- `git diff --check -- connectors/youtube/README.md`
- `ubs connectors/youtube/README.md`
- `fwc manifest fix connectors/youtube/manifest.toml --check --json`
- `rch exec -- cargo fmt --manifest-path connectors/youtube/Cargo.toml --check`
- `rch exec -- cargo check -p fcp-youtube --all-targets`
- `rch exec -- cargo test -p fcp-youtube --test integration -- --nocapture`
- `rch exec -- cargo test -p fcp-youtube -- --nocapture`
- `rch exec -- cargo clippy -p fcp-youtube --all-targets -- -D warnings`
