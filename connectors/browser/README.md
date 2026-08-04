# Browser Connector V3 Contract

> **Status**: runtime contract documented; manifest-derived operation metadata
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: `scripts/e2e/browser_target_session_manager_verification.sh`
> **Chrome DevTools Protocol upstream**: https://chromedevtools.github.io/devtools-protocol/

## Purpose

This document fixes the operator-facing contract for `fcp.browser`. The connector exposes the browser automation surface implemented in this crate: navigation, screenshots, PDF rendering, text/link extraction, selector waits, form and click interaction, JavaScript evaluation, cookie access, session-state capture/restore, and proxy control.

The connector is intentionally a bounded browser-control bridge. It is not a general HTTP client, scraping policy engine, web crawler, browser profile manager, CAPTCHA solver, test-runner framework, or host for arbitrary untrusted code.

## Current Runtime Snapshot

The current crate exposes these operations:

- `browser.navigate`
- `browser.screenshot`
- `browser.render_pdf`
- `browser.extract_text`
- `browser.extract_links`
- `browser.wait_for_selector`
- `browser.click`
- `browser.fill_form`
- `browser.evaluate_js`
- `browser.get_cookies`
- `browser.set_cookies`
- `browser.session.save`
- `browser.session.restore`
- `browser.session.describe`
- `browser.set_proxy`
- `browser.clear_proxy`

Important runtime truths the contract preserves:

- Package and binary name are `fcp-browser`.
- Runtime `BaseConnector` ID is `browser`.
- Manifest connector ID is `fcp.browser`.
- Configuration accepts no auth, `api_key`, or `credential_id`.
- Supplying both `api_key` and `credential_id` is rejected.
- Direct API-key mode sends `Authorization: Bearer <key>`.
- `credential_id` mode sends `X-FCP-Credential-ID` and expects host policy to inject usable secret material.
- Default `browser_url` is `http://localhost:9222`.
- Runtime browser-control host allowlist is `localhost`, `127.0.0.1`, `::1`, `*.browser.mesh.internal`, and `*.browser.flywheel.internal`.
- `browser_url` must be absolute and must not contain userinfo, query parameters, or fragments.
- Runtime accepts `http` and `https` browser-control URLs, but non-loopback HTTP is rejected.
- Direct Chrome DevTools WebSocket mode accepts only `ws://` loopback page endpoints under `/devtools/page/<target-id>`.
- Direct Chrome DevTools endpoint handling classifies page, browser, worker, unsupported, and missing-target URL shapes before connecting; browser/worker/non-page targets fail closed.
- Direct Chrome DevTools logs and descriptors use redacted endpoint URLs plus BLAKE3 target-id hashes rather than raw target IDs.
- Direct Chrome DevTools operations acquire a single-owner Rust target/session manager lease before opening an operation-scoped CDP session.
- The manager records current-tab ownership, stale-target recovery, command IDs, timeout/cancellation checkpoints, retry decisions, shutdown cleanup, and redacted session/cookie ownership metadata.
- In direct-CDP mode, session save/restore acquire manager leases under `browser.session.save` and `browser.session.restore`, while session describe records the selected state object under `browser.session.describe` without reopening the network session.
- Raw Chrome DevTools discovery endpoints such as `/json` and `/json/version` are rejected as `browser_url` values.
- `wss://` direct DevTools WebSocket URLs are rejected until TLS WebSocket support is wired.
- Direct Chrome DevTools WebSocket mode preserves page, cookie, and session operations, but `browser.set_proxy` and `browser.clear_proxy` fail closed with `proxy_unavailable_direct_cdp` unless the opt-in Rust-owned launcher supervisor is configured.
- `fcp-browser-control` workers that do not advertise proxy operations remain valid for non-proxy operations. Proxy dispatch is allowed only after `/health` advertises exact `browser.set_proxy` and `browser.clear_proxy` worker-policy descriptors, timeout budgets, response budgets, target policy, and the proxy redaction contract.
- The Rust-owned launcher supervisor currently has a deterministic fixture mode for launcher/proxy policy proof and a native mode that spawns a configured/discovered browser binary, waits for the `DevToolsActivePort` readiness file, kills/reaps the owned process on timeout or shutdown, and keeps all binary paths, profile paths, raw endpoints, proxy credentials, and target/session identifiers redacted in JSONL evidence.
- Proxy descriptors reject invalid schemes, embedded URL credentials, private/internal proxy targets, malformed bypass entries, oversized descriptors, and newline/control-character injection before any proxy worker dispatch.
- Runtime request timeout is 30 seconds.
- The browser client uses `fcp-browser/0.1.0` as its user agent.
- The client uses the shared retry loop with `max_retries = 2`.
- Control-plane requests carry the `X-FCP-Browser-*` operation, timeout, response-budget, target, stale-recovery, current-tab, and export-guard headers.
- Control budget classes are small `10000 ms` / `1048576` bytes, standard `30000 ms` / `10485760` bytes, and capture `60000 ms` / `52428800` bytes.
- Runtime handshake installs a `CapabilityVerifier`.
- Runtime handshake returns a SHA-256 hash of the bundled `manifest.toml`.
- `invoke` requires `operation`, `input`, and `capability_token`.
- `invoke` verifies a bound capability token for the operation capability before dispatch.
- Runtime capability-token verification currently passes an empty resource URI list.
- Direct runtime execution approval tokens are required only for JavaScript evaluation, form fill, cookies, session save/restore, and proxy set/clear.
- `health_check()` probes either a direct DevTools page endpoint or `{browser_url}/health`.
- `{browser_url}/health` must advertise the FCP browser-control contract rather than raw Chrome DevTools discovery JSON.
- `self_check()` fails when the connector is not configured, degrades for `credential_id`, and otherwise probes browser-control health.
- `browser.session.save` captures cookies, serializes canonical CBOR, and records session objects in an in-memory mesh-style store with `lease_seq` fencing.
- `browser.session.restore` rejects stale `lease_seq` values and restores cookies from the selected state object.
- Readable text output strips invisible Unicode and applies a default `200000` character cap with an absolute `1000000` character cap.
- PDF/document metadata uses a `200000` character text cap and a `4000000` pixel render cap.

## Drift Visible In This Checkout

This README documents the runtime truth and keeps current drift visible:

- Manifest target-page network constraints allow selected external host patterns, while runtime `browser_url` validation controls only the browser-control endpoint.
- Runtime `simulate` deserializes the request and unconditionally returns allowed; it does not check operation inventory, input shape, configured state, handshake state, capability token, or resource bindings.
- Runtime verifies bound capability tokens with an empty resource URI list for every operation.
- Manifest marks some risky browser operations as `requires_approval = "policy"` and dangerous operations as `interactive`.
- Runtime introspection derives approval mode from manifest `requires_approval`, while direct invocation requires an `approval_token` only for the explicit execution-approval list.
- `browser.navigate` and `browser.click` are risky operations but do not require a direct runtime `approval_token`.
- `handle_shutdown()` reports shutdown status and signals the direct-CDP manager shutdown cleanup, but it does not fully clear stored config, client, verifier, or session state.
- Manifest state hints mention browser profile state and page cache metadata, but the runtime session store in this slice is process-local.
- The tracked target/session manager verification script covers direct-CDP manager JSONL evidence; there is still no full Browser connector verification bundle for every operation mode.

A follow-up parity bead should make `simulate` enforce the same readiness and token checks as `invoke`, decide whether resource URI binding is required for browser targets, reconcile manifest policy approval with runtime enforcement, and clarify whether browser session objects need durable state.

## First-Slice Scope

The current Browser README slice documents the existing runtime surface:

- optional API-key and host credential-reference configuration
- browser-control URL validation, direct DevTools page endpoint support, health probing, timeout, retry, and control-header behavior
- navigation, capture, extraction, interaction, JavaScript, cookie, session, and proxy operations
- bound capability-token verification during `invoke`
- direct execution-approval token validation for the highest-risk operation subset
- readable-content and document-output guardrails
- deterministic integration and real-browser proof surfaces

## Readable And Document Extraction Parity Decision

The Browser connector adopts the OpenClaw-style readable-content guardrail
shape where it fits the FCP browser-control boundary, and deliberately defers
the parts that would turn `fcp.browser` into a general web-fetch or document
processing runtime.

Reference context: OpenClaw documents `web_fetch` as plain HTTP fetch plus
readable extraction, while JS-heavy or login-protected pages are routed to the
Browser tool instead. See <https://docs.openclaw.ai/tools/web-fetch> and
<https://docs.openclaw.ai/browser>.

Adopted for `browser.extract_text`:

- Plain-text and markdown output modes are part of the manifest contract.
- Invisible Unicode stripping is required before output is returned.
- The default output cap is `200000` characters and the absolute request cap is
  `1000000` characters.
- Output metadata records guardrail decisions, external-content taint, and the
  readability decision so downstream agents can distinguish trusted connector
  metadata from hostile page content.

Adopted for `browser.render_pdf`:

- Callers can request a `max_pages` bound.
- Runtime output records rendered-PDF external-content metadata and an explicit
  document-extraction decision.
- PDF text extraction is not silently implied by PDF rendering.

Consciously deferred or rejected for this connector:

- Raw HTTP `web_fetch`-style fetching is not adopted here. `fcp.browser` acts on
  an already-controlled browser target; generic HTTP fetch belongs in a
  web-fetch, Firecrawl-like, or shared extraction surface with its own network
  policy and fixture matrix.
- Raw-HTML parser bounds such as exact DOM nesting-depth rejection are not
  adopted in the Browser connector's post-render text path. The connector reads
  browser-produced page output through the control boundary instead of accepting
  arbitrary untrusted HTML blobs for tree parsing.
- PDF text extraction, OCR, image-render dependency fallbacks, and document
  page-selection extraction are deferred to a Rust/self-contained document
  extraction helper or connector. They must not introduce Node, Python, or other
  interpreted runtime dependencies.
- Browser automation remains separate from content crawling, robots policy,
  search indexing, and bot-circumvention policy.

The current test contract exercises the adopted surface through deterministic
loopback readable-content and print/PDF fixtures, oversized output denial,
capability denial before control routing, timeout/cancellation evidence, stale
session fencing, shutdown cleanup, and redaction-safe JSONL logs.

## Auth And Scope Boundary

- Authentication mechanisms: none, browser-control API key, or host credential reference.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zones: `z:work` and `z:private`.
- Forbidden zones: `z:public` and `z:community`.
- Runtime capability surface:
  - `browser.navigate` gates navigation.
  - `browser.capture` gates screenshots and PDF rendering.
  - `browser.extract` gates text, link, and selector-wait reads.
  - `browser.interact` gates clicks and form filling.
  - `browser.execute` gates page-context JavaScript.
  - `browser.cookies` gates cookie reads and writes.
  - `browser.sessions` gates session-state save, restore, and describe.
  - `browser.proxy` gates proxy set and clear operations.
- Required manifest capabilities are `network.dns`, `network.egress`, `network.tls.sni`, `storage.state`, and `media.download`.
- Optional manifest capabilities are `media.upload`, browser operation families, browser sessions, and browser proxy.
- Forbidden manifest capabilities are `system.exec` and `network.listen`.
- The connector can observe private page contents, cookies, form fields, links, document text, screenshots, PDFs, proxy details, and session state. Treat live output as work/private-zone data.

## Network And Runtime Invariants

- Browser-control default URL: `http://localhost:9222`.
- Runtime browser-control host allowlist: loopback plus `*.browser.mesh.internal` and `*.browser.flywheel.internal`.
- Non-loopback browser-control URLs must use HTTPS.
- Direct DevTools WebSocket support is limited to loopback page targets.
- Direct DevTools target metadata records the configured page target as the current-tab/export target; reconfiguring an active connector to a new loopback page target preserves the Rust manager and records stale-target recovery before the next operation connects.
- Raw DevTools discovery endpoints are rejected as control-plane bases.
- Manifest target-page host allowlist currently includes `*.github.com`, `*.google.com`, `*.wikipedia.org`, and `*.amazonaws.com`.
- Manifest target-page ports are `80` and `443`.
- Manifest target-page policy denies localhost, private ranges, tailnet ranges, and IP literals.
- Manifest target-page policy requires SNI and host canonicalization.
- Runtime browser-control URL validation is separate from target-page policy enforcement.
- Sandbox profile is `strict`, with `1024 MB` memory, `75%` CPU, `300000 ms` wall-clock timeout, writable `$CONNECTOR_STATE`, no exec, and no ptrace.
- The connector does not open inbound sockets.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `browser.navigate` | Navigate the active browser target to a URL. |
| `browser.capture` | Capture screenshot or PDF data from a page. |
| `browser.extract` | Read page text, links, or selector presence. |
| `browser.interact` | Click elements or fill forms in a page. |
| `browser.execute` | Evaluate JavaScript in the page context. |
| `browser.cookies` | Read or write page cookies. |
| `browser.sessions` | Save, restore, or describe browser session state. |
| `browser.proxy` | Set or clear browser proxy configuration. |

## Operation Inventory

| Operation | Control shape | Capability | SafetyTier | RiskLevel | Idempotency | Direct approval token |
|-----------|---------------|------------|------------|-----------|-------------|-----------------------|
| `browser.navigate` | navigation | `browser.navigate` | `Risky` | `Medium` | `None` | no |
| `browser.screenshot` | capture | `browser.capture` | `Safe` | `Low` | `Strict` | no |
| `browser.render_pdf` | capture | `browser.capture` | `Safe` | `Low` | `Strict` | no |
| `browser.extract_text` | extraction | `browser.extract` | `Safe` | `Low` | `Strict` | no |
| `browser.extract_links` | extraction | `browser.extract` | `Safe` | `Low` | `Strict` | no |
| `browser.wait_for_selector` | extraction | `browser.extract` | `Safe` | `Low` | `Strict` | no |
| `browser.click` | interaction | `browser.interact` | `Risky` | `Medium` | `None` | no |
| `browser.fill_form` | interaction | `browser.interact` | `Risky` | `Medium` | `None` | yes |
| `browser.evaluate_js` | page script | `browser.execute` | `Dangerous` | `High` | `None` | yes |
| `browser.get_cookies` | cookie read | `browser.cookies` | `Risky` | `Medium` | `Strict` | yes |
| `browser.set_cookies` | cookie write | `browser.cookies` | `Risky` | `Medium` | `Strict` | yes |
| `browser.session.save` | local state capture | `browser.sessions` | `Dangerous` | `High` | `BestEffort` | yes |
| `browser.session.restore` | local state restore | `browser.sessions` | `Dangerous` | `High` | `Strict` | yes |
| `browser.session.describe` | local state read | `browser.sessions` | `Safe` | `Low` | `Strict` | no |
| `browser.set_proxy` | proxy write | `browser.proxy` | `Dangerous` | `High` | `BestEffort` | yes |
| `browser.clear_proxy` | proxy write | `browser.proxy` | `Dangerous` | `High` | `Strict` | yes |

## Resource URIs

Runtime capability-token verification currently binds only connector ID, capability ID, operation ID, and token validity. The resource URI list passed to `verify_bound` is empty for all Browser operations.

Target URL, selector, cookie domain, session state object ID, proxy server, and output object details are not currently represented as resource URIs in the bound token check.

## Explicit Non-Goals

The current implementation does not include:

- browser installation, browser lifecycle management, or browser process spawning
- a public web crawler, crawl queue, robots-policy engine, or search indexer
- CAPTCHA solving, anti-bot bypass, credential stuffing, or stealth automation features
- persistent browser profile storage, durable page cache storage, or cross-process session database
- generic HTTP request dispatch independent of a browser target
- arbitrary host command execution
- raw Chrome DevTools discovery endpoint use as the normal FCP control plane
- live inbound webhooks or local browser-control listener setup inside the connector

These are excluded on purpose:

- Browser output can include private user data, credentials, cookies, and page contents.
- Page-context JavaScript and proxy mutation need explicit execution approval.
- Browser lifecycle, target-site policy, and credential injection belong at the host/control-plane boundary.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- configuration, auth mode, browser-control URL, host allowlist state, and request metrics
- browser-control contract health and raw DevTools discovery rejection
- control-mode split for direct CDP, proxy-capable `fcp-browser-control`, non-proxy workers, Rust-owned launcher fixture mode, and guarded native launcher mode
- credential-reference degraded state when host token injection is required
- sandbox, placement, network guard, and execution-planner profiles
- manifest-derived operation metadata with capability, risk, safety tier, idempotency, approval mode, schemas, and hints
- bound capability-token verification during `invoke`
- direct execution-approval token validation for JavaScript, form, cookies, session save/restore, and proxy changes
- readable-content and document-output metadata caps

The deterministic integration evidence is anchored on connector-local tests covering:

- lifecycle, configuration, browser URL validation, loopback allowance, direct DevTools page endpoint support, introspection, health, doctor, self-check, and shutdown behavior
- all 16 runtime operations through deterministic HTTP fixtures
- direct-CDP target/session manager unit fixtures for single-owner leasing, target attach/detach state, stale target recovery, command-id logging, timeout/cancellation markers, shutdown/no-orphan cleanup, and redacted session/cookie metadata
- proxy control-mode fixtures for direct-CDP fail-closed errors, proxy-capable worker acceptance, non-proxy worker preservation with `proxy_unavailable`, worker-policy rejection, and proxy descriptor validation
- Rust-owned launcher supervisor fixtures for launch success, proxy set/clear, readiness timeout, malformed proxy config, approval/capability pre-dispatch denial, shutdown cleanup, stale worker rejection, and direct-CDP fail-closed preservation
- control-plane request headers, timeouts, response budgets, and target-guard metadata
- bound capability-token checks for invoke
- execution-approval token checks, expiry, connector ID, operation pattern, and input constraints
- session save/restore/describe object IDs, canonical CBOR payloads, and `lease_seq` fencing
- real browser end-to-end coverage when a browser-control server is available

## Source Notes

- `connectors/browser/src/connector.rs` defines configuration parsing, browser URL policy, lifecycle handlers, introspection, simulation, execution approval, session state, capability-token verification, and invoke dispatch.
- `connectors/browser/src/client.rs` defines browser-control HTTP paths, direct DevTools page endpoint handling, control headers, retry dispatch, timeout, readable-content guardrails, document metadata, and provider error mapping.
- `connectors/browser/src/main.rs` maps FCP methods to connector handlers.
- `connectors/browser/manifest.toml` defines the operation catalog, target-page network constraints, sandbox boundary, zone policy, capability families, and rate-limit pools.
- `connectors/browser/tests/integration.rs` and `connectors/browser/tests/real_browser_e2e.rs` cover deterministic runtime behavior and real-browser proof.

## Verification Bundle

The tracked direct-CDP target/session manager bundle is `scripts/e2e/browser_target_session_manager_verification.sh`. It runs the deterministic manager proof and host supervised concurrency proof through `rch`, extracts `BROWSER_TARGET_SESSION_MANAGER_JSONL` and `BROWSER_SUPERVISED_SESSION_HOST_E2E` records from test stdout, validates the JSONL shape, and writes an ignored operator bundle under `artifacts/e2e/browser_target_session_manager/<run-id>/`.

The verification surface captures:

- runtime operation inventory and policy metadata
- browser-control URL policy, control-plane headers, timeout budgets, and raw DevTools rejection
- direct-CDP manager JSONL event coverage for manager start, target attach/detach, stale-target recovery, operation leases, command IDs, timeout/cancellation markers, dropped-lease cleanup, shutdown cleanup, and redacted session save/restore/describe metadata
- host concurrency coverage proving a second direct-CDP invoke defers before CDP connection while the first invoke owns the manager lease for the same browser instance
- capability-token and execution-approval enforcement for invoke
- deterministic HTTP fixtures and real-browser e2e coverage
- formatting, check, test, and clippy proof through `rch`
- UBS on changed files before commit

## Operator Guidance

**Prerequisites**:

- Use an isolated browser profile or browser-control service for live proof.
- Prefer `credential_id` mode when host policy should own browser-control secret material.
- Use deterministic loopback control-plane fixtures for routine proof.
- Use the real-browser e2e lane only when a compatible browser-control server is intentionally available.

**Redaction rules**:

- Redact API keys, credential IDs, cookies, form fields, page URLs when private, selectors that reveal app structure, screenshots, PDFs, extracted text, link lists, proxy credentials, session state object IDs when sensitive, provider payloads, and provider error bodies.
- Verification output should use operation IDs, host class, auth mode, status classes, result-shape summaries, byte counts, and guard decisions.

**Common remediation**:

- If configuration fails, provide at most one of `api_key` or `credential_id`.
- If `browser_url` is rejected, use loopback HTTP for local fixtures or HTTPS under the browser-control allowlist for non-loopback control planes.
- If health rejects a raw Chrome DevTools endpoint, configure an FCP browser-control base URL or a loopback direct page WebSocket.
- If invoke fails before provider dispatch, check handshake state, capability token, operation capability, and approval token for high-risk operations.
- If session restore fails, inspect `state_object_id`, `lease_seq`, and `lease_object_id` before retrying.

**Rerun commands**:

- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-browser-readme cargo check -p fcp-browser --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-browser-readme cargo test -p fcp-browser --tests -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-browser-readme cargo clippy -p fcp-browser --all-targets --no-deps -- -D warnings`
- `scripts/e2e/browser_target_session_manager_verification.sh --run-id manual-browser-manager`
- `ubs connectors/browser/README.md`
