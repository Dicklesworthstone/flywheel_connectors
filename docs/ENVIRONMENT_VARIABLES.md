# flywheel_connectors — Environment Variables (structured reference)

First structured env-var document for this repo (created 2026-10-28, task-12951,
the compliance census that previously showed 160/167 read vars with no docs).
Census method: every `std::env::var(_os)?("NAME")` in Rust sources
(`rg -o 'env::var(?:_os)?\("([A-Z][A-Z0-9_]+)"'`), split by whether the
reading file lives on the runtime path (`src/`) or under `tests/`.

- Runtime path: **61** variables
- Test / E2E-gate: **105** variables (plus CI-consumed vars, see §4)
- Provider credentials: **21** of the above are SECRET-CLASS (§2) — names and
  purposes only; values are never written into any doc, example, or fixture.

HOUSE CONVENTION: the pattern is the truth table in
loom-platform `docs/ENVIRONMENT_VARIABLES.md` (Quick Reference:
Variable | Description | Default Value | Required). A variable documented under
a name the code does not read is as broken as an undocumented one — document
the name `env::var` actually receives. This file is tracked; it must never
contain a secret value.

## 1. Runtime path (61)

Variables read from non-test code (`crates/*/src`, `connectors/*/src`).
Leave unset unless the purpose column says otherwise; defaults are safe in dev.

### 1.1 FCP_ runtime controls

| Variable | Default | Purpose (read site) |
|---|---|---|
| `FCP_DEPLOY_MODE` | `test` | Deploy profile for the adversarial connector (`connectors/_adversarial/src/connector.rs:186`). |
| `FCP_CRYPTO_BACKEND` | unset → built-in | Selects AEAD crypto implementation (`crates/fcp-crypto-hw/src/aead/chacha20_poly1305.rs:140`). |
| `FCP_CONFIG_DIR` | unset → XDG default | Config directory override for `fwc` (`crates/fwc/src/main.rs:4856`). |
| `FCP_APPROVAL_DIR` | unset → default | Approval-gate directory (`crates/fwc/src/main.rs:22931`). |
| `FCP_GIT_SHA` | cargo revision | Revision stamp embedded in built artifacts. |
| `FCP_RESOURCE_LEDGER_GIT_REVISION` | cargo revision | Revision stamp for resource-ledger evidence. |
| `FCP_TAILNET_EVIDENCE_GIT_REVISION` | cargo revision | Revision stamp for tailnet evidence artifacts. |
| `FCP_ANTHROPIC_API_VERSION` | connector pin | Anthropic API version pin for the anthropic connector. |
| `FCP_NOTION_API_VERSION` | connector pin | Notion API version pin. |
| `FCP_SALESFORCE_API_PATH` | connector default | Salesforce API path override. |
| `FCP_SALESFORCE_API_VERSION` | connector default | Salesforce API version pin. |
| `FCP_COMPUTE_MIGRATION_COST_MODEL` | built-in model | Cost model selection for compute-migration planning. |
| `FCP_FORCE_BLAKE3_TIER` | unset → tiered | Forces the blake3 content-hash tier. |
| `FCP_SUPPLY_CHAIN_CACHE_BENCH_OUT` | unset → stdout | Output dir for supply-chain cache benchmarks. |
| `FCP_TAILNET_CALLER_NODE_ID` / `FCP_TAILNET_RESPONDER_NODE_ID` | unset | Node identities for tailnet invoke harness. |
| `FCP_TAILNET_INVOKE_URL` / `FCP_TAILNET_INVOKE_ATTEMPTS` / `FCP_TAILNET_INVOKE_REQUEST_FILE` / `FCP_TAILNET_INVOKE_REQUEST_JSON` | unset | Tailnet invoke target URL, attempt count, and request payload (file or inline JSON). |
| `FCP_TAILSCALE_LOCALAPI_URL` | local socket | Tailscale local API endpoint override. |
| `FCP_TEST_CONNECTOR_ID` | harness default | Identity of the fcp-testkit in-process test connector. |
| `FCP_TEST_CONNECTOR_ARCHETYPE` | harness default | Archetype the test connector exposes. |
| `FCP_TEST_CONNECTOR_AUTH_MODE` | harness default | Auth mode the test connector advertises. |
| `FCP_TEST_CONNECTOR_HANDSHAKE_MODE` / `FCP_TEST_CONNECTOR_REQUIRE_HANDSHAKE` | harness default | Handshake behavior of the test connector. |
| `FCP_TEST_CONNECTOR_OPERATION_MODE` / `FCP_TEST_CONNECTOR_SIMULATE_MODE` / `FCP_TEST_CONNECTOR_HEALTH` | harness default | Operation/simulation mode and health façade of the test connector. |
| `FCP_TEST_CONNECTOR_ARTIFACT_POLICY` | harness default | Artifact policy the test connector enforces. |
| `FCP_UPDATE_GOLDENS` | unset → no | Regenerate golden files instead of comparing. |
| `FCP_MAC_E2E_TOKEN_OUTPUT_DIR` | unset | Where the macOS E2E token flow writes its output. |
| `FCP_SANDBOX_WINDOWS_APPCONTAINER_E2E` | unset → off | Enables the Windows AppContainer sandbox E2E path. |
| `GOOGLE_CHAT_MEDIA_E2E_JSONL_OUT` / `GOOGLE_CHAT_WEBHOOK_E2E_JSONL_OUT` / `NEXTCLOUD_TALK_WEBHOOK_E2E_JSONL_OUT` | unset | JSONL evidence output paths for those connectors' E2E capture runs. |
| `PREWARM_EVIDENCE_CARGO_TARGET_DIR` / `PREWARM_EVIDENCE_GIT_REVISION` | env/cargo | Target dir + revision stamp for prewarm evidence capture. |

### 1.2 FWC_ host & agent state

| Variable | Default | Purpose (read site) |
|---|---|---|
| `FWC_STATE_DIR` | unset → XDG default | Workflow state dir override (`crates/fwc/src/workflow.rs:1263`, `replay.rs:778`, `access_cmd.rs:1087`). |
| `FWC_SESSION_DIR` | unset → default | Session dir override (`crates/fwc/src/session.rs:245`). |
| `FWC_HOST` | `http://127.0.0.1:8788` | Audit-chain service base URL (`crates/fwc/src/audit_chain/mod.rs:346`). |
| `FWC_OPERATOR_EMAIL` | unset | Owner e-mail stamped into bootstrap/readiness (`crates/fwc/src/main.rs:12268`). |
| `FWC_AGENT_BOOTSTRAP_STATE` | unset | Agent-bootstrap state file path (`crates/fwc/src/main.rs:12275`, `agent_bootstrap.rs:569`). |
| `FWC_AGENT_BOOTSTRAP_AGENT_MAIL` | unset | Agent-mail reachability input for bootstrap readiness. |
| `FWC_AGENT_COORD_PATH` | unset | Coordination socket/path override (`crates/fwc/src/agent_coord.rs:498`). |
| `FWC_ACCESS_BUNDLE_DIR` | unset | Access-bundle export dir (`crates/fwc/src/access_cmd.rs:1079`). |
| `AGENT_NAME` | unset | Agent name prefix for readiness/bootstrap (`crates/fwc/src/main.rs:12272`, `agent_readiness_cmd.rs:1282`). |
| `RCH_WORKER_ID` | `CI_RUNNER_ID` then hostname | Worker id stamped into testkit evidence (`crates/fcp-testkit/src/evidence_helpers.rs:396-397`). |
| `CI_RUNNER_ID` | unset | Fallback worker id for evidence stamps. |

### 1.3 Ambient environment (provided by OS/CI; never set by hand)

`HOME`, `PATH`, `HOSTNAME`, `USER`, `USERNAME`, `USERPROFILE`, `TMPDIR`,
`XDG_STATE_HOME` (default root for `FWC_STATE_DIR`), `CARGO_TARGET_DIR`,
`CARGO_TARGET_TMPDIR`. Read for default paths and evidence context only.

## 2. SECRET-CLASS provider credentials (21)

Values are live API credentials. NEVER paste a value into docs, examples,
fixtures, or commits — this file and every doc like it carries name, purpose,
and rotation note only. Rotation: provider console revoke + reissue; all are
read fresh at process start, so rotation needs only a restart, not a rebuild.

| Variable | Connector / purpose |
|---|---|
| `ANTHROPIC_API_KEY` | Anthropic live chat verification (`connectors/anthropic/tests/live_verification.rs:32`). |
| `OPENAI_API_KEY` | OpenAI live chat/embeddings verification. |
| `GROQ_API_KEY` | Groq live verification + `FCP_E2E_LIVE_CREDENTIAL_POOL_GROQ`. |
| `GLM_API_KEY` (+ `GLM_API_KEY_ID` non-secret id) | GLM live verification. |
| `DASHSCOPE_API_KEY` | Alibaba DashScope/Qwen live verification. |
| `DEEPSEEK_API_KEY` | DeepSeek live verification. |
| `FIREWORKS_API_KEY` | Fireworks live chat/embedding verification. |
| `TOGETHER_API_KEY` | Together live chat/embedding verification. |
| `XAI_API_KEY` | xAI live verification (`XAI_CONNECTOR_E2E_JSONL`). |
| `NVIDIA_API_KEY` | NVIDIA NIM live verification. |
| `CEREBRAS_API_KEY` | Cerebras live verification. |
| `MICROSOFT_FOUNDRY_API_KEY` | Microsoft Foundry live verification. |
| `RUNWAY_API_KEY` | Runway video generation verification. |
| `INWORLD_API_KEY` (+ non-secret `INWORLD_REALTIME_SESSION_ID`) | InWorld realtime verification. |
| `FAL_KEY` | fal.ai image generation verification. |
| `SLACK_BOT_TOKEN` | Slack live verification (bot token). |
| `TELEGRAM_BOT_TOKEN` | Telegram live verification (bot token). |
| `STRIPE_SECRET_KEY` | Stripe live API verification. |
| `GITHUB_TOKEN` | GitHub API verification. |
| `AZURE_SPEECH_KEY` (+ non-secret `AZURE_SPEECH_REGION`) | Azure Speech live verification. |
| `AWS_BEDROCK_SECRET_ACCESS_KEY` (+ non-secret `AWS_BEDROCK_ACCESS_KEY_ID`, `AWS_BEDROCK_SESSION_TOKEN`, `AWS_BEDROCK_REGION`, `AWS_BEDROCK_MODEL_ID`) | AWS Bedrock live verification (`connectors/aws-bedrock/tests/live_verification.rs:87`). |

## 3. Test / E2E-gate variables (105)

Read only from `tests/`. Grouped by role; none affect production code paths.

- **Live-gate flags** (unset = skipped, never run live by accident):
  `AWS_BEDROCK_E2E`, `AWS_BEDROCK_STREAM_E2E`, `AZURE_SPEECH_LIVE`,
  `AZURE_SPEECH_E2E_COMMAND_LINE`, `DUCKDUCKGO_E2E`, `GOOGLE_MEET_LIVE_VERIFICATION`,
  `FCP_BOOTSTRAP_EXPECT_TOKEN`, `FCP_BOOTSTRAP_PKCS11_PROVIDER`,
  `FCP_WHISPER_LIVE_ENABLE`, `FCP_TEST_COMMAND_LINE`, `MICROSOFT_FOUNDRY_E2E_COMMAND_LINE`,
  `XAI_E2E_COMMAND_LINE`, `FCP_E2E_LIVE_CREDENTIAL_POOL_GROQ`.
- **Revision stamps** (`*_E2E_GIT_REVISION` / `FCP_TEST_GIT_REVISION` /
  `FCP_SLACK_E2E_GIT_REVISION` / `FCP_TELEGRAM_E2E_GIT_REVISION` /
  `FIREWORKS|TOGETHER|QWEN|NVIDIA_NIM|LM_STUDIO|OLLAMA|HUGGINGFACE|AZURE_SPEECH|FAL|XAI|MOONSHOT`-variants,
  `GIT_REVISION`, `FCP_GIT_REVISION`): pin the commit under test into evidence JSONL.
- **Evidence output dirs/files** (`*_JSONL_OUT`, `*_JSONL`, `*_JSONL_ARTIFACT`):
  `FCP_SWARM_JSONL_OUT`, `FCP_PREWARM_COLD_START_JSONL_OUT`,
  `FCP_BATCH_MORSELIZATION_JSONL_OUT`, `EMAIL_GENERIC_FIXTURE_JSONL_ARTIFACT`,
  `XAI_CONNECTOR_E2E_JSONL`, `MICROSOFT_FOUNDRY_CONNECTOR_E2E_JSONL`,
  `AZURE_SPEECH_E2E_JSONL`, `NEXTCLOUD_TALK_SETUP_READINESS_JSONL_OUT`,
  `PLIVO_E2E_LOG_DIR`, `TELNYX_E2E_LOG_DIR`, `FCP_TELEMETRY_OTLP_EVIDENCE`,
  `FCP_ZONE_MUTATION_PROOF_DIR`, `FCP_LATTICE_EVIDENCE_ROOT`,
  `FCP_INVOKE_AUDIT_STORM_RAW_SAMPLES`, `FCP_SELF_AUDIT_AUTO_FILE`,
  `FCP_MIGRATION_CHAOS_SEED`, `FCP_HOST_BINARY`, `PREWARM_CARGO_TARGET_DIR`.
- **Live model/service overrides**: `FIREWORKS_LIVE_CHAT_MODEL`,
  `FIREWORKS_LIVE_EMBEDDING_MODEL`, `QWEN_LIVE_CHAT_MODEL`,
  `QWEN_LIVE_EMBEDDING_MODEL`, `QWEN_LIVE_VISION_MODEL`, `TOGETHER_LIVE_CHAT_MODEL`,
  `TOGETHER_LIVE_EMBEDDING_MODEL`, `LM_STUDIO_E2E_BASE_URL`/`_MODEL`,
  `OLLAMA_E2E_BASE_URL`/`_MODEL`, `NVIDIA_NIM_E2E_MODEL`, `MOONSHOT_BASE_URL`/`MOONSHOT_MODEL`,
  `SEARXNG_E2E_URL`, `COMFYUI_BASE_URL`/`COMFYUI_ALLOWED_HOSTS`/`COMFYUI_AUTHORIZATION_HEADER`,
  `GMAIL_SECRETLESS_BASE_URL`, `GMAIL_CREDENTIAL_ID`.
- **Toolchain/harness**: `CARGO`, `CARGO_TARGET_DIR`, `COSIGN_BIN`, `TLA2TOOLS_JAR`,
  `UPDATE_GOLDENS`.

## 4. CI-consumed variables

GitLab CI job variables (runners, registries, deploy targets) are documented in
`ci_cd_variables_setup.md`; they are consumed by the pipeline, not by repo code,
and are intentionally outside this table. If a variable appears both here and
there, this file documents only the code-side read.

## 5. Name index (complete census, exact names)

Every variable name `env::var` reads in this repo, so a name search in
this file always resolves. Sections above carry the semantics.

**Runtime (61):**
`AGENT_NAME` `CARGO_TARGET_DIR` `CARGO_TARGET_TMPDIR` `CI_RUNNER_ID` `FCP_ANTHROPIC_API_VERSION` `FCP_APPROVAL_DIR` `FCP_COMPUTE_MIGRATION_COST_MODEL` `FCP_CONFIG_DIR` `FCP_CRYPTO_BACKEND` `FCP_DEPLOY_MODE` `FCP_FORCE_BLAKE3_TIER` `FCP_GIT_SHA` `FCP_HOST_LIFECYCLE_STATE_FILE` `FCP_MAC_E2E_TOKEN_OUTPUT_DIR` `FCP_NOTION_API_VERSION` `FCP_REGISTRY_TRUST_ROOTS_FILE` `FCP_RESOURCE_LEDGER_GIT_REVISION` `FCP_SALESFORCE_API_PATH` `FCP_SALESFORCE_API_VERSION` `FCP_SANDBOX_WINDOWS_APPCONTAINER_E2E` `FCP_SUPPLY_CHAIN_CACHE_BENCH_OUT` `FCP_TAILNET_CALLER_NODE_ID` `FCP_TAILNET_EVIDENCE_GIT_REVISION` `FCP_TAILNET_INVOKE_ATTEMPTS` `FCP_TAILNET_INVOKE_REQUEST_FILE` `FCP_TAILNET_INVOKE_REQUEST_JSON` `FCP_TAILNET_INVOKE_URL` `FCP_TAILNET_RESPONDER_NODE_ID` `FCP_TAILSCALE_LOCALAPI_URL` `FCP_TEST_CONNECTOR_ARCHETYPE` `FCP_TEST_CONNECTOR_ARTIFACT_POLICY` `FCP_TEST_CONNECTOR_AUTH_MODE` `FCP_TEST_CONNECTOR_HANDSHAKE_MODE` `FCP_TEST_CONNECTOR_HEALTH` `FCP_TEST_CONNECTOR_ID` `FCP_TEST_CONNECTOR_OPERATION_MODE` `FCP_TEST_CONNECTOR_REQUIRE_HANDSHAKE` `FCP_TEST_CONNECTOR_SIMULATE_MODE` `FCP_UPDATE_GOLDENS` `FWC_ACCESS_BUNDLE_DIR` `FWC_AGENT_BOOTSTRAP_AGENT_MAIL` `FWC_AGENT_BOOTSTRAP_STATE` `FWC_AGENT_COORD_PATH` `FWC_HOST` `FWC_OPERATOR_EMAIL` `FWC_SESSION_DIR` `FWC_STATE_DIR` `GOOGLE_CHAT_MEDIA_E2E_JSONL_OUT` `GOOGLE_CHAT_WEBHOOK_E2E_JSONL_OUT` `HOME` `HOSTNAME` `NEXTCLOUD_TALK_WEBHOOK_E2E_JSONL_OUT` `PATH` `PREWARM_EVIDENCE_CARGO_TARGET_DIR` `PREWARM_EVIDENCE_GIT_REVISION` `RCH_WORKER_ID` `TMPDIR` `USER` `USERNAME` `USERPROFILE` `XDG_STATE_HOME` 

**Test / E2E-gate (105):**
`ANTHROPIC_API_KEY` `AWS_BEDROCK_ACCESS_KEY_ID` `AWS_BEDROCK_E2E` `AWS_BEDROCK_MODEL_ID` `AWS_BEDROCK_REGION` `AWS_BEDROCK_SECRET_ACCESS_KEY` `AWS_BEDROCK_SESSION_TOKEN` `AWS_BEDROCK_STREAM_E2E` `AZURE_SPEECH_E2E_COMMAND_LINE` `AZURE_SPEECH_E2E_GIT_REVISION` `AZURE_SPEECH_E2E_JSONL` `AZURE_SPEECH_KEY` `AZURE_SPEECH_LIVE` `AZURE_SPEECH_REGION` `CARGO` `CARGO_TARGET_DIR` `CEREBRAS_API_KEY` `COMFYUI_ALLOWED_HOSTS` `COMFYUI_AUTHORIZATION_HEADER` `COMFYUI_BASE_URL` `COMFYUI_E2E_GIT_REVISION` `COSIGN_BIN` `DASHSCOPE_API_KEY` `DEEPSEEK_API_KEY` `DUCKDUCKGO_E2E` `EMAIL_GENERIC_FIXTURE_JSONL_ARTIFACT` `FAL_E2E_GIT_REVISION` `FAL_KEY` `FCP_BATCH_MORSELIZATION_JSONL_OUT` `FCP_BOOTSTRAP_EXPECT_TOKEN` `FCP_BOOTSTRAP_PKCS11_PROVIDER` `FCP_E2E_LIVE_CREDENTIAL_POOL_GROQ` `FCP_GIT_REVISION` `FCP_HOST_BINARY` `FCP_INVOKE_AUDIT_STORM_RAW_SAMPLES` `FCP_LATTICE_EVIDENCE_ROOT` `FCP_LATTICE_GIT_REVISION` `FCP_MIGRATION_CHAOS_SEED` `FCP_PREWARM_COLD_START_JSONL_OUT` `FCP_SELF_AUDIT_AUTO_FILE` `FCP_SLACK_E2E_GIT_REVISION` `FCP_SWARM_JSONL_OUT` `FCP_TELEGRAM_E2E_GIT_REVISION` `FCP_TELEMETRY_OTLP_EVIDENCE` `FCP_TEST_COMMAND_LINE` `FCP_TEST_GIT_REVISION` `FCP_WHISPER_LIVE_ENABLE` `FCP_ZONE_MUTATION_PROOF_DIR` `FIREWORKS_API_KEY` `FIREWORKS_E2E_GIT_REVISION` `FIREWORKS_LIVE_CHAT_MODEL` `FIREWORKS_LIVE_EMBEDDING_MODEL` `GITHUB_TOKEN` `GIT_REVISION` `GLM_API_KEY` `GLM_API_KEY_ID` `GMAIL_CREDENTIAL_ID` `GMAIL_SECRETLESS_BASE_URL` `GOOGLE_MEET_LIVE_VERIFICATION` `GROQ_API_KEY` `HUGGINGFACE_E2E_GIT_REVISION` `INWORLD_API_KEY` `INWORLD_REALTIME_SESSION_ID` `LM_STUDIO_E2E_BASE_URL` `LM_STUDIO_E2E_GIT_REVISION` `LM_STUDIO_E2E_MODEL` `MICROSOFT_FOUNDRY_API_KEY` `MICROSOFT_FOUNDRY_BASE_URL` `MICROSOFT_FOUNDRY_CONNECTOR_E2E_JSONL` `MICROSOFT_FOUNDRY_E2E_COMMAND_LINE` `MICROSOFT_FOUNDRY_E2E_GIT_REVISION` `MOONSHOT_BASE_URL` `MOONSHOT_MODEL` `NEXTCLOUD_TALK_SETUP_READINESS_JSONL_OUT` `NVIDIA_API_KEY` `NVIDIA_NIM_E2E_GIT_REVISION` `NVIDIA_NIM_E2E_MODEL` `OLLAMA_E2E_BASE_URL` `OLLAMA_E2E_GIT_REVISION` `OLLAMA_E2E_MODEL` `OPENAI_API_KEY` `PLIVO_E2E_LOG_DIR` `PREWARM_CARGO_TARGET_DIR` `PREWARM_EVIDENCE_CARGO_TARGET_DIR` `QWEN_E2E_GIT_REVISION` `QWEN_LIVE_CHAT_MODEL` `QWEN_LIVE_EMBEDDING_MODEL` `QWEN_LIVE_VISION_MODEL` `RUNWAY_API_KEY` `RUNWAY_E2E_GIT_REVISION` `SEARXNG_E2E_URL` `SLACK_BOT_TOKEN` `STRIPE_SECRET_KEY` `TELEGRAM_BOT_TOKEN` `TELNYX_E2E_LOG_DIR` `TLA2TOOLS_JAR` `TOGETHER_API_KEY` `TOGETHER_E2E_GIT_REVISION` `TOGETHER_LIVE_CHAT_MODEL` `TOGETHER_LIVE_EMBEDDING_MODEL` `UPDATE_GOLDENS` `XAI_API_KEY` `XAI_CONNECTOR_E2E_JSONL` `XAI_E2E_COMMAND_LINE` `XAI_E2E_GIT_REVISION` 
