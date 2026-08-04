#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT_ROOT="${OUT_ROOT:-${REPO_ROOT}/artifacts/e2e/google-people/${RUN_ID}}"
RCH_BIN="${RCH_BIN:-rch}"
REPO_TOOLCHAIN="${REPO_TOOLCHAIN:-nightly-2026-02-19}"
TARGET_PREFIX="${CARGO_TARGET_PREFIX:-/tmp/fcp-google-people-${RUN_ID}}"
BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"

mkdir -p "${OUT_ROOT}/logs" "${OUT_ROOT}/evidence"

OVERALL_STATUS="ok"
EXIT_CODE=0
LAST_STEP_STATUS="not_run"

manifest_status="pending"
cargo_check_status="pending"
format_check_status="pending"
integration_status="pending"
local_non_mock_status="pending"
local_non_mock_jsonl_status="pending"
clippy_status="pending"
graduation_gauntlet_status="pending"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

promote_overall_status() {
  local next_status="$1"
  case "${next_status}" in
    failed)
      OVERALL_STATUS="failed"
      EXIT_CODE=1
      ;;
    infra_blocked)
      if [[ "${OVERALL_STATUS}" == "ok" ]]; then
        OVERALL_STATUS="infra_blocked"
        EXIT_CODE=2
      fi
      ;;
  esac
}

classify_failure() {
  local log_path="$1"

  if [[ ! -f "${log_path}" ]]; then
    echo "infra_blocked"
    return
  fi

  if grep -Eq 'timeout: failed to execute process|RCH-E|remote required; refusing local fallback|missing worker|no admissible workers|no worker assigned|No space left on device|dbus-1\.pc|connection reset by peer|Backend unavailable|unable to update registry|spurious network error|failed to get successful HTTP response' "${log_path}"; then
    echo "infra_blocked"
  else
    echo "failed"
  fi
}

observed_runner() {
  local log_path="$1"

  if [[ ! -f "${log_path}" ]]; then
    echo "unknown"
  elif grep -Fq "[RCH] remote" "${log_path}"; then
    echo "rch_remote"
  elif grep -Fq "[RCH] local" "${log_path}"; then
    echo "rch_local_fallback"
  else
    echo "rch_unclassified"
  fi
}

run_logged() {
  local name="$1"
  shift
  local log_path="${OUT_ROOT}/logs/${name}.log"

  echo "[google-people-verification] ${name}: $*" >&2
  (
    cd "${REPO_ROOT}" || exit
    "$@"
  ) >"${log_path}" 2>&1
}

run_capture_stdout() {
  local name="$1"
  local stdout_path="$2"
  shift 2
  local log_path="${OUT_ROOT}/logs/${name}.log"

  echo "[google-people-verification] ${name}: $*" >&2
  (
    cd "${REPO_ROOT}" || exit
    "$@"
  ) >"${stdout_path}" 2>"${log_path}"
}

manifest_check_json_is_drift() {
  local json_path="$1"

  [[ -s "${json_path}" ]] && jq -e '.mode == "check" and .changed == true and .wrote == false' "${json_path}" >/dev/null
}

recover_manifest_check_json_from_log() {
  local log_path="$1"
  local json_path="$2"
  local recovered

  recovered="$(sed -n '/^{$/,/^}$/p' "${log_path}")"
  if [[ -n "${recovered}" ]] && jq -e '.mode == "check" and .changed == true and .wrote == false' <<<"${recovered}" >/dev/null; then
    printf '%s\n' "${recovered}" >"${json_path}"
    return 0
  fi

  return 1
}

run_step() {
  local name="$1"
  shift

  if run_logged "${name}" "$@"; then
    LAST_STEP_STATUS="passed"
  else
    local status
    status="$(classify_failure "${OUT_ROOT}/logs/${name}.log")"
    promote_overall_status "${status}"
    LAST_STEP_STATUS="${status}"
  fi
}

run_graduation_gauntlet() {
  local connector_path="connectors/google-people"
  local jsonl_path="${OUT_ROOT}/evidence/graduation_gauntlet.jsonl"
  local log_path="${OUT_ROOT}/logs/graduation_gauntlet.log"
  local rc
  local status

  : >"${jsonl_path}"
  echo "[google-people-verification] graduation_gauntlet: scripts/graduation/run_gauntlet.sh ${connector_path}" >&2
  (
    cd "${REPO_ROOT}" || exit
    scripts/graduation/run_gauntlet.sh --jsonl "${jsonl_path}" "${connector_path}"
  ) >"${log_path}" 2>&1
  rc="$?"
  if [[ "${rc}" -eq 0 ]]; then
    echo "passed"
    return
  fi
  if [[ "${rc}" -eq 8 && -s "${jsonl_path}" ]] && jq -s -e '
    map(select(.verdict == "fail")) as $failures
    | ($failures | length) == 1
    and $failures[0].check == "readme_status_match"
  ' "${jsonl_path}" >/dev/null; then
    echo "pre_promotion_pending"
    return
  fi

  status="$(classify_failure "${log_path}")"
  promote_overall_status "${status}"
  echo "${status}"
}

git_revision="$(cd "${REPO_ROOT}" && git rev-parse --short HEAD 2>/dev/null || echo unknown)"

require_cmd jq
require_cmd "${RCH_BIN}"

graduation_gauntlet_status="$(run_graduation_gauntlet)"

manifest_stdout_path="${OUT_ROOT}/evidence/manifest_check.command.json"
if run_capture_stdout \
  manifest_check \
  "${manifest_stdout_path}" \
  env RCH_FORCE_REMOTE=1 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=verbose "${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS="${BUILD_JOBS}" CARGO_TARGET_DIR="${TARGET_PREFIX}-fwc" cargo run -q -p fwc -- manifest fix connectors/google-people/manifest.toml --check --json
then
  manifest_status="passed"
  cp "${manifest_stdout_path}" "${OUT_ROOT}/evidence/manifest_check.json"
else
  if manifest_check_json_is_drift "${manifest_stdout_path}" || recover_manifest_check_json_from_log "${OUT_ROOT}/logs/manifest_check.log" "${manifest_stdout_path}"; then
    manifest_status="manifest_drift_pending"
    cp "${manifest_stdout_path}" "${OUT_ROOT}/evidence/manifest_check.json"
  else
    manifest_status="$(classify_failure "${OUT_ROOT}/logs/manifest_check.log")"
    promote_overall_status "${manifest_status}"
    jq -n \
      --arg status "${manifest_status}" \
      --arg command_output "${manifest_stdout_path}" \
      --arg log "${OUT_ROOT}/logs/manifest_check.log" \
      '{status:$status,command_output:$command_output,log:$log}' \
      >"${OUT_ROOT}/evidence/manifest_check.json"
  fi
fi

run_step cargo_check env RCH_FORCE_REMOTE=1 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=verbose "${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS="${BUILD_JOBS}" CARGO_TARGET_DIR="${TARGET_PREFIX}-check" cargo check -p fcp-google-people --all-targets
cargo_check_status="${LAST_STEP_STATUS}"

# `cargo fmt --check` validates source state; it is not accepted remote Cargo proof.
run_step format_check env -u RCH_FORCE_REMOTE -u RCH_REQUIRE_REMOTE RCH_VISIBILITY=verbose "${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS="${BUILD_JOBS}" CARGO_TARGET_DIR="${TARGET_PREFIX}-fmt" cargo fmt -p fcp-google-people -- --check
format_check_status="${LAST_STEP_STATUS}"

run_step integration_suite env RCH_FORCE_REMOTE=1 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=verbose "${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS="${BUILD_JOBS}" CARGO_TARGET_DIR="${TARGET_PREFIX}-integration" cargo test -p fcp-google-people --test integration -- --nocapture
integration_status="${LAST_STEP_STATUS}"

run_step local_non_mock env RCH_FORCE_REMOTE=1 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=verbose "${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS="${BUILD_JOBS}" CARGO_TARGET_DIR="${TARGET_PREFIX}-local" GIT_REVISION="${git_revision}" cargo test -p fcp-google-people --test local_non_mock -- --nocapture
local_non_mock_status="${LAST_STEP_STATUS}"

if grep -a '"suite_class":"local_non_mock"' "${OUT_ROOT}/logs/local_non_mock.log" >"${OUT_ROOT}/evidence/local_non_mock.jsonl"; then
  if jq -s -e '
    length >= 4
    and all(.[]; .connector == "google-people")
    and all(.[]; .acceptance_suite_class == "local_non_mock")
    and all(.[]; .fixture_mode == "loopback_http")
    and all(.[]; .provider_class == "local_sufficient")
    and all(.[]; .result == "passed")
    and any(.[]; .operation == "people.list_connections" and .method == "GET" and .endpoint_shape == "GET /v1/people/me/connections?<redacted_query>")
    and any(.[]; .operation == "self_check" and .method == "GET" and .endpoint_shape == "GET /v1/contactGroups?<redacted_query>")
    and any(.[]; .operation == "people.create_contact" and .method == "POST" and .endpoint_shape == "POST /v1/people:createContact")
    and any(.[]; .denial == "wrong_capability" and .loopback_egress_attempted == false)
    and all(.[]; (.path_segment_policy.loopback_endpoint_redacted? // true) != false)
    and all(.[]; (.path_segment_policy.contact_resource_names_redacted? // true) != false)
    and all(.[]; (.path_segment_policy.contact_group_resource_names_redacted? // true) != false)
    and all(.[]; (.path_segment_policy.contact_payload_redacted? // true) != false)
    and all(.[]; (.path_segment_policy.query_values_shape_only? // true) != false)
    and all(.[]; (.body_shape.contact_names_redacted? // true) != false)
    and all(.[]; (.body_shape.contact_emails_redacted? // true) != false)
  ' "${OUT_ROOT}/evidence/local_non_mock.jsonl" >/dev/null; then
    local_non_mock_jsonl_status="passed"
  else
    local_non_mock_jsonl_status="failed"
    if [[ "${local_non_mock_status}" == "passed" ]]; then
      promote_overall_status failed
    fi
  fi
else
  local_non_mock_jsonl_status="${local_non_mock_status}"
  cat >"${OUT_ROOT}/evidence/local_non_mock.jsonl" <<EOF
{"event":"google_people_local_non_mock_missing_jsonl","status":"${local_non_mock_jsonl_status}","reason":"local_non_mock test emitted no extractable local_non_mock JSONL records","git_revision":"${git_revision}","fixture_mode":"loopback_http","log":"${OUT_ROOT}/logs/local_non_mock.log"}
EOF
  if [[ "${local_non_mock_status}" == "passed" ]]; then
    local_non_mock_jsonl_status="failed"
    promote_overall_status failed
  fi
fi

if grep -qE 'ya29\.|local-people-auth-value|Ada|Lovelace|ada@example\.com|Grace|Hopper|grace@example\.com|people/contact|contactGroups/myContacts|people\.googleapis\.com|127\.0\.0\.1:[0-9]+|Authorization: Bearer|refresh_token|client_secret' "${OUT_ROOT}/evidence/local_non_mock.jsonl"; then
  local_non_mock_jsonl_status="failed"
  promote_overall_status failed
fi

run_step clippy env RCH_FORCE_REMOTE=1 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=verbose "${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS="${BUILD_JOBS}" CARGO_TARGET_DIR="${TARGET_PREFIX}-clippy" cargo clippy -p fcp-google-people --all-targets -- -D warnings
clippy_status="${LAST_STEP_STATUS}"

cat >"${OUT_ROOT}/environment.json" <<EOF
{
  "run_id": "${RUN_ID}",
  "connector": "fcp-google-people",
  "repo_root": "${REPO_ROOT}",
  "verification_script": "scripts/e2e/google_people_connector_verification.sh",
  "artifact_root": "${OUT_ROOT}",
  "git_revision": "${git_revision}",
  "target_prefix": "${TARGET_PREFIX}",
  "build_jobs": "${BUILD_JOBS}",
  "toolchain": "${REPO_TOOLCHAIN}",
  "runner": "rch",
  "fixture_mode": "loopback_http",
  "redaction": "no Google People access token, loopback endpoint, contact resource name, contact group resource name, contact name, contact email, live credential secret, provider payload, or provider error body is emitted in extracted evidence"
}
EOF

cat >"${OUT_ROOT}/replay.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail

RCH_BIN="\${RCH_BIN:-${RCH_BIN}}"
REPO_TOOLCHAIN="\${REPO_TOOLCHAIN:-${REPO_TOOLCHAIN}}"
TARGET_PREFIX="\${CARGO_TARGET_PREFIX:-${TARGET_PREFIX}}"
BUILD_JOBS="\${CARGO_BUILD_JOBS:-${BUILD_JOBS}}"
git_revision="\$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"

env RCH_FORCE_REMOTE=1 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=verbose "\${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}" CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS="\${BUILD_JOBS}" CARGO_TARGET_DIR="\${TARGET_PREFIX}-fwc" cargo run -q -p fwc -- manifest fix connectors/google-people/manifest.toml --check --json
env RCH_FORCE_REMOTE=1 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=verbose "\${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}" CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS="\${BUILD_JOBS}" CARGO_TARGET_DIR="\${TARGET_PREFIX}-check" cargo check -p fcp-google-people --all-targets
env -u RCH_FORCE_REMOTE -u RCH_REQUIRE_REMOTE RCH_VISIBILITY=verbose "\${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}" CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS="\${BUILD_JOBS}" CARGO_TARGET_DIR="\${TARGET_PREFIX}-fmt" cargo fmt -p fcp-google-people -- --check
env RCH_FORCE_REMOTE=1 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=verbose "\${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}" CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS="\${BUILD_JOBS}" CARGO_TARGET_DIR="\${TARGET_PREFIX}-integration" cargo test -p fcp-google-people --test integration -- --nocapture
env RCH_FORCE_REMOTE=1 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=verbose "\${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}" CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS="\${BUILD_JOBS}" CARGO_TARGET_DIR="\${TARGET_PREFIX}-local" GIT_REVISION="\${git_revision}" cargo test -p fcp-google-people --test local_non_mock -- --nocapture
env RCH_FORCE_REMOTE=1 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=verbose "\${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}" CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS="\${BUILD_JOBS}" CARGO_TARGET_DIR="\${TARGET_PREFIX}-clippy" cargo clippy -p fcp-google-people --all-targets -- -D warnings
EOF
chmod +x "${OUT_ROOT}/replay.sh"

cat >"${OUT_ROOT}/summary.json" <<EOF
{
  "run_id": "${RUN_ID}",
  "connector": "fcp-google-people",
  "overall_status": "${OVERALL_STATUS}",
  "artifacts_root": "${OUT_ROOT}",
  "runner": "rch",
  "observed_runners": {
    "manifest_check": "$(observed_runner "${OUT_ROOT}/logs/manifest_check.log")",
    "cargo_check": "$(observed_runner "${OUT_ROOT}/logs/cargo_check.log")",
    "format_check": "$(observed_runner "${OUT_ROOT}/logs/format_check.log")",
    "integration_suite": "$(observed_runner "${OUT_ROOT}/logs/integration_suite.log")",
    "local_non_mock": "$(observed_runner "${OUT_ROOT}/logs/local_non_mock.log")",
    "clippy": "$(observed_runner "${OUT_ROOT}/logs/clippy.log")"
  },
  "steps": {
    "graduation_gauntlet": "${graduation_gauntlet_status}",
    "manifest_check": "${manifest_status}",
    "cargo_check": "${cargo_check_status}",
    "format_check": "${format_check_status}",
    "integration_suite": "${integration_status}",
    "local_non_mock": "${local_non_mock_status}",
    "local_non_mock_jsonl": "${local_non_mock_jsonl_status}",
    "clippy": "${clippy_status}"
  },
  "artifacts": {
    "graduation_gauntlet": "${OUT_ROOT}/evidence/graduation_gauntlet.jsonl",
    "graduation_gauntlet_log": "${OUT_ROOT}/logs/graduation_gauntlet.log",
    "manifest_check": "${OUT_ROOT}/evidence/manifest_check.json",
    "cargo_check_log": "${OUT_ROOT}/logs/cargo_check.log",
    "format_check_log": "${OUT_ROOT}/logs/format_check.log",
    "integration_log": "${OUT_ROOT}/logs/integration_suite.log",
    "local_non_mock_log": "${OUT_ROOT}/logs/local_non_mock.log",
    "local_non_mock_jsonl": "${OUT_ROOT}/evidence/local_non_mock.jsonl",
    "clippy_log": "${OUT_ROOT}/logs/clippy.log",
    "environment": "${OUT_ROOT}/environment.json",
    "replay": "${OUT_ROOT}/replay.sh"
  }
}
EOF

echo "Google People verification artifacts written to ${OUT_ROOT}"
echo "GOOGLE_PEOPLE_E2E_JSONL=${OUT_ROOT}/evidence/local_non_mock.jsonl"
echo "GOOGLE_PEOPLE_E2E_SUMMARY=${OUT_ROOT}/summary.json"
exit "${EXIT_CODE}"
