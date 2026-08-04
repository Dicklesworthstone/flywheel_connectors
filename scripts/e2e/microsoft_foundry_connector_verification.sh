#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
SCRIPT_PATH="scripts/e2e/microsoft_foundry_connector_verification.sh"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT_ROOT="${OUT_ROOT:-${REPO_ROOT}/artifacts/e2e/microsoft-foundry/${RUN_ID}}"
LOG_JSONL="${LOG_JSONL:-${OUT_ROOT}/evidence/microsoft_foundry_connector_e2e.jsonl}"
LOCAL_NON_MOCK_JSONL="${LOCAL_NON_MOCK_JSONL:-${OUT_ROOT}/evidence/local_non_mock.jsonl}"
COMMAND_LINE="${COMMAND_LINE:-bash ${SCRIPT_PATH}}"
RCH_BIN="${RCH_BIN:-rch}"
RCH_REQUIRE_REMOTE="${RCH_REQUIRE_REMOTE:-1}"
RCH_VISIBILITY="${RCH_VISIBILITY:-verbose}"
REPO_TOOLCHAIN="${REPO_TOOLCHAIN:-nightly-2026-02-19}"
TARGET_PREFIX="${CARGO_TARGET_PREFIX:-/tmp/fcp-microsoft-foundry-${RUN_ID}}"
BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"

export RCH_FORCE_REMOTE=1
export RCH_REQUIRE_REMOTE
export RCH_VISIBILITY

mkdir -p "${OUT_ROOT}/logs" "${OUT_ROOT}/evidence"
: >"${LOG_JSONL}"

OVERALL_STATUS="ok"
EXIT_CODE=0

manifest_status="pending"
cargo_check_status="pending"
format_check_status="pending"
conformance_status="pending"
wiremock_status="pending"
live_smoke_status="pending"
local_non_mock_status="pending"
local_non_mock_jsonl_status="pending"
clippy_status="pending"

export MICROSOFT_FOUNDRY_CONNECTOR_E2E_JSONL="${LOG_JSONL}"
export MICROSOFT_FOUNDRY_E2E_COMMAND_LINE="${COMMAND_LINE}"
MICROSOFT_FOUNDRY_E2E_GIT_REVISION="$(git -c "safe.directory=${REPO_ROOT}" -C "${REPO_ROOT}" rev-parse --short HEAD 2>/dev/null || echo unknown)"
export MICROSOFT_FOUNDRY_E2E_GIT_REVISION

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

  if grep -Eq 'timeout: failed to execute process|RCH-E|remote required; refusing local fallback|missing worker|No space left on device|dbus-1\.pc|connection reset by peer|Backend unavailable|unable to update registry|spurious network error|failed to get successful HTTP response|all workers failed preflight' "${log_path}"; then
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

required_worker_execution_class_for_step() {
  case "$1" in
    format_check)
      echo "source_state"
      ;;
    *)
      echo "remote"
      ;;
  esac
}

run_logged() {
  local name="$1"
  shift
  local log_path="${OUT_ROOT}/logs/${name}.log"
  local rc

  echo "[microsoft-foundry-verification] ${name}: $*" >&2
  (
    cd "${REPO_ROOT}" || exit
    "$@"
  ) >"${log_path}" 2>&1
  rc="$?"
  return "${rc}"
}

run_step() {
  local name="$1"
  local required_worker_class
  shift
  required_worker_class="$(required_worker_execution_class_for_step "${name}")"

  if run_logged "${name}" "$@"; then
    if [[ "${required_worker_class}" == "remote" ]] && [[ "$(observed_runner "${OUT_ROOT}/logs/${name}.log")" != "rch_remote" ]]; then
      printf '%s\n' "rch command did not produce accepted remote proof" >>"${OUT_ROOT}/logs/${name}.log"
      promote_overall_status "infra_blocked"
      echo "infra_blocked"
    else
      echo "passed"
    fi
  else
    local status
    status="$(classify_failure "${OUT_ROOT}/logs/${name}.log")"
    promote_overall_status "${status}"
    echo "${status}"
  fi
}

run_rch_step() {
  local name="$1"
  local target_suffix="$2"
  shift 2
  local remote_env=(
    "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}"
    "CARGO_INCREMENTAL=0"
    "CARGO_BUILD_JOBS=${BUILD_JOBS}"
    "CARGO_TARGET_DIR=${TARGET_PREFIX}-${target_suffix}"
    "MICROSOFT_FOUNDRY_CONNECTOR_E2E_JSONL=${LOG_JSONL}"
    "MICROSOFT_FOUNDRY_E2E_COMMAND_LINE=${COMMAND_LINE}"
    "MICROSOFT_FOUNDRY_E2E_GIT_REVISION=${MICROSOFT_FOUNDRY_E2E_GIT_REVISION}"
  )
  if [[ "${name}" == "format_check" ]]; then
    run_step "${name}" env -u RCH_FORCE_REMOTE -u RCH_REQUIRE_REMOTE RCH_VISIBILITY="${RCH_VISIBILITY}" "${remote_env[@]}" "$@"
  else
    run_step "${name}" env RCH_VISIBILITY="${RCH_VISIBILITY}" "${RCH_BIN}" exec -- env "${remote_env[@]}" "$@"
  fi
}

emit_json() {
  jq -cn \
    --arg record_type "$1" \
    --arg command_line "${COMMAND_LINE}" \
    --arg git_revision "${MICROSOFT_FOUNDRY_E2E_GIT_REVISION}" \
    --arg scenario "$2" \
    --arg outcome "$3" \
    --arg details "$4" \
    '{
      record_type: $record_type,
      command_line: $command_line,
      git_revision: $git_revision,
      scenario: $scenario,
      outcome: $outcome,
      details: ($details | fromjson)
    }' >>"${LOG_JSONL}"
}

harvest_e2e_log_records() {
  local log_path="$1"
  local line
  local record
  local prefix="MICROSOFT_FOUNDRY_CONNECTOR_E2E_RECORD="

  [[ -f "${log_path}" ]] || return

  while IFS= read -r line; do
    case "${line}" in
      "${prefix}"*)
        record="${line#"${prefix}"}"
        if jq -e '
          type == "object"
          and .record_type == "microsoft_foundry_connector_e2e"
          and (.operation | type == "string")
          and (.fixture_or_live_mode | type == "string")
        ' <<<"${record}" >/dev/null 2>&1; then
          if ! grep -Fqx "${record}" "${LOG_JSONL}"; then
            printf '%s\n' "${record}" >>"${LOG_JSONL}"
          fi
        fi
        ;;
    esac
  done <"${log_path}"
}

run_test() {
  local test_name="$1"
  local status

  status="$(run_rch_step "${test_name}" "integration-${test_name}" cargo test -p fcp-microsoft-foundry --test integration "${test_name}" -- --nocapture)"
  harvest_e2e_log_records "${OUT_ROOT}/logs/${test_name}.log"
  if [[ "${status}" == "passed" ]]; then
    emit_json \
      "microsoft_foundry_connector_e2e_test" \
      "${test_name}" \
      "passed" \
      "$(jq -cn --arg raw_log "${OUT_ROOT}/logs/${test_name}.log" '{raw_log: $raw_log}')"
  else
    emit_json \
      "microsoft_foundry_connector_e2e_test" \
      "${test_name}" \
      "${status}" \
      "$(jq -cn --arg raw_log "${OUT_ROOT}/logs/${test_name}.log" '{raw_log: $raw_log}')"
  fi
  echo "${status}"
}

require_cmd jq
require_cmd "${RCH_BIN}"

validate_log() {
  local required_ops=(
    "microsoft_foundry.responses.create"
    "microsoft_foundry.responses.cancel"
    "microsoft_foundry.responses.input_items.list"
    "microsoft_foundry.chat.completions"
    "microsoft_foundry.chat.completions_stream"
    "microsoft_foundry.embeddings.create"
    "microsoft_foundry.deployments.list"
  )

  for operation in "${required_ops[@]}"; do
    local count
    count="$(jq -r --arg operation "${operation}" '
      select(.record_type == "microsoft_foundry_connector_e2e" and .operation == $operation and .fixture_or_live_mode == "fixture")
      | .operation
    ' "${LOG_JSONL}" | wc -l | tr -d ' ')"
    if [[ "${count}" -lt 1 ]]; then
      echo "missing Microsoft Foundry fixture JSONL record for ${operation}" >&2
      exit 1
    fi
  done

  if grep -qE 'foundry-test-key|entra-test-token|private prompt|Summarize privately|acct\.openai\.azure\.com|acct\.services\.ai\.azure\.com' "${LOG_JSONL}"; then
    echo "Microsoft Foundry e2e JSONL leaked a test secret, prompt, or raw resource hostname" >&2
    exit 1
  fi

  local live_count
  live_count="$(jq -r '
    select(.record_type == "microsoft_foundry_connector_e2e" and .fixture_or_live_mode == "live")
    | .outcome
  ' "${LOG_JSONL}" | wc -l | tr -d ' ')"
  if [[ "${live_count}" -lt 1 ]]; then
    echo "missing live smoke pass/skip record" >&2
    exit 1
  fi
}

emit_json "microsoft_foundry_connector_e2e_start" "start" "running" "$(jq -cn --arg out_root "${OUT_ROOT}" '{out_root: $out_root}')"

manifest_status="$(run_rch_step manifest_check fwc cargo run -q -p fwc -- manifest fix connectors/microsoft-foundry/manifest.toml --check --json)"
cargo_check_status="$(run_rch_step cargo_check check cargo check -p fcp-microsoft-foundry --all-targets)"
format_check_status="$(run_rch_step format_check fmt cargo fmt -p fcp-microsoft-foundry -- --check)"
conformance_status="$(run_rch_step conformance conformance cargo test -p fcp-microsoft-foundry --test conformance -- --nocapture)"
wiremock_status="$(run_test "microsoft_foundry_connector_wiremock_e2e")"
live_smoke_status="$(run_test "microsoft_foundry_live_smoke_e2e")"

if [[ "${wiremock_status}" == "passed" && "${live_smoke_status}" == "passed" ]]; then
  validate_log
else
  promote_overall_status failed
fi

local_non_mock_status="$(run_rch_step local_non_mock local cargo test -p fcp-microsoft-foundry --test local_non_mock -- --nocapture)"
if grep -a '"suite":"local_non_mock"' "${OUT_ROOT}/logs/local_non_mock.log" >"${LOCAL_NON_MOCK_JSONL}"; then
  if jq -s -e '
    length >= 2
    and all(.[]; .connector == "microsoft-foundry")
    and all(.[]; .suite == "local_non_mock")
    and all(.[]; .bead_id == "flywheel_connectors-bky21.3.6.48")
    and any(.[]; (.operations // []) | index("microsoft_foundry.chat.completions"))
    and any(.[]; (.operations // []) | index("microsoft_foundry.deployments.list"))
    and any(.[]; (.request_paths // []) | index("/openai/v1/chat/completions"))
    and any(.[]; (.request_paths // []) | index("/openai/v1/models"))
    and any(.[]; .capability_token_verified == true)
    and any(.[]; .request_path == "/openai/v1/chat/completions" and .error_class == "rate_limited" and .retry_after_ms == 2000)
    and any(.[]; .secret_redaction_checked == true)
  ' "${LOCAL_NON_MOCK_JSONL}" >/dev/null; then
    local_non_mock_jsonl_status="passed"
  else
    local_non_mock_jsonl_status="failed"
    if [[ "${local_non_mock_status}" == "passed" ]]; then
      promote_overall_status failed
    fi
  fi
else
  local_non_mock_jsonl_status="${local_non_mock_status}"
  cat >"${LOCAL_NON_MOCK_JSONL}" <<EOF
{"event":"microsoft_foundry_local_non_mock_missing_jsonl","status":"${local_non_mock_jsonl_status}","reason":"local_non_mock test emitted no extractable local_non_mock JSONL records","git_revision":"${MICROSOFT_FOUNDRY_E2E_GIT_REVISION}","fixture_mode":"loopback_http","log":"${OUT_ROOT}/logs/local_non_mock.log"}
EOF
  if [[ "${local_non_mock_status}" == "passed" ]]; then
    local_non_mock_jsonl_status="failed"
    promote_overall_status failed
  fi
fi

if grep -qE 'local_foundry_acceptance_secret|local foundry prompt|local foundry accepted|slow down|127\.0\.0\.1:[0-9]+' "${LOCAL_NON_MOCK_JSONL}"; then
  local_non_mock_jsonl_status="failed"
  promote_overall_status failed
fi

clippy_status="$(run_rch_step clippy clippy cargo clippy -p fcp-microsoft-foundry --all-targets -- -D warnings)"
emit_json "microsoft_foundry_connector_e2e_complete" "complete" "${OVERALL_STATUS}" "$(jq -cn --arg log_jsonl "${LOG_JSONL}" '{log_jsonl: $log_jsonl}')"

cat >"${OUT_ROOT}/environment.json" <<EOF
{
  "run_id": "${RUN_ID}",
  "connector": "fcp-microsoft-foundry",
  "repo_root": "${REPO_ROOT}",
  "verification_script": "${SCRIPT_PATH}",
  "artifact_root": "${OUT_ROOT}",
  "git_revision": "${MICROSOFT_FOUNDRY_E2E_GIT_REVISION}",
  "target_prefix": "${TARGET_PREFIX}",
  "build_jobs": "${BUILD_JOBS}",
  "toolchain": "${REPO_TOOLCHAIN}",
  "runner": "rch",
  "fixture_mode": "wiremock_and_loopback_http",
  "redaction": "no Microsoft Foundry API key, bearer token, loopback endpoint, prompt text, completion text, raw resource hostname, or provider response body is emitted in extracted evidence"
}
EOF

cat >"${OUT_ROOT}/summary.json" <<EOF
{
  "run_id": "${RUN_ID}",
  "connector": "fcp-microsoft-foundry",
  "overall_status": "${OVERALL_STATUS}",
  "artifacts_root": "${OUT_ROOT}",
  "runner": "rch",
  "observed_runners": {
    "manifest_check": "$(observed_runner "${OUT_ROOT}/logs/manifest_check.log")",
    "cargo_check": "$(observed_runner "${OUT_ROOT}/logs/cargo_check.log")",
    "format_check": "$(observed_runner "${OUT_ROOT}/logs/format_check.log")",
    "conformance": "$(observed_runner "${OUT_ROOT}/logs/conformance.log")",
    "microsoft_foundry_connector_wiremock_e2e": "$(observed_runner "${OUT_ROOT}/logs/microsoft_foundry_connector_wiremock_e2e.log")",
    "microsoft_foundry_live_smoke_e2e": "$(observed_runner "${OUT_ROOT}/logs/microsoft_foundry_live_smoke_e2e.log")",
    "local_non_mock": "$(observed_runner "${OUT_ROOT}/logs/local_non_mock.log")",
    "clippy": "$(observed_runner "${OUT_ROOT}/logs/clippy.log")"
  },
  "steps": {
    "manifest_check": "${manifest_status}",
    "cargo_check": "${cargo_check_status}",
    "format_check": "${format_check_status}",
    "conformance": "${conformance_status}",
    "microsoft_foundry_connector_wiremock_e2e": "${wiremock_status}",
    "microsoft_foundry_live_smoke_e2e": "${live_smoke_status}",
    "local_non_mock": "${local_non_mock_status}",
    "local_non_mock_jsonl": "${local_non_mock_jsonl_status}",
    "clippy": "${clippy_status}"
  },
  "artifacts": {
    "e2e_jsonl": "${LOG_JSONL}",
    "local_non_mock_jsonl": "${LOCAL_NON_MOCK_JSONL}",
    "environment": "${OUT_ROOT}/environment.json"
  },
  "redaction_checks": {
    "integration_jsonl": "passed",
    "local_non_mock_jsonl": "${local_non_mock_jsonl_status}"
  }
}
EOF

jq -c '.steps' "${OUT_ROOT}/summary.json"
echo "MICROSOFT_FOUNDRY_CONNECTOR_E2E_JSONL=${LOG_JSONL}"
echo "MICROSOFT_FOUNDRY_LOCAL_NON_MOCK_JSONL=${LOCAL_NON_MOCK_JSONL}"
exit "${EXIT_CODE}"
