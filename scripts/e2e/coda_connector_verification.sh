#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT_ROOT="${OUT_ROOT:-${REPO_ROOT}/artifacts/e2e/coda_connector/${RUN_ID}}"
REPO_TOOLCHAIN="${REPO_TOOLCHAIN:-nightly-2026-02-19}"
RCH_BIN="${RCH_BIN:-rch}"
RCH_REQUIRE_REMOTE="${RCH_REQUIRE_REMOTE:-1}"
BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"

mkdir -p "${OUT_ROOT}/logs" "${OUT_ROOT}/evidence"

OVERALL_STATUS="ok"
EXIT_CODE=0
export RCH_FORCE_REMOTE=1
export RCH_REQUIRE_REMOTE
REMOTE_TARGET_BASE="/tmp/rch-fcp-coda-${RUN_ID}"

manifest_status="pending"
manifest_note=""
cargo_check_status="pending"
format_check_status="pending"
health_guidance_status="pending"
doctor_guidance_status="pending"
self_check_status="pending"
retryable_self_check_status="pending"
pagination_evidence_status="pending"
dangerous_delete_status="pending"
compliance_status="pending"
integration_suite_status="pending"
crate_suite_status="pending"
clippy_status="pending"
manifest_stdout_path="${OUT_ROOT}/evidence/manifest_check.command.json"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

run_logged() {
  local name="$1"
  shift
  local log_path="${OUT_ROOT}/logs/${name}.log"
  local previous_pwd
  local rc

  echo "[coda-verification] ${name}: $*"
  previous_pwd="$(pwd)"
  cd "${REPO_ROOT}" || return
  "$@" >"${log_path}" 2>&1
  rc="$?"
  cd "${previous_pwd}" || return
  if [[ "${rc}" -eq 0 ]] && ! require_rch_remote_proof "${name}" "${log_path}" "$@"; then
    return 1
  fi
  return "${rc}"
}

run_capture_stdout() {
  local name="$1"
  local stdout_path="$2"
  shift 2
  local log_path="${OUT_ROOT}/logs/${name}.log"
  local previous_pwd
  local rc

  echo "[coda-verification] ${name}: $*"
  previous_pwd="$(pwd)"
  cd "${REPO_ROOT}" || return
  "$@" >"${stdout_path}" 2>"${log_path}"
  rc="$?"
  cd "${previous_pwd}" || return
  if [[ "${rc}" -eq 0 ]] && ! require_rch_remote_proof "${name}" "${log_path}" "$@"; then
    return 1
  fi
  return "${rc}"
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

log_has_remote_proof_failure() {
  local log_path="$1"
  local line
  while IFS= read -r line; do
    if [[ "${line}" == *"rch command did not produce remote proof"* ]]; then
      return 0
    fi
  done < "${log_path}"
  return 1
}

log_has_infra_blocker() {
  local log_path="$1"
  local line
  while IFS= read -r line; do
    case "${line}" in
      *"RCH-E"*|*"remote required; refusing local fallback"*|*"rch command did not produce remote proof"*|*"No space left on device"*|*"connection reset by peer"*|*"Backend unavailable"*|*"unable to update registry"*|*"spurious network error"*|*"failed to get successful HTTP response"*|*"missing worker system package"*|*"timeout: failed to execute process"*|*"The system library \`dbus-1\` required"*|*"pkg-config --libs --cflags dbus-1"*)
        return 0
        ;;
    esac
  done < "${log_path}"
  return 1
}

classify_manifest_failure() {
  local log_path="$1"
  if [[ ! -f "${log_path}" ]]; then
    echo "infra_blocked"
  elif log_has_infra_blocker "${log_path}"; then
    echo "infra_blocked"
  else
    echo "failed"
  fi
}

classify_step_failure() {
  local log_path="$1"
  if [[ ! -f "${log_path}" ]]; then
    echo "infra_blocked"
  elif log_has_infra_blocker "${log_path}"; then
    echo "infra_blocked"
  else
    echo "failed"
  fi
}

command_uses_rch_exec() {
  local previous=""
  local rch_name="${RCH_BIN##*/}"
  for arg in "$@"; do
    if [[ "${arg}" == "exec" ]] && {
      [[ "${previous}" == "rch" ]] ||
      [[ "${previous}" == "${RCH_BIN}" ]] ||
      [[ "${previous##*/}" == "${rch_name}" ]]
    }; then
      return 0
    fi
    previous="${arg}"
  done
  return 1
}

rch_remote_summary_present() {
  local log_path="$1"
  local line
  while IFS= read -r line; do
    if [[ "${line}" == *"[RCH] remote"* ]]; then
      return 0
    fi
  done < "${log_path}"
  return 1
}

command_is_source_state_step() {
  local previous=""
  for arg in "$@"; do
    if [[ "${previous}" == "cargo" && "${arg}" == "fmt" ]]; then
      return 0
    fi
    previous="${arg}"
  done
  return 1
}

require_rch_remote_proof() {
  local name="$1"
  local log_path="$2"
  shift 2

  if command_is_source_state_step "$@"; then
    return 0
  fi

  if command_uses_rch_exec "$@" && ! rch_remote_summary_present "${log_path}"; then
    echo "[coda-verification] ${name}: rch command did not produce remote proof" >&2
    echo "rch command did not produce remote proof" >>"${log_path}"
    return 1
  fi
}

require_cmd jq
require_cmd "${RCH_BIN}"

manifest_check_cmd=(
  env
  "RCH_REQUIRE_REMOTE=${RCH_REQUIRE_REMOTE}"
  RCH_FORCE_REMOTE=1
  RCH_VISIBILITY=verbose
  "${RCH_BIN}"
  exec
  --
  env
  "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}"
  CARGO_INCREMENTAL=0
  "CARGO_BUILD_JOBS=${BUILD_JOBS}"
  CARGO_TARGET_DIR="${REMOTE_TARGET_BASE}-fwc"
  cargo
  run
  -q
  -p
  fwc
  --
  manifest
  fix
  connectors/coda/manifest.toml
  --check
  --json
)

if run_capture_stdout \
  manifest_check \
  "${manifest_stdout_path}" \
  "${manifest_check_cmd[@]}"
then
  manifest_status="passed"
  cp "${manifest_stdout_path}" "${OUT_ROOT}/evidence/manifest_check.json"
else
  manifest_status="$(classify_manifest_failure "${OUT_ROOT}/logs/manifest_check.log")"
  if [[ "${manifest_status}" == "infra_blocked" ]]; then
    if log_has_remote_proof_failure "${OUT_ROOT}/logs/manifest_check.log"; then
      manifest_note="rch command did not produce remote proof for fallback manifest validation"
    else
      manifest_note="infrastructure blocked manifest validation; inspect logs/manifest_check.log"
    fi
  else
    manifest_note="manifest validation command failed; inspect logs/manifest_check.log"
  fi
  jq -n \
    --arg status "${manifest_status}" \
    --arg note "${manifest_note}" \
    --arg runner "rch:cargo-run" \
    --arg command_output "${manifest_stdout_path}" \
    --arg log "${OUT_ROOT}/logs/manifest_check.log" \
    '{status:$status,note:$note,runner:$runner,command_output:$command_output,log:$log}' \
    > "${OUT_ROOT}/evidence/manifest_check.json"
  promote_overall_status "${manifest_status}"
fi

if run_logged \
  cargo_check \
  env "RCH_REQUIRE_REMOTE=${RCH_REQUIRE_REMOTE}" RCH_FORCE_REMOTE=1 RCH_VISIBILITY=verbose "${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_INCREMENTAL=0 "CARGO_BUILD_JOBS=${BUILD_JOBS}" CARGO_TARGET_DIR="${REMOTE_TARGET_BASE}-check" cargo check -p fcp-coda --all-targets
then
  cargo_check_status="passed"
else
  cargo_check_status="$(classify_step_failure "${OUT_ROOT}/logs/cargo_check.log")"
  promote_overall_status "${cargo_check_status}"
fi

if run_logged \
  format_check \
  env -u RCH_FORCE_REMOTE -u RCH_REQUIRE_REMOTE RCH_VISIBILITY=verbose "${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_INCREMENTAL=0 "CARGO_BUILD_JOBS=${BUILD_JOBS}" CARGO_TARGET_DIR="${REMOTE_TARGET_BASE}-fmt" cargo fmt --manifest-path connectors/coda/Cargo.toml --check
then
  format_check_status="passed"
else
  format_check_status="$(classify_step_failure "${OUT_ROOT}/logs/format_check.log")"
  promote_overall_status "${format_check_status}"
fi

if run_logged \
  health_guidance_evidence \
  env "RCH_REQUIRE_REMOTE=${RCH_REQUIRE_REMOTE}" RCH_FORCE_REMOTE=1 RCH_VISIBILITY=verbose "${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_INCREMENTAL=0 "CARGO_BUILD_JOBS=${BUILD_JOBS}" CARGO_TARGET_DIR="${REMOTE_TARGET_BASE}-integration" cargo test -p fcp-coda --test integration health_unconfigured_includes_guidance -- --nocapture
then
  health_guidance_status="passed"
else
  health_guidance_status="$(classify_step_failure "${OUT_ROOT}/logs/health_guidance_evidence.log")"
  promote_overall_status "${health_guidance_status}"
fi

if run_logged \
  doctor_guidance_evidence \
  env "RCH_REQUIRE_REMOTE=${RCH_REQUIRE_REMOTE}" RCH_FORCE_REMOTE=1 RCH_VISIBILITY=verbose "${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_INCREMENTAL=0 "CARGO_BUILD_JOBS=${BUILD_JOBS}" CARGO_TARGET_DIR="${REMOTE_TARGET_BASE}-integration" cargo test -p fcp-coda --test integration doctor_unconfigured_reports_operator_guidance -- --nocapture
then
  doctor_guidance_status="passed"
else
  doctor_guidance_status="$(classify_step_failure "${OUT_ROOT}/logs/doctor_guidance_evidence.log")"
  promote_overall_status "${doctor_guidance_status}"
fi

if run_logged \
  self_check_evidence \
  env "RCH_REQUIRE_REMOTE=${RCH_REQUIRE_REMOTE}" RCH_FORCE_REMOTE=1 RCH_VISIBILITY=verbose "${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_INCREMENTAL=0 "CARGO_BUILD_JOBS=${BUILD_JOBS}" CARGO_TARGET_DIR="${REMOTE_TARGET_BASE}-integration" cargo test -p fcp-coda --test integration self_check_ready_with_mock_coda_api_and_evidence -- --nocapture
then
  self_check_status="passed"
else
  self_check_status="$(classify_step_failure "${OUT_ROOT}/logs/self_check_evidence.log")"
  promote_overall_status "${self_check_status}"
fi

if run_logged \
  retryable_self_check_evidence \
  env "RCH_REQUIRE_REMOTE=${RCH_REQUIRE_REMOTE}" RCH_FORCE_REMOTE=1 RCH_VISIBILITY=verbose "${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_INCREMENTAL=0 "CARGO_BUILD_JOBS=${BUILD_JOBS}" CARGO_TARGET_DIR="${REMOTE_TARGET_BASE}-integration" cargo test -p fcp-coda --test integration self_check_retryable_coda_failure_reports_degraded -- --nocapture
then
  retryable_self_check_status="passed"
else
  retryable_self_check_status="$(classify_step_failure "${OUT_ROOT}/logs/retryable_self_check_evidence.log")"
  promote_overall_status "${retryable_self_check_status}"
fi

if run_logged \
  pagination_evidence \
  env "RCH_REQUIRE_REMOTE=${RCH_REQUIRE_REMOTE}" RCH_FORCE_REMOTE=1 RCH_VISIBILITY=verbose "${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_INCREMENTAL=0 "CARGO_BUILD_JOBS=${BUILD_JOBS}" CARGO_TARGET_DIR="${REMOTE_TARGET_BASE}-integration" cargo test -p fcp-coda --test integration invoke_docs_list_preserves_pagination_and_scope_evidence -- --nocapture
then
  pagination_evidence_status="passed"
else
  pagination_evidence_status="$(classify_step_failure "${OUT_ROOT}/logs/pagination_evidence.log")"
  promote_overall_status "${pagination_evidence_status}"
fi

if run_logged \
  dangerous_delete_evidence \
  env "RCH_REQUIRE_REMOTE=${RCH_REQUIRE_REMOTE}" RCH_FORCE_REMOTE=1 RCH_VISIBILITY=verbose "${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_INCREMENTAL=0 "CARGO_BUILD_JOBS=${BUILD_JOBS}" CARGO_TARGET_DIR="${REMOTE_TARGET_BASE}-integration" cargo test -p fcp-coda --test integration invoke_rows_delete_tracks_async_mutation_evidence -- --nocapture
then
  dangerous_delete_status="passed"
else
  dangerous_delete_status="$(classify_step_failure "${OUT_ROOT}/logs/dangerous_delete_evidence.log")"
  promote_overall_status "${dangerous_delete_status}"
fi

if run_logged \
  compliance_evidence \
  env "RCH_REQUIRE_REMOTE=${RCH_REQUIRE_REMOTE}" RCH_FORCE_REMOTE=1 RCH_VISIBILITY=verbose "${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_INCREMENTAL=0 "CARGO_BUILD_JOBS=${BUILD_JOBS}" CARGO_TARGET_DIR="${REMOTE_TARGET_BASE}-integration" cargo test -p fcp-coda --test integration introspection_emits_v3_compliance_evidence -- --nocapture
then
  compliance_status="passed"
else
  compliance_status="$(classify_step_failure "${OUT_ROOT}/logs/compliance_evidence.log")"
  promote_overall_status "${compliance_status}"
fi

if run_logged \
  integration_suite \
  env "RCH_REQUIRE_REMOTE=${RCH_REQUIRE_REMOTE}" RCH_FORCE_REMOTE=1 RCH_VISIBILITY=verbose "${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_INCREMENTAL=0 "CARGO_BUILD_JOBS=${BUILD_JOBS}" CARGO_TARGET_DIR="${REMOTE_TARGET_BASE}-integration" cargo test -p fcp-coda --test integration -- --nocapture
then
  integration_suite_status="passed"
else
  integration_suite_status="$(classify_step_failure "${OUT_ROOT}/logs/integration_suite.log")"
  promote_overall_status "${integration_suite_status}"
fi

if run_logged \
  crate_suite \
  env "RCH_REQUIRE_REMOTE=${RCH_REQUIRE_REMOTE}" RCH_FORCE_REMOTE=1 RCH_VISIBILITY=verbose "${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_INCREMENTAL=0 "CARGO_BUILD_JOBS=${BUILD_JOBS}" CARGO_TARGET_DIR="${REMOTE_TARGET_BASE}-crate" cargo test -p fcp-coda
then
  crate_suite_status="passed"
else
  crate_suite_status="$(classify_step_failure "${OUT_ROOT}/logs/crate_suite.log")"
  promote_overall_status "${crate_suite_status}"
fi

if run_logged \
  clippy \
  env "RCH_REQUIRE_REMOTE=${RCH_REQUIRE_REMOTE}" RCH_FORCE_REMOTE=1 RCH_VISIBILITY=verbose "${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_INCREMENTAL=0 "CARGO_BUILD_JOBS=${BUILD_JOBS}" CARGO_TARGET_DIR="${REMOTE_TARGET_BASE}-clippy" cargo clippy -p fcp-coda --all-targets -- -D warnings
then
  clippy_status="passed"
else
  clippy_status="$(classify_step_failure "${OUT_ROOT}/logs/clippy.log")"
  promote_overall_status "${clippy_status}"
fi

jq -n \
  --arg status "${OVERALL_STATUS}" \
  --arg manifest_check_runner "rch:cargo-run" \
  --arg artifact_root "${OUT_ROOT}" \
  --arg remote_target_base "${REMOTE_TARGET_BASE}" \
  --arg toolchain "${REPO_TOOLCHAIN}" \
  --arg manifest_check "${manifest_status}" \
  --arg cargo_check "${cargo_check_status}" \
  --arg format_check "${format_check_status}" \
  --arg health_guidance "${health_guidance_status}" \
  --arg doctor_guidance "${doctor_guidance_status}" \
  --arg self_check "${self_check_status}" \
  --arg retryable_self_check "${retryable_self_check_status}" \
  --arg pagination_evidence "${pagination_evidence_status}" \
  --arg dangerous_delete_evidence "${dangerous_delete_status}" \
  --arg compliance "${compliance_status}" \
  --arg integration_suite "${integration_suite_status}" \
  --arg crate_suite "${crate_suite_status}" \
  --arg clippy "${clippy_status}" \
  '{
    status: $status,
    manifest_check_runner: $manifest_check_runner,
    artifact_root: $artifact_root,
    remote_target_base: $remote_target_base,
    toolchain: $toolchain,
    checks: {
      manifest_check: $manifest_check,
      cargo_check: $cargo_check,
      format_check: $format_check,
      health_guidance: $health_guidance,
      doctor_guidance: $doctor_guidance,
      self_check: $self_check,
      retryable_self_check: $retryable_self_check,
      pagination_evidence: $pagination_evidence,
      dangerous_delete_evidence: $dangerous_delete_evidence,
      compliance: $compliance,
      integration_suite: $integration_suite,
      crate_suite: $crate_suite,
      clippy: $clippy
    }
  }' > "${OUT_ROOT}/evidence/summary.json"

echo "[coda-verification] summary: ${OUT_ROOT}/evidence/summary.json"
exit "${EXIT_CODE}"
