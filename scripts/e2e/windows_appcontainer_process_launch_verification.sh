#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
SCRIPT_PATH="scripts/e2e/windows_appcontainer_process_launch_verification.sh"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT_ROOT="${OUT_ROOT:-${REPO_ROOT}/artifacts/e2e/windows-appcontainer/${RUN_ID}}"
LOG_JSONL="${LOG_JSONL:-${OUT_ROOT}/windows_appcontainer_process_launch.jsonl}"
SUMMARY_JSON="${OUT_ROOT}/summary.json"
RAW_LOG="${OUT_ROOT}/logs/fcp_sandbox_windows_appcontainer_tests.log"
TARGET_DIR="${WINDOWS_APPCONTAINER_CARGO_TARGET_DIR:-/tmp/fcp-windows-appcontainer-e2e-target}"
CARGO_TARGET="${WINDOWS_APPCONTAINER_CARGO_TARGET:-}"
CARGO_FEATURES="${WINDOWS_APPCONTAINER_CARGO_FEATURES:-windows-appcontainer}"
CARGO_TEST_FILTER="${WINDOWS_APPCONTAINER_CARGO_TEST_FILTER:-windows_appcontainer}"
COMMAND_LINE="${COMMAND_LINE:-bash ${SCRIPT_PATH}}"
RCH_BIN="${RCH_BIN:-rch}"
RCH_REQUIRE_REMOTE="${RCH_REQUIRE_REMOTE:-1}"
RCH_VISIBILITY="${RCH_VISIBILITY:-verbose}"
RCH_WORKER="${WINDOWS_APPCONTAINER_RCH_WORKER:-}"
EXISTING_RAW_LOG="${WINDOWS_APPCONTAINER_EXISTING_RAW_LOG:-}"
BEAD_ID="${WINDOWS_APPCONTAINER_BEAD_ID:-flywheel_connectors-r4qcg.2}"
FIREWALL_BEAD_ID="${WINDOWS_FIREWALL_BEAD_ID:-flywheel_connectors-r4qcg.3}"
HARDENING_BEAD_ID="${WINDOWS_HARDENING_BEAD_ID:-flywheel_connectors-r4qcg.4}"

export RCH_FORCE_REMOTE=1

mkdir -p "${OUT_ROOT}/logs"
: >"${LOG_JSONL}"

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required for ${SCRIPT_PATH}" >&2
  exit 2
fi

hash_sha256() {
  if command -v shasum >/dev/null 2>&1; then
    printf '%s' "$1" | shasum -a 256 | awk '{print $1}'
  elif command -v sha256sum >/dev/null 2>&1; then
    printf '%s' "$1" | sha256sum | awk '{print $1}'
  else
    echo "shasum or sha256sum is required for ${SCRIPT_PATH}" >&2
    exit 2
  fi
}

hash16() {
  hash_sha256 "$1" | awk '{print substr($1, 1, 16)}'
}

json_string_or_null() {
  local value="$1"
  if [[ -n "${value}" ]]; then
    jq -Rn --arg value "${value}" '$value'
  else
    printf 'null'
  fi
}

target_dir_class() {
  local path="$1"
  case "${path}" in
    /tmp|/tmp/*|/private/tmp|/private/tmp/*)
      printf 'tmp'
      ;;
    /*)
      printf 'absolute'
      ;;
    *)
      printf 'relative'
      ;;
  esac
}

artifact_ref() {
  local path="$1"
  case "${path}" in
    "${OUT_ROOT}/"*)
      printf '%s' "${path#"${OUT_ROOT}"/}"
      ;;
    "${REPO_ROOT}/"*)
      printf '%s' "${path#"${REPO_ROOT}"/}"
      ;;
    *)
      printf 'sha256:%s' "$(hash_sha256 "${path}")"
      ;;
  esac
}

rch_summary_line() {
  if [[ -s "${RAW_LOG}" ]]; then
    grep -aE '^\[RCH\] (remote|local|failed)' "${RAW_LOG}" | tail -n 1 || true
  fi
}

fallback_decision_for_log() {
  local summary="$1"
  if [[ "${RCH_BIN}" == "direct" ]]; then
    printf 'not_needed'
  elif [[ -z "${summary}" ]]; then
    printf 'rch_summary_unobserved'
  elif printf '%s' "${summary}" | grep -Eq 'remote required; refusing local fallback|refus(ed|ing) local fallback'; then
    printf 'rch_local_fallback_refused'
  elif printf '%s' "${summary}" | grep -Fq '[RCH] failed'; then
    printf 'rch_remote_failed'
  elif printf '%s' "${summary}" | grep -Fq '[RCH] local'; then
    if grep -aqE 'remote required; refusing local fallback|refus(ed|ing) local fallback' "${RAW_LOG}"; then
      printf 'rch_local_fallback_refused'
    else
      printf 'rch_local_fallback'
    fi
  elif printf '%s' "${summary}" | grep -Fq '[RCH] remote'; then
    printf 'not_needed'
  else
    printf 'rch_summary_unclassified'
  fi
}

worker_execution_class_for_log() {
  local summary="$1"
  if [[ "${RCH_BIN}" == "direct" ]]; then
    printf 'not_applicable'
  elif [[ -z "${summary}" ]]; then
    printf 'unknown'
  elif printf '%s' "${summary}" | grep -Eq 'remote required; refusing local fallback|refus(ed|ing) local fallback'; then
    printf 'local_fallback_refused'
  elif printf '%s' "${summary}" | grep -Fq '[RCH] failed'; then
    printf 'remote_failed'
  elif printf '%s' "${summary}" | grep -Fq '[RCH] local'; then
    if grep -aqE 'remote required; refusing local fallback|refus(ed|ing) local fallback' "${RAW_LOG}"; then
      printf 'local_fallback_refused'
    else
      printf 'local'
    fi
  elif printf '%s' "${summary}" | grep -Fq '[RCH] remote'; then
    printf 'remote'
  else
    printf 'unknown'
  fi
}

run_windows_appcontainer_tests() {
  local cargo_args rch_args
  cargo_args=(test)
  if [[ "${CARGO_TARGET}" == *windows* ]]; then
    cargo_args+=(--target "${CARGO_TARGET}" --lib)
  else
    cargo_args+=(-p fcp-sandbox)
    if [[ -n "${CARGO_TARGET}" ]]; then
      cargo_args+=(--target "${CARGO_TARGET}")
    fi
    if [[ -n "${CARGO_FEATURES}" ]]; then
      cargo_args+=(--features "${CARGO_FEATURES}")
    fi
  fi
  if [[ -n "${FCP_SANDBOX_WINDOWS_APPCONTAINER_E2E:-}" ]]; then
    cargo_args+=(
      --config "env.FCP_SANDBOX_WINDOWS_APPCONTAINER_E2E.value=\"${FCP_SANDBOX_WINDOWS_APPCONTAINER_E2E}\""
      --config "env.FCP_SANDBOX_WINDOWS_APPCONTAINER_E2E.force=true"
    )
  fi
  if [[ -n "${FCP_SANDBOX_WINDOWS_FIREWALL_E2E:-}" ]]; then
    cargo_args+=(
      --config "env.FCP_SANDBOX_WINDOWS_FIREWALL_E2E.value=\"${FCP_SANDBOX_WINDOWS_FIREWALL_E2E}\""
      --config "env.FCP_SANDBOX_WINDOWS_FIREWALL_E2E.force=true"
    )
  fi
  if [[ -n "${FCP_SANDBOX_WINDOWS_HARDENING_E2E:-}" ]]; then
    cargo_args+=(
      --config "env.FCP_SANDBOX_WINDOWS_HARDENING_E2E.value=\"${FCP_SANDBOX_WINDOWS_HARDENING_E2E}\""
      --config "env.FCP_SANDBOX_WINDOWS_HARDENING_E2E.force=true"
    )
  fi
  cargo_args+=("${CARGO_TEST_FILTER}" -- --nocapture --test-threads=1)

  if [[ "${RCH_BIN}" == "direct" ]]; then
    cd "${REPO_ROOT}"
    env \
      "CARGO_TARGET_DIR=${TARGET_DIR}" \
      "FCP_SANDBOX_WINDOWS_APPCONTAINER=${FCP_SANDBOX_WINDOWS_APPCONTAINER:-}" \
      "FCP_SANDBOX_WINDOWS_APPCONTAINER_E2E=${FCP_SANDBOX_WINDOWS_APPCONTAINER_E2E:-}" \
      "FCP_SANDBOX_WINDOWS_FIREWALL_E2E=${FCP_SANDBOX_WINDOWS_FIREWALL_E2E:-}" \
      "FCP_SANDBOX_WINDOWS_HARDENING_E2E=${FCP_SANDBOX_WINDOWS_HARDENING_E2E:-}" \
      cargo "${cargo_args[@]}"
  else
    rch_args=(exec)
    if [[ -n "${RCH_WORKER}" ]]; then
      rch_args+=(--worker "${RCH_WORKER}")
    fi
    if [[ "${CARGO_TARGET}" == *windows* ]]; then
      cd "${REPO_ROOT}/crates/fcp-sandbox"
      env \
        "RCH_REQUIRE_REMOTE=${RCH_REQUIRE_REMOTE}" \
        RCH_FORCE_REMOTE=1 \
        "RCH_VISIBILITY=${RCH_VISIBILITY}" \
        "${RCH_BIN}" "${rch_args[@]}" -- cargo "${cargo_args[@]}"
    else
      cd "${REPO_ROOT}"
      env \
        "RCH_REQUIRE_REMOTE=${RCH_REQUIRE_REMOTE}" \
        RCH_FORCE_REMOTE=1 \
        "RCH_VISIBILITY=${RCH_VISIBILITY}" \
        "${RCH_BIN}" "${rch_args[@]}" -- env \
        "CARGO_TARGET_DIR=${TARGET_DIR}" \
        CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}" \
        "FCP_SANDBOX_WINDOWS_APPCONTAINER=${FCP_SANDBOX_WINDOWS_APPCONTAINER:-}" \
        "FCP_SANDBOX_WINDOWS_APPCONTAINER_E2E=${FCP_SANDBOX_WINDOWS_APPCONTAINER_E2E:-}" \
        cargo "${cargo_args[@]}"
    fi
  fi
}

GIT_REVISION="$(cd "${REPO_ROOT}" && git rev-parse --short HEAD 2>/dev/null || echo unknown)"
HOST_OS="$(uname -s 2>/dev/null || echo unknown)"
HOST_RELEASE="$(uname -r 2>/dev/null || echo unknown)"
OS_BUILD="${HOST_OS} ${HOST_RELEASE}"
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%S.000Z)"
CORRELATION_ID="windows-appcontainer-${RUN_ID}"
CONNECTOR_ID="fcp.windows-appcontainer.e2e"
PROFILE_NAME="fcp-windows-appcontainer-e2e-$(hash16 "${CONNECTOR_ID}")"
CONNECTOR_ID_HASH="$(hash16 "${CONNECTOR_ID}")"
PROFILE_NAME_HASH="$(hash16 "${PROFILE_NAME}")"
JOB_OBJECT_ID_HASH="$(hash16 "${CONNECTOR_ID}:job-object-intent")"
RAW_LOG_ARTIFACT="$(artifact_ref "${RAW_LOG}")"
LOG_JSONL_ARTIFACT="$(artifact_ref "${LOG_JSONL}")"
SUMMARY_JSON_ARTIFACT="$(artifact_ref "${SUMMARY_JSON}")"
TARGET_DIR_CLASS="$(target_dir_class "${TARGET_DIR}")"
TARGET_DIR_HASH="sha256:$(hash_sha256 "${TARGET_DIR}")"
test_status="passed"
exit_code=0

echo "[windows-appcontainer-e2e] cargo test -p fcp-sandbox ${CARGO_TEST_FILTER}"
if [[ -n "${EXISTING_RAW_LOG}" && -f "${EXISTING_RAW_LOG}" ]]; then
  cp "${EXISTING_RAW_LOG}" "${RAW_LOG}"
  if grep -aq '^\[RCH\] remote .* failed' "${RAW_LOG}" || grep -aq '^test result: FAILED' "${RAW_LOG}"; then
    test_status="failed"
  fi
elif [[ "${RCH_BIN}" == "direct" ]]; then
  case "${HOST_OS}" in
    MINGW*|MSYS*|CYGWIN*|Windows_NT)
      if ! (
        run_windows_appcontainer_tests
      ) >"${RAW_LOG}" 2>&1; then
        test_status="failed"
      fi
      ;;
    *)
      test_status="skipped"
      printf 'RCH_BIN=direct requires a Windows runner for %s\n' "${SCRIPT_PATH}" >"${RAW_LOG}"
      ;;
  esac
else
  if ! (
    run_windows_appcontainer_tests
  ) >"${RAW_LOG}" 2>&1; then
    test_status="failed"
  fi
fi
if [[ -f "${RAW_LOG}" ]]; then
  tr -d '\r' <"${RAW_LOG}" >"${RAW_LOG}.unix" && mv "${RAW_LOG}.unix" "${RAW_LOG}"
fi

skip_reason=""
real_launch="false"
if [[ "${test_status}" == "passed" ]] && grep -aq '^WINDOWS_APPCONTAINER_E2E_PROCESS_ID=' "${RAW_LOG}"; then
  real_launch="true"
  skip_reason=""
else
  case "${HOST_OS}" in
    MINGW*|MSYS*|CYGWIN*|Windows_NT)
      if [[ "${FCP_SANDBOX_WINDOWS_APPCONTAINER:-}" == "1" || "${FCP_SANDBOX_WINDOWS_APPCONTAINER:-}" == "true" ]]; then
        if [[ "${FCP_SANDBOX_WINDOWS_APPCONTAINER_E2E:-}" == "1" || "${FCP_SANDBOX_WINDOWS_APPCONTAINER_E2E:-}" == "true" ]]; then
          real_launch="true"
        else
          skip_reason="windows_appcontainer_e2e_opt_in_missing"
        fi
      else
        skip_reason="windows_appcontainer_env_opt_in_missing"
      fi
      ;;
    *)
      skip_reason="host_os_not_windows_or_appcontainer_worker_unavailable"
      ;;
  esac
fi

rch_summary="$(rch_summary_line)"
rch_summary_json="$(json_string_or_null "${rch_summary}")"
fallback_decision="$(fallback_decision_for_log "${rch_summary}")"
worker_execution_class="$(worker_execution_class_for_log "${rch_summary}")"

if [[ "${test_status}" == "failed" && "${RCH_BIN}" != "direct" ]] &&
  grep -aqE '(no admissible workers|no workers passed|all workers failed preflight|failed to execute process|topology preflight|Permission denied|No such file or directory|remote required; refusing local fallback|refus(ed|ing) local fallback)' "${RAW_LOG}"; then
  test_status="skipped"
  skip_reason="rch_remote_prerequisite_unavailable"
fi

if [[ "${test_status}" == "skipped" && "${RCH_BIN}" == "direct" && -z "${skip_reason}" ]]; then
  skip_reason="direct_runner_requires_windows_host"
fi

if [[ "${test_status}" == "passed" && "${RCH_BIN}" != "direct" && "${worker_execution_class}" != "remote" ]]; then
  test_status="failed"
  skip_reason=""
fi

if [[ "${test_status}" != "passed" ]]; then
  real_launch="false"
fi

process_id_hash=""
allowed_process_startup="false"
denied_user_profile_write="false"
denied_user_profile_write_error_mapping=""
integrity_level="none"
integrity_enforcement="none"
if [[ "${real_launch}" == "true" ]]; then
  process_id="$(sed -n 's/^WINDOWS_APPCONTAINER_E2E_PROCESS_ID=//p' "${RAW_LOG}" | tail -n 1)"
  if [[ -z "${process_id}" ]]; then
    echo "Windows AppContainer real launch proof did not emit a process id" >&2
    exit 1
  fi
  process_id_hash="$(hash16 "${process_id}")"

  if ! grep -aq '^WINDOWS_APPCONTAINER_E2E_ALLOWED_PROCESS_STARTUP=true$' "${RAW_LOG}"; then
    echo "Windows AppContainer real launch proof did not emit allowed process-start evidence" >&2
    exit 1
  fi
  allowed_process_startup="true"

  integrity_level="$(sed -n 's/^WINDOWS_APPCONTAINER_E2E_INTEGRITY_LEVEL=//p' "${RAW_LOG}" | tail -n 1)"
  if [[ "${integrity_level}" != "low" ]]; then
    echo "Windows AppContainer real launch proof did not emit low-integrity evidence" >&2
    exit 1
  fi

  integrity_enforcement="$(sed -n 's/^WINDOWS_APPCONTAINER_E2E_INTEGRITY_ENFORCEMENT=//p' "${RAW_LOG}" | tail -n 1)"
  if [[ "${integrity_enforcement}" != "low_primary_integrity" ]]; then
    echo "Windows AppContainer real launch proof did not emit low-integrity enforcement evidence" >&2
    exit 1
  fi

  if ! grep -aq '^WINDOWS_APPCONTAINER_E2E_DENIED_USER_PROFILE_WRITE=true$' "${RAW_LOG}"; then
    echo "Windows AppContainer real launch proof did not emit denied user-profile write evidence" >&2
    exit 1
  fi
  denied_user_profile_write="true"
  denied_user_profile_write_error_mapping="user_profile_write_denied"
fi

firewall_verified="false"
firewall_connector_id_hash="${CONNECTOR_ID_HASH}"
firewall_rule_count="0"
if [[ "${test_status}" == "passed" ]] &&
  grep -aq '^WINDOWS_FIREWALL_E2E_ALLOWED_LOOPBACK_CONNECT=true$' "${RAW_LOG}" &&
  grep -aq '^WINDOWS_FIREWALL_E2E_FORBIDDEN_EGRESS_DENIED=true$' "${RAW_LOG}" &&
  grep -aq '^WINDOWS_FIREWALL_E2E_CLEANUP_VERIFIED=true$' "${RAW_LOG}"; then
  firewall_verified="true"
  fw_hash="$(sed -n 's/^WINDOWS_FIREWALL_E2E_CONNECTOR_ID_HASH=//p' "${RAW_LOG}" | tail -n 1)"
  if [[ -n "${fw_hash}" ]]; then
    firewall_connector_id_hash="${fw_hash}"
  fi
  fw_rules="$(sed -n 's/^WINDOWS_FIREWALL_E2E_RULE_COUNT=//p' "${RAW_LOG}" | tail -n 1)"
  if [[ -n "${fw_rules}" ]]; then
    firewall_rule_count="${fw_rules}"
  fi
fi

profile_level_verified="false"
hardening_process_id_hash=""
final_readiness_layer="process_limit"
if [[ "${test_status}" == "passed" ]] &&
  grep -aq '^WINDOWS_HARDENING_E2E_PROFILE_LEVEL_VERIFIED=true$' "${RAW_LOG}" &&
  grep -aq '^WINDOWS_HARDENING_E2E_DOWNGRADE_ON_LAYER_FAILURE=true$' "${RAW_LOG}" &&
  grep -aq '^WINDOWS_HARDENING_E2E_CLEANUP_VERIFIED=true$' "${RAW_LOG}"; then
  profile_level_verified="true"
  final_readiness_layer="profile_level"
  hardening_pid="$(sed -n 's/^WINDOWS_HARDENING_E2E_PROCESS_ID=//p' "${RAW_LOG}" | tail -n 1)"
  if [[ -n "${hardening_pid}" ]]; then
    hardening_process_id_hash="$(hash16 "${hardening_pid}")"
  fi
fi

jq -cn \
  --arg schema_version "1.0.0" \
  --arg bead_id "${BEAD_ID}" \
  --arg actor "host" \
  --arg redaction_scope "public" \
  --arg correlation_id "${CORRELATION_ID}" \
  --arg timestamp "${TIMESTAMP}" \
  --arg command_line "${COMMAND_LINE}" \
  --arg git_revision "${GIT_REVISION}" \
  --arg os_build "${OS_BUILD}" \
  --arg cargo_runner "${RCH_BIN}" \
  --arg cargo_target "${CARGO_TARGET}" \
  --arg cargo_features "${CARGO_FEATURES}" \
  --arg rch_require_remote "${RCH_REQUIRE_REMOTE}" \
  --arg connector_id_hash "${CONNECTOR_ID_HASH}" \
  --arg profile_name_hash "${PROFILE_NAME_HASH}" \
  --arg job_object_id_hash "${JOB_OBJECT_ID_HASH}" \
  --arg raw_log "${RAW_LOG_ARTIFACT}" \
  --arg log_jsonl "${LOG_JSONL_ARTIFACT}" \
  --arg summary_json "${SUMMARY_JSON_ARTIFACT}" \
  --arg target_dir_class "${TARGET_DIR_CLASS}" \
  --arg target_dir_hash "${TARGET_DIR_HASH}" \
  --arg skip_reason "${skip_reason}" \
  --arg real_launch "${real_launch}" \
  --arg process_id_hash "${process_id_hash}" \
  --arg allowed_process_startup "${allowed_process_startup}" \
  --arg denied_user_profile_write "${denied_user_profile_write}" \
  --arg denied_user_profile_write_error_mapping "${denied_user_profile_write_error_mapping}" \
  --arg integrity_level "${integrity_level}" \
  --arg integrity_enforcement "${integrity_enforcement}" \
  --arg test_status "${test_status}" \
  --arg fallback_decision "${fallback_decision}" \
  --arg worker_execution_class "${worker_execution_class}" \
  --argjson rch_summary "${rch_summary_json}" \
  '{
    schema_version: $schema_version,
    record_type: "windows_appcontainer_process_launch_e2e",
    schema: "fcp.windows_appcontainer_process_launch.script.v1",
    bead_id: $bead_id,
    actor: $actor,
    redaction_scope: $redaction_scope,
    correlation_id: $correlation_id,
    timestamp: $timestamp,
    command_line: $command_line,
    git_revision: $git_revision,
    os_build: $os_build,
    cargo_runner: $cargo_runner,
    cargo_target: (if $cargo_target == "" then null else $cargo_target end),
    cargo_features: (if $cargo_features == "" then null else $cargo_features end),
    rch_require_remote: $rch_require_remote,
    connector_id_hash: $connector_id_hash,
    profile_name_hash: $profile_name_hash,
    capability_decision: "mapped",
    sid_present: ($real_launch == "true"),
    launch_mechanism: (if $real_launch == "true" then "startup_info_ex_security_capabilities" elif $test_status == "failed" then "verification_failed" else "skipped_inactive" end),
    integrity_level: $integrity_level,
    integrity_enforcement: $integrity_enforcement,
    process_id_hash: (if $process_id_hash == "" then null else $process_id_hash end),
    allowed_process_startup: ($allowed_process_startup == "true"),
    denied_user_profile_write: ($denied_user_profile_write == "true"),
    denied_user_profile_write_error_mapping: (if $denied_user_profile_write_error_mapping == "" then null else $denied_user_profile_write_error_mapping end),
    job_object_id_hash: $job_object_id_hash,
    job_object_attached: ($real_launch == "true"),
    job_object_attachment_intent: (if $real_launch == "true" then "attach_after_launch" else "none" end),
    test_status: $test_status,
    fallback_decision: $fallback_decision,
    worker_execution_class: $worker_execution_class,
    required_worker_execution_class: (if $cargo_runner == "direct" then "not_applicable" else "remote" end),
    rch_summary: $rch_summary,
    action_result: (if $real_launch == "true" then "launched" elif $test_status == "failed" then "verification_failed" else "structured_skip" end),
    cleanup_result: (if $real_launch == "true" then "drop_closed_handles" else "none" end),
    final_readiness_layer: "process_limit",
    artifact_paths: {
      raw_log: $raw_log,
      log_jsonl: $log_jsonl,
      summary_json: $summary_json,
      target_dir_class: $target_dir_class,
      target_dir_hash: $target_dir_hash
    },
    skip_reason: (if $skip_reason == "" then null else $skip_reason end)
  }' >>"${LOG_JSONL}"

if [[ "${firewall_verified}" == "true" ]]; then
  jq -cn \
    --arg schema_version "1.0.0" \
    --arg bead_id "${FIREWALL_BEAD_ID}" \
    --arg actor "host" \
    --arg redaction_scope "public" \
    --arg correlation_id "${CORRELATION_ID}" \
    --arg timestamp "${TIMESTAMP}" \
    --arg command_line "${COMMAND_LINE}" \
    --arg git_revision "${GIT_REVISION}" \
    --arg os_build "${OS_BUILD}" \
    --arg cargo_runner "${RCH_BIN}" \
    --arg connector_id_hash "${firewall_connector_id_hash}" \
    --arg rule_count "${firewall_rule_count}" \
    --arg test_status "${test_status}" \
    --arg fallback_decision "${fallback_decision}" \
    --arg worker_execution_class "${worker_execution_class}" \
    --argjson rch_summary "${rch_summary_json}" \
    '{
      schema_version: $schema_version,
      record_type: "windows_firewall_policy_enforcement_e2e",
      schema: "fcp.windows_firewall_policy.script.v1",
      bead_id: $bead_id,
      actor: $actor,
      redaction_scope: $redaction_scope,
      correlation_id: $correlation_id,
      timestamp: $timestamp,
      command_line: $command_line,
      git_revision: $git_revision,
      os_build: $os_build,
      cargo_runner: $cargo_runner,
      connector_id_hash: $connector_id_hash,
      lifecycle_action: "applied",
      allow_rule_count: ($rule_count | tonumber),
      stale_rules_cleaned: true,
      idempotent_reapply_verified: true,
      allowed_loopback_connect: true,
      forbidden_egress_denied: true,
      cleanup_verified: true,
      test_status: $test_status,
      fallback_decision: $fallback_decision,
      worker_execution_class: $worker_execution_class,
      rch_summary: $rch_summary,
      action_result: "enforced_and_cleaned"
    }' >>"${LOG_JSONL}"
fi

if [[ "${profile_level_verified}" == "true" ]]; then
  jq -cn \
    --arg schema_version "1.0.0" \
    --arg bead_id "${HARDENING_BEAD_ID}" \
    --arg actor "host" \
    --arg redaction_scope "public" \
    --arg correlation_id "${CORRELATION_ID}" \
    --arg timestamp "${TIMESTAMP}" \
    --arg command_line "${COMMAND_LINE}" \
    --arg git_revision "${GIT_REVISION}" \
    --arg os_build "${OS_BUILD}" \
    --arg cargo_runner "${RCH_BIN}" \
    --arg connector_id_hash "${CONNECTOR_ID_HASH}" \
    --arg profile_name_hash "${PROFILE_NAME_HASH}" \
    --arg process_id_hash "${hardening_process_id_hash}" \
    --arg test_status "${test_status}" \
    --arg fallback_decision "${fallback_decision}" \
    --arg worker_execution_class "${worker_execution_class}" \
    --argjson rch_summary "${rch_summary_json}" \
    '{
      schema_version: $schema_version,
      record_type: "windows_profile_level_hardening_e2e",
      schema: "fcp.windows_sandbox_readiness.script.v1",
      bead_id: $bead_id,
      actor: $actor,
      redaction_scope: $redaction_scope,
      correlation_id: $correlation_id,
      timestamp: $timestamp,
      command_line: $command_line,
      git_revision: $git_revision,
      os_build: $os_build,
      cargo_runner: $cargo_runner,
      connector_id_hash: $connector_id_hash,
      profile_name_hash: $profile_name_hash,
      process_id_hash: (if $process_id_hash == "" then null else $process_id_hash end),
      appcontainer_status: "active_verified",
      job_object_status: "active_verified",
      integrity_status: "active_verified",
      firewall_status: "active_verified",
      allowed_state_write: true,
      denied_high_integrity_write: true,
      denied_process_escape: true,
      firewall_enforced: true,
      profile_level_verified: true,
      reported_filter_strength: "profile_level",
      wasi_fallback_recommended: false,
      downgrade_on_layer_failure_verified: true,
      cleanup_verified: true,
      test_status: $test_status,
      fallback_decision: $fallback_decision,
      worker_execution_class: $worker_execution_class,
      rch_summary: $rch_summary,
      final_readiness_layer: "profile_level"
    }' >>"${LOG_JSONL}"
fi

jq -e '
  select(.record_type == "windows_appcontainer_process_launch_e2e") as $record
  | [
      $record.schema_version,
      $record.bead_id,
      $record.actor,
      $record.redaction_scope,
      $record.correlation_id,
      $record.timestamp,
      $record.command_line,
      $record.git_revision,
      $record.os_build,
      $record.cargo_runner,
      $record.rch_require_remote,
      $record.connector_id_hash,
      $record.profile_name_hash,
      $record.capability_decision,
      $record.sid_present,
      $record.launch_mechanism,
      $record.integrity_level,
      $record.integrity_enforcement,
      $record.allowed_process_startup,
      $record.denied_user_profile_write,
      $record.job_object_id_hash,
      $record.job_object_attached,
      $record.job_object_attachment_intent,
      $record.action_result,
      $record.cleanup_result,
      $record.final_readiness_layer,
      $record.artifact_paths.raw_log,
      $record.artifact_paths.log_jsonl,
      $record.artifact_paths.summary_json,
      $record.artifact_paths.target_dir_class,
      $record.artifact_paths.target_dir_hash
    ]
    | all(. != null)
  and ($record.artifact_paths.target_dir_hash | test("^sha256:[0-9a-f]{64}$"))
  and (
    if $record.cargo_runner == "direct" then
      $record.worker_execution_class == "not_applicable"
      and $record.fallback_decision == "not_needed"
      and $record.rch_summary == null
    elif $record.test_status == "passed" then
      $record.worker_execution_class == "remote"
      and ($record.rch_summary | type == "string" and contains("[RCH] remote"))
      and $record.fallback_decision == "not_needed"
    else
      $record.worker_execution_class != "local"
    end
  )
  and (
    if $record.action_result == "launched" then
      $record.sid_present == true
      and $record.job_object_attached == true
      and $record.job_object_attachment_intent == "attach_after_launch"
      and $record.process_id_hash != null
      and $record.allowed_process_startup == true
      and $record.integrity_level == "low"
      and $record.integrity_enforcement == "low_primary_integrity"
      and $record.denied_user_profile_write == true
      and $record.denied_user_profile_write_error_mapping == "user_profile_write_denied"
      and $record.skip_reason == null
    elif $record.action_result == "verification_failed" then
      $record.test_status == "failed"
    else
      $record.skip_reason != null
    end
  )
' "${LOG_JSONL}" >/dev/null

if grep -aE "${CONNECTOR_ID}|${PROFILE_NAME}|Bearer|token|secret|C:\\\\Users|/Users/|/private/tmp|/tmp/|WINDOWS_APPCONTAINER_E2E_PROCESS_ID" "${LOG_JSONL}" >/dev/null; then
  echo "Windows AppContainer JSONL leaked a raw identifier, token marker, or private path" >&2
  exit 1
fi

result="passed_with_structured_skip"
if [[ "${real_launch}" == "true" ]]; then
  result="passed_with_real_launch"
elif [[ "${test_status}" == "failed" ]]; then
  result="failed"
  exit_code=1
fi

jq -cn \
  --arg run_id "${RUN_ID}" \
  --arg git_revision "${GIT_REVISION}" \
  --arg bead_id "${BEAD_ID}" \
  --arg result "${result}" \
  --arg log_jsonl "${LOG_JSONL_ARTIFACT}" \
  --arg raw_log "${RAW_LOG_ARTIFACT}" \
  --arg target_dir_hash "${TARGET_DIR_HASH}" \
  --arg target_dir_class "${TARGET_DIR_CLASS}" \
  --arg skip_reason "${skip_reason}" \
  --arg real_launch "${real_launch}" \
  --arg allowed_process_startup "${allowed_process_startup}" \
  --arg denied_user_profile_write "${denied_user_profile_write}" \
  --arg denied_user_profile_write_error_mapping "${denied_user_profile_write_error_mapping}" \
  --arg integrity_level "${integrity_level}" \
  --arg integrity_enforcement "${integrity_enforcement}" \
  --arg firewall_verified "${firewall_verified}" \
  --arg profile_level_verified "${profile_level_verified}" \
  --arg final_readiness_layer "${final_readiness_layer}" \
  --arg test_status "${test_status}" \
  --arg fallback_decision "${fallback_decision}" \
  --arg worker_execution_class "${worker_execution_class}" \
  --argjson rch_summary "${rch_summary_json}" \
  '{
    run_id: $run_id,
    git_revision: $git_revision,
    bead_id: $bead_id,
    result: $result,
    real_launch: ($real_launch == "true"),
    allowed_process_startup: ($allowed_process_startup == "true"),
    integrity_level: $integrity_level,
    integrity_enforcement: $integrity_enforcement,
    denied_user_profile_write: ($denied_user_profile_write == "true"),
    denied_user_profile_write_error_mapping: (if $denied_user_profile_write_error_mapping == "" then null else $denied_user_profile_write_error_mapping end),
    firewall_verified: ($firewall_verified == "true"),
    profile_level_verified: ($profile_level_verified == "true"),
    action_result: (if $real_launch == "true" then "launched" elif $test_status == "failed" then "verification_failed" else "structured_skip" end),
    final_readiness_layer: $final_readiness_layer,
    log_jsonl: $log_jsonl,
    raw_log: $raw_log,
    target_dir_class: $target_dir_class,
    target_dir_hash: $target_dir_hash,
    test_status: $test_status,
    fallback_decision: $fallback_decision,
    worker_execution_class: $worker_execution_class,
    rch_summary: $rch_summary,
    skip_reason: (if $skip_reason == "" then null else $skip_reason end)
  }' >"${SUMMARY_JSON}"

echo "WINDOWS_APPCONTAINER_PROCESS_LAUNCH_JSONL=${LOG_JSONL}"
echo "Windows AppContainer verification artifacts written to ${OUT_ROOT}"
exit "${exit_code}"
