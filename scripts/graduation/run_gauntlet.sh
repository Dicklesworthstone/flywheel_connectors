#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHECKS_FILE="${SCRIPT_DIR}/checks/core.sh"
BATCH4_INVENTORY="${SCRIPT_DIR}/batch4_inventory.sh"

# shellcheck source=scripts/graduation/checks/core.sh
source "${CHECKS_FILE}"

JSONL_PATH=""
LIST_CHECKS=0
CONNECTOR_ARG=""
BATCH_ARG=""
STATUS_MD_PATH=""

BATCH1_CONNECTORS=(
  "connectors/postgresql"
  "connectors/stripe"
  "connectors/github"
  "connectors/gmail"
  "connectors/telegram"
  "connectors/slack"
  "connectors/kubernetes"
)

BATCH2_CONNECTORS=(
  "connectors/google-calendar"
  "connectors/google-drive"
  "connectors/google-docs"
  "connectors/google-sheets"
  "connectors/google-people"
  "connectors/google-chat"
  "connectors/google-meet"
  "connectors/google-admin-reports"
  "connectors/google-workspace-events"
)

BATCH3_CONNECTORS=(
  "connectors/huggingface"
  "connectors/deepseek"
  "connectors/llm-router"
  "connectors/google-ai"
)

BATCH_STATUS_CONNECTORS=()
BATCH_STATUS_VERDICTS=()
BATCH_STATUS_FAILED_CHECKS=()
BATCH_STATUS_DETAILS=()
BATCH_STATUS_PASSED_COUNTS=()
LAST_FAILED_CHECK=""
LAST_FAILURE_DETAIL=""
LAST_PASSED_COUNT=0

usage() {
  cat <<'EOF'
Usage:
  scripts/graduation/run_gauntlet.sh [--jsonl <path>] <connector-path>
  scripts/graduation/run_gauntlet.sh [--jsonl <path>] --batch batch1|batch2|batch3|batch4 --status-md <path>
  scripts/graduation/run_gauntlet.sh --list-checks
EOF
}

require_option_value() {
  local option="$1"
  local value="${2:-}"

  if [[ -z "${value}" || "${value}" == --* ]]; then
    echo "${option} requires a value" >&2
    usage >&2
    exit 1
  fi
}

json_escape() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//$'\n'/ }"
  value="${value//$'\r'/ }"
  printf '%s' "${value}"
}

md_escape() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//|/\\|}"
  value="${value//$'\n'/ }"
  value="${value//$'\r'/ }"
  printf '%s' "${value}"
}

emit_jsonl() {
  local connector="$1"
  local check="$2"
  local verdict="$3"
  local duration_ms="$4"
  local stderr_excerpt="$5"
  local line

  line="{\"connector\":\"$(json_escape "${connector}")\",\"check\":\"$(json_escape "${check}")\",\"verdict\":\"$(json_escape "${verdict}")\",\"duration_ms\":${duration_ms},\"stderr_excerpt\":\"$(json_escape "${stderr_excerpt}")\"}"
  printf '%s\n' "${line}"
  if [[ -n "${JSONL_PATH}" ]]; then
    printf '%s\n' "${line}" >>"${JSONL_PATH}"
  fi
}

normalize_path() {
  local path="$1"
  case "${path}" in
    /*)
      printf '%s\n' "${path}"
      ;;
    *)
      printf '%s/%s\n' "$(pwd)" "${path}"
      ;;
  esac
}

batch_display_name() {
  local batch="$1"

  case "${batch}" in
    batch1)
      printf '%s\n' "Batch 1"
      ;;
    batch2)
      printf '%s\n' "Batch 2"
      ;;
    batch3)
      printf '%s\n' "Batch 3"
      ;;
    batch4)
      printf '%s\n' "Batch 4"
      ;;
    *)
      printf '%s\n' "${batch}"
      ;;
  esac
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --list-checks)
      LIST_CHECKS=1
      shift
      ;;
    --jsonl)
      require_option_value "$1" "${2:-}"
      JSONL_PATH="$2"
      shift 2
      ;;
    --batch)
      require_option_value "$1" "${2:-}"
      BATCH_ARG="$2"
      shift 2
      ;;
    --status-md)
      require_option_value "$1" "${2:-}"
      STATUS_MD_PATH="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    -*)
      echo "unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
    *)
      if [[ -n "${CONNECTOR_ARG}" ]]; then
        echo "only one connector path may be provided" >&2
        exit 1
      fi
      CONNECTOR_ARG="$1"
      shift
      ;;
  esac
done

run_connector_checks() {
  local connector_arg="$1"
  local connector_path="$2"
  local fail_fast="$3"
  local check_record
  local check_id
  local exit_code
  local check_fn
  local start_seconds
  local end_seconds
  local output

  LAST_FAILED_CHECK=""
  LAST_FAILURE_DETAIL=""
  LAST_PASSED_COUNT=0

  for check_record in "${GRADUATION_CHECKS[@]}"; do
    IFS='|' read -r check_id exit_code _description <<<"${check_record}"
    check_fn="graduation_check_${check_id}"
    start_seconds="$(date -u +%s)"

    if output="$("${check_fn}" "${connector_path}" 2>&1)"; then
      end_seconds="$(date -u +%s)"
      emit_jsonl "${connector_arg}" "${check_id}" "pass" "$(((end_seconds - start_seconds) * 1000))" ""
      LAST_PASSED_COUNT=$((LAST_PASSED_COUNT + 1))
      continue
    fi

    end_seconds="$(date -u +%s)"
    emit_jsonl "${connector_arg}" "${check_id}" "fail" "$(((end_seconds - start_seconds) * 1000))" "${output}"
    LAST_FAILED_CHECK="${check_id}"
    LAST_FAILURE_DETAIL="${output}"
    if [[ "${fail_fast}" -eq 1 ]]; then
      echo "check=${check_id} verdict=fail code=${exit_code} connector=${connector_arg} detail=${output}" >&2
    fi
    return "${exit_code}"
  done

  return 0
}

write_batch_status_markdown() {
  local path="$1"
  local batch="$2"
  local batch_label
  local total="${#BATCH_STATUS_CONNECTORS[@]}"
  local passing=0
  local index
  local connector
  local verdict
  local failed_check
  local detail
  local passed_count
  local proven_status_blocked=1
  local unpromoted=0
  batch_label="$(batch_display_name "${batch}")"

  for verdict in "${BATCH_STATUS_VERDICTS[@]}"; do
    if [[ "${verdict}" == "pass" ]]; then
      passing=$((passing + 1))
    fi
  done
  unpromoted=$((total - passing))

  for index in "${!BATCH_STATUS_CONNECTORS[@]}"; do
    if [[ "${BATCH_STATUS_VERDICTS[$index]}" != "pass" \
      && "${BATCH_STATUS_FAILED_CHECKS[$index]}" != "readme_status_match" ]]
    then
      proven_status_blocked=0
    fi
  done

  {
    printf '# %s Graduation Status\n\n' "${batch_label}"
    printf "Generated by \`scripts/graduation/run_gauntlet.sh --batch %s --status-md %s\`.\n\n" "${batch}" "${path}"
    printf 'This is a status artifact, not a graduation claim. A connector is PROVEN only after it passes every 12-point gauntlet check and its README and manifest truthfully advertise that status.\n\n'
    printf "Summary: \`%s/%s\` %s connectors currently pass the graduation gauntlet.\n\n" "${passing}" "${total}" "${batch_label}"
    if [[ "${passing}" -lt "${total}" && "${proven_status_blocked}" -eq 1 ]]; then
      if [[ "${passing}" -eq 0 ]]; then
        printf "Pre-promotion status: \`%s/%s\` %s connectors pass every check before \`readme_status_match\`; none should be called PROVEN until the full proof bundle lands.\n\n" "${total}" "${total}" "${batch_label}"
      else
        printf "Promotion status: \`%s/%s\` %s connectors are PROVEN; \`%s/%s\` still pass every check before \`readme_status_match\` and need tracked verifier proof before promotion.\n\n" "${passing}" "${total}" "${batch_label}" "${unpromoted}" "${total}"
      fi
    fi
    printf '| Connector | Status | First failing check | Checks passed before failure | Detail |\n'
    printf '|-----------|--------|---------------------|------------------------------|--------|\n'
    for index in "${!BATCH_STATUS_CONNECTORS[@]}"; do
      connector="${BATCH_STATUS_CONNECTORS[$index]}"
      verdict="${BATCH_STATUS_VERDICTS[$index]}"
      failed_check="${BATCH_STATUS_FAILED_CHECKS[$index]}"
      detail="${BATCH_STATUS_DETAILS[$index]}"
      passed_count="${BATCH_STATUS_PASSED_COUNTS[$index]}"
      if [[ "${verdict}" == "pass" ]]; then
        failed_check="-"
        detail="All checks passed"
      fi
      printf "| \`%s\` | \`%s\` | \`%s\` | \`%s\` | %s |\n" \
        "$(md_escape "${connector}")" \
        "$(md_escape "${verdict}")" \
        "$(md_escape "${failed_check}")" \
        "$(md_escape "${passed_count}")" \
        "$(md_escape "${detail}")"
    done
    printf '\n## Current Next Actions\n\n'
    if [[ "${passing}" -eq "${total}" ]]; then
      printf '%s\n' "- Keep this artifact scoped to mechanical gauntlet status until the PROVEN promotion proof bundle lands."
      printf '%s\n' "- Run each ${batch_label} connector's tracked verifier and cite redaction-safe JSONL artifact paths/hashes, not just the presence-only gauntlet checks."
      printf '%s\n' "- Promote README and manifest statuses to PROVEN only in the same change that cites the full verifier, conformance, and proof-lane results."
      printf '%s\n' "- After PROVEN markers are present, run \`rch exec -- cargo test -p fcp-conformance --test graduation_gauntlet_conformance all_proven_connectors_pass_gauntlet -- --nocapture\`."
    elif [[ "${proven_status_blocked}" -eq 1 ]]; then
      if [[ "${passing}" -eq 0 ]]; then
        printf '%s\n' "- ${batch_label} has completed the pre-promotion metadata/local-non-mock checks, but every connector is still blocked at \`readme_status_match\`."
        printf '%s\n' "- Run each ${batch_label} connector's tracked verifier and cite redaction-safe JSONL artifact paths/hashes before any PROVEN promotion."
        printf '%s\n' "- Promote README and manifest statuses to PROVEN only in the same change that cites the full verifier, conformance, and proof-lane results."
        printf '%s\n' "- After PROVEN markers are present, run \`rch exec -- cargo test -p fcp-conformance --test graduation_gauntlet_conformance all_proven_connectors_pass_gauntlet -- --nocapture\`."
      else
        printf '%s\n' "- ${batch_label} has ${passing}/${total} connectors already PROVEN; promote the remaining ${unpromoted} only with tracked verifier, conformance, and proof-lane evidence."
        printf '%s\n' "- Remaining blocked connectors are waiting at \`readme_status_match\`; rerun each tracked verifier and cite redaction-safe JSONL artifact paths/hashes before promotion."
        printf '%s\n' "- Promote README and manifest statuses to PROVEN only in the same change that cites the full verifier, conformance, and proof-lane results."
        printf '%s\n' "- After additional PROVEN markers are present, run \`rch exec -- cargo test -p fcp-conformance --test graduation_gauntlet_conformance all_proven_connectors_pass_gauntlet -- --nocapture\`."
      fi
    else
      printf '%s\n' "- Add or restore connector-local \`operations_info\` metadata where the gauntlet stops at \`operations_info\`."
      printf '%s\n' "- Add redaction-safe \`scripts/e2e/...\` verification-script declarations where the gauntlet stops at \`verification_script_declared\`."
      printf '%s\n' "- Add connector-local \`tests/local_non_mock.rs\` acceptance coverage where the gauntlet stops at \`local_non_mock\`."
      printf '%s\n' "- Fix manifest network constraints where the gauntlet stops at \`network_policy\`."
      printf '%s\n' "- Do not mark any ${batch_label} connector PROVEN until its manifest, README, local non-mock proof, sandbox/network policy, and operator guidance all pass the gauntlet."
    fi
  } >"${path}"
}

run_batch_status() {
  local batch="$1"
  local connector
  local connector_path
  local result
  local batch_connectors=()

  case "${batch}" in
    batch1)
      batch_connectors=("${BATCH1_CONNECTORS[@]}")
      ;;
    batch2)
      batch_connectors=("${BATCH2_CONNECTORS[@]}")
      ;;
    batch3)
      batch_connectors=("${BATCH3_CONNECTORS[@]}")
      ;;
    batch4)
      if [[ ! -x "${BATCH4_INVENTORY}" ]]; then
        echo "batch4 inventory script missing or not executable: ${BATCH4_INVENTORY}" >&2
        exit 1
      fi
      while IFS= read -r connector; do
        [[ -n "${connector}" ]] || continue
        batch_connectors+=("${connector}")
      done < <("${BATCH4_INVENTORY}")
      ;;
    *)
      echo "unknown batch: ${batch}" >&2
      exit 1
      ;;
  esac

  if [[ -n "${JSONL_PATH}" ]]; then
    : > "${JSONL_PATH}"
  fi

  for connector in "${batch_connectors[@]}"; do
    connector_path="$(normalize_path "${connector}")"
    run_connector_checks "${connector}" "${connector_path}" 0
    result="$?"
    BATCH_STATUS_CONNECTORS+=("${connector}")
    BATCH_STATUS_PASSED_COUNTS+=("${LAST_PASSED_COUNT}")
    if [[ "${result}" -eq 0 ]]; then
      BATCH_STATUS_VERDICTS+=("pass")
      BATCH_STATUS_FAILED_CHECKS+=("-")
      BATCH_STATUS_DETAILS+=("All checks passed")
    else
      BATCH_STATUS_VERDICTS+=("blocked")
      BATCH_STATUS_FAILED_CHECKS+=("${LAST_FAILED_CHECK}")
      BATCH_STATUS_DETAILS+=("${LAST_FAILURE_DETAIL}")
    fi
  done

  if [[ -n "${STATUS_MD_PATH}" ]]; then
    write_batch_status_markdown "${STATUS_MD_PATH}" "${batch}"
  fi
}

if [[ "${LIST_CHECKS}" -eq 1 ]]; then
  graduation_list_checks
  exit 0
fi

if [[ -n "${BATCH_ARG}" ]]; then
  if [[ -n "${CONNECTOR_ARG}" ]]; then
    echo "--batch cannot be combined with a connector path" >&2
    exit 1
  fi
  run_batch_status "${BATCH_ARG}"
  exit 0
fi

if [[ -n "${STATUS_MD_PATH}" ]]; then
  echo "--status-md requires --batch" >&2
  exit 1
fi

if [[ -z "${CONNECTOR_ARG}" ]]; then
  echo "missing connector path" >&2
  usage >&2
  exit 1
fi

CONNECTOR_PATH="$(normalize_path "${CONNECTOR_ARG}")"

run_connector_checks "${CONNECTOR_ARG}" "${CONNECTOR_PATH}" 1
exit "$?"
