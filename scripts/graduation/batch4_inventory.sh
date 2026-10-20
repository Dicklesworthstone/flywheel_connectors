#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

BATCH1_TO_3_CONNECTORS=(
  "postgresql"
  "stripe"
  "github"
  "gmail"
  "telegram"
  "slack"
  "kubernetes"
  "google-calendar"
  "google-drive"
  "google-docs"
  "google-sheets"
  "google-people"
  "google-chat"
  "google-meet"
  "google-admin-reports"
  "google-workspace-events"
  "huggingface"
  "deepseek"
  "llm-router"
  "google-ai"
)

usage() {
  cat <<'EOF'
Usage:
  scripts/graduation/batch4_inventory.sh [--markdown|--count]

Default output is one connector path per line for run_gauntlet batch mode.
The inventory is scanner-derived from connectors/* README status lines after
excluding Batch 1-3 connectors. It includes explicit long-tail maturity states:
missing status, incubating, planning contract, retrofit contract, first-slice,
and accepted first-slice.
EOF
}

is_prior_batch_connector() {
  local name="$1"
  local connector

  for connector in "${BATCH1_TO_3_CONNECTORS[@]}"; do
    if [[ "${name}" == "${connector}" ]]; then
      return 0
    fi
  done

  return 1
}

status_line_for() {
  local connector_dir="$1"
  local readme="${connector_dir}/README.md"
  local status=""

  if [[ -f "${readme}" ]]; then
    status="$(sed -n 's/^> \*\*Status\*\*: //p' "${readme}" | head -n 1)"
  fi

  if [[ -z "${status}" ]]; then
    status="NO_STATUS"
  fi

  printf '%s\n' "${status}"
}

is_batch4_status() {
  local status="$1"
  local lower_status

  if [[ "${status}" == "NO_STATUS" ]]; then
    return 0
  fi

  lower_status="$(printf '%s' "${status}" | tr '[:upper:]' '[:lower:]')"

  case "${lower_status}" in
    *incubat*|*planning\ contract*|*retrofit\ contract*|*first-slice*)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

category_for() {
  local name="$1"

  case "${name}" in
    amplitude|posthog)
      printf '%s\n' "analytics"
      ;;
    anthropic-vertex|azure-speech|inworld|microsoft-foundry)
      printf '%s\n' "ai-ml"
      ;;
    circleci|package-registry)
      printf '%s\n' "developer-platform"
      ;;
    coda|confluence|microsoft365|roam)
      printf '%s\n' "productivity"
      ;;
    paypal)
      printf '%s\n' "fintech"
      ;;
    plivo|telnyx)
      printf '%s\n' "communications"
      ;;
    irc|line|qq|synology-chat|tlon|twitch|wecom)
      printf '%s\n' "messaging-social"
      ;;
    *)
      printf '%s\n' "other"
      ;;
  esac
}

emit_inventory() {
  local format="$1"
  local connector_dir
  local name
  local status
  local category
  local rows=()

  for connector_dir in "${REPO_ROOT}"/connectors/*; do
    [[ -d "${connector_dir}" ]] || continue
    name="$(basename "${connector_dir}")"
    if is_prior_batch_connector "${name}"; then
      continue
    fi
    status="$(status_line_for "${connector_dir}")"
    if ! is_batch4_status "${status}"; then
      continue
    fi
    category="$(category_for "${name}")"
    rows+=("${category}|connectors/${name}|${status}")
  done

  if [[ "${format}" == "count" ]]; then
    printf '%s\n' "${#rows[@]}"
    return 0
  fi

  if [[ "${format}" == "markdown" ]]; then
    printf '| Category | Connector | README status |\n'
    printf '|----------|-----------|---------------|\n'
    if [[ "${#rows[@]}" -gt 0 ]]; then
      printf '%s\n' "${rows[@]}" | sort | while IFS='|' read -r category connector status; do
        printf "| \`%s\` | \`%s\` | %s |\n" "${category}" "${connector}" "${status}"
      done
    fi
    return 0
  fi

  if [[ "${#rows[@]}" -gt 0 ]]; then
    printf '%s\n' "${rows[@]}" | sort | cut -d'|' -f2
  fi
}

FORMAT="plain"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --markdown)
      FORMAT="markdown"
      shift
      ;;
    --count)
      FORMAT="count"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

emit_inventory "${FORMAT}"
