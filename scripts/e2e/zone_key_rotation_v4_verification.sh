#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT_DIR="${OUT_DIR:-${REPO_ROOT}/artifacts/e2e/zone_key_rotation_v4/${RUN_ID}}"
mkdir -p "${OUT_DIR}"

JSONL_PATH="${OUT_DIR}/zone_key_rotation_cutover_e2e.jsonl"
SUMMARY_PATH="${OUT_DIR}/summary.json"
: > "${JSONL_PATH}"

cd "${REPO_ROOT}"

ZONE_KEY_ROTATION_E2E_JSONL="${JSONL_PATH}" \
  cargo test -p fcp-mesh --test zone_key_rotation_cutover_e2e -- --nocapture

RECORD_COUNT="$(wc -l < "${JSONL_PATH}" | tr -d ' ')"
if [[ "${RECORD_COUNT}" -ne 7 ]]; then
  echo "expected 7 JSONL records in ${JSONL_PATH}, got ${RECORD_COUNT}" >&2
  exit 1
fi

jq -e -s '
  length == 7
  and (map(.fixture_id) == [
    "v3_only",
    "v4_only",
    "mixed_v3_v4",
    "require_pq_kem",
    "membership_change_rekey",
    "revocation_rekey",
    "downgrade_tamper"
  ])
  and all(.[];
    has("command_line")
    and has("git_revision")
    and has("fixture_id")
    and has("node_id_hashes")
    and has("protocol_versions")
    and has("policy_flags")
    and has("wrapped_key_variant_counts")
    and has("rotation_phase")
    and has("recipient_capability_class")
    and has("signature_verification_result")
    and has("downgrade_decision")
    and has("fcp_error_mapping")
    and has("cleanup_result")
    and has("skip_reason")
  )
' "${JSONL_PATH}" > /dev/null

jq -n \
  --arg run_id "${RUN_ID}" \
  --arg jsonl_path "${JSONL_PATH}" \
  --argjson record_count "${RECORD_COUNT}" \
  '{
    status: "passed",
    run_id: $run_id,
    record_count: $record_count,
    jsonl_path: $jsonl_path
  }' > "${SUMMARY_PATH}"

cat "${SUMMARY_PATH}"
