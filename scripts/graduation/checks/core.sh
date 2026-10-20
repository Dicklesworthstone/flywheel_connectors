#!/usr/bin/env bash

GRADUATION_CHECKS=(
  "connector_path|1|connector argument resolves to a directory"
  "operations_info|2|connector source exposes operations_info metadata"
  "manifest_present|3|connector manifest.toml exists"
  "readme_present|4|connector README.md exists"
  "verification_script_declared|5|README declares a scripts/e2e verification script"
  "manifest_operations|6|manifest declares at least one operation"
  "local_non_mock|7|connector has tests/local_non_mock.rs"
  "readme_status_match|8|literal PROVEN README status matches manifest status"
  "operation_inventory|9|README operation inventory contains a manifest operation"
  "network_policy|10|manifest network policy denies localhost and private ranges"
  "sandbox_profile|11|manifest declares a sandbox profile"
  "operator_guidance|12|README includes operator guidance and rerun commands"
)

graduation_list_checks() {
  printf '%s\n' "${GRADUATION_CHECKS[@]}"
}

graduation_check_connector_path() {
  local connector="$1"

  if [[ ! -d "${connector}" ]]; then
    echo "connector path does not exist or is not a directory"
    return 1
  fi

  return 0
}

graduation_check_operations_info() {
  local connector="$1"
  local src_dir="${connector}/src"

  if [[ ! -d "${connector}" ]]; then
    return 0
  fi

  if [[ ! -d "${src_dir}" ]]; then
    echo "src directory missing; cannot find operations_info"
    return 1
  fi

  if grep -R "operations_info" "${src_dir}" >/dev/null 2>&1; then
    return 0
  fi

  if grep -R "OperationInfo" "${src_dir}" >/dev/null 2>&1 \
    && grep -R "Introspection" "${src_dir}" >/dev/null 2>&1 \
    && grep -RE "op_info\\(|policy_backed_operation_info|operation_catalog" "${src_dir}" >/dev/null 2>&1
  then
    return 0
  fi

  echo "missing operations_info source metadata or equivalent OperationInfo catalog"
  return 1
}

graduation_check_manifest_present() {
  local connector="$1"

  if [[ -f "${connector}/manifest.toml" ]]; then
    return 0
  fi

  echo "missing manifest.toml"
  return 1
}

graduation_check_readme_present() {
  local connector="$1"

  if [[ -f "${connector}/README.md" ]]; then
    return 0
  fi

  echo "missing README.md"
  return 1
}

graduation_check_verification_script_declared() {
  local connector="$1"
  local readme="${connector}/README.md"

  if [[ ! -f "${readme}" ]]; then
    return 0
  fi

  if grep -Eq 'Verification script|scripts/e2e/[^`[:space:]]+\.sh' "${readme}"; then
    if grep -Eq 'scripts/e2e/[^`[:space:]]+\.sh' "${readme}"; then
      return 0
    fi
  fi

  echo "README does not declare a scripts/e2e verification script"
  return 1
}

graduation_check_manifest_operations() {
  local connector="$1"
  local manifest="${connector}/manifest.toml"

  if [[ ! -f "${manifest}" ]]; then
    return 0
  fi

  if grep -Eq '^\[provides\.operations\.' "${manifest}"; then
    return 0
  fi

  echo "manifest declares no provides.operations entries"
  return 1
}

graduation_check_local_non_mock() {
  local connector="$1"

  if [[ -f "${connector}/tests/local_non_mock.rs" ]]; then
    return 0
  fi

  echo "missing tests/local_non_mock.rs"
  return 1
}

graduation_check_readme_status_match() {
  local connector="$1"
  local readme="${connector}/README.md"
  local manifest="${connector}/manifest.toml"
  local readme_proven=0
  local manifest_proven=0

  if [[ ! -f "${readme}" || ! -f "${manifest}" ]]; then
    return 0
  fi

  if grep -Eq '^> \*\*Status\*\*:.*\bPROVEN\b' "${readme}"; then
    readme_proven=1
  fi
  if grep -Eq '^[[:space:]]*status[[:space:]]*=[[:space:]]*"proven"' "${manifest}"; then
    manifest_proven=1
  fi

  if [[ "${readme_proven}" -eq "${manifest_proven}" ]]; then
    if [[ "${readme_proven}" -eq 1 ]]; then
      return 0
    fi
    echo "README and manifest must both declare PROVEN/proven for graduation"
    return 1
  fi

  if [[ "${readme_proven}" -eq 1 ]]; then
    echo "README status is PROVEN but manifest status is not proven"
  else
    echo "manifest status is proven but README status is not PROVEN"
  fi
  return 1
}

graduation_manifest_operation_ids() {
  local manifest="$1"

  sed -n \
    -e 's/^\[provides\.operations\."\([^"]*\)"\].*/\1/p' \
    -e 's/^\[provides\.operations\.\([^].]*\)\].*/\1/p' \
    "${manifest}" | sort -u
}

graduation_check_operation_inventory() {
  local connector="$1"
  local readme="${connector}/README.md"
  local manifest="${connector}/manifest.toml"
  local operation_id

  if [[ ! -f "${readme}" || ! -f "${manifest}" ]]; then
    return 0
  fi

  if ! grep -Eq '^## (Operation Inventory|Operations)$' "${readme}"; then
    echo "README missing Operation Inventory section"
    return 1
  fi

  while IFS= read -r operation_id; do
    if [[ -n "${operation_id}" ]] && grep -Fq -- "${operation_id}" "${readme}"; then
      return 0
    fi
  done < <(graduation_manifest_operation_ids "${manifest}")

  echo "README operation inventory does not mention any manifest operation ID"
  return 1
}

graduation_check_network_policy() {
  local connector="$1"
  local manifest="${connector}/manifest.toml"

  if [[ ! -f "${manifest}" ]]; then
    return 0
  fi

  if (grep -Eq '\.network_constraints\]' "${manifest}" \
      || grep -Eq '^[[:space:]]*network_constraints[[:space:]]*=[[:space:]]*\{' "${manifest}") \
    && (
      (grep -Eq '(^|[[:space:],{])deny_localhost[[:space:]]*=[[:space:]]*true' "${manifest}" \
        && grep -Eq '(^|[[:space:],{])deny_private_ranges[[:space:]]*=[[:space:]]*true' "${manifest}") \
      || (grep -Eq 'host_allow[[:space:]]*=[[:space:]]*\["localhost\.localdomain"\]' "${manifest}" \
        && grep -Eq '^[[:space:]]*deny_tailnet_ranges[[:space:]]*=[[:space:]]*true' "${manifest}" \
        && grep -Eq '^[[:space:]]*deny_ip_literals[[:space:]]*=[[:space:]]*true' "${manifest}")
    )
  then
    return 0
  fi

  echo "manifest operation network policy must deny localhost and private ranges"
  return 1
}

graduation_check_sandbox_profile() {
  local connector="$1"
  local manifest="${connector}/manifest.toml"

  if [[ ! -f "${manifest}" ]]; then
    return 0
  fi

  if grep -Eq '^\[sandbox\]' "${manifest}"; then
    return 0
  fi

  echo "manifest missing [sandbox] profile"
  return 1
}

graduation_check_operator_guidance() {
  local connector="$1"
  local readme="${connector}/README.md"

  if [[ ! -f "${readme}" ]]; then
    return 0
  fi

  if grep -Eq '^## Operator Guidance$' "${readme}" \
    && grep -Eq 'Rerun commands' "${readme}"
  then
    return 0
  fi

  echo "README missing operator guidance or rerun commands"
  return 1
}
