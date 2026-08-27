//! Joined `FeatureUniverse` inventory ratchet.
//!
//! This does not certify full semantic parity across every surface. It makes the
//! current universe mechanically enumerable and gives each row an explicit
//! verifier owner so future parity work has a stable map to tighten.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

const MIN_README_FEATURE_ROWS: usize = 24;
const MIN_FORMAL_COVERAGE_ROWS: usize = 24;
const MIN_FWC_SCHEMA_FILES: usize = 20;
const MIN_FWC_TOP_LEVEL_COMMANDS: usize = 68;
const MIN_FWC_TOP_LEVEL_COMMAND_NAMES: usize = 68;
const MIN_FWC_TOP_LEVEL_COMMAND_ALIASES: usize = 23;
const MIN_FWC_NESTED_SUBCOMMAND_VARIANTS: usize = 132;
const MIN_FWC_NESTED_SUBCOMMAND_NAMES: usize = 132;
const MIN_FWC_NESTED_SUBCOMMAND_ALIASES: usize = 4;
const MIN_FWC_SCHEMA_CASES: usize = 12;
const MIN_FWC_SCHEMA_CASE_PARSE_CONTRACTS: usize = 12;
const MIN_FWC_SCHEMA_CASE_RUNTIME_CONTRACTS: usize = 2;
const MIN_FWC_JSON_OUTPUT_CONTRACTS: usize = 469;
const MIN_FWC_JSON_SCHEMA_VERSION_CONTRACTS: usize = 143;
const MIN_FWC_JSON_SCHEMA_CASE_CONTRACTS: usize = 112;
const MIN_FWC_JSON_OUTPUT_FIELD_ASSERTION_CONTRACTS: usize = 467;
const MIN_FWC_JSON_OUTPUT_NO_SCHEMA_DECISION_CONTRACTS: usize = 11;
const MIN_FWC_JSON_OUTPUT_OWNERSHIP_CLASSIFICATIONS: usize = 469;
const MAX_FWC_JSON_OUTPUT_PARSE_ONLY_CONTRACTS: usize = 0;
const MIN_GRADUATION_GAUNTLET_CHECKS: usize = 12;
const MIN_COVERAGE_SCANNER_CONNECTORS: usize = 177;
const MIN_CONNECTOR_MANIFESTS: usize = 177;
const MIN_CONNECTOR_MANIFEST_OPERATIONS: usize = 1675;
const MIN_CONNECTOR_README_OPERATIONS: usize = 1591;
const MIN_CONNECTOR_MANIFEST_README_MATCHED_OPERATIONS: usize = 1448;
const MAX_CONNECTOR_MANIFEST_OPERATIONS_MISSING_FROM_README: usize = 227;
const MAX_CONNECTOR_README_OPERATIONS_MISSING_FROM_MANIFEST: usize = 143;
const MAX_CONNECTOR_README_OPERATION_TABLE_GAPS: usize = 9;
const MAX_COVERAGE_SCANNER_GAPS: usize = 6;
const MAX_FWC_SCHEMA_CASES_MISSING_DIRECT_PARSE_CONTRACT: usize = 2;

const FWC_COMMAND_SCHEMAS_PATH: &str = "crates/fcp-conformance/tests/fwc_command_schemas.rs";

const ALLOWED_CONNECTOR_README_OPERATION_TABLE_GAPS: &[&str] = &[
    "anthropic-vertex",
    "azure-speech",
    "matrix",
    "microsoft-foundry",
    "openai",
    "plivo",
    "roam",
    "telnyx",
    "zoom",
];

const ALLOWED_COVERAGE_SCANNER_GAPS: &[&str] = &[
    "browser",
    "cron",
    "nostr",
    "vectordb",
    "webhook-receiver",
    "zalouser",
];

const ALLOWED_FWC_SCHEMA_CASE_DIRECT_PARSE_GAPS: &[&str] = &[
    "audit chain status -> audit_chain_status.schema.json",
    "audit verify -> audit_verify.schema.json",
];

#[derive(Clone, Debug)]
struct FeatureUniverseRow {
    surface: &'static str,
    item_id: String,
    owner_file: String,
    verifier_kind: String,
    verifier_path: String,
    verifier_name: String,
    proof_status: String,
}

impl FeatureUniverseRow {
    fn key(&self) -> (String, String, String) {
        (
            self.surface.to_owned(),
            self.item_id.clone(),
            self.owner_file.clone(),
        )
    }
}

fn row(
    surface: &'static str,
    item_id: impl Into<String>,
    owner_file: impl Into<String>,
    verifier_kind: impl Into<String>,
    verifier_path: impl Into<String>,
    verifier_name: impl Into<String>,
    proof_status: impl Into<String>,
) -> FeatureUniverseRow {
    FeatureUniverseRow {
        surface,
        item_id: item_id.into(),
        owner_file: owner_file.into(),
        verifier_kind: verifier_kind.into(),
        verifier_path: verifier_path.into(),
        verifier_name: verifier_name.into(),
        proof_status: proof_status.into(),
    }
}

fn workspace_root() -> Result<PathBuf, String> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| "cannot derive workspace root from CARGO_MANIFEST_DIR".to_owned())
}

fn display_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root).map_or_else(
        |_| path.display().to_string(),
        |relative| relative.display().to_string(),
    )
}

fn read_to_string(root: &Path, relative: &str) -> Result<String, String> {
    fs::read_to_string(root.join(relative))
        .map_err(|err| format!("expected {relative} to be readable: {err}"))
}

fn markdown_cells(line: &str) -> Vec<String> {
    line.trim()
        .trim_matches('|')
        .split('|')
        .map(str::trim)
        .map(ToOwned::to_owned)
        .collect()
}

fn is_separator_row(cells: &[String]) -> bool {
    cells.iter().all(|cell| {
        !cell.is_empty()
            && cell
                .chars()
                .all(|character| matches!(character, '-' | ':' | ' '))
    })
}

fn readme_feature_rows(root: &Path) -> Result<Vec<FeatureUniverseRow>, String> {
    let readme = read_to_string(root, "README.md")?;
    let mut rows = Vec::new();
    let mut in_feature_status_table = false;

    for line in readme.lines() {
        let cells = markdown_cells(line);
        if cells == ["Feature", "Status", "What It Does", "Evidence"] {
            in_feature_status_table = true;
            continue;
        }
        if !in_feature_status_table {
            continue;
        }
        if !line.trim_start().starts_with('|') {
            break;
        }
        if is_separator_row(&cells) {
            continue;
        }
        if cells.len() != 4 {
            return Err(format!(
                "README feature-status row must have 4 columns: {line}"
            ));
        }
        let Some(feature) = cells[0]
            .strip_prefix("**")
            .and_then(|feature| feature.strip_suffix("**"))
        else {
            continue;
        };
        rows.push(row(
            "readme_feature_status",
            feature,
            "README.md",
            "rust_conformance",
            "crates/fcp-conformance/tests/coverage_matrix_completeness.rs",
            "test_every_readme_status_row_covered",
            "ratcheted",
        ));
    }

    if rows.is_empty() {
        return Err("README.md must contain a non-empty feature-status table".to_owned());
    }
    Ok(rows)
}

fn formal_coverage_rows(root: &Path) -> Result<Vec<FeatureUniverseRow>, String> {
    let matrix_path = "docs/formal/coverage-matrix.md";
    let matrix = read_to_string(root, matrix_path)?;
    let mut rows = Vec::new();
    let mut in_matrix = false;

    for line in matrix.lines() {
        if !line.trim_start().starts_with('|') {
            continue;
        }
        let cells = markdown_cells(line);
        if cells.first().is_some_and(|cell| cell == "readme_section") {
            in_matrix = true;
            continue;
        }
        if !in_matrix || is_separator_row(&cells) {
            continue;
        }
        if cells.len() != 6 {
            return Err(format!("coverage matrix row must have 6 columns: {line}"));
        }
        rows.push(row(
            "formal_coverage_matrix",
            cells[0].clone(),
            matrix_path,
            "rust_conformance",
            "crates/fcp-conformance/tests/coverage_matrix_completeness.rs",
            "test_each_row_has_one_of_lean_tla_csp_or_explicit_no_model",
            "ratcheted",
        ));
    }

    if rows.is_empty() {
        return Err(format!(
            "{matrix_path} must contain a non-empty readme_section table"
        ));
    }
    Ok(rows)
}

fn collect_rust_sources(dir: &Path, sources: &mut Vec<PathBuf>) -> Result<(), String> {
    for entry in fs::read_dir(dir).map_err(|err| format!("cannot read {}: {err}", dir.display()))? {
        let entry = entry.map_err(|err| format!("cannot read directory entry: {err}"))?;
        let path = entry.path();
        if path.is_dir() {
            collect_rust_sources(&path, sources)?;
        } else if path.extension().and_then(|extension| extension.to_str()) == Some("rs") {
            sources.push(path);
        }
    }
    Ok(())
}

fn schema_reference_sources(root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut sources = Vec::new();
    for relative in [
        "crates/fcp-conformance/tests",
        "crates/fwc/tests",
        "crates/fwc/src",
    ] {
        collect_rust_sources(&root.join(relative), &mut sources)?;
    }
    Ok(sources)
}

fn referenced_schema_files(
    root: &Path,
    schema_files: &BTreeSet<String>,
) -> Result<BTreeSet<String>, String> {
    let mut referenced = BTreeSet::new();
    for source_path in schema_reference_sources(root)? {
        let source = fs::read_to_string(&source_path).map_err(|err| {
            format!(
                "expected Rust source {} to be readable: {err}",
                source_path.display()
            )
        })?;
        for schema_file in schema_files {
            if source.contains(schema_file) {
                referenced.insert(schema_file.clone());
            }
        }
    }
    Ok(referenced)
}

fn fwc_schema_rows(root: &Path) -> Result<Vec<FeatureUniverseRow>, String> {
    let schema_dir = root.join("crates/fwc/schemas");
    let mut schema_files = BTreeSet::new();
    for entry in fs::read_dir(&schema_dir)
        .map_err(|err| format!("cannot read {}: {err}", schema_dir.display()))?
    {
        let entry = entry.map_err(|err| format!("cannot read fwc schema entry: {err}"))?;
        let file_name = entry
            .file_name()
            .to_str()
            .ok_or_else(|| "fwc schema filename must be UTF-8".to_owned())?
            .to_owned();
        if file_name.ends_with(".schema.json") {
            schema_files.insert(file_name);
        }
    }
    let referenced = referenced_schema_files(root, &schema_files)?;
    Ok(schema_files
        .into_iter()
        .map(|schema_file| {
            let proof_status = if referenced.contains(&schema_file) {
                "ratcheted"
            } else {
                "missing_validator_reference"
            };
            row(
                "fwc_schema_file",
                schema_file.clone(),
                format!("crates/fwc/schemas/{schema_file}"),
                "rust_conformance",
                "crates/fcp-conformance/tests/fwc_command_schemas.rs",
                "every_fwc_schema_file_has_validator_reference",
                proof_status,
            )
        })
        .collect())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FwcSchemaCase {
    schema_file: String,
    command_path: Vec<String>,
    success_schema_version: String,
}

impl FwcSchemaCase {
    fn item_id(&self) -> String {
        format!("{} -> {}", self.command_path.join(" "), self.schema_file)
    }
}

enum RustOptionalStringLiteral {
    None,
    Some(String),
}

fn rust_field_string_literal(line: &str, field: &str) -> Option<String> {
    let (candidate, value) = line.trim().split_once(':')?;
    if candidate.trim() != field {
        return None;
    }
    string_literal_value(value.trim().trim_end_matches(',').trim())
}

fn rust_field_optional_string_literal(
    line: &str,
    field: &str,
) -> Option<RustOptionalStringLiteral> {
    let (candidate, value) = line.trim().split_once(':')?;
    if candidate.trim() != field {
        return None;
    }
    let value = value.trim().trim_end_matches(',').trim();
    if value == "None" {
        return Some(RustOptionalStringLiteral::None);
    }
    value
        .strip_prefix("Some(")
        .and_then(|value| value.strip_suffix(')'))
        .and_then(string_literal_value)
        .map(RustOptionalStringLiteral::Some)
}

fn fwc_command_schema_cases(source: &str) -> Result<Vec<FwcSchemaCase>, String> {
    let mut cases = Vec::new();
    let mut in_case = false;
    let mut schema_file = None;
    let mut command = None;
    let mut subcommand = None;
    let mut success_schema_version = None;
    let mut saw_subcommand = false;

    for line in source.lines() {
        let trimmed = line.trim();
        if !in_case {
            if trimmed == "CommandSchemaCase {" {
                in_case = true;
                schema_file = None;
                command = None;
                subcommand = None;
                success_schema_version = None;
                saw_subcommand = false;
            }
            continue;
        }

        if let Some(value) = rust_field_string_literal(trimmed, "file") {
            schema_file = Some(value);
            continue;
        }
        if let Some(value) = rust_field_string_literal(trimmed, "command") {
            command = Some(value);
            continue;
        }
        if let Some(value) = rust_field_optional_string_literal(trimmed, "subcommand") {
            subcommand = match value {
                RustOptionalStringLiteral::None => None,
                RustOptionalStringLiteral::Some(value) => Some(value),
            };
            saw_subcommand = true;
            continue;
        }
        if let Some(value) = rust_field_string_literal(trimmed, "success_schema_version") {
            success_schema_version = Some(value);
            continue;
        }
        if trimmed == "}," {
            let schema_file = schema_file
                .take()
                .ok_or_else(|| "CommandSchemaCase missing file".to_owned())?;
            let command = command
                .take()
                .ok_or_else(|| format!("{schema_file} CommandSchemaCase missing command"))?;
            let success_schema_version = success_schema_version.take().ok_or_else(|| {
                format!("{schema_file} CommandSchemaCase missing success_schema_version")
            })?;
            if !saw_subcommand {
                return Err(format!(
                    "{schema_file} CommandSchemaCase missing subcommand"
                ));
            }

            let mut command_path = vec![command];
            if let Some(subcommand) = subcommand.take() {
                command_path.extend(subcommand.split_whitespace().map(ToOwned::to_owned));
            }
            cases.push(FwcSchemaCase {
                schema_file,
                command_path,
                success_schema_version,
            });
            in_case = false;
        }
    }

    if cases.is_empty() {
        return Err("failed to inventory fwc CommandSchemaCase entries".to_owned());
    }
    Ok(cases)
}

fn fwc_schema_cases(root: &Path) -> Result<Vec<FwcSchemaCase>, String> {
    let source = read_to_string(root, FWC_COMMAND_SCHEMAS_PATH)?;
    fwc_command_schema_cases(&source)
}

fn fwc_schema_case_rows(root: &Path) -> Result<Vec<FeatureUniverseRow>, String> {
    Ok(fwc_schema_cases(root)?
        .into_iter()
        .map(|case| {
            row(
                "fwc_schema_case",
                case.item_id(),
                FWC_COMMAND_SCHEMAS_PATH,
                "json_schema_conformance",
                FWC_COMMAND_SCHEMAS_PATH,
                "fwc_command_truth_source_schemas_compile_and_validate_envelopes",
                "schema_payload_validated",
            )
        })
        .collect())
}

#[derive(Debug, Eq, PartialEq)]
struct FwcTopLevelCommand {
    variant: String,
    cli_name: String,
    aliases: BTreeSet<String>,
}

fn command_attribute_args(line: &str) -> Option<&str> {
    line.trim()
        .strip_prefix("#[command(")
        .and_then(|line| line.strip_suffix(")]"))
}

fn split_command_attribute_args(args: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut bracket_depth = 0_usize;
    let mut in_string = false;
    let mut escaped = false;

    for (index, character) in args.char_indices() {
        if in_string {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                in_string = false;
            }
            continue;
        }

        match character {
            '"' => in_string = true,
            '[' => bracket_depth += 1,
            ']' => bracket_depth = bracket_depth.saturating_sub(1),
            ',' if bracket_depth == 0 => {
                parts.push(args[start..index].trim());
                start = index + character.len_utf8();
            }
            _ => {}
        }
    }

    let tail = args[start..].trim();
    if !tail.is_empty() {
        parts.push(tail);
    }
    parts
}

fn string_literal_value(value: &str) -> Option<String> {
    let value = value.trim().strip_prefix('"')?;
    let (value, suffix) = value.split_once('"')?;
    if suffix.trim().is_empty() && !value.is_empty() {
        Some(value.to_owned())
    } else {
        None
    }
}

fn first_string_literal_value(value: &str) -> Option<String> {
    let value = value.trim_start().strip_prefix('"')?;
    let (value, _suffix) = value.split_once('"')?;
    if value.is_empty() {
        None
    } else {
        Some(value.to_owned())
    }
}

fn command_attribute_string_values(line: &str, key: &str) -> Vec<String> {
    let Some(args) = command_attribute_args(line) else {
        return Vec::new();
    };

    split_command_attribute_args(args)
        .into_iter()
        .flat_map(|arg| {
            let Some((candidate_key, value)) = arg.split_once('=') else {
                return Vec::new();
            };
            if candidate_key.trim() != key {
                return Vec::new();
            }

            let value = value.trim();
            if let Some(value) = string_literal_value(value) {
                return vec![value];
            }
            if let Some(array) = value
                .strip_prefix('[')
                .and_then(|value| value.strip_suffix(']'))
            {
                return split_command_attribute_args(array)
                    .into_iter()
                    .filter_map(string_literal_value)
                    .collect::<Vec<_>>();
            }
            Vec::new()
        })
        .collect()
}

fn variant_cli_name(variant: &str) -> String {
    let mut name = String::new();
    for (index, character) in variant.chars().enumerate() {
        if character.is_uppercase() {
            if index > 0 {
                name.push('-');
            }
            name.extend(character.to_lowercase());
        } else {
            name.push(character);
        }
    }
    name
}

fn fwc_top_level_commands(source: &str) -> Result<Vec<FwcTopLevelCommand>, String> {
    let mut commands = Vec::new();
    let mut in_commands = false;
    let mut brace_depth = 0_usize;
    let mut pending_command_attrs = Vec::<String>::new();

    for line in source.lines() {
        let trimmed = line.trim_start();
        if !in_commands {
            if trimmed == "enum Commands {" {
                in_commands = true;
                brace_depth = 1;
            }
            continue;
        }

        brace_depth += line.matches('{').count();
        brace_depth = brace_depth
            .checked_sub(line.matches('}').count())
            .ok_or_else(|| "fwc Commands enum brace depth underflowed".to_owned())?;

        if brace_depth == 1 && trimmed.starts_with("#[command(") {
            pending_command_attrs.push(trimmed.to_owned());
            continue;
        }

        if brace_depth == 1 && line.starts_with("    ") && !line.starts_with("        ") {
            let trimmed = line.trim();
            if let Some((variant, _args)) = trimmed.split_once('(') {
                if variant.chars().next().is_some_and(char::is_uppercase) {
                    let cli_name = pending_command_attrs
                        .iter()
                        .flat_map(|attr| command_attribute_string_values(attr, "name"))
                        .next()
                        .unwrap_or_else(|| variant_cli_name(variant));
                    let aliases = pending_command_attrs
                        .iter()
                        .flat_map(|attr| {
                            command_attribute_string_values(attr, "visible_alias")
                                .into_iter()
                                .chain(command_attribute_string_values(attr, "alias"))
                        })
                        .collect::<BTreeSet<_>>();
                    commands.push(FwcTopLevelCommand {
                        variant: variant.to_owned(),
                        cli_name,
                        aliases,
                    });
                    pending_command_attrs.clear();
                }
            }
        }
        if brace_depth == 0 {
            break;
        }
    }

    if commands.is_empty() {
        return Err("failed to inventory fwc top-level Commands enum".to_owned());
    }
    Ok(commands)
}

fn fwc_top_level_command_rows(root: &Path) -> Result<Vec<FeatureUniverseRow>, String> {
    let source = read_to_string(root, "crates/fwc/src/main.rs")?;
    let mut rows = Vec::new();

    for command in fwc_top_level_commands(&source)? {
        rows.push(row(
            "fwc_top_level_command",
            format!("Commands::{}", command.variant),
            "crates/fwc/src/main.rs",
            "inventory_only",
            "crates/fcp-conformance/tests/feature_universe_inventory.rs",
            "feature_universe_inventory_rows_are_joined_and_ratcheted",
            "inventory_only",
        ));
        rows.push(row(
            "fwc_top_level_command_name",
            command.cli_name.clone(),
            "crates/fwc/src/main.rs",
            "inventory_only",
            "crates/fcp-conformance/tests/feature_universe_inventory.rs",
            "feature_universe_inventory_rows_are_joined_and_ratcheted",
            "inventory_only",
        ));
        rows.extend(command.aliases.into_iter().map(|alias| {
            row(
                "fwc_top_level_command_alias",
                alias,
                "crates/fwc/src/main.rs",
                "inventory_only",
                "crates/fcp-conformance/tests/feature_universe_inventory.rs",
                "feature_universe_inventory_rows_are_joined_and_ratcheted",
                "inventory_only",
            )
        }));
    }
    Ok(rows)
}

#[derive(Debug, Eq, PartialEq)]
struct FwcSubcommandVariant {
    enum_name: String,
    variant: String,
    cli_name: String,
    aliases: BTreeSet<String>,
}

fn enum_name_from_line(line: &str) -> Option<String> {
    let enum_start = line.find("enum ")? + "enum ".len();
    let name = line[enum_start..]
        .split(|character: char| character == '{' || character == '<' || character.is_whitespace())
        .next()?
        .trim();
    if name.is_empty() {
        None
    } else {
        Some(name.to_owned())
    }
}

fn variant_name_from_line(line: &str) -> Option<String> {
    let trimmed = line.trim();
    if trimmed.starts_with('#') || trimmed.starts_with('/') {
        return None;
    }
    let variant = trimmed
        .split(|character: char| {
            character == '('
                || character == ','
                || character == '{'
                || character == '='
                || character.is_whitespace()
        })
        .next()?;
    if variant.chars().next().is_some_and(char::is_uppercase)
        && variant
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '_')
    {
        Some(variant.to_owned())
    } else {
        None
    }
}

fn fwc_subcommand_variants_in_source(source: &str) -> Result<Vec<FwcSubcommandVariant>, String> {
    let mut variants = Vec::new();
    let mut pending_subcommand_derive = false;
    let mut in_subcommand_enum = false;
    let mut enum_name = String::new();
    let mut brace_depth = 0_usize;
    let mut pending_command_attrs = Vec::<String>::new();

    for line in source.lines() {
        let trimmed = line.trim_start();
        if !in_subcommand_enum {
            if trimmed.starts_with("#[derive(") && trimmed.contains("Subcommand") {
                pending_subcommand_derive = true;
                continue;
            }
            if pending_subcommand_derive {
                if let Some(name) = enum_name_from_line(trimmed) {
                    enum_name = name;
                    in_subcommand_enum = true;
                    brace_depth = line.matches('{').count();
                    brace_depth = brace_depth
                        .checked_sub(line.matches('}').count())
                        .ok_or_else(|| "fwc subcommand enum brace depth underflowed".to_owned())?;
                    pending_subcommand_derive = false;
                    continue;
                }
                if !(trimmed.is_empty() || trimmed.starts_with("#[") || trimmed.starts_with("///"))
                {
                    pending_subcommand_derive = false;
                }
            }
            continue;
        }

        brace_depth += line.matches('{').count();
        brace_depth = brace_depth
            .checked_sub(line.matches('}').count())
            .ok_or_else(|| "fwc subcommand enum brace depth underflowed".to_owned())?;

        if brace_depth == 1 && trimmed.starts_with("#[command(") {
            pending_command_attrs.push(trimmed.to_owned());
            continue;
        }

        if brace_depth == 1 {
            if let Some(variant) = variant_name_from_line(trimmed) {
                let cli_name = pending_command_attrs
                    .iter()
                    .flat_map(|attr| command_attribute_string_values(attr, "name"))
                    .next()
                    .unwrap_or_else(|| variant_cli_name(&variant));
                let aliases = pending_command_attrs
                    .iter()
                    .flat_map(|attr| {
                        command_attribute_string_values(attr, "visible_alias")
                            .into_iter()
                            .chain(command_attribute_string_values(attr, "alias"))
                            .chain(command_attribute_string_values(attr, "visible_aliases"))
                            .chain(command_attribute_string_values(attr, "aliases"))
                    })
                    .collect::<BTreeSet<_>>();
                variants.push(FwcSubcommandVariant {
                    enum_name: enum_name.clone(),
                    variant,
                    cli_name,
                    aliases,
                });
                pending_command_attrs.clear();
            }
        }
        if brace_depth == 0 {
            in_subcommand_enum = false;
            enum_name.clear();
            pending_command_attrs.clear();
        }
    }

    Ok(variants)
}

fn fwc_source_files(root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut sources = Vec::new();
    collect_rust_sources(&root.join("crates/fwc/src"), &mut sources)?;
    sources.sort();
    Ok(sources)
}

fn fwc_nested_subcommand_rows(root: &Path) -> Result<Vec<FeatureUniverseRow>, String> {
    let mut rows = Vec::new();
    for source_path in fwc_source_files(root)? {
        let source = fs::read_to_string(&source_path)
            .map_err(|err| format!("expected {} to be readable: {err}", source_path.display()))?;
        let owner_file = display_path(root, &source_path);
        for variant in fwc_subcommand_variants_in_source(&source)?
            .into_iter()
            .filter(|variant| variant.enum_name != "Commands")
        {
            let variant_id = format!("{}::{}", variant.enum_name, variant.variant);
            rows.push(row(
                "fwc_nested_subcommand_variant",
                variant_id,
                owner_file.clone(),
                "inventory_only",
                "crates/fcp-conformance/tests/feature_universe_inventory.rs",
                "feature_universe_inventory_rows_are_joined_and_ratcheted",
                "inventory_only",
            ));
            rows.push(row(
                "fwc_nested_subcommand_name",
                format!("{}::{}", variant.enum_name, variant.cli_name),
                owner_file.clone(),
                "inventory_only",
                "crates/fcp-conformance/tests/feature_universe_inventory.rs",
                "feature_universe_inventory_rows_are_joined_and_ratcheted",
                "inventory_only",
            ));
            rows.extend(variant.aliases.into_iter().map(|alias| {
                row(
                    "fwc_nested_subcommand_alias",
                    format!("{}::{alias}", variant.enum_name),
                    owner_file.clone(),
                    "inventory_only",
                    "crates/fcp-conformance/tests/feature_universe_inventory.rs",
                    "feature_universe_inventory_rows_are_joined_and_ratcheted",
                    "inventory_only",
                )
            }));
        }
    }

    if rows.is_empty() {
        return Err("failed to inventory fwc nested subcommands".to_owned());
    }
    Ok(rows)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FwcJsonOutputContract {
    line_number: usize,
    normalized_args: Vec<String>,
}

fn string_array_end(source: &str, start: usize) -> Result<usize, String> {
    let mut bracket_depth = 1_usize;
    let mut in_string = false;
    let mut escaped = false;

    for (offset, character) in source[start..].char_indices() {
        if in_string {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                in_string = false;
            }
            continue;
        }

        match character {
            '"' => in_string = true,
            '[' => bracket_depth += 1,
            ']' => {
                bracket_depth = bracket_depth
                    .checked_sub(1)
                    .ok_or_else(|| "execute_json argument array depth underflowed".to_owned())?;
                if bracket_depth == 0 {
                    return Ok(start + offset);
                }
            }
            _ => {}
        }
    }

    Err("unterminated execute_json argument array".to_owned())
}

fn normalized_static_arg(arg: &str) -> String {
    string_literal_value(arg).unwrap_or_else(|| "<expr>".to_owned())
}

fn fwc_json_output_contracts(source: &str) -> Result<Vec<FwcJsonOutputContract>, String> {
    let marker = "execute_json(&[";
    let mut contracts = Vec::new();

    for (call_index, _marker) in source.match_indices(marker) {
        let args_start = call_index + marker.len();
        let args_end = string_array_end(source, args_start)?;
        let args_body = &source[args_start..args_end];
        let normalized_args = split_command_attribute_args(args_body)
            .into_iter()
            .filter(|arg| !arg.trim().is_empty())
            .map(normalized_static_arg)
            .collect::<Vec<_>>();
        if normalized_args.is_empty() {
            return Err(format!(
                "execute_json call at byte {call_index} has no static argument entries"
            ));
        }
        contracts.push(FwcJsonOutputContract {
            line_number: source[..call_index].lines().count() + 1,
            normalized_args,
        });
    }

    if contracts.is_empty() {
        return Err("failed to inventory fwc execute_json output contracts".to_owned());
    }
    Ok(contracts)
}

fn fwc_json_output_contract_rows(root: &Path) -> Result<Vec<FeatureUniverseRow>, String> {
    let source_path = "crates/fwc/src/main.rs";
    let source = read_to_string(root, source_path)?;
    Ok(fwc_json_output_contracts(&source)?
        .into_iter()
        .map(|contract| {
            row(
                "fwc_json_output_contract",
                format!(
                    "{}:{}",
                    contract.line_number,
                    contract.normalized_args.join(" ")
                ),
                source_path,
                "rust_unit_test",
                source_path,
                "execute_json",
                "json_parse_ratcheted",
            )
        })
        .collect())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RustTestBody {
    name: String,
    start_line: usize,
    body: String,
}

fn rust_test_bodies_in_source(owner_file: &str, source: &str) -> Result<Vec<RustTestBody>, String> {
    let mut tests = Vec::new();
    let mut pending_test = false;
    let mut current_test: Option<RustTestBody> = None;

    for (line_index, line) in source.lines().enumerate() {
        let trimmed = line.trim_start();

        if trimmed == "#[test]" {
            if let Some(test) = current_test.take() {
                tests.push(test);
            }
            pending_test = true;
            continue;
        }

        if pending_test {
            if let Some(name) = rust_test_name(trimmed) {
                let mut body = String::new();
                body.push_str(line);
                body.push('\n');
                current_test = Some(RustTestBody {
                    name,
                    start_line: line_index + 1,
                    body,
                });
                pending_test = false;
                continue;
            }
            if !(trimmed.is_empty() || trimmed.starts_with("#[") || trimmed.starts_with("///")) {
                return Err(format!(
                    "{owner_file}:{} has #[test] not followed by a Rust test fn",
                    line_index + 1
                ));
            }
            continue;
        }

        if let Some(test) = current_test.as_mut() {
            test.body.push_str(line);
            test.body.push('\n');
        }
    }

    if let Some(test) = current_test {
        tests.push(test);
    }

    Ok(tests)
}

fn normalized_command_tokens(args: &[String]) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut index = usize::from(args.first().is_some_and(|arg| arg == "fwc"));

    while let Some(arg) = args.get(index) {
        match arg.as_str() {
            "--json" => index += 1,
            "--host" => index += 2,
            _ if arg.starts_with("--") => index += 1,
            _ => {
                tokens.push(arg.clone());
                index += 1;
            }
        }
    }

    tokens
}

fn schema_case_has_parse_contract(
    schema_case: &FwcSchemaCase,
    contracts: &[FwcJsonOutputContract],
) -> bool {
    contracts.iter().any(|contract| {
        normalized_command_tokens(&contract.normalized_args).starts_with(&schema_case.command_path)
    })
}

fn schema_case_for_contract<'a>(
    contract: &FwcJsonOutputContract,
    schema_cases: &'a [FwcSchemaCase],
) -> Option<&'a FwcSchemaCase> {
    let command_tokens = normalized_command_tokens(&contract.normalized_args);
    schema_cases
        .iter()
        .filter(|case| command_tokens.starts_with(&case.command_path))
        .max_by_key(|case| case.command_path.len())
}

fn fwc_json_schema_case_contract_rows(root: &Path) -> Result<Vec<FeatureUniverseRow>, String> {
    let source_path = "crates/fwc/src/main.rs";
    let source = read_to_string(root, source_path)?;
    let schema_cases = fwc_schema_cases(root)?;

    Ok(fwc_json_output_contracts(&source)?
        .into_iter()
        .filter_map(|contract| {
            let schema_case = schema_case_for_contract(&contract, &schema_cases)?;
            Some(row(
                "fwc_json_schema_case_contract",
                format!(
                    "{}:{}:{}",
                    contract.line_number,
                    schema_case.schema_file,
                    contract.normalized_args.join(" ")
                ),
                source_path,
                "json_schema_case_owner",
                FWC_COMMAND_SCHEMAS_PATH,
                "fwc_command_truth_source_schemas_compile_and_validate_envelopes",
                "schema_case_owner_available",
            ))
        })
        .collect())
}

fn contract_identity(contract: &FwcJsonOutputContract) -> (usize, Vec<String>) {
    (contract.line_number, contract.normalized_args.clone())
}

fn fwc_json_output_ownership_status(
    contract: &FwcJsonOutputContract,
    schema_cases: &[FwcSchemaCase],
    schema_version_contracts: &BTreeSet<(usize, Vec<String>)>,
    field_assertion_contracts: &BTreeSet<(usize, Vec<String>)>,
    no_schema_decision_contracts: &BTreeSet<(usize, Vec<String>)>,
) -> &'static str {
    let has_schema_version = schema_version_contracts.contains(&contract_identity(contract));
    let has_schema_case = schema_case_for_contract(contract, schema_cases).is_some();
    let has_field_assertion = field_assertion_contracts.contains(&contract_identity(contract));
    let has_no_schema_decision =
        no_schema_decision_contracts.contains(&contract_identity(contract));

    match (
        has_schema_version,
        has_schema_case,
        has_no_schema_decision,
        has_field_assertion,
    ) {
        (true, true, _, _) => "schema_version_and_schema_case_owner",
        (true, false, _, _) => "schema_version_asserted",
        (false, true, _, _) => "schema_case_owner_available",
        (false, false, true, _) => "explicit_no_schema_decision",
        (false, false, false, true) => "field_assertions_only_schema_decision_pending",
        (false, false, false, false) => "parse_contract_only",
    }
}

fn fwc_json_output_ownership_rows(root: &Path) -> Result<Vec<FeatureUniverseRow>, String> {
    let source_path = "crates/fwc/src/main.rs";
    let source = read_to_string(root, source_path)?;
    let schema_cases = fwc_schema_cases(root)?;
    let schema_version_contracts =
        fwc_json_schema_version_contracts_in_source(source_path, &source)?
            .into_iter()
            .map(|contract| (contract.line_number, contract.normalized_args))
            .collect::<BTreeSet<_>>();
    let field_assertion_contracts =
        fwc_json_field_assertion_contracts_in_source(source_path, &source)?
            .into_iter()
            .map(|contract| (contract.line_number, contract.normalized_args))
            .collect::<BTreeSet<_>>();
    let no_schema_decision_contracts =
        fwc_json_no_schema_decision_contracts_in_source(source_path, &source)?
            .into_iter()
            .map(|contract| (contract.line_number, contract.normalized_args))
            .collect::<BTreeSet<_>>();

    Ok(fwc_json_output_contracts(&source)?
        .into_iter()
        .map(|contract| {
            let proof_status = fwc_json_output_ownership_status(
                &contract,
                &schema_cases,
                &schema_version_contracts,
                &field_assertion_contracts,
                &no_schema_decision_contracts,
            );
            row(
                "fwc_json_output_ownership",
                format!(
                    "{}:{}",
                    contract.line_number,
                    contract.normalized_args.join(" ")
                ),
                source_path,
                "json_output_ownership_union",
                "crates/fcp-conformance/tests/feature_universe_inventory.rs",
                "fwc_json_output_ownership_rows_classify_all_parse_contracts",
                proof_status,
            )
        })
        .collect())
}

fn fwc_schema_case_parse_contract_rows(root: &Path) -> Result<Vec<FeatureUniverseRow>, String> {
    let schema_cases = fwc_schema_cases(root)?;
    let source = read_to_string(root, "crates/fwc/src/main.rs")?;
    let contracts = fwc_json_output_contracts(&source)?;

    Ok(schema_cases
        .into_iter()
        .map(|case| {
            let proof_status = if schema_case_has_parse_contract(&case, &contracts) {
                "parse_contract_present"
            } else {
                "missing_direct_execute_json_contract"
            };
            row(
                "fwc_schema_case_parse_contract",
                case.item_id(),
                "crates/fwc/src/main.rs",
                "rust_unit_test",
                "crates/fwc/src/main.rs",
                "execute_json",
                proof_status,
            )
        })
        .collect())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FwcRuntimeSchemaContract {
    owner_file: String,
    test_name: String,
    line_number: usize,
    normalized_args: Vec<String>,
    schema_version: String,
}

fn rust_test_name(line: &str) -> Option<String> {
    let rest = line.trim_start().strip_prefix("fn ")?;
    let (name, _args) = rest.split_once('(')?;
    if name.trim().is_empty() {
        None
    } else {
        Some(name.trim().to_owned())
    }
}

fn schema_version_assertions(body: &str) -> Vec<String> {
    let marker = r#"payload["schema_version"]"#;
    let mut versions = BTreeSet::new();

    for (index, _marker) in body.match_indices(marker) {
        let after_marker = &body[index + marker.len()..];
        let Some((_, expected)) = after_marker.split_once(',') else {
            continue;
        };
        let Some(quote_index) = expected.find('"') else {
            continue;
        };
        let expected = &expected[quote_index..];
        if let Some(version) = first_string_literal_value(expected)
            && version.starts_with("fcp.")
        {
            versions.insert(version);
        }
    }

    versions.into_iter().collect()
}

fn schema_version_assertion_value(expected: &str) -> Option<String> {
    if let Some(version) = first_string_literal_value(expected) {
        return Some(version);
    }

    let expected = expected.trim_start().trim_start_matches('&').trim_start();
    let end = expected
        .find([')', ',', '\n', ';'])
        .unwrap_or(expected.len());
    let expression = expected[..end].trim();
    if expression.is_empty()
        || !expression.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '_' | ':' | '.')
        })
    {
        return None;
    }
    if expression.contains("SCHEMA_VERSION") {
        Some(expression.to_owned())
    } else {
        None
    }
}

fn json_schema_version_assertions(body: &str) -> Vec<String> {
    let marker = r#"["schema_version"]"#;
    let mut versions = BTreeSet::new();

    for (index, _marker) in body.match_indices(marker) {
        let after_marker = &body[index + marker.len()..];
        let statement = after_marker.split(';').next().unwrap_or(after_marker);
        let Some((_, expected)) = statement.split_once(',') else {
            continue;
        };
        if let Some(version) = schema_version_assertion_value(expected) {
            versions.insert(version);
        }
    }

    versions.into_iter().collect()
}

fn execute_json_contracts_from_test_body(
    body: &str,
    test_start_line: usize,
) -> Result<Vec<FwcJsonOutputContract>, String> {
    Ok(
        execute_json_contracts_from_test_body_with_indexes(body, test_start_line)?
            .into_iter()
            .map(|(_call_index, contract)| contract)
            .collect(),
    )
}

fn execute_json_contracts_from_test_body_with_indexes(
    body: &str,
    test_start_line: usize,
) -> Result<Vec<(usize, FwcJsonOutputContract)>, String> {
    let marker = "execute_json(&[";
    let mut contracts = Vec::new();

    for (call_index, _marker) in body.match_indices(marker) {
        let args_start = call_index + marker.len();
        let args_end = string_array_end(body, args_start)?;
        let args_body = &body[args_start..args_end];
        let normalized_args = split_command_attribute_args(args_body)
            .into_iter()
            .filter(|arg| !arg.trim().is_empty())
            .map(normalized_static_arg)
            .collect::<Vec<_>>();
        if normalized_args.is_empty() {
            return Err(format!(
                "execute_json call at byte {call_index} has no static argument entries"
            ));
        }
        contracts.push((
            call_index,
            FwcJsonOutputContract {
                line_number: test_start_line + body[..call_index].lines().count(),
                normalized_args,
            },
        ));
    }

    Ok(contracts)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FwcJsonSchemaVersionContract {
    test_name: String,
    line_number: usize,
    normalized_args: Vec<String>,
    schema_version: String,
}

fn json_schema_version_contracts_from_test_body(
    test_name: &str,
    test_start_line: usize,
    body: &str,
) -> Result<Vec<FwcJsonSchemaVersionContract>, String> {
    let schema_versions = json_schema_version_assertions(body);
    if schema_versions.is_empty() {
        return Ok(Vec::new());
    }

    Ok(
        execute_json_contracts_from_test_body(body, test_start_line)?
            .into_iter()
            .flat_map(|contract| {
                schema_versions
                    .iter()
                    .map(move |schema_version| FwcJsonSchemaVersionContract {
                        test_name: test_name.to_owned(),
                        line_number: contract.line_number,
                        normalized_args: contract.normalized_args.clone(),
                        schema_version: schema_version.clone(),
                    })
            })
            .collect(),
    )
}

fn fwc_json_schema_version_contracts_in_source(
    owner_file: &str,
    source: &str,
) -> Result<Vec<FwcJsonSchemaVersionContract>, String> {
    let mut contracts = Vec::new();
    for test in rust_test_bodies_in_source(owner_file, source)? {
        contracts.extend(json_schema_version_contracts_from_test_body(
            &test.name,
            test.start_line,
            &test.body,
        )?);
    }
    Ok(contracts)
}

fn fwc_json_schema_version_contract_rows(root: &Path) -> Result<Vec<FeatureUniverseRow>, String> {
    let source_path = "crates/fwc/src/main.rs";
    let source = read_to_string(root, source_path)?;
    Ok(
        fwc_json_schema_version_contracts_in_source(source_path, &source)?
            .into_iter()
            .map(|contract| {
                row(
                    "fwc_json_schema_version_contract",
                    format!(
                        "{}:{}:{}",
                        contract.line_number,
                        contract.schema_version,
                        contract.normalized_args.join(" ")
                    ),
                    source_path,
                    "rust_unit_test",
                    source_path,
                    contract.test_name,
                    "schema_version_asserted",
                )
            })
            .collect(),
    )
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FwcJsonFieldAssertionContract {
    test_name: String,
    line_number: usize,
    normalized_args: Vec<String>,
    payload_variable: String,
    assertion_count: usize,
}

fn clean_binding_variable(raw: &str) -> Option<String> {
    let variable = raw
        .trim()
        .trim_start_matches("mut ")
        .trim_start_matches('&')
        .trim();
    if variable.is_empty()
        || variable.starts_with('_')
        || !variable
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | ':'))
    {
        None
    } else {
        Some(variable.to_owned())
    }
}

fn execute_json_payload_variable_before_call(body: &str, call_index: usize) -> Option<String> {
    let before_call = &body[..call_index];
    let let_index = before_call.rfind("let ")?;
    let binding = before_call[let_index + "let ".len()..].trim();
    let (pattern, _rest) = binding.split_once('=')?;
    let tuple = pattern
        .trim()
        .strip_prefix('(')
        .and_then(|pattern| pattern.strip_suffix(')'))?;
    let fields = split_command_attribute_args(tuple);
    fields
        .get(1)
        .and_then(|field| clean_binding_variable(field))
}

fn json_field_reference_count(body: &str, payload_variable: &str) -> usize {
    let bracket_reference = format!("{payload_variable}[");
    let get_reference = format!("{payload_variable}.get(");
    body.match_indices(&bracket_reference).count() + body.match_indices(&get_reference).count()
}

fn json_field_assertion_contracts_from_test_body(
    test_name: &str,
    test_start_line: usize,
    body: &str,
) -> Result<Vec<FwcJsonFieldAssertionContract>, String> {
    let mut contracts = Vec::new();
    for (call_index, contract) in
        execute_json_contracts_from_test_body_with_indexes(body, test_start_line)?
    {
        let Some(payload_variable) = execute_json_payload_variable_before_call(body, call_index)
        else {
            continue;
        };
        let assertion_count = json_field_reference_count(body, &payload_variable);
        if assertion_count == 0 {
            continue;
        }
        contracts.push(FwcJsonFieldAssertionContract {
            test_name: test_name.to_owned(),
            line_number: contract.line_number,
            normalized_args: contract.normalized_args,
            payload_variable,
            assertion_count,
        });
    }
    Ok(contracts)
}

fn fwc_json_field_assertion_contracts_in_source(
    owner_file: &str,
    source: &str,
) -> Result<Vec<FwcJsonFieldAssertionContract>, String> {
    let mut contracts = Vec::new();
    for test in rust_test_bodies_in_source(owner_file, source)? {
        contracts.extend(json_field_assertion_contracts_from_test_body(
            &test.name,
            test.start_line,
            &test.body,
        )?);
    }
    Ok(contracts)
}

fn fwc_json_output_field_assertion_contract_rows(
    root: &Path,
) -> Result<Vec<FeatureUniverseRow>, String> {
    let source_path = "crates/fwc/src/main.rs";
    let source = read_to_string(root, source_path)?;
    Ok(
        fwc_json_field_assertion_contracts_in_source(source_path, &source)?
            .into_iter()
            .map(|contract| {
                row(
                    "fwc_json_output_field_assertion_contract",
                    format!(
                        "{}:{}:{}:{}",
                        contract.line_number,
                        contract.payload_variable,
                        contract.assertion_count,
                        contract.normalized_args.join(" ")
                    ),
                    source_path,
                    "json_output_field_assertion",
                    source_path,
                    contract.test_name,
                    "same_test_json_field_asserted",
                )
            })
            .collect(),
    )
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FwcJsonNoSchemaDecisionContract {
    test_name: String,
    line_number: usize,
    normalized_args: Vec<String>,
    payload_variable: String,
    decision_count: usize,
}

fn json_no_schema_decision_reference_count(body: &str, payload_variable: &str) -> usize {
    let get_is_none = format!(r#"{payload_variable}.get("schema_version").is_none()"#);
    let index_is_null = format!(r#"{payload_variable}["schema_version"].is_null()"#);
    body.match_indices(&get_is_none).count() + body.match_indices(&index_is_null).count()
}

fn json_no_schema_decision_contracts_from_test_body(
    test_name: &str,
    test_start_line: usize,
    body: &str,
) -> Result<Vec<FwcJsonNoSchemaDecisionContract>, String> {
    let mut contracts = Vec::new();
    for (call_index, contract) in
        execute_json_contracts_from_test_body_with_indexes(body, test_start_line)?
    {
        let Some(payload_variable) = execute_json_payload_variable_before_call(body, call_index)
        else {
            continue;
        };
        let decision_count = json_no_schema_decision_reference_count(body, &payload_variable);
        if decision_count == 0 {
            continue;
        }
        contracts.push(FwcJsonNoSchemaDecisionContract {
            test_name: test_name.to_owned(),
            line_number: contract.line_number,
            normalized_args: contract.normalized_args,
            payload_variable,
            decision_count,
        });
    }
    Ok(contracts)
}

fn fwc_json_no_schema_decision_contracts_in_source(
    owner_file: &str,
    source: &str,
) -> Result<Vec<FwcJsonNoSchemaDecisionContract>, String> {
    let mut contracts = Vec::new();
    for test in rust_test_bodies_in_source(owner_file, source)? {
        contracts.extend(json_no_schema_decision_contracts_from_test_body(
            &test.name,
            test.start_line,
            &test.body,
        )?);
    }
    Ok(contracts)
}

fn fwc_json_output_no_schema_decision_contract_rows(
    root: &Path,
) -> Result<Vec<FeatureUniverseRow>, String> {
    let source_path = "crates/fwc/src/main.rs";
    let source = read_to_string(root, source_path)?;
    Ok(
        fwc_json_no_schema_decision_contracts_in_source(source_path, &source)?
            .into_iter()
            .map(|contract| {
                row(
                    "fwc_json_output_no_schema_decision_contract",
                    format!(
                        "{}:{}:{}:{}",
                        contract.line_number,
                        contract.payload_variable,
                        contract.decision_count,
                        contract.normalized_args.join(" ")
                    ),
                    source_path,
                    "json_output_no_schema_decision",
                    source_path,
                    contract.test_name,
                    "explicit_no_schema_decision",
                )
            })
            .collect(),
    )
}

fn run_fwc_json_contracts(
    body: &str,
    test_start_line: usize,
) -> Result<Vec<FwcJsonOutputContract>, String> {
    let marker = "run_fwc(&[";
    let mut contracts = Vec::new();

    for (call_index, _marker) in body.match_indices(marker) {
        let args_start = call_index + marker.len();
        let args_end = string_array_end(body, args_start)?;
        let args_body = &body[args_start..args_end];
        let normalized_args = split_command_attribute_args(args_body)
            .into_iter()
            .filter(|arg| !arg.trim().is_empty())
            .map(normalized_static_arg)
            .collect::<Vec<_>>();
        if normalized_args.is_empty() {
            return Err(format!(
                "run_fwc call at byte {call_index} has no static argument entries"
            ));
        }
        contracts.push(FwcJsonOutputContract {
            line_number: test_start_line + body[..call_index].lines().count(),
            normalized_args,
        });
    }

    Ok(contracts)
}

fn runtime_schema_contracts_from_test_body(
    owner_file: &str,
    test_name: &str,
    test_start_line: usize,
    body: &str,
) -> Result<Vec<FwcRuntimeSchemaContract>, String> {
    let schema_versions = schema_version_assertions(body);
    if schema_versions.is_empty() {
        return Ok(Vec::new());
    }

    Ok(run_fwc_json_contracts(body, test_start_line)?
        .into_iter()
        .flat_map(|contract| {
            schema_versions
                .iter()
                .map(move |schema_version| FwcRuntimeSchemaContract {
                    owner_file: owner_file.to_owned(),
                    test_name: test_name.to_owned(),
                    line_number: contract.line_number,
                    normalized_args: contract.normalized_args.clone(),
                    schema_version: schema_version.clone(),
                })
        })
        .collect())
}

fn fwc_runtime_schema_contracts_in_source(
    owner_file: &str,
    source: &str,
) -> Result<Vec<FwcRuntimeSchemaContract>, String> {
    let mut contracts = Vec::new();
    for test in rust_test_bodies_in_source(owner_file, source)? {
        contracts.extend(runtime_schema_contracts_from_test_body(
            owner_file,
            &test.name,
            test.start_line,
            &test.body,
        )?);
    }

    Ok(contracts)
}

fn fwc_runtime_schema_contracts(root: &Path) -> Result<Vec<FwcRuntimeSchemaContract>, String> {
    let mut sources = Vec::new();
    collect_rust_sources(&root.join("crates/fwc/tests"), &mut sources)?;
    sources.sort();

    let mut contracts = Vec::new();
    for source_path in sources {
        let owner_file = display_path(root, &source_path);
        let source = fs::read_to_string(&source_path)
            .map_err(|err| format!("expected {owner_file} to be readable: {err}"))?;
        contracts.extend(fwc_runtime_schema_contracts_in_source(
            &owner_file,
            &source,
        )?);
    }
    Ok(contracts)
}

fn schema_case_runtime_contract<'a>(
    schema_case: &FwcSchemaCase,
    contracts: &'a [FwcRuntimeSchemaContract],
) -> Option<&'a FwcRuntimeSchemaContract> {
    contracts.iter().find(|contract| {
        contract.schema_version == schema_case.success_schema_version
            && normalized_command_tokens(&contract.normalized_args)
                .starts_with(&schema_case.command_path)
    })
}

fn fwc_schema_case_runtime_contract_rows(root: &Path) -> Result<Vec<FeatureUniverseRow>, String> {
    let schema_cases = fwc_schema_cases(root)?;
    let contracts = fwc_runtime_schema_contracts(root)?;

    Ok(schema_cases
        .iter()
        .filter_map(|case| {
            let contract = schema_case_runtime_contract(case, &contracts)?;
            Some(row(
                "fwc_schema_case_runtime_contract",
                case.item_id(),
                contract.owner_file.clone(),
                "rust_integration_test",
                contract.owner_file.clone(),
                contract.test_name.clone(),
                "schema_version_asserted",
            ))
        })
        .collect())
}

#[derive(Debug, Eq, PartialEq)]
struct GraduationGauntletCheck {
    id: String,
    exit_code: usize,
}

fn graduation_gauntlet_checks(source: &str) -> Result<Vec<GraduationGauntletCheck>, String> {
    let mut checks = Vec::new();
    let mut in_checks = false;

    for line in source.lines() {
        let trimmed = line.trim();
        if !in_checks {
            if trimmed == "GRADUATION_CHECKS=(" {
                in_checks = true;
            }
            continue;
        }
        if trimmed == ")" {
            break;
        }
        if trimmed.is_empty() {
            continue;
        }
        let entry = trimmed
            .strip_prefix('"')
            .and_then(|entry| entry.strip_suffix('"'))
            .ok_or_else(|| format!("malformed graduation check entry: {line}"))?;
        let mut parts = entry.splitn(3, '|');
        let id = parts
            .next()
            .filter(|id| !id.trim().is_empty())
            .ok_or_else(|| format!("graduation check entry missing id: {line}"))?;
        let exit_code = parts
            .next()
            .ok_or_else(|| format!("graduation check entry missing exit code: {line}"))?
            .parse::<usize>()
            .map_err(|err| {
                format!("graduation check exit code must be numeric in {line}: {err}")
            })?;
        let description = parts
            .next()
            .filter(|description| !description.trim().is_empty())
            .ok_or_else(|| format!("graduation check entry missing description: {line}"))?;
        if description.contains('|') {
            return Err(format!(
                "graduation check description must not contain a pipe: {line}"
            ));
        }
        checks.push(GraduationGauntletCheck {
            id: id.to_owned(),
            exit_code,
        });
    }

    if checks.is_empty() {
        return Err("failed to inventory graduation gauntlet checks".to_owned());
    }
    Ok(checks)
}

fn graduation_gauntlet_check_rows(root: &Path) -> Result<Vec<FeatureUniverseRow>, String> {
    let checks_path = "scripts/graduation/checks/core.sh";
    let checks = read_to_string(root, checks_path)?;

    Ok(graduation_gauntlet_checks(&checks)?
        .into_iter()
        .map(|check| {
            row(
                "graduation_gauntlet_check",
                format!("{}:{}", check.exit_code, check.id),
                checks_path,
                "rust_conformance",
                "crates/fcp-conformance/tests/graduation_gauntlet_conformance.rs",
                "test_gauntlet_recognizes_all_12_checks",
                "ratcheted",
            )
        })
        .collect())
}

fn discover_connector_dirs(root: &Path) -> Result<Vec<(String, PathBuf)>, String> {
    let connectors_dir = root.join("connectors");
    let mut connectors = Vec::new();
    for entry in fs::read_dir(&connectors_dir)
        .map_err(|err| format!("cannot read {}: {err}", connectors_dir.display()))?
    {
        let entry = entry.map_err(|err| format!("cannot read connector directory entry: {err}"))?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let Some(connector) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        connectors.push((connector.to_owned(), path));
    }
    connectors.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(connectors)
}

fn connector_coverage_status(connector_dir: &Path) -> &'static str {
    let has_local_non_mock = connector_dir.join("tests/local_non_mock.rs").exists();
    let has_live_verification = connector_dir.join("tests/live_verification.rs").exists();
    if has_local_non_mock || has_live_verification {
        "ratcheted"
    } else {
        "known_gap"
    }
}

fn coverage_scanner_rows(root: &Path) -> Result<Vec<FeatureUniverseRow>, String> {
    let mut rows = Vec::new();
    for (connector, connector_dir) in discover_connector_dirs(root)? {
        let owner_file = display_path(root, &connector_dir);
        let proof_status = connector_coverage_status(&connector_dir);
        rows.push(row(
            "coverage_scanner_connector",
            connector.clone(),
            owner_file.clone(),
            "rust_conformance",
            "crates/fcp-conformance/tests/coverage_scanner_conformance.rs",
            "test_scanner_enumerates_every_connector",
            proof_status,
        ));
        if proof_status == "known_gap" {
            rows.push(row(
                "coverage_scanner_gap",
                connector,
                owner_file,
                "rust_conformance",
                "crates/fcp-conformance/tests/coverage_scanner_conformance.rs",
                "test_no_new_gap_connectors",
                "known_gap",
            ));
        }
    }
    Ok(rows)
}

fn discover_connector_manifests(root: &Path) -> Result<Vec<(String, PathBuf)>, String> {
    let connectors_dir = root.join("connectors");
    let mut manifests = Vec::new();
    for entry in fs::read_dir(&connectors_dir)
        .map_err(|err| format!("cannot read {}: {err}", connectors_dir.display()))?
    {
        let entry = entry.map_err(|err| format!("cannot read connector directory entry: {err}"))?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let manifest_path = path.join("manifest.toml");
        if !manifest_path.exists() {
            continue;
        }
        let Some(connector) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        manifests.push((connector.to_owned(), manifest_path));
    }
    manifests.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(manifests)
}

fn parse_manifest(body: &str) -> Result<toml::Value, String> {
    toml::from_str::<toml::Table>(body)
        .map(toml::Value::Table)
        .map_err(|err| err.to_string())
}

fn canonical_operation_ids(manifest: &toml::Value) -> Vec<String> {
    let mut ids = Vec::new();
    if let Some(operations) = manifest
        .get("provides")
        .and_then(|provides| provides.get("operations"))
        .and_then(toml::Value::as_table)
    {
        ids.extend(
            operations
                .keys()
                .filter(|id| !id.trim().is_empty())
                .cloned(),
        );
    }
    ids.sort();
    ids
}

fn connector_manifest_operation_rows(root: &Path) -> Result<Vec<FeatureUniverseRow>, String> {
    let mut rows = Vec::new();
    let manifests = discover_connector_manifests(root)?;
    for (connector, manifest_path) in manifests {
        let owner_file = display_path(root, &manifest_path);
        let manifest_body = fs::read_to_string(&manifest_path)
            .map_err(|err| format!("cannot read {}: {err}", manifest_path.display()))?;
        let manifest = parse_manifest(&manifest_body)
            .map_err(|err| format!("{owner_file} must parse as TOML: {err}"))?;
        let operation_ids = canonical_operation_ids(&manifest);
        if operation_ids.is_empty() {
            return Err(format!("{owner_file} has no canonical manifest operations"));
        }
        rows.extend(operation_ids.into_iter().map(|operation_id| {
            row(
                "connector_manifest_operation",
                format!("{connector}:{operation_id}"),
                owner_file.clone(),
                "rust_conformance",
                "crates/fcp-conformance/tests/manifest_operations_conformance.rs",
                "raw_manifest_operation_harness_rejects_zero_operation_connectors",
                "ratcheted",
            )
        }));
    }
    Ok(rows)
}

fn extract_backticked_identifier(cell: &str) -> Option<String> {
    let rest = cell.trim().strip_prefix('`')?;
    let (identifier, _suffix) = rest.split_once('`')?;
    let identifier = identifier.trim();
    if identifier.is_empty() || identifier.chars().any(char::is_whitespace) {
        None
    } else {
        Some(identifier.to_owned())
    }
}

fn operation_column_index(cells: &[String]) -> Option<usize> {
    cells
        .iter()
        .position(|cell| cell.trim().eq_ignore_ascii_case("Operation"))
}

fn readme_operation_ids(readme: &str) -> BTreeSet<String> {
    let mut operation_ids = BTreeSet::new();
    let mut active_operation_column = None;

    for line in readme.lines() {
        if !line.trim_start().starts_with('|') {
            active_operation_column = None;
            continue;
        }

        let cells = markdown_cells(line);
        if let Some(operation_column) = operation_column_index(&cells) {
            active_operation_column = Some(operation_column);
            continue;
        }
        if is_separator_row(&cells) {
            continue;
        }
        let Some(operation_column) = active_operation_column else {
            continue;
        };
        let Some(cell) = cells.get(operation_column) else {
            active_operation_column = None;
            continue;
        };
        if let Some(operation_id) = extract_backticked_identifier(cell) {
            operation_ids.insert(operation_id);
        }
    }

    operation_ids
}

fn connector_readme_operation_rows(root: &Path) -> Result<Vec<FeatureUniverseRow>, String> {
    let mut rows = Vec::new();
    for (connector, manifest_path) in discover_connector_manifests(root)? {
        let readme_path = manifest_path
            .parent()
            .ok_or_else(|| format!("manifest has no parent: {}", manifest_path.display()))?
            .join("README.md");
        let owner_file = display_path(root, &readme_path);
        let operation_ids = if readme_path.exists() {
            let readme = fs::read_to_string(&readme_path)
                .map_err(|err| format!("cannot read {}: {err}", readme_path.display()))?;
            readme_operation_ids(&readme)
        } else {
            BTreeSet::new()
        };
        let proof_status = if operation_ids.is_empty() {
            "known_gap"
        } else {
            "ratcheted"
        };
        rows.push(row(
            "connector_readme_operation_inventory",
            connector.clone(),
            owner_file.clone(),
            "rust_conformance",
            "crates/fcp-conformance/tests/readme_presence.rs",
            "connector_readme_backticked_table_row_gaps_do_not_grow",
            proof_status,
        ));
        rows.extend(operation_ids.into_iter().map(|operation_id| {
            row(
                "connector_readme_operation",
                format!("{connector}:{operation_id}"),
                owner_file.clone(),
                "rust_conformance",
                "crates/fcp-conformance/tests/feature_universe_inventory.rs",
                "feature_universe_inventory_rows_are_joined_and_ratcheted",
                "inventory_only",
            )
        }));
    }
    Ok(rows)
}

fn all_inventory_rows(root: &Path) -> Result<Vec<FeatureUniverseRow>, String> {
    let mut rows = Vec::new();
    rows.extend(readme_feature_rows(root)?);
    rows.extend(formal_coverage_rows(root)?);
    rows.extend(fwc_schema_rows(root)?);
    rows.extend(fwc_schema_case_rows(root)?);
    rows.extend(fwc_top_level_command_rows(root)?);
    rows.extend(fwc_nested_subcommand_rows(root)?);
    rows.extend(fwc_json_output_contract_rows(root)?);
    rows.extend(fwc_json_schema_version_contract_rows(root)?);
    rows.extend(fwc_json_schema_case_contract_rows(root)?);
    rows.extend(fwc_json_output_field_assertion_contract_rows(root)?);
    rows.extend(fwc_json_output_no_schema_decision_contract_rows(root)?);
    rows.extend(fwc_json_output_ownership_rows(root)?);
    rows.extend(fwc_schema_case_parse_contract_rows(root)?);
    rows.extend(fwc_schema_case_runtime_contract_rows(root)?);
    rows.extend(graduation_gauntlet_check_rows(root)?);
    rows.extend(coverage_scanner_rows(root)?);
    rows.extend(connector_manifest_operation_rows(root)?);
    rows.extend(connector_readme_operation_rows(root)?);
    Ok(rows)
}

fn count_by_surface(rows: &[FeatureUniverseRow]) -> BTreeMap<&'static str, usize> {
    let mut counts = BTreeMap::new();
    for row in rows {
        *counts.entry(row.surface).or_insert(0) += 1;
    }
    counts
}

fn proof_status_counts(
    rows: &[FeatureUniverseRow],
    surface: &'static str,
) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for row in rows.iter().filter(|row| row.surface == surface) {
        *counts.entry(row.proof_status.clone()).or_insert(0) += 1;
    }
    counts
}

fn require_surface_at_least(
    counts: &BTreeMap<&'static str, usize>,
    surface: &'static str,
    minimum: usize,
) -> Result<(), String> {
    let actual = counts.get(surface).copied().unwrap_or_default();
    if actual < minimum {
        return Err(format!(
            "{surface} row count shrank below baseline {minimum}: {actual}"
        ));
    }
    Ok(())
}

fn assert_no_duplicate_rows(rows: &[FeatureUniverseRow]) -> Result<(), String> {
    let mut keys = BTreeSet::new();
    let mut duplicates = Vec::new();
    for row in rows {
        let key = row.key();
        if !keys.insert(key.clone()) {
            duplicates.push(key);
        }
    }
    if !duplicates.is_empty() {
        return Err(format!("duplicate FeatureUniverse rows: {duplicates:?}"));
    }
    Ok(())
}

fn assert_rows_have_verifier_owners(rows: &[FeatureUniverseRow]) -> Result<(), String> {
    let missing = rows
        .iter()
        .filter(|row| {
            row.verifier_kind.trim().is_empty()
                || row.verifier_path.trim().is_empty()
                || row.verifier_name.trim().is_empty()
                || row.proof_status.trim().is_empty()
        })
        .map(FeatureUniverseRow::key)
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(format!(
            "FeatureUniverse rows missing verifier ownership: {missing:?}"
        ));
    }
    Ok(())
}

fn assert_no_unreferenced_fwc_schema(rows: &[FeatureUniverseRow]) -> Result<(), String> {
    let missing = rows
        .iter()
        .filter(|row| {
            row.surface == "fwc_schema_file" && row.proof_status == "missing_validator_reference"
        })
        .map(|row| row.item_id.clone())
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(format!(
            "fwc schema files missing validator references: {missing:?}"
        ));
    }
    Ok(())
}

fn assert_connector_readme_operation_gaps_do_not_grow(
    rows: &[FeatureUniverseRow],
) -> Result<(), String> {
    let allowed = ALLOWED_CONNECTOR_README_OPERATION_TABLE_GAPS
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let gaps = rows
        .iter()
        .filter(|row| {
            row.surface == "connector_readme_operation_inventory" && row.proof_status == "known_gap"
        })
        .map(|row| row.item_id.as_str())
        .collect::<Vec<_>>();
    let unexpected = gaps
        .iter()
        .copied()
        .filter(|connector| !allowed.contains(connector))
        .collect::<Vec<_>>();
    if !unexpected.is_empty() {
        return Err(format!(
            "new connector README operation table gaps: {unexpected:?}; allowed gaps: {ALLOWED_CONNECTOR_README_OPERATION_TABLE_GAPS:?}"
        ));
    }
    if gaps.len() > MAX_CONNECTOR_README_OPERATION_TABLE_GAPS {
        return Err(format!(
            "connector README operation table gap count grew from {MAX_CONNECTOR_README_OPERATION_TABLE_GAPS} to {}: {gaps:?}",
            gaps.len()
        ));
    }
    Ok(())
}

fn coverage_scanner_gap_connectors(rows: &[FeatureUniverseRow]) -> Vec<String> {
    rows.iter()
        .filter(|row| row.surface == "coverage_scanner_gap")
        .map(|row| row.item_id.clone())
        .collect()
}

fn assert_coverage_scanner_gaps_do_not_grow(gaps: &[String]) -> Result<(), String> {
    let allowed = ALLOWED_COVERAGE_SCANNER_GAPS
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let unexpected = gaps
        .iter()
        .filter(|connector| !allowed.contains(connector.as_str()))
        .collect::<Vec<_>>();
    if !unexpected.is_empty() {
        return Err(format!(
            "new coverage scanner gaps: {unexpected:?}; allowed gaps: {ALLOWED_COVERAGE_SCANNER_GAPS:?}"
        ));
    }
    if gaps.len() > MAX_COVERAGE_SCANNER_GAPS {
        return Err(format!(
            "coverage scanner gap count grew from {MAX_COVERAGE_SCANNER_GAPS} to {}: {gaps:?}",
            gaps.len()
        ));
    }
    Ok(())
}

fn assert_feature_universe_surface_floors(
    counts: &BTreeMap<&'static str, usize>,
) -> Result<(), String> {
    require_surface_at_least(counts, "readme_feature_status", MIN_README_FEATURE_ROWS)?;
    require_surface_at_least(counts, "formal_coverage_matrix", MIN_FORMAL_COVERAGE_ROWS)?;
    require_surface_at_least(counts, "fwc_schema_file", MIN_FWC_SCHEMA_FILES)?;
    require_surface_at_least(counts, "fwc_schema_case", MIN_FWC_SCHEMA_CASES)?;
    require_surface_at_least(counts, "fwc_top_level_command", MIN_FWC_TOP_LEVEL_COMMANDS)?;
    require_surface_at_least(
        counts,
        "fwc_top_level_command_name",
        MIN_FWC_TOP_LEVEL_COMMAND_NAMES,
    )?;
    require_surface_at_least(
        counts,
        "fwc_top_level_command_alias",
        MIN_FWC_TOP_LEVEL_COMMAND_ALIASES,
    )?;
    require_surface_at_least(
        counts,
        "fwc_nested_subcommand_variant",
        MIN_FWC_NESTED_SUBCOMMAND_VARIANTS,
    )?;
    require_surface_at_least(
        counts,
        "fwc_nested_subcommand_name",
        MIN_FWC_NESTED_SUBCOMMAND_NAMES,
    )?;
    require_surface_at_least(
        counts,
        "fwc_nested_subcommand_alias",
        MIN_FWC_NESTED_SUBCOMMAND_ALIASES,
    )?;
    require_surface_at_least(
        counts,
        "fwc_json_output_contract",
        MIN_FWC_JSON_OUTPUT_CONTRACTS,
    )?;
    require_surface_at_least(
        counts,
        "fwc_json_schema_version_contract",
        MIN_FWC_JSON_SCHEMA_VERSION_CONTRACTS,
    )?;
    require_surface_at_least(
        counts,
        "fwc_json_schema_case_contract",
        MIN_FWC_JSON_SCHEMA_CASE_CONTRACTS,
    )?;
    require_surface_at_least(
        counts,
        "fwc_json_output_field_assertion_contract",
        MIN_FWC_JSON_OUTPUT_FIELD_ASSERTION_CONTRACTS,
    )?;
    require_surface_at_least(
        counts,
        "fwc_json_output_no_schema_decision_contract",
        MIN_FWC_JSON_OUTPUT_NO_SCHEMA_DECISION_CONTRACTS,
    )?;
    require_surface_at_least(
        counts,
        "fwc_json_output_ownership",
        MIN_FWC_JSON_OUTPUT_OWNERSHIP_CLASSIFICATIONS,
    )?;
    require_surface_at_least(
        counts,
        "fwc_schema_case_parse_contract",
        MIN_FWC_SCHEMA_CASE_PARSE_CONTRACTS,
    )?;
    require_surface_at_least(
        counts,
        "fwc_schema_case_runtime_contract",
        MIN_FWC_SCHEMA_CASE_RUNTIME_CONTRACTS,
    )?;
    require_surface_at_least(
        counts,
        "graduation_gauntlet_check",
        MIN_GRADUATION_GAUNTLET_CHECKS,
    )?;
    require_surface_at_least(
        counts,
        "coverage_scanner_connector",
        MIN_COVERAGE_SCANNER_CONNECTORS,
    )?;
    require_surface_at_least(
        counts,
        "connector_manifest_operation",
        MIN_CONNECTOR_MANIFEST_OPERATIONS,
    )?;
    require_surface_at_least(
        counts,
        "connector_readme_operation_inventory",
        MIN_CONNECTOR_MANIFESTS,
    )?;
    require_surface_at_least(
        counts,
        "connector_readme_operation",
        MIN_CONNECTOR_README_OPERATIONS,
    )
}

fn fwc_schema_case_parse_contract_gaps(rows: &[FeatureUniverseRow]) -> Vec<String> {
    rows.iter()
        .filter(|row| {
            row.surface == "fwc_schema_case_parse_contract"
                && row.proof_status == "missing_direct_execute_json_contract"
        })
        .map(|row| row.item_id.clone())
        .collect()
}

fn assert_fwc_schema_case_parse_contract_gaps_do_not_grow(gaps: &[String]) -> Result<(), String> {
    let allowed = ALLOWED_FWC_SCHEMA_CASE_DIRECT_PARSE_GAPS
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let unexpected = gaps
        .iter()
        .filter(|gap| !allowed.contains(gap.as_str()))
        .collect::<Vec<_>>();
    if !unexpected.is_empty() {
        return Err(format!(
            "new fwc schema cases without direct execute_json parse contracts: {unexpected:?}; allowed gaps: {ALLOWED_FWC_SCHEMA_CASE_DIRECT_PARSE_GAPS:?}"
        ));
    }
    if gaps.len() > MAX_FWC_SCHEMA_CASES_MISSING_DIRECT_PARSE_CONTRACT {
        return Err(format!(
            "fwc schema case direct parse-contract gap count grew from {MAX_FWC_SCHEMA_CASES_MISSING_DIRECT_PARSE_CONTRACT} to {}: {gaps:?}",
            gaps.len()
        ));
    }
    Ok(())
}

fn fwc_schema_case_runtime_contract_item_ids(rows: &[FeatureUniverseRow]) -> BTreeSet<String> {
    rows.iter()
        .filter(|row| row.surface == "fwc_schema_case_runtime_contract")
        .map(|row| row.item_id.clone())
        .collect()
}

fn assert_fwc_schema_case_direct_gaps_have_runtime_contracts(
    rows: &[FeatureUniverseRow],
    gaps: &[String],
) -> Result<(), String> {
    let runtime_contracts = fwc_schema_case_runtime_contract_item_ids(rows);
    let missing = gaps
        .iter()
        .filter(|gap| !runtime_contracts.contains(*gap))
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(format!(
            "fwc schema cases without direct execute_json parse contracts also lack runtime schema-version contract ownership: {missing:?}"
        ));
    }
    Ok(())
}

fn fwc_json_output_contracts_with_status(
    rows: &[FeatureUniverseRow],
    proof_status: &str,
) -> Vec<String> {
    rows.iter()
        .filter(|row| {
            row.surface == "fwc_json_output_ownership" && row.proof_status == proof_status
        })
        .map(|row| row.item_id.clone())
        .collect()
}

fn fwc_json_output_parse_only_contracts(rows: &[FeatureUniverseRow]) -> Vec<String> {
    fwc_json_output_contracts_with_status(rows, "parse_contract_only")
}

fn redaction_safe_output_contract_token(token: &str) -> String {
    let lower = token.to_ascii_lowercase();
    if lower.contains("://")
        || lower.contains("authorization=")
        || lower.contains("bearer")
        || lower.contains("password")
        || lower.contains("passwd")
        || lower.contains("secret")
        || lower.contains("api_key=")
        || lower.starts_with('{')
        || lower.starts_with('[')
    {
        "<redacted>".to_owned()
    } else {
        token.to_owned()
    }
}

fn redaction_safe_output_contract_ids(item_ids: &[String]) -> Vec<String> {
    item_ids
        .iter()
        .map(|item_id| {
            item_id
                .split_whitespace()
                .map(redaction_safe_output_contract_token)
                .collect::<Vec<_>>()
                .join(" ")
        })
        .collect()
}

fn assert_fwc_json_output_parse_only_contracts_do_not_grow(
    rows: &[FeatureUniverseRow],
) -> Result<(), String> {
    let parse_only = fwc_json_output_parse_only_contracts(rows);
    if parse_only.len() > MAX_FWC_JSON_OUTPUT_PARSE_ONLY_CONTRACTS {
        return Err(format!(
            "fwc JSON output parse-only ownership count grew above baseline {MAX_FWC_JSON_OUTPUT_PARSE_ONLY_CONTRACTS}: {} parse-only rows; first 50: {:?}",
            parse_only.len(),
            parse_only.iter().take(50).collect::<Vec<_>>()
        ));
    }
    Ok(())
}

#[derive(Debug)]
struct ConnectorOperationParity {
    matched_count: usize,
    manifest_missing_from_readme: Vec<String>,
    readme_missing_from_manifest: Vec<String>,
}

fn connector_operation_prefixes(connector: &str) -> BTreeSet<String> {
    [
        connector.to_owned(),
        connector.replace('-', "_"),
        connector.replace('-', "."),
    ]
    .into_iter()
    .filter(|prefix| !prefix.is_empty())
    .collect()
}

fn strip_connector_operation_prefix(connector: &str, operation_id: &str) -> Option<String> {
    connector_operation_prefixes(connector)
        .into_iter()
        .find_map(|prefix| {
            operation_id
                .strip_prefix(&prefix)
                .and_then(|rest| rest.strip_prefix('.'))
                .filter(|rest| !rest.is_empty())
                .map(ToOwned::to_owned)
        })
}

fn connector_operation_matches(connector: &str, left: &str, right: &str) -> bool {
    left == right
        || strip_connector_operation_prefix(connector, left)
            .is_some_and(|stripped| stripped == right)
        || strip_connector_operation_prefix(connector, right)
            .is_some_and(|stripped| stripped == left)
}

fn operation_rows_by_connector(
    rows: &[FeatureUniverseRow],
    surface: &'static str,
) -> BTreeMap<String, BTreeSet<String>> {
    let mut operations = BTreeMap::<String, BTreeSet<String>>::new();
    for row in rows.iter().filter(|row| row.surface == surface) {
        if let Some((connector, operation_id)) = row.item_id.split_once(':') {
            operations
                .entry(connector.to_owned())
                .or_default()
                .insert(operation_id.to_owned());
        }
    }
    operations
}

fn connector_operation_parity(rows: &[FeatureUniverseRow]) -> ConnectorOperationParity {
    let manifest_operations = operation_rows_by_connector(rows, "connector_manifest_operation");
    let readme_operations = operation_rows_by_connector(rows, "connector_readme_operation");
    let mut matched_count = 0;
    let mut manifest_missing_from_readme = Vec::new();
    let mut readme_missing_from_manifest = Vec::new();

    for (connector, manifest_ids) in &manifest_operations {
        let Some(readme_ids) = readme_operations.get(connector) else {
            manifest_missing_from_readme.extend(
                manifest_ids
                    .iter()
                    .map(|operation_id| format!("{connector}:{operation_id}")),
            );
            continue;
        };
        for manifest_id in manifest_ids {
            if readme_ids
                .iter()
                .any(|readme_id| connector_operation_matches(connector, manifest_id, readme_id))
            {
                matched_count += 1;
            } else {
                manifest_missing_from_readme.push(format!("{connector}:{manifest_id}"));
            }
        }
    }

    for (connector, readme_ids) in &readme_operations {
        let Some(manifest_ids) = manifest_operations.get(connector) else {
            readme_missing_from_manifest.extend(
                readme_ids
                    .iter()
                    .map(|operation_id| format!("{connector}:{operation_id}")),
            );
            continue;
        };
        for readme_id in readme_ids {
            if !manifest_ids
                .iter()
                .any(|manifest_id| connector_operation_matches(connector, manifest_id, readme_id))
            {
                readme_missing_from_manifest.push(format!("{connector}:{readme_id}"));
            }
        }
    }

    ConnectorOperationParity {
        matched_count,
        manifest_missing_from_readme,
        readme_missing_from_manifest,
    }
}

fn assert_connector_operation_parity_does_not_regress(
    parity: &ConnectorOperationParity,
) -> Result<(), String> {
    if parity.matched_count < MIN_CONNECTOR_MANIFEST_README_MATCHED_OPERATIONS {
        return Err(format!(
            "connector manifest/README matched operation count shrank below baseline {MIN_CONNECTOR_MANIFEST_README_MATCHED_OPERATIONS}: {}",
            parity.matched_count
        ));
    }
    if parity.manifest_missing_from_readme.len()
        > MAX_CONNECTOR_MANIFEST_OPERATIONS_MISSING_FROM_README
    {
        return Err(format!(
            "connector manifest operations missing from README grew above baseline {MAX_CONNECTOR_MANIFEST_OPERATIONS_MISSING_FROM_README}: {} missing; first 50: {:?}",
            parity.manifest_missing_from_readme.len(),
            parity
                .manifest_missing_from_readme
                .iter()
                .take(50)
                .collect::<Vec<_>>()
        ));
    }
    if parity.readme_missing_from_manifest.len()
        > MAX_CONNECTOR_README_OPERATIONS_MISSING_FROM_MANIFEST
    {
        return Err(format!(
            "connector README operations missing from manifest grew above baseline {MAX_CONNECTOR_README_OPERATIONS_MISSING_FROM_MANIFEST}: {} missing; first 50: {:?}",
            parity.readme_missing_from_manifest.len(),
            parity
                .readme_missing_from_manifest
                .iter()
                .take(50)
                .collect::<Vec<_>>()
        ));
    }
    Ok(())
}

#[test]
fn fwc_top_level_command_parser_extracts_names_and_aliases() -> Result<(), String> {
    let commands = fwc_top_level_commands(
        r#"
enum Commands {
    #[command(visible_alias = "contract")]
    Guide(GuideArgs),

    #[command(name = "agent-readiness", visible_alias = "readiness-handoff")]
    AgentReadiness(AgentReadinessArgs),

    List(ListArgs),
}
"#,
    )?;

    assert_eq!(
        commands,
        vec![
            FwcTopLevelCommand {
                variant: "Guide".to_owned(),
                cli_name: "guide".to_owned(),
                aliases: BTreeSet::from(["contract".to_owned()]),
            },
            FwcTopLevelCommand {
                variant: "AgentReadiness".to_owned(),
                cli_name: "agent-readiness".to_owned(),
                aliases: BTreeSet::from(["readiness-handoff".to_owned()]),
            },
            FwcTopLevelCommand {
                variant: "List".to_owned(),
                cli_name: "list".to_owned(),
                aliases: BTreeSet::new(),
            },
        ]
    );
    Ok(())
}

#[test]
fn command_attribute_parser_does_not_confuse_alias_with_visible_alias() {
    let attr = r#"#[command(name = "agent-readiness", visible_alias = "readiness-handoff", visible_aliases = ["handoff", "ready"])]"#;

    assert_eq!(
        command_attribute_string_values(attr, "name"),
        vec!["agent-readiness".to_owned()]
    );
    assert_eq!(
        command_attribute_string_values(attr, "visible_alias"),
        vec!["readiness-handoff".to_owned()]
    );
    assert_eq!(
        command_attribute_string_values(attr, "visible_aliases"),
        vec!["handoff".to_owned(), "ready".to_owned()]
    );
    assert_eq!(
        command_attribute_string_values(attr, "alias"),
        [] as [std::string::String; 0]
    );
}

#[test]
fn fwc_command_schema_case_parser_extracts_command_paths() -> Result<(), String> {
    let cases = fwc_command_schema_cases(
        r#"
const CASES: &[CommandSchemaCase] = &[
    CommandSchemaCase {
        file: "status.schema.json",
        command: "status",
        subcommand: None,
        command_required_on_success: true,
        success_schema_version: "fcp.fwc.truth-source.v1",
        error_schema_version: "fcp.fwc.truth-source.v1",
    },
    CommandSchemaCase {
        file: "audit_chain_status.schema.json",
        command: "audit",
        subcommand: Some("chain status"),
        command_required_on_success: true,
        success_schema_version: "fcp.fwc.audit_chain_status.v1",
        error_schema_version: "fcp.fwc.truth-source.v1",
    },
];
"#,
    )?;

    assert_eq!(
        cases,
        vec![
            FwcSchemaCase {
                schema_file: "status.schema.json".to_owned(),
                command_path: vec!["status".to_owned()],
                success_schema_version: "fcp.fwc.truth-source.v1".to_owned(),
            },
            FwcSchemaCase {
                schema_file: "audit_chain_status.schema.json".to_owned(),
                command_path: vec!["audit".to_owned(), "chain".to_owned(), "status".to_owned(),],
                success_schema_version: "fcp.fwc.audit_chain_status.v1".to_owned(),
            },
        ]
    );
    Ok(())
}

#[test]
fn fwc_runtime_schema_contract_parser_extracts_cli_schema_assertions() -> Result<(), String> {
    let contracts = fwc_runtime_schema_contracts_in_source(
        "crates/fwc/tests/audit_chain_status_shape.rs",
        r#"
#[test]
fn audit_verify_json_reports_offline_truth_source() {
    let output = run_fwc(&[
        "audit",
        "verify",
        "--events",
        events_path.to_str().expect("events path UTF-8"),
        "--json",
    ]);

    let payload = stdout_json(&output);
    assert_eq!(payload["schema_version"], "fcp.fwc.audit_verify.v1");
}
"#,
    )?;

    assert_eq!(
        contracts,
        vec![FwcRuntimeSchemaContract {
            owner_file: "crates/fwc/tests/audit_chain_status_shape.rs".to_owned(),
            test_name: "audit_verify_json_reports_offline_truth_source".to_owned(),
            line_number: 5,
            normalized_args: vec![
                "audit".to_owned(),
                "verify".to_owned(),
                "--events".to_owned(),
                "<expr>".to_owned(),
                "--json".to_owned(),
            ],
            schema_version: "fcp.fwc.audit_verify.v1".to_owned(),
        }]
    );
    Ok(())
}

#[test]
fn fwc_subcommand_parser_extracts_nested_names_and_aliases() -> Result<(), String> {
    let variants = fwc_subcommand_variants_in_source(
        r#"
#[derive(Subcommand, Debug, Serialize)]
#[serde(tag = "subcommand", content = "args", rename_all = "kebab-case")]
enum ProofCommand {
    Graph(ProofGraphArgs),

    #[command(name = "rch-status", visible_aliases = ["worker-status", "capacity"])]
    RchStatus(ProofRchStatusArgs),

    #[command(name = "dry-run", visible_alias = "preview")]
    DryRun(ProofDryRunArgs),
}
"#,
    )?;

    assert_eq!(
        variants,
        vec![
            FwcSubcommandVariant {
                enum_name: "ProofCommand".to_owned(),
                variant: "Graph".to_owned(),
                cli_name: "graph".to_owned(),
                aliases: BTreeSet::new(),
            },
            FwcSubcommandVariant {
                enum_name: "ProofCommand".to_owned(),
                variant: "RchStatus".to_owned(),
                cli_name: "rch-status".to_owned(),
                aliases: BTreeSet::from(["capacity".to_owned(), "worker-status".to_owned()]),
            },
            FwcSubcommandVariant {
                enum_name: "ProofCommand".to_owned(),
                variant: "DryRun".to_owned(),
                cli_name: "dry-run".to_owned(),
                aliases: BTreeSet::from(["preview".to_owned()]),
            },
        ]
    );
    Ok(())
}

#[test]
fn fwc_json_output_contract_parser_extracts_static_arrays() -> Result<(), String> {
    let contracts = fwc_json_output_contracts(
        r#"
#[test]
fn output_shapes() {
    let (_, first) = execute_json(&["fwc", "--json", "mesh", "status"]);
    let (_, second) = execute_json(&[
        "fwc",
        "--json",
        "--host",
        &host,
        "show",
        "github",
    ]);
    let dynamic = execute_json(&["fwc", "--json", "recipe", "estimate", slug]);
}
"#,
    )?;

    assert_eq!(
        contracts,
        vec![
            FwcJsonOutputContract {
                line_number: 5,
                normalized_args: vec![
                    "fwc".to_owned(),
                    "--json".to_owned(),
                    "mesh".to_owned(),
                    "status".to_owned(),
                ],
            },
            FwcJsonOutputContract {
                line_number: 6,
                normalized_args: vec![
                    "fwc".to_owned(),
                    "--json".to_owned(),
                    "--host".to_owned(),
                    "<expr>".to_owned(),
                    "show".to_owned(),
                    "github".to_owned(),
                ],
            },
            FwcJsonOutputContract {
                line_number: 14,
                normalized_args: vec![
                    "fwc".to_owned(),
                    "--json".to_owned(),
                    "recipe".to_owned(),
                    "estimate".to_owned(),
                    "<expr>".to_owned(),
                ],
            },
        ]
    );
    Ok(())
}

#[test]
fn fwc_json_schema_version_contract_parser_extracts_test_owned_versions() -> Result<(), String> {
    let contracts = fwc_json_schema_version_contracts_in_source(
        "crates/fwc/src/main.rs",
        r#"
#[test]
fn mesh_status_json_reports_schema() {
    let (exit_code, payload) = execute_json(&[
        "fwc",
        "--json",
        "mesh",
        "status",
    ]);
    assert_eq!(exit_code, CliExitCode::Success.into());
    assert_eq!(payload["schema_version"], TRUTH_SOURCE_SCHEMA_VERSION);
}

#[test]
fn mesh_cutover_gates_json_reports_literal_schema() {
    let (first_exit, first) = execute_json(&["fwc", "--json", "mesh", "cutover-gates"]);
    let (second_exit, second) = execute_json(&["fwc", "--json", "mesh", "cutover-gates"]);
    assert_eq!(first_exit, std::process::ExitCode::SUCCESS);
    assert_eq!(second_exit, std::process::ExitCode::SUCCESS);
    assert_eq!(first["schema_version"], "1.2.0");
    assert_eq!(first["data_hash"], second["data_hash"]);
}
"#,
    )?;

    assert_eq!(
        contracts,
        vec![
            FwcJsonSchemaVersionContract {
                test_name: "mesh_status_json_reports_schema".to_owned(),
                line_number: 5,
                normalized_args: vec![
                    "fwc".to_owned(),
                    "--json".to_owned(),
                    "mesh".to_owned(),
                    "status".to_owned(),
                ],
                schema_version: "TRUTH_SOURCE_SCHEMA_VERSION".to_owned(),
            },
            FwcJsonSchemaVersionContract {
                test_name: "mesh_cutover_gates_json_reports_literal_schema".to_owned(),
                line_number: 17,
                normalized_args: vec![
                    "fwc".to_owned(),
                    "--json".to_owned(),
                    "mesh".to_owned(),
                    "cutover-gates".to_owned(),
                ],
                schema_version: "1.2.0".to_owned(),
            },
            FwcJsonSchemaVersionContract {
                test_name: "mesh_cutover_gates_json_reports_literal_schema".to_owned(),
                line_number: 18,
                normalized_args: vec![
                    "fwc".to_owned(),
                    "--json".to_owned(),
                    "mesh".to_owned(),
                    "cutover-gates".to_owned(),
                ],
                schema_version: "1.2.0".to_owned(),
            },
        ]
    );
    Ok(())
}

#[test]
fn json_field_assertion_contract_parser_tracks_bound_payload_variables() -> Result<(), String> {
    let contracts = fwc_json_field_assertion_contracts_in_source(
        "crates/fwc/src/main.rs",
        r#"
#[test]
fn mesh_status_json_asserts_payload_fields() {
    let (exit_code, payload) = execute_json(&["fwc", "--json", "mesh", "status"]);
    assert_eq!(exit_code, CliExitCode::Success.into());
    assert_eq!(payload["status"], "ok");
    assert!(payload.get("summary").is_some());
}

#[test]
fn guide_json_only_parses_payload() {
    let (_exit_code, _payload) = execute_json(&["fwc", "--json", "guide"]);
}
"#,
    )?;

    assert_eq!(
        contracts,
        vec![FwcJsonFieldAssertionContract {
            test_name: "mesh_status_json_asserts_payload_fields".to_owned(),
            line_number: 5,
            normalized_args: vec![
                "fwc".to_owned(),
                "--json".to_owned(),
                "mesh".to_owned(),
                "status".to_owned(),
            ],
            payload_variable: "payload".to_owned(),
            assertion_count: 2,
        }]
    );
    Ok(())
}

#[test]
fn json_no_schema_decision_contract_parser_tracks_explicit_absence() -> Result<(), String> {
    let contracts = fwc_json_no_schema_decision_contracts_in_source(
        "crates/fwc/src/main.rs",
        r#"
#[test]
fn malformed_config_has_no_schema_version() {
    let (exit_code, payload) = execute_json(&["fwc", "--json", "mesh", "cutover-gates"]);
    assert_eq!(exit_code, CliExitCode::Validation.into());
    assert!(payload.get("schema_version").is_none());
}

#[test]
fn normal_schema_assertion_is_not_no_schema() {
    let (_exit_code, payload) = execute_json(&["fwc", "--json", "mesh", "status"]);
    assert_eq!(payload["schema_version"], TRUTH_SOURCE_SCHEMA_VERSION);
}
"#,
    )?;

    assert_eq!(
        contracts,
        vec![FwcJsonNoSchemaDecisionContract {
            test_name: "malformed_config_has_no_schema_version".to_owned(),
            line_number: 5,
            normalized_args: vec![
                "fwc".to_owned(),
                "--json".to_owned(),
                "mesh".to_owned(),
                "cutover-gates".to_owned(),
            ],
            payload_variable: "payload".to_owned(),
            decision_count: 1,
        }]
    );
    Ok(())
}

#[test]
fn schema_case_parse_contract_matching_uses_normalized_command_prefixes() {
    let schema_case = FwcSchemaCase {
        schema_file: "mesh_explain_availability.schema.json".to_owned(),
        command_path: vec!["mesh".to_owned(), "explain-availability".to_owned()],
        success_schema_version: "fcp.fwc.mesh_explain_availability.v1".to_owned(),
    };
    let contracts = vec![
        FwcJsonOutputContract {
            line_number: 10,
            normalized_args: vec![
                "fwc".to_owned(),
                "--json".to_owned(),
                "--host".to_owned(),
                "<expr>".to_owned(),
                "mesh".to_owned(),
                "explain-availability".to_owned(),
                "github".to_owned(),
            ],
        },
        FwcJsonOutputContract {
            line_number: 20,
            normalized_args: vec![
                "fwc".to_owned(),
                "--json".to_owned(),
                "audit".to_owned(),
                "matrix".to_owned(),
            ],
        },
    ];

    assert_eq!(
        normalized_command_tokens(&contracts[0].normalized_args),
        vec![
            "mesh".to_owned(),
            "explain-availability".to_owned(),
            "github".to_owned(),
        ]
    );
    assert!(schema_case_has_parse_contract(&schema_case, &contracts));
}

#[test]
fn json_schema_case_contract_matching_uses_longest_command_prefix() {
    let schema_cases = vec![
        FwcSchemaCase {
            schema_file: "mesh.schema.json".to_owned(),
            command_path: vec!["mesh".to_owned()],
            success_schema_version: "fcp.fwc.truth-source.v1".to_owned(),
        },
        FwcSchemaCase {
            schema_file: "mesh_explain_availability.schema.json".to_owned(),
            command_path: vec!["mesh".to_owned(), "explain-availability".to_owned()],
            success_schema_version: "fcp.fwc.truth-source.v1".to_owned(),
        },
    ];
    let contract = FwcJsonOutputContract {
        line_number: 15,
        normalized_args: vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "--host".to_owned(),
            "<expr>".to_owned(),
            "mesh".to_owned(),
            "explain-availability".to_owned(),
            "github".to_owned(),
        ],
    };

    assert_eq!(
        schema_case_for_contract(&contract, &schema_cases),
        Some(&schema_cases[1])
    );
}

#[test]
fn json_output_ownership_status_tracks_union_categories() {
    let schema_cases = vec![FwcSchemaCase {
        schema_file: "mesh_explain_availability.schema.json".to_owned(),
        command_path: vec!["mesh".to_owned(), "explain-availability".to_owned()],
        success_schema_version: "fcp.fwc.truth-source.v1".to_owned(),
    }];
    let schema_version_contracts = BTreeSet::from([(
        10,
        vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "mesh".to_owned(),
            "explain-availability".to_owned(),
        ],
    )]);
    let field_assertion_contracts = BTreeSet::from([(
        30,
        vec!["fwc".to_owned(), "--json".to_owned(), "unknown".to_owned()],
    )]);
    let no_schema_decision_contracts = BTreeSet::new();

    let schema_version_and_case = FwcJsonOutputContract {
        line_number: 10,
        normalized_args: vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "mesh".to_owned(),
            "explain-availability".to_owned(),
        ],
    };
    let schema_case_only = FwcJsonOutputContract {
        line_number: 20,
        normalized_args: vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "mesh".to_owned(),
            "explain-availability".to_owned(),
            "github".to_owned(),
        ],
    };
    let parse_only = FwcJsonOutputContract {
        line_number: 40,
        normalized_args: vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "no-assertion".to_owned(),
        ],
    };
    let field_assertions_only = FwcJsonOutputContract {
        line_number: 30,
        normalized_args: vec!["fwc".to_owned(), "--json".to_owned(), "unknown".to_owned()],
    };

    assert_eq!(
        fwc_json_output_ownership_status(
            &schema_version_and_case,
            &schema_cases,
            &schema_version_contracts,
            &field_assertion_contracts,
            &no_schema_decision_contracts,
        ),
        "schema_version_and_schema_case_owner"
    );
    assert_eq!(
        fwc_json_output_ownership_status(
            &schema_case_only,
            &schema_cases,
            &schema_version_contracts,
            &field_assertion_contracts,
            &no_schema_decision_contracts,
        ),
        "schema_case_owner_available"
    );
    assert_eq!(
        fwc_json_output_ownership_status(
            &field_assertions_only,
            &schema_cases,
            &schema_version_contracts,
            &field_assertion_contracts,
            &no_schema_decision_contracts,
        ),
        "field_assertions_only_schema_decision_pending"
    );
    assert_eq!(
        fwc_json_output_ownership_status(
            &parse_only,
            &schema_cases,
            &schema_version_contracts,
            &field_assertion_contracts,
            &no_schema_decision_contracts,
        ),
        "parse_contract_only"
    );
}

#[test]
fn json_output_ownership_status_tracks_explicit_no_schema_decision() {
    let schema_cases = Vec::new();
    let schema_version_contracts = BTreeSet::new();
    let field_assertion_contracts = BTreeSet::new();
    let no_schema_decision_contracts = BTreeSet::from([(
        50,
        vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "validation-only".to_owned(),
        ],
    )]);
    let no_schema_decision = FwcJsonOutputContract {
        line_number: 50,
        normalized_args: vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "validation-only".to_owned(),
        ],
    };

    assert_eq!(
        fwc_json_output_ownership_status(
            &no_schema_decision,
            &schema_cases,
            &schema_version_contracts,
            &field_assertion_contracts,
            &no_schema_decision_contracts,
        ),
        "explicit_no_schema_decision"
    );
}

#[test]
fn schema_case_runtime_contract_matching_uses_schema_version_and_command_prefix() {
    let schema_case = FwcSchemaCase {
        schema_file: "audit_verify.schema.json".to_owned(),
        command_path: vec!["audit".to_owned(), "verify".to_owned()],
        success_schema_version: "fcp.fwc.audit_verify.v1".to_owned(),
    };
    let contracts = vec![
        FwcRuntimeSchemaContract {
            owner_file: "crates/fwc/tests/audit_chain_status_shape.rs".to_owned(),
            test_name: "audit_verify_json_reports_offline_truth_source".to_owned(),
            line_number: 480,
            normalized_args: vec![
                "audit".to_owned(),
                "verify".to_owned(),
                "--events".to_owned(),
                "<expr>".to_owned(),
                "--json".to_owned(),
            ],
            schema_version: "fcp.fwc.audit_verify.v1".to_owned(),
        },
        FwcRuntimeSchemaContract {
            owner_file: "crates/fwc/tests/audit_chain_status_shape.rs".to_owned(),
            test_name: "audit_verify_error_reports_truth_source_schema".to_owned(),
            line_number: 530,
            normalized_args: vec!["audit".to_owned(), "verify".to_owned(), "--json".to_owned()],
            schema_version: "fcp.fwc.truth-source.v1".to_owned(),
        },
    ];

    assert_eq!(
        schema_case_runtime_contract(&schema_case, &contracts),
        Some(&contracts[0])
    );
}

#[test]
fn graduation_gauntlet_check_parser_extracts_ids_and_exit_codes() -> Result<(), String> {
    let checks = graduation_gauntlet_checks(
        r#"
GRADUATION_CHECKS=(
  "connector_path|1|connector argument resolves to a directory"
  "operator_guidance|12|README includes operator guidance and rerun commands"
)
"#,
    )?;

    assert_eq!(
        checks,
        vec![
            GraduationGauntletCheck {
                id: "connector_path".to_owned(),
                exit_code: 1,
            },
            GraduationGauntletCheck {
                id: "operator_guidance".to_owned(),
                exit_code: 12,
            },
        ]
    );
    Ok(())
}

#[test]
fn feature_universe_inventory_rows_are_joined_and_ratcheted() -> Result<(), String> {
    let root = workspace_root()?;
    let rows = all_inventory_rows(&root)?;
    let counts = count_by_surface(&rows);
    let operation_parity = connector_operation_parity(&rows);
    let coverage_scanner_gaps = coverage_scanner_gap_connectors(&rows);
    let fwc_schema_case_parse_contract_gaps = fwc_schema_case_parse_contract_gaps(&rows);
    let fwc_json_parse_only_contracts = fwc_json_output_parse_only_contracts(&rows);
    let fwc_json_field_assertion_pending_contracts = fwc_json_output_contracts_with_status(
        &rows,
        "field_assertions_only_schema_decision_pending",
    );
    let fwc_json_parse_only_contract_samples =
        redaction_safe_output_contract_ids(&fwc_json_parse_only_contracts);
    let fwc_json_field_assertion_pending_contract_samples =
        redaction_safe_output_contract_ids(&fwc_json_field_assertion_pending_contracts);

    println!(
        "{}",
        serde_json::json!({
            "event": "feature_universe_inventory_summary",
            "surface_counts": counts,
            "coverage_scanner": {
                "gap_count": coverage_scanner_gaps.len(),
                "gaps": &coverage_scanner_gaps,
            },
            "fwc_schema_case_parse_contract": {
                "gap_count": fwc_schema_case_parse_contract_gaps.len(),
                "gaps": &fwc_schema_case_parse_contract_gaps,
            },
            "fwc_schema_case_runtime_contract": {
                "covered_direct_gap_count": fwc_schema_case_parse_contract_gaps
                    .iter()
                    .filter(|gap| fwc_schema_case_runtime_contract_item_ids(&rows).contains(*gap))
                    .count(),
            },
            "fwc_json_schema_version_contract": {
                "contract_count": counts
                    .get("fwc_json_schema_version_contract")
                    .copied()
                    .unwrap_or_default(),
            },
            "fwc_json_schema_case_contract": {
                "contract_count": counts
                    .get("fwc_json_schema_case_contract")
                    .copied()
                    .unwrap_or_default(),
            },
            "fwc_json_output_field_assertion_contract": {
                "contract_count": counts
                    .get("fwc_json_output_field_assertion_contract")
                    .copied()
                    .unwrap_or_default(),
            },
            "fwc_json_output_no_schema_decision_contract": {
                "contract_count": counts
                    .get("fwc_json_output_no_schema_decision_contract")
                    .copied()
                    .unwrap_or_default(),
            },
            "fwc_json_output_ownership": {
                "contract_count": counts
                    .get("fwc_json_output_ownership")
                    .copied()
                    .unwrap_or_default(),
                "status_counts": proof_status_counts(&rows, "fwc_json_output_ownership"),
                "parse_only_count": fwc_json_parse_only_contracts.len(),
                "parse_only_first_25": fwc_json_parse_only_contract_samples.iter().take(25).collect::<Vec<_>>(),
                "field_assertions_only_schema_decision_pending_count": fwc_json_field_assertion_pending_contracts.len(),
                "field_assertions_only_schema_decision_pending_first_25": fwc_json_field_assertion_pending_contract_samples.iter().take(25).collect::<Vec<_>>(),
            },
            "connector_operation_parity": {
                "matched_count": operation_parity.matched_count,
                "manifest_missing_from_readme_count": operation_parity.manifest_missing_from_readme.len(),
                "manifest_missing_from_readme_first_25": operation_parity.manifest_missing_from_readme.iter().take(25).collect::<Vec<_>>(),
                "readme_missing_from_manifest_count": operation_parity.readme_missing_from_manifest.len(),
                "readme_missing_from_manifest_first_25": operation_parity.readme_missing_from_manifest.iter().take(25).collect::<Vec<_>>(),
            },
            "redaction_decision": "repository-relative paths, connector names, schema names, command variants, operation ids, and redacted output-contract sample tokens only; no credentials, payloads, prompts, transcripts, or PII read",
        })
    );

    assert_feature_universe_surface_floors(&counts)?;

    assert_no_duplicate_rows(&rows)?;
    assert_rows_have_verifier_owners(&rows)?;
    assert_no_unreferenced_fwc_schema(&rows)?;
    assert_connector_readme_operation_gaps_do_not_grow(&rows)?;
    assert_coverage_scanner_gaps_do_not_grow(&coverage_scanner_gaps)?;
    assert_fwc_schema_case_parse_contract_gaps_do_not_grow(&fwc_schema_case_parse_contract_gaps)?;
    assert_fwc_schema_case_direct_gaps_have_runtime_contracts(
        &rows,
        &fwc_schema_case_parse_contract_gaps,
    )?;
    assert_fwc_json_output_parse_only_contracts_do_not_grow(&rows)?;
    assert_connector_operation_parity_does_not_regress(&operation_parity)?;
    Ok(())
}
