//! Tabular output formatters: table, CSV, TSV, and Markdown.
//!
//! Transforms JSON arrays of objects into human-readable or pipe-friendly
//! tabular representations, with column selection, sorting, and row limiting.

use serde_json::Value;

/// Tabular output format.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TabularFormat {
    Table,
    Csv,
    Tsv,
    Markdown,
}

/// Options controlling tabular rendering.
#[derive(Clone, Debug, Default)]
pub struct TabularOptions {
    /// Explicit column list. If empty, auto-detect from data.
    pub columns: Vec<String>,
    /// Sort output by this column name.
    pub sort_by: Option<String>,
    /// Maximum rows to include (0 = unlimited).
    pub limit: usize,
    /// Suppress column headers.
    pub no_headers: bool,
}

/// Render a JSON value as a tabular string.
///
/// The value should be either:
/// - A JSON array of objects (rows)
/// - A JSON object with one array-of-objects field (auto-detected)
///
/// Returns the formatted string or an error message if the data is not tabular.
pub fn render_tabular(
    value: &Value,
    format: TabularFormat,
    options: &TabularOptions,
) -> Result<String, String> {
    let rows = extract_rows(value)?;

    if rows.is_empty() {
        return Ok(empty_result(format));
    }

    let columns = if options.columns.is_empty() {
        auto_detect_columns(&rows)
    } else {
        options.columns.clone()
    };

    if columns.is_empty() {
        return Ok(empty_result(format));
    }

    let mut row_values = extract_cell_values(&rows, &columns);

    // Sort if requested.
    if let Some(sort_col) = &options.sort_by {
        if let Some(col_idx) = columns.iter().position(|c| c == sort_col) {
            row_values.sort_by(|a, b| a[col_idx].cmp(&b[col_idx]));
        }
    }

    // Limit rows.
    if options.limit > 0 && row_values.len() > options.limit {
        row_values.truncate(options.limit);
    }

    let output = match format {
        TabularFormat::Table => render_ascii_table(&columns, &row_values, options.no_headers),
        TabularFormat::Csv => render_delimited(&columns, &row_values, ',', options.no_headers),
        TabularFormat::Tsv => render_delimited(&columns, &row_values, '\t', options.no_headers),
        TabularFormat::Markdown => render_markdown_table(&columns, &row_values, options.no_headers),
    };

    Ok(output)
}

/// Extract the row array from a JSON value.
fn extract_rows(value: &Value) -> Result<Vec<&Value>, String> {
    // Direct array of objects.
    if let Some(arr) = value.as_array() {
        return Ok(arr.iter().collect());
    }

    // Object with a single array field, or a well-known array field.
    if let Some(obj) = value.as_object() {
        // Look for common data array field names.
        for key in &[
            "items",
            "results",
            "data",
            "rows",
            "entries",
            "records",
            "connectors",
            "operations",
            "issues",
            "messages",
        ] {
            if let Some(arr) = obj.get(*key).and_then(Value::as_array) {
                return Ok(arr.iter().collect());
            }
        }

        // Fallback: find the first array-of-objects field.
        for (_key, val) in obj {
            if let Some(arr) = val.as_array() {
                if arr.first().is_some_and(Value::is_object) {
                    return Ok(arr.iter().collect());
                }
            }
        }
    }

    Err("data is not tabular: expected a JSON array of objects".to_string())
}

/// Auto-detect column names from the first row's keys, preserving insertion order.
fn auto_detect_columns(rows: &[&Value]) -> Vec<String> {
    let Some(first) = rows.first() else {
        return Vec::new();
    };
    let Some(obj) = first.as_object() else {
        return Vec::new();
    };

    obj.keys().cloned().collect()
}

/// Extract cell string values for each row × column.
fn extract_cell_values(rows: &[&Value], columns: &[String]) -> Vec<Vec<String>> {
    rows.iter()
        .map(|row| columns.iter().map(|col| cell_value(row, col)).collect())
        .collect()
}

/// Get a cell value from a row, supporting dot notation for nested fields.
fn cell_value(row: &Value, column: &str) -> String {
    let val = resolve_path(row, column);
    format_cell(val)
}

/// Resolve a dotted path like `"user.login"` into a nested JSON value.
fn resolve_path<'a>(value: &'a Value, path: &str) -> &'a Value {
    let mut current = value;
    for segment in path.split('.') {
        // Handle array index notation like `labels[0]`.
        if let Some((key, idx_str)) = segment.split_once('[') {
            current = current.get(key).unwrap_or(&Value::Null);
            if let Some(idx_str) = idx_str.strip_suffix(']') {
                if let Ok(idx) = idx_str.parse::<usize>() {
                    current = current.get(idx).unwrap_or(&Value::Null);
                }
            }
        } else {
            current = current.get(segment).unwrap_or(&Value::Null);
        }
    }
    current
}

/// Format a single cell value as a display string.
fn format_cell(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => s.clone(),
        Value::Array(arr) => {
            let items: Vec<String> = arr.iter().map(format_cell).collect();
            items.join(", ")
        }
        Value::Object(_) => serde_json::to_string(value).unwrap_or_default(),
    }
}

/// Render an ASCII-art table with aligned columns.
fn render_ascii_table(columns: &[String], rows: &[Vec<String>], no_headers: bool) -> String {
    // Calculate column widths.
    let mut widths: Vec<usize> = columns.iter().map(String::len).collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            if i < widths.len() {
                widths[i] = widths[i].max(cell.len());
            }
        }
    }

    let mut out = String::new();

    // Header.
    if !no_headers {
        let header: Vec<String> = columns
            .iter()
            .enumerate()
            .map(|(i, col)| format!("{:width$}", col, width = widths[i]))
            .collect();
        out.push_str(&header.join("  "));
        out.push('\n');

        // Separator.
        let sep: Vec<String> = widths.iter().map(|w| "-".repeat(*w)).collect();
        out.push_str(&sep.join("  "));
        out.push('\n');
    }

    // Rows.
    for row in rows {
        let cells: Vec<String> = row
            .iter()
            .enumerate()
            .map(|(i, cell)| {
                let w = widths.get(i).copied().unwrap_or(0);
                format!("{cell:w$}")
            })
            .collect();
        out.push_str(&cells.join("  "));
        out.push('\n');
    }

    out
}

/// Render a delimited format (CSV or TSV).
fn render_delimited(
    columns: &[String],
    rows: &[Vec<String>],
    delimiter: char,
    no_headers: bool,
) -> String {
    let mut out = String::new();

    if !no_headers {
        let header: Vec<String> = columns
            .iter()
            .map(|c| escape_delimited(c, delimiter))
            .collect();
        out.push_str(&header.join(&delimiter.to_string()));
        out.push('\n');
    }

    for row in rows {
        let cells: Vec<String> = row.iter().map(|c| escape_delimited(c, delimiter)).collect();
        out.push_str(&cells.join(&delimiter.to_string()));
        out.push('\n');
    }

    out
}

/// Escape a cell for delimited output (CSV quoting rules).
fn escape_delimited(value: &str, delimiter: char) -> String {
    let needs_quoting = match delimiter {
        ',' => {
            value.contains(',')
                || value.contains('"')
                || value.contains('\n')
                || value.contains('\r')
        }
        '\t' => value.contains('\t') || value.contains('\n') || value.contains('\r'),
        _ => false,
    };
    if needs_quoting {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

/// Render a Markdown table.
fn render_markdown_table(columns: &[String], rows: &[Vec<String>], no_headers: bool) -> String {
    let mut out = String::new();

    if !no_headers {
        // Header row.
        out.push_str("| ");
        out.push_str(&columns.join(" | "));
        out.push_str(" |\n");

        // Separator row.
        let seps: Vec<&str> = columns.iter().map(|_| "---").collect();
        out.push_str("| ");
        out.push_str(&seps.join(" | "));
        out.push_str(" |\n");
    }

    for row in rows {
        let cells: Vec<String> = row.iter().map(|c| escape_markdown_cell(c)).collect();
        out.push_str("| ");
        out.push_str(&cells.join(" | "));
        out.push_str(" |\n");
    }

    out
}

/// Escape pipe characters and line breaks in markdown table cells.
///
/// A literal newline inside a cell would split the row across lines and
/// corrupt the table, so line breaks are rendered as `<br>`.
fn escape_markdown_cell(value: &str) -> String {
    value
        .replace('|', "\\|")
        .replace("\r\n", "<br>")
        .replace(['\n', '\r'], "<br>")
}

/// Empty result string for tabular output.
fn empty_result(format: TabularFormat) -> String {
    match format {
        TabularFormat::Csv | TabularFormat::Tsv => String::new(),
        TabularFormat::Table | TabularFormat::Markdown => "(no rows)\n".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_issues() -> Value {
        json!([
            {"number": 1, "title": "Bug fix", "state": "open"},
            {"number": 2, "title": "Feature request", "state": "closed"},
            {"number": 3, "title": "Docs update", "state": "open"},
        ])
    }

    fn default_opts() -> TabularOptions {
        TabularOptions::default()
    }

    // ── Format tests ────────────────────────────────────────────────

    #[test]
    fn ascii_table_basic() {
        let result =
            render_tabular(&sample_issues(), TabularFormat::Table, &default_opts()).unwrap();
        assert!(result.contains("number"));
        assert!(result.contains("title"));
        assert!(result.contains("state"));
        assert!(result.contains("Bug fix"));
        assert!(result.contains("Feature request"));
        // Check separator line exists.
        assert!(result.contains("------"));
    }

    #[test]
    fn csv_basic() {
        let result = render_tabular(&sample_issues(), TabularFormat::Csv, &default_opts()).unwrap();
        let lines: Vec<&str> = result.lines().collect();
        assert_eq!(lines.len(), 4); // header + 3 rows
        assert!(lines[0].contains("number,"));
        assert!(lines[1].contains("1,"));
    }

    #[test]
    fn tsv_basic() {
        let result = render_tabular(&sample_issues(), TabularFormat::Tsv, &default_opts()).unwrap();
        let lines: Vec<&str> = result.lines().collect();
        assert_eq!(lines.len(), 4);
        assert!(lines[0].contains('\t'));
    }

    #[test]
    fn markdown_basic() {
        let result =
            render_tabular(&sample_issues(), TabularFormat::Markdown, &default_opts()).unwrap();
        assert!(result.contains("| number"));
        assert!(result.contains("| ---"));
        assert!(result.contains("| Bug fix"));
    }

    // ── Column selection ────────────────────────────────────────────

    #[test]
    fn explicit_columns() {
        let opts = TabularOptions {
            columns: vec!["number".into(), "state".into()],
            ..default_opts()
        };
        let result = render_tabular(&sample_issues(), TabularFormat::Csv, &opts).unwrap();
        let header = result.lines().next().unwrap();
        assert_eq!(header, "number,state");
    }

    #[test]
    fn no_headers_flag() {
        let opts = TabularOptions {
            no_headers: true,
            ..default_opts()
        };
        let result = render_tabular(&sample_issues(), TabularFormat::Csv, &opts).unwrap();
        let lines: Vec<&str> = result.lines().collect();
        assert_eq!(lines.len(), 3); // no header row
        assert!(lines[0].starts_with('1')); // first data row
    }

    // ── Sort and limit ──────────────────────────────────────────────

    #[test]
    fn sort_by_column() {
        let opts = TabularOptions {
            sort_by: Some("title".into()),
            ..default_opts()
        };
        let result = render_tabular(&sample_issues(), TabularFormat::Csv, &opts).unwrap();
        let lines: Vec<&str> = result.lines().collect();
        // Alphabetical: Bug fix, Docs update, Feature request
        assert!(lines[1].contains("Bug fix"));
        assert!(lines[2].contains("Docs update"));
        assert!(lines[3].contains("Feature request"));
    }

    #[test]
    fn limit_rows() {
        let opts = TabularOptions {
            limit: 2,
            ..default_opts()
        };
        let result = render_tabular(&sample_issues(), TabularFormat::Csv, &opts).unwrap();
        assert_eq!(result.lines().count(), 3); // header + 2 rows
    }

    // ── Nested object extraction ────────────────────────────────────

    #[test]
    fn nested_dot_notation() {
        let data = json!([
            {"user": {"login": "alice"}, "score": 10},
            {"user": {"login": "bob"}, "score": 20},
        ]);
        let opts = TabularOptions {
            columns: vec!["user.login".into(), "score".into()],
            ..default_opts()
        };
        let result = render_tabular(&data, TabularFormat::Table, &opts).unwrap();
        assert!(result.contains("alice"));
        assert!(result.contains("bob"));
    }

    #[test]
    fn array_index_notation() {
        let data = json!([
            {"labels": ["bug", "urgent"], "id": 1},
            {"labels": ["feature"], "id": 2},
        ]);
        let opts = TabularOptions {
            columns: vec!["labels[0]".into(), "id".into()],
            ..default_opts()
        };
        let result = render_tabular(&data, TabularFormat::Csv, &opts).unwrap();
        assert!(result.contains("bug"));
        assert!(result.contains("feature"));
    }

    // ── Object with data array ──────────────────────────────────────

    #[test]
    fn extract_from_wrapper_object() {
        let data = json!({
            "status": "ok",
            "connectors": [
                {"name": "github", "ops": 24},
                {"name": "slack", "ops": 12},
            ]
        });
        let result = render_tabular(&data, TabularFormat::Table, &default_opts()).unwrap();
        assert!(result.contains("github"));
        assert!(result.contains("slack"));
    }

    #[test]
    fn extract_from_items_field() {
        let data = json!({
            "total": 2,
            "items": [
                {"id": "a", "value": 1},
                {"id": "b", "value": 2},
            ]
        });
        let result = render_tabular(&data, TabularFormat::Csv, &default_opts()).unwrap();
        assert!(result.contains("id,value"));
    }

    // ── Edge cases ──────────────────────────────────────────────────

    #[test]
    fn empty_array() {
        let data = json!([]);
        let result = render_tabular(&data, TabularFormat::Table, &default_opts()).unwrap();
        assert!(result.contains("no rows"));
    }

    #[test]
    fn non_tabular_data_returns_error() {
        let data = json!("just a string");
        let result = render_tabular(&data, TabularFormat::Table, &default_opts());
        assert!(result.is_err());
    }

    #[test]
    fn null_values_render_as_empty() {
        let data = json!([
            {"name": "alice", "email": null},
            {"name": "bob", "email": "bob@test.com"},
        ]);
        let result = render_tabular(&data, TabularFormat::Csv, &default_opts()).unwrap();
        let lines: Vec<&str> = result.lines().collect();
        // alice's email should be empty
        assert!(lines[1].ends_with(','));
    }

    #[test]
    fn boolean_values_rendered() {
        let data = json!([{"active": true}, {"active": false}]);
        let result = render_tabular(&data, TabularFormat::Csv, &default_opts()).unwrap();
        assert!(result.contains("true"));
        assert!(result.contains("false"));
    }

    #[test]
    fn csv_escapes_commas() {
        let data = json!([{"title": "Hello, World", "id": 1}]);
        let result = render_tabular(&data, TabularFormat::Csv, &default_opts()).unwrap();
        assert!(result.contains("\"Hello, World\""));
    }

    #[test]
    fn csv_escapes_quotes() {
        let data = json!([{"title": "Say \"hello\"", "id": 1}]);
        let result = render_tabular(&data, TabularFormat::Csv, &default_opts()).unwrap();
        assert!(result.contains("\"\"hello\"\""));
    }

    #[test]
    fn markdown_escapes_pipes() {
        let data = json!([{"cmd": "a | b", "id": 1}]);
        let result = render_tabular(&data, TabularFormat::Markdown, &default_opts()).unwrap();
        assert!(result.contains("a \\| b"));
    }

    #[test]
    fn array_field_flattened() {
        let data = json!([
            {"tags": ["a", "b", "c"]},
        ]);
        let opts = TabularOptions {
            columns: vec!["tags".into()],
            ..default_opts()
        };
        let result = render_tabular(&data, TabularFormat::Table, &opts).unwrap();
        assert!(result.contains("a, b, c"));
    }

    #[test]
    fn missing_column_renders_empty() {
        let data = json!([
            {"name": "alice"},
            {"name": "bob"},
        ]);
        let opts = TabularOptions {
            columns: vec!["name".into(), "nonexistent".into()],
            ..default_opts()
        };
        let result = render_tabular(&data, TabularFormat::Table, &opts).unwrap();
        assert!(result.contains("alice"));
        assert!(result.contains("nonexistent")); // column header present
    }

    #[test]
    fn sort_and_limit_combined() {
        let opts = TabularOptions {
            sort_by: Some("title".into()),
            limit: 1,
            ..default_opts()
        };
        let result = render_tabular(&sample_issues(), TabularFormat::Csv, &opts).unwrap();
        let lines: Vec<&str> = result.lines().collect();
        assert_eq!(lines.len(), 2); // header + 1 row
        assert!(lines[1].contains("Bug fix")); // first alphabetically
    }

    #[test]
    fn deterministic_output() {
        let a = render_tabular(&sample_issues(), TabularFormat::Table, &default_opts()).unwrap();
        let b = render_tabular(&sample_issues(), TabularFormat::Table, &default_opts()).unwrap();
        assert_eq!(a, b);
    }

    // ── TabularFormat enum tests ────────────────────────────────────

    #[test]
    fn tabular_format_eq() {
        assert_eq!(TabularFormat::Table, TabularFormat::Table);
        assert_eq!(TabularFormat::Csv, TabularFormat::Csv);
        assert_eq!(TabularFormat::Tsv, TabularFormat::Tsv);
        assert_eq!(TabularFormat::Markdown, TabularFormat::Markdown);
    }

    #[test]
    fn tabular_format_ne() {
        assert_ne!(TabularFormat::Table, TabularFormat::Csv);
        assert_ne!(TabularFormat::Csv, TabularFormat::Tsv);
        assert_ne!(TabularFormat::Tsv, TabularFormat::Markdown);
    }

    #[test]
    fn tabular_format_copy() {
        let f = TabularFormat::Table;
        let g = f;
        assert_eq!(f, g);
    }

    // ── Empty result format tests ───────────────────────────────────

    #[test]
    fn empty_csv_is_blank() {
        let result = render_tabular(&json!([]), TabularFormat::Csv, &default_opts()).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn empty_tsv_is_blank() {
        let result = render_tabular(&json!([]), TabularFormat::Tsv, &default_opts()).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn empty_markdown_says_no_rows() {
        let result = render_tabular(&json!([]), TabularFormat::Markdown, &default_opts()).unwrap();
        assert!(result.contains("no rows"));
    }

    // ── No headers across all formats ───────────────────────────────

    #[test]
    fn no_headers_table() {
        let opts = TabularOptions {
            no_headers: true,
            ..default_opts()
        };
        let result = render_tabular(&sample_issues(), TabularFormat::Table, &opts).unwrap();
        assert!(!result.contains("number"));
        assert!(!result.contains("------"));
        assert!(result.contains("Bug fix"));
    }

    #[test]
    fn no_headers_tsv() {
        let opts = TabularOptions {
            no_headers: true,
            ..default_opts()
        };
        let result = render_tabular(&sample_issues(), TabularFormat::Tsv, &opts).unwrap();
        assert_eq!(result.lines().count(), 3);
    }

    #[test]
    fn no_headers_markdown() {
        let opts = TabularOptions {
            no_headers: true,
            ..default_opts()
        };
        let result = render_tabular(&sample_issues(), TabularFormat::Markdown, &opts).unwrap();
        assert!(!result.contains("---"));
        assert!(result.contains("Bug fix"));
    }

    // ── Wrapper object extraction ───────────────────────────────────

    #[test]
    fn extract_from_results_field() {
        let data = json!({
            "count": 1,
            "results": [{"name": "test", "value": 42}]
        });
        let result = render_tabular(&data, TabularFormat::Csv, &default_opts()).unwrap();
        assert!(result.contains("test"));
    }

    #[test]
    fn extract_from_data_field() {
        let data = json!({
            "data": [{"x": 1}, {"x": 2}]
        });
        let result = render_tabular(&data, TabularFormat::Csv, &default_opts()).unwrap();
        assert!(result.contains('1'));
        assert!(result.contains('2'));
    }

    #[test]
    fn extract_from_rows_field() {
        let data = json!({
            "rows": [{"a": "hello"}]
        });
        let result = render_tabular(&data, TabularFormat::Csv, &default_opts()).unwrap();
        assert!(result.contains("hello"));
    }

    #[test]
    fn extract_from_entries_field() {
        let data = json!({
            "entries": [{"k": "v"}]
        });
        let result = render_tabular(&data, TabularFormat::Csv, &default_opts()).unwrap();
        assert!(result.contains('v'));
    }

    #[test]
    fn extract_from_records_field() {
        let data = json!({
            "records": [{"id": 1}]
        });
        let result = render_tabular(&data, TabularFormat::Csv, &default_opts()).unwrap();
        assert!(result.contains('1'));
    }

    #[test]
    fn extract_from_operations_field() {
        let data = json!({
            "operations": [{"op": "create"}]
        });
        let result = render_tabular(&data, TabularFormat::Csv, &default_opts()).unwrap();
        assert!(result.contains("create"));
    }

    #[test]
    fn extract_from_issues_field() {
        let data = json!({
            "issues": [{"title": "bug"}]
        });
        let result = render_tabular(&data, TabularFormat::Csv, &default_opts()).unwrap();
        assert!(result.contains("bug"));
    }

    #[test]
    fn extract_from_messages_field() {
        let data = json!({
            "messages": [{"text": "hi"}]
        });
        let result = render_tabular(&data, TabularFormat::Csv, &default_opts()).unwrap();
        assert!(result.contains("hi"));
    }

    #[test]
    fn extract_fallback_first_array_field() {
        let data = json!({
            "meta": "info",
            "my_custom_list": [{"name": "found"}]
        });
        let result = render_tabular(&data, TabularFormat::Csv, &default_opts()).unwrap();
        assert!(result.contains("found"));
    }

    // ── Non-tabular data errors ─────────────────────────────────────

    #[test]
    fn number_returns_error() {
        let data = json!(42);
        assert!(render_tabular(&data, TabularFormat::Table, &default_opts()).is_err());
    }

    #[test]
    fn null_returns_error() {
        let data = json!(null);
        assert!(render_tabular(&data, TabularFormat::Table, &default_opts()).is_err());
    }

    #[test]
    fn bool_returns_error() {
        let data = json!(true);
        assert!(render_tabular(&data, TabularFormat::Table, &default_opts()).is_err());
    }

    #[test]
    fn object_with_no_arrays_returns_error() {
        let data = json!({"a": 1, "b": "text"});
        assert!(render_tabular(&data, TabularFormat::Table, &default_opts()).is_err());
    }

    // ── Cell value formatting ───────────────────────────────────────

    #[test]
    fn number_values_rendered() {
        let data = json!([{"count": 42}, {"count": 0}]);
        let result = render_tabular(&data, TabularFormat::Csv, &default_opts()).unwrap();
        assert!(result.contains("42"));
        assert!(result.contains('0'));
    }

    #[test]
    fn nested_object_renders_as_json() {
        let data = json!([{"meta": {"key": "val"}}]);
        let opts = TabularOptions {
            columns: vec!["meta".into()],
            ..default_opts()
        };
        let result = render_tabular(&data, TabularFormat::Csv, &opts).unwrap();
        assert!(result.contains("key"));
        assert!(result.contains("val"));
    }

    // ── resolve_path tests ──────────────────────────────────────────

    #[test]
    fn resolve_path_simple_key() {
        let row = json!({"name": "alice"});
        assert_eq!(resolve_path(&row, "name"), &json!("alice"));
    }

    #[test]
    fn resolve_path_nested_dot() {
        let row = json!({"user": {"name": "bob"}});
        assert_eq!(resolve_path(&row, "user.name"), &json!("bob"));
    }

    #[test]
    fn resolve_path_missing_returns_null() {
        let row = json!({"name": "alice"});
        assert_eq!(resolve_path(&row, "missing"), &Value::Null);
    }

    #[test]
    fn resolve_path_array_index() {
        let row = json!({"items": ["a", "b", "c"]});
        assert_eq!(resolve_path(&row, "items[1]"), &json!("b"));
    }

    #[test]
    fn resolve_path_deep_nested() {
        let row = json!({"a": {"b": {"c": 99}}});
        assert_eq!(resolve_path(&row, "a.b.c"), &json!(99));
    }

    // ── Escape tests ────────────────────────────────────────────────

    #[test]
    fn escape_csv_normal() {
        assert_eq!(escape_delimited("hello", ','), "hello");
    }

    #[test]
    fn escape_csv_with_comma() {
        assert_eq!(escape_delimited("a,b", ','), "\"a,b\"");
    }

    #[test]
    fn escape_csv_with_newline() {
        assert_eq!(escape_delimited("line1\nline2", ','), "\"line1\nline2\"");
    }

    #[test]
    fn escape_tsv_normal() {
        assert_eq!(escape_delimited("hello", '\t'), "hello");
    }

    #[test]
    fn escape_tsv_with_tab() {
        assert_eq!(escape_delimited("a\tb", '\t'), "\"a\tb\"");
    }

    #[test]
    fn escape_markdown_no_pipe() {
        assert_eq!(escape_markdown_cell("hello"), "hello");
    }

    #[test]
    fn escape_markdown_with_pipe() {
        assert_eq!(escape_markdown_cell("a | b | c"), "a \\| b \\| c");
    }

    #[test]
    fn escape_markdown_with_newline() {
        assert_eq!(escape_markdown_cell("line1\nline2"), "line1<br>line2");
        assert_eq!(escape_markdown_cell("line1\r\nline2"), "line1<br>line2");
        assert_eq!(escape_markdown_cell("line1\rline2"), "line1<br>line2");
    }

    #[test]
    fn escape_csv_with_carriage_return() {
        assert_eq!(escape_delimited("a\rb", ','), "\"a\rb\"");
    }

    #[test]
    fn escape_tsv_with_newline() {
        assert_eq!(escape_delimited("a\nb", '\t'), "\"a\nb\"");
        assert_eq!(escape_delimited("a\rb", '\t'), "\"a\rb\"");
    }

    // ── Column auto-detection ───────────────────────────────────────

    #[test]
    fn auto_detect_columns_from_first_row() {
        let data = json!([
            {"id": 1, "name": "alice"},
            {"id": 2, "name": "bob", "email": "bob@test.com"},
        ]);
        let rows = extract_rows(&data).unwrap();
        let cols = auto_detect_columns(&rows);
        assert!(cols.contains(&"id".to_string()));
        assert!(cols.contains(&"name".to_string()));
        // email only in second row, not auto-detected
        assert!(!cols.contains(&"email".to_string()));
    }

    #[test]
    fn auto_detect_empty_rows() {
        let cols = auto_detect_columns(&[]);
        assert!(cols.is_empty());
    }

    // ── Sort by non-existent column is no-op ────────────────────────

    #[test]
    fn sort_by_nonexistent_column_preserves_order() {
        let opts = TabularOptions {
            sort_by: Some("nonexistent".into()),
            ..default_opts()
        };
        let result = render_tabular(&sample_issues(), TabularFormat::Csv, &opts).unwrap();
        let lines: Vec<&str> = result.lines().collect();
        assert_eq!(lines.len(), 4);
        // Order preserved (1, 2, 3)
        assert!(lines[1].starts_with('1'));
    }

    // ── Limit of zero means unlimited ───────────────────────────────

    #[test]
    fn limit_zero_means_unlimited() {
        let opts = TabularOptions {
            limit: 0,
            ..default_opts()
        };
        let result = render_tabular(&sample_issues(), TabularFormat::Csv, &opts).unwrap();
        assert_eq!(result.lines().count(), 4); // header + 3 rows
    }

    // ── Single row data ─────────────────────────────────────────────

    #[test]
    fn single_row_table() {
        let data = json!([{"id": 1, "name": "only"}]);
        let result = render_tabular(&data, TabularFormat::Table, &default_opts()).unwrap();
        assert!(result.contains("only"));
        assert_eq!(result.lines().count(), 3); // header + separator + 1 row
    }

    #[test]
    fn single_row_csv() {
        let data = json!([{"id": 1}]);
        let result = render_tabular(&data, TabularFormat::Csv, &default_opts()).unwrap();
        assert_eq!(result.lines().count(), 2);
    }

    // ── Large column width alignment ────────────────────────────────

    #[test]
    fn table_aligns_wide_values() {
        let data = json!([
            {"name": "short", "desc": "a"},
            {"name": "very long name here", "desc": "b"},
        ]);
        let result = render_tabular(&data, TabularFormat::Table, &default_opts()).unwrap();
        let lines: Vec<&str> = result.lines().collect();
        // All lines should have consistent column alignment
        assert!(lines[0].len() > 10);
    }

    // ── Mixed types in rows ─────────────────────────────────────────

    #[test]
    fn mixed_types_in_column() {
        let data = json!([
            {"value": "text"},
            {"value": 42},
            {"value": true},
            {"value": null},
        ]);
        let result = render_tabular(&data, TabularFormat::Csv, &default_opts()).unwrap();
        let lines: Vec<&str> = result.lines().collect();
        assert_eq!(lines.len(), 5);
        assert!(lines[1].contains("text"));
        assert!(lines[2].contains("42"));
        assert!(lines[3].contains("true"));
    }

    // ── CSV double-quote escaping ───────────────────────────────────

    #[test]
    fn csv_escapes_embedded_double_quotes() {
        let val = escape_delimited("say \"hi\" please", ',');
        assert_eq!(val, "\"say \"\"hi\"\" please\"");
    }

    // ── TabularFormat trait coverage ──────────────────────────────────

    #[test]
    fn tabular_format_clone() {
        let f = TabularFormat::Markdown;
        let g = f;
        assert_eq!(f, g);
    }

    #[test]
    fn tabular_format_debug() {
        let s = format!("{:?}", TabularFormat::Table);
        assert_eq!(s, "Table");
        assert_eq!(format!("{:?}", TabularFormat::Csv), "Csv");
        assert_eq!(format!("{:?}", TabularFormat::Tsv), "Tsv");
        assert_eq!(format!("{:?}", TabularFormat::Markdown), "Markdown");
    }

    #[test]
    fn tabular_format_all_pairs_ne() {
        let variants = [
            TabularFormat::Table,
            TabularFormat::Csv,
            TabularFormat::Tsv,
            TabularFormat::Markdown,
        ];
        for (i, a) in variants.iter().enumerate() {
            for (j, b) in variants.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b);
                } else {
                    assert_ne!(a, b);
                }
            }
        }
    }

    // ── TabularOptions trait coverage ─────────────────────────────────

    #[test]
    fn tabular_options_default_values() {
        let opts = TabularOptions::default();
        assert!(opts.columns.is_empty());
        assert!(opts.sort_by.is_none());
        assert_eq!(opts.limit, 0);
        assert!(!opts.no_headers);
    }

    #[test]
    fn tabular_options_clone() {
        let opts = TabularOptions {
            columns: vec!["a".into(), "b".into()],
            sort_by: Some("a".into()),
            limit: 5,
            no_headers: true,
        };
        let cloned = opts.clone();
        assert_eq!(opts.columns, cloned.columns);
        assert_eq!(opts.sort_by, cloned.sort_by);
        assert_eq!(opts.limit, cloned.limit);
        assert_eq!(opts.no_headers, cloned.no_headers);
    }

    #[test]
    fn tabular_options_debug() {
        let opts = TabularOptions {
            columns: vec!["x".into()],
            sort_by: None,
            limit: 10,
            no_headers: false,
        };
        let s = format!("{:?}", opts);
        assert!(s.contains("TabularOptions"));
        assert!(s.contains("columns"));
        assert!(s.contains("limit"));
    }

    // ── resolve_path edge cases ──────────────────────────────────────

    #[test]
    fn resolve_path_missing_intermediate() {
        let row = json!({"a": {"b": 1}});
        assert_eq!(resolve_path(&row, "a.missing.c"), &Value::Null);
    }

    #[test]
    fn resolve_path_array_out_of_bounds() {
        let row = json!({"items": ["only"]});
        assert_eq!(resolve_path(&row, "items[5]"), &Value::Null);
    }

    #[test]
    fn resolve_path_nested_array_index() {
        let row = json!({"data": {"list": [10, 20, 30]}});
        assert_eq!(resolve_path(&row, "data.list[2]"), &json!(30));
    }

    #[test]
    fn resolve_path_empty_key() {
        let row = json!({"": "empty_key"});
        assert_eq!(resolve_path(&row, ""), &json!("empty_key"));
    }

    #[test]
    fn resolve_path_on_non_object() {
        let row = json!(42);
        assert_eq!(resolve_path(&row, "anything"), &Value::Null);
    }

    #[test]
    fn resolve_path_array_index_zero() {
        let row = json!({"arr": ["first", "second"]});
        assert_eq!(resolve_path(&row, "arr[0]"), &json!("first"));
    }

    #[test]
    fn resolve_path_array_index_on_non_array() {
        let row = json!({"val": "not_array"});
        assert_eq!(resolve_path(&row, "val[0]"), &Value::Null);
    }

    // ── format_cell edge cases ───────────────────────────────────────

    #[test]
    fn format_cell_empty_string() {
        assert_eq!(format_cell(&json!("")), "");
    }

    #[test]
    fn format_cell_empty_array() {
        assert_eq!(format_cell(&json!([])), "");
    }

    #[test]
    fn format_cell_nested_array() {
        let val = json!([1, [2, 3]]);
        let result = format_cell(&val);
        assert!(result.contains('1'));
        // Inner array gets serialized
        assert!(result.contains('2'));
    }

    #[test]
    fn format_cell_float_number() {
        assert_eq!(format_cell(&json!(2.5)), "2.5");
    }

    #[test]
    fn format_cell_negative_number() {
        assert_eq!(format_cell(&json!(-7)), "-7");
    }

    #[test]
    fn format_cell_large_number() {
        assert_eq!(format_cell(&json!(1_000_000)), "1000000");
    }

    #[test]
    fn format_cell_object_with_nested() {
        let val = json!({"inner": {"deep": true}});
        let result = format_cell(&val);
        assert!(result.contains("inner"));
        assert!(result.contains("deep"));
        assert!(result.contains("true"));
    }

    #[test]
    fn format_cell_array_of_bools() {
        let result = format_cell(&json!([true, false, true]));
        assert_eq!(result, "true, false, true");
    }

    #[test]
    fn format_cell_array_of_numbers() {
        let result = format_cell(&json!([1, 2, 3]));
        assert_eq!(result, "1, 2, 3");
    }

    // ── escape_delimited edge cases ──────────────────────────────────

    #[test]
    fn escape_delimited_non_standard_delimiter() {
        // Non-standard delimiters never trigger quoting
        let result = escape_delimited("a|b", '|');
        assert_eq!(result, "a|b");
    }

    #[test]
    fn escape_csv_empty_string() {
        assert_eq!(escape_delimited("", ','), "");
    }

    #[test]
    fn escape_tsv_with_comma() {
        // Comma in TSV should NOT trigger quoting
        assert_eq!(escape_delimited("a,b", '\t'), "a,b");
    }

    #[test]
    fn escape_csv_with_all_special_chars() {
        let result = escape_delimited("a,b\"c\nd", ',');
        // Should be quoted and internal quotes doubled
        assert!(result.starts_with('"'));
        assert!(result.ends_with('"'));
        assert!(result.contains("\"\""));
    }

    // ── escape_markdown_cell edge cases ──────────────────────────────

    #[test]
    fn escape_markdown_empty() {
        assert_eq!(escape_markdown_cell(""), "");
    }

    #[test]
    fn escape_markdown_multiple_pipes() {
        assert_eq!(escape_markdown_cell("||"), "\\|\\|");
    }

    // ── Integration: sort + no_headers ───────────────────────────────

    #[test]
    fn sort_and_no_headers_combined() {
        let opts = TabularOptions {
            sort_by: Some("title".into()),
            no_headers: true,
            ..default_opts()
        };
        let result = render_tabular(&sample_issues(), TabularFormat::Csv, &opts).unwrap();
        let lines: Vec<&str> = result.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[0].contains("Bug fix"));
        assert!(lines[1].contains("Docs update"));
        assert!(lines[2].contains("Feature request"));
    }

    #[test]
    fn all_options_combined() {
        let opts = TabularOptions {
            columns: vec!["title".into(), "state".into()],
            sort_by: Some("title".into()),
            limit: 2,
            no_headers: true,
        };
        let result = render_tabular(&sample_issues(), TabularFormat::Table, &opts).unwrap();
        let lines: Vec<&str> = result.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("Bug fix"));
        assert!(lines[1].contains("Docs update"));
    }

    // ── Limit larger than row count ──────────────────────────────────

    #[test]
    fn limit_larger_than_rows() {
        let opts = TabularOptions {
            limit: 100,
            ..default_opts()
        };
        let result = render_tabular(&sample_issues(), TabularFormat::Csv, &opts).unwrap();
        assert_eq!(result.lines().count(), 4); // all rows present
    }

    #[test]
    fn limit_equal_to_row_count() {
        let opts = TabularOptions {
            limit: 3,
            ..default_opts()
        };
        let result = render_tabular(&sample_issues(), TabularFormat::Csv, &opts).unwrap();
        assert_eq!(result.lines().count(), 4);
    }

    #[test]
    fn limit_one() {
        let opts = TabularOptions {
            limit: 1,
            ..default_opts()
        };
        let result = render_tabular(&sample_issues(), TabularFormat::Csv, &opts).unwrap();
        assert_eq!(result.lines().count(), 2); // header + 1
    }

    // ── Unicode handling ─────────────────────────────────────────────

    #[test]
    fn unicode_values_in_table() {
        let data = json!([
            {"name": "日本語", "emoji": "🎉"},
            {"name": "中文", "emoji": "🚀"},
        ]);
        let result = render_tabular(&data, TabularFormat::Table, &default_opts()).unwrap();
        assert!(result.contains("日本語"));
        assert!(result.contains("🎉"));
    }

    #[test]
    fn unicode_in_csv() {
        let data = json!([{"greet": "héllo wörld"}]);
        let result = render_tabular(&data, TabularFormat::Csv, &default_opts()).unwrap();
        assert!(result.contains("héllo wörld"));
    }

    // ── Whitespace in values ─────────────────────────────────────────

    #[test]
    fn whitespace_preserved_in_table() {
        let data = json!([{"text": "  leading spaces"}, {"text": "trailing  "}]);
        let result = render_tabular(&data, TabularFormat::Csv, &default_opts()).unwrap();
        assert!(result.contains("  leading spaces"));
        assert!(result.contains("trailing  "));
    }

    // ── Single column table ──────────────────────────────────────────

    #[test]
    fn single_column_table() {
        let data = json!([{"id": 1}, {"id": 2}, {"id": 3}]);
        let opts = TabularOptions {
            columns: vec!["id".into()],
            ..default_opts()
        };
        let result = render_tabular(&data, TabularFormat::Table, &opts).unwrap();
        assert!(result.contains("id"));
        assert!(result.contains('1'));
        assert!(result.contains('2'));
        assert!(result.contains('3'));
    }

    #[test]
    fn single_column_csv() {
        let data = json!([{"val": "a"}, {"val": "b"}]);
        let opts = TabularOptions {
            columns: vec!["val".into()],
            ..default_opts()
        };
        let result = render_tabular(&data, TabularFormat::Csv, &opts).unwrap();
        let lines: Vec<&str> = result.lines().collect();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0], "val");
        assert_eq!(lines[1], "a");
        assert_eq!(lines[2], "b");
    }

    // ── Object with array of non-objects ─────────────────────────────

    #[test]
    fn object_with_scalar_array_renders_empty() {
        // Well-known field "items" contains scalars, not objects.
        // extract_rows succeeds but auto_detect_columns returns empty → "(no rows)".
        let data = json!({"items": [1, 2, 3]});
        let result = render_tabular(&data, TabularFormat::Table, &default_opts()).unwrap();
        assert!(result.contains("no rows"));
    }

    #[test]
    fn object_with_empty_array_returns_error() {
        let data = json!({"items": []});
        // Empty array in well-known field returns empty rows → Ok with "(no rows)"
        let result = render_tabular(&data, TabularFormat::Table, &default_opts()).unwrap();
        assert!(result.contains("no rows"));
    }

    // ── Error message content ────────────────────────────────────────

    #[test]
    fn error_message_is_descriptive() {
        let data = json!("text");
        let err = render_tabular(&data, TabularFormat::Table, &default_opts()).unwrap_err();
        assert!(err.contains("not tabular"));
    }

    // ── Multiple wrapper field precedence ────────────────────────────

    #[test]
    fn well_known_field_takes_priority() {
        // "items" should be preferred over an unknown array field
        let data = json!({
            "other_list": [{"z": 1}],
            "items": [{"a": 2}]
        });
        let result = render_tabular(&data, TabularFormat::Csv, &default_opts()).unwrap();
        // Should extract from "items" (well-known) over "other_list"
        assert!(result.contains('a'));
        assert!(result.contains('2'));
    }

    // ── Markdown with special content ────────────────────────────────

    #[test]
    fn markdown_no_headers_still_has_pipes() {
        let data = json!([{"x": 1}]);
        let opts = TabularOptions {
            no_headers: true,
            ..default_opts()
        };
        let result = render_tabular(&data, TabularFormat::Markdown, &opts).unwrap();
        assert!(result.starts_with("| "));
        assert!(result.contains('1'));
    }

    #[test]
    fn markdown_multiple_rows() {
        let data = json!([
            {"a": 1, "b": 2},
            {"a": 3, "b": 4},
            {"a": 5, "b": 6},
        ]);
        let result = render_tabular(&data, TabularFormat::Markdown, &default_opts()).unwrap();
        let lines: Vec<&str> = result.lines().collect();
        assert_eq!(lines.len(), 5); // header + separator + 3 rows
        assert!(lines[0].starts_with("| "));
        assert!(lines[1].contains("---"));
    }

    // ── TSV with special characters ──────────────────────────────────

    #[test]
    fn tsv_value_with_comma_not_quoted() {
        let data = json!([{"text": "hello, world"}]);
        let result = render_tabular(&data, TabularFormat::Tsv, &default_opts()).unwrap();
        // Commas don't need quoting in TSV
        assert!(result.contains("hello, world"));
        assert!(!result.contains('"'));
    }

    // ── Table alignment edge cases ───────────────────────────────────

    #[test]
    fn table_with_empty_cell_values() {
        let data = json!([
            {"name": "alice", "bio": ""},
            {"name": "bob", "bio": "engineer"},
        ]);
        let result = render_tabular(&data, TabularFormat::Table, &default_opts()).unwrap();
        assert!(result.contains("alice"));
        assert!(result.contains("engineer"));
    }

    #[test]
    fn table_column_width_uses_header_minimum() {
        let data = json!([{"longheader": "x"}]);
        let result = render_tabular(&data, TabularFormat::Table, &default_opts()).unwrap();
        let lines: Vec<&str> = result.lines().collect();
        // Header and separator should be at least as wide as "longheader"
        assert!(lines[1].len() >= "longheader".len());
    }

    // ── Auto-detect columns with non-object first row ────────────────

    #[test]
    fn auto_detect_columns_non_object_first_row() {
        let rows_val = json!([42, "text"]);
        let rows: Vec<&Value> = rows_val.as_array().unwrap().iter().collect();
        let cols = auto_detect_columns(&rows);
        assert!(cols.is_empty());
    }

    // ── extract_cell_values coverage ─────────────────────────────────

    #[test]
    fn extract_cell_values_empty_rows() {
        let rows: Vec<&Value> = vec![];
        let columns = vec!["a".into()];
        let result = extract_cell_values(&rows, &columns);
        assert!(result.is_empty());
    }

    #[test]
    fn extract_cell_values_multiple_columns() {
        let data = json!([{"x": 1, "y": 2}]);
        let rows: Vec<&Value> = data.as_array().unwrap().iter().collect();
        let columns = vec!["x".into(), "y".into()];
        let result = extract_cell_values(&rows, &columns);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].len(), 2);
        assert_eq!(result[0][0], "1");
        assert_eq!(result[0][1], "2");
    }
}
