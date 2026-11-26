//! Google Sheets API v4 data types.

use serde::{Deserialize, Serialize};

/// A spreadsheet resource.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Spreadsheet {
    pub spreadsheet_id: String,
    #[serde(default)]
    pub properties: SpreadsheetProperties,
    #[serde(default)]
    pub sheets: Vec<Sheet>,
    #[serde(default)]
    pub spreadsheet_url: String,
}

/// Spreadsheet-level properties.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpreadsheetProperties {
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub locale: String,
    #[serde(default)]
    pub time_zone: String,
}

/// A single sheet within a spreadsheet.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Sheet {
    pub properties: SheetProperties,
}

/// Sheet-level properties.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SheetProperties {
    pub sheet_id: u32,
    pub title: String,
    #[serde(default)]
    pub index: u32,
    #[serde(default)]
    pub sheet_type: String,
}

/// Response from `spreadsheets.values.get`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValueRange {
    pub range: String,
    #[serde(default)]
    pub major_dimension: String,
    #[serde(default)]
    pub values: Vec<Vec<serde_json::Value>>,
}

/// Response from `spreadsheets.values.update`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateValuesResponse {
    pub spreadsheet_id: String,
    pub updated_range: String,
    #[serde(default)]
    pub updated_rows: u32,
    #[serde(default)]
    pub updated_columns: u32,
    #[serde(default)]
    pub updated_cells: u32,
}

/// Response from `spreadsheets.values.append`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppendValuesResponse {
    pub spreadsheet_id: String,
    #[serde(default)]
    pub table_range: String,
    #[serde(default)]
    pub updates: Option<UpdateValuesResponse>,
}

/// Request body for batch update.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchUpdateValuesRequest {
    pub value_input_option: String,
    pub data: Vec<ValueRange>,
}

/// Response from batch update.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchUpdateValuesResponse {
    pub spreadsheet_id: String,
    #[serde(default)]
    pub total_updated_rows: u32,
    #[serde(default)]
    pub total_updated_columns: u32,
    #[serde(default)]
    pub total_updated_cells: u32,
    #[serde(default)]
    pub total_updated_sheets: u32,
}

/// Google Sheets API error response.
#[derive(Debug, Deserialize)]
pub(crate) struct ApiErrorResponse {
    pub error: ApiErrorDetail,
}

/// Error detail from the API.
#[derive(Debug, Deserialize)]
pub(crate) struct ApiErrorDetail {
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spreadsheet_serde() {
        let json = r#"{
            "spreadsheetId": "abc123",
            "properties": {"title": "Test Sheet", "locale": "en_US", "timeZone": "UTC"},
            "sheets": [{"properties": {"sheetId": 0, "title": "Sheet1", "index": 0, "sheetType": "GRID"}}],
            "spreadsheetUrl": "https://docs.google.com/spreadsheets/d/abc123"
        }"#;
        let ss: Spreadsheet = serde_json::from_str(json).unwrap();
        assert_eq!(ss.spreadsheet_id, "abc123");
        assert_eq!(ss.properties.title, "Test Sheet");
        assert_eq!(ss.sheets.len(), 1);
        assert_eq!(ss.sheets[0].properties.title, "Sheet1");
    }

    #[test]
    fn value_range_serde() {
        let json = r#"{
            "range": "Sheet1!A1:B2",
            "majorDimension": "ROWS",
            "values": [["a", "b"], ["c", "d"]]
        }"#;
        let vr: ValueRange = serde_json::from_str(json).unwrap();
        assert_eq!(vr.range, "Sheet1!A1:B2");
        assert_eq!(vr.values.len(), 2);
    }

    #[test]
    fn value_range_empty_values() {
        let json = r#"{"range": "Sheet1!A1:A1", "majorDimension": "ROWS"}"#;
        let vr: ValueRange = serde_json::from_str(json).unwrap();
        assert!(vr.values.is_empty());
    }

    #[test]
    fn update_response_serde() {
        let json = r#"{
            "spreadsheetId": "abc",
            "updatedRange": "Sheet1!A1:B2",
            "updatedRows": 2,
            "updatedColumns": 2,
            "updatedCells": 4
        }"#;
        let ur: UpdateValuesResponse = serde_json::from_str(json).unwrap();
        assert_eq!(ur.updated_cells, 4);
    }

    #[test]
    fn append_response_serde() {
        let json = r#"{
            "spreadsheetId": "abc",
            "tableRange": "Sheet1!A1:B2"
        }"#;
        let ar: AppendValuesResponse = serde_json::from_str(json).unwrap();
        assert_eq!(ar.table_range, "Sheet1!A1:B2");
        assert!(ar.updates.is_none());
    }

    #[test]
    fn batch_update_response_serde() {
        let json = r#"{
            "spreadsheetId": "abc",
            "totalUpdatedRows": 10,
            "totalUpdatedColumns": 3,
            "totalUpdatedCells": 30,
            "totalUpdatedSheets": 1
        }"#;
        let br: BatchUpdateValuesResponse = serde_json::from_str(json).unwrap();
        assert_eq!(br.total_updated_cells, 30);
    }

    #[test]
    fn api_error_response_serde() {
        let json = r#"{"error": {"code": 404, "message": "not found"}}"#;
        let er: ApiErrorResponse = serde_json::from_str(json).unwrap();
        assert_eq!(er.error.message, "not found");
    }

    #[test]
    fn spreadsheet_properties_default() {
        let props = SpreadsheetProperties::default();
        assert!(props.title.is_empty());
    }

    #[test]
    fn sheet_properties_debug() {
        let sp = SheetProperties {
            sheet_id: 0,
            title: "Test".into(),
            index: 0,
            sheet_type: "GRID".into(),
        };
        let dbg = format!("{sp:?}");
        assert!(dbg.contains("Test"));
    }
}
