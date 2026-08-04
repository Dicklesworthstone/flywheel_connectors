//! `Snowflake` SQL API client.

use fcp_prelude::log_redaction::redact_url;
use std::fmt;
use std::time::Duration;

use fcp_sdk::migration::HttpRetryConfig;
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use reqwest::{Client, Response, StatusCode};
use tracing::{debug, instrument};

use crate::{
    error::{SnowflakeError, SnowflakeResult},
    types::ApiErrorResponse,
};

/// Validate a Snowflake SQL identifier (database, schema, table name).
///
/// Only allows alphanumeric characters, underscores, dots (for qualified names
/// like `db.schema`), and dollar signs (Snowflake allows `$` in identifiers).
/// Rejects anything that could be used for SQL injection.
fn validate_sql_identifier<'a>(value: &'a str, field: &str) -> SnowflakeResult<&'a str> {
    let value = value.trim();
    if value.is_empty() {
        return Err(SnowflakeError::InvalidInput(format!(
            "{field} must not be empty"
        )));
    }
    // Must start with a letter or underscore
    let first = value.chars().next().unwrap();
    if !first.is_ascii_alphabetic() && first != '_' {
        return Err(SnowflakeError::InvalidInput(format!(
            "{field} must start with a letter or underscore"
        )));
    }
    // Only allow alphanumeric, underscore, dot (for qualified names), dollar sign
    for ch in value.chars() {
        if !ch.is_ascii_alphanumeric() && ch != '_' && ch != '.' && ch != '$' {
            return Err(SnowflakeError::InvalidInput(format!(
                "{field} contains invalid character '{ch}'"
            )));
        }
    }
    // Reject consecutive dots or leading/trailing dots
    if value.starts_with('.') || value.ends_with('.') || value.contains("..") {
        return Err(SnowflakeError::InvalidInput(format!(
            "{field} has invalid dot placement"
        )));
    }
    Ok(value)
}

/// Validate a Snowflake account identifier before it is interpolated into the
/// request host (`https://{account}.snowflakecomputing.com`).
///
/// Account identifiers are either `orgname-account_name` or a legacy account
/// locator optionally suffixed with region/cloud segments
/// (`xy12345.us-east-1.aws`), so only ASCII alphanumerics plus `-`, `_`, and
/// `.` are legitimate. Anything else (`/`, `\`, `@`, `:`, `?`, `#`, `%`,
/// whitespace) could terminate or escape the intended host — e.g. `evil.com/`
/// parses to host `evil.com` — redirecting the bearer-token-carrying request to
/// an attacker-controlled server.
fn validate_account_identifier(value: &str) -> SnowflakeResult<()> {
    if value.is_empty() {
        return Err(SnowflakeError::InvalidInput(
            "account_identifier must not be empty".into(),
        ));
    }
    for ch in value.chars() {
        if !ch.is_ascii_alphanumeric() && ch != '-' && ch != '_' && ch != '.' {
            return Err(SnowflakeError::InvalidInput(format!(
                "account_identifier contains invalid character '{ch}'"
            )));
        }
    }
    if value.starts_with('.') || value.ends_with('.') || value.contains("..") {
        return Err(SnowflakeError::InvalidInput(
            "account_identifier has invalid dot placement".into(),
        ));
    }
    Ok(())
}

/// `Snowflake` authentication credentials.
#[derive(Clone)]
pub struct SnowflakeAuth {
    pub access_token: String,
    pub account_identifier: String,
}

impl SnowflakeAuth {
    #[must_use]
    pub fn redacted_label(&self) -> String {
        format!("account:{},token:redacted", self.account_identifier)
    }
}

impl fmt::Debug for SnowflakeAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SnowflakeAuth")
            .field("account_identifier", &self.account_identifier)
            .field("access_token", &"<redacted>")
            .finish()
    }
}

/// `Snowflake` API client.
pub struct SnowflakeClient {
    client: Client,
    auth: SnowflakeAuth,
    base_url: String,
    /// Default warehouse for SQL statements.
    pub warehouse: Option<String>,
    /// Default database for SQL statements.
    pub database: Option<String>,
    /// Default schema for SQL statements.
    pub schema: Option<String>,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
}

impl fmt::Debug for SnowflakeClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SnowflakeClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .finish()
    }
}

impl SnowflakeClient {
    /// Create a new `Snowflake` client.
    pub fn new(
        auth: SnowflakeAuth,
        base_url: Option<&str>,
        warehouse: Option<String>,
        database: Option<String>,
        schema: Option<String>,
    ) -> SnowflakeResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(60))
            .user_agent("fcp-snowflake/0.1.0 (FCP connector)")
            .build()?;

        let url = if let Some(u) = base_url {
            u.trim_end_matches('/').to_string()
        } else {
            validate_account_identifier(&auth.account_identifier)?;
            format!(
                "https://{}.snowflakecomputing.com/api/v2",
                auth.account_identifier
            )
        };

        Ok(Self {
            client,
            auth,
            base_url: url,
            warehouse,
            database,
            schema,
            runtime: ConnectorRuntime::new(
                ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_secs(30)),
            ),
            retry_config: HttpRetryConfig {
                max_retries: 2,
                ..HttpRetryConfig::default()
            },
        })
    }

    /// Gracefully shut down the connector runtime.
    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    fn add_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        req.bearer_auth(&self.auth.access_token)
    }

    async fn handle_response(&self, resp: Response) -> SnowflakeResult<serde_json::Value> {
        let status = resp.status();
        if status.is_success() {
            let body = resp.text().await?;
            decode_success_body(status, &body)
        } else {
            self.handle_error(status, resp).await
        }
    }

    async fn handle_error(
        &self,
        status: StatusCode,
        resp: Response,
    ) -> SnowflakeResult<serde_json::Value> {
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        let body = resp.text().await.unwrap_or_default();
        let detail = serde_json::from_str::<ApiErrorResponse>(&body)
            .ok()
            .and_then(|e| e.message)
            .unwrap_or_else(|| body.clone());

        match status.as_u16() {
            401 => Err(SnowflakeError::Unauthorized),
            403 => Err(SnowflakeError::Forbidden),
            404 => Err(SnowflakeError::NotFound { resource: detail }),
            429 => Err(SnowflakeError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(60) * 1000,
            }),
            code => Err(SnowflakeError::Api {
                status_code: code,
                message: detail,
            }),
        }
    }

    #[instrument(skip(self), fields(url))]
    async fn get(&self, path: &str) -> SnowflakeResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %redact_url(&url), "GET request");
        let req = self
            .add_auth(self.client.get(&url))
            .header("Accept", "application/json");
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    #[instrument(skip(self, body), fields(url))]
    async fn post(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> SnowflakeResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %redact_url(&url), "POST request");
        let req = self
            .add_auth(self.client.post(&url))
            .header("Accept", "application/json")
            .json(body);
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    // -- Databases --

    /// List all databases.
    pub async fn list_databases(&self) -> SnowflakeResult<serde_json::Value> {
        self.get("/databases").await
    }

    // -- Warehouses --

    /// List all warehouses.
    pub async fn list_warehouses(&self) -> SnowflakeResult<serde_json::Value> {
        self.get("/warehouses").await
    }

    // -- SQL Statements --

    /// Execute a SQL query (read-only SELECT).
    pub async fn sql_query(
        &self,
        statement: &str,
        warehouse: Option<&str>,
        database: Option<&str>,
        schema: Option<&str>,
    ) -> SnowflakeResult<serde_json::Value> {
        let mut body = serde_json::json!({
            "statement": statement,
            "timeout": 60,
        });

        let wh = warehouse
            .map(String::from)
            .or_else(|| self.warehouse.clone());
        let db = database.map(String::from).or_else(|| self.database.clone());
        let sc = schema.map(String::from).or_else(|| self.schema.clone());

        if let Some(w) = wh {
            body["warehouse"] = serde_json::json!(w);
        }
        if let Some(d) = db {
            body["database"] = serde_json::json!(d);
        }
        if let Some(s) = sc {
            body["schema"] = serde_json::json!(s);
        }

        self.post("/statements", &body).await
    }

    /// Execute a SQL statement (DDL/DML).
    pub async fn sql_execute(
        &self,
        statement: &str,
        warehouse: Option<&str>,
        database: Option<&str>,
        schema: Option<&str>,
    ) -> SnowflakeResult<serde_json::Value> {
        let mut body = serde_json::json!({
            "statement": statement,
            "timeout": 60,
        });

        let wh = warehouse
            .map(String::from)
            .or_else(|| self.warehouse.clone());
        let db = database.map(String::from).or_else(|| self.database.clone());
        let sc = schema.map(String::from).or_else(|| self.schema.clone());

        if let Some(w) = wh {
            body["warehouse"] = serde_json::json!(w);
        }
        if let Some(d) = db {
            body["database"] = serde_json::json!(d);
        }
        if let Some(s) = sc {
            body["schema"] = serde_json::json!(s);
        }

        self.post("/statements", &body).await
    }

    // -- Tables --

    /// List tables in a database by executing SHOW TABLES.
    pub async fn list_tables(
        &self,
        database: &str,
        schema: Option<&str>,
    ) -> SnowflakeResult<serde_json::Value> {
        let database = validate_sql_identifier(database, "database")?;
        let statement = match schema {
            Some(s) => {
                let s = validate_sql_identifier(s, "schema")?;
                format!("SHOW TABLES IN SCHEMA {database}.{s}")
            }
            None => format!("SHOW TABLES IN DATABASE {database}"),
        };

        let wh = self.warehouse.clone();
        self.sql_query(&statement, wh.as_deref(), Some(database), schema)
            .await
    }
}

fn decode_success_body(status: StatusCode, body: &str) -> SnowflakeResult<serde_json::Value> {
    if status == StatusCode::NO_CONTENT {
        return Ok(serde_json::json!({}));
    }
    if body.trim().is_empty() {
        return Err(SnowflakeError::Api {
            status_code: status.as_u16(),
            message: "empty response body".into(),
        });
    }
    Ok(serde_json::from_str(body)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_debug_redacts_token() {
        let auth = SnowflakeAuth {
            access_token: "secret-token-value".into(),
            account_identifier: "myaccount".into(),
        };
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("secret-token-value"));
        assert!(dbg.contains("redacted"));
        assert!(dbg.contains("myaccount"));
    }

    #[test]
    fn auth_redacted_label() {
        let auth = SnowflakeAuth {
            access_token: "secret".into(),
            account_identifier: "myaccount".into(),
        };
        let label = auth.redacted_label();
        assert!(label.contains("myaccount"));
        assert!(label.contains("redacted"));
        assert!(!label.contains("secret"));
    }

    #[test]
    fn client_new_with_custom_base_url() {
        let auth = SnowflakeAuth {
            access_token: "TOKEN".into(),
            account_identifier: "ACC".into(),
        };
        let client = SnowflakeClient::new(
            auth,
            Some("https://test.example.com/api/v2"),
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(client.base_url, "https://test.example.com/api/v2");
    }

    #[test]
    fn client_new_default_url() {
        let auth = SnowflakeAuth {
            access_token: "TOKEN".into(),
            account_identifier: "myaccount".into(),
        };
        let client = SnowflakeClient::new(auth, None, None, None, None).unwrap();
        assert_eq!(
            client.base_url,
            "https://myaccount.snowflakecomputing.com/api/v2"
        );
    }

    #[test]
    fn client_new_rejects_host_injecting_account_identifier() {
        // A crafted account identifier must not be able to break out of the
        // `{account}.snowflakecomputing.com` host and redirect the
        // access-token-carrying request to an attacker-controlled server.
        for evil in [
            "evil.com/",
            "evil.com\\",
            "acct@evil.com",
            "acct:8080",
            "acct?x=1",
            "acct#frag",
            "acct%2f..",
            "..",
            "acct with space",
            "",
        ] {
            let auth = SnowflakeAuth {
                access_token: "TOKEN".into(),
                account_identifier: evil.into(),
            };
            let result = SnowflakeClient::new(auth, None, None, None, None);
            assert!(
                matches!(result, Err(SnowflakeError::InvalidInput(_))),
                "account_identifier {evil:?} must be rejected"
            );
        }

        // Legitimate identifier shapes (org-account and legacy locator) accepted.
        for ok in ["myorg-myaccount", "xy12345.us-east-1.aws", "ACC_1"] {
            let auth = SnowflakeAuth {
                access_token: "TOKEN".into(),
                account_identifier: ok.into(),
            };
            assert!(
                SnowflakeClient::new(auth, None, None, None, None).is_ok(),
                "account_identifier {ok:?} must be accepted"
            );
        }
    }

    #[test]
    fn client_new_strips_trailing_slash() {
        let auth = SnowflakeAuth {
            access_token: "TOKEN".into(),
            account_identifier: "ACC".into(),
        };
        let client = SnowflakeClient::new(
            auth,
            Some("https://test.example.com/api/v2/"),
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(client.base_url, "https://test.example.com/api/v2");
    }

    #[test]
    fn decode_success_body_rejects_empty_ok() {
        let err = decode_success_body(StatusCode::OK, "").unwrap_err();
        assert!(matches!(
            err,
            SnowflakeError::Api {
                status_code: 200,
                message
            } if message == "empty response body"
        ));
    }

    #[test]
    fn decode_success_body_rejects_whitespace_ok() {
        let err = decode_success_body(StatusCode::OK, "  \n\t").unwrap_err();
        assert!(matches!(
            err,
            SnowflakeError::Api {
                status_code: 200,
                message
            } if message == "empty response body"
        ));
    }

    #[test]
    fn decode_success_body_allows_empty_no_content() {
        assert_eq!(
            decode_success_body(StatusCode::NO_CONTENT, "").unwrap(),
            serde_json::json!({})
        );
    }

    #[test]
    fn client_debug_shows_base_url() {
        let auth = SnowflakeAuth {
            access_token: "TOKEN".into(),
            account_identifier: "ACC".into(),
        };
        let client =
            SnowflakeClient::new(auth, Some("https://example.com"), None, None, None).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("example.com"));
        assert!(!dbg.contains("TOKEN"));
    }

    #[test]
    fn auth_clone() {
        let auth = SnowflakeAuth {
            access_token: "TOKEN".into(),
            account_identifier: "ACC".into(),
        };
        let cloned = SnowflakeAuth::clone(&auth);
        assert_eq!(cloned.access_token, "TOKEN");
        assert_eq!(cloned.account_identifier, "ACC");
    }

    #[test]
    fn client_stores_defaults() {
        let auth = SnowflakeAuth {
            access_token: "T".into(),
            account_identifier: "A".into(),
        };
        let client = SnowflakeClient::new(
            auth,
            Some("https://example.com"),
            Some("COMPUTE_WH".into()),
            Some("ANALYTICS".into()),
            Some("PUBLIC".into()),
        )
        .unwrap();
        assert_eq!(client.warehouse, Some("COMPUTE_WH".into()));
        assert_eq!(client.database, Some("ANALYTICS".into()));
        assert_eq!(client.schema, Some("PUBLIC".into()));
    }

    #[test]
    fn client_no_defaults() {
        let auth = SnowflakeAuth {
            access_token: "T".into(),
            account_identifier: "A".into(),
        };
        let client =
            SnowflakeClient::new(auth, Some("https://example.com"), None, None, None).unwrap();
        assert!(client.warehouse.is_none());
        assert!(client.database.is_none());
        assert!(client.schema.is_none());
    }

    #[test]
    fn auth_debug_contains_struct_name() {
        let auth = SnowflakeAuth {
            access_token: "secret".into(),
            account_identifier: "acc".into(),
        };
        let dbg = format!("{auth:?}");
        assert!(dbg.contains("SnowflakeAuth"));
    }

    #[test]
    fn auth_debug_shows_account_identifier() {
        let auth = SnowflakeAuth {
            access_token: "secret".into(),
            account_identifier: "my_account_xyz".into(),
        };
        let dbg = format!("{auth:?}");
        assert!(dbg.contains("my_account_xyz"));
    }

    #[test]
    fn client_debug_contains_struct_name() {
        let auth = SnowflakeAuth {
            access_token: "T".into(),
            account_identifier: "A".into(),
        };
        let client =
            SnowflakeClient::new(auth, Some("https://example.com"), None, None, None).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("SnowflakeClient"));
    }

    #[test]
    fn client_debug_does_not_leak_token() {
        let auth = SnowflakeAuth {
            access_token: "super-secret-token-12345".into(),
            account_identifier: "A".into(),
        };
        let client =
            SnowflakeClient::new(auth, Some("https://example.com"), None, None, None).unwrap();
        let dbg = format!("{client:?}");
        assert!(!dbg.contains("super-secret-token-12345"));
    }

    #[test]
    fn auth_redacted_label_format() {
        let auth = SnowflakeAuth {
            access_token: "token".into(),
            account_identifier: "test_acc".into(),
        };
        let label = auth.redacted_label();
        assert_eq!(label, "account:test_acc,token:redacted");
    }

    #[test]
    fn client_new_multiple_trailing_slashes() {
        let auth = SnowflakeAuth {
            access_token: "T".into(),
            account_identifier: "A".into(),
        };
        let client =
            SnowflakeClient::new(auth, Some("https://example.com///"), None, None, None).unwrap();
        assert!(!client.base_url.ends_with('/'));
    }

    #[test]
    fn client_new_with_warehouse_only() {
        let auth = SnowflakeAuth {
            access_token: "T".into(),
            account_identifier: "A".into(),
        };
        let client = SnowflakeClient::new(
            auth,
            Some("https://example.com"),
            Some("MY_WH".into()),
            None,
            None,
        )
        .unwrap();
        assert_eq!(client.warehouse, Some("MY_WH".into()));
        assert!(client.database.is_none());
        assert!(client.schema.is_none());
    }

    #[test]
    fn client_new_with_database_only() {
        let auth = SnowflakeAuth {
            access_token: "T".into(),
            account_identifier: "A".into(),
        };
        let client = SnowflakeClient::new(
            auth,
            Some("https://example.com"),
            None,
            Some("MY_DB".into()),
            None,
        )
        .unwrap();
        assert!(client.warehouse.is_none());
        assert_eq!(client.database, Some("MY_DB".into()));
    }

    #[test]
    fn client_new_with_schema_only() {
        let auth = SnowflakeAuth {
            access_token: "T".into(),
            account_identifier: "A".into(),
        };
        let client = SnowflakeClient::new(
            auth,
            Some("https://example.com"),
            None,
            None,
            Some("PUBLIC".into()),
        )
        .unwrap();
        assert_eq!(client.schema, Some("PUBLIC".into()));
    }

    #[test]
    fn client_default_url_uses_account_identifier() {
        let auth = SnowflakeAuth {
            access_token: "T".into(),
            account_identifier: "xy12345.us-east-1".into(),
        };
        let client = SnowflakeClient::new(auth, None, None, None, None).unwrap();
        assert!(client.base_url.contains("xy12345.us-east-1"));
        assert!(client.base_url.contains("snowflakecomputing.com"));
    }

    // -- validate_sql_identifier tests --

    #[test]
    fn validate_sql_identifier_simple() {
        assert_eq!(
            validate_sql_identifier("MY_DB", "database").unwrap(),
            "MY_DB"
        );
    }

    #[test]
    fn validate_sql_identifier_with_dollar() {
        assert_eq!(
            validate_sql_identifier("MY$DB", "database").unwrap(),
            "MY$DB"
        );
    }

    #[test]
    fn validate_sql_identifier_qualified_name() {
        assert_eq!(
            validate_sql_identifier("MY_DB.PUBLIC", "database.schema").unwrap(),
            "MY_DB.PUBLIC"
        );
    }

    #[test]
    fn validate_sql_identifier_rejects_empty() {
        let err = validate_sql_identifier("", "database").unwrap_err();
        assert!(err.to_string().contains("must not be empty"));
    }

    #[test]
    fn validate_sql_identifier_rejects_whitespace_only() {
        let err = validate_sql_identifier("   ", "database").unwrap_err();
        assert!(err.to_string().contains("must not be empty"));
    }

    #[test]
    fn validate_sql_identifier_rejects_starting_digit() {
        let err = validate_sql_identifier("1BAD", "database").unwrap_err();
        assert!(err.to_string().contains("must start with"));
    }

    #[test]
    fn validate_sql_identifier_rejects_semicolon() {
        let err = validate_sql_identifier("MY_DB; DROP TABLE", "database").unwrap_err();
        assert!(err.to_string().contains("invalid character"));
    }

    #[test]
    fn validate_sql_identifier_rejects_single_quote() {
        let err = validate_sql_identifier("MY_DB' OR '1'='1", "database").unwrap_err();
        assert!(err.to_string().contains("invalid character"));
    }

    #[test]
    fn validate_sql_identifier_rejects_dash() {
        let err = validate_sql_identifier("MY-DB", "database").unwrap_err();
        assert!(err.to_string().contains("invalid character"));
    }

    #[test]
    fn validate_sql_identifier_rejects_space() {
        let err = validate_sql_identifier("MY DB", "database").unwrap_err();
        assert!(err.to_string().contains("invalid character"));
    }

    #[test]
    fn validate_sql_identifier_rejects_parenthesis() {
        let err = validate_sql_identifier("DB()", "database").unwrap_err();
        assert!(err.to_string().contains("invalid character"));
    }

    #[test]
    fn validate_sql_identifier_rejects_double_dash_comment() {
        // -- is a SQL comment. The dash itself is invalid.
        let err = validate_sql_identifier("DB--comment", "database").unwrap_err();
        assert!(err.to_string().contains("invalid character"));
    }

    #[test]
    fn validate_sql_identifier_rejects_leading_dot() {
        let err = validate_sql_identifier(".MY_DB", "database").unwrap_err();
        assert!(err.to_string().contains("must start with"));
    }

    #[test]
    fn validate_sql_identifier_rejects_trailing_dot() {
        let err = validate_sql_identifier("MY_DB.", "database").unwrap_err();
        assert!(err.to_string().contains("invalid dot placement"));
    }

    #[test]
    fn validate_sql_identifier_rejects_consecutive_dots() {
        let err = validate_sql_identifier("MY_DB..SCHEMA", "database").unwrap_err();
        assert!(err.to_string().contains("invalid dot placement"));
    }

    #[test]
    fn validate_sql_identifier_allows_underscore_start() {
        assert_eq!(
            validate_sql_identifier("_internal", "schema").unwrap(),
            "_internal"
        );
    }

    #[test]
    fn validate_sql_identifier_allows_mixed_case() {
        assert_eq!(
            validate_sql_identifier("MyDatabase123", "database").unwrap(),
            "MyDatabase123"
        );
    }
}
