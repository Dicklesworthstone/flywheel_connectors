//! SQLite client and local query execution helpers.

#![allow(clippy::doc_markdown)]

use std::cell::Cell;
use std::fmt;
use std::io::{self, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use rusqlite::{
    Connection, OpenFlags,
    hooks::{AuthAction, AuthContext, Authorization},
    limits::Limit,
    params_from_iter,
    types::{Value as SqlValue, ValueRef},
};
use serde::Serialize;
use serde_json::json;
use tracing::warn;

use crate::{
    error::{SqliteError, SqliteResult},
    types::{
        BatchStatement, BatchStatementResult, ExecuteResult, QueryColumn, QueryResult,
        SchemaColumn, SqliteConfig, SqliteHealth, TableInfo, TransactionMode,
    },
};

const ALLOWED_PRAGMAS: &[&str] = &[
    "application_id",
    "auto_vacuum",
    "cache_size",
    "compile_options",
    "encoding",
    "foreign_keys",
    "freelist_count",
    "journal_mode",
    "locking_mode",
    "mmap_size",
    "page_count",
    "page_size",
    "schema_version",
    "synchronous",
    "temp_store",
    "user_version",
    "wal_autocheckpoint",
];

/// Maximum rows in one query, schema listing, pragma, or batch response.
pub const MAX_RESULT_ROWS: usize = 10_000;
/// Maximum compact JSON result size before the enclosing FCP response is checked.
pub const MAX_RESULT_BYTES: u64 = 8 * 1024 * 1024;
const MAX_SQL_BYTES: i32 = 1024 * 1024;
const MAX_VALUE_BYTES: i32 = 8 * 1024 * 1024;
const PROGRESS_INTERVAL: i32 = 1_000;

#[derive(Clone, Copy)]
struct InvocationLimits {
    deadline: Instant,
    result_bytes: u64,
}

/// Owns the execution budget without borrowing the client during dispatch.
/// Dropping it also releases a deadline after a failed or abandoned invocation.
pub struct SqliteInvocationGuard {
    limits: Arc<Mutex<Option<InvocationLimits>>>,
}

impl Drop for SqliteInvocationGuard {
    fn drop(&mut self) {
        if let Ok(mut limits) = self.limits.lock() {
            *limits = None;
        }
    }
}

/// Counts serialized bytes without allocating another copy of the result.
struct ResultBudget {
    remaining: u64,
    limit: u64,
}

impl ResultBudget {
    const fn new(limit: u64) -> Self {
        Self {
            remaining: limit,
            limit,
        }
    }

    fn charge(&mut self, bytes: u64) -> SqliteResult<()> {
        self.remaining = self
            .remaining
            .checked_sub(bytes)
            .ok_or(SqliteError::ResultLimit {
                resource: "JSON bytes",
                limit: self.limit,
            })?;
        Ok(())
    }

    fn charge_json(&mut self, value: &(impl Serialize + ?Sized)) -> SqliteResult<()> {
        serde_json::to_writer(&mut *self, value).map_err(|_| SqliteError::ResultLimit {
            resource: "JSON bytes",
            limit: self.limit,
        })
    }
}

impl Write for ResultBudget {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.charge(bytes.len() as u64).map_err(io::Error::other)?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AuthorizerPolicy {
    ReadOnly,
    Write,
    PragmaRead,
}

fn authorize_read_only(ctx: AuthContext<'_>) -> Authorization {
    authorize(AuthorizerPolicy::ReadOnly, ctx)
}

fn authorize_write(ctx: AuthContext<'_>) -> Authorization {
    authorize(AuthorizerPolicy::Write, ctx)
}

fn authorize_pragma_read(ctx: AuthContext<'_>) -> Authorization {
    authorize(AuthorizerPolicy::PragmaRead, ctx)
}

fn authorize(policy: AuthorizerPolicy, ctx: AuthContext<'_>) -> Authorization {
    match ctx.action {
        AuthAction::Attach { .. }
        | AuthAction::Detach { .. }
        | AuthAction::CreateVtable { .. }
        | AuthAction::DropVtable { .. } => Authorization::Deny,
        AuthAction::Function { function_name }
            if function_name.eq_ignore_ascii_case("load_extension") =>
        {
            Authorization::Deny
        }
        AuthAction::Pragma { .. } => match policy {
            AuthorizerPolicy::PragmaRead => Authorization::Allow,
            AuthorizerPolicy::ReadOnly | AuthorizerPolicy::Write => Authorization::Deny,
        },
        AuthAction::Transaction { .. } => Authorization::Deny,
        // Only allow the batch wrapper's own savepoint under Write; reject all
        // user-supplied SAVEPOINT/RELEASE/ROLLBACK TO statements so callers
        // cannot implicitly open nested transactions.
        AuthAction::Savepoint { savepoint_name, .. }
            if matches!(policy, AuthorizerPolicy::Write)
                && savepoint_name == "fcp_sqlite_batch" =>
        {
            Authorization::Allow
        }
        AuthAction::Savepoint { .. } => Authorization::Deny,
        AuthAction::Select | AuthAction::Read { .. } | AuthAction::Recursive => {
            Authorization::Allow
        }
        AuthAction::Function { .. } => Authorization::Allow,
        _ => match policy {
            AuthorizerPolicy::ReadOnly | AuthorizerPolicy::PragmaRead => Authorization::Deny,
            AuthorizerPolicy::Write => Authorization::Allow,
        },
    }
}

/// Local SQLite client.
pub struct SqliteClient {
    config: SqliteConfig,
    connection: Connection,
    invocation_limits: Arc<Mutex<Option<InvocationLimits>>>,
    cleanup_failed: Cell<bool>,
}

impl fmt::Debug for SqliteClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SqliteClient")
            .field("config", &self.config)
            .finish()
    }
}

impl SqliteClient {
    /// Open a SQLite client using the supplied configuration.
    pub fn new(config: SqliteConfig) -> SqliteResult<Self> {
        // rusqlite's busy_timeout panics when milliseconds do not fit i32.
        if config.busy_timeout_ms == 0 || config.busy_timeout_ms > i32::MAX as u64 {
            return Err(SqliteError::InvalidConfig(
                "busy_timeout_ms must be between 1 and 2147483647".into(),
            ));
        }
        let connection = open_connection(&config)?;
        connection.set_limit(Limit::SQLITE_LIMIT_LENGTH, MAX_VALUE_BYTES)?;
        connection.set_limit(Limit::SQLITE_LIMIT_SQL_LENGTH, MAX_SQL_BYTES)?;
        apply_connection_settings(&connection, &config)?;
        let invocation_limits = Arc::new(Mutex::new(None::<InvocationLimits>));
        let progress_limits = Arc::clone(&invocation_limits);
        connection.progress_handler(
            PROGRESS_INTERVAL,
            Some(move || match progress_limits.lock() {
                Ok(limits) => limits.is_some_and(|limits| Instant::now() >= limits.deadline),
                // Unavailable budget state cannot authorize unbounded SQL.
                Err(_) => true,
            }),
        )?;
        Ok(Self {
            config,
            connection,
            invocation_limits,
            cleanup_failed: Cell::new(false),
        })
    }

    /// Install one monotonic invocation deadline and its admitted response cap.
    /// The guard must cover the complete synchronous dispatch, including batches.
    pub fn begin_invocation(
        &self,
        deadline: Instant,
        response_byte_limit: u64,
    ) -> SqliteResult<SqliteInvocationGuard> {
        if deadline <= Instant::now() {
            return Err(SqliteError::DeadlineExceeded);
        }
        if response_byte_limit == 0 {
            return Err(SqliteError::ResultLimit {
                resource: "JSON bytes",
                limit: 0,
            });
        }
        let mut limits = self
            .invocation_limits
            .lock()
            .map_err(|_| SqliteError::Policy("SQLite execution budget is unavailable".into()))?;
        if limits.is_some() {
            return Err(SqliteError::Policy(
                "an SQLite invocation is already active".into(),
            ));
        }
        *limits = Some(InvocationLimits {
            deadline,
            result_bytes: response_byte_limit.min(MAX_RESULT_BYTES),
        });
        drop(limits);
        Ok(SqliteInvocationGuard {
            limits: Arc::clone(&self.invocation_limits),
        })
    }

    /// Inspect SQLite's actual transaction state after errors or interruption.
    #[must_use]
    pub fn is_in_transaction(&self) -> bool {
        !self.connection.is_autocommit()
    }

    fn limits(&self) -> SqliteResult<Option<InvocationLimits>> {
        self.invocation_limits
            .lock()
            .map(|limits| *limits)
            .map_err(|_| SqliteError::Policy("SQLite execution budget is unavailable".into()))
    }

    fn check_execution(&self) -> SqliteResult<()> {
        if self.cleanup_failed.get() {
            return Err(SqliteError::Transaction(
                "SQLite cleanup failed; reconfigure the connector before further execution".into(),
            ));
        }
        let mut wait = Duration::from_millis(self.config.busy_timeout_ms);
        if let Some(limits) = self.limits()? {
            let remaining = limits.deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(SqliteError::DeadlineExceeded);
            }
            wait = wait.min(remaining);
        }
        self.connection.busy_timeout(wait)?;
        Ok(())
    }

    fn result_budget(&self) -> SqliteResult<ResultBudget> {
        Ok(ResultBudget::new(
            self.limits()?
                .map_or(MAX_RESULT_BYTES, |limits| limits.result_bytes),
        ))
    }

    fn classify_execution<T>(&self, result: SqliteResult<T>) -> SqliteResult<T> {
        if self
            .limits()?
            .is_some_and(|limits| Instant::now() >= limits.deadline)
        {
            return Err(SqliteError::DeadlineExceeded);
        }
        result
    }

    fn require_writable(&self) -> SqliteResult<()> {
        if self.config.read_only {
            return Err(SqliteError::Policy(
                "SQLite database is configured read-only".into(),
            ));
        }
        Ok(())
    }

    /// Read the client configuration.
    #[must_use]
    pub const fn config(&self) -> &SqliteConfig {
        &self.config
    }

    /// Health probe against the currently open database.
    pub fn health_check(&self) -> SqliteResult<SqliteHealth> {
        self.check_execution()?;
        let query_ok = self
            .connection
            .query_row("SELECT 1", [], |row| row.get::<_, i64>(0))
            .map(|value| value == 1)?;
        let journal_mode = self
            .connection
            .pragma_query_value(None, "journal_mode", |row| row.get::<_, String>(0))
            .ok();

        Ok(SqliteHealth {
            query_ok,
            database_path: self.config.database_path.clone(),
            read_only: self.config.read_only,
            journal_mode,
        })
    }

    /// Execute a read-only query.
    pub fn query(&self, sql: &str, params: &[serde_json::Value]) -> SqliteResult<QueryResult> {
        self.with_authorizer(AuthorizerPolicy::ReadOnly, |connection| {
            let mut statement = connection.prepare(sql).map_err(read_only_prepare_error)?;
            if !statement.readonly() {
                return Err(SqliteError::Policy(
                    "sqlite.query accepts only read-only statements".into(),
                ));
            }
            collect_query_result(&mut statement, params, self.result_budget()?)
        })
    }

    /// Execute `EXPLAIN QUERY PLAN` for a read-only query.
    pub fn explain(&self, sql: &str, params: &[serde_json::Value]) -> SqliteResult<QueryResult> {
        self.with_authorizer(AuthorizerPolicy::ReadOnly, |connection| {
            let statement = connection.prepare(sql).map_err(read_only_prepare_error)?;
            if !statement.readonly() {
                return Err(SqliteError::Policy(
                    "sqlite.explain accepts only read-only statements".into(),
                ));
            }
            drop(statement);
            let explain_sql = format!("EXPLAIN QUERY PLAN {sql}");
            let mut statement = connection.prepare(&explain_sql)?;
            collect_query_result(&mut statement, params, self.result_budget()?)
        })
    }

    /// Execute a single non-returning mutating statement.
    pub fn execute(&self, sql: &str, params: &[serde_json::Value]) -> SqliteResult<ExecuteResult> {
        self.require_writable()?;
        self.with_authorizer(AuthorizerPolicy::Write, |connection| {
            execute_statement(connection, sql, params)
        })
    }

    /// List user tables in the main database.
    pub fn list_tables(&self) -> SqliteResult<Vec<TableInfo>> {
        self.check_execution()?;
        let mut budget = self.result_budget()?;
        budget.charge(16)?;
        let mut statement = self.connection.prepare(
            "SELECT schema, name, type, ncol, wr, strict \
             FROM pragma_table_list \
             WHERE schema = 'main' AND type = 'table' AND name NOT LIKE 'sqlite_%' \
             ORDER BY name",
        )?;
        let mut rows = statement.query([])?;
        let mut tables = Vec::new();

        while let Some(row) = rows.next()? {
            check_result_rows(tables.len())?;
            let table = TableInfo {
                schema: row.get::<_, String>(0)?,
                name: row.get::<_, String>(1)?,
                table_type: row.get::<_, String>(2)?,
                column_count: row.get::<_, i64>(3)? as u64,
                without_rowid: row.get::<_, i64>(4)? != 0,
                strict: row.get::<_, i64>(5)? != 0,
            };
            budget.charge_json(&table)?;
            budget.charge(1)?;
            tables.push(table);
        }

        self.classify_execution(Ok(tables))
    }

    /// Describe columns for a table.
    pub fn list_columns(&self, table: &str) -> SqliteResult<Vec<SchemaColumn>> {
        self.check_execution()?;
        let mut budget = self.result_budget()?;
        budget.charge(16)?;
        let mut statement = self.connection.prepare(
            "SELECT cid, name, type, \"notnull\", dflt_value, pk, hidden \
             FROM pragma_table_xinfo(?1) \
             ORDER BY cid",
        )?;
        let params = [serde_json::Value::String(table.to_string())];
        let values = json_params_to_sql_values(&params)?;
        let mut rows = statement.query(params_from_iter(values.iter()))?;
        let mut columns = Vec::new();

        while let Some(row) = rows.next()? {
            check_result_rows(columns.len())?;
            let column = SchemaColumn {
                cid: row.get::<_, i64>(0)?,
                name: row.get::<_, String>(1)?,
                data_type: row.get::<_, String>(2)?,
                not_null: row.get::<_, i64>(3)? != 0,
                default_value: row.get::<_, Option<String>>(4)?,
                primary_key: row.get::<_, i64>(5)? != 0,
                hidden: row.get::<_, i64>(6)? != 0,
            };
            budget.charge_json(&column)?;
            budget.charge(1)?;
            columns.push(column);
        }

        self.classify_execution(Ok(columns))
    }

    /// Begin a transaction with the requested mode.
    pub fn begin_transaction(&self, mode: TransactionMode) -> SqliteResult<()> {
        self.require_writable()?;
        self.check_execution()?;
        self.classify_execution(
            self.connection
                .execute_batch(mode.begin_sql())
                .map_err(Into::into),
        )
    }

    /// Commit the active transaction.
    pub fn commit_transaction(&self) -> SqliteResult<()> {
        self.check_execution()?;
        self.classify_execution(self.connection.execute_batch("COMMIT").map_err(Into::into))
    }

    /// Roll back the active transaction.
    pub fn rollback_transaction(&self) -> SqliteResult<()> {
        self.check_execution()?;
        self.classify_execution(
            self.connection
                .execute_batch("ROLLBACK")
                .map_err(Into::into),
        )
    }

    /// Execute a batch atomically via a savepoint.
    pub fn batch(&self, statements: &[BatchStatement]) -> SqliteResult<Vec<BatchStatementResult>> {
        self.require_writable()?;
        if statements.is_empty() {
            return Err(SqliteError::InvalidInput(
                "sqlite.batch requires at least one statement".into(),
            ));
        }
        if statements.len() > MAX_RESULT_ROWS {
            return Err(SqliteError::ResultLimit {
                resource: "batch statements",
                limit: MAX_RESULT_ROWS as u64,
            });
        }

        self.with_authorizer(AuthorizerPolicy::Write, |connection| {
            let mut budget = self.result_budget()?;
            budget.charge(16)?;
            connection.execute_batch("SAVEPOINT fcp_sqlite_batch")?;

            let result = (|| {
                let mut results = Vec::with_capacity(statements.len());
                for (index, statement) in statements.iter().enumerate() {
                    // A batch spends one deadline; each statement only gets
                    // the remaining lock-wait allowance, never a new budget.
                    self.check_execution()?;
                    let exec = execute_statement(connection, &statement.sql, &statement.params)?;
                    let result = BatchStatementResult {
                        index,
                        rows_affected: exec.rows_affected,
                        last_insert_rowid: exec.last_insert_rowid,
                    };
                    budget.charge_json(&result)?;
                    budget.charge(1)?;
                    results.push(result);
                }
                self.check_execution()?;
                connection.execute_batch("RELEASE SAVEPOINT fcp_sqlite_batch")?;
                Ok(results)
            })();

            match result {
                Ok(results) => Ok(results),
                Err(error) => {
                    self.rollback_batch()?;
                    Err(error)
                }
            }
        })
    }

    /// Read an allowlisted pragma.
    pub fn read_pragma(&self, name: &str) -> SqliteResult<QueryResult> {
        let normalized = Self::validate_pragma_name(name)?;

        self.with_authorizer(AuthorizerPolicy::PragmaRead, |connection| {
            let sql = format!("PRAGMA {normalized}");
            let mut statement = connection.prepare(&sql)?;
            collect_query_result(&mut statement, &[], self.result_budget()?)
        })
    }

    /// Validate a pragma for both preflight and execution without touching SQLite.
    pub fn validate_pragma_name(name: &str) -> SqliteResult<String> {
        let normalized = normalize_pragma_name(name)?;
        if !ALLOWED_PRAGMAS.contains(&normalized.as_str()) {
            return Err(SqliteError::Pragma(format!(
                "pragma `{normalized}` is not allowlisted"
            )));
        }

        Ok(normalized)
    }

    /// Run `VACUUM`.
    pub fn vacuum(&self) -> SqliteResult<ExecuteResult> {
        self.require_writable()?;
        self.check_execution()?;
        self.classify_execution(self.connection.execute_batch("VACUUM").map_err(Into::into))?;
        Ok(ExecuteResult {
            rows_affected: 0,
            last_insert_rowid: self.connection.last_insert_rowid(),
        })
    }

    fn with_authorizer<T>(
        &self,
        policy: AuthorizerPolicy,
        operation: impl FnOnce(&Connection) -> SqliteResult<T>,
    ) -> SqliteResult<T> {
        self.check_execution()?;
        let hook = match policy {
            AuthorizerPolicy::ReadOnly => {
                authorize_read_only as fn(AuthContext<'_>) -> Authorization
            }
            AuthorizerPolicy::Write => authorize_write as fn(AuthContext<'_>) -> Authorization,
            AuthorizerPolicy::PragmaRead => {
                authorize_pragma_read as fn(AuthContext<'_>) -> Authorization
            }
        };
        self.connection.authorizer(Some(hook))?;

        let operation_result = operation(&self.connection);
        let reset_result = self
            .connection
            .authorizer(None::<fn(AuthContext<'_>) -> Authorization>);

        let result = match (operation_result, reset_result) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), Ok(())) => Err(error),
            (Ok(_), Err(reset_error)) => Err(SqliteError::from(reset_error)),
            (Err(error), Err(_)) => Err(error),
        };
        self.classify_execution(result)
    }

    fn rollback_batch(&self) -> SqliteResult<()> {
        // SQLITE_INTERRUPT can already have rolled back the entire transaction.
        if self.connection.is_autocommit() {
            return Ok(());
        }
        // Cleanup must still run after the caller's deadline. It performs only
        // these fixed savepoint statements, with no lock wait or user SQL. The
        // progress callback is suspended so it cannot interrupt the rollback.
        let previous = self
            .invocation_limits
            .lock()
            .map_err(|_| SqliteError::Policy("SQLite execution budget is unavailable".into()))?
            .take();
        let result = self.connection.busy_timeout(Duration::ZERO).and_then(|()| {
            self.connection.execute_batch(
                "ROLLBACK TO SAVEPOINT fcp_sqlite_batch; RELEASE SAVEPOINT fcp_sqlite_batch",
            )
        });
        *self
            .invocation_limits
            .lock()
            .map_err(|_| SqliteError::Policy("SQLite execution budget is unavailable".into()))? =
            previous;
        if result.is_err() {
            self.cleanup_failed.set(true);
            return Err(SqliteError::Transaction(
                "SQLite batch rollback failed; reconfigure the connector before further execution"
                    .into(),
            ));
        }
        Ok(())
    }
}

fn read_only_prepare_error(error: rusqlite::Error) -> SqliteError {
    if error.sqlite_error_code() == Some(rusqlite::ErrorCode::AuthorizationForStatementDenied) {
        SqliteError::Policy("statement is not permitted by the SQLite read-only policy".into())
    } else {
        SqliteError::Rusqlite(error)
    }
}

fn open_connection(config: &SqliteConfig) -> SqliteResult<Connection> {
    if config.database_path == ":memory:" {
        return Ok(Connection::open_in_memory()?);
    }

    let mut flags = if config.read_only {
        OpenFlags::SQLITE_OPEN_READ_ONLY
    } else {
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | if config.create_if_missing {
                OpenFlags::SQLITE_OPEN_CREATE
            } else {
                OpenFlags::empty()
            }
    };
    flags |= OpenFlags::SQLITE_OPEN_URI;

    Ok(Connection::open_with_flags(
        Path::new(&config.database_path),
        flags,
    )?)
}

fn apply_connection_settings(connection: &Connection, config: &SqliteConfig) -> SqliteResult<()> {
    connection.busy_timeout(Duration::from_millis(config.busy_timeout_ms))?;

    if !config.read_only {
        if config.enforce_foreign_keys {
            connection.execute_batch("PRAGMA foreign_keys = ON")?;
        }

        if config.enable_wal && config.database_path != ":memory:" {
            match connection
                .pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get::<_, String>(0))
            {
                Ok(mode) if mode.eq_ignore_ascii_case("wal") => {}
                Ok(mode) => warn!(mode, "SQLite did not enter WAL mode"),
                Err(error) => warn!(%error, "Failed to request WAL mode"),
            }
        }
    }

    Ok(())
}

fn execute_statement(
    connection: &Connection,
    sql: &str,
    params: &[serde_json::Value],
) -> SqliteResult<ExecuteResult> {
    let mut statement = connection.prepare(sql)?;
    if statement.readonly() {
        return Err(SqliteError::Policy(
            "sqlite.execute accepts only mutating or DDL statements".into(),
        ));
    }
    if statement.column_count() > 0 {
        return Err(SqliteError::Policy(
            "sqlite.execute does not support statements that return rows".into(),
        ));
    }

    let values = json_params_to_sql_values(params)?;
    let rows_affected = statement.execute(params_from_iter(values.iter()))?;

    Ok(ExecuteResult {
        rows_affected: rows_affected as u64,
        last_insert_rowid: connection.last_insert_rowid(),
    })
}

fn collect_query_result(
    statement: &mut rusqlite::Statement<'_>,
    params: &[serde_json::Value],
    mut budget: ResultBudget,
) -> SqliteResult<QueryResult> {
    let columns = statement
        .columns()
        .into_iter()
        .enumerate()
        .map(|(ordinal, column)| QueryColumn {
            ordinal,
            name: column.name().to_string(),
            decl_type: column.decl_type().map(str::to_string),
        })
        .collect::<Vec<_>>();
    // Account for result keys, separators and row_count before retaining rows.
    budget.charge(64)?;
    budget.charge_json(&columns)?;

    let values = json_params_to_sql_values(params)?;
    let mut rows = statement.query(params_from_iter(values.iter()))?;
    let mut result_rows = Vec::new();

    while let Some(row) = rows.next()? {
        check_result_rows(result_rows.len())?;
        budget.charge(3)?;
        let mut result_row = Vec::with_capacity(columns.len());
        for index in 0..columns.len() {
            // Borrow first: reject an oversized text/blob before copying it or
            // allocating its larger escaped JSON/base64 representation.
            let value = row.get_ref(index)?;
            result_row.push(sql_value_to_json(value, &mut budget)?);
            budget.charge(1)?;
        }
        result_rows.push(result_row);
    }

    Ok(QueryResult {
        columns,
        row_count: result_rows.len() as u64,
        rows: result_rows,
    })
}

fn check_result_rows(retained: usize) -> SqliteResult<()> {
    if retained >= MAX_RESULT_ROWS {
        return Err(SqliteError::ResultLimit {
            resource: "rows",
            limit: MAX_RESULT_ROWS as u64,
        });
    }
    Ok(())
}

fn json_params_to_sql_values(params: &[serde_json::Value]) -> SqliteResult<Vec<SqlValue>> {
    params.iter().map(json_to_sql_value).collect()
}

fn json_to_sql_value(value: &serde_json::Value) -> SqliteResult<SqlValue> {
    match value {
        serde_json::Value::Null => Ok(SqlValue::Null),
        serde_json::Value::Bool(flag) => Ok(SqlValue::Integer(i64::from(*flag))),
        serde_json::Value::Number(number) => {
            if let Some(integer) = number.as_i64() {
                Ok(SqlValue::Integer(integer))
            } else if let Some(float) = number.as_f64() {
                Ok(SqlValue::Real(float))
            } else {
                Err(SqliteError::InvalidInput(format!(
                    "unsupported JSON number `{number}`"
                )))
            }
        }
        serde_json::Value::String(text) => Ok(SqlValue::Text(text.clone())),
        serde_json::Value::Array(_) | serde_json::Value::Object(_) => {
            Ok(SqlValue::Text(serde_json::to_string(value)?))
        }
    }
}

fn sql_value_to_json(
    value: ValueRef<'_>,
    budget: &mut ResultBudget,
) -> SqliteResult<serde_json::Value> {
    let scalar = match value {
        ValueRef::Null => serde_json::Value::Null,
        ValueRef::Integer(integer) => json!(integer),
        ValueRef::Real(real) => serde_json::Number::from_f64(real).map_or_else(
            || serde_json::Value::String(real.to_string()),
            serde_json::Value::Number,
        ),
        ValueRef::Text(bytes) => {
            let text = std::str::from_utf8(bytes)
                .map_err(|_| SqliteError::Query("SQLite text result is not valid UTF-8".into()))?;
            budget.charge_json(text)?;
            return Ok(serde_json::Value::String(text.to_owned()));
        }
        ValueRef::Blob(bytes) => {
            let encoded_bytes = (bytes.len() as u64).div_ceil(3).saturating_mul(4);
            budget.charge(encoded_bytes.saturating_add(19))?;
            return Ok(json!({
                "$blob_base64": BASE64.encode(bytes),
            }));
        }
    };
    budget.charge_json(&scalar)?;
    Ok(scalar)
}

fn normalize_pragma_name(name: &str) -> SqliteResult<String> {
    let normalized = name.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return Err(SqliteError::Pragma("pragma name must not be empty".into()));
    }
    if !normalized.chars().all(|character| {
        character.is_ascii_lowercase() || character == '_' || character.is_ascii_digit()
    }) {
        return Err(SqliteError::Pragma(format!(
            "pragma `{name}` contains unsupported characters"
        )));
    }
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn memory_client() -> SqliteClient {
        SqliteClient::new(SqliteConfig {
            database_path: ":memory:".into(),
            read_only: false,
            create_if_missing: true,
            busy_timeout_ms: 5_000,
            enable_wal: false,
            enforce_foreign_keys: true,
        })
        .unwrap()
    }

    #[test]
    fn normalize_pragma_name_lowercases_supported_names() {
        assert_eq!(
            normalize_pragma_name("Journal_Mode").unwrap(),
            "journal_mode"
        );
    }

    #[test]
    fn normalize_pragma_name_rejects_invalid_characters() {
        let error = normalize_pragma_name("journal-mode").unwrap_err();
        assert!(matches!(error, SqliteError::Pragma(_)));
    }

    #[test]
    fn json_arrays_are_serialized_as_text_parameters() {
        let value = json_to_sql_value(&json!([1, 2, 3])).unwrap();
        assert_eq!(value, SqlValue::Text("[1,2,3]".into()));
    }

    #[test]
    fn sql_blob_values_are_base64_wrapped() {
        let json =
            sql_value_to_json(ValueRef::Blob(&[1, 2, 3]), &mut ResultBudget::new(1024)).unwrap();
        assert_eq!(json["$blob_base64"], "AQID");
    }

    #[test]
    fn result_rows_fail_explicitly_without_truncated_success() {
        let client = memory_client();
        let error = client.query(
            "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x + 1 FROM n WHERE x < 10001) SELECT x FROM n",
            &[],
        ).unwrap_err();
        assert!(matches!(
            error,
            SqliteError::ResultLimit {
                resource: "rows",
                limit: 10_000
            }
        ));
        let exact = client.query(
            "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x + 1 FROM n WHERE x < 10000) SELECT x FROM n",
            &[],
        ).unwrap();
        assert_eq!(exact.row_count, 10_000);
        assert_eq!(client.query("SELECT 1", &[]).unwrap().row_count, 1);
    }

    #[test]
    fn string_and_blob_limits_count_encoded_bytes_before_allocation() {
        let mut escaped = ResultBudget::new(4);
        assert_eq!(
            sql_value_to_json(ValueRef::Text(b"\n"), &mut escaped).unwrap(),
            json!("\n")
        );
        assert_eq!(escaped.remaining, 0);
        assert!(sql_value_to_json(ValueRef::Text(b"\n"), &mut ResultBudget::new(3)).is_err());
        let mut blob = ResultBudget::new(23);
        assert_eq!(
            sql_value_to_json(ValueRef::Blob(&[1, 2, 3]), &mut blob).unwrap(),
            json!({"$blob_base64": "AQID"})
        );
        assert_eq!(blob.remaining, 0);
        assert!(sql_value_to_json(ValueRef::Blob(&[1, 2, 3]), &mut ResultBudget::new(22)).is_err());
    }

    #[test]
    fn invalid_utf8_text_is_refused_without_returning_database_bytes() {
        let client = memory_client();
        let error = client.query("SELECT CAST(x'ff' AS TEXT)", &[]).unwrap_err();
        assert_eq!(
            error.to_string(),
            "SQLite query error: SQLite text result is not valid UTF-8"
        );
        assert!(!error.is_retryable());
        assert!(client.query("SELECT 1", &[]).is_ok());
    }

    #[test]
    fn signed_response_cap_narrows_the_result_budget() {
        let client = memory_client();
        let guard = client
            .begin_invocation(Instant::now() + Duration::from_secs(5), 256)
            .unwrap();
        assert!(client.query("SELECT 1", &[]).is_ok());
        assert!(matches!(
            client.query("SELECT ?1", &[json!("x".repeat(300))]),
            Err(SqliteError::ResultLimit { limit: 256, .. })
        ));
        drop(guard);
        assert!(client.query("SELECT ?1", &[json!("x".repeat(300))]).is_ok());
    }

    #[test]
    fn recursive_aggregate_is_interrupted_and_next_invocation_can_run() {
        let client = memory_client();
        let guard = client
            .begin_invocation(Instant::now() + Duration::from_millis(20), MAX_RESULT_BYTES)
            .unwrap();
        let result = client.query(
            "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x + 1 FROM n) SELECT sum(x) FROM n",
            &[],
        );
        assert!(matches!(result, Err(SqliteError::DeadlineExceeded)));
        drop(guard);
        let _guard = client
            .begin_invocation(Instant::now() + Duration::from_secs(5), MAX_RESULT_BYTES)
            .unwrap();
        assert_eq!(
            client.query("SELECT 7", &[]).unwrap().rows,
            vec![vec![json!(7)]]
        );
    }

    #[test]
    fn expired_and_nested_admission_never_replace_the_live_budget() {
        let client = memory_client();
        assert!(matches!(
            client.begin_invocation(Instant::now(), MAX_RESULT_BYTES),
            Err(SqliteError::DeadlineExceeded)
        ));
        let guard = client
            .begin_invocation(Instant::now() + Duration::from_secs(1), 128)
            .unwrap();
        assert!(
            client
                .begin_invocation(Instant::now() + Duration::from_secs(30), MAX_RESULT_BYTES)
                .is_err()
        );
        assert_eq!(client.result_budget().unwrap().limit, 128);
        drop(guard);
        assert_eq!(client.result_budget().unwrap().limit, MAX_RESULT_BYTES);
    }

    #[test]
    fn batch_response_limit_rolls_back_every_statement() {
        let client = memory_client();
        client
            .execute("CREATE TABLE items (value INTEGER)", &[])
            .unwrap();
        let statements = (0..8)
            .map(|index| BatchStatement {
                sql: "INSERT INTO items VALUES (?1)".into(),
                params: vec![json!(index)],
            })
            .collect::<Vec<_>>();
        let guard = client
            .begin_invocation(Instant::now() + Duration::from_secs(5), 128)
            .unwrap();
        assert!(matches!(
            client.batch(&statements),
            Err(SqliteError::ResultLimit { .. })
        ));
        assert!(!client.is_in_transaction());
        drop(guard);
        assert_eq!(
            client
                .query("SELECT count(*) FROM items", &[])
                .unwrap()
                .rows,
            vec![vec![json!(0)]]
        );
    }

    #[test]
    fn batch_response_limit_preserves_prior_outer_transaction_work() {
        let client = memory_client();
        client
            .execute("CREATE TABLE items (value INTEGER)", &[])
            .unwrap();
        client
            .begin_transaction(TransactionMode::Immediate)
            .unwrap();
        client
            .execute("INSERT INTO items VALUES (99)", &[])
            .unwrap();
        let statements = (0..8)
            .map(|index| BatchStatement {
                sql: "INSERT INTO items VALUES (?1)".into(),
                params: vec![json!(index)],
            })
            .collect::<Vec<_>>();
        let guard = client
            .begin_invocation(Instant::now() + Duration::from_secs(5), 128)
            .unwrap();
        assert!(matches!(
            client.batch(&statements),
            Err(SqliteError::ResultLimit { .. })
        ));
        assert!(client.is_in_transaction());
        drop(guard);
        client.commit_transaction().unwrap();
        assert_eq!(
            client.query("SELECT value FROM items", &[]).unwrap().rows,
            vec![vec![json!(99)]]
        );
    }

    #[test]
    fn interrupted_batch_exposes_sqlite_automatic_outer_rollback() {
        let client = memory_client();
        client
            .execute("CREATE TABLE items (value INTEGER)", &[])
            .unwrap();
        client
            .begin_transaction(TransactionMode::Immediate)
            .unwrap();
        client
            .execute("INSERT INTO items VALUES (99)", &[])
            .unwrap();
        let statements = vec![BatchStatement {
            sql: "INSERT INTO items WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x + 1 FROM n) SELECT x FROM n".into(),
            params: vec![],
        }];
        let guard = client
            .begin_invocation(Instant::now() + Duration::from_secs(30), MAX_RESULT_BYTES)
            .unwrap();
        // Expire the real budget only after the INSERT is executing. A tiny
        // wall-clock deadline could instead expire before dispatch on a loaded
        // machine, which correctly leaves the outer transaction untouched.
        let limits = Arc::clone(&client.invocation_limits);
        let mut callbacks = 0;
        client
            .connection
            .progress_handler(
                PROGRESS_INTERVAL,
                Some(move || {
                    callbacks += 1;
                    if callbacks < 5 {
                        return false;
                    }
                    if let Some(limits) = limits.lock().unwrap().as_mut() {
                        limits.deadline = Instant::now();
                        true
                    } else {
                        false
                    }
                }),
            )
            .unwrap();
        assert!(matches!(
            client.batch(&statements),
            Err(SqliteError::DeadlineExceeded)
        ));
        assert!(!client.is_in_transaction());
        drop(guard);
        assert_eq!(
            client
                .query("SELECT count(*) FROM items", &[])
                .unwrap()
                .rows,
            vec![vec![json!(0)]]
        );
    }

    #[test]
    fn engine_limits_reject_huge_values_and_sql_without_losing_connection() {
        let client = memory_client();
        assert!(client.query("SELECT zeroblob(8388609)", &[]).is_err());
        assert!(
            client
                .query(
                    &format!("SELECT 1{}", " ".repeat(MAX_SQL_BYTES as usize)),
                    &[]
                )
                .is_err()
        );
        assert_eq!(client.query("SELECT 1", &[]).unwrap().row_count, 1);
    }

    #[test]
    fn oversized_batch_is_refused_before_any_statement() {
        let client = memory_client();
        let statements = vec![
            BatchStatement {
                sql: "CREATE TABLE must_not_exist (value INTEGER)".into(),
                params: vec![]
            };
            MAX_RESULT_ROWS + 1
        ];
        assert!(matches!(
            client.batch(&statements),
            Err(SqliteError::ResultLimit {
                resource: "batch statements",
                ..
            })
        ));
        assert!(client.list_tables().unwrap().is_empty());
    }

    #[test]
    fn read_only_memory_databases_refuse_writes_and_transactions() {
        let mut config = memory_client().config().clone();
        config.read_only = true;
        let client = SqliteClient::new(config).unwrap();
        assert!(
            client
                .execute("CREATE TABLE nope (id INTEGER)", &[])
                .is_err()
        );
        assert!(client.begin_transaction(TransactionMode::Deferred).is_err());
        assert!(client.vacuum().is_err());
        assert!(client.query("SELECT 1", &[]).is_ok());
    }

    #[test]
    fn busy_timeout_overflow_is_a_configuration_error_not_a_panic() {
        let mut config = memory_client().config().clone();
        config.busy_timeout_ms = u64::MAX;
        assert!(matches!(
            SqliteClient::new(config),
            Err(SqliteError::InvalidConfig(_))
        ));
    }

    #[test]
    fn lock_wait_is_narrowed_to_remaining_invocation_time() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("busy.sqlite");
        let mut config = memory_client().config().clone();
        config.database_path = path.to_string_lossy().into_owned();
        let client = SqliteClient::new(config).unwrap();
        client
            .execute("CREATE TABLE items (value INTEGER)", &[])
            .unwrap();
        let locker = Connection::open(&path).unwrap();
        locker.execute_batch("BEGIN EXCLUSIVE").unwrap();
        let guard = client
            .begin_invocation(Instant::now() + Duration::from_millis(25), MAX_RESULT_BYTES)
            .unwrap();
        let before = Instant::now();
        let result = client.execute("INSERT INTO items VALUES (1)", &[]);
        assert!(result.is_err());
        assert!(before.elapsed() < Duration::from_secs(2));
        drop(guard);
        locker.execute_batch("ROLLBACK").unwrap();
        assert_eq!(
            client
                .query("SELECT count(*) FROM items", &[])
                .unwrap()
                .rows,
            vec![vec![json!(0)]]
        );
    }
}
