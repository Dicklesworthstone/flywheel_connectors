//! Operation types and typed GraphQL traits.

use serde::{Deserialize, Serialize};

use crate::error::{GraphqlError, GraphqlLimitExceeded};

/// Default maximum GraphQL query text size in bytes.
pub const DEFAULT_MAX_QUERY_BYTES: usize = 64 * 1024;
/// Default maximum GraphQL selection-set depth.
pub const DEFAULT_MAX_QUERY_DEPTH: usize = 10;
/// Default maximum alias count in a single GraphQL request.
pub const DEFAULT_MAX_QUERY_ALIASES: usize = 50;
/// Default maximum root field count in a single GraphQL operation.
pub const DEFAULT_MAX_QUERY_ROOT_FIELDS: usize = 50;

/// Default GraphQL query limits used by clients and subscriptions.
pub const DEFAULT_GRAPHQL_QUERY_LIMITS: GraphqlQueryLimits = GraphqlQueryLimits {
    max_query_bytes: DEFAULT_MAX_QUERY_BYTES,
    max_depth: DEFAULT_MAX_QUERY_DEPTH,
    max_aliases: DEFAULT_MAX_QUERY_ALIASES,
    max_root_fields: DEFAULT_MAX_QUERY_ROOT_FIELDS,
    introspection: GraphqlIntrospectionPolicy::Allow,
};

/// Schema introspection handling for GraphQL query validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GraphqlIntrospectionPolicy {
    /// Permit `__schema` and `__type` fields.
    Allow,
    /// Reject `__schema` and `__type` fields before dispatch.
    Deny,
}

/// Resource guardrails applied before GraphQL requests reach transport or resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GraphqlQueryLimits {
    /// Maximum query text size in bytes.
    pub max_query_bytes: usize,
    /// Maximum selection-set nesting depth.
    pub max_depth: usize,
    /// Maximum number of aliases in a request.
    pub max_aliases: usize,
    /// Maximum number of root fields in a request.
    pub max_root_fields: usize,
    /// Schema introspection policy enforced before request dispatch.
    pub introspection: GraphqlIntrospectionPolicy,
}

impl GraphqlQueryLimits {
    /// Construct explicit query limits.
    #[must_use]
    pub const fn new(
        max_query_bytes: usize,
        max_depth: usize,
        max_aliases: usize,
        max_root_fields: usize,
    ) -> Self {
        Self {
            max_query_bytes,
            max_depth,
            max_aliases,
            max_root_fields,
            introspection: GraphqlIntrospectionPolicy::Allow,
        }
    }

    /// Override schema introspection handling.
    #[must_use]
    pub const fn with_introspection_policy(
        mut self,
        introspection: GraphqlIntrospectionPolicy,
    ) -> Self {
        self.introspection = introspection;
        self
    }

    /// Validate a query against this limit set.
    pub fn validate(self, query: &str) -> Result<(), GraphqlLimitExceeded> {
        validate_query_limits(query, self)
    }
}

impl Default for GraphqlQueryLimits {
    fn default() -> Self {
        DEFAULT_GRAPHQL_QUERY_LIMITS
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GraphqlToken<'a> {
    Name(&'a str),
    LBrace,
    RBrace,
    LParen,
    RParen,
    LBracket,
    RBracket,
    Colon,
    At,
    Ellipsis,
}

fn validate_query_limits(
    query: &str,
    limits: GraphqlQueryLimits,
) -> Result<(), GraphqlLimitExceeded> {
    if query.len() > limits.max_query_bytes {
        return Err(GraphqlLimitExceeded::QueryTooLarge {
            actual_bytes: query.len(),
            max_bytes: limits.max_query_bytes,
        });
    }

    let tokens = tokenize_query(query);
    let mut selection_depth = 0usize;
    let mut max_depth_seen = 0usize;
    let mut paren_depth = 0usize;
    let mut bracket_depth = 0usize;
    let mut alias_count = 0usize;
    let mut root_field_count = 0usize;
    let mut alias_target_pending = false;
    let mut skip_directive_name = false;
    let mut inline_fragment_type_pending = false;

    for (index, token) in tokens.iter().enumerate() {
        match *token {
            GraphqlToken::LParen => {
                paren_depth = paren_depth.saturating_add(1);
            }
            GraphqlToken::RParen => {
                paren_depth = paren_depth.saturating_sub(1);
            }
            GraphqlToken::LBracket => {
                bracket_depth = bracket_depth.saturating_add(1);
            }
            GraphqlToken::RBracket => {
                bracket_depth = bracket_depth.saturating_sub(1);
            }
            GraphqlToken::LBrace if paren_depth == 0 && bracket_depth == 0 => {
                selection_depth = selection_depth.saturating_add(1);
                max_depth_seen = max_depth_seen.max(selection_depth);
                if max_depth_seen > limits.max_depth {
                    return Err(GraphqlLimitExceeded::DepthExceeded {
                        actual_depth: max_depth_seen,
                        max_depth: limits.max_depth,
                    });
                }
                alias_target_pending = false;
                skip_directive_name = false;
                inline_fragment_type_pending = false;
            }
            GraphqlToken::RBrace if paren_depth == 0 && bracket_depth == 0 => {
                selection_depth = selection_depth.saturating_sub(1);
                alias_target_pending = false;
                skip_directive_name = false;
                inline_fragment_type_pending = false;
            }
            GraphqlToken::At if in_selection_level(selection_depth, paren_depth, bracket_depth) => {
                skip_directive_name = true;
            }
            GraphqlToken::Ellipsis
                if in_selection_level(selection_depth, paren_depth, bracket_depth) =>
            {
                alias_target_pending = false;
                inline_fragment_type_pending = true;
            }
            GraphqlToken::Name(name)
                if in_selection_level(selection_depth, paren_depth, bracket_depth) =>
            {
                if skip_directive_name {
                    skip_directive_name = false;
                    continue;
                }
                if inline_fragment_type_pending {
                    if name != "on" {
                        inline_fragment_type_pending = false;
                    }
                    continue;
                }
                if alias_target_pending {
                    validate_introspection_field(name, limits.introspection)?;
                    alias_target_pending = false;
                    root_field_count = validate_root_field_count(
                        selection_depth,
                        root_field_count,
                        limits.max_root_fields,
                    )?;
                    continue;
                }
                if matches!(tokens.get(index + 1), Some(GraphqlToken::Colon)) {
                    alias_count = alias_count.saturating_add(1);
                    if alias_count > limits.max_aliases {
                        return Err(GraphqlLimitExceeded::AliasLimitExceeded {
                            actual_aliases: alias_count,
                            max_aliases: limits.max_aliases,
                        });
                    }
                    alias_target_pending = true;
                    continue;
                }
                validate_introspection_field(name, limits.introspection)?;
                root_field_count = validate_root_field_count(
                    selection_depth,
                    root_field_count,
                    limits.max_root_fields,
                )?;
            }
            _ => {}
        }
    }

    Ok(())
}

fn validate_introspection_field(
    name: &str,
    introspection: GraphqlIntrospectionPolicy,
) -> Result<(), GraphqlLimitExceeded> {
    if introspection == GraphqlIntrospectionPolicy::Deny && matches!(name, "__schema" | "__type") {
        return Err(GraphqlLimitExceeded::IntrospectionDisabled {
            field_name: name.to_string(),
        });
    }
    Ok(())
}

const fn validate_root_field_count(
    selection_depth: usize,
    root_field_count: usize,
    max_root_fields: usize,
) -> Result<usize, GraphqlLimitExceeded> {
    if selection_depth != 1 {
        return Ok(root_field_count);
    }
    let actual_root_fields = root_field_count.saturating_add(1);
    if actual_root_fields > max_root_fields {
        return Err(GraphqlLimitExceeded::RootFieldLimitExceeded {
            actual_root_fields,
            max_root_fields,
        });
    }
    Ok(actual_root_fields)
}

const fn in_selection_level(
    selection_depth: usize,
    paren_depth: usize,
    bracket_depth: usize,
) -> bool {
    selection_depth > 0 && paren_depth == 0 && bracket_depth == 0
}

fn tokenize_query(query: &str) -> Vec<GraphqlToken<'_>> {
    let bytes = query.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0usize;

    while index < bytes.len() {
        match bytes[index] {
            b'{' => {
                tokens.push(GraphqlToken::LBrace);
                index += 1;
            }
            b'}' => {
                tokens.push(GraphqlToken::RBrace);
                index += 1;
            }
            b'(' => {
                tokens.push(GraphqlToken::LParen);
                index += 1;
            }
            b')' => {
                tokens.push(GraphqlToken::RParen);
                index += 1;
            }
            b'[' => {
                tokens.push(GraphqlToken::LBracket);
                index += 1;
            }
            b']' => {
                tokens.push(GraphqlToken::RBracket);
                index += 1;
            }
            b':' => {
                tokens.push(GraphqlToken::Colon);
                index += 1;
            }
            b'@' => {
                tokens.push(GraphqlToken::At);
                index += 1;
            }
            b'.' if bytes.get(index..index + 3) == Some(b"...") => {
                tokens.push(GraphqlToken::Ellipsis);
                index += 3;
            }
            b'#' => {
                index = skip_comment(bytes, index);
            }
            b'"' if bytes.get(index..index + 3) == Some(b"\"\"\"") => {
                index = skip_block_string(bytes, index + 3);
            }
            b'"' => {
                index = skip_string(bytes, index + 1);
            }
            byte if is_name_start(byte) => {
                let start = index;
                index += 1;
                while index < bytes.len() && is_name_continue(bytes[index]) {
                    index += 1;
                }
                tokens.push(GraphqlToken::Name(&query[start..index]));
            }
            _ => {
                index += 1;
            }
        }
    }

    tokens
}

fn skip_comment(bytes: &[u8], mut index: usize) -> usize {
    while index < bytes.len() && bytes[index] != b'\n' && bytes[index] != b'\r' {
        index += 1;
    }
    index
}

/// Skip to the end of a block string, honouring the one escape the GraphQL
/// spec defines inside one: `\"""` is an escaped triple-quote, not a
/// terminator.
///
/// Treating `\"""` as a terminator desynchronised the tokenizer from the
/// document a real GraphQL server parses: the string closed early, the *real*
/// closing `"""` then opened a second block string with no terminator, and
/// this function swallowed the entire remainder of the query. Every guard
/// downstream — `max_depth`, `max_aliases`, `max_root_fields`, and the
/// `GraphqlIntrospectionPolicy::Deny` security policy — then saw an empty
/// token stream and passed a query the server would happily execute. A single
/// argument value of `"""a\"""b"""` was enough to disable all of them.
fn skip_block_string(bytes: &[u8], mut index: usize) -> usize {
    while index < bytes.len() {
        if bytes[index] == b'\\' {
            // Consume the backslash and whatever it escapes so an escaped
            // `"""` cannot be mistaken for the closing delimiter.
            index += 2;
            continue;
        }
        if bytes.get(index..index + 3) == Some(b"\"\"\"") {
            return index + 3;
        }
        index += 1;
    }
    bytes.len()
}

fn skip_string(bytes: &[u8], mut index: usize) -> usize {
    let mut escaped = false;
    while index < bytes.len() {
        let byte = bytes[index];
        if escaped {
            escaped = false;
        } else if byte == b'\\' {
            escaped = true;
        } else if byte == b'"' {
            return index + 1;
        }
        index += 1;
    }
    index
}

const fn is_name_start(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphabetic()
}

const fn is_name_continue(byte: u8) -> bool {
    is_name_start(byte) || byte.is_ascii_digit()
}

/// GraphQL query wrapper.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct GraphqlQuery {
    query: String,
}

impl GraphqlQuery {
    /// Create a new query from a string.
    #[must_use]
    pub fn new(query: impl Into<String>) -> Self {
        Self {
            query: query.into(),
        }
    }

    /// Create a new query from a static string.
    #[must_use]
    pub fn from_static(query: &'static str) -> Self {
        Self::new(query)
    }

    /// Return the query text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.query
    }
}

/// Typed GraphQL operation definition.
///
/// Implement this trait for each query/mutation/subscription.
pub trait GraphqlOperation {
    /// Variables type.
    type Variables: Serialize + Send + Sync;
    /// Response data type.
    type ResponseData: Serialize + for<'de> Deserialize<'de> + Send + Sync;

    /// GraphQL query text.
    const QUERY: &'static str;
    /// Operation name (used for observability and routing).
    const OPERATION_NAME: &'static str;

    /// Optional JSON Schema for variables.
    fn variables_schema() -> Option<&'static str> {
        None
    }

    /// Optional JSON Schema for response data.
    fn response_schema() -> Option<&'static str> {
        None
    }

    /// Whether this operation is safe to retry on transport errors.
    fn is_idempotent() -> bool {
        true
    }
}

/// GraphQL request payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphqlRequest<V> {
    /// Query text.
    pub query: GraphqlQuery,
    /// Variables.
    pub variables: V,
    /// Optional operation name.
    #[serde(rename = "operationName", skip_serializing_if = "Option::is_none")]
    pub operation_name: Option<String>,
}

impl<V> GraphqlRequest<V> {
    /// Create a new request.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn new(query: GraphqlQuery, variables: V) -> Self {
        Self {
            query,
            variables,
            operation_name: None,
        }
    }

    /// Attach an operation name.
    #[must_use]
    pub fn with_operation_name(mut self, name: impl Into<String>) -> Self {
        self.operation_name = Some(name.into());
        self
    }
}

/// GraphQL batch item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphqlBatchItem<V> {
    /// Query text.
    pub query: GraphqlQuery,
    /// Variables payload.
    pub variables: V,
    /// Optional operation name.
    #[serde(rename = "operationName", skip_serializing_if = "Option::is_none")]
    pub operation_name: Option<String>,
}

impl<V> GraphqlBatchItem<V> {
    /// Create a batch item.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn new(query: GraphqlQuery, variables: V) -> Self {
        Self {
            query,
            variables,
            operation_name: None,
        }
    }

    /// Attach an operation name.
    #[must_use]
    pub fn with_operation_name(mut self, name: impl Into<String>) -> Self {
        self.operation_name = Some(name.into());
        self
    }
}

/// GraphQL response container.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(deserialize = "T: Deserialize<'de>"))]
pub struct GraphqlResponse<T> {
    /// Response data.
    #[serde(default)]
    pub data: Option<T>,
    /// GraphQL errors.
    #[serde(default)]
    pub errors: Vec<GraphqlError>,
    /// Extensions payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<serde_json::Value>,
}

impl<T> GraphqlResponse<T> {
    /// Returns `true` if no GraphQL errors were returned.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        self.errors.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- GraphqlQuery ----

    #[test]
    fn query_new_and_as_str() {
        let q = GraphqlQuery::new("{ users { id } }");
        assert_eq!(q.as_str(), "{ users { id } }");
    }

    #[test]
    fn query_from_static() {
        let q = GraphqlQuery::from_static("query Foo { bar }");
        assert_eq!(q.as_str(), "query Foo { bar }");
    }

    #[test]
    fn query_serde_roundtrip() {
        let q = GraphqlQuery::new("{ ping }");
        let json = serde_json::to_string(&q).unwrap();
        assert_eq!(json, "\"{ ping }\"");
        let back: GraphqlQuery = serde_json::from_str(&json).unwrap();
        assert_eq!(q, back);
    }

    #[test]
    fn query_clone_eq() {
        let q = GraphqlQuery::new("{ x }");
        let q2 = q.clone();
        assert_eq!(q, q2);
    }

    #[test]
    fn query_limits_accept_default_query() {
        GraphqlQueryLimits::default()
            .validate("query Viewer { viewer { id } }")
            .unwrap();
    }

    #[test]
    fn query_limits_allow_introspection_by_default() {
        assert!(
            GraphqlQueryLimits::default()
                .validate("query Introspection { __schema { types { name } } }")
                .is_ok()
        );
    }

    #[test]
    fn query_limits_reject_disabled_direct_introspection() {
        let result = GraphqlQueryLimits::default()
            .with_introspection_policy(GraphqlIntrospectionPolicy::Deny)
            .validate("query Introspection { __schema { types { name } } }");
        assert_eq!(
            result,
            Err(GraphqlLimitExceeded::IntrospectionDisabled {
                field_name: "__schema".to_string(),
            })
        );
    }

    /// An escaped triple-quote inside a block string used to desynchronise the
    /// tokenizer from the document a real GraphQL server parses: the string
    /// closed early, the real closing `"""` opened an unterminated one, and
    /// `skip_block_string` swallowed the whole remainder of the query. Every
    /// guard then ran against an empty token stream and passed.
    #[test]
    fn query_limits_see_through_escaped_triple_quote_in_block_string() {
        let limits = GraphqlQueryLimits::default()
            .with_introspection_policy(GraphqlIntrospectionPolicy::Deny);

        // Control: an ordinary block string does not hide the introspection.
        assert_eq!(
            limits.validate(r#"query { f(note: """ab""") { __schema { types { name } } } }"#),
            Err(GraphqlLimitExceeded::IntrospectionDisabled {
                field_name: "__schema".to_string(),
            })
        );

        // The escaped `\"""` must be consumed as string content, not as the
        // terminator, so the introspection after it is still seen.
        assert_eq!(
            limits.validate(r#"query { f(note: """a\"""b""") { __schema { types { name } } } }"#),
            Err(GraphqlLimitExceeded::IntrospectionDisabled {
                field_name: "__schema".to_string(),
            })
        );

        // The depth guard must survive the same trick.
        let depth_limits = GraphqlQueryLimits::new(4096, 2, 64, 64);
        assert!(matches!(
            depth_limits
                .validate(r#"query { f(note: """a\"""b""") { p { q { r { s { t } } } } } }"#),
            Err(GraphqlLimitExceeded::DepthExceeded { .. })
        ));

        // A trailing backslash must not run the scan past the end of input.
        assert!(
            GraphqlQueryLimits::default()
                .validate(r#"query { f(note: """unterminated\"#)
                .is_ok()
        );
    }

    #[test]
    fn query_limits_reject_disabled_aliased_introspection() {
        let result = GraphqlQueryLimits::default()
            .with_introspection_policy(GraphqlIntrospectionPolicy::Deny)
            .validate("query Introspection { schemaAlias: __schema { types { name } } }");
        assert_eq!(
            result,
            Err(GraphqlLimitExceeded::IntrospectionDisabled {
                field_name: "__schema".to_string(),
            })
        );
    }

    #[test]
    fn query_limits_reject_disabled_nested_type_introspection() {
        let result = GraphqlQueryLimits::default()
            .with_introspection_policy(GraphqlIntrospectionPolicy::Deny)
            .validate("query Introspection { viewer { __type(name: \"User\") { name } } }");
        assert_eq!(
            result,
            Err(GraphqlLimitExceeded::IntrospectionDisabled {
                field_name: "__type".to_string(),
            })
        );
    }

    #[test]
    fn query_limits_reject_depth_over_limit() {
        let err = GraphqlQueryLimits::new(1024, 2, 50, 50)
            .validate("query Deep { a { b { c } } }")
            .unwrap_err();
        assert_eq!(
            err,
            GraphqlLimitExceeded::DepthExceeded {
                actual_depth: 3,
                max_depth: 2,
            }
        );
    }

    #[test]
    fn query_limits_reject_alias_bomb() {
        let err = GraphqlQueryLimits::new(1024, 10, 1, 50)
            .validate("query AliasBomb { a1: viewer { id } a2: viewer { id } }")
            .unwrap_err();
        assert_eq!(
            err,
            GraphqlLimitExceeded::AliasLimitExceeded {
                actual_aliases: 2,
                max_aliases: 1,
            }
        );
    }

    #[test]
    fn query_limits_reject_root_field_bomb() {
        let err = GraphqlQueryLimits::new(1024, 10, 50, 1)
            .validate("query RootBomb { viewer { id } node { id } }")
            .unwrap_err();
        assert_eq!(
            err,
            GraphqlLimitExceeded::RootFieldLimitExceeded {
                actual_root_fields: 2,
                max_root_fields: 1,
            }
        );
    }

    #[test]
    fn query_limits_ignore_strings_comments_arguments_and_fragments() {
        GraphqlQueryLimits::new(2048, 3, 1, 2)
            .validate(
                r#"
                query Safe($filter: Filter = { nested: { ignored: true } }) {
                    viewer(arg: "{ braces { inside } string }") {
                        id
                    }
                    ... on Query {
                        node
                    }
                    # aliasLike: ignored { too { deep } }
                }
                "#,
            )
            .unwrap();
    }

    // ---- GraphqlRequest ----

    #[test]
    fn request_new_no_operation_name() {
        let req = GraphqlRequest::new(GraphqlQuery::new("{ x }"), serde_json::json!({}));
        assert!(req.operation_name.is_none());
    }

    #[test]
    fn request_with_operation_name() {
        let req = GraphqlRequest::new(GraphqlQuery::new("{ x }"), serde_json::json!({}))
            .with_operation_name("GetUsers");
        assert_eq!(req.operation_name.as_deref(), Some("GetUsers"));
    }

    #[test]
    fn request_serde_roundtrip() {
        let req = GraphqlRequest::new(
            GraphqlQuery::new("query Q($id: ID!) { user(id: $id) { name } }"),
            serde_json::json!({"id": "123"}),
        )
        .with_operation_name("Q");
        let json = serde_json::to_string(&req).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            value,
            serde_json::json!({
                "query": "query Q($id: ID!) { user(id: $id) { name } }",
                "variables": {"id": "123"},
                "operationName": "Q"
            })
        );
        let back: GraphqlRequest<serde_json::Value> = serde_json::from_str(&json).unwrap();
        assert_eq!(back.operation_name.as_deref(), Some("Q"));
        assert_eq!(back.variables["id"], "123");
    }

    #[test]
    fn request_serde_skips_none_operation_name() {
        let req = GraphqlRequest::new(GraphqlQuery::new("{ x }"), serde_json::json!({}));
        let json = serde_json::to_string(&req).unwrap();
        assert!(!json.contains("operation_name"));
        assert!(!json.contains("operationName"));
    }

    // ---- GraphqlBatchItem ----

    #[test]
    fn batch_item_new() {
        let item = GraphqlBatchItem::new(GraphqlQuery::new("{ x }"), serde_json::json!({}));
        assert!(item.operation_name.is_none());
    }

    #[test]
    fn batch_item_with_operation_name() {
        let item = GraphqlBatchItem::new(GraphqlQuery::new("{ x }"), serde_json::json!({}))
            .with_operation_name("Op");
        assert_eq!(item.operation_name.as_deref(), Some("Op"));
    }

    // ---- GraphqlResponse ----

    #[test]
    fn response_is_ok_when_no_errors() {
        let resp = GraphqlResponse::<serde_json::Value> {
            data: Some(serde_json::json!({"user": "alice"})),
            errors: vec![],
            extensions: None,
        };
        assert!(resp.is_ok());
    }

    #[test]
    fn response_is_not_ok_when_errors() {
        let resp = GraphqlResponse::<serde_json::Value> {
            data: None,
            errors: vec![GraphqlError {
                message: "not found".into(),
                locations: vec![],
                path: vec![],
                extensions: None,
            }],
            extensions: None,
        };
        assert!(!resp.is_ok());
    }

    #[test]
    fn response_serde_roundtrip() {
        let resp = GraphqlResponse {
            data: Some(serde_json::json!({"count": 42})),
            errors: vec![],
            extensions: Some(serde_json::json!({"trace_id": "abc"})),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let back: GraphqlResponse<serde_json::Value> = serde_json::from_str(&json).unwrap();
        assert_eq!(back.data.unwrap()["count"], 42);
        assert!(back.errors.is_empty());
        assert!(back.extensions.is_some());
    }

    #[test]
    fn response_minimal_json() {
        let json = "{}";
        let resp: GraphqlResponse<serde_json::Value> = serde_json::from_str(json).unwrap();
        assert!(resp.data.is_none());
        assert!(resp.errors.is_empty());
        assert!(resp.extensions.is_none());
        assert!(resp.is_ok());
    }

    #[test]
    fn response_with_partial_data_and_errors() {
        let json = r#"{"data":{"user":null},"errors":[{"message":"Not authorized"}]}"#;
        let resp: GraphqlResponse<serde_json::Value> = serde_json::from_str(json).unwrap();
        assert!(resp.data.is_some());
        assert!(!resp.is_ok());
        assert_eq!(resp.errors.len(), 1);
    }

    #[test]
    fn request_and_response_shape_snapshot() {
        let request = GraphqlRequest::new(
            GraphqlQuery::new(
                "query ViewerById($id: ID!, $includeTeams: Boolean!) {\n  viewer(id: $id) {\n    id\n    teams @include(if: $includeTeams) {\n      id\n      slug\n    }\n  }\n}",
            ),
            serde_json::json!({
                "id": "[id]",
                "includeTeams": true,
            }),
        )
        .with_operation_name("ViewerById");
        let response = GraphqlResponse::<serde_json::Value> {
            data: Some(serde_json::json!({
                "viewer": {
                    "id": "[id]",
                    "teams": [
                        {
                            "id": "[id]",
                            "slug": "platform"
                        }
                    ]
                }
            })),
            errors: vec![GraphqlError {
                message: "viewer team edge is stale".into(),
                locations: vec![crate::error::GraphqlErrorLocation { line: 4, column: 7 }],
                path: vec![
                    crate::error::GraphqlPathSegment::Key("viewer".into()),
                    crate::error::GraphqlPathSegment::Key("teams".into()),
                    crate::error::GraphqlPathSegment::Index(0),
                ],
                extensions: Some(serde_json::json!({
                    "code": "STALE_EDGE",
                    "trace_id": "[trace-id]",
                })),
            }],
            extensions: Some(serde_json::json!({
                "cost": 7,
                "request_id": "[request-id]",
            })),
        };

        insta::assert_json_snapshot!(
            "request_and_response_shape_snapshot",
            serde_json::json!({
                "request": serde_json::to_value(&request).unwrap(),
                "response": serde_json::to_value(&response).unwrap(),
            })
        );
    }

    // ---- GraphqlQuery additional tests ----

    #[test]
    fn query_debug() {
        let q = GraphqlQuery::new("{ users { id } }");
        let dbg = format!("{q:?}");
        assert!(dbg.contains("GraphqlQuery"));
        assert!(dbg.contains("users"));
    }

    #[test]
    fn query_empty_string() {
        let q = GraphqlQuery::new("");
        assert_eq!(q.as_str(), "");
    }

    #[test]
    fn query_unicode_content() {
        let q = GraphqlQuery::new("{ benutzer { name } }");
        assert_eq!(q.as_str(), "{ benutzer { name } }");
    }

    #[test]
    fn query_multiline() {
        let q = GraphqlQuery::new("{\n  users {\n    id\n    name\n  }\n}");
        assert!(q.as_str().contains('\n'));
        let json = serde_json::to_string(&q).unwrap();
        let back: GraphqlQuery = serde_json::from_str(&json).unwrap();
        assert_eq!(q, back);
    }

    #[test]
    fn query_with_variables_placeholder() {
        let q = GraphqlQuery::new("query GetUser($id: ID!) { user(id: $id) { name } }");
        assert!(q.as_str().contains("$id"));
    }

    #[test]
    fn query_inequality() {
        let a = GraphqlQuery::new("{ a }");
        let b = GraphqlQuery::new("{ b }");
        assert_ne!(a, b);
    }

    // ---- GraphqlRequest additional tests ----

    #[test]
    fn request_debug() {
        let req = GraphqlRequest::new(GraphqlQuery::new("{ x }"), serde_json::json!({}));
        let dbg = format!("{req:?}");
        assert!(dbg.contains("GraphqlRequest"));
    }

    #[test]
    fn request_clone() {
        let req = GraphqlRequest::new(GraphqlQuery::new("{ x }"), serde_json::json!({"a": 1}))
            .with_operation_name("Op");
        let cloned = req.clone();
        assert_eq!(req.query, cloned.query);
        assert_eq!(req.operation_name, cloned.operation_name);
    }

    #[test]
    fn request_with_complex_variables() {
        let vars = serde_json::json!({
            "input": {
                "name": "Alice",
                "tags": ["admin", "user"],
                "nested": {"deep": true}
            }
        });
        let req = GraphqlRequest::new(
            GraphqlQuery::new("mutation Create($input: Input!) { create(input: $input) { id } }"),
            vars,
        );
        let json = serde_json::to_string(&req).unwrap();
        let back: GraphqlRequest<serde_json::Value> = serde_json::from_str(&json).unwrap();
        assert_eq!(back.variables["input"]["name"], "Alice");
        assert!(back.variables["input"]["tags"].is_array());
    }

    #[test]
    fn request_with_null_variables() {
        let req = GraphqlRequest::new(GraphqlQuery::new("{ ping }"), serde_json::Value::Null);
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("null"));
    }

    // ---- GraphqlBatchItem additional tests ----

    #[test]
    fn batch_item_debug() {
        let item = GraphqlBatchItem::new(GraphqlQuery::new("{ x }"), serde_json::json!({}));
        let dbg = format!("{item:?}");
        assert!(dbg.contains("GraphqlBatchItem"));
    }

    #[test]
    fn batch_item_clone() {
        let item = GraphqlBatchItem::new(GraphqlQuery::new("{ x }"), serde_json::json!({"k": "v"}))
            .with_operation_name("BatchOp");
        let cloned = item.clone();
        assert_eq!(item.operation_name, cloned.operation_name);
        assert_eq!(item.query, cloned.query);
    }

    #[test]
    fn batch_item_serde_roundtrip() {
        let item = GraphqlBatchItem::new(
            GraphqlQuery::new("{ users { id } }"),
            serde_json::json!({"limit": 10}),
        )
        .with_operation_name("GetUsers");
        let json = serde_json::to_string(&item).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            value,
            serde_json::json!({
                "query": "{ users { id } }",
                "variables": {"limit": 10},
                "operationName": "GetUsers"
            })
        );
        let back: GraphqlBatchItem<serde_json::Value> = serde_json::from_str(&json).unwrap();
        assert_eq!(back.operation_name.as_deref(), Some("GetUsers"));
        assert_eq!(back.variables["limit"], 10);
    }

    #[test]
    fn batch_item_skips_none_operation_name() {
        let item = GraphqlBatchItem::new(GraphqlQuery::new("{ x }"), serde_json::json!({}));
        let json = serde_json::to_string(&item).unwrap();
        assert!(!json.contains("operation_name"));
        assert!(!json.contains("operationName"));
    }

    // ---- GraphqlResponse additional tests ----

    #[test]
    fn response_debug() {
        let resp = GraphqlResponse::<serde_json::Value> {
            data: Some(serde_json::json!({})),
            errors: vec![],
            extensions: None,
        };
        let dbg = format!("{resp:?}");
        assert!(dbg.contains("GraphqlResponse"));
    }

    #[test]
    fn response_clone() {
        let resp = GraphqlResponse {
            data: Some(serde_json::json!({"x": 1})),
            errors: vec![],
            extensions: Some(serde_json::json!({"trace": "abc"})),
        };
        let cloned = resp.clone();
        assert_eq!(cloned.data.unwrap()["x"], 1);
        assert!(resp.data.is_some());
    }

    #[test]
    fn response_with_multiple_errors() {
        let json = r#"{"errors":[{"message":"a"},{"message":"b"},{"message":"c"}]}"#;
        let resp: GraphqlResponse<serde_json::Value> = serde_json::from_str(json).unwrap();
        assert_eq!(resp.errors.len(), 3);
        assert!(!resp.is_ok());
        assert!(resp.data.is_none());
    }

    #[test]
    fn response_extensions_only() {
        let json = r#"{"extensions":{"requestId":"xyz-123"}}"#;
        let resp: GraphqlResponse<serde_json::Value> = serde_json::from_str(json).unwrap();
        assert!(resp.data.is_none());
        assert!(resp.is_ok());
        assert_eq!(resp.extensions.unwrap()["requestId"], "xyz-123");
    }

    #[test]
    fn response_skips_none_extensions_in_serialization() {
        let resp = GraphqlResponse::<serde_json::Value> {
            data: Some(serde_json::json!({})),
            errors: vec![],
            extensions: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(!json.contains("extensions"));
    }

    // ---- GraphqlQuery from String (not &str) ----

    #[test]
    fn query_from_owned_string() {
        let owned = String::from("mutation { createUser { id } }");
        let q = GraphqlQuery::new(owned);
        assert!(q.as_str().contains("createUser"));
    }

    #[test]
    fn query_from_static_long_query() {
        let q = GraphqlQuery::from_static(
            "query GetUsersWithFilters($filter: FilterInput!, $limit: Int, $offset: Int) { users(filter: $filter, limit: $limit, offset: $offset) { id name email } }",
        );
        assert!(q.as_str().contains("FilterInput"));
        assert!(q.as_str().contains("$limit"));
    }

    #[test]
    fn query_with_fragment() {
        let q = GraphqlQuery::new(
            "fragment UserFields on User { id name } query { users { ...UserFields } }",
        );
        assert!(q.as_str().contains("fragment"));
        assert!(q.as_str().contains("UserFields"));
    }

    #[test]
    fn query_eq_same_content_different_construction() {
        let a = GraphqlQuery::new("{ x }");
        let b = GraphqlQuery::from_static("{ x }");
        assert_eq!(a, b);
    }

    #[test]
    fn query_serde_preserves_whitespace() {
        let q = GraphqlQuery::new("{\n  users  {\n    id\n  }\n}");
        let json = serde_json::to_string(&q).unwrap();
        let back: GraphqlQuery = serde_json::from_str(&json).unwrap();
        assert!(back.as_str().contains('\n'));
        assert_eq!(q, back);
    }

    // ---- GraphqlRequest edge cases ----

    #[test]
    fn request_with_empty_variables() {
        let req = GraphqlRequest::new(GraphqlQuery::new("{ ping }"), serde_json::json!({}));
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("{}"));
    }

    #[test]
    fn request_with_array_variables() {
        let vars = serde_json::json!({"ids": [1, 2, 3]});
        let req = GraphqlRequest::new(
            GraphqlQuery::new("query($ids: [Int!]!) { byIds(ids: $ids) { id } }"),
            vars,
        );
        let json = serde_json::to_string(&req).unwrap();
        let back: GraphqlRequest<serde_json::Value> = serde_json::from_str(&json).unwrap();
        assert!(back.variables["ids"].is_array());
        assert_eq!(back.variables["ids"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn request_operation_name_overwrite() {
        let req = GraphqlRequest::new(GraphqlQuery::new("{ x }"), serde_json::json!({}))
            .with_operation_name("First")
            .with_operation_name("Second");
        assert_eq!(req.operation_name.as_deref(), Some("Second"));
    }

    #[test]
    fn request_serde_includes_operation_name() {
        let req = GraphqlRequest::new(GraphqlQuery::new("{ x }"), serde_json::json!({}))
            .with_operation_name("MyOp");
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("MyOp"));
        assert!(json.contains("operationName"));
        assert!(!json.contains("operation_name"));
    }

    // ---- GraphqlBatchItem edge cases ----

    #[test]
    fn batch_item_serde_with_complex_vars() {
        let vars = serde_json::json!({
            "input": {"name": "test", "tags": ["a", "b"]},
            "limit": 50
        });
        let item = GraphqlBatchItem::new(GraphqlQuery::new("mutation M { m }"), vars)
            .with_operation_name("M");
        let json = serde_json::to_string(&item).unwrap();
        let back: GraphqlBatchItem<serde_json::Value> = serde_json::from_str(&json).unwrap();
        assert_eq!(back.variables["limit"], 50);
        assert_eq!(back.operation_name.as_deref(), Some("M"));
    }

    #[test]
    fn batch_item_operation_name_overwrite() {
        let item = GraphqlBatchItem::new(GraphqlQuery::new("{ x }"), serde_json::json!({}))
            .with_operation_name("A")
            .with_operation_name("B");
        assert_eq!(item.operation_name.as_deref(), Some("B"));
    }

    #[test]
    fn batch_item_with_null_variables() {
        let item = GraphqlBatchItem::new(GraphqlQuery::new("{ x }"), serde_json::Value::Null);
        let json = serde_json::to_string(&item).unwrap();
        assert!(json.contains("null"));
    }

    // ---- GraphqlResponse edge cases ----

    #[test]
    fn response_data_none_no_errors_is_ok() {
        let resp = GraphqlResponse::<serde_json::Value> {
            data: None,
            errors: vec![],
            extensions: None,
        };
        assert!(resp.is_ok());
    }

    #[test]
    fn response_data_some_with_errors_is_not_ok() {
        let resp = GraphqlResponse {
            data: Some(serde_json::json!({"partial": true})),
            errors: vec![GraphqlError {
                message: "partial error".into(),
                locations: vec![],
                path: vec![],
                extensions: None,
            }],
            extensions: None,
        };
        assert!(!resp.is_ok());
    }

    #[test]
    fn response_serde_with_typed_data() {
        #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
        struct User {
            id: String,
            name: String,
        }
        let resp = GraphqlResponse {
            data: Some(User {
                id: "1".into(),
                name: "Alice".into(),
            }),
            errors: vec![],
            extensions: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        let back: GraphqlResponse<User> = serde_json::from_str(&json).unwrap();
        assert_eq!(back.data.unwrap().name, "Alice");
    }

    #[test]
    fn response_deserialized_from_server_format() {
        let json = r#"{
            "data": {"viewer": {"login": "test-user"}},
            "errors": [],
            "extensions": {"cost": {"requestedQueryCost": 1}}
        }"#;
        let resp: GraphqlResponse<serde_json::Value> = serde_json::from_str(json).unwrap();
        assert!(resp.is_ok());
        assert_eq!(resp.data.unwrap()["viewer"]["login"], "test-user");
        assert!(resp.extensions.is_some());
    }

    #[test]
    fn response_data_null_deserialized_as_none() {
        let json = r#"{"data": null}"#;
        let resp: GraphqlResponse<serde_json::Value> = serde_json::from_str(json).unwrap();
        assert!(resp.data.is_none());
        assert!(resp.is_ok());
    }

    #[test]
    fn response_with_only_errors() {
        let json = r#"{"errors":[{"message":"forbidden"}]}"#;
        let resp: GraphqlResponse<serde_json::Value> = serde_json::from_str(json).unwrap();
        assert!(resp.data.is_none());
        assert!(!resp.is_ok());
        assert_eq!(resp.errors[0].message, "forbidden");
    }

    #[test]
    fn response_clone_preserves_errors() {
        let resp = GraphqlResponse::<serde_json::Value> {
            data: None,
            errors: vec![
                GraphqlError {
                    message: "err1".into(),
                    locations: vec![],
                    path: vec![],
                    extensions: None,
                },
                GraphqlError {
                    message: "err2".into(),
                    locations: vec![],
                    path: vec![],
                    extensions: None,
                },
            ],
            extensions: None,
        };
        let cloned = resp.clone();
        assert_eq!(resp.errors.len(), cloned.errors.len());
        assert_eq!(resp.errors.len(), 2);
    }

    // ---- GraphqlOperation trait tests ----

    #[derive(Debug)]
    struct TestOp;

    #[derive(Debug, Serialize, Deserialize)]
    struct TestVars {
        id: String,
    }

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct TestData {
        name: String,
    }

    impl GraphqlOperation for TestOp {
        type Variables = TestVars;
        type ResponseData = TestData;

        const QUERY: &'static str = "query GetUser($id: ID!) { user(id: $id) { name } }";
        const OPERATION_NAME: &'static str = "GetUser";
    }

    #[test]
    fn trait_defaults_variables_schema_none() {
        assert!(TestOp::variables_schema().is_none());
    }

    #[test]
    fn trait_defaults_response_schema_none() {
        assert!(TestOp::response_schema().is_none());
    }

    #[test]
    fn trait_defaults_is_idempotent_true() {
        assert!(TestOp::is_idempotent());
    }

    #[test]
    fn trait_query_constant() {
        assert!(TestOp::QUERY.contains("GetUser"));
        assert!(TestOp::QUERY.contains("$id"));
    }

    #[test]
    fn trait_operation_name_constant() {
        assert_eq!(TestOp::OPERATION_NAME, "GetUser");
    }

    // ---- Non-idempotent operation test ----

    struct MutationOp;

    impl GraphqlOperation for MutationOp {
        type Variables = serde_json::Value;
        type ResponseData = serde_json::Value;

        const QUERY: &'static str = "mutation CreateUser { createUser { id } }";
        const OPERATION_NAME: &'static str = "CreateUser";

        fn is_idempotent() -> bool {
            false
        }

        fn variables_schema() -> Option<&'static str> {
            Some(r#"{"type":"object"}"#)
        }

        fn response_schema() -> Option<&'static str> {
            Some(r#"{"type":"object"}"#)
        }
    }

    #[test]
    fn mutation_op_not_idempotent() {
        assert!(!MutationOp::is_idempotent());
    }

    #[test]
    fn mutation_op_has_schemas() {
        assert!(MutationOp::variables_schema().is_some());
        assert!(MutationOp::response_schema().is_some());
    }

    // ---- GraphqlQuery edge cases ----

    #[test]
    fn query_very_long_string() {
        let long = "a".repeat(10_000);
        let q = GraphqlQuery::new(long);
        assert_eq!(q.as_str().len(), 10_000);
        let json = serde_json::to_string(&q).unwrap();
        let back: GraphqlQuery = serde_json::from_str(&json).unwrap();
        assert_eq!(q, back);
    }

    #[test]
    fn query_with_special_json_chars() {
        let q = GraphqlQuery::new(r#"{ user(name: "test\"escaped") { id } }"#);
        let json = serde_json::to_string(&q).unwrap();
        let back: GraphqlQuery = serde_json::from_str(&json).unwrap();
        assert_eq!(q, back);
    }

    #[test]
    fn query_with_tab_and_carriage_return() {
        let q = GraphqlQuery::new("{\t\r\n  users { id }\r\n}");
        assert!(q.as_str().contains('\t'));
        assert!(q.as_str().contains('\r'));
    }

    // ---- GraphqlRequest edge cases ----

    #[test]
    fn request_with_deeply_nested_variables() {
        let vars = serde_json::json!({
            "l1": {"l2": {"l3": {"l4": {"l5": "deep"}}}}
        });
        let req = GraphqlRequest::new(GraphqlQuery::new("{ x }"), vars);
        let json = serde_json::to_string(&req).unwrap();
        let back: GraphqlRequest<serde_json::Value> = serde_json::from_str(&json).unwrap();
        assert_eq!(back.variables["l1"]["l2"]["l3"]["l4"]["l5"], "deep");
    }

    #[test]
    fn request_with_unicode_operation_name() {
        let req = GraphqlRequest::new(GraphqlQuery::new("{ x }"), serde_json::json!({}))
            .with_operation_name("BenutzerAbfrage");
        assert_eq!(req.operation_name.as_deref(), Some("BenutzerAbfrage"));
    }

    #[test]
    fn request_with_empty_operation_name() {
        let req = GraphqlRequest::new(GraphqlQuery::new("{ x }"), serde_json::json!({}))
            .with_operation_name("");
        assert_eq!(req.operation_name.as_deref(), Some(""));
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("operationName"));
        assert!(!json.contains("operation_name"));
    }

    // ---- GraphqlBatchItem edge cases ----

    #[test]
    fn batch_item_with_empty_operation_name() {
        let item = GraphqlBatchItem::new(GraphqlQuery::new("{ x }"), serde_json::json!({}))
            .with_operation_name("");
        assert_eq!(item.operation_name.as_deref(), Some(""));
    }

    #[test]
    fn batch_item_with_deeply_nested_variables() {
        let vars = serde_json::json!({"a": {"b": {"c": 42}}});
        let item = GraphqlBatchItem::new(GraphqlQuery::new("{ x }"), vars);
        let json = serde_json::to_string(&item).unwrap();
        let back: GraphqlBatchItem<serde_json::Value> = serde_json::from_str(&json).unwrap();
        assert_eq!(back.variables["a"]["b"]["c"], 42);
    }

    // ---- GraphqlResponse edge cases ----

    #[test]
    fn response_serde_with_nested_errors_and_extensions() {
        let json = r#"{
            "data": {"count": 5},
            "errors": [
                {
                    "message": "partial",
                    "locations": [{"line": 2, "column": 3}],
                    "path": ["users", 0],
                    "extensions": {"code": "PARTIAL_RESULT"}
                }
            ],
            "extensions": {"requestId": "req-123", "cost": 7}
        }"#;
        let resp: GraphqlResponse<serde_json::Value> = serde_json::from_str(json).unwrap();
        assert!(!resp.is_ok());
        assert_eq!(resp.data.unwrap()["count"], 5);
        assert_eq!(resp.errors.len(), 1);
        assert_eq!(resp.errors[0].locations[0].line, 2);
        assert_eq!(resp.extensions.unwrap()["cost"], 7);
    }

    #[test]
    fn response_with_empty_data_object() {
        let json = r#"{"data":{}}"#;
        let resp: GraphqlResponse<serde_json::Value> = serde_json::from_str(json).unwrap();
        assert!(resp.is_ok());
        assert!(resp.data.is_some());
        assert!(resp.data.unwrap().is_object());
    }

    #[test]
    fn response_with_empty_errors_array() {
        let json = r#"{"data":null,"errors":[]}"#;
        let resp: GraphqlResponse<serde_json::Value> = serde_json::from_str(json).unwrap();
        assert!(resp.is_ok());
        assert!(resp.data.is_none());
    }

    #[test]
    fn response_clone_with_extensions() {
        let resp = GraphqlResponse {
            data: Some(serde_json::json!({"key": "val"})),
            errors: vec![],
            extensions: Some(serde_json::json!({"trace_id": "abc", "cost": 42})),
        };
        let cloned = resp.clone();
        assert_eq!(cloned.extensions.unwrap()["trace_id"], "abc");
        assert!(resp.extensions.is_some());
    }

    #[test]
    fn response_debug_contains_struct_name() {
        let resp = GraphqlResponse::<String> {
            data: Some("hello".to_string()),
            errors: vec![],
            extensions: None,
        };
        let dbg = format!("{resp:?}");
        assert!(dbg.contains("GraphqlResponse"));
        assert!(dbg.contains("hello"));
    }
}
