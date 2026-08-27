//! FCP GraphQL - Typed GraphQL client infrastructure for connectors.
//!
//! This crate provides:
//! - Typed GraphQL operations with schema-aware validation.
//! - Retry, backoff, and error mapping to the FCP taxonomy.
//! - Cursor and offset pagination helpers.
//! - GraphQL over WebSocket subscriptions.

#![forbid(unsafe_code)]
// Lint groups come from [workspace.lints.clippy]; duplicating them here would
// override that table and defeat its allow entries.
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::return_self_not_must_use)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::too_many_lines)]

mod client;
mod error;
mod operation;
mod pagination;
mod retry;
mod schema;
mod subscription;

pub use client::{
    GraphqlClient, GraphqlClientBuilder, GraphqlClientConfig, GraphqlClientMetrics,
    SchemaValidationMode,
};
pub use error::{
    GraphqlClientError, GraphqlError, GraphqlErrorLocation, GraphqlLimitExceeded,
    GraphqlPathSegment,
};
pub use operation::{
    DEFAULT_GRAPHQL_QUERY_LIMITS, DEFAULT_MAX_QUERY_ALIASES, DEFAULT_MAX_QUERY_BYTES,
    DEFAULT_MAX_QUERY_DEPTH, DEFAULT_MAX_QUERY_ROOT_FIELDS, GraphqlBatchItem,
    GraphqlIntrospectionPolicy, GraphqlOperation, GraphqlQuery, GraphqlQueryLimits, GraphqlRequest,
    GraphqlResponse,
};
pub use pagination::{
    CursorPage, CursorPageInfo, OffsetPage, PageLimit, PaginationError, paginate_cursor,
    paginate_offset,
};
pub use retry::{RetryDecision, RetryPolicy, RetryStrategy};
pub use subscription::{
    GraphqlSubscriptionClient, GraphqlSubscriptionConfig, GraphqlSubscriptionStream,
};

#[doc(hidden)]
pub use subscription::__fuzz;

#[doc(hidden)]
pub mod __bench {
    pub use crate::schema::SchemaCache;
}
