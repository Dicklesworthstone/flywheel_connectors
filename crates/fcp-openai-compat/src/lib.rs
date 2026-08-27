//! OpenAI-compatible client infrastructure for FCP connectors.
//!
//! This crate centralizes the protocol details shared by OpenAI-compatible
//! providers such as Groq, DeepSeek, xAI, local vLLM/Ollama-compatible servers,
//! and direct OpenAI-compatible embeddings providers. It intentionally stores no
//! credentials and owns no global HTTP client; connector crates inject their
//! provider policy and an `fcp_async_core::http::HttpClient`.

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
mod rate_limit;
mod sse;
mod tools;
mod types;

pub use client::{
    ChatCompletionStream, ErrorMapper, HttpRequest, OpenAiCompatClient, OpenAiCompatClientConfig,
    OpenAiCompatProvider,
};
pub use error::{
    NetworkError, OpenAiError, StreamingError, redact_sensitive_text, truncate_response_body,
};
pub use rate_limit::{
    HeaderList, RateLimitConfig, RateLimitPolicy, RateLimitSnapshot, header_value,
    parse_rate_limit_headers, parse_retry_after, upsert_header,
};
pub use sse::{
    OpenAiSseDecoder, OpenAiStreamEvent, accumulate_chunks, accumulate_chunks_with_reasoning,
};
pub use tools::Tools;
pub use types::*;
