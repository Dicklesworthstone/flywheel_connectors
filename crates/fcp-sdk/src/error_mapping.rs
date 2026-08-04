//! Canonical connector error-mapping contract.
//!
//! Connector authors implement [`ConnectorErrorMapping`] on their connector
//! error type so retry/runtime helpers can convert `fcp-async-core` deadline,
//! cancellation, and runtime failures into both connector-specific errors and
//! the standard FCP error taxonomy.

use std::fmt;
use std::time::Duration;

use fcp_async_core::AsyncError;

use crate::FcpError;

/// Trait for mapping `AsyncError` to connector-specific error types.
///
/// Every connector must implement this to handle deadline/cancellation
/// errors from `ExecutionContext` operations.
///
/// # Example
///
/// ```ignore
/// impl ConnectorErrorMapping for MyConnectorError {
///     fn from_async_error(error: AsyncError) -> Self {
///         match error {
///             AsyncError::Timeout { timeout_ms } => Self::DeadlineExceeded {
///                 message: format!("request deadline exceeded after {timeout_ms}ms"),
///             },
///             AsyncError::Cancelled => Self::RequestCancelled,
///             other => Self::Runtime { message: other.to_string() },
///         }
///     }
///
///     fn to_fcp_error(&self) -> FcpError { /* ... */ }
/// }
/// ```
pub trait ConnectorErrorMapping: fmt::Display + fmt::Debug + Send + Sync {
    /// Map an `AsyncError` (timeout, cancellation, etc.) to this connector's error type.
    fn from_async_error(error: AsyncError) -> Self
    where
        Self: Sized;

    /// Convert this connector error to the standard `FcpError` taxonomy.
    fn to_fcp_error(&self) -> FcpError;

    /// Whether this error is retryable.
    fn is_retryable(&self) -> bool;

    /// Suggested retry-after delay, if available.
    fn retry_after(&self) -> Option<Duration> {
        None
    }

    /// Redaction-safe rendering of this error for SDK-owned log lines.
    ///
    /// The SDK must never render a connector error's raw [`fmt::Display`] into
    /// a log: `reqwest::Error`'s `Display` appends `" for url (<url>)"`, and
    /// several providers authenticate by putting the API key in the query
    /// string (`?key=…`), so a connector that forwards a transport error
    /// verbatim leaks the credential on every retry. Connectors are expected
    /// to redact at their own error type (see the Telegram connector's
    /// hand-written `Display`/`Debug`), but the SDK cannot depend on all 176
    /// of them getting it right — this is the backstop on the one code path
    /// the SDK itself owns.
    ///
    /// The default drops query strings and userinfo from every URL-looking
    /// substring. Override it when a connector error can carry secret material
    /// somewhere other than a URL.
    fn redacted_summary(&self) -> String {
        redact_urls_in_error_text(&self.to_string())
    }
}

/// Strip credential-bearing components out of every URL in an error rendering.
///
/// Scheme, host, and path survive so the line stays diagnostic; the query
/// string and any `user:pass@` userinfo are replaced with a marker. Anything
/// that is not URL-shaped is passed through untouched.
#[must_use]
pub fn redact_urls_in_error_text(text: &str) -> String {
    const SCHEMES: [&str; 2] = ["https://", "http://"];

    // A URL in prose ends at the first byte that cannot appear unescaped in
    // one. `)` is included because `reqwest` wraps the URL in parentheses.
    const fn url_ends_at(byte: u8) -> bool {
        matches!(
            byte,
            b' ' | b'\t' | b'\n' | b'\r' | b')' | b'"' | b'\'' | b'<' | b'>'
        )
    }

    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0usize;

    while cursor < bytes.len() {
        let Some((scheme_start, scheme_len)) = SCHEMES
            .iter()
            .filter_map(|scheme| {
                text[cursor..]
                    .find(scheme)
                    .map(|at| (cursor + at, scheme.len()))
            })
            .min_by_key(|(at, _)| *at)
        else {
            break;
        };

        out.push_str(&text[cursor..scheme_start]);

        let body_start = scheme_start + scheme_len;
        let body_end = bytes[body_start..]
            .iter()
            .position(|byte| url_ends_at(*byte))
            .map_or(bytes.len(), |offset| body_start + offset);
        let body = &text[body_start..body_end];

        out.push_str(&text[scheme_start..body_start]);

        // Userinfo (`user:pass@host`) — keep the host, drop the credentials.
        // Only an `@` before the first `/` is userinfo; a later one is path.
        let authority_end = body.find('/').unwrap_or(body.len());
        let after_userinfo = body[..authority_end].rfind('@').map_or(body, |at| {
            out.push_str("<redacted>@");
            &body[at + 1..]
        });

        match after_userinfo.find('?') {
            Some(at) => {
                out.push_str(&after_userinfo[..at]);
                out.push_str("?<redacted>");
            }
            None => out.push_str(after_userinfo),
        }

        cursor = body_end;
    }

    out.push_str(&text[cursor.min(text.len())..]);
    out
}

/// Map an `AsyncError` from context operations to a standard `FcpError`.
///
/// This is the canonical mapping for context-level errors (timeout, cancellation).
/// Connector-specific error types should delegate to this for the `AsyncError` arm.
#[must_use]
pub fn map_async_to_fcp_error(error: &AsyncError) -> FcpError {
    match error {
        AsyncError::Timeout { timeout_ms } => FcpError::External {
            service: "runtime".into(),
            message: format!("request deadline exceeded after {timeout_ms}ms"),
            status_code: Some(504),
            retryable: true,
            retry_after: None,
        },
        AsyncError::Cancelled => FcpError::External {
            service: "runtime".into(),
            message: "request cancelled".into(),
            status_code: None,
            retryable: false,
            retry_after: None,
        },
        other => FcpError::Internal {
            message: other.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::redact_urls_in_error_text;

    /// The live shape of the leak: `reqwest::Error`'s `Display` appends
    /// `" for url (<url>)"`, and providers like `YouTube` authenticate with
    /// `?key=<API_KEY>` in the query string.
    #[test]
    fn drops_the_query_string_that_carries_the_api_key() {
        let leaked = "error sending request for url \
             (https://www.googleapis.com/youtube/v3/search?part=snippet&key=AIzaSyREALKEY)";
        let redacted = redact_urls_in_error_text(leaked);

        assert!(!redacted.contains("AIzaSyREALKEY"), "{redacted}");
        assert!(!redacted.contains("part=snippet"), "{redacted}");
        // Still diagnostic: scheme, host and path survive.
        assert!(
            redacted.contains("https://www.googleapis.com/youtube/v3/search?<redacted>"),
            "{redacted}"
        );
        assert!(
            redacted.starts_with("error sending request for url ("),
            "{redacted}"
        );
        assert!(redacted.ends_with(')'), "{redacted}");
    }

    #[test]
    fn drops_userinfo_credentials() {
        let redacted =
            redact_urls_in_error_text("connect failed: https://alice:hunter2@api.example.test/v1");
        assert!(!redacted.contains("hunter2"), "{redacted}");
        assert!(!redacted.contains("alice"), "{redacted}");
        assert!(
            redacted.contains("<redacted>@api.example.test/v1"),
            "{redacted}"
        );
    }

    #[test]
    fn redacts_every_url_in_a_multi_url_message() {
        let redacted = redact_urls_in_error_text(
            "redirected from http://a.test/x?token=AAA to https://b.test/y?token=BBB",
        );
        assert!(!redacted.contains("AAA"), "{redacted}");
        assert!(!redacted.contains("BBB"), "{redacted}");
        assert_eq!(redacted.matches("?<redacted>").count(), 2, "{redacted}");
    }

    #[test]
    fn passes_through_text_without_urls() {
        for text in [
            "",
            "Rate limited, retry after 500ms",
            "YouTube API error: quota exceeded (status Some(403))",
            "a ? mark and an @ sign but no url",
        ] {
            assert_eq!(redact_urls_in_error_text(text), text);
        }
    }

    /// An `@` after the path start is part of the path, not userinfo, and a
    /// URL with no query string must be left intact.
    #[test]
    fn leaves_paths_and_query_less_urls_intact() {
        let text = "GET https://api.test/users/@me failed";
        assert_eq!(redact_urls_in_error_text(text), text);
    }
}
