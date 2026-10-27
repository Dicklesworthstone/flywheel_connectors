//! Bounded newline JSON-RPC framing for native connector subprocesses.
//!
//! This is the host's stdio transport, not an FCPC control-plane frame. Only
//! host-loaded operation policy can enlarge an invocation response; lifecycle
//! replies and undeclared operations retain the small control-message budget.

use std::collections::BTreeMap;
use std::io;

pub(super) const CONTROL_RESPONSE_BYTES: usize = 64 * 1024;
const INTROSPECTION_RESPONSE_BYTES: usize = 1024 * 1024;
pub(super) const MAX_RESPONSE_BYTES: usize = 32 * 1024 * 1024;

/// Provider response limits apply before connector output serialization.
/// JSON escaping can require six bytes per input byte (`\u0000`); base64's
/// four-for-three expansion fits within that allowance. Reserve a control
/// frame for the FCP/JSON-RPC envelope, then enforce the independent host cap.
fn encoded_response_limit(provider_bytes: u64) -> usize {
    usize::try_from(provider_bytes)
        .unwrap_or(usize::MAX)
        .saturating_mul(6)
        .saturating_add(CONTROL_RESPONSE_BYTES)
        .min(MAX_RESPONSE_BYTES)
}

#[derive(Debug, Default)]
pub(super) struct NativeResponseLimits {
    operations: BTreeMap<String, usize>,
}

impl NativeResponseLimits {
    /// Combine manifest and managed-inventory policy without allowing an
    /// inventory override to enlarge a more restrictive manifest limit.
    pub(super) fn restrict_operation(&mut self, operation: &str, provider_bytes: u64) {
        let limit = encoded_response_limit(provider_bytes);
        self.operations
            .entry(operation.to_owned())
            .and_modify(|current| *current = (*current).min(limit))
            .or_insert(limit);
    }

    pub(super) fn for_request(&self, method: &str, operation: Option<&str>) -> usize {
        match method {
            "introspect" => INTROSPECTION_RESPONSE_BYTES,
            "invoke" => operation
                .and_then(|id| self.operations.get(id))
                .copied()
                .unwrap_or(CONTROL_RESPONSE_BYTES),
            _ => CONTROL_RESPONSE_BYTES,
        }
    }
}

/// Incremental framing independent of the async reader. A chunk may contain
/// several responses: `append` consumes only through the first newline, so
/// the reader retains all bytes belonging to subsequent frames.
pub(super) struct ResponseFrame {
    bytes: Vec<u8>,
    limit: usize,
}

impl ResponseFrame {
    pub(super) fn new(limit: usize) -> Self {
        let limit = limit.min(MAX_RESPONSE_BYTES);
        Self {
            bytes: Vec::with_capacity(limit.min(1024)),
            limit,
        }
    }

    /// Returns the bytes consumed and whether a complete newline was found.
    /// Reject an oversized chunk before copying any part beyond the limit.
    pub(super) fn append(&mut self, chunk: &[u8]) -> io::Result<(usize, bool)> {
        let newline = chunk.iter().position(|byte| *byte == b'\n');
        let consumed = newline.map_or(chunk.len(), |index| index + 1);
        if consumed > self.limit.saturating_sub(self.bytes.len()) {
            return Err(io::Error::other(format!(
                "stdout frame exceeded {} bytes",
                self.limit
            )));
        }
        let required = self.bytes.len() + consumed;
        if required > self.bytes.capacity() {
            let capacity = required
                .max(self.bytes.capacity().saturating_mul(2))
                .min(self.limit);
            self.bytes
                .try_reserve_exact(capacity - self.bytes.len())
                .map_err(|_| io::Error::other("unable to allocate bounded connector response"))?;
        }
        self.bytes.extend_from_slice(&chunk[..consumed]);
        Ok((consumed, newline.is_some()))
    }

    pub(super) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_declared_invokes_and_introspection_receive_larger_limits() {
        let mut limits = NativeResponseLimits::default();
        limits.restrict_operation("files.download", 1024 * 1024);
        assert_eq!(
            limits.for_request("invoke", Some("files.download")),
            6 * 1024 * 1024 + CONTROL_RESPONSE_BYTES
        );
        for method in ["health", "configure", "handshake", "simulate", "self_check"] {
            assert_eq!(
                limits.for_request(method, Some("files.download")),
                CONTROL_RESPONSE_BYTES
            );
        }
        assert_eq!(limits.for_request("invoke", None), CONTROL_RESPONSE_BYTES);
        assert_eq!(
            limits.for_request("invoke", Some("files.unknown")),
            CONTROL_RESPONSE_BYTES
        );
        assert_eq!(
            limits.for_request("introspect", None),
            INTROSPECTION_RESPONSE_BYTES
        );
    }

    #[test]
    fn response_limits_combine_restrictions_and_never_overflow() {
        let mut limits = NativeResponseLimits::default();
        limits.restrict_operation("files.download", 1024 * 1024);
        limits.restrict_operation("files.download", 128 * 1024);
        limits.restrict_operation("files.download", u64::MAX);
        assert_eq!(
            limits.for_request("invoke", Some("files.download")),
            6 * 128 * 1024 + CONTROL_RESPONSE_BYTES
        );
        assert_eq!(encoded_response_limit(u64::MAX), MAX_RESPONSE_BYTES);
        assert_eq!(encoded_response_limit(0), CONTROL_RESPONSE_BYTES);
    }

    #[test]
    fn exact_limit_includes_newline_and_one_extra_byte_is_rejected() {
        let mut frame = ResponseFrame::new(5);
        assert_eq!(frame.append(b"1234\nfollowing").unwrap(), (5, true));
        assert_eq!(frame.bytes(), b"1234\n");
        let mut oversized = ResponseFrame::new(5);
        assert_eq!(oversized.append(b"12345").unwrap(), (5, false));
        assert!(oversized.append(b"\n").is_err());
        assert_eq!(oversized.bytes(), b"12345");
        assert!(oversized.bytes.capacity() <= 5);
    }

    #[test]
    fn large_chunk_rejection_does_not_allocate_or_consume_next_frame() {
        let mut frame = ResponseFrame::new(CONTROL_RESPONSE_BYTES);
        let chunk = vec![b'x'; CONTROL_RESPONSE_BYTES + 1];
        assert!(frame.append(&chunk).is_err());
        assert!(frame.bytes().is_empty());
        assert_eq!(frame.bytes.capacity(), 1024);
    }

    #[test]
    fn chunked_large_response_preserves_utf8_and_the_following_frame() {
        let mut payload = b"{\"result\":{\"content_base64\":\"".to_vec();
        payload.extend(std::iter::repeat_n(b'A', 256 * 1024));
        payload.extend_from_slice("\",\"name\":\"雪\"}}\n".as_bytes());
        let mut stream = payload.clone();
        stream.extend_from_slice(b"{\"id\":\"next\"}\n");
        let mut frame = ResponseFrame::new(512 * 1024);
        let mut position = 0;
        loop {
            let end = (position + 4097).min(stream.len());
            let (used, finished) = frame.append(&stream[position..end]).unwrap();
            position += used;
            if finished {
                break;
            }
        }
        assert_eq!(frame.bytes(), payload);
        assert_eq!(&stream[position..], b"{\"id\":\"next\"}\n");
        assert!(std::str::from_utf8(frame.bytes()).is_ok());
    }

    #[test]
    fn hard_ceiling_applies_even_when_a_caller_supplies_an_unbounded_limit() {
        let frame = ResponseFrame::new(usize::MAX);
        assert_eq!(frame.limit, MAX_RESPONSE_BYTES);
    }
}
