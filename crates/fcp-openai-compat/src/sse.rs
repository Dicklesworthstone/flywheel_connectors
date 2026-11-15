//! OpenAI-compatible SSE decoding.

use std::collections::VecDeque;

use bytes::Bytes;

use crate::{ChatChunk, NetworkError, OpenAiError, StreamingError, redact_sensitive_text};

/// Decoded stream event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenAiStreamEvent {
    /// Chat chunk.
    Chunk(ChatChunk),
    /// Provider sent `data: [DONE]`.
    Done,
}

/// Incremental SSE decoder for OpenAI-compatible chat streams.
///
/// An in-progress event and its partial line share a bounded allocation. Each
/// `data` field retains its newline, including empty fields; there is no vector
/// of per-line strings. Complete events are returned to the caller immediately.
/// `[DONE]`, protocol errors and truncated EOF permanently terminate decoding.
#[derive(Debug)]
pub struct OpenAiSseDecoder {
    /// Assembled event data followed by the current incomplete physical line.
    buffer: Vec<u8>,
    line_start: usize,
    event_is_error: bool,
    max_buffer_size: usize,
    pending_cr_swallows_lf: bool,
    first_line: bool,
    terminal: bool,
    done: bool,
}

const DEFAULT_MAX_SSE_BUFFER_SIZE: usize = 1024 * 1024;
const MAX_SSE_BUFFER_SIZE: usize = 64 * 1024 * 1024;

impl Default for OpenAiSseDecoder {
    fn default() -> Self {
        Self::with_max_buffer_size(DEFAULT_MAX_SSE_BUFFER_SIZE)
    }
}

impl OpenAiSseDecoder {
    /// Create an empty decoder with a 1 MiB retained framing limit.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the retained framing limit, capped at 64 MiB.
    ///
    /// The limit covers assembled event data, its newline separators and the
    /// current raw line. It does not limit the total lifetime of a stream or
    /// the size of a transport chunk containing many complete events. Zero
    /// rejects any nonempty field. Allocation capacity cannot exceed the limit.
    pub fn with_max_buffer_size(max_buffer_size: usize) -> Self {
        Self {
            buffer: Vec::new(),
            line_start: 0,
            event_is_error: false,
            max_buffer_size: max_buffer_size.min(MAX_SSE_BUFFER_SIZE),
            pending_cr_swallows_lf: false,
            first_line: true,
            terminal: false,
            done: false,
        }
    }

    /// Feed bytes and return complete events followed by at most one error.
    ///
    /// The decoder stops at the first terminal event, even if the same input
    /// chunk contains more bytes. Calls after termination return no events.
    pub fn feed(&mut self, bytes: &Bytes) -> Vec<Result<OpenAiStreamEvent, OpenAiError>> {
        if self.terminal || bytes.is_empty() {
            return Vec::new();
        }
        let mut output = Vec::new();
        let mut remaining = bytes.as_ref();

        while !remaining.is_empty() {
            if self.pending_cr_swallows_lf {
                self.pending_cr_swallows_lf = false;
                if remaining[0] == b'\n' {
                    remaining = &remaining[1..];
                    continue;
                }
            }

            // Scan only newly received bytes. Never copy a complete transport
            // chunk or rescan an incomplete line after every tiny fragment.
            let line_end = remaining
                .iter()
                .position(|byte| matches!(byte, b'\r' | b'\n'))
                .unwrap_or(remaining.len());
            if let Err(error) = self.append_fragment(&remaining[..line_end]) {
                self.terminate();
                output.push(Err(error));
                break;
            }
            remaining = &remaining[line_end..];
            let Some(terminator) = remaining.first() else {
                break;
            };
            self.pending_cr_swallows_lf = *terminator == b'\r';
            remaining = &remaining[1..];

            if let Some(event) = self.process_line() {
                let terminal = matches!(&event, Ok(OpenAiStreamEvent::Done) | Err(_));
                output.push(event);
                if terminal {
                    self.terminate();
                    break;
                }
            }
        }

        output
    }

    /// End the stream and report truncation unless `[DONE]` or an error ended it.
    ///
    /// Empty, comment-only and unterminated streams are truncated too. EOF does
    /// not dispatch a partial SSE block. The error is emitted only once.
    pub fn finish(&mut self) -> Option<Result<OpenAiStreamEvent, OpenAiError>> {
        if self.terminal {
            return None;
        }
        self.terminate();
        Some(Err(OpenAiError::Network(NetworkError::ConnectionDropped)))
    }

    /// Whether a terminal `[DONE]` was observed.
    pub const fn is_done(&self) -> bool {
        self.done
    }

    fn append_fragment(&mut self, bytes: &[u8]) -> Result<(), OpenAiError> {
        let required = self.buffer.len().saturating_add(bytes.len());
        if required > self.max_buffer_size {
            return Err(self.overflow_error());
        }
        if required > self.buffer.capacity() {
            // Grow geometrically without Vec's implicit capacity overshoot.
            let capacity = required
                .max(self.buffer.capacity().saturating_mul(2))
                .max(64)
                .min(self.max_buffer_size);
            self.buffer
                .try_reserve_exact(capacity - self.buffer.len())
                .map_err(|_| self.overflow_error())?;
            if self.buffer.capacity() > self.max_buffer_size {
                return Err(self.overflow_error());
            }
        }
        self.buffer.extend_from_slice(bytes);
        Ok(())
    }

    fn overflow_error(&self) -> OpenAiError {
        OpenAiError::Streaming(StreamingError::MalformedPayload {
            message: format!(
                "SSE framing exceeds the retained buffer limit of {} bytes",
                self.max_buffer_size
            ),
        })
    }

    fn terminate(&mut self) {
        self.terminal = true;
        self.buffer = Vec::new();
        self.line_start = 0;
        self.event_is_error = false;
        self.pending_cr_swallows_lf = false;
    }

    fn process_line(&mut self) -> Option<Result<OpenAiStreamEvent, OpenAiError>> {
        let mut start = self.line_start;
        if self.first_line {
            self.first_line = false;
            if self.buffer[start..].starts_with(b"\xef\xbb\xbf") {
                start += 3;
            }
        }
        let line = &self.buffer[start..];
        if line.is_empty() {
            self.buffer.truncate(self.line_start);
            return self.dispatch_event();
        }
        let (field, value_start) =
            line.iter()
                .position(|byte| *byte == b':')
                .map_or((line, self.buffer.len()), |colon| {
                    let mut value_start = start + colon + 1;
                    if self.buffer.get(value_start) == Some(&b' ') {
                        value_start += 1;
                    }
                    (&line[..colon], value_start)
                });

        if field == b"data" {
            // Compact into the same allocation. Even an empty data field
            // consumes its retained newline, without per-line heap objects.
            let value_len = self.buffer.len() - value_start;
            self.buffer.copy_within(value_start.., self.line_start);
            self.buffer.truncate(self.line_start + value_len);
            self.buffer.push(b'\n');
            self.line_start = self.buffer.len();
        } else {
            if field == b"event" {
                self.event_is_error = &self.buffer[value_start..] == b"error";
            }
            // Comments and unknown fields carry no retained event state.
            self.buffer.truncate(self.line_start);
        }
        None
    }

    fn dispatch_event(&mut self) -> Option<Result<OpenAiStreamEvent, OpenAiError>> {
        let event_is_error = std::mem::take(&mut self.event_is_error);
        if self.line_start == 0 {
            return None;
        }
        self.line_start = 0;
        self.buffer.pop(); // SSE removes the last data-field newline.
        let data = match String::from_utf8(std::mem::take(&mut self.buffer)) {
            Ok(data) => data,
            Err(_) => {
                return Some(Err(OpenAiError::Streaming(
                    StreamingError::MalformedPayload {
                        message: "SSE data is not valid UTF-8".to_owned(),
                    },
                )));
            }
        };

        if data.trim() == "[DONE]" {
            self.done = true;
            return Some(Ok(OpenAiStreamEvent::Done));
        }

        if event_is_error {
            return Some(Err(OpenAiError::Streaming(StreamingError::ProviderEvent {
                message: redact_sensitive_text(&data),
            })));
        }

        match serde_json::from_str::<ChatChunk>(&data) {
            Ok(chunk) => Some(Ok(OpenAiStreamEvent::Chunk(chunk))),
            Err(err) => Some(Err(OpenAiError::Streaming(
                StreamingError::MalformedPayload {
                    // Invalid JSON cannot be reliably structurally redacted.
                    // Preserve the location, never the provider's raw payload.
                    message: format!(
                        "invalid chat chunk JSON at line {}, column {}",
                        err.line(),
                        err.column()
                    ),
                },
            ))),
        }
    }
}

/// Accumulate streamed content and tool-call argument deltas for tests and
/// callers that need whole-message materialization.
pub fn accumulate_chunks(chunks: &[ChatChunk]) -> (String, Vec<String>) {
    let (content, _reasoning_content, tool_arguments) = accumulate_chunks_with_reasoning(chunks);
    (content, tool_arguments)
}

/// Accumulate streamed final content, reasoning content, and tool-call argument
/// deltas while preserving the distinction between reasoning and final answer.
pub fn accumulate_chunks_with_reasoning(chunks: &[ChatChunk]) -> (String, String, Vec<String>) {
    let mut content = String::new();
    let mut reasoning_content = String::new();
    let mut tool_arguments: VecDeque<String> = VecDeque::new();
    for chunk in chunks {
        for choice in &chunk.choices {
            if let Some(delta) = &choice.delta.content {
                content.push_str(delta);
            }
            if let Some(delta) = &choice.delta.reasoning_content {
                reasoning_content.push_str(delta);
            }
            if let Some(tool_calls) = &choice.delta.tool_calls {
                for tool_call in tool_calls {
                    let index = usize::try_from(tool_call.index).unwrap_or(usize::MAX);
                    while tool_arguments.len() <= index {
                        tool_arguments.push_back(String::new());
                    }
                    if let Some(function) = &tool_call.function {
                        if let Some(arguments) = &function.arguments {
                            if let Some(slot) = tool_arguments.get_mut(index) {
                                slot.push_str(arguments);
                            }
                        }
                    }
                }
            }
        }
    }
    (
        content,
        reasoning_content,
        tool_arguments.into_iter().collect(),
    )
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use serde_json::json;

    use super::*;

    fn decode_all(chunks: &[&str]) -> Vec<Result<OpenAiStreamEvent, OpenAiError>> {
        let mut decoder = OpenAiSseDecoder::new();
        let mut output = Vec::new();
        for chunk in chunks {
            output.extend(decoder.feed(&Bytes::copy_from_slice(chunk.as_bytes())));
        }
        if let Some(event) = decoder.finish() {
            output.push(event);
        }
        output
    }

    fn chunk_json(content: Option<&str>, finish_reason: Option<&str>) -> String {
        json!({
            "id": "chatcmpl-1",
            "object": "chat.completion.chunk",
            "created": 1,
            "model": "test",
            "choices": [{
                "index": 0,
                "delta": {"content": content},
                "finish_reason": finish_reason
            }]
        })
        .to_string()
    }

    #[test]
    fn decodes_single_chunk_and_done() {
        let frame = format!("data: {}\n\ndata: [DONE]\n\n", chunk_json(Some("hi"), None));
        let output = decode_all(&[&frame]);
        assert_eq!(output.len(), 2);
        assert!(matches!(output[0], Ok(OpenAiStreamEvent::Chunk(_))));
        assert!(matches!(output[1], Ok(OpenAiStreamEvent::Done)));
    }

    #[test]
    fn buffers_split_frames() {
        let frame = format!("data: {}\n\n", chunk_json(Some("split"), None));
        let midpoint = frame.len() / 2;
        let output = decode_all(&[&frame[..midpoint], &frame[midpoint..], "data: [DONE]\n\n"]);
        assert!(matches!(output[0], Ok(OpenAiStreamEvent::Chunk(_))));
        assert!(matches!(output[1], Ok(OpenAiStreamEvent::Done)));
    }

    #[test]
    fn ignores_heartbeat_comments() {
        let frame = format!(
            ": heartbeat\n\ndata: {}\n\ndata: [DONE]\n\n",
            chunk_json(Some("x"), None)
        );
        let output = decode_all(&[&frame]);
        assert_eq!(output.len(), 2);
    }

    #[test]
    fn event_error_maps_to_streaming_error() {
        let output = decode_all(&["event: error\ndata: {\"error\":{\"message\":\"bad\"}}\n\n"]);
        assert!(matches!(
            &output[0],
            Err(OpenAiError::Streaming(StreamingError::ProviderEvent { .. }))
        ));
    }

    #[test]
    fn malformed_json_payload_is_rejected() {
        let output = decode_all(&["data: {not-json}\n\ndata: [DONE]\n\n"]);
        assert!(matches!(
            &output[0],
            Err(OpenAiError::Streaming(
                StreamingError::MalformedPayload { .. }
            ))
        ));
    }

    #[test]
    fn network_drop_without_done_is_error() {
        let frame = format!("data: {}\n\n", chunk_json(Some("partial"), None));
        let output = decode_all(&[&frame]);
        assert!(matches!(
            output.last(),
            Some(Err(OpenAiError::Network(NetworkError::ConnectionDropped)))
        ));
    }

    #[test]
    fn bom_multiline_data_and_line_endings_survive_every_fragment_boundary() {
        let payload = chunk_json(Some("hi \u{feff} π 😀"), None);
        let split = payload.find(',').expect("JSON has multiple fields") + 1;
        let expected = vec![
            Ok(OpenAiStreamEvent::Chunk(
                serde_json::from_str(&payload).unwrap(),
            )),
            Ok(OpenAiStreamEvent::Done),
        ];
        for newline in ["\n", "\r\n", "\r"] {
            let frame = format!(
                "\u{feff}data: {}{newline}: heartbeat{newline}data: {}{newline}{newline}data: [DONE]{newline}{newline}",
                &payload[..split],
                &payload[split..],
            );
            for boundary in 0..=frame.len() {
                let mut decoder = OpenAiSseDecoder::new();
                let mut events =
                    decoder.feed(&Bytes::copy_from_slice(&frame.as_bytes()[..boundary]));
                events.extend(decoder.feed(&Bytes::new()));
                events.extend(decoder.feed(&Bytes::copy_from_slice(&frame.as_bytes()[boundary..])));
                assert_eq!(events, expected, "newline {newline:?}, boundary {boundary}");
                assert!(decoder.is_done());
                assert!(decoder.finish().is_none());
                assert_eq!(decoder.buffer.capacity(), 0);
            }
            let mut decoder = OpenAiSseDecoder::new();
            let mut events = Vec::new();
            for byte in frame.bytes() {
                events.extend(decoder.feed(&Bytes::copy_from_slice(&[byte])));
                events.extend(decoder.feed(&Bytes::new()));
            }
            assert_eq!(events, expected, "one-byte fragments with {newline:?}");
        }
    }

    #[test]
    fn buffer_limit_applies_to_partial_events_not_whole_transport_chunks() {
        let payload = chunk_json(Some("bounded"), None);
        let frame = format!("data: {payload}\n\n");
        let limit = frame.len();
        let mut decoder = OpenAiSseDecoder::with_max_buffer_size(limit);
        let input = format!("{}data: [DONE]\n\n", frame.repeat(32));
        assert!(input.len() > limit * 32);
        let events = decoder.feed(&Bytes::from(input));
        assert_eq!(events.len(), 33);
        assert!(
            events[..32]
                .iter()
                .all(|event| matches!(event, Ok(OpenAiStreamEvent::Chunk(_))))
        );
        assert_eq!(events[32], Ok(OpenAiStreamEvent::Done));
        assert!(decoder.finish().is_none());
    }

    #[test]
    fn oversized_partial_lines_fail_before_unbounded_retention() {
        for prefix in ["data: ", "event: ", ": ", "unknown: "] {
            let mut decoder = OpenAiSseDecoder::with_max_buffer_size(64);
            assert!(
                decoder
                    .feed(&Bytes::from_static(prefix.as_bytes()))
                    .is_empty()
            );
            let mut errors = 0;
            for _ in 0..128 {
                for event in decoder.feed(&Bytes::from_static(b"x")) {
                    assert!(matches!(
                        event,
                        Err(OpenAiError::Streaming(
                            StreamingError::MalformedPayload { .. }
                        ))
                    ));
                    errors += 1;
                }
                assert!(decoder.buffer.len() <= 64);
                assert!(decoder.buffer.capacity() <= 64);
            }
            assert_eq!(errors, 1, "{prefix}");
            assert_eq!(decoder.buffer.capacity(), 0);
            assert!(!decoder.is_done());
            assert!(decoder.finish().is_none());
            assert!(
                decoder
                    .feed(&Bytes::from_static(b"data: [DONE]\n\n"))
                    .is_empty()
            );
        }
    }

    #[test]
    fn empty_data_fields_consume_bounded_space_without_per_line_allocations() {
        for field in [b"data:\n".as_slice(), b"data\n".as_slice()] {
            let mut decoder = OpenAiSseDecoder::with_max_buffer_size(64);
            let mut errors = 0;
            for _ in 0..128 {
                for event in decoder.feed(&Bytes::from_static(field)) {
                    assert!(matches!(
                        event,
                        Err(OpenAiError::Streaming(
                            StreamingError::MalformedPayload { .. }
                        ))
                    ));
                    errors += 1;
                }
                assert!(decoder.buffer.len() <= 64);
                assert!(decoder.buffer.capacity() <= 64);
            }
            assert_eq!(errors, 1);
            assert_eq!(decoder.buffer.capacity(), 0);
            assert!(decoder.finish().is_none());
        }
    }

    #[test]
    fn overflow_keeps_complete_prefix_and_fuses_before_trailing_done() {
        let payload = chunk_json(Some("kept"), None);
        let mut decoder = OpenAiSseDecoder::with_max_buffer_size(512);
        let events = decoder.feed(&Bytes::from(format!(
            "data: {payload}\n\ndata: {}\n\ndata: [DONE]\n\n",
            "x".repeat(513),
        )));
        assert_eq!(events.len(), 2);
        assert_eq!(
            events[0],
            Ok(OpenAiStreamEvent::Chunk(
                serde_json::from_str(&payload).unwrap()
            ))
        );
        assert!(matches!(
            events[1],
            Err(OpenAiError::Streaming(
                StreamingError::MalformedPayload { .. }
            ))
        ));
        assert!(!decoder.is_done());
        assert!(decoder.finish().is_none());
        assert_eq!(decoder.buffer.capacity(), 0);
    }

    #[test]
    fn done_and_errors_are_sticky_and_ignore_same_chunk_suffixes() {
        let payload = chunk_json(Some("prefix"), None);
        for (terminal, done) in [
            ("data: [DONE]\n\n", true),
            ("event: error\ndata: {\"message\":\"failed\"}\n\n", false),
            ("data: {not-json}\n\n", false),
        ] {
            let mut decoder = OpenAiSseDecoder::with_max_buffer_size(512);
            let input = format!(
                "data: {payload}\n\n{terminal}data: {payload}\n\ndata: {}",
                "x".repeat(1024),
            );
            let events = decoder.feed(&Bytes::from(input));
            assert_eq!(events.len(), 2, "{terminal}");
            assert!(matches!(events[0], Ok(OpenAiStreamEvent::Chunk(_))));
            if done {
                assert_eq!(events[1], Ok(OpenAiStreamEvent::Done));
            } else {
                assert!(events[1].is_err());
            }
            assert_eq!(decoder.is_done(), done);
            assert_eq!(decoder.buffer.capacity(), 0);
            for _ in 0..3 {
                assert!(
                    decoder
                        .feed(&Bytes::from_static(b"data: [DONE]\n\n"))
                        .is_empty()
                );
                assert!(decoder.finish().is_none());
            }
        }
    }

    #[test]
    fn every_eof_without_a_dispatched_done_is_one_truncation_error() {
        let complete_chunk = format!("data: {}\n\n", chunk_json(Some("partial"), None));
        for input in [
            "",
            ": heartbeat\n\n",
            "event: message\n\n",
            "data: [DONE]",
            "data: [DONE]\n",
            complete_chunk.as_str(),
        ] {
            let mut decoder = OpenAiSseDecoder::new();
            let events = decoder.feed(&Bytes::copy_from_slice(input.as_bytes()));
            assert!(events.iter().all(Result::is_ok));
            assert!(!decoder.is_done());
            assert_eq!(
                decoder.finish(),
                Some(Err(OpenAiError::Network(NetworkError::ConnectionDropped))),
                "{input}"
            );
            assert_eq!(decoder.buffer.capacity(), 0);
            assert!(decoder.finish().is_none());
            assert!(
                decoder
                    .feed(&Bytes::from_static(b"data: [DONE]\n\n"))
                    .is_empty()
            );
        }
    }

    #[test]
    fn invalid_utf8_is_terminal_and_malformed_errors_never_echo_payloads() {
        let mut decoder = OpenAiSseDecoder::new();
        let events = decoder.feed(&Bytes::from_static(b"data: \xff\n\ndata: [DONE]\n\n"));
        assert_eq!(events.len(), 1);
        assert!(matches!(
            events[0],
            Err(OpenAiError::Streaming(
                StreamingError::MalformedPayload { .. }
            ))
        ));
        assert!(decoder.finish().is_none());
        let output = decode_all(&["data: {\"content\":\"private completion\",bad}\n\n"]);
        let error = output[0].as_ref().unwrap_err().to_string();
        assert!(!error.contains("private completion"));
        assert!(error.contains("line"));
    }

    #[test]
    fn configured_limits_are_finite_and_zero_never_allocates_for_fields() {
        let decoder = OpenAiSseDecoder::with_max_buffer_size(usize::MAX);
        assert_eq!(decoder.max_buffer_size, MAX_SSE_BUFFER_SIZE);
        assert_eq!(decoder.buffer.capacity(), 0);
        let mut decoder = OpenAiSseDecoder::with_max_buffer_size(0);
        let events = decoder.feed(&Bytes::from_static(b"data:\n\n"));
        assert_eq!(events.len(), 1);
        assert!(events[0].is_err());
        assert_eq!(decoder.buffer.capacity(), 0);
    }

    #[test]
    fn accumulates_content_and_tool_call_arguments() {
        let chunks: Vec<ChatChunk> = [
            json!({
                "id": "chatcmpl-1",
                "object": "chat.completion.chunk",
                "created": 1,
                "model": "test",
                "choices": [{
                    "index": 0,
                    "delta": {
                        "content": "he",
                        "tool_calls": [{
                            "index": 0,
                            "id": "call_1",
                            "type": "function",
                            "function": {"name": "lookup", "arguments": "{\"q\""}
                        }]
                    },
                    "finish_reason": null
                }]
            }),
            json!({
                "id": "chatcmpl-1",
                "object": "chat.completion.chunk",
                "created": 1,
                "model": "test",
                "choices": [{
                    "index": 0,
                    "delta": {
                        "content": "llo",
                        "tool_calls": [{
                            "index": 0,
                            "function": {"arguments": ":\"x\"}"}
                        }]
                    },
                    "finish_reason": "tool_calls"
                }]
            }),
        ]
        .into_iter()
        .map(|value| serde_json::from_value(value).expect("chunk fixture is valid"))
        .collect();

        let (content, tool_args) = accumulate_chunks(&chunks);
        assert_eq!(content, "hello");
        assert_eq!(tool_args, vec!["{\"q\":\"x\"}".to_string()]);
    }

    #[test]
    fn accumulates_reasoning_content_separately_from_final_content() {
        let chunks: Vec<ChatChunk> = [
            json!({
                "id": "chunk-1",
                "object": "chat.completion.chunk",
                "created": 1,
                "model": "deepseek-v4-pro",
                "choices": [{
                    "index": 0,
                    "delta": {"reasoning_content": "think "},
                    "finish_reason": null
                }]
            }),
            json!({
                "id": "chunk-2",
                "object": "chat.completion.chunk",
                "created": 1,
                "model": "deepseek-v4-pro",
                "choices": [{
                    "index": 0,
                    "delta": {"content": "answer"},
                    "finish_reason": "stop"
                }]
            }),
        ]
        .into_iter()
        .map(|value| serde_json::from_value(value).expect("chunk fixture is valid"))
        .collect();

        let (content, reasoning_content, tool_args) = accumulate_chunks_with_reasoning(&chunks);
        assert_eq!(content, "answer");
        assert_eq!(reasoning_content, "think ");
        assert!(tool_args.is_empty());

        let (legacy_content, legacy_tool_args) = accumulate_chunks(&chunks);
        assert_eq!(legacy_content, "answer");
        assert!(legacy_tool_args.is_empty());
    }
}
