//! OpenAI-compatible SSE decoding.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write};

use bytes::Bytes;
use futures_util::{Stream, StreamExt};
use serde::Serialize;

use crate::{
    ChatChunk, ChatMessage, FunctionCall, NetworkError, OpenAiError, ProviderExtensions,
    StreamingError, ToolCall, Usage, redact_sensitive_text,
};

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

/// Bounds for materializing a streaming completion into one invoke response.
///
/// The byte budget applies to all consumed chunk JSON and to the final response
/// JSON. Counting retains no payload bytes. Cardinality limits also bound map
/// and metadata overhead, even for empty deltas.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChatStreamLimits {
    /// Maximum aggregate encoded bytes (10 MiB by default).
    pub max_bytes: usize,
    /// Maximum chunks, including usage-only chunks.
    pub max_chunks: usize,
    /// Maximum choice count and exclusive choice-index bound.
    pub max_choices: usize,
    /// Maximum tool count and exclusive tool-index bound within each choice.
    pub max_tool_calls_per_choice: usize,
}

impl Default for ChatStreamLimits {
    fn default() -> Self {
        Self {
            max_bytes: 10 * 1024 * 1024,
            max_chunks: 65_536,
            max_choices: 128,
            max_tool_calls_per_choice: 128,
        }
    }
}

/// Per-chunk metadata without completion text, reasoning, or tool arguments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ChatStreamChunkMetadata {
    /// Provider chunk identity.
    pub id: String,
    /// Number of choices in this chunk.
    pub choice_count: usize,
    /// Provider model identity.
    pub model: String,
    /// Bytes of final-content deltas across all choices.
    pub content_delta_bytes: usize,
    /// Bytes of reasoning deltas across all choices.
    pub reasoning_delta_bytes: usize,
    /// Whether this chunk contains usage accounting.
    pub has_usage: bool,
}

/// One assembled choice. Tool indexes are local to this choice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ChatStreamChoice {
    /// Original provider choice index.
    pub index: u32,
    /// Assistant message with assembled text, reasoning, and tool calls.
    pub message: ChatMessage,
    /// Provider terminal reason; `length` and `content_filter` remain visible.
    pub finish_reason: String,
    /// Uninterpreted provider-specific delta fields, in arrival order.
    /// Their merge semantics are provider-specific; retain the fragments rather
    /// than silently discard reasoning details, refusals, or other extensions.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub provider_deltas: Vec<ProviderExtensions>,
}

/// Bounded materialization of a complete chat stream.
///
/// Convenience fields describe choice zero; `choices` preserves alternatives
/// without mixing their text or tool arguments. Arguments remain JSON strings:
/// callers must validate them against their tool schemas before execution and
/// inspect each finish reason before using possibly truncated model output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ChatStreamSummary {
    /// Final text for choice zero (empty for pure tool-call responses).
    pub content: String,
    /// Reasoning text for choice zero, when exposed by the provider.
    pub reasoning_content: String,
    /// Final-text length in bytes for choice zero.
    pub content_bytes: usize,
    /// Reasoning-text length in bytes for choice zero.
    pub reasoning_content_bytes: usize,
    /// Terminal reason for choice zero.
    pub finish_reason: String,
    /// Assembled choice-zero tool calls, ordered by tool index.
    pub tool_calls: Vec<ToolCall>,
    /// All choices in ascending index order.
    pub choices: Vec<ChatStreamChoice>,
    /// Last provider usage snapshot, including a trailing usage-only chunk.
    pub usage: Option<Usage>,
    /// Last provider system fingerprint.
    pub system_fingerprint: Option<String>,
    /// Number of consumed chunks.
    pub chunk_count: u64,
    /// Number of choice deltas carrying one or more tool-call fragments.
    pub tool_call_delta_count: u64,
    /// Number of choice deltas carrying reasoning content.
    pub reasoning_delta_count: u64,
    /// Payload-free metadata in original chunk order.
    pub chunks: Vec<ChatStreamChunkMetadata>,
}

#[derive(Debug, Default)]
struct AccumulatedToolCall {
    id: Option<String>,
    tool_type: Option<String>,
    name: String,
    arguments: String,
}

#[derive(Debug, Default)]
struct AccumulatedChoice {
    content: Option<String>,
    reasoning_content: Option<String>,
    tools: BTreeMap<u32, AccumulatedToolCall>,
    finish_reason: Option<String>,
    provider_deltas: Vec<ProviderExtensions>,
}

/// Incremental, bounded completion collector shared by provider connectors.
///
/// No raw chunks or vectors indexed by provider input are retained. A rejected
/// chunk poisons the collector and releases payloads, preventing publication of
/// a partial completion after an error.
#[derive(Debug, Default)]
pub struct ChatStreamAccumulator {
    limits: ChatStreamLimits,
    bytes: usize,
    choices: BTreeMap<u32, AccumulatedChoice>,
    chunks: Vec<ChatStreamChunkMetadata>,
    usage: Option<Usage>,
    system_fingerprint: Option<String>,
    tool_call_delta_count: u64,
    reasoning_delta_count: u64,
    failed: bool,
}

impl ChatStreamAccumulator {
    /// Construct a collector using the default limits.
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct a collector using caller-controlled limits.
    pub fn with_limits(limits: ChatStreamLimits) -> Self {
        Self {
            limits,
            ..Self::default()
        }
    }

    /// Apply one chunk, preserving choice and tool-call identities.
    pub fn push(&mut self, chunk: ChatChunk) -> Result<(), OpenAiError> {
        if self.failed {
            return Err(aggregation_error(
                "completion collector is already terminated",
            ));
        }
        let result = self.push_inner(chunk);
        if result.is_err() {
            self.failed = true;
            self.choices.clear();
            self.chunks = Vec::new();
            self.system_fingerprint = None;
        }
        result
    }

    fn push_inner(&mut self, chunk: ChatChunk) -> Result<(), OpenAiError> {
        if self.chunks.len() >= self.limits.max_chunks {
            return Err(aggregation_error("completion exceeds the chunk limit"));
        }
        self.bytes +=
            encoded_size_with_limit(&chunk, self.limits.max_bytes.saturating_sub(self.bytes))?;
        if chunk.choices.len() > self.limits.max_choices {
            return Err(aggregation_error("completion exceeds the choice limit"));
        }

        let mut seen_choices = BTreeSet::new();
        let mut metadata = ChatStreamChunkMetadata {
            id: chunk.id,
            choice_count: chunk.choices.len(),
            model: chunk.model,
            content_delta_bytes: 0,
            reasoning_delta_bytes: 0,
            has_usage: chunk.usage.is_some(),
        };
        for choice in chunk.choices {
            if usize::try_from(choice.index).map_or(true, |index| index >= self.limits.max_choices)
            {
                return Err(aggregation_error(
                    "choice index exceeds the configured limit",
                ));
            }
            if !seen_choices.insert(choice.index) {
                return Err(aggregation_error("duplicate choice index in one chunk"));
            }
            if choice
                .delta
                .role
                .as_deref()
                .is_some_and(|role| role != "assistant")
            {
                return Err(aggregation_error(
                    "completion delta has a non-assistant role",
                ));
            }
            let state = self.choices.entry(choice.index).or_default();
            if state.finish_reason.is_some() {
                return Err(aggregation_error(
                    "received a delta after the choice finished",
                ));
            }
            if let Some(content) = choice.delta.content {
                metadata.content_delta_bytes += content.len();
                state
                    .content
                    .get_or_insert_with(String::new)
                    .push_str(&content);
            }
            if let Some(reasoning) = choice.delta.reasoning_content {
                metadata.reasoning_delta_bytes += reasoning.len();
                self.reasoning_delta_count += 1;
                state
                    .reasoning_content
                    .get_or_insert_with(String::new)
                    .push_str(&reasoning);
            }
            if let Some(tools) = choice.delta.tool_calls {
                if tools.len() > self.limits.max_tool_calls_per_choice {
                    return Err(aggregation_error("completion exceeds the tool-call limit"));
                }
                if !tools.is_empty() {
                    self.tool_call_delta_count += 1;
                }
                let mut seen_tools = BTreeSet::new();
                for tool in tools {
                    if usize::try_from(tool.index)
                        .map_or(true, |index| index >= self.limits.max_tool_calls_per_choice)
                    {
                        return Err(aggregation_error("tool index exceeds the configured limit"));
                    }
                    if !seen_tools.insert(tool.index) {
                        return Err(aggregation_error(
                            "duplicate tool index in one choice delta",
                        ));
                    }
                    let accumulated = state.tools.entry(tool.index).or_default();
                    if let Some(id) = tool.id.filter(|id| !id.is_empty()) {
                        if accumulated
                            .id
                            .as_ref()
                            .is_some_and(|existing| *existing != id)
                        {
                            return Err(aggregation_error("tool-call identity changed mid-stream"));
                        }
                        accumulated.id = Some(id);
                    }
                    if let Some(tool_type) = tool.tool_type.filter(|kind| !kind.is_empty()) {
                        if tool_type != "function" {
                            return Err(aggregation_error("unsupported streamed tool-call type"));
                        }
                        accumulated.tool_type = Some(tool_type);
                    }
                    if let Some(function) = tool.function {
                        if let Some(name) = function.name {
                            if !accumulated.name.is_empty()
                                && !name.is_empty()
                                && accumulated.name != name
                            {
                                return Err(aggregation_error(
                                    "tool-call function changed mid-stream",
                                ));
                            }
                            if !name.is_empty() {
                                accumulated.name = name;
                            }
                        }
                        if let Some(arguments) = function.arguments {
                            accumulated.arguments.push_str(&arguments);
                        }
                    }
                }
            }
            if !choice.delta.provider_extensions.is_empty() {
                state.provider_deltas.push(choice.delta.provider_extensions);
            }
            if let Some(reason) = choice.finish_reason {
                if reason.is_empty() {
                    return Err(aggregation_error("empty completion finish reason"));
                }
                state.finish_reason = Some(reason);
            }
        }
        if let Some(usage) = chunk.usage {
            self.usage = Some(usage);
        }
        if let Some(fingerprint) = chunk.system_fingerprint {
            self.system_fingerprint = Some(fingerprint);
        }
        self.chunks.push(metadata);
        Ok(())
    }

    /// Finish after the transport has completed successfully.
    ///
    /// Every choice must have a finish reason. Missing tool identity metadata,
    /// duplicate tool IDs, and a missing choice zero are rejected. The native
    /// `ChatCompletionStream` additionally requires the SSE `[DONE]` marker.
    pub fn finish(self) -> Result<ChatStreamSummary, OpenAiError> {
        if self.failed {
            return Err(aggregation_error(
                "completion collector is already terminated",
            ));
        }
        if !self.choices.contains_key(&0) {
            return Err(aggregation_error("completed stream has no choice zero"));
        }
        let mut choices = Vec::with_capacity(self.choices.len());
        for (index, state) in self.choices {
            let finish_reason = state
                .finish_reason
                .ok_or(OpenAiError::Network(NetworkError::ConnectionDropped))?;
            let mut tool_ids = BTreeSet::new();
            let mut tool_calls = Vec::with_capacity(state.tools.len());
            for tool in state.tools.into_values() {
                let id = tool.id.filter(|id| !id.is_empty()).ok_or_else(|| {
                    aggregation_error("completed tool call is missing its identity")
                })?;
                if !tool_ids.insert(id.clone()) {
                    return Err(aggregation_error(
                        "distinct tool indexes share one identity",
                    ));
                }
                let tool_type = tool
                    .tool_type
                    .ok_or_else(|| aggregation_error("completed tool call is missing its type"))?;
                if tool.name.is_empty() {
                    return Err(aggregation_error(
                        "completed tool call is missing its function name",
                    ));
                }
                tool_calls.push(ToolCall {
                    id,
                    tool_type,
                    function: FunctionCall {
                        name: tool.name,
                        arguments: tool.arguments,
                    },
                });
            }
            if finish_reason == "tool_calls" && tool_calls.is_empty() {
                return Err(aggregation_error(
                    "tool-call finish reason has no tool calls",
                ));
            }
            choices.push(ChatStreamChoice {
                index,
                message: ChatMessage::Assistant {
                    content: state.content,
                    reasoning_content: state.reasoning_content,
                    tool_calls: (!tool_calls.is_empty()).then_some(tool_calls),
                    name: None,
                    provider_extensions: ProviderExtensions::new(),
                },
                finish_reason,
                provider_deltas: state.provider_deltas,
            });
        }
        let first = &choices[0];
        let (content, reasoning_content, tool_calls) = match &first.message {
            ChatMessage::Assistant {
                content,
                reasoning_content,
                tool_calls,
                ..
            } => (
                content.clone().unwrap_or_default(),
                reasoning_content.clone().unwrap_or_default(),
                tool_calls.clone().unwrap_or_default(),
            ),
            _ => unreachable!("the collector only creates assistant messages"),
        };
        let summary = ChatStreamSummary {
            content_bytes: content.len(),
            reasoning_content_bytes: reasoning_content.len(),
            content,
            reasoning_content,
            finish_reason: first.finish_reason.clone(),
            tool_calls,
            choices,
            usage: self.usage,
            system_fingerprint: self.system_fingerprint,
            chunk_count: u64::try_from(self.chunks.len()).unwrap_or(u64::MAX),
            tool_call_delta_count: self.tool_call_delta_count,
            reasoning_delta_count: self.reasoning_delta_count,
            chunks: self.chunks,
        };
        encoded_size_with_limit(&summary, self.limits.max_bytes)?;
        Ok(summary)
    }
}

fn aggregation_error(message: &'static str) -> OpenAiError {
    OpenAiError::Streaming(StreamingError::MalformedPayload {
        message: message.to_owned(),
    })
}

fn encoded_size_with_limit(value: &impl Serialize, limit: usize) -> Result<usize, OpenAiError> {
    struct Counter {
        bytes: usize,
        limit: usize,
    }
    impl Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if bytes.len() > self.limit.saturating_sub(self.bytes) {
                return Err(io::Error::other("completion byte limit exceeded"));
            }
            self.bytes += bytes.len();
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter { bytes: 0, limit };
    serde_json::to_writer(&mut counter, value)
        .map_err(|_| aggregation_error("completion exceeds the aggregate byte limit"))?;
    Ok(counter.bytes)
}

/// Consume a completion stream incrementally and return one bounded result.
///
/// Any transport, provider, cancellation, framing, or aggregation error drops the
/// stream immediately. No further chunks are polled or partial output published.
pub async fn collect_chat_stream(
    stream: impl Stream<Item = Result<ChatChunk, OpenAiError>>,
) -> Result<ChatStreamSummary, OpenAiError> {
    let mut stream = std::pin::pin!(stream);
    let mut accumulator = ChatStreamAccumulator::new();
    while let Some(chunk) = stream.next().await {
        accumulator.push(chunk?)?;
    }
    accumulator.finish()
}

/// Materialize choice-zero content and tool arguments from a bounded chunk list.
pub fn accumulate_chunks(chunks: &[ChatChunk]) -> Result<(String, Vec<String>), OpenAiError> {
    let (content, _reasoning_content, tool_arguments) = accumulate_chunks_with_reasoning(chunks)?;
    Ok((content, tool_arguments))
}

/// Materialize choice-zero final text, reasoning, and tool arguments separately.
pub fn accumulate_chunks_with_reasoning(
    chunks: &[ChatChunk],
) -> Result<(String, String, Vec<String>), OpenAiError> {
    let mut accumulator = ChatStreamAccumulator::new();
    for chunk in chunks {
        accumulator.push(chunk.clone())?;
    }
    let summary = accumulator.finish()?;
    Ok((
        summary.content,
        summary.reasoning_content,
        summary
            .tool_calls
            .into_iter()
            .map(|tool| tool.function.arguments)
            .collect(),
    ))
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

        let (content, tool_args) = accumulate_chunks(&chunks).expect("complete tool response");
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

        let (content, reasoning_content, tool_args) =
            accumulate_chunks_with_reasoning(&chunks).expect("complete reasoning response");
        assert_eq!(content, "answer");
        assert_eq!(reasoning_content, "think ");
        assert!(tool_args.is_empty());

        let (legacy_content, legacy_tool_args) =
            accumulate_chunks(&chunks).expect("complete response");
        assert_eq!(legacy_content, "answer");
        assert!(legacy_tool_args.is_empty());
    }

    fn aggregation_chunk(choices: serde_json::Value) -> ChatChunk {
        serde_json::from_value(json!({
            "id": "completion-1", "object": "chat.completion.chunk",
            "created": 1, "model": "fixture", "choices": choices,
        }))
        .expect("valid aggregation fixture")
    }

    #[test]
    fn accumulator_preserves_interleaved_choices_tools_reasoning_and_final_usage() {
        let mut collector = ChatStreamAccumulator::new();
        collector
            .push(aggregation_chunk(json!([
                {"index": 1, "delta": {"content": "alternative", "tool_calls": [
                    {"index": 0, "id": "other-choice", "type": "function",
                     "function": {"name": "other", "arguments": "{\"b\":"}}
                ]}},
                {"index": 0, "delta": {"role": "assistant", "content": "primary ",
                    "reasoning_content": "private reasoning", "provider_detail": {"ref": 1},
                    "tool_calls": [
                        {"index": 1, "id": "second", "type": "function",
                         "function": {"name": "second_tool", "arguments": "["}},
                        {"index": 0, "id": "first", "type": "function",
                         "function": {"name": "first_tool", "arguments": "{\"a\":"}}
                    ]}}
            ])))
            .expect("initial interleaved deltas");
        collector
            .push(aggregation_chunk(json!([
                {"index": 0, "delta": {"content": "answer", "tool_calls": [
                    {"index": 0, "id": "first", "type": "function",
                     "function": {"name": "first_tool", "arguments": "1}"}},
                {"index": 1, "id": "", "type": "", "function": {"name": "", "arguments": "2]"}}
                ]}, "finish_reason": "tool_calls"},
                {"index": 1, "delta": {"tool_calls": [
                    {"index": 0, "function": {"arguments": "3}"}}
                ]}, "finish_reason": "tool_calls"}
            ])))
            .expect("terminal deltas");
        let mut usage = aggregation_chunk(json!([]));
        usage.usage = Some(Usage {
            prompt_tokens: 5,
            completion_tokens: 8,
            total_tokens: 13,
        });
        usage.system_fingerprint = Some("fingerprint".into());
        collector.push(usage).expect("usage-only chunk");

        let summary = collector.finish().expect("complete stream");
        assert_eq!(summary.content, "primary answer");
        assert_eq!(summary.reasoning_content, "private reasoning");
        assert_eq!(summary.tool_calls[0].id, "first");
        assert_eq!(summary.tool_calls[0].function.name, "first_tool");
        assert_eq!(summary.tool_calls[0].function.arguments, "{\"a\":1}");
        assert_eq!(summary.tool_calls[1].id, "second");
        assert_eq!(summary.tool_calls[1].function.arguments, "[2]");
        assert_eq!(summary.choices[0].index, 0);
        assert_eq!(summary.choices[1].index, 1);
        let secondary = serde_json::to_value(&summary.choices[1]).expect("serializable choice");
        assert_eq!(secondary["message"]["content"], "alternative");
        assert_eq!(
            secondary["message"]["tool_calls"][0]["function"]["arguments"],
            "{\"b\":3}"
        );
        assert_eq!(summary.usage.expect("usage").total_tokens, 13);
        assert_eq!(summary.system_fingerprint.as_deref(), Some("fingerprint"));
        assert_eq!(summary.chunk_count, 3);
        assert_eq!(summary.tool_call_delta_count, 4);
        assert_eq!(summary.reasoning_delta_count, 1);
        assert!(summary.chunks[2].has_usage);
        assert_eq!(summary.chunks[2].choice_count, 0);
        assert_eq!(
            summary.choices[0].provider_deltas[0]["provider_detail"],
            json!({"ref": 1})
        );
        let metadata = serde_json::to_string(&summary.chunks).expect("serializable metadata");
        assert!(!metadata.contains("primary answer"));
        assert!(!metadata.contains("private reasoning"));
        assert!(!metadata.contains("first_tool"));
    }

    #[test]
    fn accumulator_rejects_huge_and_duplicate_indexes_without_retained_state() {
        for choices in [
            json!([{"index": u32::MAX, "delta": {}}]),
            json!([{"index": 0, "delta": {}}, {"index": 0, "delta": {}}]),
            json!([{"index": 0, "delta": {"tool_calls": [{"index": u32::MAX}]}}]),
            json!([{"index": 0, "delta": {"tool_calls": [{"index": 0}, {"index": 0}]}}]),
        ] {
            let mut collector = ChatStreamAccumulator::new();
            let error = collector
                .push(aggregation_chunk(choices))
                .expect_err("invalid indexes");
            assert!(matches!(error, OpenAiError::Streaming(_)));
            assert!(collector.choices.is_empty());
            assert!(collector.chunks.is_empty());
            assert!(collector.push(aggregation_chunk(json!([]))).is_err());
            assert!(collector.finish().is_err());
        }
    }

    #[test]
    fn accumulator_handles_sparse_tool_indexes_without_dense_allocation() {
        let mut collector = ChatStreamAccumulator::new();
        collector
            .push(aggregation_chunk(json!([{
                "index": 0, "delta": {"tool_calls": [{
                    "index": 127, "id": "sparse", "type": "function",
                    "function": {"name": "lookup", "arguments": "{}"}
                }]}, "finish_reason": "tool_calls"
            }])))
            .expect("bounded sparse index");
        assert_eq!(collector.choices[&0].tools.len(), 1);
        let summary = collector.finish().expect("complete sparse call");
        assert_eq!(summary.tool_calls.len(), 1);
        assert_eq!(summary.tool_calls[0].id, "sparse");
    }

    #[test]
    fn accumulator_rejects_conflicting_tool_metadata_and_post_finish_deltas() {
        for delta in [
            json!({"tool_calls": [{"index": 0, "id": "replacement"}]}),
            json!({"tool_calls": [{"index": 0, "function": {"name": "replacement"}}]}),
            json!({"tool_calls": [{"index": 0, "type": "custom"}]}),
            json!({"role": "user"}),
        ] {
            let mut collector = ChatStreamAccumulator::new();
            collector
                .push(aggregation_chunk(json!([{"index": 0, "delta": {
                    "tool_calls": [{"index": 0, "id": "original", "type": "function",
                        "function": {"name": "lookup", "arguments": ""}}]
                }}])))
                .expect("initial identity");
            assert!(
                collector
                    .push(aggregation_chunk(json!([{"index": 0, "delta": delta}])))
                    .is_err()
            );
            assert!(collector.finish().is_err());
        }
        let mut collector = ChatStreamAccumulator::new();
        collector
            .push(aggregation_chunk(json!([{
                "index": 0, "delta": {"content": "done"}, "finish_reason": "stop"
            }])))
            .expect("finished choice");
        assert!(
            collector
                .push(aggregation_chunk(json!([{
                    "index": 0, "delta": {"content": "late"}
                }])))
                .is_err()
        );
    }

    #[test]
    fn accumulator_refuses_missing_terminal_or_tool_identity_metadata() {
        for choices in [
            json!([]),
            json!([{"index": 0, "delta": {"content": "unfinished"}}]),
            json!([{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]),
            json!([{"index": 0, "delta": {"tool_calls": [{
                "index": 0, "type": "function", "function": {"name": "missing_id", "arguments": "{}"}
            }]}, "finish_reason": "tool_calls"}]),
            json!([{"index": 0, "delta": {"tool_calls": [{
                "index": 0, "id": "missing_type", "function": {"name": "lookup", "arguments": "{}"}
            }]}, "finish_reason": "tool_calls"}]),
            json!([{"index": 0, "delta": {"tool_calls": [{
                "index": 0, "id": "missing_name", "type": "function", "function": {"arguments": "{}"}
            }]}, "finish_reason": "tool_calls"}]),
            json!([{"index": 0, "delta": {"tool_calls": [
                {"index": 0, "id": "duplicate", "type": "function", "function": {"name": "a"}},
                {"index": 1, "id": "duplicate", "type": "function", "function": {"name": "b"}}
            ]}, "finish_reason": "tool_calls"}]),
        ] {
            let mut collector = ChatStreamAccumulator::new();
            collector
                .push(aggregation_chunk(choices))
                .expect("decodable fragment");
            assert!(
                collector.finish().is_err(),
                "incomplete completion must not succeed"
            );
        }
    }

    #[test]
    fn accumulator_enforces_input_output_and_cardinality_budgets() {
        let chunk = aggregation_chunk(json!([{
            "index": 0, "delta": {"content": "hello"}, "finish_reason": "stop"
        }]));
        let encoded = serde_json::to_vec(&chunk).expect("encode fixture").len();
        let mut too_small = ChatStreamAccumulator::with_limits(ChatStreamLimits {
            max_bytes: encoded - 1,
            ..ChatStreamLimits::default()
        });
        assert!(too_small.push(chunk.clone()).is_err());

        let mut baseline = ChatStreamAccumulator::new();
        baseline.push(chunk.clone()).expect("baseline input");
        let summary = baseline.finish().expect("baseline summary");
        let summary_size = serde_json::to_vec(&summary).expect("encode summary").len();
        assert!(summary_size > encoded);
        for (limit, succeeds) in [(summary_size, true), (summary_size - 1, false)] {
            let mut collector = ChatStreamAccumulator::with_limits(ChatStreamLimits {
                max_bytes: limit,
                ..ChatStreamLimits::default()
            });
            collector.push(chunk.clone()).expect("input fits");
            assert_eq!(collector.finish().is_ok(), succeeds);
        }

        let mut chunk_limited = ChatStreamAccumulator::with_limits(ChatStreamLimits {
            max_chunks: 1,
            ..ChatStreamLimits::default()
        });
        chunk_limited.push(chunk).expect("one chunk allowed");
        assert!(chunk_limited.push(aggregation_chunk(json!([]))).is_err());
        assert!(chunk_limited.finish().is_err());

        let mut choice_limited = ChatStreamAccumulator::with_limits(ChatStreamLimits {
            max_choices: 1,
            ..ChatStreamLimits::default()
        });
        assert!(
            choice_limited
                .push(aggregation_chunk(json!([{"index": 1, "delta": {}}])))
                .is_err()
        );
        let mut tool_limited = ChatStreamAccumulator::with_limits(ChatStreamLimits {
            max_tool_calls_per_choice: 1,
            ..ChatStreamLimits::default()
        });
        assert!(
            tool_limited
                .push(aggregation_chunk(json!([{
                    "index": 0, "delta": {"tool_calls": [{"index": 1}]}
                }])))
                .is_err()
        );
    }

    #[test]
    fn collector_stops_immediately_on_provider_and_limit_errors() {
        use futures_util::FutureExt as _;

        let error = OpenAiError::Network(NetworkError::ConnectionDropped);
        let chunks =
            futures_util::stream::iter([Err(error.clone())]).chain(futures_util::stream::pending());
        let result = collect_chat_stream(chunks)
            .now_or_never()
            .expect("must not await more chunks");
        assert_eq!(result.expect_err("transport error preserved"), error);

        let invalid = aggregation_chunk(json!([{"index": u32::MAX, "delta": {}}]));
        let chunks =
            futures_util::stream::iter([Ok(invalid)]).chain(futures_util::stream::pending());
        assert!(
            collect_chat_stream(chunks)
                .now_or_never()
                .expect("limit stops collection")
                .is_err()
        );
    }

    #[test]
    fn collector_preserves_finish_reasons_but_refuses_truncated_transport() {
        use futures_util::FutureExt as _;

        for reason in ["stop", "length", "content_filter"] {
            let frame = format!(
                "data: {}\n\n",
                chunk_json(Some("partial or full"), Some(reason))
            );
            for completed in [false, true] {
                let terminal = if completed { "data: [DONE]\n\n" } else { "" };
                let chunks = decode_all(&[&frame, terminal])
                    .into_iter()
                    .filter_map(|event| match event {
                        Ok(OpenAiStreamEvent::Chunk(chunk)) => Some(Ok(chunk)),
                        Ok(OpenAiStreamEvent::Done) => None,
                        Err(error) => Some(Err(error)),
                    });
                let result = collect_chat_stream(futures_util::stream::iter(chunks))
                    .now_or_never()
                    .expect("ready fixture");
                if completed {
                    assert_eq!(result.expect("complete transport").finish_reason, reason);
                } else {
                    assert_eq!(
                        result.expect_err("missing DONE"),
                        OpenAiError::Network(NetworkError::ConnectionDropped)
                    );
                }
            }
        }
    }
}
