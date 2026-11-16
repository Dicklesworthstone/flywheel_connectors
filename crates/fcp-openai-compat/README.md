# OpenAI-compatible client support

This crate provides the shared HTTP client, request and response types, error
redaction, rate-limit handling, SSE decoder, and completion collector used by the
OpenAI-compatible connectors.

## Streaming completion results

The Cerebras, DeepSeek, Fireworks, GLM, Groq, LM Studio, Microsoft Foundry,
Moonshot, NVIDIA NIM, Ollama, Qwen, Together, and xAI connectors use
`collect_chat_stream` for their streaming invocation operations. The collector
consumes provider events incrementally and returns one materialized response
after the stream completes. It does not retain the raw chunk sequence.

The result keeps each choice separate, including interleaved parallel tool calls:

- `content`, `reasoning_content`, `finish_reason`, and `tool_calls` describe choice
  zero. Tool calls contain their complete `id`, `type`, function `name`, and
  assembled `arguments` string, ordered by the provider's tool index.
- `choices` contains every choice in index order. Each entry includes its
  `index`, assembled assistant `message`, and `finish_reason`. Provider-specific
  delta fields are retained in arrival order as `provider_deltas`, when present;
  their merge semantics remain provider-specific.
- `usage` preserves the last provider usage snapshot, including a trailing chunk
  with an empty `choices` array. It is `null` when the provider does not supply
  usage. `system_fingerprint` similarly preserves the last supplied value.
- `chunk_count`, `tool_call_delta_count`, and `reasoning_delta_count` describe the
  consumed stream. A tool-call delta count measures choice deltas containing at
  least one tool fragment, rather than the number of finished tool calls.
- `chunks` contains only chunk IDs, model IDs, choice counts, content and
  reasoning byte counts, and usage-presence flags. Completion text, reasoning,
  and tool arguments are returned in the assembled choices, not this metadata.

Function arguments remain strings because streaming fragments need not be valid
JSON individually. Callers must inspect the finish reason and validate the final
arguments against the tool's schema before execution. Provider finish reasons
such as `length` and `content_filter` remain visible rather than being changed to
`stop`.

### Completion and resource limits

The shared HTTP stream requires the SSE `[DONE]` marker. The collector also
requires a terminal finish reason for every observed choice and complete,
consistent tool identities. Missing termination, conflicting identities,
duplicate indexes in a chunk, unsupported tool types, and provider or transport
errors fail the invocation. An error stops further polling and no partial
completion is returned as success.

Default limits are 65,536 chunks, 128 choices, and 128 tool calls per choice.
Choice and tool indexes must be below 128; sparse indexes do not allocate dense
arrays. The summed JSON encoding of accepted chunks and the final serialized
response are each capped at 10 MiB. Incoming chunks are measured individually,
and the final response is measured once, so fragmented output does not repeatedly
reserialize accumulated text. `ChatStreamAccumulator::with_limits` supports
explicit limits for direct crate consumers.

`accumulate_chunks` and `accumulate_chunks_with_reasoning` also use this bounded
collector and return `Result`. These convenience helpers expose choice-zero
text and argument strings; use the full summary when consuming tool identities,
additional choices, reasoning extensions, or usage accounting.

The implementation and adversarial stream fixtures are in
[`src/sse.rs`](src/sse.rs). The Groq connector additionally exercises the full
authorized invocation path through a real loopback HTTP server in
[`local_non_mock.rs`](../../connectors/groq/tests/local_non_mock.rs).
