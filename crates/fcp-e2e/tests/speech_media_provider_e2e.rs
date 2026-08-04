//! Deepgram and ElevenLabs connector-boundary evidence.
//!
//! This deterministic lane covers the implemented prerecorded, finite realtime,
//! and finite streaming speech/media surfaces. It deliberately records only
//! counts, hashes, ids, and status mappings: no transcripts, source URLs, audio
//! bytes, generated text, or API keys.

#![cfg(all(feature = "deepgram", feature = "elevenlabs"))]
#![allow(clippy::too_many_lines)]

use std::future::poll_fn;
use std::io::{self, Write as _};
use std::pin::Pin;
use std::task::Poll;
use std::time::{Duration, Instant};

use asupersync::net::websocket::{
    CloseReason, Message as ServerWsMessage, ServerWebSocket, WebSocketAcceptor,
};
use base64::Engine as _;
use fcp_async_core::io::{AsyncRead, AsyncWriteExt, ReadBuf};
use fcp_async_core::net::{TcpListener, TcpStream};
use fcp_deepgram::DeepgramConnector;
use fcp_e2e::{HttpFixtureResponse, HttpFixtureRoute, HttpFixtureServer, RecordedHttpRequest};
use fcp_elevenlabs::ElevenlabsConnector;
use fcp_prelude::FcpError;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const ARTIFACT_PATH: &str = "target/fcp-speech-media/speech-media-e2e.jsonl";
const DEEPGRAM_TRANSCRIBE: &str = "deepgram.listen.transcribe";
const DEEPGRAM_STREAM: &str = "deepgram.listen.stream";
const ELEVEN_VOICES: &str = "elevenlabs.voices.list";
const ELEVEN_TTS: &str = "elevenlabs.tts.generate";
const ELEVEN_TTS_STREAM: &str = "elevenlabs.tts.stream";
const ELEVEN_SCRIBE_REALTIME: &str = "elevenlabs.scribe.realtime.transcribe";
const MAX_HEADERS: usize = 16 * 1024;

type TestServerWebSocket = ServerWebSocket<TcpStream>;

#[fcp_async_core::runtime::test]
async fn speech_media_provider_loopback_emits_redacted_evidence() {
    let mut records = Vec::new();
    run_deepgram_fixture_script(&mut records).await;
    run_elevenlabs_fixture_script(&mut records).await;

    let jsonl = write_jsonl_artifact(&records);
    assert!(jsonl.contains("\"fixture_mode\":\"loopback_http_tcp\""));
    assert!(jsonl.contains("\"fixture_mode\":\"loopback_websocket_tcp\""));
    assert!(jsonl.contains("\"fixture_mode\":\"loopback_http_chunked_tcp\""));
    assert!(jsonl.contains("\"operation_id\":\"deepgram.listen.stream\""));
    assert!(jsonl.contains("\"operation_id\":\"elevenlabs.scribe.realtime.transcribe\""));
    assert!(jsonl.contains("\"operation_id\":\"elevenlabs.tts.stream\""));
    assert!(jsonl.contains("\"provider\":\"deepgram\""));
    assert!(jsonl.contains("\"provider\":\"elevenlabs\""));
    assert!(!jsonl.contains("deepgram-fixture-key"));
    assert!(!jsonl.contains("eleven-fixture-key"));
    assert!(!jsonl.contains("https://media.example.test"));
    assert!(!jsonl.contains("fixture transcript"));
    assert!(!jsonl.contains("hello from deepgram realtime"));
    assert!(!jsonl.contains("hello from elevenlabs realtime"));
    assert!(!jsonl.contains("hello from fixture"));
    assert!(!jsonl.contains("streaming tts fixture"));
    assert!(!jsonl.contains("unsupported format fixture"));
    assert!(!jsonl.contains("AQIDBAU="));
    assert!(!jsonl.contains("aGVsbG8="));
    assert!(!jsonl.contains("d29ybGQ="));
    assert_eq!(fcp_e2e::scan_log_jsonl(&jsonl).error_count, 0);
}

async fn run_deepgram_fixture_script(records: &mut Vec<Value>) {
    let server = HttpFixtureServer::start().expect("Deepgram loopback should bind");
    mount_deepgram_transcribe_success(&server);
    let mut connector = configured_deepgram(&server, 5_000).await;

    let started = Instant::now();
    let transcript = deepgram_invoke(
        &connector,
        json!({
            "audio_url": "https://media.example.test/path/customer-audio.wav",
            "language": "en",
            "smart_format": true
        }),
    )
    .await
    .expect("Deepgram fixture transcription should succeed");
    assert_single_deepgram_transcribe_request(&server, "customer-audio.wav");
    records.push(evidence_record(EvidenceInput {
        provider: "deepgram",
        operation: DEEPGRAM_TRANSCRIBE,
        scenario_id: "deepgram_prerecorded_success",
        latency_ms: started.elapsed().as_millis(),
        http_status: Some(200),
        retry_decision: "not_needed",
        fcp_error_mapping: "ok",
        skip_reason: None,
        details: json!({
            "model_id": "nova-3",
            "media_reference_hash": hash_label("https://media.example.test/path/customer-audio.wav"),
            "media_byte_count": Value::Null,
            "transcript_char_count": transcript_char_count(&transcript),
            "stream_frame_count": 0_u64,
            "streaming_supported": false,
            "realtime_scope": "not_in_this_slice"
        }),
    }));

    let cleanup_result = connector
        .handle_shutdown(json!({ "reason": "speech media fixture complete" }))
        .await
        .map(|_| "shutdown_ok")
        .unwrap_or("shutdown_error");
    records.push(evidence_record(EvidenceInput {
        provider: "deepgram",
        operation: "deepgram.cleanup",
        scenario_id: "deepgram_cleanup",
        latency_ms: 0,
        http_status: None,
        retry_decision: "not_needed",
        fcp_error_mapping: "ok",
        skip_reason: None,
        details: json!({ "cleanup_result": cleanup_result }),
    }));

    let rate_server = HttpFixtureServer::start().expect("Deepgram rate limit loopback should bind");
    mount_deepgram_rate_limit(&rate_server);
    let rate_connector = configured_deepgram(&rate_server, 5_000).await;
    let started = Instant::now();
    let rate_limited = deepgram_invoke(
        &rate_connector,
        json!({"audio_url": "https://media.example.test/path/rate-limit.wav"}),
    )
    .await
    .expect_err("rate-limited fixture should fail");
    assert_single_deepgram_transcribe_request(&rate_server, "rate-limit.wav");
    records.push(evidence_record(EvidenceInput {
        provider: "deepgram",
        operation: DEEPGRAM_TRANSCRIBE,
        scenario_id: "deepgram_rate_limit",
        latency_ms: started.elapsed().as_millis(),
        http_status: Some(429),
        retry_decision: "provider_returned_retry_after",
        fcp_error_mapping: classify_error(&rate_limited),
        skip_reason: None,
        details: json!({
            "model_id": "nova-3",
            "media_reference_hash": hash_label("https://media.example.test/path/rate-limit.wav"),
            "media_byte_count": Value::Null,
            "stream_frame_count": 0_u64
        }),
    }));

    let oversized = deepgram_invoke(
        &rate_connector,
        json!({
            "audio_url": "https://media.example.test/path/oversized.wav",
            "media_byte_count": 1_073_741_825_u64
        }),
    )
    .await
    .expect_err("oversized media fixture should fail before network I/O");
    records.push(evidence_record(EvidenceInput {
        provider: "deepgram",
        operation: DEEPGRAM_TRANSCRIBE,
        scenario_id: "deepgram_oversized_media_denial",
        latency_ms: 0,
        http_status: None,
        retry_decision: "not_attempted",
        fcp_error_mapping: classify_error(&oversized),
        skip_reason: None,
        details: json!({
            "model_id": "nova-3",
            "media_reference_hash": hash_label("https://media.example.test/path/oversized.wav"),
            "media_byte_count": 1_073_741_825_u64,
            "stream_frame_count": 0_u64
        }),
    }));

    let mut credential_connector = DeepgramConnector::new();
    credential_connector
        .handle_configure(json!({ "credential_id": "deepgram-credential-ref" }))
        .await
        .expect("credential-id configure should succeed");
    credential_connector
        .handle_handshake(json!({}))
        .await
        .expect("credential-id handshake should succeed");
    let denied = credential_connector
        .handle_invoke(json!({
            "operation_id": DEEPGRAM_TRANSCRIBE,
            "input": { "audio_url": "https://media.example.test/path/denied.wav" }
        }))
        .await
        .expect_err("credential-id mode should be denied without host injection");
    records.push(evidence_record(EvidenceInput {
        provider: "deepgram",
        operation: DEEPGRAM_TRANSCRIBE,
        scenario_id: "deepgram_credential_injection_required",
        latency_ms: 0,
        http_status: None,
        retry_decision: "not_attempted",
        fcp_error_mapping: classify_error(&denied),
        skip_reason: Some("host_credential_injection_not_available_in_fixture"),
        details: json!({
            "media_reference_hash": hash_label("https://media.example.test/path/denied.wav"),
            "stream_frame_count": 0_u64
        }),
    }));

    run_deepgram_realtime_success(records).await;
    run_deepgram_realtime_error(records).await;
}

async fn run_elevenlabs_fixture_script(records: &mut Vec<Value>) {
    let server = HttpFixtureServer::start().expect("ElevenLabs loopback should bind");
    mount_elevenlabs_voices(&server);
    mount_elevenlabs_tts(&server);
    let mut connector = configured_elevenlabs(&server, 5_000).await;

    let started = Instant::now();
    let voices = elevenlabs_invoke(&connector, ELEVEN_VOICES, json!({}))
        .await
        .expect("ElevenLabs voices fixture should succeed");
    assert_elevenlabs_voices_request(&server);
    records.push(evidence_record(EvidenceInput {
        provider: "elevenlabs",
        operation: ELEVEN_VOICES,
        scenario_id: "elevenlabs_voices_success",
        latency_ms: started.elapsed().as_millis(),
        http_status: Some(200),
        retry_decision: "not_needed",
        fcp_error_mapping: "ok",
        skip_reason: None,
        details: json!({
            "voice_count": voices["voices"].as_array().map_or(0, Vec::len),
            "voice_id": "voice-fixture",
            "model_id": "eleven_multilingual_v2",
            "stream_frame_count": 0_u64,
            "streaming_supported": false,
            "realtime_scope": "not_in_this_slice"
        }),
    }));

    let started = Instant::now();
    let speech = elevenlabs_invoke(
        &connector,
        ELEVEN_TTS,
        json!({
            "voice_id": "voice-fixture",
            "text": "hello from fixture",
            "output_format": "mp3_44100_128",
            "seed": 7_u64
        }),
    )
    .await
    .expect("ElevenLabs TTS fixture should succeed");
    assert_elevenlabs_tts_request(&server);
    records.push(evidence_record(EvidenceInput {
        provider: "elevenlabs",
        operation: ELEVEN_TTS,
        scenario_id: "elevenlabs_tts_success",
        latency_ms: started.elapsed().as_millis(),
        http_status: Some(200),
        retry_decision: "not_needed",
        fcp_error_mapping: "ok",
        skip_reason: None,
        details: json!({
            "voice_id": speech["voice_id"].clone(),
            "model_id": "eleven_multilingual_v2",
            "audio_content_type": speech["content_type"].clone(),
            "audio_byte_count": speech["audio_size_bytes"].clone(),
            "output_format": "mp3_44100_128",
            "generated_text_hash": hash_label("hello from fixture"),
            "stream_frame_count": 0_u64
        }),
    }));

    let unsupported_format = elevenlabs_invoke(
        &connector,
        ELEVEN_TTS,
        json!({
            "voice_id": "voice-fixture",
            "text": "unsupported format fixture",
            "output_format": "wav"
        }),
    )
    .await
    .expect_err("unsupported output format should fail before network I/O");
    records.push(evidence_record(EvidenceInput {
        provider: "elevenlabs",
        operation: ELEVEN_TTS,
        scenario_id: "elevenlabs_unsupported_output_format",
        latency_ms: 0,
        http_status: None,
        retry_decision: "not_attempted",
        fcp_error_mapping: classify_error(&unsupported_format),
        skip_reason: None,
        details: json!({
            "voice_id": "voice-fixture",
            "model_id": "eleven_multilingual_v2",
            "output_format": "wav",
            "generated_text_hash": hash_label("unsupported format fixture"),
            "stream_frame_count": 0_u64
        }),
    }));

    let cleanup_result = connector
        .handle_shutdown(json!({ "reason": "speech media fixture complete" }))
        .await
        .map(|_| "shutdown_ok")
        .unwrap_or("shutdown_error");
    records.push(evidence_record(EvidenceInput {
        provider: "elevenlabs",
        operation: "elevenlabs.cleanup",
        scenario_id: "elevenlabs_cleanup",
        latency_ms: 0,
        http_status: None,
        retry_decision: "not_needed",
        fcp_error_mapping: "ok",
        skip_reason: None,
        details: json!({ "cleanup_result": cleanup_result }),
    }));

    let timeout_server =
        HttpFixtureServer::start().expect("ElevenLabs timeout loopback should bind");
    mount_elevenlabs_slow_tts(&timeout_server);
    let timeout_connector = configured_elevenlabs(&timeout_server, 20).await;
    let started = Instant::now();
    let timeout = elevenlabs_invoke(
        &timeout_connector,
        ELEVEN_TTS,
        json!({"voice_id": "voice-timeout", "text": "timeout fixture"}),
    )
    .await
    .expect_err("timeout fixture should fail");
    records.push(evidence_record(EvidenceInput {
        provider: "elevenlabs",
        operation: ELEVEN_TTS,
        scenario_id: "elevenlabs_timeout",
        latency_ms: started.elapsed().as_millis(),
        http_status: None,
        retry_decision: "request_timed_out",
        fcp_error_mapping: classify_error(&timeout),
        skip_reason: None,
        details: json!({
            "voice_id": "voice-timeout",
            "generated_text_hash": hash_label("timeout fixture"),
            "stream_frame_count": 0_u64
        }),
    }));

    run_elevenlabs_tts_stream_success(records).await;
    run_elevenlabs_tts_stream_limit_failure(records).await;
    run_elevenlabs_realtime_success(records).await;
    run_elevenlabs_realtime_error(records).await;
}

async fn configured_deepgram(
    server: &HttpFixtureServer,
    request_timeout_ms: u64,
) -> DeepgramConnector {
    configured_deepgram_url(server.base_url(), request_timeout_ms).await
}

async fn configured_deepgram_url(base_url: String, request_timeout_ms: u64) -> DeepgramConnector {
    let mut connector = DeepgramConnector::new();
    connector
        .handle_configure(json!({
            "api_key": "deepgram-fixture-key",
            "base_url": base_url,
            "request_timeout_ms": request_timeout_ms
        }))
        .await
        .expect("Deepgram connector should configure");
    connector
        .handle_handshake(json!({}))
        .await
        .expect("Deepgram connector should handshake");
    connector
}

async fn configured_elevenlabs(
    server: &HttpFixtureServer,
    request_timeout_ms: u64,
) -> ElevenlabsConnector {
    configured_elevenlabs_url(server.base_url(), request_timeout_ms).await
}

async fn configured_elevenlabs_url(
    base_url: String,
    request_timeout_ms: u64,
) -> ElevenlabsConnector {
    let mut connector = ElevenlabsConnector::new();
    connector
        .handle_configure(json!({
            "api_key": "eleven-fixture-key",
            "base_url": base_url,
            "request_timeout_ms": request_timeout_ms
        }))
        .await
        .expect("ElevenLabs connector should configure");
    connector
        .handle_handshake(json!({"session_id": "speech-media-fixture"}))
        .await
        .expect("ElevenLabs connector should handshake");
    connector
}

async fn deepgram_invoke(
    connector: &DeepgramConnector,
    input: Value,
) -> fcp_core::FcpResult<Value> {
    connector
        .handle_invoke(json!({"operation_id": DEEPGRAM_TRANSCRIBE, "input": input}))
        .await
}

async fn deepgram_stream_invoke(
    connector: &DeepgramConnector,
    input: Value,
) -> fcp_core::FcpResult<Value> {
    connector
        .handle_invoke(json!({"operation_id": DEEPGRAM_STREAM, "input": input}))
        .await
}

async fn elevenlabs_invoke(
    connector: &ElevenlabsConnector,
    operation: &'static str,
    input: Value,
) -> fcp_core::FcpResult<Value> {
    connector
        .handle_invoke(json!({"operation_id": operation, "input": input}))
        .await
}

async fn run_deepgram_realtime_success(records: &mut Vec<Value>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind Deepgram realtime loopback");
    let base_url = format!(
        "http://{}",
        listener.local_addr().expect("listener local addr")
    );
    let expected_audio = base64::engine::general_purpose::STANDARD.encode(b"mulaw-audio");
    let server_task = fcp_async_core::task::spawn(async move {
        let (tcp_stream, _) = listener
            .accept()
            .await
            .expect("accept Deepgram websocket client");
        let (mut ws, headers) = accept_test_websocket(tcp_stream).await;
        assert!(
            headers.starts_with(
                "GET /v1/listen?model=nova-3&encoding=mulaw&sample_rate=8000&endpointing=800&interim_results=true HTTP/1.1"
            ),
            "unexpected Deepgram realtime request: {headers}"
        );
        assert!(
            headers.contains("Authorization: Token deepgram-fixture-key"),
            "missing Deepgram authorization header: {headers}"
        );
        expect_binary_frame(&mut ws, b"mulaw-audio", "receive Deepgram audio").await?;
        expect_json_text_field(&mut ws, "type", "Finalize", "receive Deepgram finalize").await?;
        expect_json_text_field(
            &mut ws,
            "type",
            "CloseStream",
            "receive Deepgram close stream",
        )
        .await?;
        send_json_frame(
            &mut ws,
            json!({
                "type": "Results",
                "is_final": false,
                "speech_final": false,
                "channel": {
                    "alternatives": [{
                        "transcript": "hello from",
                        "confidence": 0.91
                    }]
                }
            }),
            "send Deepgram partial results",
        )
        .await;
        send_json_frame(
            &mut ws,
            json!({
                "type": "Results",
                "is_final": true,
                "speech_final": true,
                "channel": {
                    "alternatives": [{
                        "transcript": "hello from deepgram realtime",
                        "confidence": 0.99
                    }]
                }
            }),
            "send Deepgram final results",
        )
        .await;
        send_json_frame(
            &mut ws,
            json!({
                "type": "Metadata",
                "request_id": "deepgram-realtime-fixture",
                "sha256": "redacted-fixture-hash",
                "duration": 0.25,
                "channels": 1
            }),
            "send Deepgram metadata",
        )
        .await;
        close_test_websocket(&mut ws).await;
        Ok::<(), String>(())
    });

    let connector = configured_deepgram_url(base_url, 5_000).await;
    let started = Instant::now();
    let result = deepgram_stream_invoke(
        &connector,
        json!({
            "audio_base64": expected_audio,
            "timeout_ms": 2_000,
            "connect_timeout_ms": 1_000,
            "max_reconnect_attempts": 0
        }),
    )
    .await
    .expect("Deepgram realtime loopback should succeed");
    server_task
        .await
        .expect("Deepgram realtime server task")
        .expect("Deepgram realtime server proof");
    assert_eq!(result["provider_request_id"], "deepgram-realtime-fixture");
    assert_eq!(result["text"], "hello from deepgram realtime");
    records.push(evidence_record(EvidenceInput {
        provider: "deepgram",
        operation: DEEPGRAM_STREAM,
        scenario_id: "deepgram_realtime_websocket_success",
        latency_ms: started.elapsed().as_millis(),
        http_status: None,
        retry_decision: "not_needed",
        fcp_error_mapping: "ok",
        skip_reason: None,
        details: json!({
            "fixture_mode": "loopback_websocket_tcp",
            "provider_fixture_id": "deepgram-realtime-fixture",
            "model_id": result["model"].clone(),
            "media_byte_count": result["stats"]["audio_bytes_sent"].clone(),
            "audio_content_type": "audio/mulaw",
            "transcript_char_count": result["text"].as_str().map_or(0, str::len),
            "stream_frame_count": result["stats"]["events_seen"].clone(),
            "stream_chunk_count": result["stats"]["audio_chunks_sent"].clone(),
            "websocket_status": "closed_normal",
            "streaming_supported": true,
            "realtime_scope": "finite_connector_boundary"
        }),
    }));
}

async fn run_deepgram_realtime_error(records: &mut Vec<Value>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind Deepgram realtime error loopback");
    let base_url = format!(
        "http://{}",
        listener.local_addr().expect("listener local addr")
    );
    let expected_audio = base64::engine::general_purpose::STANDARD.encode(b"mulaw-error");
    let server_task = fcp_async_core::task::spawn(async move {
        let (tcp_stream, _) = listener
            .accept()
            .await
            .expect("accept Deepgram error websocket client");
        let (mut ws, headers) = accept_test_websocket(tcp_stream).await;
        assert!(
            headers.contains("Authorization: Token deepgram-fixture-key"),
            "missing Deepgram authorization header: {headers}"
        );
        expect_binary_frame(&mut ws, b"mulaw-error", "receive Deepgram error audio").await?;
        expect_json_text_field(
            &mut ws,
            "type",
            "Finalize",
            "receive Deepgram error finalize",
        )
        .await?;
        expect_json_text_field(
            &mut ws,
            "type",
            "CloseStream",
            "receive Deepgram error close stream",
        )
        .await?;
        send_json_frame(
            &mut ws,
            json!({
                "type": "Error",
                "message": "redacted streaming fixture error"
            }),
            "send Deepgram error frame",
        )
        .await;
        close_test_websocket(&mut ws).await;
        Ok::<(), String>(())
    });

    let connector = configured_deepgram_url(base_url, 5_000).await;
    let started = Instant::now();
    let error = deepgram_stream_invoke(
        &connector,
        json!({
            "audio_base64": expected_audio,
            "timeout_ms": 2_000,
            "connect_timeout_ms": 1_000,
            "max_reconnect_attempts": 0
        }),
    )
    .await
    .expect_err("Deepgram realtime error fixture should fail");
    server_task
        .await
        .expect("Deepgram realtime error server task")
        .expect("Deepgram realtime error server proof");
    records.push(evidence_record(EvidenceInput {
        provider: "deepgram",
        operation: DEEPGRAM_STREAM,
        scenario_id: "deepgram_realtime_websocket_error",
        latency_ms: started.elapsed().as_millis(),
        http_status: None,
        retry_decision: "provider_error_frame",
        fcp_error_mapping: classify_error(&error),
        skip_reason: None,
        details: json!({
            "fixture_mode": "loopback_websocket_tcp",
            "provider_fixture_id": "deepgram-realtime-error",
            "model_id": "nova-3",
            "media_byte_count": 11_u64,
            "audio_content_type": "audio/mulaw",
            "stream_frame_count": 1_u64,
            "stream_chunk_count": 1_u64,
            "websocket_status": "provider_error_frame",
            "streaming_supported": true,
            "realtime_scope": "finite_connector_boundary"
        }),
    }));
}

async fn run_elevenlabs_tts_stream_success(records: &mut Vec<Value>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ElevenLabs TTS stream loopback");
    let base_url = format!(
        "http://{}",
        listener.local_addr().expect("listener local addr")
    );
    let server_task = fcp_async_core::task::spawn(async move {
        let (mut stream, _) = listener
            .accept()
            .await
            .expect("accept ElevenLabs TTS stream client");
        let headers = read_headers_string(&mut stream)
            .await
            .expect("read ElevenLabs TTS stream request");
        assert!(
            headers.starts_with(
                "POST /text-to-speech/voice-stream/stream?output_format=mp3_44100_128 HTTP/1.1"
            ),
            "unexpected ElevenLabs TTS stream request: {headers}"
        );
        let lower_headers = headers.to_ascii_lowercase();
        assert!(
            lower_headers.contains("xi-api-key: eleven-fixture-key"),
            "missing ElevenLabs API key header: {headers}"
        );
        assert!(
            lower_headers.contains("content-type: application/json"),
            "missing ElevenLabs JSON content type: {headers}"
        );
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: audio/mpeg\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n5\r\nworld\r\n0\r\n\r\n",
            )
            .await
            .expect("write ElevenLabs chunked TTS response");
        Ok::<(), String>(())
    });

    let connector = configured_elevenlabs_url(base_url, 5_000).await;
    let started = Instant::now();
    let result = elevenlabs_invoke(
        &connector,
        ELEVEN_TTS_STREAM,
        json!({
            "voice_id": "voice-stream",
            "text": "streaming tts fixture",
            "output_format": "mp3_44100_128",
            "max_audio_bytes": 128,
            "max_chunks": 16
        }),
    )
    .await
    .expect("ElevenLabs TTS stream fixture should succeed");
    server_task
        .await
        .expect("ElevenLabs TTS stream server task")
        .expect("ElevenLabs TTS stream proof");
    assert_eq!(result["audio_size_bytes"], 10);
    assert_eq!(result["audio_chunk_count"], 2);
    records.push(evidence_record(EvidenceInput {
        provider: "elevenlabs",
        operation: ELEVEN_TTS_STREAM,
        scenario_id: "elevenlabs_tts_stream_chunked_success",
        latency_ms: started.elapsed().as_millis(),
        http_status: Some(200),
        retry_decision: "not_needed",
        fcp_error_mapping: "ok",
        skip_reason: None,
        details: json!({
            "fixture_mode": "loopback_http_chunked_tcp",
            "provider_fixture_id": "elevenlabs-tts-stream-fixture",
            "voice_id": result["voice_id"].clone(),
            "model_id": "eleven_multilingual_v2",
            "audio_content_type": result["content_type"].clone(),
            "audio_byte_count": result["audio_size_bytes"].clone(),
            "output_format": "mp3_44100_128",
            "generated_text_hash": hash_label("streaming tts fixture"),
            "stream_frame_count": result["audio_chunk_count"].clone(),
            "stream_chunk_count": result["audio_chunk_count"].clone(),
            "websocket_status": Value::Null
        }),
    }));
}

async fn run_elevenlabs_tts_stream_limit_failure(records: &mut Vec<Value>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ElevenLabs TTS stream limit loopback");
    let base_url = format!(
        "http://{}",
        listener.local_addr().expect("listener local addr")
    );
    let server_task = fcp_async_core::task::spawn(async move {
        let (mut stream, _) = listener
            .accept()
            .await
            .expect("accept ElevenLabs TTS limit client");
        let headers = read_headers_string(&mut stream)
            .await
            .expect("read ElevenLabs TTS limit request");
        assert!(
            headers.contains("/text-to-speech/voice-stream-limit/stream"),
            "unexpected ElevenLabs TTS limit request: {headers}"
        );
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: audio/mpeg\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n5\r\nworld\r\n0\r\n\r\n",
            )
            .await
            .expect("write ElevenLabs chunked limit response");
        Ok::<(), String>(())
    });

    let connector = configured_elevenlabs_url(base_url, 5_000).await;
    let started = Instant::now();
    let error = elevenlabs_invoke(
        &connector,
        ELEVEN_TTS_STREAM,
        json!({
            "voice_id": "voice-stream-limit",
            "text": "streaming tts fixture",
            "output_format": "mp3_44100_128",
            "max_audio_bytes": 6,
            "max_chunks": 16
        }),
    )
    .await
    .expect_err("ElevenLabs TTS stream limit fixture should fail");
    server_task
        .await
        .expect("ElevenLabs TTS limit server task")
        .expect("ElevenLabs TTS limit proof");
    records.push(evidence_record(EvidenceInput {
        provider: "elevenlabs",
        operation: ELEVEN_TTS_STREAM,
        scenario_id: "elevenlabs_tts_stream_size_limit",
        latency_ms: started.elapsed().as_millis(),
        http_status: Some(200),
        retry_decision: "stream_limit_exceeded",
        fcp_error_mapping: classify_error(&error),
        skip_reason: None,
        details: json!({
            "fixture_mode": "loopback_http_chunked_tcp",
            "provider_fixture_id": "elevenlabs-tts-stream-limit",
            "voice_id": "voice-stream-limit",
            "model_id": "eleven_multilingual_v2",
            "audio_content_type": "audio/mpeg",
            "audio_byte_count": 10_u64,
            "output_format": "mp3_44100_128",
            "generated_text_hash": hash_label("streaming tts fixture"),
            "stream_frame_count": 2_u64,
            "stream_chunk_count": 2_u64,
            "websocket_status": Value::Null
        }),
    }));
}

async fn run_elevenlabs_realtime_success(records: &mut Vec<Value>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ElevenLabs realtime loopback");
    let base_url = format!(
        "http://{}",
        listener.local_addr().expect("listener local addr")
    );
    let expected_audio = base64::engine::general_purpose::STANDARD.encode(b"ulaw-audio");
    let server_task = fcp_async_core::task::spawn({
        let expected_audio = expected_audio.clone();
        async move {
            let (tcp_stream, _) = listener
                .accept()
                .await
                .expect("accept ElevenLabs realtime client");
            let (mut ws, headers) = accept_test_websocket(tcp_stream).await;
            assert!(
                headers.starts_with(
                    "GET /v1/speech-to-text/realtime?model_id=scribe_v2_realtime&audio_format=ulaw_8000&commit_strategy=vad&include_timestamps=false&include_language_detection=false&language_code=en HTTP/1.1"
                ),
                "unexpected ElevenLabs realtime request: {headers}"
            );
            assert!(
                headers.contains("xi-api-key: eleven-fixture-key"),
                "missing ElevenLabs realtime API key header: {headers}"
            );
            send_json_frame(
                &mut ws,
                json!({
                    "message_type": "session_started",
                    "session_id": "elevenlabs-realtime-fixture",
                    "config": {
                        "sample_rate": 8000,
                        "audio_format": "ulaw_8000",
                        "language_code": "en",
                        "model_id": "scribe_v2_realtime",
                        "include_timestamps": false,
                        "include_language_detection": false
                    }
                }),
                "send ElevenLabs session_started",
            )
            .await;
            expect_elevenlabs_audio_chunk(&mut ws, &expected_audio, false).await?;
            expect_elevenlabs_audio_chunk(&mut ws, "", true).await?;
            send_json_frame(
                &mut ws,
                json!({
                    "message_type": "partial_transcript",
                    "text": "hello from"
                }),
                "send ElevenLabs partial transcript",
            )
            .await;
            send_json_frame(
                &mut ws,
                json!({
                    "message_type": "committed_transcript_with_timestamps",
                    "text": "hello from elevenlabs realtime",
                    "language_code": "en",
                    "words": []
                }),
                "send ElevenLabs committed transcript",
            )
            .await;
            close_test_websocket(&mut ws).await;
            Ok::<(), String>(())
        }
    });

    let connector = configured_elevenlabs_url(base_url, 5_000).await;
    let started = Instant::now();
    let result = elevenlabs_invoke(
        &connector,
        ELEVEN_SCRIBE_REALTIME,
        json!({
            "audio_base64": expected_audio,
            "language_code": "en",
            "timeout_ms": 2_000,
            "connect_timeout_ms": 1_000,
            "max_reconnect_attempts": 0
        }),
    )
    .await
    .expect("ElevenLabs realtime fixture should succeed");
    server_task
        .await
        .expect("ElevenLabs realtime server task")
        .expect("ElevenLabs realtime proof");
    assert_eq!(result["provider_session_id"], "elevenlabs-realtime-fixture");
    assert_eq!(result["text"], "hello from elevenlabs realtime");
    records.push(evidence_record(EvidenceInput {
        provider: "elevenlabs",
        operation: ELEVEN_SCRIBE_REALTIME,
        scenario_id: "elevenlabs_scribe_realtime_websocket_success",
        latency_ms: started.elapsed().as_millis(),
        http_status: None,
        retry_decision: "not_needed",
        fcp_error_mapping: "ok",
        skip_reason: None,
        details: json!({
            "fixture_mode": "loopback_websocket_tcp",
            "provider_fixture_id": "elevenlabs-realtime-fixture",
            "model_id": result["model_id"].clone(),
            "media_byte_count": result["stats"]["audio_bytes_sent"].clone(),
            "audio_content_type": "audio/ulaw",
            "transcript_char_count": result["text"].as_str().map_or(0, str::len),
            "stream_frame_count": result["stats"]["events_seen"].clone(),
            "stream_chunk_count": result["stats"]["audio_chunks_sent"].clone(),
            "websocket_status": "closed_normal",
            "streaming_supported": true,
            "realtime_scope": "finite_connector_boundary"
        }),
    }));
}

async fn run_elevenlabs_realtime_error(records: &mut Vec<Value>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ElevenLabs realtime error loopback");
    let base_url = format!(
        "http://{}",
        listener.local_addr().expect("listener local addr")
    );
    let expected_audio = base64::engine::general_purpose::STANDARD.encode(b"ulaw-error");
    let server_task = fcp_async_core::task::spawn({
        let expected_audio = expected_audio.clone();
        async move {
            let (tcp_stream, _) = listener
                .accept()
                .await
                .expect("accept ElevenLabs realtime error client");
            let (mut ws, headers) = accept_test_websocket(tcp_stream).await;
            assert!(
                headers.contains("xi-api-key: eleven-fixture-key"),
                "missing ElevenLabs realtime API key header: {headers}"
            );
            send_json_frame(
                &mut ws,
                json!({
                    "message_type": "session_started",
                    "session_id": "elevenlabs-realtime-error",
                    "config": {
                        "sample_rate": 8000,
                        "audio_format": "ulaw_8000",
                        "language_code": "en",
                        "model_id": "scribe_v2_realtime"
                    }
                }),
                "send ElevenLabs error session_started",
            )
            .await;
            expect_elevenlabs_audio_chunk(&mut ws, &expected_audio, false).await?;
            expect_elevenlabs_audio_chunk(&mut ws, "", true).await?;
            send_json_frame(
                &mut ws,
                json!({
                    "message_type": "error",
                    "error": "redacted realtime fixture error"
                }),
                "send ElevenLabs realtime error",
            )
            .await;
            close_test_websocket(&mut ws).await;
            Ok::<(), String>(())
        }
    });

    let connector = configured_elevenlabs_url(base_url, 5_000).await;
    let started = Instant::now();
    let error = elevenlabs_invoke(
        &connector,
        ELEVEN_SCRIBE_REALTIME,
        json!({
            "audio_base64": expected_audio,
            "language_code": "en",
            "timeout_ms": 2_000,
            "connect_timeout_ms": 1_000,
            "max_reconnect_attempts": 0
        }),
    )
    .await
    .expect_err("ElevenLabs realtime error fixture should fail");
    server_task
        .await
        .expect("ElevenLabs realtime error server task")
        .expect("ElevenLabs realtime error proof");
    records.push(evidence_record(EvidenceInput {
        provider: "elevenlabs",
        operation: ELEVEN_SCRIBE_REALTIME,
        scenario_id: "elevenlabs_scribe_realtime_websocket_error",
        latency_ms: started.elapsed().as_millis(),
        http_status: None,
        retry_decision: "provider_error_frame",
        fcp_error_mapping: classify_error(&error),
        skip_reason: None,
        details: json!({
            "fixture_mode": "loopback_websocket_tcp",
            "provider_fixture_id": "elevenlabs-realtime-error",
            "model_id": "scribe_v2_realtime",
            "media_byte_count": 10_u64,
            "audio_content_type": "audio/ulaw",
            "stream_frame_count": 2_u64,
            "stream_chunk_count": 1_u64,
            "websocket_status": "provider_error_frame",
            "streaming_supported": true,
            "realtime_scope": "finite_connector_boundary"
        }),
    }));
}

fn mount_deepgram_transcribe_success(server: &HttpFixtureServer) {
    server.mount(
        HttpFixtureRoute::post("/v1/listen")
            .for_scenario("deepgram_prerecorded_success")
            .with_query("model", "nova-3")
            .require_header("authorization", "Token deepgram-fixture-key")
            .respond_with(HttpFixtureResponse::json(json!({
                "metadata": { "request_id": "deepgram-fixture" },
                "results": {
                    "channels": [{
                        "alternatives": [{
                            "transcript": "fixture transcript should stay out of evidence",
                            "confidence": 0.98
                        }]
                    }]
                }
            }))),
    );
}

fn mount_deepgram_rate_limit(server: &HttpFixtureServer) {
    server.mount(
        HttpFixtureRoute::post("/v1/listen")
            .for_scenario("deepgram_rate_limit")
            .with_query("model", "nova-3")
            .require_header("authorization", "Token deepgram-fixture-key")
            .respond_with(HttpFixtureResponse::rate_limited(
                2,
                json!({"error": "rate limited"}),
            )),
    );
}

fn mount_elevenlabs_voices(server: &HttpFixtureServer) {
    server.mount(
        HttpFixtureRoute::get("/voices")
            .for_scenario("elevenlabs_voices_success")
            .require_header("xi-api-key", "eleven-fixture-key")
            .respond_with(HttpFixtureResponse::json(json!({
                "voices": [{
                    "voice_id": "voice-fixture",
                    "name": "Fixture Voice",
                    "category": "generated"
                }]
            }))),
    );
}

fn mount_elevenlabs_tts(server: &HttpFixtureServer) {
    server.mount(
        HttpFixtureRoute::post("/text-to-speech/voice-fixture")
            .for_scenario("elevenlabs_tts_success")
            .with_query("output_format", "mp3_44100_128")
            .require_header("xi-api-key", "eleven-fixture-key")
            .respond_with(HttpFixtureResponse::binary(
                vec![1_u8, 2, 3, 4, 5],
                "audio/mpeg",
            )),
    );
}

fn mount_elevenlabs_slow_tts(server: &HttpFixtureServer) {
    server.mount(
        HttpFixtureRoute::post("/text-to-speech/voice-timeout")
            .for_scenario("elevenlabs_timeout")
            .require_header("xi-api-key", "eleven-fixture-key")
            .respond_with(
                HttpFixtureResponse::binary(vec![1_u8, 2, 3], "audio/mpeg")
                    .with_delay(Duration::from_millis(200)),
            ),
    );
}

fn assert_single_deepgram_transcribe_request(server: &HttpFixtureServer, media_name: &str) {
    let requests = server.recorded_requests();
    assert_eq!(requests.len(), 1, "expected one Deepgram HTTP request");
    let request = &requests[0];
    assert_eq!(request.method, "POST");
    assert_eq!(request.path, "/v1/listen");
    assert_eq!(request.query_value("model"), Some("nova-3"));
    assert_eq!(
        request.header("authorization"),
        Some("Token deepgram-fixture-key")
    );
    assert_eq!(
        request
            .body_json()
            .expect("Deepgram request body should be JSON"),
        json!({ "url": format!("https://media.example.test/path/{media_name}") })
    );
}

fn assert_elevenlabs_voices_request(server: &HttpFixtureServer) {
    let request = recorded_request(server, "GET", "/voices");
    assert_eq!(request.header("xi-api-key"), Some("eleven-fixture-key"));
}

fn assert_elevenlabs_tts_request(server: &HttpFixtureServer) {
    let request = recorded_request(server, "POST", "/text-to-speech/voice-fixture");
    assert_eq!(request.header("xi-api-key"), Some("eleven-fixture-key"));
    assert_eq!(request.query_value("output_format"), Some("mp3_44100_128"));
    assert_eq!(
        request
            .body_json()
            .expect("ElevenLabs TTS request body should be JSON"),
        json!({
            "text": "hello from fixture",
            "model_id": "eleven_multilingual_v2",
            "seed": 7_u64
        })
    );
}

fn recorded_request(server: &HttpFixtureServer, method: &str, path: &str) -> RecordedHttpRequest {
    server
        .recorded_requests()
        .into_iter()
        .find(|request| request.method == method && request.path == path)
        .unwrap_or_else(|| panic!("expected {method} {path} request"))
}

async fn read_http_headers<R>(stream: &mut R) -> io::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut buf = Vec::with_capacity(1024);
    let mut temp = [0_u8; 1024];
    loop {
        let read = poll_fn(|cx| {
            let mut read_buf = ReadBuf::new(&mut temp);
            match Pin::new(&mut *stream).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => Poll::Ready(Ok(read_buf.filled().len())),
                Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
                Poll::Pending => Poll::Pending,
            }
        })
        .await?;

        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "EOF before HTTP headers completed",
            ));
        }

        let filled = temp.get(..read).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP header read exceeded buffer",
            )
        })?;
        buf.extend_from_slice(filled);
        if buf.windows(4).any(|window| window == b"\r\n\r\n") {
            return Ok(buf);
        }
        if buf.len() > MAX_HEADERS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP headers too large",
            ));
        }
    }
}

async fn read_headers_string<R>(stream: &mut R) -> io::Result<String>
where
    R: AsyncRead + Unpin,
{
    read_http_headers(stream)
        .await
        .map(|headers| String::from_utf8_lossy(&headers).into_owned())
}

async fn accept_test_websocket(mut stream: TcpStream) -> (TestServerWebSocket, String) {
    let request = read_http_headers(&mut stream)
        .await
        .expect("read websocket handshake");
    let headers = String::from_utf8_lossy(&request).into_owned();
    let ws = WebSocketAcceptor::new()
        .accept(&fcp_async_core::compatibility_cx(), &request, stream)
        .await
        .expect("accept websocket");
    (ws, headers)
}

async fn send_json_frame(ws: &mut TestServerWebSocket, value: Value, context: &str) {
    ws.send(
        &fcp_async_core::compatibility_cx(),
        ServerWsMessage::text(value.to_string()),
    )
    .await
    .expect(context);
}

async fn recv_frame(
    ws: &mut TestServerWebSocket,
    context: &str,
) -> Result<ServerWsMessage, String> {
    match ws.recv(&fcp_async_core::compatibility_cx()).await {
        Ok(Some(message)) => Ok(message),
        Ok(None) => Err(format!("websocket closed before {context}")),
        Err(err) => Err(format!("{context}: {err}")),
    }
}

async fn recv_text_frame(ws: &mut TestServerWebSocket, context: &str) -> Result<String, String> {
    match recv_frame(ws, context).await? {
        ServerWsMessage::Text(text) => Ok(text),
        other => Err(format!("expected text frame for {context}, got {other:?}")),
    }
}

async fn expect_binary_frame(
    ws: &mut TestServerWebSocket,
    expected: &[u8],
    context: &str,
) -> Result<(), String> {
    match recv_frame(ws, context).await? {
        ServerWsMessage::Binary(bytes) if bytes.as_ref() == expected => Ok(()),
        ServerWsMessage::Binary(bytes) => Err(format!(
            "unexpected binary frame for {context}: {} bytes",
            bytes.len()
        )),
        other => Err(format!(
            "expected binary frame for {context}, got {other:?}"
        )),
    }
}

async fn expect_json_text_field(
    ws: &mut TestServerWebSocket,
    field: &str,
    expected: &str,
    context: &str,
) -> Result<(), String> {
    let frame = recv_text_frame(ws, context).await?;
    let value: Value =
        serde_json::from_str(&frame).map_err(|error| format!("{context}: {error}"))?;
    assert_eq!(value[field], expected);
    Ok(())
}

async fn expect_elevenlabs_audio_chunk(
    ws: &mut TestServerWebSocket,
    expected_audio_base64: &str,
    expected_commit: bool,
) -> Result<(), String> {
    let frame = recv_text_frame(ws, "receive ElevenLabs audio chunk").await?;
    let value: Value =
        serde_json::from_str(&frame).map_err(|error| format!("audio chunk JSON: {error}"))?;
    assert_eq!(value["message_type"], "input_audio_chunk");
    assert_eq!(value["audio_base_64"], expected_audio_base64);
    assert_eq!(value["sample_rate"], 8000);
    if expected_commit {
        assert_eq!(value["commit"], true);
    } else {
        assert!(value.get("commit").is_none());
    }
    Ok(())
}

async fn close_test_websocket(ws: &mut TestServerWebSocket) {
    let _ = ws
        .close(&fcp_async_core::compatibility_cx(), CloseReason::normal())
        .await;
}

struct EvidenceInput<'a> {
    provider: &'a str,
    operation: &'a str,
    scenario_id: &'a str,
    latency_ms: u128,
    http_status: Option<u16>,
    retry_decision: &'a str,
    fcp_error_mapping: &'a str,
    skip_reason: Option<&'a str>,
    details: Value,
}

fn evidence_record(input: EvidenceInput<'_>) -> Value {
    let EvidenceInput {
        provider,
        operation,
        scenario_id,
        latency_ms,
        http_status,
        retry_decision,
        fcp_error_mapping,
        skip_reason,
        details,
    } = input;
    json!({
        "schema": "fcp.speech_media.e2e.v1",
        "command_line": "cargo test -p fcp-e2e --no-default-features --features deepgram,elevenlabs --test speech_media_provider_e2e -- --nocapture",
        "git_revision": git_revision(),
        "fixture_mode": details.get("fixture_mode").cloned().unwrap_or(json!("loopback_http_tcp")),
        "provider_fixture_id": details.get("provider_fixture_id").cloned().unwrap_or(json!(scenario_id)),
        "provider": provider,
        "operation": operation,
        "operation_id": operation,
        "scenario_id": scenario_id,
        "model_id": details.get("model_id").cloned().unwrap_or(Value::Null),
        "voice_id": details.get("voice_id").cloned().unwrap_or(Value::Null),
        "media_reference_hash": details.get("media_reference_hash").cloned().unwrap_or(Value::Null),
        "media_byte_count": details.get("media_byte_count").cloned().unwrap_or(Value::Null),
        "audio_content_type": details.get("audio_content_type").cloned().unwrap_or(Value::Null),
        "audio_byte_count": details.get("audio_byte_count").cloned().unwrap_or(Value::Null),
        "output_format": details.get("output_format").cloned().unwrap_or(Value::Null),
        "transcript_char_count": details.get("transcript_char_count").cloned().unwrap_or(Value::Null),
        "voice_count": details.get("voice_count").cloned().unwrap_or(Value::Null),
        "generated_text_hash": details.get("generated_text_hash").cloned().unwrap_or(Value::Null),
        "stream_frame_count": details.get("stream_frame_count").cloned().unwrap_or(json!(0_u64)),
        "stream_chunk_count": details.get("stream_chunk_count").cloned().unwrap_or(json!(0_u64)),
        "streaming_supported": details.get("streaming_supported").cloned().unwrap_or(json!(false)),
        "realtime_scope": details.get("realtime_scope").cloned().unwrap_or(json!("not_in_this_slice")),
        "http_status": http_status,
        "websocket_status": details.get("websocket_status").cloned().unwrap_or(Value::Null),
        "latency_ms": u64::try_from(latency_ms).unwrap_or(u64::MAX),
        "retry_decision": retry_decision,
        "fcp_error_mapping": fcp_error_mapping,
        "audit_receipt_id_hash": audit_receipt_id_hash(provider, operation, scenario_id),
        "artifact_hashes": details.get("artifact_hashes").cloned().unwrap_or_else(|| json!([])),
        "cleanup_result": details.get("cleanup_result").cloned().unwrap_or(json!("pending")),
        "skip_reason": skip_reason
    })
}

fn transcript_char_count(payload: &Value) -> u64 {
    payload
        .get("results")
        .and_then(|results| results.get("channels"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .flat_map(|channel| {
            channel
                .get("alternatives")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
        })
        .filter_map(|alternative| alternative.get("transcript").and_then(Value::as_str))
        .map(|transcript| u64::try_from(transcript.chars().count()).unwrap_or(u64::MAX))
        .sum()
}

fn classify_error(error: &FcpError) -> &'static str {
    match error {
        FcpError::External {
            status_code: Some(429),
            ..
        } => "external.rate_limited",
        FcpError::External { .. } => "external.provider_error",
        FcpError::UpstreamTimeout { .. } => "external.timeout",
        FcpError::InvalidRequest { .. } => "protocol.invalid_request",
        _ => "other",
    }
}

fn audit_receipt_id_hash(provider: &str, operation: &str, scenario_id: &str) -> String {
    let input = format!("{provider}:{operation}:{scenario_id}");
    format!("sha256:{}", hex_lower(&Sha256::digest(input.as_bytes())))
}

fn hash_label(value: &str) -> String {
    format!("sha256:{}", hex_lower(&Sha256::digest(value.as_bytes())))
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn git_revision() -> String {
    std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|revision| revision.trim().to_string())
        .filter(|revision| !revision.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

fn write_jsonl_artifact(records: &[Value]) -> String {
    let jsonl = records
        .iter()
        .map(|record| serde_json::to_string(record).expect("evidence record should serialize"))
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::create_dir_all("target/fcp-speech-media")
        .expect("artifact directory should be writable");
    let mut file = std::fs::File::create(ARTIFACT_PATH).expect("artifact should be writable");
    for line in jsonl.lines() {
        println!("SPEECH_MEDIA_FIXTURE_JSONL {line}");
    }
    file.write_all(jsonl.as_bytes())
        .expect("artifact should write");
    file.write_all(b"\n")
        .expect("artifact newline should write");
    jsonl
}
