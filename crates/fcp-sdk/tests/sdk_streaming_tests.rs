//! SDK Streaming Tests
//!
//! Comprehensive tests for `EventStreamManager`, subscriptions, replay, and acks.
//! These tests verify:
//! - Cursor monotonicity
//! - Ack required/optional behavior
//! - Replay from cursor semantics
//! - Buffer management and trimming
//! - Subscribe → receive events → ack → replay flow

use fcp_sdk::prelude::*;
use fcp_sdk::streaming::{BufferLimits, EventStreamManager, ReplayError};
use serde_json::json;

// ─────────────────────────────────────────────────────────────────────────────
// Test Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn sample_event_data() -> EventData {
    EventData::new(
        ConnectorId::from_static("test:streaming:v1"),
        InstanceId::new(),
        ZoneId::work(),
        Principal {
            kind: "user".to_string(),
            id: "test-user".to_string(),
            trust: TrustLevel::Paired,
            display: Some("Test User".to_string()),
        },
        json!({"message": "test event"}),
    )
}

const fn event_caps(replay: bool, requires_ack: bool, min_buffer_events: u32) -> EventCaps {
    EventCaps {
        streaming: true,
        replay,
        min_buffer_events,
        requires_ack,
    }
}

fn subscribe_request(topics: Vec<&str>) -> SubscribeRequest {
    SubscribeRequest {
        r#type: "subscribe".to_string(),
        id: RequestId::new("sub-test-1"),
        topics: topics.into_iter().map(String::from).collect(),
        since: None,
        max_events_per_sec: None,
        batch_ms: None,
        window_size: None,
        capability_token: None,
    }
}

fn subscribe_request_with_since(topics: Vec<&str>, since: &str) -> SubscribeRequest {
    SubscribeRequest {
        r#type: "subscribe".to_string(),
        id: RequestId::new("sub-test-2"),
        topics: topics.into_iter().map(String::from).collect(),
        since: Some(since.to_string()),
        max_events_per_sec: None,
        batch_ms: None,
        window_size: None,
        capability_token: None,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Cursor Monotonicity Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_cursor_monotonicity_single_topic() {
    let mut manager = EventStreamManager::new(event_caps(true, false, 10));

    let e1 = manager.emit("events.test", sample_event_data());
    let e2 = manager.emit("events.test", sample_event_data());
    let e3 = manager.emit("events.test", sample_event_data());

    // Sequences must be monotonically increasing
    assert_eq!(e1.seq, 0);
    assert_eq!(e2.seq, 1);
    assert_eq!(e3.seq, 2);

    // Cursors derived from seq must also be monotonic
    assert_eq!(e1.cursor, "0");
    assert_eq!(e2.cursor, "1");
    assert_eq!(e3.cursor, "2");
}

#[test]
fn test_cursor_monotonicity_multiple_topics() {
    let mut manager = EventStreamManager::new(event_caps(true, false, 10));

    // Different topics have independent sequences
    let e1_a = manager.emit("topic.a", sample_event_data());
    let e1_b = manager.emit("topic.b", sample_event_data());
    let e2_a = manager.emit("topic.a", sample_event_data());
    let e2_b = manager.emit("topic.b", sample_event_data());

    // Topic A sequences
    assert_eq!(e1_a.seq, 0);
    assert_eq!(e2_a.seq, 1);

    // Topic B sequences (independent)
    assert_eq!(e1_b.seq, 0);
    assert_eq!(e2_b.seq, 1);
}

#[test]
fn test_cursor_monotonicity_with_explicit_seq() {
    let mut manager = EventStreamManager::new(event_caps(true, false, 10));

    // Emit with explicit seq
    let e1 = manager.emit_with_seq("events.explicit", 100, sample_event_data());
    let e2 = manager.emit("events.explicit", sample_event_data());

    assert_eq!(e1.seq, 100);
    assert_eq!(e1.cursor, "100");

    // Next auto-assigned seq should be after 100
    assert_eq!(e2.seq, 101);
    assert_eq!(e2.cursor, "101");
}

// ─────────────────────────────────────────────────────────────────────────────
// Ack Required/Optional Behavior Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_ack_required_flag_propagation() {
    let mut manager = EventStreamManager::new(event_caps(true, true, 5));

    let e1 = manager.emit("events.ack", sample_event_data());
    let e2 = manager.emit("events.ack", sample_event_data());

    // When requires_ack is true in caps, events get the flag
    assert!(e1.requires_ack);
    assert!(e2.requires_ack);
}

#[test]
fn test_ack_optional_flag_propagation() {
    let mut manager = EventStreamManager::new(event_caps(true, false, 5));

    let e1 = manager.emit("events.noack", sample_event_data());
    let e2 = manager.emit("events.noack", sample_event_data());

    // When requires_ack is false in caps, events don't require ack
    assert!(!e1.requires_ack);
    assert!(!e2.requires_ack);
}

#[test]
fn test_pending_ack_tracking() {
    let mut manager = EventStreamManager::new(event_caps(true, true, 5));

    let e1 = manager.emit("events.pending", sample_event_data());
    let e2 = manager.emit("events.pending", sample_event_data());
    let e3 = manager.emit("events.pending", sample_event_data());

    // All three should be pending
    assert_eq!(manager.pending_acks("events.pending"), 3);

    // Ack one
    let ack = EventAck::new("events.pending", vec![e1.seq]).with_cursors(vec![e1.cursor.clone()]);
    let result = manager.handle_ack(&ack);

    assert_eq!(result.acked, vec![e1.seq]);
    assert_eq!(result.missing, [] as [u64; 0]);
    assert_eq!(manager.pending_acks("events.pending"), 2);

    // Ack remaining
    let ack2 = EventAck::new("events.pending", vec![e2.seq, e3.seq])
        .with_cursors(vec![e2.cursor, e3.cursor]);
    let result2 = manager.handle_ack(&ack2);

    assert_eq!(result2.acked.len(), 2);
    assert_eq!(manager.pending_acks("events.pending"), 0);
}

#[test]
fn test_ack_unknown_seq() {
    let mut manager = EventStreamManager::new(event_caps(true, true, 5));

    let _ = manager.emit("events.ack", sample_event_data());

    // Ack a seq that doesn't exist
    let ack = EventAck::new("events.ack", vec![999]).with_cursors(vec!["999".to_string()]);
    let result = manager.handle_ack(&ack);

    assert_eq!(result.acked, [] as [u64; 0]);
    assert_eq!(result.missing, vec![999]);
}

#[test]
fn test_ack_unknown_topic() {
    let mut manager = EventStreamManager::new(event_caps(true, true, 5));

    // Ack on a topic that doesn't exist
    let ack = EventAck::new("events.nonexistent", vec![0]).with_cursors(vec!["0".to_string()]);
    let result = manager.handle_ack(&ack);

    assert_eq!(result.acked, [] as [u64; 0]);
    assert_eq!(result.missing, vec![0]);
}

// ─────────────────────────────────────────────────────────────────────────────
// Nack Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_nack_redelivery() {
    let mut manager = EventStreamManager::new(event_caps(true, true, 5));

    let e1 = manager.emit("events.nack", sample_event_data());
    let _e2 = manager.emit("events.nack", sample_event_data());

    // Request redelivery of e1
    let nack = EventNack::new("events.nack", vec![e1.seq], "processing_failed".to_string());
    let result = manager.handle_nack(&nack);

    assert_eq!(result.redeliver.len(), 1);
    assert_eq!(result.redeliver[0].seq, e1.seq);
    assert_eq!(result.missing, [] as [u64; 0]);
}

#[test]
fn test_nack_unknown_seq() {
    let mut manager = EventStreamManager::new(event_caps(true, true, 5));

    let _ = manager.emit("events.nack", sample_event_data());

    // Nack a seq that doesn't exist
    let nack = EventNack::new("events.nack", vec![999], "not_found".to_string());
    let result = manager.handle_nack(&nack);

    assert!(result.redeliver.is_empty());
    assert_eq!(result.missing, vec![999]);
}

// ─────────────────────────────────────────────────────────────────────────────
// Replay Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_replay_from_cursor() {
    let mut manager = EventStreamManager::new(event_caps(true, false, 10));

    let e1 = manager.emit("events.replay", sample_event_data());
    let e2 = manager.emit("events.replay", sample_event_data());
    let e3 = manager.emit("events.replay", sample_event_data());

    // Replay from cursor 0 should return e2 and e3
    let replayed = manager.replay_from("events.replay", &e1.cursor).unwrap();
    assert_eq!(replayed.len(), 2);
    assert_eq!(replayed[0].seq, e2.seq);
    assert_eq!(replayed[1].seq, e3.seq);
}

#[test]
fn test_replay_from_empty_cursor() {
    let mut manager = EventStreamManager::new(event_caps(true, false, 10));

    let _ = manager.emit("events.replay", sample_event_data());
    let _ = manager.emit("events.replay", sample_event_data());

    // Empty cursor replays all events
    let replayed = manager.replay_from("events.replay", "").unwrap();
    assert_eq!(replayed.len(), 2);
}

#[test]
fn test_replay_stale_cursor() {
    let mut manager =
        EventStreamManager::with_limits(event_caps(true, false, 2), BufferLimits::new(2, 3));

    // Emit more events than buffer holds
    let _ = manager.emit("events.stale", sample_event_data()); // seq 0 - will be trimmed
    let _ = manager.emit("events.stale", sample_event_data()); // seq 1 - will be trimmed
    let _ = manager.emit("events.stale", sample_event_data()); // seq 2
    let _ = manager.emit("events.stale", sample_event_data()); // seq 3
    let _ = manager.emit("events.stale", sample_event_data()); // seq 4

    // Cursor pointing to seq 0 is now stale (oldest is seq 2)
    let result = manager.replay_from("events.stale", "0");
    assert!(matches!(result, Err(ReplayError::CursorStale { .. })));
}

#[test]
fn test_replay_invalid_cursor() {
    let mut manager = EventStreamManager::new(event_caps(true, false, 10));

    let _ = manager.emit("events.replay", sample_event_data());

    // Invalid cursor format
    let result = manager.replay_from("events.replay", "not-a-number");
    assert!(matches!(result, Err(ReplayError::InvalidCursor { .. })));
}

#[test]
fn test_replay_unknown_topic() {
    let manager = EventStreamManager::new(event_caps(true, false, 10));

    let result = manager.replay_from("events.unknown", "0");
    assert!(matches!(result, Err(ReplayError::UnknownTopic { .. })));
}

// ─────────────────────────────────────────────────────────────────────────────
// Subscribe Flow Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_subscribe_creates_topic() {
    let mut manager = EventStreamManager::new(event_caps(true, false, 10));

    let req = subscribe_request(vec!["events.new"]);
    let outcome = manager.handle_subscribe(&req).unwrap();

    assert!(
        outcome
            .response
            .result
            .confirmed_topics
            .contains(&"events.new".to_string())
    );
    assert!(outcome.response.result.replay_supported);
}

#[test]
fn test_subscribe_with_replay() {
    let mut manager = EventStreamManager::new(event_caps(true, false, 10));

    // Emit some events first
    let e1 = manager.emit("events.sub", sample_event_data());
    let _ = manager.emit("events.sub", sample_event_data());

    // Subscribe with since cursor
    let req = subscribe_request_with_since(vec!["events.sub"], &e1.cursor);
    let outcome = manager.handle_subscribe(&req).unwrap();

    // Should replay events after cursor
    assert!(outcome.replay_events.contains_key("events.sub"));
    assert_eq!(outcome.replay_events["events.sub"].len(), 1);
}

#[test]
fn test_subscribe_multiple_topics() {
    let mut manager = EventStreamManager::new(event_caps(true, false, 10));

    let req = subscribe_request(vec!["topic.a", "topic.b", "topic.c"]);
    let outcome = manager.handle_subscribe(&req).unwrap();

    assert_eq!(outcome.response.result.confirmed_topics.len(), 3);
}

#[test]
fn test_unsubscribe() {
    let mut manager = EventStreamManager::new(event_caps(true, false, 10));

    // Subscribe to topics
    let req = subscribe_request(vec!["topic.a", "topic.b"]);
    let _ = manager.handle_subscribe(&req).unwrap();

    // Emit events
    let _ = manager.emit("topic.a", sample_event_data());
    let _ = manager.emit("topic.b", sample_event_data());

    // Unsubscribe from one
    let removed = manager.unsubscribe(&["topic.a".to_string()]);
    assert_eq!(removed, 1);

    // topic.a should be gone
    let result = manager.replay_from("topic.a", "");
    assert!(matches!(result, Err(ReplayError::UnknownTopic { .. })));

    // topic.b should still exist
    let replayed = manager.replay_from("topic.b", "").unwrap();
    assert_eq!(replayed.len(), 1);
}

// ─────────────────────────────────────────────────────────────────────────────
// Buffer Management Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_buffer_limits_creation() {
    let limits = BufferLimits::new(5, 10);
    assert_eq!(limits.min_events, 5);
    assert_eq!(limits.max_events, 10);

    // Max should be at least min
    let limits2 = BufferLimits::new(10, 5);
    assert_eq!(limits2.min_events, 10);
    assert_eq!(limits2.max_events, 10); // Clamped to min
}

#[test]
fn test_buffer_trimming_respects_pending_acks() {
    let mut manager =
        EventStreamManager::with_limits(event_caps(true, true, 2), BufferLimits::new(2, 3));

    // Emit events that require acks
    let e1 = manager.emit("events.trim", sample_event_data());
    let _e2 = manager.emit("events.trim", sample_event_data());
    let _e3 = manager.emit("events.trim", sample_event_data());
    let _e4 = manager.emit("events.trim", sample_event_data());

    // All should be in buffer because they have pending acks
    assert_eq!(manager.pending_acks("events.trim"), 4);

    // Ack oldest event
    let ack = EventAck::new("events.trim", vec![e1.seq]).with_cursors(vec![e1.cursor]);
    manager.handle_ack(&ack);

    // Now buffer can trim e1
    assert_eq!(manager.pending_acks("events.trim"), 3);
}

// ─────────────────────────────────────────────────────────────────────────────
// Integration: Subscribe → Receive → Ack → Replay Flow
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_full_streaming_flow() {
    let mut manager = EventStreamManager::new(event_caps(true, true, 10));

    // 1. Subscribe to topic
    let req = subscribe_request(vec!["events.flow"]);
    let outcome = manager.handle_subscribe(&req).unwrap();
    assert!(outcome.response.result.replay_supported);

    // 2. Emit events
    let e1 = manager.emit("events.flow", sample_event_data());
    let e2 = manager.emit("events.flow", sample_event_data());
    let e3 = manager.emit("events.flow", sample_event_data());

    // 3. Ack first event
    let ack = EventAck::new("events.flow", vec![e1.seq]).with_cursors(vec![e1.cursor.clone()]);
    let ack_result = manager.handle_ack(&ack);
    assert_eq!(ack_result.acked, vec![e1.seq]);

    // 4. Replay from first event cursor
    let replayed = manager.replay_from("events.flow", &e1.cursor).unwrap();
    assert_eq!(replayed.len(), 2);
    assert_eq!(replayed[0].seq, e2.seq);
    assert_eq!(replayed[1].seq, e3.seq);

    // 5. Verify remaining pending acks
    assert_eq!(manager.pending_acks("events.flow"), 2);

    // 6. Ack remaining
    let ack2 =
        EventAck::new("events.flow", vec![e2.seq, e3.seq]).with_cursors(vec![e2.cursor, e3.cursor]);
    manager.handle_ack(&ack2);
    assert_eq!(manager.pending_acks("events.flow"), 0);
}

// ─────────────────────────────────────────────────────────────────────────────
// Edge Cases
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_empty_topic_replay() {
    let mut manager = EventStreamManager::new(event_caps(true, false, 10));

    // Subscribe but don't emit
    let req = subscribe_request(vec!["events.empty"]);
    let _ = manager.handle_subscribe(&req).unwrap();

    // Replay on empty topic
    let replayed = manager.replay_from("events.empty", "").unwrap();
    assert!(replayed.is_empty());
}

#[test]
fn test_replay_disabled() {
    let mut manager = EventStreamManager::new(event_caps(false, false, 0));

    let req = subscribe_request(vec!["events.noreplay"]);
    let outcome = manager.handle_subscribe(&req).unwrap();

    assert!(!outcome.response.result.replay_supported);
    assert!(outcome.response.result.buffer.is_none());
}

#[test]
fn test_record_envelope_preserves_existing_values() {
    let mut manager = EventStreamManager::new(event_caps(true, false, 10));

    // Create envelope with custom cursor
    let mut envelope = EventEnvelope::new("events.custom", sample_event_data());
    envelope.cursor = "custom-cursor-123".to_string();

    // Record should preserve the cursor
    let recorded = manager.record(envelope);
    assert_eq!(recorded.cursor, "custom-cursor-123");
}

#[test]
fn test_telegram_ordering_example_preserves_seq_and_thread_metadata() {
    let mut manager = EventStreamManager::new(event_caps(true, false, 10));
    let thread = ThreadInfo::new("chat-123", ThreadKind::Channel);
    let envelope = EventEnvelope::new(
        "telegram.message.new",
        sample_event_data().with_thread_info(thread.clone()),
    )
    .with_seq(41)
    .with_cursor_seq(41);

    let recorded = manager.record(envelope);
    assert_eq!(recorded.seq, 41);
    assert_eq!(recorded.cursor, "41");
    assert_eq!(recorded.data.thread_info.as_ref(), Some(&thread));

    let replayed = manager.replay_from("telegram.message.new", "").unwrap();
    assert_eq!(replayed.len(), 1);
    assert_eq!(replayed[0].seq, 41);
    assert_eq!(replayed[0].cursor, "41");
    assert_eq!(replayed[0].data.thread_info.as_ref(), Some(&thread));
}

#[test]
fn test_discord_ordering_example_preserves_explicit_gateway_seq() {
    let mut manager = EventStreamManager::new(event_caps(true, false, 10));
    let first = manager.record(
        EventEnvelope::new("discord.message", sample_event_data())
            .with_seq(812)
            .with_cursor_seq(812),
    );
    let second = manager.emit("discord.message", sample_event_data());

    assert_eq!(first.seq, 812);
    assert_eq!(first.cursor, "812");
    assert_eq!(second.seq, 813);
    assert_eq!(second.cursor, "813");

    let replayed = manager.replay_from("discord.message", "812").unwrap();
    assert_eq!(replayed.len(), 1);
    assert_eq!(replayed[0].seq, 813);
}
