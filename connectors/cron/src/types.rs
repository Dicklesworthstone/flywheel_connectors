//! Cron connector types.

use serde::{Deserialize, Serialize};

/// A cron schedule.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Schedule {
    /// Unique schedule identifier.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Cron expression (5 space-separated fields).
    pub expression: String,
    /// FCP operation ID to invoke on trigger.
    pub target_operation: String,
    /// Optional static payload to pass to the target operation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<serde_json::Value>,
    /// Whether the schedule is enabled.
    pub enabled: bool,
    /// ISO 8601 creation timestamp.
    pub created_at: String,
}

/// An execution record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Execution {
    /// Unique execution identifier.
    pub id: String,
    /// The schedule that was triggered.
    pub schedule_id: String,
    /// ISO 8601 trigger timestamp.
    pub triggered_at: String,
    /// Execution status (e.g. "triggered", "completed", "failed").
    pub status: String,
}

/// Validate five-field UTC cron syntax, including lists, ranges and steps.
pub fn validate_cron_expression(expression: &str) -> bool {
    const MONTHS: &[&str] = &[
        "JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC",
    ];
    const WEEKDAYS: &[&str] = &["SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"];
    let mut fields = expression.split_ascii_whitespace();
    for (min, max, names) in [
        (0, 59, &[][..]),
        (0, 23, &[][..]),
        (1, 31, &[][..]),
        (1, 12, MONTHS),
        (0, 7, WEEKDAYS),
    ] {
        let Some(field) = fields.next() else {
            return false;
        };
        if !field
            .split(',')
            .all(|part| valid_cron_part(part, min, max, names))
        {
            return false;
        }
    }
    fields.next().is_none()
}

fn valid_cron_part(part: &str, min: u8, max: u8, names: &[&str]) -> bool {
    let value = |text: &str| {
        if text.bytes().all(|b| b.is_ascii_digit()) {
            return text.parse::<u8>().ok().filter(|n| (min..=max).contains(n));
        }
        names
            .iter()
            .position(|name| name.eq_ignore_ascii_case(text))
            .and_then(|i| u8::try_from(i).ok())
            .map(|i| i + min)
    };
    let base = if let Some((base, step)) = part.split_once('/') {
        if !step.bytes().all(|b| b.is_ascii_digit())
            || !step.parse::<u32>().is_ok_and(|n| n > 0)
            || (base != "*" && !base.contains('-'))
        {
            return false;
        }
        base
    } else {
        part
    };
    if base == "*" {
        return true;
    }
    if let Some((first, last)) = base.split_once('-') {
        return matches!((value(first), value(last)), (Some(a), Some(b)) if a <= b);
    }
    value(base).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // -- Schedule tests --

    #[test]
    fn schedule_roundtrip() {
        let s = Schedule {
            id: "sched_abc123".into(),
            name: "hourly-sync".into(),
            expression: "0 * * * *".into(),
            target_operation: "slack.channels.list".into(),
            payload: Some(json!({"channel": "general"})),
            enabled: true,
            created_at: "2026-03-05T12:00:00Z".into(),
        };
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(v["id"], "sched_abc123");
        assert_eq!(v["name"], "hourly-sync");
        assert_eq!(v["expression"], "0 * * * *");
        assert_eq!(v["target_operation"], "slack.channels.list");
        assert_eq!(v["payload"]["channel"], "general");
        assert_eq!(v["enabled"], true);
        assert_eq!(v["created_at"], "2026-03-05T12:00:00Z");

        let deserialized: Schedule = serde_json::from_value(v).unwrap();
        assert_eq!(deserialized, s);
    }

    #[test]
    fn schedule_without_payload() {
        let s = Schedule {
            id: "sched_1".into(),
            name: "nightly".into(),
            expression: "0 0 * * *".into(),
            target_operation: "backup.run".into(),
            payload: None,
            enabled: true,
            created_at: "2026-03-05T00:00:00Z".into(),
        };
        let v = serde_json::to_value(&s).unwrap();
        assert!(
            v.get("payload").is_none(),
            "payload should be skipped when None"
        );
    }

    #[test]
    fn schedule_deserialize_with_payload() {
        let v = json!({
            "id": "s1",
            "name": "test",
            "expression": "*/5 * * * *",
            "target_operation": "op.test",
            "payload": {"key": "value"},
            "enabled": false,
            "created_at": "2026-01-01T00:00:00Z"
        });
        let s: Schedule = serde_json::from_value(v).unwrap();
        assert_eq!(s.id, "s1");
        assert!(!s.enabled);
        assert!(s.payload.is_some());
    }

    #[test]
    fn schedule_deserialize_without_payload() {
        let v = json!({
            "id": "s2",
            "name": "minimal",
            "expression": "0 0 * * *",
            "target_operation": "op.test",
            "enabled": true,
            "created_at": "2026-01-01T00:00:00Z"
        });
        let s: Schedule = serde_json::from_value(v).unwrap();
        assert!(s.payload.is_none());
    }

    #[test]
    fn schedule_equality() {
        let s1 = Schedule {
            id: "s1".into(),
            name: "a".into(),
            expression: "0 * * * *".into(),
            target_operation: "op.a".into(),
            payload: None,
            enabled: true,
            created_at: "2026-01-01T00:00:00Z".into(),
        };
        let s2 = s1.clone();
        assert_eq!(s1, s2);
    }

    #[test]
    fn schedule_clone() {
        let s1 = Schedule {
            id: "s1".into(),
            name: "a".into(),
            expression: "0 * * * *".into(),
            target_operation: "op.a".into(),
            payload: Some(json!({"x": 1})),
            enabled: true,
            created_at: "2026-01-01T00:00:00Z".into(),
        };
        let s2 = s1.clone();
        assert_eq!(s1.id, s2.id);
        assert_eq!(s1.payload, s2.payload);
    }

    #[test]
    fn schedule_debug_format() {
        let s = Schedule {
            id: "s1".into(),
            name: "test".into(),
            expression: "* * * * *".into(),
            target_operation: "op.test".into(),
            payload: None,
            enabled: true,
            created_at: "2026-01-01T00:00:00Z".into(),
        };
        let debug = format!("{s:?}");
        assert!(debug.contains("Schedule"));
        assert!(debug.contains("s1"));
    }

    // -- Execution tests --

    #[test]
    fn execution_roundtrip() {
        let e = Execution {
            id: "exec_abc123".into(),
            schedule_id: "sched_abc123".into(),
            triggered_at: "2026-03-05T12:00:00Z".into(),
            status: "triggered".into(),
        };
        let v = serde_json::to_value(&e).unwrap();
        assert_eq!(v["id"], "exec_abc123");
        assert_eq!(v["schedule_id"], "sched_abc123");
        assert_eq!(v["triggered_at"], "2026-03-05T12:00:00Z");
        assert_eq!(v["status"], "triggered");

        let deserialized: Execution = serde_json::from_value(v).unwrap();
        assert_eq!(deserialized, e);
    }

    #[test]
    fn execution_equality() {
        let e1 = Execution {
            id: "e1".into(),
            schedule_id: "s1".into(),
            triggered_at: "2026-01-01T00:00:00Z".into(),
            status: "triggered".into(),
        };
        let e2 = e1.clone();
        assert_eq!(e1, e2);
    }

    #[test]
    fn execution_clone() {
        let e = Execution {
            id: "e1".into(),
            schedule_id: "s1".into(),
            triggered_at: "2026-01-01T00:00:00Z".into(),
            status: "completed".into(),
        };
        let cloned = e.clone();
        assert_eq!(e.id, cloned.id);
        assert_eq!(e.status, cloned.status);
    }

    #[test]
    fn execution_debug_format() {
        let e = Execution {
            id: "e1".into(),
            schedule_id: "s1".into(),
            triggered_at: "2026-01-01T00:00:00Z".into(),
            status: "triggered".into(),
        };
        let debug = format!("{e:?}");
        assert!(debug.contains("Execution"));
        assert!(debug.contains("e1"));
    }

    #[test]
    fn execution_from_json() {
        let v = json!({
            "id": "e1",
            "schedule_id": "s1",
            "triggered_at": "2026-03-05T12:00:00Z",
            "status": "failed"
        });
        let e: Execution = serde_json::from_value(v).unwrap();
        assert_eq!(e.status, "failed");
    }

    // -- Cron expression validation tests --

    #[test]
    fn valid_every_minute() {
        assert!(validate_cron_expression("* * * * *"));
    }

    #[test]
    fn valid_every_5_minutes() {
        assert!(validate_cron_expression("*/5 * * * *"));
    }

    #[test]
    fn valid_hourly() {
        assert!(validate_cron_expression("0 * * * *"));
    }

    #[test]
    fn valid_daily_midnight() {
        assert!(validate_cron_expression("0 0 * * *"));
    }

    #[test]
    fn valid_weekly_monday() {
        assert!(validate_cron_expression("0 9 * * 1"));
    }

    #[test]
    fn valid_complex() {
        assert!(validate_cron_expression("15,45 */2 1-15 * 1-5"));
    }

    #[test]
    fn invalid_too_few_fields() {
        assert!(!validate_cron_expression("* * *"));
    }

    #[test]
    fn invalid_too_many_fields() {
        assert!(!validate_cron_expression("* * * * * *"));
    }

    #[test]
    fn invalid_empty_string() {
        assert!(!validate_cron_expression(""));
    }

    #[test]
    fn invalid_single_field() {
        assert!(!validate_cron_expression("*"));
    }

    #[test]
    fn invalid_four_fields() {
        assert!(!validate_cron_expression("* * * *"));
    }

    #[test]
    fn invalid_whitespace_only() {
        assert!(!validate_cron_expression("   "));
    }

    #[test]
    fn valid_with_extra_spacing() {
        // split_whitespace handles multiple spaces
        assert!(validate_cron_expression("0  *  *  *  *"));
    }

    #[test]
    fn valid_ranges_and_lists() {
        assert!(validate_cron_expression("0,30 9-17 * * 1-5"));
    }

    #[test]
    fn cron_field_boundaries_and_named_ranges() {
        for expr in [
            "0,59 0,23 1,31 1,12 0,7",
            "*/15 9-17/2 * jan,mAr Mon-Fri",
        ] {
            assert!(validate_cron_expression(expr), "{expr}");
        }
        for expr in [
            "@reboot 0 0 0 0",
            "60 * * * *",
            "* 24 * * *",
            "* * 0 * *",
            "* * * 13 *",
            "* * * * 8",
            "* * * * FRI-MON",
            "*/0 * * * *",
            "1,,5 * * * *",
            "*//2 * * * *",
            "* * * Smarch *",
            "1- * * * *",
        ] {
            assert!(!validate_cron_expression(expr), "{expr}");
        }
    }

    // -- Additional serde tests --

    #[test]
    fn schedule_inequality_different_id() {
        let s1 = Schedule {
            id: "s1".into(),
            name: "a".into(),
            expression: "0 * * * *".into(),
            target_operation: "op.a".into(),
            payload: None,
            enabled: true,
            created_at: "2026-01-01T00:00:00Z".into(),
        };
        let mut s2 = s1.clone();
        s2.id = "s2".into();
        assert_ne!(s1, s2);
    }

    #[test]
    fn schedule_inequality_different_enabled() {
        let s1 = Schedule {
            id: "s1".into(),
            name: "a".into(),
            expression: "0 * * * *".into(),
            target_operation: "op.a".into(),
            payload: None,
            enabled: true,
            created_at: "2026-01-01T00:00:00Z".into(),
        };
        let mut s2 = s1.clone();
        s2.enabled = false;
        assert_ne!(s1, s2);
    }

    #[test]
    fn schedule_json_string_roundtrip() {
        let s = Schedule {
            id: "s1".into(),
            name: "test".into(),
            expression: "*/10 * * * *".into(),
            target_operation: "op.sync".into(),
            payload: Some(json!({"key": "val"})),
            enabled: true,
            created_at: "2026-01-01T00:00:00Z".into(),
        };
        let json_str = serde_json::to_string(&s).unwrap();
        let parsed: Schedule = serde_json::from_str(&json_str).unwrap();
        assert_eq!(s, parsed);
    }

    #[test]
    fn execution_inequality_different_status() {
        let e1 = Execution {
            id: "e1".into(),
            schedule_id: "s1".into(),
            triggered_at: "2026-01-01T00:00:00Z".into(),
            status: "triggered".into(),
        };
        let mut e2 = e1.clone();
        e2.status = "completed".into();
        assert_ne!(e1, e2);
    }

    #[test]
    fn execution_json_string_roundtrip() {
        let e = Execution {
            id: "exec_1".into(),
            schedule_id: "sched_1".into(),
            triggered_at: "2026-03-06T12:00:00Z".into(),
            status: "completed".into(),
        };
        let json_str = serde_json::to_string(&e).unwrap();
        let parsed: Execution = serde_json::from_str(&json_str).unwrap();
        assert_eq!(e, parsed);
    }

    #[test]
    fn execution_with_failed_status() {
        let v = json!({
            "id": "e1",
            "schedule_id": "s1",
            "triggered_at": "2026-03-06T12:00:00Z",
            "status": "completed"
        });
        let e: Execution = serde_json::from_value(v).unwrap();
        assert_eq!(e.status, "completed");
    }

    #[test]
    fn schedule_with_complex_payload() {
        let payload = json!({
            "nested": {
                "deep": [1, 2, 3],
                "flag": true
            },
            "list": ["a", "b"]
        });
        let s = Schedule {
            id: "s1".into(),
            name: "complex".into(),
            expression: "0 * * * *".into(),
            target_operation: "op.sync".into(),
            payload: Some(payload.clone()),
            enabled: true,
            created_at: "2026-01-01T00:00:00Z".into(),
        };
        let v = serde_json::to_value(&s).unwrap();
        let back: Schedule = serde_json::from_value(v).unwrap();
        assert_eq!(back.payload.unwrap(), payload);
    }

    #[test]
    fn validate_cron_step_values() {
        assert!(validate_cron_expression("*/2 */3 */4 */5 */6"));
    }

    #[test]
    fn validate_cron_numeric_values() {
        assert!(validate_cron_expression("0 12 15 6 3"));
    }

    #[test]
    fn validate_cron_tabs_not_spaces() {
        // Tabs are whitespace but split_whitespace handles them
        assert!(validate_cron_expression("0\t*\t*\t*\t*"));
    }
}
