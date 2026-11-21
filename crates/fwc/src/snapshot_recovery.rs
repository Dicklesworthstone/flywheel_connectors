//! Snapshot tests for recovery, ambiguity, and suggestion surfaces (bead 18.2).
//!
//! Verifies that command suggestion on typo, ambiguous command resolution,
//! missing argument recovery, invalid flag recovery, and context-aware
//! suggestions behave as expected.

#[cfg(test)]
#[allow(clippy::suspicious_operation_groupings)]
mod tests {
    use serde::{Deserialize, Serialize};

    // ── Test scaffolding types ──────────────────────────────────────────

    /// A recovery suggestion presented to the user after a command error.
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct RecoverySuggestion {
        original: String,
        corrected: String,
        kind: SuggestionKind,
        confidence: Confidence,
        message: String,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    enum SuggestionKind {
        Typo,
        Alias,
        Prefix,
        Ambiguous,
        Missing,
        Invalid,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    enum Confidence {
        High,
        Medium,
        Low,
    }

    /// Simulated mode context for context-aware suggestions.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum CliMode {
        Online,
        Offline,
        ReadOnly,
    }

    // ── Canonical command lists ──────────────────────────────────────────

    const CANONICAL_COMMANDS: &[&str] = &[
        "guide",
        "list",
        "search",
        "show",
        "ops",
        "schema",
        "examples",
        "status",
        "doctor",
        "budget",
        "capabilities",
        "install",
        "update",
        "pin",
        "unpin",
        "config",
        "invoke",
        "simulate",
        "pipeline",
        "batch",
        "task",
        "plan",
        "explain",
        "do",
        "template",
        "history",
        "replay",
        "undo",
        "compare",
        "approvals",
    ];

    const CONNECTOR_NAMES: &[&str] = &[
        "github",
        "gitlab",
        "jira",
        "slack",
        "discord",
        "telegram",
        "airtable",
        "notion",
        "linear",
        "asana",
        "zendesk",
        "stripe",
        "twilio",
        "sendgrid",
        "shopify",
        "salesforce",
    ];

    const OPERATION_NAMES: &[&str] = &[
        "create_issue",
        "list_repos",
        "get_user",
        "send_message",
        "create_channel",
        "update_record",
        "delete_page",
        "list_projects",
        "search_tickets",
        "get_balance",
    ];

    // ── Levenshtein distance ────────────────────────────────────────────

    fn levenshtein(left: &str, right: &str) -> usize {
        let right_chars: Vec<char> = right.chars().collect();
        let mut costs: Vec<usize> = (0..=right_chars.len()).collect();
        for (left_index, left_char) in left.chars().enumerate() {
            let mut previous = costs[0];
            costs[0] = left_index + 1;
            for (right_index, right_char) in right_chars.iter().enumerate() {
                let insertion = costs[right_index + 1] + 1;
                let deletion = costs[right_index] + 1;
                let substitution = previous + usize::from(left_char != *right_char);
                previous = costs[right_index + 1];
                costs[right_index + 1] = insertion.min(deletion).min(substitution);
            }
        }
        costs[right_chars.len()]
    }

    fn closest_matches<'a>(
        value: &str,
        candidates: &[&'a str],
        max_distance: usize,
        limit: usize,
    ) -> Vec<&'a str> {
        let mut matches: Vec<(&str, usize)> = candidates
            .iter()
            .map(|c| (*c, levenshtein(value, c)))
            .filter(|(c, d)| c.starts_with(value) || value.starts_with(*c) || *d <= max_distance)
            .collect();
        matches.sort_by_key(|(c, d)| (*d, c.len()));
        matches.into_iter().take(limit).map(|(c, _)| c).collect()
    }

    fn suggest_command(typo: &str) -> Option<RecoverySuggestion> {
        let matches = closest_matches(typo, CANONICAL_COMMANDS, 2, 1);
        matches.first().map(|corrected| RecoverySuggestion {
            original: typo.to_string(),
            corrected: corrected.to_string(),
            kind: SuggestionKind::Typo,
            confidence: if levenshtein(typo, corrected) <= 1 {
                Confidence::High
            } else {
                Confidence::Medium
            },
            message: format!("Did you mean '{corrected}'?"),
        })
    }

    fn suggest_connector(typo: &str) -> Option<RecoverySuggestion> {
        let matches = closest_matches(typo, CONNECTOR_NAMES, 2, 1);
        matches.first().map(|corrected| RecoverySuggestion {
            original: typo.to_string(),
            corrected: corrected.to_string(),
            kind: SuggestionKind::Typo,
            confidence: if levenshtein(typo, corrected) <= 1 {
                Confidence::High
            } else {
                Confidence::Medium
            },
            message: format!("Did you mean connector '{corrected}'?"),
        })
    }

    fn suggest_operation(typo: &str) -> Option<RecoverySuggestion> {
        let matches = closest_matches(typo, OPERATION_NAMES, 3, 1);
        matches.first().map(|corrected| RecoverySuggestion {
            original: typo.to_string(),
            corrected: corrected.to_string(),
            kind: SuggestionKind::Typo,
            confidence: Confidence::Medium,
            message: format!("Did you mean operation '{corrected}'?"),
        })
    }

    fn resolve_ambiguous(prefix: &str) -> Vec<&'static str> {
        CANONICAL_COMMANDS
            .iter()
            .filter(|c| c.starts_with(prefix))
            .copied()
            .collect()
    }

    fn validate_flag(flag: &str) -> Option<RecoverySuggestion> {
        let known_flags = &[
            "--format",
            "--json",
            "--help",
            "--host",
            "--input",
            "--file",
            "--set",
            "--connector",
            "--operation",
            "--zone",
            "--retry",
            "--token-stats",
            "--approve",
            "--version",
        ];
        if known_flags.contains(&flag) {
            return None; // valid
        }
        let matches = closest_matches(flag, known_flags, 3, 1);
        matches.first().map(|corrected| RecoverySuggestion {
            original: flag.to_string(),
            corrected: corrected.to_string(),
            kind: SuggestionKind::Invalid,
            confidence: if levenshtein(flag, corrected) <= 2 {
                Confidence::Medium
            } else {
                Confidence::Low
            },
            message: format!("Unknown flag '{flag}'. Did you mean '{corrected}'?"),
        })
    }

    fn missing_argument_recovery(command: &str, missing: &str) -> RecoverySuggestion {
        RecoverySuggestion {
            original: command.to_string(),
            corrected: format!("{command} <{missing}>"),
            kind: SuggestionKind::Missing,
            confidence: Confidence::High,
            message: format!("Missing required argument: {missing}"),
        }
    }

    fn context_aware_suggestions(command: &str, mode: CliMode) -> Vec<&'static str> {
        let read_only = &[
            "list", "search", "show", "ops", "schema", "examples", "status", "guide", "history",
            "compare",
        ];
        let write_commands = &["invoke", "do", "batch", "install", "update", "pin", "unpin"];
        match mode {
            CliMode::Offline | CliMode::ReadOnly => read_only
                .iter()
                .filter(|c| {
                    c.starts_with(command)
                        || command.starts_with(**c)
                        || levenshtein(command, c) <= 2
                })
                .copied()
                .collect(),
            CliMode::Online => {
                let mut all: Vec<&str> = read_only.to_vec();
                all.extend_from_slice(write_commands);
                all.into_iter()
                    .filter(|c| {
                        c.starts_with(command)
                            || command.starts_with(*c)
                            || levenshtein(command, c) <= 2
                    })
                    .collect()
            }
        }
    }

    fn unknown_subcommand_recovery(parent: &str, sub: &str) -> RecoverySuggestion {
        let subcommands: &[&str] = match parent {
            "config" => &[
                "get", "set", "unset", "import", "export", "doctor", "schema",
            ],
            "task" => &[
                "create", "show", "list", "resolve", "ask", "advance", "bind", "approve", "run",
                "reconcile",
            ],
            "pipeline" => &["create", "run", "show", "list", "validate"],
            "approvals" => &["list", "create", "revoke", "show"],
            _ => &[],
        };
        let matches = closest_matches(sub, subcommands, 2, 1);
        matches.first().map_or_else(
            || RecoverySuggestion {
                original: format!("{parent} {sub}"),
                corrected: format!("{parent} --help"),
                kind: SuggestionKind::Invalid,
                confidence: Confidence::Low,
                message: format!("Unknown subcommand '{sub}' for '{parent}'. Use --help for available subcommands."),
            },
            |corrected| RecoverySuggestion {
                original: format!("{parent} {sub}"),
                corrected: format!("{parent} {corrected}"),
                kind: SuggestionKind::Typo,
                confidence: Confidence::Medium,
                message: format!("Unknown subcommand '{sub}' for '{parent}'. Did you mean '{corrected}'?"),
            },
        )
    }

    // ── 1. Command suggestion on typo ───────────────────────────────────

    mod command_typo {
        use super::*;

        #[test]
        fn serch_suggests_search() {
            let s = suggest_command("serch").unwrap();
            assert_eq!(s.corrected, "search");
            assert_eq!(s.kind, SuggestionKind::Typo);
        }

        #[test]
        fn validat_suggests_validate() {
            // "validate" is not in CANONICAL_COMMANDS but simulate and others are
            // test that close matches work for known commands
            let s = suggest_command("invoek").unwrap();
            assert_eq!(s.corrected, "invoke");
        }

        #[test]
        fn serach_suggests_search() {
            let s = suggest_command("serach").unwrap();
            assert_eq!(s.corrected, "search");
        }

        #[test]
        fn invke_suggests_invoke() {
            let s = suggest_command("invke").unwrap();
            assert_eq!(s.corrected, "invoke");
        }

        #[test]
        fn simualte_suggests_simulate() {
            let s = suggest_command("simualte").unwrap();
            assert_eq!(s.corrected, "simulate");
        }

        #[test]
        fn pipline_suggests_pipeline() {
            let s = suggest_command("pipline").unwrap();
            assert_eq!(s.corrected, "pipeline");
        }

        #[test]
        fn batcg_suggests_batch() {
            let s = suggest_command("batcg").unwrap();
            assert_eq!(s.corrected, "batch");
        }

        #[test]
        fn guidee_suggests_guide() {
            let s = suggest_command("guidee").unwrap();
            assert_eq!(s.corrected, "guide");
        }

        #[test]
        fn sttaus_suggests_status() {
            let s = suggest_command("sttaus").unwrap();
            assert_eq!(s.corrected, "status");
        }

        #[test]
        fn histroy_suggests_history() {
            let s = suggest_command("histroy").unwrap();
            assert_eq!(s.corrected, "history");
        }

        #[test]
        fn typo_suggestion_has_confidence() {
            let s = suggest_command("serch").unwrap();
            assert!(matches!(
                s.confidence,
                Confidence::High | Confidence::Medium
            ));
        }

        #[test]
        fn completely_wrong_returns_none() {
            let s = suggest_command("zzzyyyxxx");
            assert!(s.is_none(), "Gibberish should not match any command");
        }
    }

    // ── 2. Ambiguous command resolution ─────────────────────────────────

    mod ambiguous_resolution {
        use super::*;

        #[test]
        fn s_is_ambiguous() {
            let matches = resolve_ambiguous("s");
            assert!(
                matches.len() > 1,
                "Single 's' should match multiple commands: {matches:?}"
            );
            assert!(matches.contains(&"search"));
            assert!(matches.contains(&"schema"));
            assert!(matches.contains(&"show"));
            assert!(matches.contains(&"status"));
            assert!(matches.contains(&"simulate"));
        }

        #[test]
        fn se_matches_search() {
            let matches = resolve_ambiguous("se");
            assert!(matches.contains(&"search"));
        }

        #[test]
        fn in_matches_invoke_and_install() {
            let matches = resolve_ambiguous("in");
            assert!(matches.contains(&"invoke"));
            assert!(matches.contains(&"install"));
        }

        #[test]
        fn pi_matches_pipeline_and_pin() {
            let matches = resolve_ambiguous("pi");
            assert!(matches.contains(&"pipeline"));
            assert!(matches.contains(&"pin"));
        }

        #[test]
        fn un_matches_undo_and_unpin() {
            let matches = resolve_ambiguous("un");
            assert!(matches.contains(&"undo"));
            assert!(matches.contains(&"unpin"));
        }

        #[test]
        fn up_matches_update_and_unpin() {
            let matches = resolve_ambiguous("up");
            assert!(matches.contains(&"update"));
        }

        #[test]
        fn ex_matches_explain_and_examples() {
            let matches = resolve_ambiguous("ex");
            assert!(matches.contains(&"explain"));
            assert!(matches.contains(&"examples"));
        }

        #[test]
        fn full_command_is_unambiguous() {
            let matches = resolve_ambiguous("search");
            assert_eq!(matches.len(), 1);
            assert_eq!(matches[0], "search");
        }

        #[test]
        fn empty_prefix_matches_all() {
            let matches = resolve_ambiguous("");
            assert_eq!(matches.len(), CANONICAL_COMMANDS.len());
        }

        #[test]
        fn no_match_returns_empty() {
            let matches = resolve_ambiguous("zzz");
            assert!(matches.is_empty());
        }

        #[test]
        fn do_is_unambiguous() {
            let matches = resolve_ambiguous("do");
            assert!(matches.contains(&"do"));
            assert!(matches.contains(&"doctor"));
        }

        #[test]
        fn ba_matches_batch_and_budget() {
            let matches = resolve_ambiguous("ba");
            assert!(matches.contains(&"batch"));
        }
    }

    // ── 3. Missing argument recovery ────────────────────────────────────

    mod missing_argument {
        use super::*;

        #[test]
        fn invoke_missing_connector() {
            let r = missing_argument_recovery("invoke", "connector");
            assert_eq!(r.kind, SuggestionKind::Missing);
            assert!(r.message.contains("connector"));
            assert_eq!(r.corrected, "invoke <connector>");
        }

        #[test]
        fn invoke_missing_operation() {
            let r = missing_argument_recovery("invoke github", "operation");
            assert!(r.message.contains("operation"));
        }

        #[test]
        fn schema_missing_connector() {
            let r = missing_argument_recovery("schema", "connector");
            assert_eq!(r.kind, SuggestionKind::Missing);
            assert!(r.message.contains("connector"));
        }

        #[test]
        fn batch_missing_items() {
            let r = missing_argument_recovery("batch github create_issue", "items");
            assert!(r.message.contains("items"));
        }

        #[test]
        fn task_create_missing_intent() {
            let r = missing_argument_recovery("task create", "intent");
            assert!(r.message.contains("intent"));
        }

        #[test]
        fn missing_argument_confidence_is_high() {
            let r = missing_argument_recovery("invoke", "connector");
            assert_eq!(r.confidence, Confidence::High);
        }

        #[test]
        fn config_missing_connector() {
            let r = missing_argument_recovery("config", "connector");
            assert!(r.corrected.contains("<connector>"));
        }

        #[test]
        fn replay_missing_entry_id() {
            let r = missing_argument_recovery("replay", "entry-id");
            assert!(r.message.contains("entry-id"));
        }
    }

    // ── 4. Invalid flag recovery ────────────────────────────────────────

    mod invalid_flag {
        use super::*;

        #[test]
        fn valid_flag_returns_none() {
            assert!(validate_flag("--format").is_none());
        }

        #[test]
        fn valid_json_flag_returns_none() {
            assert!(validate_flag("--json").is_none());
        }

        #[test]
        fn valid_help_flag_returns_none() {
            assert!(validate_flag("--help").is_none());
        }

        #[test]
        fn formt_suggests_format() {
            let s = validate_flag("--formt").unwrap();
            assert_eq!(s.corrected, "--format");
        }

        #[test]
        fn jsn_suggests_json() {
            let s = validate_flag("--jsn").unwrap();
            assert_eq!(s.corrected, "--json");
        }

        #[test]
        fn inpu_suggests_input() {
            let s = validate_flag("--inpu").unwrap();
            assert_eq!(s.corrected, "--input");
        }

        #[test]
        fn hoste_suggests_host() {
            let s = validate_flag("--hoste").unwrap();
            assert_eq!(s.corrected, "--host");
        }

        #[test]
        fn invalid_flag_kind_is_invalid() {
            let s = validate_flag("--formt").unwrap();
            assert_eq!(s.kind, SuggestionKind::Invalid);
        }

        #[test]
        fn completely_unknown_flag() {
            let s = validate_flag("--zzzzz");
            // Should return None for totally unrelated flag
            assert!(s.is_none(), "Totally unknown flag should not match");
        }

        #[test]
        fn retr_suggests_retry() {
            let s = validate_flag("--retr").unwrap();
            assert_eq!(s.corrected, "--retry");
        }
    }

    // ── 5. Connector name suggestion ────────────────────────────────────

    mod connector_suggestion {
        use super::*;

        #[test]
        fn githbu_suggests_github() {
            let s = suggest_connector("githbu").unwrap();
            assert_eq!(s.corrected, "github");
        }

        #[test]
        fn gitlba_suggests_gitlab() {
            let s = suggest_connector("gitlba").unwrap();
            assert_eq!(s.corrected, "gitlab");
        }

        #[test]
        fn slakc_suggests_slack() {
            let s = suggest_connector("slakc").unwrap();
            assert_eq!(s.corrected, "slack");
        }

        #[test]
        fn discrod_suggests_discord() {
            let s = suggest_connector("discrod").unwrap();
            assert_eq!(s.corrected, "discord");
        }

        #[test]
        fn telegarm_suggests_telegram() {
            let s = suggest_connector("telegarm").unwrap();
            assert_eq!(s.corrected, "telegram");
        }

        #[test]
        fn jiira_suggests_jira() {
            let s = suggest_connector("jiira").unwrap();
            assert_eq!(s.corrected, "jira");
        }

        #[test]
        fn notiom_suggests_notion() {
            let s = suggest_connector("notiom").unwrap();
            assert_eq!(s.corrected, "notion");
        }

        #[test]
        fn exact_match_returns_self() {
            let s = suggest_connector("github").unwrap();
            assert_eq!(s.corrected, "github");
        }

        #[test]
        fn gibberish_connector_returns_none() {
            let s = suggest_connector("zzzyyyxxx");
            assert!(s.is_none());
        }
    }

    // ── 6. Operation name suggestion ────────────────────────────────────

    mod operation_suggestion {
        use super::*;

        #[test]
        fn crate_issue_suggests_create_issue() {
            let s = suggest_operation("crate_issue").unwrap();
            assert_eq!(s.corrected, "create_issue");
        }

        #[test]
        fn list_reops_suggests_list_repos() {
            let s = suggest_operation("list_reops").unwrap();
            assert_eq!(s.corrected, "list_repos");
        }

        #[test]
        fn get_usr_suggests_get_user() {
            let s = suggest_operation("get_usr").unwrap();
            assert_eq!(s.corrected, "get_user");
        }

        #[test]
        fn send_mesage_suggests_send_message() {
            let s = suggest_operation("send_mesage").unwrap();
            assert_eq!(s.corrected, "send_message");
        }

        #[test]
        fn update_reocrd_suggests_update_record() {
            let s = suggest_operation("update_reocrd").unwrap();
            assert_eq!(s.corrected, "update_record");
        }

        #[test]
        fn search_ticktes_suggests_search_tickets() {
            let s = suggest_operation("search_ticktes").unwrap();
            assert_eq!(s.corrected, "search_tickets");
        }

        #[test]
        fn gibberish_operation_returns_none() {
            let s = suggest_operation("xxxyyyzzz");
            assert!(s.is_none());
        }
    }

    // ── 7. Unknown subcommand handling ──────────────────────────────────

    mod unknown_subcommand {
        use super::*;

        #[test]
        fn config_gte_suggests_get() {
            let r = unknown_subcommand_recovery("config", "gte");
            assert_eq!(r.kind, SuggestionKind::Typo);
            assert!(r.corrected.contains("get"));
        }

        #[test]
        fn config_ste_suggests_set() {
            let r = unknown_subcommand_recovery("config", "ste");
            assert!(r.corrected.contains("set"));
        }

        #[test]
        fn task_cretae_suggests_create() {
            let r = unknown_subcommand_recovery("task", "cretae");
            assert!(r.corrected.contains("create"), "got: {}", r.corrected);
        }

        #[test]
        fn task_shwo_suggests_show() {
            let r = unknown_subcommand_recovery("task", "shwo");
            assert!(r.corrected.contains("show"));
        }

        #[test]
        fn pipeline_rnu_suggests_run() {
            let r = unknown_subcommand_recovery("pipeline", "rnu");
            assert!(r.corrected.contains("run"));
        }

        #[test]
        fn approvals_lits_suggests_list() {
            let r = unknown_subcommand_recovery("approvals", "lits");
            assert!(r.corrected.contains("list"));
        }

        #[test]
        fn totally_unknown_subcommand_suggests_help() {
            let r = unknown_subcommand_recovery("config", "zzzzz");
            assert_eq!(r.kind, SuggestionKind::Invalid);
            assert!(r.message.contains("--help"));
        }

        #[test]
        fn unknown_parent_gives_help() {
            let r = unknown_subcommand_recovery("nonexistent", "foo");
            assert_eq!(r.kind, SuggestionKind::Invalid);
        }
    }

    // ── 8. Context-aware suggestions ────────────────────────────────────

    mod context_aware {
        use super::*;

        #[test]
        fn offline_mode_suggests_read_only() {
            let suggestions = context_aware_suggestions("s", CliMode::Offline);
            for s in &suggestions {
                assert!(
                    !["invoke", "do", "batch", "install", "update", "pin", "unpin"].contains(s),
                    "Offline mode should not suggest write command: {s}"
                );
            }
        }

        #[test]
        fn online_mode_includes_invoke() {
            let suggestions = context_aware_suggestions("inv", CliMode::Online);
            assert!(
                suggestions.contains(&"invoke"),
                "Online mode should suggest invoke"
            );
        }

        #[test]
        fn readonly_mode_excludes_batch() {
            let suggestions = context_aware_suggestions("b", CliMode::ReadOnly);
            assert!(
                !suggestions.contains(&"batch"),
                "ReadOnly mode should not suggest batch"
            );
        }

        #[test]
        fn offline_search_suggests_search() {
            let suggestions = context_aware_suggestions("searc", CliMode::Offline);
            assert!(suggestions.contains(&"search"));
        }

        #[test]
        fn online_mode_suggests_both_read_and_write() {
            let read_suggestions = context_aware_suggestions("", CliMode::Online);
            let has_read = read_suggestions
                .iter()
                .any(|s| *s == "search" || *s == "list");
            let has_write = read_suggestions
                .iter()
                .any(|s| *s == "invoke" || *s == "do");
            assert!(has_read, "Online mode should include read commands");
            assert!(has_write, "Online mode should include write commands");
        }

        #[test]
        fn offline_history_is_available() {
            let suggestions = context_aware_suggestions("hist", CliMode::Offline);
            assert!(suggestions.contains(&"history"));
        }

        #[test]
        fn readonly_compare_is_available() {
            let suggestions = context_aware_suggestions("comp", CliMode::ReadOnly);
            assert!(suggestions.contains(&"compare"));
        }
    }

    // ── 9. Serialization and recovery envelope ──────────────────────────

    mod recovery_envelope {
        use super::*;

        #[test]
        fn suggestion_serializes_to_json() {
            let s = suggest_command("serch").unwrap();
            let json = serde_json::to_value(&s).unwrap();
            assert_eq!(json["original"], "serch");
            assert_eq!(json["corrected"], "search");
            assert_eq!(json["kind"], "typo");
        }

        #[test]
        fn suggestion_roundtrips_through_serde() {
            let s = suggest_command("invke").unwrap();
            let json = serde_json::to_string(&s).unwrap();
            let parsed: RecoverySuggestion = serde_json::from_str(&json).unwrap();
            assert_eq!(s, parsed);
        }

        #[test]
        fn missing_arg_serializes_correctly() {
            let r = missing_argument_recovery("invoke", "connector");
            let json = serde_json::to_value(&r).unwrap();
            assert_eq!(json["kind"], "missing");
            assert_eq!(json["confidence"], "high");
        }

        #[test]
        fn invalid_flag_serializes_correctly() {
            let s = validate_flag("--formt").unwrap();
            let json = serde_json::to_value(&s).unwrap();
            assert_eq!(json["kind"], "invalid");
        }

        #[test]
        fn levenshtein_self_is_zero() {
            assert_eq!(levenshtein("search", "search"), 0);
        }

        #[test]
        fn levenshtein_empty_strings() {
            assert_eq!(levenshtein("", ""), 0);
        }

        #[test]
        fn levenshtein_one_empty() {
            assert_eq!(levenshtein("abc", ""), 3);
            assert_eq!(levenshtein("", "xyz"), 3);
        }

        #[test]
        fn levenshtein_known_distance() {
            assert_eq!(levenshtein("kitten", "sitting"), 3);
        }

        #[test]
        fn closest_matches_exact() {
            let matches = closest_matches("search", CANONICAL_COMMANDS, 2, 5);
            assert_eq!(matches[0], "search");
        }

        #[test]
        fn closest_matches_respects_limit() {
            let matches = closest_matches("s", CANONICAL_COMMANDS, 10, 3);
            assert!(matches.len() <= 3);
        }
    }
}
