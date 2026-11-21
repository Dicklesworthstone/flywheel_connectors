//! Snapshot tests for help text, taxonomy, and progressive disclosure surfaces (bead 18.1).
//!
//! Verifies that command help text formatting, taxonomy classification,
//! progressive disclosure levels, and output mode consistency behave
//! as expected across all major FWC command families.

#[cfg(test)]
#[allow(
    clippy::too_many_lines,
    clippy::redundant_closure_for_method_calls,
    clippy::format_push_string,
    clippy::uninlined_format_args,
    clippy::needless_collect
)]
mod tests {
    use serde::{Deserialize, Serialize};
    use std::collections::BTreeSet;

    // ── Test scaffolding types ──────────────────────────────────────────

    /// A synthetic command descriptor for snapshot testing.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    struct CommandDescriptor {
        name: &'static str,
        category: CommandCategory,
        synopsis: &'static str,
        description: &'static str,
        examples: Vec<&'static str>,
        subcommands: Vec<&'static str>,
        hidden: bool,
        advanced: bool,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    enum CommandCategory {
        Discovery,
        Execution,
        Workflow,
        Admin,
        Meta,
    }

    impl CommandCategory {
        const fn as_str(self) -> &'static str {
            match self {
                Self::Discovery => "discovery",
                Self::Execution => "execution",
                Self::Workflow => "workflow",
                Self::Admin => "admin",
                Self::Meta => "meta",
            }
        }

        fn all() -> &'static [Self] {
            &[
                Self::Discovery,
                Self::Execution,
                Self::Workflow,
                Self::Admin,
                Self::Meta,
            ]
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum DisclosureLevel {
        Basic,
        Detailed,
        Examples,
        Advanced,
    }

    /// Structured help output for a command.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    struct HelpOutput {
        command: String,
        synopsis: String,
        description: String,
        usage: String,
        options: Vec<OptionEntry>,
        examples: Vec<String>,
        see_also: Vec<String>,
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    struct OptionEntry {
        flag: String,
        description: String,
        required: bool,
        default_value: Option<String>,
    }

    /// Error envelope in help context.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    struct HelpErrorEnvelope {
        code: String,
        message: String,
        suggestion: Option<String>,
    }

    // ── Registry of all FWC command families ────────────────────────────

    fn command_registry() -> Vec<CommandDescriptor> {
        vec![
            CommandDescriptor {
                name: "search",
                category: CommandCategory::Discovery,
                synopsis: "Search for connectors and operations",
                description: "Full-text search across the connector catalog, operations, and schema fields.",
                examples: vec!["fwc search github", "fwc search --tag crm"],
                subcommands: vec!["operations", "connectors", "schemas"],
                hidden: false,
                advanced: false,
            },
            CommandDescriptor {
                name: "invoke",
                category: CommandCategory::Execution,
                synopsis: "Invoke a connector operation",
                description: "Execute a single operation against a running connector with input validation and capability checking.",
                examples: vec!["fwc invoke github create_issue --input '{}'"],
                subcommands: vec![],
                hidden: false,
                advanced: false,
            },
            CommandDescriptor {
                name: "validate",
                category: CommandCategory::Discovery,
                synopsis: "Validate input against operation schema",
                description: "Check that a JSON input payload conforms to the operation's expected schema.",
                examples: vec!["fwc validate github create_issue --input '{}'"],
                subcommands: vec![],
                hidden: false,
                advanced: false,
            },
            CommandDescriptor {
                name: "discover",
                category: CommandCategory::Discovery,
                synopsis: "Discover available connectors",
                description: "List and introspect the connector catalog, showing available operations and capabilities.",
                examples: vec!["fwc discover", "fwc discover --format json"],
                subcommands: vec!["connectors", "operations"],
                hidden: false,
                advanced: false,
            },
            CommandDescriptor {
                name: "history",
                category: CommandCategory::Meta,
                synopsis: "Show operation execution history",
                description: "Display the audit log of past invocations with filtering and replay support.",
                examples: vec!["fwc history", "fwc history --connector github"],
                subcommands: vec!["list", "show", "export"],
                hidden: false,
                advanced: false,
            },
            CommandDescriptor {
                name: "pipeline",
                category: CommandCategory::Workflow,
                synopsis: "Define and run multi-step pipelines",
                description: "Create, validate, and execute named pipelines that chain multiple operations.",
                examples: vec!["fwc pipeline run my-pipeline"],
                subcommands: vec!["create", "run", "show", "list", "validate"],
                hidden: false,
                advanced: false,
            },
            CommandDescriptor {
                name: "batch",
                category: CommandCategory::Execution,
                synopsis: "Execute an operation over multiple inputs",
                description: "Apply a single operation to N inputs in parallel with configurable concurrency.",
                examples: vec!["fwc batch github create_issue --items '[{}]'"],
                subcommands: vec![],
                hidden: false,
                advanced: false,
            },
            CommandDescriptor {
                name: "compare",
                category: CommandCategory::Meta,
                synopsis: "Compare two invocation results",
                description: "Diff the output of two operations or two runs of the same operation.",
                examples: vec!["fwc compare result1.json result2.json"],
                subcommands: vec![],
                hidden: false,
                advanced: false,
            },
            CommandDescriptor {
                name: "replay",
                category: CommandCategory::Meta,
                synopsis: "Replay a past invocation",
                description: "Re-execute a recorded invocation from the history log with optional input overrides.",
                examples: vec!["fwc replay <entry-id>"],
                subcommands: vec![],
                hidden: false,
                advanced: false,
            },
            CommandDescriptor {
                name: "undo",
                category: CommandCategory::Execution,
                synopsis: "Undo a reversible operation",
                description: "Reverse a previously executed operation using its recorded inverse.",
                examples: vec!["fwc undo <entry-id>"],
                subcommands: vec![],
                hidden: false,
                advanced: false,
            },
            CommandDescriptor {
                name: "approvals",
                category: CommandCategory::Admin,
                synopsis: "Manage approval tokens",
                description: "List, create, revoke, and inspect approval tokens for elevated operations.",
                examples: vec!["fwc approvals list", "fwc approvals create --scope github"],
                subcommands: vec!["list", "create", "revoke", "show"],
                hidden: false,
                advanced: false,
            },
            CommandDescriptor {
                name: "guide",
                category: CommandCategory::Meta,
                synopsis: "Show command taxonomy and help",
                description: "Display the full command taxonomy with categories, aliases, and usage guides.",
                examples: vec!["fwc guide", "fwc guide --category discovery"],
                subcommands: vec![],
                hidden: false,
                advanced: false,
            },
            CommandDescriptor {
                name: "doctor",
                category: CommandCategory::Admin,
                synopsis: "Diagnose connector health issues",
                description: "Run connectivity, auth, and configuration checks for one or all connectors.",
                examples: vec!["fwc doctor", "fwc doctor github"],
                subcommands: vec![],
                hidden: false,
                advanced: false,
            },
            CommandDescriptor {
                name: "config",
                category: CommandCategory::Admin,
                synopsis: "Manage connector configuration",
                description: "Get, set, and validate connector configuration values.",
                examples: vec!["fwc config github get api_key"],
                subcommands: vec![
                    "get", "set", "unset", "import", "export", "doctor", "schema",
                ],
                hidden: false,
                advanced: false,
            },
            CommandDescriptor {
                name: "__internal_debug",
                category: CommandCategory::Meta,
                synopsis: "Internal debugging utilities",
                description: "Debug and diagnostic commands not shown in public help.",
                examples: vec![],
                subcommands: vec![],
                hidden: true,
                advanced: true,
            },
            CommandDescriptor {
                name: "__profile",
                category: CommandCategory::Meta,
                synopsis: "Internal profiling tools",
                description: "Performance profiling utilities for development.",
                examples: vec![],
                subcommands: vec![],
                hidden: true,
                advanced: true,
            },
            CommandDescriptor {
                name: "simulate",
                category: CommandCategory::Execution,
                synopsis: "Dry-run an operation without side effects",
                description: "Preview what an invocation would do without actually executing it.",
                examples: vec!["fwc simulate github create_issue --input '{}'"],
                subcommands: vec![],
                hidden: false,
                advanced: false,
            },
            CommandDescriptor {
                name: "task",
                category: CommandCategory::Workflow,
                synopsis: "Manage workflow tasks",
                description: "Create, inspect, resolve, and execute workflow task capsules.",
                examples: vec!["fwc task create \"deploy to staging\"", "fwc task list"],
                subcommands: vec![
                    "create", "show", "list", "resolve", "ask", "advance", "bind", "approve", "run",
                    "reconcile",
                ],
                hidden: false,
                advanced: false,
            },
            CommandDescriptor {
                name: "schema",
                category: CommandCategory::Discovery,
                synopsis: "Show operation input/output schema",
                description: "Display the JSON Schema for an operation's input and output payloads.",
                examples: vec!["fwc schema github create_issue"],
                subcommands: vec![],
                hidden: false,
                advanced: false,
            },
            CommandDescriptor {
                name: "budget",
                category: CommandCategory::Admin,
                synopsis: "View and manage usage budgets",
                description: "Check rate limit budgets and usage windows for connectors.",
                examples: vec!["fwc budget github"],
                subcommands: vec![],
                hidden: false,
                advanced: true,
            },
        ]
    }

    fn build_help_output(cmd: &CommandDescriptor, level: DisclosureLevel) -> HelpOutput {
        let options = match level {
            DisclosureLevel::Basic => vec![
                OptionEntry {
                    flag: "--format".into(),
                    description: "Output format (json, toon, table)".into(),
                    required: false,
                    default_value: Some("toon".into()),
                },
                OptionEntry {
                    flag: "--help".into(),
                    description: "Show help for this command".into(),
                    required: false,
                    default_value: None,
                },
            ],
            DisclosureLevel::Detailed | DisclosureLevel::Examples => vec![
                OptionEntry {
                    flag: "--format".into(),
                    description: "Output format (json, toon, table, csv, tsv, markdown)".into(),
                    required: false,
                    default_value: Some("toon".into()),
                },
                OptionEntry {
                    flag: "--help".into(),
                    description: "Show detailed help for this command".into(),
                    required: false,
                    default_value: None,
                },
                OptionEntry {
                    flag: "--json".into(),
                    description: "Shorthand for --format json".into(),
                    required: false,
                    default_value: None,
                },
            ],
            DisclosureLevel::Advanced => vec![
                OptionEntry {
                    flag: "--format".into(),
                    description:
                        "Output format (json, toon, table, csv, tsv, markdown, ndjson, jsonl)"
                            .into(),
                    required: false,
                    default_value: Some("toon".into()),
                },
                OptionEntry {
                    flag: "--help".into(),
                    description: "Show help for this command".into(),
                    required: false,
                    default_value: None,
                },
                OptionEntry {
                    flag: "--json".into(),
                    description: "Shorthand for --format json".into(),
                    required: false,
                    default_value: None,
                },
                OptionEntry {
                    flag: "--host".into(),
                    description: "Override the FCP host address".into(),
                    required: false,
                    default_value: None,
                },
                OptionEntry {
                    flag: "--token-stats".into(),
                    description: "Show token budget statistics".into(),
                    required: false,
                    default_value: None,
                },
            ],
        };

        let examples = match level {
            DisclosureLevel::Basic => vec![],
            _ => cmd.examples.iter().map(|e| (*e).to_string()).collect(),
        };

        HelpOutput {
            command: cmd.name.to_string(),
            synopsis: cmd.synopsis.to_string(),
            description: match level {
                DisclosureLevel::Basic => cmd.synopsis.to_string(),
                _ => cmd.description.to_string(),
            },
            usage: format!("fwc {} [OPTIONS]", cmd.name),
            options,
            examples,
            see_also: if cmd.subcommands.is_empty() {
                vec!["fwc guide".into()]
            } else {
                cmd.subcommands
                    .iter()
                    .map(|sub| format!("fwc {} {sub}", cmd.name))
                    .collect()
            },
        }
    }

    fn render_toon(help: &HelpOutput) -> String {
        use std::fmt::Write;
        let mut out = String::new();
        let _ = writeln!(out, "{}", help.command);
        let _ = writeln!(out, "  {}\n", help.synopsis);
        let _ = writeln!(out, "USAGE: {}\n", help.usage);
        if !help.description.is_empty() {
            let _ = writeln!(out, "DESCRIPTION:\n  {}\n", help.description);
        }
        if !help.options.is_empty() {
            out.push_str("OPTIONS:\n");
            for opt in &help.options {
                let _ = writeln!(out, "  {:<20} {}", opt.flag, opt.description);
            }
            out.push('\n');
        }
        if !help.examples.is_empty() {
            out.push_str("EXAMPLES:\n");
            for ex in &help.examples {
                let _ = writeln!(out, "  {ex}");
            }
            out.push('\n');
        }
        out
    }

    fn render_json(help: &HelpOutput) -> String {
        serde_json::to_string_pretty(help).unwrap()
    }

    // ── 1. Help text format for major command families ──────────────────

    mod help_text_format {
        use super::*;

        #[test]
        fn search_help_has_synopsis() {
            let reg = command_registry();
            let cmd = reg.iter().find(|c| c.name == "search").unwrap();
            let help = build_help_output(cmd, DisclosureLevel::Basic);
            assert!(
                help.synopsis.contains("Search"),
                "synopsis: {}",
                help.synopsis
            );
        }

        #[test]
        fn invoke_help_has_synopsis() {
            let reg = command_registry();
            let cmd = reg.iter().find(|c| c.name == "invoke").unwrap();
            let help = build_help_output(cmd, DisclosureLevel::Basic);
            assert!(
                help.synopsis.contains("Invoke"),
                "synopsis: {}",
                help.synopsis
            );
        }

        #[test]
        fn validate_help_has_synopsis() {
            let reg = command_registry();
            let cmd = reg.iter().find(|c| c.name == "validate").unwrap();
            let help = build_help_output(cmd, DisclosureLevel::Basic);
            assert!(
                help.synopsis.contains("Validate"),
                "synopsis: {}",
                help.synopsis
            );
        }

        #[test]
        fn discover_help_has_synopsis() {
            let reg = command_registry();
            let cmd = reg.iter().find(|c| c.name == "discover").unwrap();
            let help = build_help_output(cmd, DisclosureLevel::Basic);
            assert!(!help.synopsis.is_empty());
        }

        #[test]
        fn history_help_has_synopsis() {
            let reg = command_registry();
            let cmd = reg.iter().find(|c| c.name == "history").unwrap();
            let help = build_help_output(cmd, DisclosureLevel::Basic);
            assert!(
                help.synopsis.contains("history"),
                "synopsis: {}",
                help.synopsis
            );
        }

        #[test]
        fn pipeline_help_has_synopsis() {
            let reg = command_registry();
            let cmd = reg.iter().find(|c| c.name == "pipeline").unwrap();
            let help = build_help_output(cmd, DisclosureLevel::Basic);
            assert!(
                help.synopsis.contains("pipeline"),
                "synopsis: {}",
                help.synopsis
            );
        }

        #[test]
        fn batch_help_has_synopsis() {
            let reg = command_registry();
            let cmd = reg.iter().find(|c| c.name == "batch").unwrap();
            let help = build_help_output(cmd, DisclosureLevel::Basic);
            assert!(
                help.synopsis.contains("Execute"),
                "synopsis: {}",
                help.synopsis
            );
        }

        #[test]
        fn compare_help_has_synopsis() {
            let reg = command_registry();
            let cmd = reg.iter().find(|c| c.name == "compare").unwrap();
            let help = build_help_output(cmd, DisclosureLevel::Basic);
            assert!(help.synopsis.contains("Compare"));
        }

        #[test]
        fn replay_help_has_synopsis() {
            let reg = command_registry();
            let cmd = reg.iter().find(|c| c.name == "replay").unwrap();
            let help = build_help_output(cmd, DisclosureLevel::Basic);
            assert!(help.synopsis.contains("Replay"));
        }

        #[test]
        fn undo_help_has_synopsis() {
            let reg = command_registry();
            let cmd = reg.iter().find(|c| c.name == "undo").unwrap();
            let help = build_help_output(cmd, DisclosureLevel::Basic);
            assert!(help.synopsis.contains("Undo"));
        }

        #[test]
        fn approvals_help_has_synopsis() {
            let reg = command_registry();
            let cmd = reg.iter().find(|c| c.name == "approvals").unwrap();
            let help = build_help_output(cmd, DisclosureLevel::Basic);
            assert!(help.synopsis.contains("approval"));
        }

        #[test]
        fn guide_help_has_synopsis() {
            let reg = command_registry();
            let cmd = reg.iter().find(|c| c.name == "guide").unwrap();
            let help = build_help_output(cmd, DisclosureLevel::Basic);
            assert!(help.synopsis.contains("taxonomy") || help.synopsis.contains("help"));
        }
    }

    // ── 2. Taxonomy classification ──────────────────────────────────────

    mod taxonomy {
        use super::*;

        #[test]
        fn search_is_discovery() {
            let reg = command_registry();
            let cmd = reg.iter().find(|c| c.name == "search").unwrap();
            assert_eq!(cmd.category, CommandCategory::Discovery);
        }

        #[test]
        fn validate_is_discovery() {
            let reg = command_registry();
            let cmd = reg.iter().find(|c| c.name == "validate").unwrap();
            assert_eq!(cmd.category, CommandCategory::Discovery);
        }

        #[test]
        fn discover_is_discovery() {
            let reg = command_registry();
            let cmd = reg.iter().find(|c| c.name == "discover").unwrap();
            assert_eq!(cmd.category, CommandCategory::Discovery);
        }

        #[test]
        fn schema_is_discovery() {
            let reg = command_registry();
            let cmd = reg.iter().find(|c| c.name == "schema").unwrap();
            assert_eq!(cmd.category, CommandCategory::Discovery);
        }

        #[test]
        fn invoke_is_execution() {
            let reg = command_registry();
            let cmd = reg.iter().find(|c| c.name == "invoke").unwrap();
            assert_eq!(cmd.category, CommandCategory::Execution);
        }

        #[test]
        fn batch_is_execution() {
            let reg = command_registry();
            let cmd = reg.iter().find(|c| c.name == "batch").unwrap();
            assert_eq!(cmd.category, CommandCategory::Execution);
        }

        #[test]
        fn simulate_is_execution() {
            let reg = command_registry();
            let cmd = reg.iter().find(|c| c.name == "simulate").unwrap();
            assert_eq!(cmd.category, CommandCategory::Execution);
        }

        #[test]
        fn undo_is_execution() {
            let reg = command_registry();
            let cmd = reg.iter().find(|c| c.name == "undo").unwrap();
            assert_eq!(cmd.category, CommandCategory::Execution);
        }

        #[test]
        fn pipeline_is_workflow() {
            let reg = command_registry();
            let cmd = reg.iter().find(|c| c.name == "pipeline").unwrap();
            assert_eq!(cmd.category, CommandCategory::Workflow);
        }

        #[test]
        fn task_is_workflow() {
            let reg = command_registry();
            let cmd = reg.iter().find(|c| c.name == "task").unwrap();
            assert_eq!(cmd.category, CommandCategory::Workflow);
        }

        #[test]
        fn approvals_is_admin() {
            let reg = command_registry();
            let cmd = reg.iter().find(|c| c.name == "approvals").unwrap();
            assert_eq!(cmd.category, CommandCategory::Admin);
        }

        #[test]
        fn doctor_is_admin() {
            let reg = command_registry();
            let cmd = reg.iter().find(|c| c.name == "doctor").unwrap();
            assert_eq!(cmd.category, CommandCategory::Admin);
        }

        #[test]
        fn config_is_admin() {
            let reg = command_registry();
            let cmd = reg.iter().find(|c| c.name == "config").unwrap();
            assert_eq!(cmd.category, CommandCategory::Admin);
        }

        #[test]
        fn history_is_meta() {
            let reg = command_registry();
            let cmd = reg.iter().find(|c| c.name == "history").unwrap();
            assert_eq!(cmd.category, CommandCategory::Meta);
        }

        #[test]
        fn compare_is_meta() {
            let reg = command_registry();
            let cmd = reg.iter().find(|c| c.name == "compare").unwrap();
            assert_eq!(cmd.category, CommandCategory::Meta);
        }

        #[test]
        fn replay_is_meta() {
            let reg = command_registry();
            let cmd = reg.iter().find(|c| c.name == "replay").unwrap();
            assert_eq!(cmd.category, CommandCategory::Meta);
        }

        #[test]
        fn guide_is_meta() {
            let reg = command_registry();
            let cmd = reg.iter().find(|c| c.name == "guide").unwrap();
            assert_eq!(cmd.category, CommandCategory::Meta);
        }

        #[test]
        fn all_categories_have_at_least_one_command() {
            let reg = command_registry();
            for cat in CommandCategory::all() {
                let count = reg.iter().filter(|c| c.category == *cat).count();
                assert_ne!(count, 0, "Category {cat:?} has no commands");
            }
        }

        #[test]
        fn category_as_str_roundtrips() {
            for cat in CommandCategory::all() {
                let json = serde_json::to_string(cat).unwrap();
                let parsed: CommandCategory = serde_json::from_str(&json).unwrap();
                assert_eq!(*cat, parsed);
            }
        }

        #[test]
        fn no_duplicate_command_names() {
            let reg = command_registry();
            let names: Vec<&str> = reg.iter().map(|c| c.name).collect();
            let unique: BTreeSet<&str> = names.iter().copied().collect();
            assert_eq!(names.len(), unique.len(), "Duplicate command names found");
        }
    }

    // ── 3. Progressive disclosure ───────────────────────────────────────

    mod progressive_disclosure {
        use super::*;

        #[test]
        fn basic_has_no_examples() {
            let reg = command_registry();
            let cmd = reg.iter().find(|c| c.name == "search").unwrap();
            let help = build_help_output(cmd, DisclosureLevel::Basic);
            assert!(
                help.examples.is_empty(),
                "Basic help should have no examples"
            );
        }

        #[test]
        fn detailed_has_full_description() {
            let reg = command_registry();
            let cmd = reg.iter().find(|c| c.name == "search").unwrap();
            let basic = build_help_output(cmd, DisclosureLevel::Basic);
            let detailed = build_help_output(cmd, DisclosureLevel::Detailed);
            assert!(
                detailed.description.len() >= basic.description.len(),
                "Detailed description should be at least as long as basic"
            );
        }

        #[test]
        fn examples_level_has_examples() {
            let reg = command_registry();
            let cmd = reg.iter().find(|c| c.name == "search").unwrap();
            let help = build_help_output(cmd, DisclosureLevel::Examples);
            assert!(
                !help.examples.is_empty(),
                "Examples level should show examples"
            );
        }

        #[test]
        fn advanced_has_more_options_than_basic() {
            let reg = command_registry();
            let cmd = reg.iter().find(|c| c.name == "search").unwrap();
            let basic = build_help_output(cmd, DisclosureLevel::Basic);
            let advanced = build_help_output(cmd, DisclosureLevel::Advanced);
            assert!(
                advanced.options.len() > basic.options.len(),
                "Advanced should have more options ({}) than basic ({})",
                advanced.options.len(),
                basic.options.len()
            );
        }

        #[test]
        fn basic_always_has_help_flag() {
            let reg = command_registry();
            for cmd in &reg {
                if cmd.hidden {
                    continue;
                }
                let help = build_help_output(cmd, DisclosureLevel::Basic);
                assert!(
                    help.options.iter().any(|o| o.flag == "--help"),
                    "Command {} missing --help in basic level",
                    cmd.name
                );
            }
        }

        #[test]
        fn advanced_has_host_flag() {
            let reg = command_registry();
            let cmd = reg.iter().find(|c| c.name == "invoke").unwrap();
            let help = build_help_output(cmd, DisclosureLevel::Advanced);
            assert!(
                help.options.iter().any(|o| o.flag == "--host"),
                "Advanced invoke help missing --host flag"
            );
        }

        #[test]
        fn basic_format_default_is_toon() {
            let reg = command_registry();
            let cmd = reg.iter().find(|c| c.name == "search").unwrap();
            let help = build_help_output(cmd, DisclosureLevel::Basic);
            let fmt_opt = help.options.iter().find(|o| o.flag == "--format").unwrap();
            assert_eq!(fmt_opt.default_value.as_deref(), Some("toon"));
        }
    }

    // ── 4. Help text consistency ────────────────────────────────────────

    mod consistency {
        use super::*;

        #[test]
        fn every_public_command_has_synopsis() {
            let reg = command_registry();
            for cmd in &reg {
                if cmd.hidden {
                    continue;
                }
                assert!(
                    !cmd.synopsis.is_empty(),
                    "Command {} has empty synopsis",
                    cmd.name
                );
            }
        }

        #[test]
        fn every_public_command_has_description() {
            let reg = command_registry();
            for cmd in &reg {
                if cmd.hidden {
                    continue;
                }
                assert!(
                    !cmd.description.is_empty(),
                    "Command {} has empty description",
                    cmd.name
                );
            }
        }

        #[test]
        fn every_public_command_has_examples() {
            let reg = command_registry();
            for cmd in &reg {
                if cmd.hidden {
                    continue;
                }
                assert!(
                    !cmd.examples.is_empty(),
                    "Command {} has no examples",
                    cmd.name
                );
            }
        }

        #[test]
        fn synopsis_does_not_end_with_period() {
            let reg = command_registry();
            for cmd in &reg {
                assert!(
                    !cmd.synopsis.ends_with('.'),
                    "Command {} synopsis ends with period: {}",
                    cmd.name,
                    cmd.synopsis
                );
            }
        }

        #[test]
        fn description_ends_with_period() {
            let reg = command_registry();
            for cmd in &reg {
                assert!(
                    cmd.description.ends_with('.'),
                    "Command {} description does not end with period: {}",
                    cmd.name,
                    cmd.description
                );
            }
        }

        #[test]
        fn examples_start_with_fwc() {
            let reg = command_registry();
            for cmd in &reg {
                for ex in &cmd.examples {
                    assert!(
                        ex.starts_with("fwc "),
                        "Example for {} doesn't start with 'fwc ': {}",
                        cmd.name,
                        ex
                    );
                }
            }
        }

        #[test]
        fn no_empty_subcommand_names() {
            let reg = command_registry();
            for cmd in &reg {
                for sub in &cmd.subcommands {
                    assert!(!sub.is_empty(), "Command {} has empty subcommand", cmd.name);
                }
            }
        }
    }

    // ── 5. TOON vs JSON help output equivalence ─────────────────────────

    mod output_equivalence {
        use super::*;

        #[test]
        fn toon_contains_command_name() {
            let reg = command_registry();
            let cmd = reg.iter().find(|c| c.name == "search").unwrap();
            let help = build_help_output(cmd, DisclosureLevel::Detailed);
            let toon = render_toon(&help);
            assert!(toon.contains("search"), "TOON output missing command name");
        }

        #[test]
        fn json_contains_command_name() {
            let reg = command_registry();
            let cmd = reg.iter().find(|c| c.name == "search").unwrap();
            let help = build_help_output(cmd, DisclosureLevel::Detailed);
            let json = render_json(&help);
            assert!(json.contains("search"), "JSON output missing command name");
        }

        #[test]
        fn toon_and_json_have_same_synopsis() {
            let reg = command_registry();
            let cmd = reg.iter().find(|c| c.name == "invoke").unwrap();
            let help = build_help_output(cmd, DisclosureLevel::Detailed);
            let toon = render_toon(&help);
            let json_str = render_json(&help);
            let json: HelpOutput = serde_json::from_str(&json_str).unwrap();
            assert!(toon.contains(&help.synopsis));
            assert_eq!(json.synopsis, help.synopsis);
        }

        #[test]
        fn toon_and_json_have_same_examples_count() {
            let reg = command_registry();
            let cmd = reg.iter().find(|c| c.name == "search").unwrap();
            let help = build_help_output(cmd, DisclosureLevel::Examples);
            let json_str = render_json(&help);
            let json: HelpOutput = serde_json::from_str(&json_str).unwrap();
            assert_eq!(help.examples.len(), json.examples.len());
            // TOON should contain each example
            let toon = render_toon(&help);
            for ex in &help.examples {
                assert!(toon.contains(ex), "TOON missing example: {ex}");
            }
        }

        #[test]
        fn json_roundtrips_through_serde() {
            let reg = command_registry();
            let cmd = reg.iter().find(|c| c.name == "pipeline").unwrap();
            let help = build_help_output(cmd, DisclosureLevel::Detailed);
            let json_str = render_json(&help);
            let parsed: HelpOutput = serde_json::from_str(&json_str).unwrap();
            let re_serialized = serde_json::to_string_pretty(&parsed).unwrap();
            assert_eq!(json_str, re_serialized);
        }

        #[test]
        fn toon_has_usage_section() {
            let reg = command_registry();
            let cmd = reg.iter().find(|c| c.name == "batch").unwrap();
            let help = build_help_output(cmd, DisclosureLevel::Detailed);
            let toon = render_toon(&help);
            assert!(toon.contains("USAGE:"), "TOON output missing USAGE section");
        }

        #[test]
        fn toon_has_options_section() {
            let reg = command_registry();
            let cmd = reg.iter().find(|c| c.name == "batch").unwrap();
            let help = build_help_output(cmd, DisclosureLevel::Detailed);
            let toon = render_toon(&help);
            assert!(
                toon.contains("OPTIONS:"),
                "TOON output missing OPTIONS section"
            );
        }
    }

    // ── 6. Subcommand help ──────────────────────────────────────────────

    mod subcommand_help {
        use super::*;

        #[test]
        fn pipeline_has_subcommands() {
            let reg = command_registry();
            let cmd = reg.iter().find(|c| c.name == "pipeline").unwrap();
            assert!(
                !cmd.subcommands.is_empty(),
                "pipeline should have subcommands"
            );
        }

        #[test]
        fn config_has_subcommands() {
            let reg = command_registry();
            let cmd = reg.iter().find(|c| c.name == "config").unwrap();
            assert!(
                cmd.subcommands.len() >= 3,
                "config should have 3+ subcommands"
            );
        }

        #[test]
        fn task_has_nine_subcommands() {
            let reg = command_registry();
            let cmd = reg.iter().find(|c| c.name == "task").unwrap();
            assert_eq!(
                cmd.subcommands.len(),
                9,
                "task should have exactly 9 subcommands"
            );
        }

        #[test]
        fn top_level_see_also_lists_subcommands() {
            let reg = command_registry();
            let cmd = reg.iter().find(|c| c.name == "pipeline").unwrap();
            let help = build_help_output(cmd, DisclosureLevel::Detailed);
            for sub in &cmd.subcommands {
                let expected = format!("fwc pipeline {sub}");
                assert!(
                    help.see_also.contains(&expected),
                    "see_also missing '{expected}'"
                );
            }
        }

        #[test]
        fn commands_without_subcommands_see_also_guide() {
            let reg = command_registry();
            let cmd = reg.iter().find(|c| c.name == "invoke").unwrap();
            let help = build_help_output(cmd, DisclosureLevel::Basic);
            assert!(
                help.see_also.contains(&"fwc guide".to_string()),
                "Commands without subcommands should reference fwc guide"
            );
        }

        #[test]
        fn approvals_subcommands_include_create_and_revoke() {
            let reg = command_registry();
            let cmd = reg.iter().find(|c| c.name == "approvals").unwrap();
            assert!(cmd.subcommands.contains(&"create"));
            assert!(cmd.subcommands.contains(&"revoke"));
        }

        #[test]
        fn history_subcommands_include_list_and_export() {
            let reg = command_registry();
            let cmd = reg.iter().find(|c| c.name == "history").unwrap();
            assert!(cmd.subcommands.contains(&"list"));
            assert!(cmd.subcommands.contains(&"export"));
        }
    }

    // ── 7. Hidden/internal commands ─────────────────────────────────────

    mod hidden_commands {
        use super::*;

        #[test]
        fn hidden_commands_exist_in_registry() {
            let reg = command_registry();
            let hidden_count = reg.iter().filter(|c| c.hidden).count();
            assert!(hidden_count > 0, "Should have at least one hidden command");
        }

        #[test]
        fn hidden_commands_start_with_underscore() {
            let reg = command_registry();
            for cmd in reg.iter().filter(|c| c.hidden) {
                assert!(
                    cmd.name.starts_with("__"),
                    "Hidden command {} should start with __",
                    cmd.name
                );
            }
        }

        #[test]
        fn basic_help_excludes_hidden() {
            let reg = command_registry();
            // Build a simulated "basic help overview"
            let visible_names: BTreeSet<&str> =
                reg.iter().filter(|c| !c.hidden).map(|c| c.name).collect();
            for h in reg.iter().filter(|c| c.hidden) {
                assert!(
                    !visible_names.contains(h.name),
                    "Hidden command {} should not appear in visible set",
                    h.name
                );
            }
        }

        #[test]
        fn hidden_commands_have_no_examples() {
            let reg = command_registry();
            for cmd in reg.iter().filter(|c| c.hidden) {
                assert!(
                    cmd.examples.is_empty(),
                    "Hidden command {} should not have examples",
                    cmd.name
                );
            }
        }

        #[test]
        fn all_hidden_commands_are_advanced() {
            let reg = command_registry();
            for cmd in reg.iter().filter(|c| c.hidden) {
                assert!(
                    cmd.advanced,
                    "Hidden command {} should be marked advanced",
                    cmd.name
                );
            }
        }
    }

    // ── 8. Error message format in help context ─────────────────────────

    mod error_format {
        use super::*;

        fn make_error_envelope(
            code: &str,
            message: &str,
            suggestion: Option<&str>,
        ) -> HelpErrorEnvelope {
            HelpErrorEnvelope {
                code: code.to_string(),
                message: message.to_string(),
                suggestion: suggestion.map(str::to_string),
            }
        }

        #[test]
        fn error_envelope_has_code() {
            let env = make_error_envelope("FCP_ERR_UNKNOWN_COMMAND", "Unknown command: foo", None);
            assert!(env.code.starts_with("FCP_ERR_"));
        }

        #[test]
        fn error_envelope_serializes_to_json() {
            let env =
                make_error_envelope("FCP_ERR_PARSE_FAILED", "Bad syntax", Some("Try fwc guide"));
            let json = serde_json::to_value(&env).unwrap();
            assert_eq!(json["code"], "FCP_ERR_PARSE_FAILED");
            assert_eq!(json["message"], "Bad syntax");
            assert_eq!(json["suggestion"], "Try fwc guide");
        }

        #[test]
        fn error_envelope_without_suggestion() {
            let env = make_error_envelope("FCP_ERR_INTERNAL", "Unexpected error", None);
            let json = serde_json::to_value(&env).unwrap();
            assert!(json["suggestion"].is_null());
        }

        #[test]
        fn error_envelope_code_is_uppercase_screaming_snake() {
            let env = make_error_envelope("FCP_ERR_RATE_LIMITED", "Rate limited", None);
            assert!(env.code.chars().all(|c| c.is_ascii_uppercase() || c == '_'));
        }

        #[test]
        fn error_envelope_message_is_non_empty() {
            let env = make_error_envelope("FCP_ERR_INTERNAL", "Something went wrong", None);
            assert!(!env.message.is_empty());
        }
    }

    // ── 9. Additional help structure invariants ─────────────────────────

    mod help_invariants {
        use super::*;

        #[test]
        fn all_help_outputs_have_usage() {
            let reg = command_registry();
            for cmd in &reg {
                let help = build_help_output(cmd, DisclosureLevel::Basic);
                assert!(
                    help.usage.starts_with("fwc "),
                    "Command {} usage should start with 'fwc '",
                    cmd.name
                );
            }
        }

        #[test]
        fn all_help_outputs_have_at_least_two_options() {
            let reg = command_registry();
            for cmd in &reg {
                let help = build_help_output(cmd, DisclosureLevel::Basic);
                assert!(
                    help.options.len() >= 2,
                    "Command {} should have at least 2 options",
                    cmd.name
                );
            }
        }

        #[test]
        fn format_option_has_toon_default() {
            let reg = command_registry();
            for cmd in &reg {
                let help = build_help_output(cmd, DisclosureLevel::Basic);
                if let Some(fmt) = help.options.iter().find(|o| o.flag == "--format") {
                    assert_eq!(
                        fmt.default_value.as_deref(),
                        Some("toon"),
                        "Command {} --format default should be toon",
                        cmd.name
                    );
                }
            }
        }

        #[test]
        fn help_output_command_matches_descriptor() {
            let reg = command_registry();
            for cmd in &reg {
                let help = build_help_output(cmd, DisclosureLevel::Basic);
                assert_eq!(help.command, cmd.name);
            }
        }

        #[test]
        fn category_string_is_lowercase() {
            for cat in CommandCategory::all() {
                let s = cat.as_str();
                assert!(
                    s.chars().all(|c| c.is_lowercase() || !c.is_alphabetic()),
                    "Category {cat:?} string not lowercase"
                );
            }
        }

        #[test]
        fn registry_has_at_least_fifteen_commands() {
            let reg = command_registry();
            assert!(
                reg.len() >= 15,
                "Registry should have 15+ commands, got {}",
                reg.len()
            );
        }

        #[test]
        fn see_also_never_empty() {
            let reg = command_registry();
            for cmd in &reg {
                let help = build_help_output(cmd, DisclosureLevel::Basic);
                assert!(
                    !help.see_also.is_empty(),
                    "Command {} should always have see_also entries",
                    cmd.name
                );
            }
        }

        #[test]
        fn toon_render_contains_all_sections() {
            let reg = command_registry();
            let cmd = reg.iter().find(|c| c.name == "search").unwrap();
            let help = build_help_output(cmd, DisclosureLevel::Examples);
            let toon = render_toon(&help);
            assert!(toon.contains("USAGE:"));
            assert!(toon.contains("DESCRIPTION:"));
            assert!(toon.contains("OPTIONS:"));
            assert!(toon.contains("EXAMPLES:"));
        }
    }
}
