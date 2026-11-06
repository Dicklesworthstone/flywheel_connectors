//! Live host bridge for reactive rules. Credentials and target identities are
//! frozen for the whole batch; the host independently enforces the tier ceiling.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use anyhow::{Context, Result, ensure};
use fcp_core::SafetyTier;
use serde_json::json;

use crate::reactive_rules::Rule;
use crate::rules_cmd::{
    self, ExecutionScope, InvocationResult, RuleExecutor, RulesArgs, RulesRunOptions,
};
use crate::{
    CliExitCode, CommandAvailability, CommandEnvelope, DispatchOutcome, HostAdminClient,
    InvokeArgs, InvokeRequest, KnowledgeState, LiveAuthArgs, ResolvedHostConfig, ResolvedLiveAuth,
    inject_truth_source_metadata, invoke_dispatch_host_controlled, normalize_host_endpoint,
    resolve_host_config, resolve_host_tool, resolve_live_auth, resolved_zone,
};

pub(crate) fn dispatch(args: &RulesArgs, explicit_host: Option<&str>) -> Result<DispatchOutcome> {
    let live = args.run_options().is_some_and(|options| !options.dry_run);
    let result = if let Some(options) = args.run_options().filter(|options| !options.dry_run) {
        (|| {
            let host = resolve_host_config(explicit_host)?
                .context("live rules require a configured host or --host")?;
            let mut executor = HostRuleExecutor::new(host, options)?;
            rules_cmd::run(args, &mut executor)
        })()
    } else {
        rules_cmd::dispatch(args)
    };
    let (mut payload, exit_code, availability, truth) = match result {
        Ok(output) => {
            let uncertain = live && has_uncertain_results(&output.payload);
            (
                output.payload,
                if output.rejected {
                    if live {
                        CliExitCode::Connector
                    } else {
                        CliExitCode::Validation
                    }
                } else {
                    CliExitCode::Success
                },
                if uncertain {
                    CommandAvailability::Unknown
                } else if live {
                    CommandAvailability::LiveRuntime
                } else {
                    CommandAvailability::OfflineArtifact
                },
                if uncertain {
                    None
                } else {
                    Some(if live {
                        KnowledgeState::HostBacked
                    } else {
                        KnowledgeState::Offline
                    })
                },
            )
        }
        Err(error) => (
            json!({"status": "error", "command": "rules",
                "error": {"type": "rules-request-failed", "message": error.to_string()}}),
            CliExitCode::Validation,
            if live {
                CommandAvailability::Unavailable
            } else {
                CommandAvailability::OfflineArtifact
            },
            if live {
                None
            } else {
                Some(KnowledgeState::Offline)
            },
        ),
    };
    CommandEnvelope::new(availability, "rules").inject_into(&mut payload);
    if let Some(truth) = truth {
        inject_truth_source_metadata(&mut payload, truth);
    } else {
        payload["_truth_source"] = json!("unavailable");
    }
    Ok(DispatchOutcome { payload, exit_code })
}

fn has_uncertain_results(payload: &serde_json::Value) -> bool {
    payload["data"]["results"]
        .as_array()
        .is_some_and(|results| {
            results.iter().any(|result| {
                result["outcome"] == "outcome_unknown"
                    || result["previous_outcome"] == "pending"
                    || result["previous_outcome"] == "unknown"
                    || result["state_persisted"] == false
            })
        })
}

struct PreparedRule {
    scope: ExecutionScope,
    auth: ResolvedLiveAuth,
}

struct HostRuleExecutor {
    host: ResolvedHostConfig,
    client: HostAdminClient,
    options: RulesRunOptions,
    prepared: BTreeMap<String, PreparedRule>,
}

impl HostRuleExecutor {
    fn new(mut host: ResolvedHostConfig, options: &RulesRunOptions) -> Result<Self> {
        host.endpoint = canonical_host(&host.endpoint)?;
        let client = HostAdminClient::new(&host.endpoint)?;
        Ok(Self {
            host,
            client,
            options: options.clone(),
            prepared: BTreeMap::new(),
        })
    }
}

fn canonical_host(endpoint: &str) -> Result<String> {
    let normalized = normalize_host_endpoint(endpoint)?;
    #[cfg(unix)]
    if normalized.starts_with("unix://") || normalized.starts_with('/') {
        let path = normalized.strip_prefix("unix://").unwrap_or(&normalized);
        let path = std::fs::canonicalize(path).context("cannot resolve the host socket path")?;
        let path = path.to_str().context("host socket path must be UTF-8")?;
        return Ok(format!("unix://{path}"));
    }
    let url = url::Url::parse(&normalized)?;
    Ok(url.as_str().trim_end_matches('/').to_owned())
}

fn credential_bindings(
    values: &[String],
    flag: &str,
    names: &BTreeSet<&str>,
) -> Result<BTreeMap<String, String>> {
    let mut bindings = BTreeMap::new();
    for raw in values {
        let (name, value) = raw
            .split_once('=')
            .with_context(|| format!("{flag} requires RULE=VALUE"))?;
        let name = name.trim();
        // Never echo unknown keys: a bare base64 credential can contain '='.
        ensure!(
            names.contains(name),
            "{flag} names an unknown or disabled rule"
        );
        ensure!(!value.trim().is_empty(), "{flag} has an empty value");
        ensure!(
            bindings.insert(name.to_owned(), value.to_owned()).is_none(),
            "{flag} repeats a rule"
        );
    }
    Ok(bindings)
}

const fn tier_rank(tier: SafetyTier) -> u8 {
    match tier {
        SafetyTier::Safe => 0,
        SafetyTier::Risky => 1,
        SafetyTier::Dangerous => 2,
        SafetyTier::Critical => 3,
        SafetyTier::Forbidden => 4,
    }
}

fn require_tier(actual: SafetyTier, ceiling: SafetyTier) -> Result<()> {
    ensure!(
        ceiling != SafetyTier::Forbidden
            && actual != SafetyTier::Forbidden
            && tier_rank(actual) <= tier_rank(ceiling),
        "live operation exceeds the registered rule safety ceiling"
    );
    Ok(())
}

impl RuleExecutor for HostRuleExecutor {
    fn prepare(&mut self, rules: &[Rule]) -> Result<BTreeMap<String, ExecutionScope>> {
        ensure!(
            self.prepared.is_empty(),
            "rule authority has already been prepared"
        );
        let names = rules.iter().map(|rule| rule.name.as_str()).collect();
        let inline = credential_bindings(
            &self.options.rule_capability_token,
            "--rule-capability-token",
            &names,
        )?;
        let files = credential_bindings(
            &self.options.rule_capability_token_file,
            "--rule-capability-token-file",
            &names,
        )?;
        let keys = credential_bindings(
            &self.options.rule_holder_key_file,
            "--rule-holder-key-file",
            &names,
        )?;
        for name in inline.keys() {
            ensure!(
                !files.contains_key(name),
                "a rule has both inline and file capability tokens"
            );
        }
        for name in keys.keys() {
            ensure!(
                inline.contains_key(name) || files.contains_key(name),
                "a rule holder key requires that rule's explicit capability token"
            );
        }
        let client = &self.client;
        let (catalog, _) = client.catalog(None)?;
        let zone = resolved_zone(self.options.zone.as_deref(), &self.host);
        let zone = zone
            .parse::<fcp_core::ZoneId>()
            .context("invalid reactive execution zone")?
            .to_string();
        let mut targets = BTreeMap::new();
        let mut default_connectors = BTreeSet::new();
        for rule in rules {
            let connector = catalog
                .resolve_connector(&rule.action.connector)
                .map_err(|_| {
                    anyhow::anyhow!("reactive connector selector did not resolve uniquely")
                })?;
            let introspection = client.introspect(connector.summary.id.as_str())?;
            let operation = resolve_host_tool(&introspection.tools, &rule.action.operation)
                .map_err(|_| {
                    anyhow::anyhow!("reactive operation selector did not resolve uniquely")
                })?;
            require_tier(operation.safety_tier, rule.safety_tier)?;
            let connector_id = connector.summary.id.to_string();
            let operation_id = operation.name.clone();
            // Reject invalid canonical identifiers before any rule can execute.
            connector_id.parse::<fcp_core::ConnectorId>()?;
            operation_id.parse::<fcp_core::OperationId>()?;
            if !inline.contains_key(&rule.name) && !files.contains_key(&rule.name) {
                default_connectors.insert(connector_id.clone());
            }
            targets.insert(rule.name.clone(), (connector_id, operation_id));
        }
        ensure!(
            default_connectors.len() <= 1,
            "default credentials may cover only one connector; assign --rule-capability-token-file RULE=PATH to separately authorized rules"
        );
        let default_args = LiveAuthArgs {
            capability_token: self.options.capability_token.clone(),
            capability_token_file: self.options.capability_token_file.clone(),
            holder_key_file: self.options.holder_key_file.clone(),
            approval_token: self.options.approval_token.clone(),
            approval_token_file: self.options.approval_token_file.clone(),
        };
        let default_requested = default_args.capability_token.is_some()
            || default_args.capability_token_file.is_some()
            || default_args.holder_key_file.is_some();
        let default_auth = if default_requested || !default_connectors.is_empty() {
            Some(
                resolve_live_auth(&default_args)
                    .map_err(|error| anyhow::anyhow!(error.message()))?,
            )
        } else {
            None
        };
        let mut prepared = BTreeMap::new();
        let mut scopes = BTreeMap::new();
        for rule in rules {
            let auth = if inline.contains_key(&rule.name) || files.contains_key(&rule.name) {
                let args = LiveAuthArgs {
                    capability_token: inline.get(&rule.name).cloned(),
                    capability_token_file: files.get(&rule.name).map(PathBuf::from),
                    // Different capabilities never inherit the default holder key.
                    holder_key_file: keys.get(&rule.name).map(PathBuf::from),
                    approval_token: default_args.approval_token.clone(),
                    approval_token_file: default_args.approval_token_file.clone(),
                };
                resolve_live_auth(&args).map_err(|error| anyhow::anyhow!(error.message()))?
            } else {
                default_auth
                    .clone()
                    .context("rule is missing a capability token")?
            };
            if let Some(principal) = &self.options.principal {
                ensure!(
                    auth.principal_hint.as_deref() == Some(principal.as_str()),
                    "reactive principal must match the capability's principal"
                );
            }
            let (connector, operation) = targets
                .remove(&rule.name)
                .context("rule has no resolved target")?;
            let scope = ExecutionScope {
                host: self.host.endpoint.clone(),
                zone: zone.clone(),
                principal: self
                    .options
                    .principal
                    .clone()
                    .or_else(|| auth.principal_hint.clone()),
                connector,
                operation,
            };
            scopes.insert(rule.name.clone(), scope.clone());
            prepared.insert(rule.name.clone(), PreparedRule { scope, auth });
        }
        self.prepared = prepared;
        Ok(scopes)
    }

    fn invoke(
        &mut self,
        rule: &Rule,
        inputs: &BTreeMap<String, String>,
        idempotency_key: &str,
        admit: &mut dyn FnMut(&str, &str) -> Result<()>,
    ) -> Result<InvocationResult> {
        let prepared = self
            .prepared
            .get(&rule.name)
            .context("rule authority was not prepared")?;
        let args = InvokeArgs {
            connector: prepared.scope.connector.clone(),
            operation: prepared.scope.operation.clone(),
            input: Some(serde_json::to_string(inputs)?),
            file: None,
            stdin: false,
            set: Vec::new(),
            zone: Some(prepared.scope.zone.clone()),
            principal: prepared.scope.principal.clone(),
            idempotency_key: Some(idempotency_key.to_owned()),
            lease_seq: self.options.lease_seq,
            deadline_ms: self.options.deadline_ms,
            auth: LiveAuthArgs::default(),
        };
        let mut guard = InvocationGuard {
            auth: &prepared.auth,
            client: &self.client,
            scope: &prepared.scope,
            max_safety_tier: rule.safety_tier,
            admit,
        };
        let outcome = invoke_dispatch_host_controlled(
            "invoke",
            &args,
            &self.host,
            None,
            None,
            Some(&mut guard),
        )?;
        Ok(InvocationResult {
            success: outcome.exit_code == CliExitCode::Success,
            payload: outcome.payload,
        })
    }
}

/// Only the live rules bridge constructs this guard. It ties the ordinary invoke
/// path to frozen authority and a durable reservation immediately before I/O.
pub(crate) struct InvocationGuard<'a> {
    pub(crate) auth: &'a ResolvedLiveAuth,
    pub(crate) client: &'a HostAdminClient,
    scope: &'a ExecutionScope,
    pub(crate) max_safety_tier: SafetyTier,
    admit: &'a mut dyn FnMut(&str, &str) -> Result<()>,
}

impl InvocationGuard<'_> {
    pub(crate) fn validate_target(
        &self,
        host: &str,
        connector: &str,
        operation: &str,
        zone: &str,
        principal: Option<&str>,
        safety: SafetyTier,
    ) -> Result<()> {
        ensure!(
            self.scope.host == host
                && self.scope.connector == connector
                && self.scope.operation == operation
                && self.scope.zone == zone
                && self.scope.principal.as_deref() == principal,
            "live invocation no longer matches the prepared rule scope"
        );
        require_tier(safety, self.max_safety_tier)
    }

    pub(crate) fn reserve(&mut self, request: &InvokeRequest) -> Result<()> {
        ensure!(
            request.connector_id.as_str() == self.scope.connector
                && request.operation.as_str() == self.scope.operation
                && request.zone_id.as_str() == self.scope.zone,
            "prepared rule request changed before reservation"
        );
        let key = request
            .idempotency_key
            .as_deref()
            .context("reactive invoke requires an idempotency key")?;
        (self.admit)(&request.id.to_string(), key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_unknown_results_never_claim_confirmed_live_execution() {
        for result in [
            json!({"outcome": "outcome_unknown"}),
            json!({"outcome": "duplicate", "previous_outcome": "pending"}),
            json!({"outcome": "duplicate", "previous_outcome": "unknown"}),
            json!({"outcome": "executed", "state_persisted": false}),
        ] {
            assert!(has_uncertain_results(&json!({"data": {"results": [
                {"outcome": "executed", "state_persisted": true}, result
            ]}})));
        }
        assert!(!has_uncertain_results(&json!({"data": {"results": [
            {"outcome": "executed", "state_persisted": true},
            {"outcome": "duplicate", "previous_outcome": "completed"}
        ]}})));
    }

    #[test]
    fn credential_bindings_reject_unknown_keys_without_exposing_tokens() {
        let names = BTreeSet::from(["known"]);
        let secret = "not-a-rule-secret==";
        let error = credential_bindings(&[secret.to_owned()], "--rule-capability-token", &names)
            .unwrap_err();
        assert!(!error.to_string().contains(secret));
        assert!(
            credential_bindings(&["known=one".into(), "known=two".into()], "flag", &names).is_err()
        );
        assert!(credential_bindings(&["known=".into()], "flag", &names).is_err());
        assert_eq!(
            credential_bindings(&["known=abc==".into()], "flag", &names).unwrap()["known"],
            "abc=="
        );
    }

    #[test]
    fn live_tiers_cannot_exceed_registration_or_admit_forbidden() {
        let tiers = [
            SafetyTier::Safe,
            SafetyTier::Risky,
            SafetyTier::Dangerous,
            SafetyTier::Critical,
            SafetyTier::Forbidden,
        ];
        for (actual_index, actual) in tiers.iter().enumerate() {
            for (ceiling_index, ceiling) in tiers.iter().enumerate() {
                assert_eq!(
                    require_tier(*actual, *ceiling).is_ok(),
                    actual_index < 4 && ceiling_index < 4 && actual_index <= ceiling_index
                );
            }
        }
    }

    #[test]
    fn equivalent_http_endpoints_share_replay_scope() {
        assert_eq!(
            canonical_host("http://LOCALHOST:80/").unwrap(),
            canonical_host("localhost").unwrap()
        );
        assert!(canonical_host("https://user:secret@example.com").is_err());
        assert!(canonical_host("https://example.com?token=secret").is_err());
        assert_ne!(
            canonical_host("https://example.com/a").unwrap(),
            canonical_host("https://example.com/b").unwrap()
        );
    }
}
