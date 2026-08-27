//! Cross-connector semantic operation search engine.
//!
//! Builds an in-memory search index from connector introspections and scores
//! matches using weighted keyword matching with faceted filtering.

use std::collections::BTreeSet;

use serde::Serialize;
use serde_json::{Value, json};

use crate::{
    readiness::{DiscoveredConnector, DiscoveredOperation},
    recovery::levenshtein,
};

// ── Scoring weights ─────────────────────────────────────────────────────

/// Weight for exact operation ID match.
const WEIGHT_OP_ID_EXACT: i64 = 30;
/// Weight for partial operation ID match.
const WEIGHT_OP_ID_PARTIAL: i64 = 14;
/// Weight for fuzzy operation ID or alias match within a tight edit budget.
const WEIGHT_OP_ID_FUZZY: i64 = 6;
/// Weight for match in `when_to_use` (highest value for agent consumption).
const WEIGHT_WHEN_TO_USE: i64 = 18;
/// Weight for match in operation summary/description.
const WEIGHT_SUMMARY: i64 = 10;
/// Weight for match in capability.
const WEIGHT_CAPABILITY: i64 = 8;
/// Weight for connector slug/name match.
const WEIGHT_CONNECTOR_NAME: i64 = 6;
/// Weight for match in `common_mistakes`.
const WEIGHT_COMMON_MISTAKES: i64 = 4;
/// Weight for match in related operations.
const WEIGHT_RELATED: i64 = 2;

// ── Filters ─────────────────────────────────────────────────────────────

/// Faceted search filters applied before scoring.
#[derive(Debug, Default)]
pub struct SearchFilters {
    /// Restrict to a specific connector slug.
    pub connector: Option<String>,
    /// Filter by capability family prefix (e.g. "write", "read", "admin").
    pub capability: Option<String>,
    /// Maximum risk level to include.
    pub risk_max: Option<RiskCeiling>,
    /// Maximum safety tier to include.
    pub safety_max: Option<SafetyCeiling>,
    /// Filter by connector archetype.
    pub archetype: Option<String>,
    /// Filter by connector category/cohort.
    pub category: Option<String>,
    /// Only include idempotent (safe to retry) operations.
    pub idempotent_only: bool,
    /// Zone filter.
    pub zone: Option<String>,
    /// Include connectors that are hidden from default catalog flows.
    pub include_hidden: bool,
}

impl SearchFilters {
    const fn has_active_filters(&self) -> bool {
        self.connector.is_some()
            || self.capability.is_some()
            || self.risk_max.is_some()
            || self.safety_max.is_some()
            || self.archetype.is_some()
            || self.category.is_some()
            || self.idempotent_only
            || self.zone.is_some()
    }
}

/// Risk level ceiling for filtering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskCeiling {
    Low,
    Medium,
    High,
}

impl RiskCeiling {
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "low" => Some(Self::Low),
            "medium" | "med" => Some(Self::Medium),
            "high" => Some(Self::High),
            _ => None,
        }
    }

    #[must_use]
    pub fn allows(self, level: &str) -> bool {
        match self {
            Self::Low => level == "low",
            Self::Medium => matches!(level, "low" | "medium"),
            Self::High => true,
        }
    }
}

/// Safety tier ceiling for filtering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SafetyCeiling {
    Safe,
    Risky,
    Dangerous,
    Critical,
}

impl SafetyCeiling {
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "safe" => Some(Self::Safe),
            "risky" => Some(Self::Risky),
            "dangerous" => Some(Self::Dangerous),
            "critical" => Some(Self::Critical),
            _ => None,
        }
    }

    fn allows(self, tier: &str) -> bool {
        match self {
            Self::Safe => tier == "safe",
            Self::Risky => matches!(tier, "safe" | "risky"),
            Self::Dangerous => matches!(tier, "safe" | "risky" | "dangerous"),
            Self::Critical => matches!(tier, "safe" | "risky" | "dangerous" | "critical"),
        }
    }
}

// ── Search result ───────────────────────────────────────────────────────

/// A single scored search result at the operation level.
#[derive(Debug, Serialize)]
pub struct SearchResult {
    pub connector_slug: String,
    pub connector_name: String,
    pub connector_status: Option<String>,
    pub hidden_by_default: bool,
    pub non_live_rationale: Option<String>,
    pub graduation_guidance: Option<String>,
    pub operation_id: String,
    pub selector: String,
    pub summary: String,
    pub capability: String,
    pub risk_level: String,
    pub safety_tier: String,
    pub idempotency: String,
    pub score: i64,
    pub match_reasons: Vec<String>,
}

// ── Search engine ───────────────────────────────────────────────────────

/// Execute a cross-connector operation search.
///
/// Returns scored results sorted by relevance (descending), then by operation
/// ID (ascending) for deterministic output.
#[must_use]
pub fn search_operations(
    connectors: &[DiscoveredConnector],
    query: &str,
    filters: &SearchFilters,
) -> Vec<SearchResult> {
    let tokens = tokenize(query);
    let faceted_only = query.trim().is_empty() && filters.has_active_filters();
    let mut results = Vec::new();

    for connector in connectors {
        if !connector_passes_filters(connector, filters) {
            continue;
        }

        let connector_bonus = connector_relevance(connector, &tokens);

        for operation in &connector.operations {
            if !operation_passes_filters(operation, filters) {
                continue;
            }

            let (score, reasons) = score_operation(connector, operation, &tokens);
            let total = score + connector_bonus;

            if total > 0 || faceted_only {
                // Faceted-only search (blank query with active filters) returns
                // all matching operations with base score of 1.
                let final_score = if total > 0 { total } else { 1 };
                results.push(SearchResult {
                    connector_slug: connector.slug.clone(),
                    connector_name: connector.detail.summary.name.clone(),
                    connector_status: connector.manifest_status.map(|status| status.to_string()),
                    hidden_by_default: connector.hidden_by_default,
                    non_live_rationale: connector.non_live_rationale.clone(),
                    graduation_guidance: connector.graduation_guidance.clone(),
                    operation_id: operation.actual_id.clone(),
                    selector: operation.preferred_selector.clone(),
                    summary: operation.summary.summary.clone(),
                    capability: operation.summary.capability.clone(),
                    risk_level: operation.summary.risk_level.clone(),
                    safety_tier: operation.summary.safety_tier.clone(),
                    idempotency: operation.summary.idempotency.clone(),
                    score: final_score,
                    match_reasons: reasons,
                });
            }
        }
    }

    results.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| a.operation_id.cmp(&b.operation_id))
    });

    results
}

/// Convert results to JSON for dispatch.
#[must_use]
pub fn results_to_json(results: &[SearchResult], limit: usize) -> Vec<Value> {
    results
        .iter()
        .take(limit)
        .map(|r| {
            json!({
                "connector": r.connector_slug,
                "connector_name": r.connector_name,
                "connector_status": r.connector_status.clone(),
                "hidden_by_default": r.hidden_by_default,
                "non_live_rationale": r.non_live_rationale.clone(),
                "graduation_guidance": r.graduation_guidance.clone(),
                "operation": r.operation_id,
                "selector": r.selector,
                "summary": r.summary,
                "capability": r.capability,
                "risk_level": r.risk_level,
                "safety_tier": r.safety_tier,
                "idempotency": r.idempotency,
                "score": r.score,
                "match_reasons": r.match_reasons,
            })
        })
        .collect()
}

// ── Internal scoring ────────────────────────────────────────────────────

fn connector_passes_filters(connector: &DiscoveredConnector, filters: &SearchFilters) -> bool {
    if !filters.include_hidden && connector.is_hidden_by_default() {
        return false;
    }
    if let Some(ref slug) = filters.connector {
        let slug_lower = slug.to_lowercase();
        if connector.search_slug_lower != slug_lower
            && !connector
                .detail
                .summary
                .id
                .to_lowercase()
                .ends_with(&slug_lower)
        {
            return false;
        }
    }
    if let Some(ref zone) = filters.zone {
        if !connector.matches_zone(zone) {
            return false;
        }
    }
    if let Some(ref archetype) = filters.archetype {
        let arch_lower = archetype.to_lowercase();
        if !connector
            .detail
            .summary
            .archetypes
            .as_known()
            .into_iter()
            .flatten()
            .any(|a| a.to_lowercase() == arch_lower)
        {
            return false;
        }
    }
    if let Some(ref category) = filters.category {
        if connector.search_cohort_lower != category.to_lowercase() {
            return false;
        }
    }
    true
}

fn operation_passes_filters(operation: &DiscoveredOperation, filters: &SearchFilters) -> bool {
    if let Some(ref cap) = filters.capability {
        let cap_lower = cap.to_lowercase();
        if !operation.search_capability_lower.contains(&cap_lower) {
            return false;
        }
    }
    if let Some(ceiling) = filters.risk_max {
        if !ceiling.allows(&operation.summary.risk_level) {
            return false;
        }
    }
    if let Some(ceiling) = filters.safety_max {
        if !ceiling.allows(&operation.summary.safety_tier) {
            return false;
        }
    }
    !(filters.idempotent_only
        && !matches!(
            operation.summary.idempotency.as_str(),
            "strict" | "best_effort"
        ))
}

fn connector_relevance(connector: &DiscoveredConnector, tokens: &[String]) -> i64 {
    let mut bonus = 0_i64;
    // Use pre-cached lowercase fields (computed once at construction).
    let slug = &connector.search_slug_lower;
    let name = &connector.search_name_lower;

    for token in tokens {
        if slug == token || slug.contains(token.as_str()) {
            bonus += WEIGHT_CONNECTOR_NAME;
        } else if name.contains(token.as_str()) {
            bonus += WEIGHT_CONNECTOR_NAME / 2;
        }
    }
    bonus
}

fn score_operation(
    _connector: &DiscoveredConnector,
    operation: &DiscoveredOperation,
    tokens: &[String],
) -> (i64, Vec<String>) {
    let mut score = 0_i64;
    let mut reasons = BTreeSet::new();

    // Use pre-cached lowercase fields (computed once at construction, not per-search).
    let op_id_lower = &operation.search_actual_id_lower;
    let local_id_lower = &operation.search_local_id_lower;
    let aliases_lower = &operation.search_aliases_lower;
    let summary_lower = &operation.search_summary_lower;
    let when_to_use_lower = &operation.search_when_to_use_lower;
    let capability_lower = &operation.search_capability_lower;

    for token in tokens {
        // Exact operation ID match (highest priority).
        if op_id_lower == token || local_id_lower == token {
            score += WEIGHT_OP_ID_EXACT;
            reasons.insert("exact_id_match".to_owned());
        } else if op_id_lower.contains(token.as_str()) || local_id_lower.contains(token.as_str()) {
            score += WEIGHT_OP_ID_PARTIAL;
            reasons.insert("partial_id_match".to_owned());
        } else if identifier_has_fuzzy_match(op_id_lower, token)
            || identifier_has_fuzzy_match(local_id_lower, token)
        {
            score += WEIGHT_OP_ID_FUZZY;
            reasons.insert("fuzzy_id_match".to_owned());
        }

        // Alias match — single pass with early exit (was 3× sequential scans).
        let mut best_alias_match = None;
        for alias in aliases_lower {
            if alias == token {
                best_alias_match = Some(WEIGHT_OP_ID_EXACT);
                break; // Can't do better than exact
            } else if alias.contains(token.as_str()) {
                if best_alias_match.is_none_or(|b| b < WEIGHT_OP_ID_PARTIAL) {
                    best_alias_match = Some(WEIGHT_OP_ID_PARTIAL);
                }
            } else if best_alias_match.is_none() && identifier_has_fuzzy_match(alias, token) {
                best_alias_match = Some(WEIGHT_OP_ID_FUZZY);
            }
        }
        if let Some(weight) = best_alias_match {
            score += weight;
            let reason = match weight {
                w if w == WEIGHT_OP_ID_EXACT => "alias_match",
                w if w == WEIGHT_OP_ID_PARTIAL => "partial_alias_match",
                _ => "fuzzy_alias_match",
            };
            reasons.insert(reason.to_owned());
        }

        // when_to_use (3x effective — highest value for agent search).
        if when_to_use_lower.contains(token.as_str()) {
            score += WEIGHT_WHEN_TO_USE;
            reasons.insert("when_to_use_match".to_owned());
        }

        // Summary/description.
        if summary_lower.contains(token.as_str()) {
            score += WEIGHT_SUMMARY;
            reasons.insert("summary_match".to_owned());
        }

        // Capability.
        if capability_lower.contains(token.as_str()) {
            score += WEIGHT_CAPABILITY;
            reasons.insert("capability_match".to_owned());
        }

        // Common mistakes (uses pre-cached lowercase).
        if operation
            .search_common_mistakes_lower
            .iter()
            .any(|m| m.contains(token.as_str()))
        {
            score += WEIGHT_COMMON_MISTAKES;
            reasons.insert("common_mistakes_match".to_owned());
        }

        // Related operations (uses pre-cached lowercase).
        if operation
            .search_related_lower
            .iter()
            .any(|r| r.contains(token.as_str()))
        {
            score += WEIGHT_RELATED;
            reasons.insert("related_match".to_owned());
        }
    }

    (score, reasons.into_iter().collect())
}

fn identifier_has_fuzzy_match(identifier: &str, token: &str) -> bool {
    fuzzy_term_matches(identifier, token)
        || identifier
            .split(|ch: char| !ch.is_ascii_alphanumeric())
            .filter(|segment| !segment.is_empty())
            .any(|segment| fuzzy_term_matches(segment, token))
}

fn fuzzy_term_matches(candidate: &str, token: &str) -> bool {
    let max_distance = fuzzy_distance_budget(candidate, token);
    max_distance > 0 && levenshtein(candidate, token) <= max_distance
}

fn fuzzy_distance_budget(candidate: &str, token: &str) -> usize {
    let candidate_len = candidate.chars().count();
    let token_len = token.chars().count();
    if candidate_len == 0 || token_len < 4 {
        return 0;
    }

    let length_gap = candidate_len.abs_diff(token_len);
    if length_gap > 2 {
        return 0;
    }

    if candidate_len >= 8 || token_len >= 8 {
        2
    } else {
        1
    }
}

fn tokenize(query: &str) -> Vec<String> {
    query
        .split(|ch: char| {
            !ch.is_ascii_alphanumeric() && ch != ':' && ch != '.' && ch != '_' && ch != '-'
        })
        .filter(|token| !token.is_empty())
        .map(str::to_lowercase)
        .collect()
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::readiness::{
        ConnectorDetail, ConnectorState, ConnectorSummary, DiscoveredConnector,
        DiscoveredOperation, OperationSummary,
    };

    fn stub_connector(slug: &str, ops: Vec<DiscoveredOperation>) -> DiscoveredConnector {
        let op_summaries: Vec<OperationSummary> = ops.iter().map(|o| o.summary.clone()).collect();
        DiscoveredConnector {
            slug: slug.to_owned(),
            manifest_path: format!("connectors/{slug}/manifest.toml"),
            cohort: "dev-tools".to_owned(),
            manifest_status: Some(fcp_manifest::ConnectorStatus::Ready),
            hidden_by_default: false,
            non_live_rationale: None,
            graduation_guidance: None,
            runtime_format: "wasi".to_owned(),
            state_model: crate::readiness::MetadataField::Unknown,
            supported_zones: vec!["z:work".to_owned()],
            forbidden_zones: vec![],
            detail: ConnectorDetail {
                summary: ConnectorSummary {
                    id: format!("fcp.{slug}"),
                    name: format!("{} Connector", capitalize(slug)),
                    version: "0.1.0".to_owned(),
                    description: format!("FCP connector for {slug}"),
                    archetypes: crate::readiness::MetadataField::Known(vec![
                        "operational".to_owned(),
                    ]),
                    state: ConnectorState::Unknown,
                    operation_count: ops.len(),
                    max_risk: "medium".to_owned(),
                    has_events: crate::readiness::MetadataField::Unknown,
                },
                operations: op_summaries,
                config_schema: crate::readiness::MetadataField::Unknown,
                health: crate::readiness::MetadataField::Unknown,
                rate_limits: crate::readiness::MetadataField::Unknown,
            },
            zones: json!({}),
            capabilities: json!({}),
            connector_schema: json!({}),
            operations: ops,
            search_slug_lower: slug.to_lowercase(),
            search_name_lower: format!("{slug} connector").to_lowercase(),
            search_cohort_lower: "dev-tools".to_owned(),
        }
    }

    fn stub_operation(
        id: &str,
        summary: &str,
        capability: &str,
        risk: &str,
        safety: &str,
        when_to_use: &str,
    ) -> DiscoveredOperation {
        DiscoveredOperation {
            actual_id: id.to_owned(),
            local_id: id.rsplit('.').next().unwrap_or(id).to_owned(),
            preferred_selector: id.rsplit('.').next().unwrap_or(id).to_owned(),
            aliases: vec![],
            description: summary.to_owned(),
            summary: OperationSummary {
                id: id.to_owned(),
                summary: summary.to_owned(),
                capability: capability.to_owned(),
                risk_level: risk.to_owned(),
                safety_tier: safety.to_owned(),
                idempotency: "strict".to_owned(),
                requires_approval: false,
                supports_simulate: crate::readiness::MetadataField::Unknown,
            },
            input_schema: json!({"type": "object"}),
            output_schema: json!({"type": "object"}),
            approval_mode: String::new(),
            when_to_use: when_to_use.to_owned(),
            common_mistakes: vec![],
            examples: vec![],
            related: vec![],
            network_constraints: None,
            rate_limits: None,
            search_actual_id_lower: id.to_lowercase(),
            search_local_id_lower: id.rsplit('.').next().unwrap_or(id).to_lowercase(),
            search_aliases_lower: vec![],
            search_summary_lower: summary.to_lowercase(),
            search_when_to_use_lower: when_to_use.to_lowercase(),
            search_capability_lower: capability.to_lowercase(),
            search_common_mistakes_lower: vec![],
            search_related_lower: vec![],
        }
    }

    fn capitalize(s: &str) -> String {
        let mut chars = s.chars();
        chars.next().map_or_else(String::new, |c| {
            c.to_uppercase().collect::<String>() + chars.as_str()
        })
    }

    fn sample_connectors() -> Vec<DiscoveredConnector> {
        vec![
            stub_connector(
                "github",
                vec![
                    stub_operation(
                        "github.create_issue",
                        "Create a GitHub issue",
                        "github.write",
                        "medium",
                        "risky",
                        "Create an issue in a GitHub repository to track bugs or feature requests.",
                    ),
                    stub_operation(
                        "github.list_issues",
                        "List issues in a repository",
                        "github.read",
                        "low",
                        "safe",
                        "List issues with optional filters for state, labels, and assignee.",
                    ),
                ],
            ),
            stub_connector(
                "slack",
                vec![
                    stub_operation(
                        "slack.send_message",
                        "Send a message to a Slack channel",
                        "slack.write",
                        "medium",
                        "risky",
                        "Send a message to notify your team about deployments, alerts, or updates.",
                    ),
                    stub_operation(
                        "slack.list_channels",
                        "List Slack channels",
                        "slack.read",
                        "low",
                        "safe",
                        "List available channels in the workspace.",
                    ),
                ],
            ),
            stub_connector(
                "notion",
                vec![stub_operation(
                    "notion.create_page",
                    "Create a Notion page",
                    "notion.write",
                    "medium",
                    "risky",
                    "Create a new page in a Notion database or as a child of an existing page.",
                )],
            ),
        ]
    }

    // ── Keyword search tests ────────────────────────────────────────

    #[test]
    fn search_exact_operation_id() {
        let connectors = sample_connectors();
        let results = search_operations(
            &connectors,
            "github.create_issue",
            &SearchFilters::default(),
        );
        assert!(!results.is_empty());
        assert_eq!(results[0].operation_id, "github.create_issue");
        assert!(
            results[0]
                .match_reasons
                .contains(&"exact_id_match".to_owned())
        );
    }

    #[test]
    fn search_keyword_in_when_to_use() {
        let connectors = sample_connectors();
        let results = search_operations(&connectors, "team", &SearchFilters::default());
        assert!(!results.is_empty());
        // slack.send_message has "team" in when_to_use
        assert_eq!(results[0].operation_id, "slack.send_message");
        assert!(
            results[0]
                .match_reasons
                .contains(&"when_to_use_match".to_owned())
        );
    }

    #[test]
    fn search_keyword_in_summary() {
        let connectors = sample_connectors();
        let results = search_operations(&connectors, "channel", &SearchFilters::default());
        assert!(!results.is_empty());
        let has_slack = results
            .iter()
            .any(|r| r.operation_id == "slack.list_channels");
        assert!(has_slack);
    }

    #[test]
    fn search_no_results_for_unknown_term() {
        let connectors = sample_connectors();
        let results = search_operations(&connectors, "xyzzy", &SearchFilters::default());
        assert!(results.is_empty());
    }

    #[test]
    fn search_multiple_keywords() {
        let connectors = sample_connectors();
        let results = search_operations(&connectors, "create issue", &SearchFilters::default());
        assert!(!results.is_empty());
        assert_eq!(results[0].operation_id, "github.create_issue");
    }

    #[test]
    fn search_case_insensitive() {
        let connectors = sample_connectors();
        let results = search_operations(&connectors, "GitHub", &SearchFilters::default());
        assert!(!results.is_empty());
        assert!(results.iter().any(|r| r.connector_slug == "github"));
    }

    #[test]
    fn search_connector_slug_boosts_all_ops() {
        let connectors = sample_connectors();
        let results = search_operations(&connectors, "slack", &SearchFilters::default());
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r.connector_slug == "slack"));
    }

    #[test]
    fn search_excludes_hidden_connectors_by_default() {
        let mut hidden = stub_connector(
            "tlon",
            vec![stub_operation(
                "tlon.dm.send",
                "Send a Tlon DM",
                "tlon.dm",
                "medium",
                "safe",
                "Send a direct message in Tlon",
            )],
        );
        hidden.manifest_status = Some(fcp_manifest::ConnectorStatus::Incubating);
        hidden.hidden_by_default = true;
        hidden.non_live_rationale =
            Some("Runtime path is incomplete or lacks production evidence".to_owned());

        let results = search_operations(&[hidden], "tlon", &SearchFilters::default());
        assert!(results.is_empty());
    }

    #[test]
    fn search_includes_hidden_connectors_when_requested() {
        let mut hidden = stub_connector(
            "tlon",
            vec![stub_operation(
                "tlon.dm.send",
                "Send a Tlon DM",
                "tlon.dm",
                "medium",
                "safe",
                "Send a direct message in Tlon",
            )],
        );
        hidden.manifest_status = Some(fcp_manifest::ConnectorStatus::Incubating);
        hidden.hidden_by_default = true;
        hidden.non_live_rationale =
            Some("Runtime path is incomplete or lacks production evidence".to_owned());
        hidden.graduation_guidance = Some(
            "Complete runtime implementation, add production evidence, pass compliance suite"
                .to_owned(),
        );

        let filters = SearchFilters {
            include_hidden: true,
            ..SearchFilters::default()
        };
        let results = search_operations(&[hidden], "tlon", &filters);

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].connector_status.as_deref(), Some("incubating"));
        assert!(results[0].hidden_by_default);
        assert!(results[0].non_live_rationale.is_some());
        assert!(results[0].graduation_guidance.is_some());
    }

    // ── Faceted filter tests ────────────────────────────────────────

    #[test]
    fn filter_by_connector() {
        let connectors = sample_connectors();
        let filters = SearchFilters {
            connector: Some("github".to_owned()),
            ..Default::default()
        };
        let results = search_operations(&connectors, "create", &filters);
        assert!(!results.is_empty());
        assert!(results.iter().all(|r| r.connector_slug == "github"));
    }

    #[test]
    fn filter_by_capability() {
        let connectors = sample_connectors();
        let filters = SearchFilters {
            capability: Some("read".to_owned()),
            ..Default::default()
        };
        let results = search_operations(&connectors, "list", &filters);
        assert!(!results.is_empty());
        assert!(results.iter().all(|r| r.capability.contains("read")));
    }

    #[test]
    fn filter_by_risk_max_low() {
        let connectors = sample_connectors();
        let filters = SearchFilters {
            risk_max: Some(RiskCeiling::Low),
            ..Default::default()
        };
        let results = search_operations(&connectors, "list", &filters);
        assert!(!results.is_empty());
        assert!(results.iter().all(|r| r.risk_level == "low"));
    }

    #[test]
    fn filter_by_risk_max_medium() {
        let connectors = sample_connectors();
        let filters = SearchFilters {
            risk_max: Some(RiskCeiling::Medium),
            ..Default::default()
        };
        let results = search_operations(&connectors, "create", &filters);
        assert!(!results.is_empty());
        assert!(
            results
                .iter()
                .all(|r| matches!(r.risk_level.as_str(), "low" | "medium"))
        );
    }

    #[test]
    fn filter_by_safety_max_safe() {
        let connectors = sample_connectors();
        let filters = SearchFilters {
            safety_max: Some(SafetyCeiling::Safe),
            ..Default::default()
        };
        let results = search_operations(&connectors, "list", &filters);
        assert!(!results.is_empty());
        assert!(results.iter().all(|r| r.safety_tier == "safe"));
    }

    #[test]
    fn filter_idempotent_only() {
        let connectors = sample_connectors();
        let filters = SearchFilters {
            idempotent_only: true,
            ..Default::default()
        };
        let results = search_operations(&connectors, "list", &filters);
        assert!(!results.is_empty());
        assert!(
            results
                .iter()
                .all(|r| matches!(r.idempotency.as_str(), "strict" | "best_effort"))
        );
    }

    #[test]
    fn faceted_only_search_no_keywords() {
        let connectors = sample_connectors();
        let filters = SearchFilters {
            capability: Some("read".to_owned()),
            ..Default::default()
        };
        // Empty query with filters should return all read operations.
        let results = search_operations(&connectors, "", &filters);
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r.capability.contains("read")));
        assert!(results.iter().all(|r| r.score == 1));
    }

    #[test]
    fn punctuation_only_query_does_not_degenerate_into_filterless_match_all() {
        let connectors = sample_connectors();
        let results = search_operations(&connectors, "!!!", &SearchFilters::default());
        assert!(results.is_empty());
    }

    #[test]
    fn filter_excludes_nonmatching_connectors() {
        let connectors = sample_connectors();
        let filters = SearchFilters {
            connector: Some("notion".to_owned()),
            ..Default::default()
        };
        let results = search_operations(&connectors, "create", &filters);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].connector_slug, "notion");
    }

    // ── Scoring tests ───────────────────────────────────────────────

    #[test]
    fn scoring_exact_id_beats_summary_match() {
        let connectors = sample_connectors();
        let results = search_operations(&connectors, "create_issue", &SearchFilters::default());
        assert!(!results.is_empty());
        assert_eq!(results[0].operation_id, "github.create_issue");
    }

    #[test]
    fn scoring_when_to_use_is_high_weight() {
        let connectors = sample_connectors();
        // "deployments" appears in slack.send_message.when_to_use
        let results = search_operations(&connectors, "deployments", &SearchFilters::default());
        assert!(!results.is_empty());
        assert_eq!(results[0].operation_id, "slack.send_message");
    }

    #[test]
    fn fuzzy_typo_in_operation_id_recovers_result() {
        let connectors = sample_connectors();
        let results = search_operations(&connectors, "send_mesage", &SearchFilters::default());
        assert!(!results.is_empty());
        assert_eq!(results[0].operation_id, "slack.send_message");
        assert!(
            results[0]
                .match_reasons
                .contains(&"fuzzy_id_match".to_owned())
        );
    }

    #[test]
    fn fuzzy_typo_in_identifier_segment_recovers_result() {
        let connectors = sample_connectors();
        let results = search_operations(&connectors, "mesage", &SearchFilters::default());
        assert!(!results.is_empty());
        assert_eq!(results[0].operation_id, "slack.send_message");
        assert!(
            results[0]
                .match_reasons
                .contains(&"fuzzy_id_match".to_owned())
        );
    }

    #[test]
    fn fuzzy_typo_in_alias_recovers_result() {
        let mut connectors = sample_connectors();
        connectors[0].operations[0].aliases = vec!["open_ticket".to_owned()];
        connectors[0].operations[0].search_aliases_lower = vec!["open_ticket".to_owned()];
        let results = search_operations(&connectors, "open_tiket", &SearchFilters::default());
        assert!(!results.is_empty());
        assert_eq!(results[0].operation_id, "github.create_issue");
        assert!(
            results[0]
                .match_reasons
                .contains(&"fuzzy_alias_match".to_owned())
        );
    }

    #[test]
    fn results_sorted_by_score_descending() {
        let connectors = sample_connectors();
        let results = search_operations(&connectors, "create", &SearchFilters::default());
        for window in results.windows(2) {
            assert!(window[0].score >= window[1].score);
        }
    }

    #[test]
    fn deterministic_output_for_same_score() {
        let connectors = sample_connectors();
        let results1 = search_operations(&connectors, "list", &SearchFilters::default());
        let results2 = search_operations(&connectors, "list", &SearchFilters::default());
        assert_eq!(results1.len(), results2.len());
        for (a, b) in results1.iter().zip(results2.iter()) {
            assert_eq!(a.operation_id, b.operation_id);
            assert_eq!(a.score, b.score);
        }
    }

    // ── Tokenization tests ──────────────────────────────────────────

    #[test]
    fn tokenize_simple_words() {
        let tokens = tokenize("send a message");
        assert_eq!(tokens, vec!["send", "a", "message"]);
    }

    #[test]
    fn tokenize_preserves_dots_and_underscores() {
        let tokens = tokenize("github.create_issue");
        assert_eq!(tokens, vec!["github.create_issue"]);
    }

    #[test]
    fn tokenize_lowercases() {
        let tokens = tokenize("GitHub Create");
        assert_eq!(tokens, vec!["github", "create"]);
    }

    #[test]
    fn tokenize_empty_query() {
        let tokens = tokenize("");
        assert!(tokens.is_empty());
    }

    #[test]
    fn tokenize_special_chars_split() {
        let tokens = tokenize("send+message&fast");
        assert_eq!(tokens, vec!["send", "message", "fast"]);
    }

    // ── RiskCeiling tests ───────────────────────────────────────────

    #[test]
    fn risk_ceiling_parse() {
        assert_eq!(RiskCeiling::parse("low"), Some(RiskCeiling::Low));
        assert_eq!(RiskCeiling::parse("MEDIUM"), Some(RiskCeiling::Medium));
        assert_eq!(RiskCeiling::parse("med"), Some(RiskCeiling::Medium));
        assert_eq!(RiskCeiling::parse("high"), Some(RiskCeiling::High));
        assert_eq!(RiskCeiling::parse("extreme"), None);
    }

    #[test]
    fn risk_ceiling_low_allows_only_low() {
        assert!(RiskCeiling::Low.allows("low"));
        assert!(!RiskCeiling::Low.allows("medium"));
        assert!(!RiskCeiling::Low.allows("high"));
    }

    #[test]
    fn risk_ceiling_medium_allows_low_and_medium() {
        assert!(RiskCeiling::Medium.allows("low"));
        assert!(RiskCeiling::Medium.allows("medium"));
        assert!(!RiskCeiling::Medium.allows("high"));
    }

    #[test]
    fn risk_ceiling_high_allows_all() {
        assert!(RiskCeiling::High.allows("low"));
        assert!(RiskCeiling::High.allows("medium"));
        assert!(RiskCeiling::High.allows("high"));
    }

    // ── SafetyCeiling tests ─────────────────────────────────────────

    #[test]
    fn safety_ceiling_parse() {
        assert_eq!(SafetyCeiling::parse("safe"), Some(SafetyCeiling::Safe));
        assert_eq!(SafetyCeiling::parse("RISKY"), Some(SafetyCeiling::Risky));
        assert_eq!(
            SafetyCeiling::parse("dangerous"),
            Some(SafetyCeiling::Dangerous)
        );
        assert_eq!(
            SafetyCeiling::parse("critical"),
            Some(SafetyCeiling::Critical)
        );
        assert_eq!(SafetyCeiling::parse("forbidden"), None);
    }

    #[test]
    fn safety_ceiling_safe_allows_only_safe() {
        assert!(SafetyCeiling::Safe.allows("safe"));
        assert!(!SafetyCeiling::Safe.allows("risky"));
    }

    #[test]
    fn safety_ceiling_risky_allows_safe_and_risky() {
        assert!(SafetyCeiling::Risky.allows("safe"));
        assert!(SafetyCeiling::Risky.allows("risky"));
        assert!(!SafetyCeiling::Risky.allows("dangerous"));
    }

    #[test]
    fn safety_ceiling_dangerous_allows_up_to_dangerous() {
        assert!(SafetyCeiling::Dangerous.allows("safe"));
        assert!(SafetyCeiling::Dangerous.allows("risky"));
        assert!(SafetyCeiling::Dangerous.allows("dangerous"));
        assert!(!SafetyCeiling::Dangerous.allows("critical"));
    }

    // ── results_to_json tests ───────────────────────────────────────

    #[test]
    fn results_to_json_respects_limit() {
        let connectors = sample_connectors();
        let results = search_operations(&connectors, "list", &SearchFilters::default());
        let json = results_to_json(&results, 1);
        assert_eq!(json.len(), 1);
    }

    #[test]
    fn results_to_json_includes_all_fields() {
        let connectors = sample_connectors();
        let results = search_operations(
            &connectors,
            "github.create_issue",
            &SearchFilters::default(),
        );
        let json = results_to_json(&results, 10);
        assert!(!json.is_empty());
        let first = &json[0];
        assert!(first.get("connector").is_some());
        assert!(first.get("operation").is_some());
        assert!(first.get("score").is_some());
        assert!(first.get("match_reasons").is_some());
        assert!(first.get("risk_level").is_some());
        assert!(first.get("safety_tier").is_some());
    }

    // ── Common mistakes / related matching ──────────────────────────

    #[test]
    fn common_mistakes_boost_score() {
        let mut connectors = sample_connectors();
        connectors[0].operations[0].common_mistakes =
            vec!["Forgetting to set labels for triage".to_owned()];
        connectors[0].operations[0].search_common_mistakes_lower =
            vec!["forgetting to set labels for triage".to_owned()];
        let results = search_operations(&connectors, "triage", &SearchFilters::default());
        assert!(!results.is_empty());
        assert!(
            results[0]
                .match_reasons
                .contains(&"common_mistakes_match".to_owned())
        );
    }

    #[test]
    fn related_operations_boost_score() {
        let mut connectors = sample_connectors();
        connectors[0].operations[0].related = vec!["github.list_issues".to_owned()];
        connectors[0].operations[0].search_related_lower = vec!["github.list_issues".to_owned()];
        let results = search_operations(&connectors, "list_issues", &SearchFilters::default());
        // Both the actual list_issues and the related reference should match
        assert!(results.len() >= 2);
    }

    // ── Edge cases ──────────────────────────────────────────────────

    #[test]
    fn empty_connectors_returns_empty() {
        let results = search_operations(&[], "test", &SearchFilters::default());
        assert!(results.is_empty());
    }

    #[test]
    fn connector_with_no_operations() {
        let connectors = vec![stub_connector("empty", vec![])];
        let results = search_operations(&connectors, "test", &SearchFilters::default());
        assert!(results.is_empty());
    }

    #[test]
    fn multiple_filters_combined() {
        let connectors = sample_connectors();
        let filters = SearchFilters {
            capability: Some("read".to_owned()),
            risk_max: Some(RiskCeiling::Low),
            safety_max: Some(SafetyCeiling::Safe),
            idempotent_only: true,
            ..Default::default()
        };
        let results = search_operations(&connectors, "list", &filters);
        assert!(!results.is_empty());
        for r in &results {
            assert!(r.capability.contains("read"));
            assert_eq!(r.risk_level, "low");
            assert_eq!(r.safety_tier, "safe");
        }
    }

    // ── Additional tokenization tests ───────────────────────────────

    #[test]
    fn tokenize_colons_preserved() {
        let tokens = tokenize("scope:read");
        assert_eq!(tokens, vec!["scope:read"]);
    }

    #[test]
    fn tokenize_hyphens_preserved() {
        let tokens = tokenize("list-items");
        assert_eq!(tokens, vec!["list-items"]);
    }

    #[test]
    fn tokenize_mixed_separators() {
        let tokens = tokenize("send a+message&quickly");
        assert_eq!(tokens, vec!["send", "a", "message", "quickly"]);
    }

    #[test]
    fn tokenize_leading_trailing_spaces() {
        let tokens = tokenize("  hello  ");
        assert_eq!(tokens, vec!["hello"]);
    }

    #[test]
    fn tokenize_only_separators() {
        let tokens = tokenize("   + & ");
        assert!(tokens.is_empty());
    }

    #[test]
    fn fuzzy_identifier_match_rejects_short_noise() {
        assert!(!identifier_has_fuzzy_match("send_message", "sg"));
    }

    #[test]
    fn fuzzy_identifier_match_accepts_small_typos() {
        assert!(identifier_has_fuzzy_match("send_message", "send_mesage"));
        assert!(identifier_has_fuzzy_match("send_message", "mesage"));
    }

    #[test]
    fn fuzzy_identifier_match_rejects_distant_terms() {
        assert!(!identifier_has_fuzzy_match("send_message", "calendar"));
    }

    #[test]
    fn tokenize_numbers() {
        let tokens = tokenize("page 42");
        assert_eq!(tokens, vec!["page", "42"]);
    }

    // ── RiskCeiling additional tests ────────────────────────────────

    #[test]
    fn risk_ceiling_parse_case_insensitive() {
        assert_eq!(RiskCeiling::parse("LOW"), Some(RiskCeiling::Low));
        assert_eq!(RiskCeiling::parse("High"), Some(RiskCeiling::High));
        assert_eq!(RiskCeiling::parse("MED"), Some(RiskCeiling::Medium));
    }

    #[test]
    fn risk_ceiling_parse_empty() {
        assert_eq!(RiskCeiling::parse(""), None);
    }

    #[test]
    fn risk_ceiling_allows_unknown_level() {
        assert!(!RiskCeiling::Low.allows("unknown"));
        assert!(!RiskCeiling::Medium.allows("critical"));
        assert!(RiskCeiling::High.allows("high"));
    }

    #[test]
    fn risk_ceiling_clone() {
        let r = RiskCeiling::Low;
        let r2 = r;
        assert_eq!(r, r2);
    }

    // ── SafetyCeiling additional tests ──────────────────────────────

    #[test]
    fn safety_ceiling_parse_case_insensitive() {
        assert_eq!(SafetyCeiling::parse("SAFE"), Some(SafetyCeiling::Safe));
        assert_eq!(
            SafetyCeiling::parse("Critical"),
            Some(SafetyCeiling::Critical)
        );
    }

    #[test]
    fn safety_ceiling_parse_empty() {
        assert_eq!(SafetyCeiling::parse(""), None);
    }

    #[test]
    fn safety_ceiling_critical_allows_all() {
        assert!(SafetyCeiling::Critical.allows("safe"));
        assert!(SafetyCeiling::Critical.allows("risky"));
        assert!(SafetyCeiling::Critical.allows("dangerous"));
        assert!(SafetyCeiling::Critical.allows("critical"));
    }

    #[test]
    fn safety_ceiling_unknown_tier_rejected() {
        assert!(!SafetyCeiling::Critical.allows("unknown"));
        assert!(!SafetyCeiling::Safe.allows("extreme"));
    }

    #[test]
    fn safety_ceiling_clone() {
        let s = SafetyCeiling::Dangerous;
        let s2 = s;
        assert_eq!(s, s2);
    }

    // ── Scoring weight tests ────────────────────────────────────────

    #[test]
    fn alias_exact_match_scores_same_as_id() {
        let mut op = stub_operation(
            "github.create_issue",
            "Create issue",
            "github.write",
            "medium",
            "risky",
            "Track bugs",
        );
        op.aliases = vec!["new_issue".to_owned()];
        op.search_aliases_lower = vec!["new_issue".to_owned()];
        let connectors = vec![stub_connector("github", vec![op])];
        let results = search_operations(&connectors, "new_issue", &SearchFilters::default());
        assert!(!results.is_empty());
        assert!(results[0].match_reasons.contains(&"alias_match".to_owned()));
    }

    #[test]
    fn alias_partial_match_detected() {
        let mut op = stub_operation(
            "github.create_issue",
            "Create issue",
            "github.write",
            "medium",
            "risky",
            "Track bugs",
        );
        op.aliases = vec!["new_github_issue".to_owned()];
        op.search_aliases_lower = vec!["new_github_issue".to_owned()];
        let connectors = vec![stub_connector("github", vec![op])];
        let results = search_operations(&connectors, "github_issue", &SearchFilters::default());
        assert!(!results.is_empty());
        assert!(
            results[0]
                .match_reasons
                .contains(&"partial_alias_match".to_owned())
        );
    }

    #[test]
    fn capability_match_boosts_score() {
        let connectors = sample_connectors();
        let results = search_operations(&connectors, "write", &SearchFilters::default());
        assert!(!results.is_empty());
        assert!(
            results[0]
                .match_reasons
                .contains(&"capability_match".to_owned())
        );
    }

    #[test]
    fn partial_id_match_detected() {
        let connectors = sample_connectors();
        let results = search_operations(&connectors, "issue", &SearchFilters::default());
        assert!(!results.is_empty());
        let has_partial = results
            .iter()
            .any(|r| r.match_reasons.contains(&"partial_id_match".to_owned()));
        assert!(has_partial);
    }

    // ── Filter combination tests ────────────────────────────────────

    #[test]
    fn filter_connector_and_capability() {
        let connectors = sample_connectors();
        let filters = SearchFilters {
            connector: Some("github".to_owned()),
            capability: Some("read".to_owned()),
            ..Default::default()
        };
        let results = search_operations(&connectors, "list", &filters);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].operation_id, "github.list_issues");
    }

    #[test]
    fn filter_connector_and_risk_max() {
        let connectors = sample_connectors();
        let filters = SearchFilters {
            connector: Some("github".to_owned()),
            risk_max: Some(RiskCeiling::Low),
            ..Default::default()
        };
        let results = search_operations(&connectors, "github", &filters);
        assert!(results.iter().all(|r| r.risk_level == "low"));
    }

    #[test]
    fn filter_safety_and_idempotent() {
        let connectors = sample_connectors();
        let filters = SearchFilters {
            safety_max: Some(SafetyCeiling::Safe),
            idempotent_only: true,
            ..Default::default()
        };
        let results = search_operations(&connectors, "list", &filters);
        assert!(!results.is_empty());
        for r in &results {
            assert_eq!(r.safety_tier, "safe");
            assert!(matches!(r.idempotency.as_str(), "strict" | "best_effort"));
        }
    }

    // ── Idempotent filter tests ─────────────────────────────────────

    #[test]
    fn idempotent_filter_accepts_best_effort() {
        let mut op = stub_operation("test.op", "Test op", "test.read", "low", "safe", "Testing");
        op.summary.idempotency = "best_effort".to_owned();
        let connectors = vec![stub_connector("test", vec![op])];
        let filters = SearchFilters {
            idempotent_only: true,
            ..Default::default()
        };
        let results = search_operations(&connectors, "test", &filters);
        assert!(!results.is_empty());
    }

    #[test]
    fn idempotent_filter_rejects_none() {
        let mut op = stub_operation(
            "test.op",
            "Test op",
            "test.write",
            "medium",
            "risky",
            "Testing",
        );
        op.summary.idempotency = "none".to_owned();
        let connectors = vec![stub_connector("test", vec![op])];
        let filters = SearchFilters {
            idempotent_only: true,
            ..Default::default()
        };
        let results = search_operations(&connectors, "test", &filters);
        assert!(results.is_empty());
    }

    // ── results_to_json additional tests ────────────────────────────

    #[test]
    fn results_to_json_empty() {
        let json = results_to_json(&[], 10);
        assert!(json.is_empty());
    }

    #[test]
    fn results_to_json_limit_larger_than_results() {
        let connectors = sample_connectors();
        let results = search_operations(
            &connectors,
            "github.create_issue",
            &SearchFilters::default(),
        );
        let json = results_to_json(&results, 100);
        assert_eq!(json.len(), results.len());
    }

    #[test]
    fn results_to_json_limit_zero() {
        let connectors = sample_connectors();
        let results = search_operations(&connectors, "list", &SearchFilters::default());
        let json = results_to_json(&results, 0);
        assert!(json.is_empty());
    }

    #[test]
    fn results_to_json_field_values_correct() {
        let connectors = sample_connectors();
        let results = search_operations(
            &connectors,
            "github.create_issue",
            &SearchFilters::default(),
        );
        let json = results_to_json(&results, 10);
        assert!(!json.is_empty());
        let first = &json[0];
        assert_eq!(first["connector"], "github");
        assert_eq!(first["operation"], "github.create_issue");
        assert_eq!(first["risk_level"], "medium");
        assert_eq!(first["safety_tier"], "risky");
        assert!(first["score"].as_i64().unwrap() > 0);
    }

    // ── Connector relevance tests ───────────────────────────────────

    #[test]
    fn connector_name_boosts_results() {
        let connectors = sample_connectors();
        // "notion" matches connector slug
        let results = search_operations(&connectors, "notion create", &SearchFilters::default());
        assert!(!results.is_empty());
        assert_eq!(results[0].connector_slug, "notion");
    }

    #[test]
    fn connector_slug_exact_match_boosts() {
        let connectors = sample_connectors();
        let results = search_operations(&connectors, "github", &SearchFilters::default());
        // Both github ops should appear
        assert_eq!(
            results
                .iter()
                .filter(|r| r.connector_slug == "github")
                .count(),
            2
        );
    }

    // ── Zone filter test ────────────────────────────────────────────

    #[test]
    fn filter_by_zone_matching() {
        let connectors = sample_connectors();
        let filters = SearchFilters {
            zone: Some("z:work".to_owned()),
            ..Default::default()
        };
        let results = search_operations(&connectors, "list", &filters);
        assert!(!results.is_empty());
    }

    #[test]
    fn filter_by_zone_nonmatching() {
        let connectors = sample_connectors();
        let filters = SearchFilters {
            zone: Some("z:personal".to_owned()),
            ..Default::default()
        };
        let results = search_operations(&connectors, "list", &filters);
        assert!(results.is_empty());
    }

    // ── Archetype filter test ───────────────────────────────────────

    #[test]
    fn filter_by_archetype_matching() {
        let connectors = sample_connectors();
        let filters = SearchFilters {
            archetype: Some("operational".to_owned()),
            ..Default::default()
        };
        let results = search_operations(&connectors, "list", &filters);
        assert!(!results.is_empty());
    }

    #[test]
    fn filter_by_archetype_nonmatching() {
        let connectors = sample_connectors();
        let filters = SearchFilters {
            archetype: Some("analytics".to_owned()),
            ..Default::default()
        };
        let results = search_operations(&connectors, "list", &filters);
        assert!(results.is_empty());
    }

    // ── Category filter test ────────────────────────────────────────

    #[test]
    fn filter_by_category_matching() {
        let connectors = sample_connectors();
        let filters = SearchFilters {
            category: Some("dev-tools".to_owned()),
            ..Default::default()
        };
        let results = search_operations(&connectors, "create", &filters);
        assert!(!results.is_empty());
    }

    #[test]
    fn filter_by_category_nonmatching() {
        let connectors = sample_connectors();
        let filters = SearchFilters {
            category: Some("finance".to_owned()),
            ..Default::default()
        };
        let results = search_operations(&connectors, "create", &filters);
        assert!(results.is_empty());
    }

    // ── SearchResult field tests ────────────────────────────────────

    #[test]
    fn search_result_includes_selector() {
        let connectors = sample_connectors();
        let results = search_operations(
            &connectors,
            "github.create_issue",
            &SearchFilters::default(),
        );
        assert!(!results.is_empty());
        assert_eq!(results[0].selector, "create_issue");
    }

    #[test]
    fn search_result_includes_connector_name() {
        let connectors = sample_connectors();
        let results = search_operations(
            &connectors,
            "github.create_issue",
            &SearchFilters::default(),
        );
        assert!(!results.is_empty());
        assert_eq!(results[0].connector_name, "Github Connector");
    }

    #[test]
    fn search_result_includes_idempotency() {
        let connectors = sample_connectors();
        let results = search_operations(
            &connectors,
            "github.create_issue",
            &SearchFilters::default(),
        );
        assert!(!results.is_empty());
        assert_eq!(results[0].idempotency, "strict");
    }

    // ── Multi-connector same query ──────────────────────────────────

    #[test]
    fn search_across_all_connectors_for_create() {
        let connectors = sample_connectors();
        let results = search_operations(&connectors, "create", &SearchFilters::default());
        // github.create_issue, notion.create_page
        let ops: Vec<&str> = results.iter().map(|r| r.operation_id.as_str()).collect();
        assert!(ops.contains(&"github.create_issue"));
        assert!(ops.contains(&"notion.create_page"));
    }

    #[test]
    fn search_returns_all_matching_connectors() {
        let connectors = sample_connectors();
        let results = search_operations(&connectors, "list", &SearchFilters::default());
        let slugs: std::collections::BTreeSet<&str> =
            results.iter().map(|r| r.connector_slug.as_str()).collect();
        assert!(slugs.contains("github"));
        assert!(slugs.contains("slack"));
    }

    // ── Score ordering edge cases ───────────────────────────────────

    #[test]
    fn tied_scores_sorted_by_operation_id() {
        let op1 = stub_operation("b.op", "test", "b.read", "low", "safe", "test");
        let op2 = stub_operation("a.op", "test", "a.read", "low", "safe", "test");
        let connectors = vec![
            stub_connector("b", vec![op1]),
            stub_connector("a", vec![op2]),
        ];
        let results = search_operations(&connectors, "test", &SearchFilters::default());
        assert!(results.len() >= 2);
        // For equal scores, a.op should come before b.op
        let a_idx = results.iter().position(|r| r.operation_id == "a.op");
        let b_idx = results.iter().position(|r| r.operation_id == "b.op");
        if let (Some(a), Some(b)) = (a_idx, b_idx) {
            if results[a].score == results[b].score {
                assert!(a < b);
            }
        }
    }

    // ── Fuzzy distance budget tests ────────────────────────────────

    #[test]
    fn fuzzy_budget_zero_for_empty_candidate() {
        assert_eq!(fuzzy_distance_budget("", "abcd"), 0);
    }

    #[test]
    fn fuzzy_budget_zero_for_short_token() {
        assert_eq!(fuzzy_distance_budget("send", "abc"), 0);
        assert_eq!(fuzzy_distance_budget("send", "ab"), 0);
        assert_eq!(fuzzy_distance_budget("send", "a"), 0);
    }

    #[test]
    fn fuzzy_budget_zero_for_large_length_gap() {
        // candidate=4, token=8 => gap=4 > 2
        assert_eq!(fuzzy_distance_budget("send", "messages"), 0);
    }

    #[test]
    fn fuzzy_budget_one_for_short_pair() {
        // candidate=4, token=4 => gap=0, both < 8
        assert_eq!(fuzzy_distance_budget("send", "sned"), 1);
    }

    #[test]
    fn fuzzy_budget_two_for_long_pair() {
        // candidate=12, token=11 => gap=1, both >= 8
        assert_eq!(fuzzy_distance_budget("send_message", "send_mesage"), 2);
    }

    #[test]
    fn fuzzy_budget_two_when_candidate_long_token_at_boundary() {
        // candidate=8, token=7 => gap=1, candidate >= 8
        assert_eq!(fuzzy_distance_budget("messages", "mesages"), 2);
    }

    #[test]
    fn fuzzy_budget_one_when_both_under_eight() {
        // candidate=5, token=5 => gap=0, both < 8
        assert_eq!(fuzzy_distance_budget("hello", "hallo"), 1);
    }

    #[test]
    fn fuzzy_budget_zero_gap_exactly_three() {
        // candidate=7, token=4 => gap=3 > 2
        assert_eq!(fuzzy_distance_budget("message", "mesg"), 0);
    }

    #[test]
    fn fuzzy_budget_nonzero_gap_exactly_two() {
        // candidate=6, token=4 => gap=2, both < 8
        assert_eq!(fuzzy_distance_budget("create", "cret"), 1);
    }

    // ── fuzzy_term_matches tests ───────────────────────────────────

    #[test]
    fn fuzzy_term_matches_identical_strings() {
        // distance=0, budget=1 for len-4 tokens, 1 > 0 && 0 <= 1 => true
        assert!(fuzzy_term_matches("send", "send"));
    }

    #[test]
    fn fuzzy_term_matches_one_typo() {
        assert!(fuzzy_term_matches("send_message", "send_mesage"));
    }

    #[test]
    fn fuzzy_term_rejects_many_typos() {
        assert!(!fuzzy_term_matches("send", "xxxx"));
    }

    #[test]
    fn fuzzy_term_rejects_short_token() {
        assert!(!fuzzy_term_matches("hello", "hel"));
    }

    // ── identifier_has_fuzzy_match segment splitting ───────────────

    #[test]
    fn fuzzy_id_match_via_segment_split() {
        // "send_message" splits on '_' into ["send", "message"]
        // "mesage" (6 chars) vs "message" (7 chars) => gap=1, both < 8 => budget=1
        // levenshtein("message","mesage")=1 => 1 <= 1 => true
        assert!(identifier_has_fuzzy_match("send_message", "mesage"));
    }

    #[test]
    fn fuzzy_id_match_whole_identifier() {
        // "send_mesage" (11 chars) vs whole "send_message" (12 chars) => gap=1, both >= 8 => budget=2
        // levenshtein=1 => match
        assert!(identifier_has_fuzzy_match("send_message", "send_mesage"));
    }

    #[test]
    fn fuzzy_id_no_match_on_completely_different() {
        assert!(!identifier_has_fuzzy_match("send_message", "calendar"));
    }

    #[test]
    fn fuzzy_id_segments_skip_empty() {
        // "a..b" has empty segment between dots
        assert!(!identifier_has_fuzzy_match("a..b", "xxxx"));
    }

    // ── Tokenization edge cases ────────────────────────────────────

    #[test]
    fn tokenize_unicode_chars_are_separators() {
        let tokens = tokenize("hello\u{00e9}world");
        // e-acute is not ascii alphanumeric, not :._- so it splits
        assert_eq!(tokens, vec!["hello", "world"]);
    }

    #[test]
    fn tokenize_tabs_and_newlines() {
        let tokens = tokenize("hello\tworld\nfoo");
        assert_eq!(tokens, vec!["hello", "world", "foo"]);
    }

    #[test]
    fn tokenize_dot_colon_underscore_hyphen_all_preserved() {
        let tokens = tokenize("a.b:c_d-e");
        assert_eq!(tokens, vec!["a.b:c_d-e"]);
    }

    #[test]
    fn tokenize_repeated_separators() {
        let tokens = tokenize("a    b");
        assert_eq!(tokens, vec!["a", "b"]);
    }

    #[test]
    fn tokenize_single_char() {
        let tokens = tokenize("x");
        assert_eq!(tokens, vec!["x"]);
    }

    #[test]
    fn tokenize_only_numbers() {
        let tokens = tokenize("123 456");
        assert_eq!(tokens, vec!["123", "456"]);
    }

    #[test]
    fn tokenize_alphanumeric_mix() {
        let tokens = tokenize("v2 api3");
        assert_eq!(tokens, vec!["v2", "api3"]);
    }

    // ── RiskCeiling exhaustive ─────────────────────────────────────

    #[test]
    fn risk_ceiling_high_allows_everything() {
        // High.allows() returns true unconditionally
        assert!(RiskCeiling::High.allows("high"));
        assert!(RiskCeiling::High.allows("low"));
        assert!(RiskCeiling::High.allows("extreme"));
        assert!(RiskCeiling::High.allows(""));
    }

    #[test]
    fn risk_ceiling_medium_rejects_unknown_string() {
        assert!(!RiskCeiling::Medium.allows("none"));
        assert!(!RiskCeiling::Medium.allows(""));
    }

    #[test]
    fn risk_ceiling_low_rejects_empty() {
        assert!(!RiskCeiling::Low.allows(""));
    }

    #[test]
    fn risk_ceiling_debug_format() {
        let r = RiskCeiling::Medium;
        let dbg = format!("{r:?}");
        assert!(dbg.contains("Medium"));
    }

    // ── SafetyCeiling exhaustive ───────────────────────────────────

    #[test]
    fn safety_ceiling_dangerous_rejects_unknown() {
        assert!(!SafetyCeiling::Dangerous.allows("lethal"));
        assert!(!SafetyCeiling::Dangerous.allows(""));
    }

    #[test]
    fn safety_ceiling_risky_rejects_dangerous() {
        assert!(!SafetyCeiling::Risky.allows("dangerous"));
        assert!(!SafetyCeiling::Risky.allows("critical"));
    }

    #[test]
    fn safety_ceiling_safe_rejects_all_above() {
        assert!(!SafetyCeiling::Safe.allows("risky"));
        assert!(!SafetyCeiling::Safe.allows("dangerous"));
        assert!(!SafetyCeiling::Safe.allows("critical"));
    }

    #[test]
    fn safety_ceiling_debug_format() {
        let s = SafetyCeiling::Critical;
        let dbg = format!("{s:?}");
        assert!(dbg.contains("Critical"));
    }

    #[test]
    fn safety_ceiling_parse_mixed_case() {
        assert_eq!(
            SafetyCeiling::parse("DaNgErOuS"),
            Some(SafetyCeiling::Dangerous)
        );
        assert_eq!(SafetyCeiling::parse("rIsKy"), Some(SafetyCeiling::Risky));
    }

    #[test]
    fn risk_ceiling_parse_mixed_case() {
        assert_eq!(RiskCeiling::parse("MeDiUm"), Some(RiskCeiling::Medium));
        assert_eq!(RiskCeiling::parse("hIgH"), Some(RiskCeiling::High));
    }

    // ── Connector filter edge cases ────────────────────────────────

    #[test]
    fn connector_filter_matches_by_id_suffix() {
        let connectors = sample_connectors();
        // filter by "github" should match connector whose id is "fcp.github"
        let filters = SearchFilters {
            connector: Some("github".to_owned()),
            ..Default::default()
        };
        let result = connector_passes_filters(&connectors[0], &filters);
        assert!(result);
    }

    #[test]
    fn connector_filter_case_insensitive() {
        let connectors = sample_connectors();
        let filters = SearchFilters {
            connector: Some("GITHUB".to_owned()),
            ..Default::default()
        };
        let result = connector_passes_filters(&connectors[0], &filters);
        assert!(result);
    }

    #[test]
    fn connector_filter_rejects_partial_slug() {
        let connectors = sample_connectors();
        let filters = SearchFilters {
            connector: Some("git".to_owned()),
            ..Default::default()
        };
        // slug "github" != "git" and id "fcp.github" doesn't end_with "git"
        let result = connector_passes_filters(&connectors[0], &filters);
        assert!(!result);
    }

    #[test]
    fn connector_filter_no_archetype_on_unknown() {
        let mut connector = stub_connector("test", vec![]);
        connector.detail.summary.archetypes = crate::readiness::MetadataField::Unknown;
        let filters = SearchFilters {
            archetype: Some("operational".to_owned()),
            ..Default::default()
        };
        assert!(!connector_passes_filters(&connector, &filters));
    }

    #[test]
    fn connector_filter_category_case_insensitive() {
        let connectors = sample_connectors();
        let filters = SearchFilters {
            category: Some("DEV-TOOLS".to_owned()),
            ..Default::default()
        };
        assert!(connector_passes_filters(&connectors[0], &filters));
    }

    // ── Operation filter edge cases ────────────────────────────────

    #[test]
    fn operation_filter_capability_case_insensitive() {
        let op = stub_operation("test.op", "Test", "github.WRITE", "low", "safe", "test");
        let filters = SearchFilters {
            capability: Some("write".to_owned()),
            ..Default::default()
        };
        assert!(operation_passes_filters(&op, &filters));
    }

    #[test]
    fn operation_filter_no_filters_passes_all() {
        let op = stub_operation("test.op", "Test", "test.read", "high", "critical", "test");
        assert!(operation_passes_filters(&op, &SearchFilters::default()));
    }

    #[test]
    fn operation_filter_idempotent_rejects_unknown_string() {
        let mut op = stub_operation("t.op", "T", "t.w", "low", "safe", "t");
        op.summary.idempotency = "unknown".to_owned();
        let filters = SearchFilters {
            idempotent_only: true,
            ..Default::default()
        };
        assert!(!operation_passes_filters(&op, &filters));
    }

    // ── Connector relevance scoring ────────────────────────────────

    #[test]
    fn connector_relevance_slug_exact_match() {
        let connector = stub_connector("github", vec![]);
        let tokens = vec!["github".to_owned()];
        let bonus = connector_relevance(&connector, &tokens);
        assert_eq!(bonus, WEIGHT_CONNECTOR_NAME);
    }

    #[test]
    fn connector_relevance_slug_contains() {
        let connector = stub_connector("github", vec![]);
        let tokens = vec!["git".to_owned()];
        let bonus = connector_relevance(&connector, &tokens);
        assert_eq!(bonus, WEIGHT_CONNECTOR_NAME);
    }

    #[test]
    fn connector_relevance_name_contains() {
        let connector = stub_connector("github", vec![]);
        // name is "Github Connector"
        let tokens = vec!["connector".to_owned()];
        let bonus = connector_relevance(&connector, &tokens);
        assert_eq!(bonus, WEIGHT_CONNECTOR_NAME / 2);
    }

    #[test]
    fn connector_relevance_no_match() {
        let connector = stub_connector("github", vec![]);
        let tokens = vec!["zzzzz".to_owned()];
        let bonus = connector_relevance(&connector, &tokens);
        assert_eq!(bonus, 0);
    }

    #[test]
    fn connector_relevance_multiple_tokens_accumulate() {
        let connector = stub_connector("github", vec![]);
        // "github" matches slug, "connector" matches name
        let tokens = vec!["github".to_owned(), "connector".to_owned()];
        let bonus = connector_relevance(&connector, &tokens);
        assert_eq!(bonus, WEIGHT_CONNECTOR_NAME + WEIGHT_CONNECTOR_NAME / 2);
    }

    #[test]
    fn connector_relevance_empty_tokens() {
        let connector = stub_connector("github", vec![]);
        let bonus = connector_relevance(&connector, &[]);
        assert_eq!(bonus, 0);
    }

    // ── Score operation detailed tests ─────────────────────────────

    #[test]
    fn score_operation_exact_local_id_match() {
        let op = stub_operation(
            "github.create_issue",
            "Create issue",
            "github.write",
            "medium",
            "risky",
            "Track bugs",
        );
        let connector = stub_connector("github", vec![op.clone()]);
        let tokens = vec!["create_issue".to_owned()];
        let (score, reasons) = score_operation(&connector, &op, &tokens);
        assert!(score >= WEIGHT_OP_ID_EXACT);
        assert!(reasons.contains(&"exact_id_match".to_owned()));
    }

    #[test]
    fn score_operation_when_to_use_match() {
        let op = stub_operation(
            "slack.send",
            "Send msg",
            "slack.write",
            "medium",
            "risky",
            "Notify team about deployments",
        );
        let connector = stub_connector("slack", vec![op.clone()]);
        let tokens = vec!["deployments".to_owned()];
        let (score, reasons) = score_operation(&connector, &op, &tokens);
        assert!(score >= WEIGHT_WHEN_TO_USE);
        assert!(reasons.contains(&"when_to_use_match".to_owned()));
    }

    #[test]
    fn score_operation_summary_match() {
        let op = stub_operation(
            "test.op",
            "Create a new repository",
            "test.write",
            "medium",
            "risky",
            "Use for repos",
        );
        let connector = stub_connector("test", vec![op.clone()]);
        let tokens = vec!["repository".to_owned()];
        let (score, reasons) = score_operation(&connector, &op, &tokens);
        assert!(score >= WEIGHT_SUMMARY);
        assert!(reasons.contains(&"summary_match".to_owned()));
    }

    #[test]
    fn score_operation_capability_match() {
        let op = stub_operation(
            "test.op",
            "Test",
            "admin.write",
            "high",
            "dangerous",
            "Use for admin",
        );
        let connector = stub_connector("test", vec![op.clone()]);
        let tokens = vec!["admin".to_owned()];
        let (score, reasons) = score_operation(&connector, &op, &tokens);
        assert!(score >= WEIGHT_CAPABILITY);
        assert!(reasons.contains(&"capability_match".to_owned()));
    }

    #[test]
    fn score_operation_common_mistakes_match() {
        let mut op = stub_operation("t.op", "T", "t.w", "low", "safe", "T");
        op.common_mistakes = vec!["Remember to set the timeout".to_owned()];
        op.search_common_mistakes_lower = vec!["remember to set the timeout".to_owned()];
        let connector = stub_connector("t", vec![op.clone()]);
        let tokens = vec!["timeout".to_owned()];
        let (score, reasons) = score_operation(&connector, &op, &tokens);
        assert!(score >= WEIGHT_COMMON_MISTAKES);
        assert!(reasons.contains(&"common_mistakes_match".to_owned()));
    }

    #[test]
    fn score_operation_related_match() {
        let mut op = stub_operation("t.op", "T", "t.w", "low", "safe", "T");
        op.related = vec!["t.other_op".to_owned()];
        op.search_related_lower = vec!["t.other_op".to_owned()];
        let connector = stub_connector("t", vec![op.clone()]);
        let tokens = vec!["other_op".to_owned()];
        let (score, reasons) = score_operation(&connector, &op, &tokens);
        assert!(score >= WEIGHT_RELATED);
        assert!(reasons.contains(&"related_match".to_owned()));
    }

    #[test]
    fn score_operation_no_match_returns_zero() {
        let op = stub_operation("t.op", "T", "t.w", "low", "safe", "T");
        let connector = stub_connector("t", vec![op.clone()]);
        let tokens = vec!["xyzzy12345".to_owned()];
        let (score, reasons) = score_operation(&connector, &op, &tokens);
        assert_eq!(score, 0);
        assert!(reasons.is_empty());
    }

    #[test]
    fn score_operation_empty_tokens_returns_zero() {
        let op = stub_operation("t.op", "T", "t.w", "low", "safe", "T");
        let connector = stub_connector("t", vec![op.clone()]);
        let (score, reasons) = score_operation(&connector, &op, &[]);
        assert_eq!(score, 0);
        assert!(reasons.is_empty());
    }

    #[test]
    fn score_operation_multiple_tokens_accumulate() {
        let op = stub_operation(
            "github.create_issue",
            "Create an issue for tracking bugs",
            "github.write",
            "medium",
            "risky",
            "Track bugs in repositories",
        );
        let connector = stub_connector("github", vec![op.clone()]);
        // "create" hits partial_id, summary, when_to_use(no); "bugs" hits summary, when_to_use
        let tokens = vec!["create".to_owned(), "bugs".to_owned()];
        let (score, _reasons) = score_operation(&connector, &op, &tokens);
        // Should be well above any single-match weight
        assert!(score > WEIGHT_OP_ID_PARTIAL);
    }

    // ── Search with aliases ────────────────────────────────────────

    #[test]
    fn alias_exact_match_gives_high_score() {
        let mut op = stub_operation("t.op", "T", "t.w", "low", "safe", "T");
        op.aliases = vec!["quick_lookup".to_owned()];
        op.search_aliases_lower = vec!["quick_lookup".to_owned()];
        let connectors = vec![stub_connector("t", vec![op])];
        let results = search_operations(&connectors, "quick_lookup", &SearchFilters::default());
        assert!(!results.is_empty());
        assert!(results[0].score >= WEIGHT_OP_ID_EXACT);
    }

    #[test]
    fn alias_partial_match_gives_partial_score() {
        let mut op = stub_operation("t.op", "T", "t.w", "low", "safe", "T");
        op.aliases = vec!["quick_lookup_all".to_owned()];
        op.search_aliases_lower = vec!["quick_lookup_all".to_owned()];
        let connectors = vec![stub_connector("t", vec![op])];
        let results = search_operations(&connectors, "lookup", &SearchFilters::default());
        assert!(!results.is_empty());
        assert!(
            results[0]
                .match_reasons
                .contains(&"partial_alias_match".to_owned())
        );
    }

    #[test]
    fn alias_fuzzy_match_on_typo() {
        let mut op = stub_operation("t.op", "T", "t.w", "low", "safe", "T");
        op.aliases = vec!["quick_lookup".to_owned()];
        op.search_aliases_lower = vec!["quick_lookup".to_owned()];
        let connectors = vec![stub_connector("t", vec![op])];
        let results = search_operations(&connectors, "quick_lokup", &SearchFilters::default());
        assert!(!results.is_empty());
        assert!(
            results[0]
                .match_reasons
                .contains(&"fuzzy_alias_match".to_owned())
        );
    }

    // ── Multiple connectors with mixed ops ─────────────────────────

    #[test]
    fn search_high_risk_ops_excluded_by_low_ceiling() {
        let op_low = stub_operation("a.op", "A", "a.r", "low", "safe", "A");
        let op_high = stub_operation("b.op", "B", "b.r", "high", "dangerous", "B");
        let connectors = vec![
            stub_connector("a", vec![op_low]),
            stub_connector("b", vec![op_high]),
        ];
        let filters = SearchFilters {
            risk_max: Some(RiskCeiling::Low),
            ..Default::default()
        };
        // "op" is partial match for both
        let results = search_operations(&connectors, "op", &filters);
        assert!(results.iter().all(|r| r.risk_level == "low"));
    }

    #[test]
    fn search_dangerous_ops_excluded_by_risky_safety() {
        let op_safe = stub_operation("a.op", "A", "a.r", "low", "safe", "A");
        let op_danger = stub_operation("b.op", "B", "b.r", "high", "dangerous", "B");
        let connectors = vec![
            stub_connector("a", vec![op_safe]),
            stub_connector("b", vec![op_danger]),
        ];
        let filters = SearchFilters {
            safety_max: Some(SafetyCeiling::Risky),
            ..Default::default()
        };
        let results = search_operations(&connectors, "op", &filters);
        assert!(
            results
                .iter()
                .all(|r| matches!(r.safety_tier.as_str(), "safe" | "risky"))
        );
    }

    // ── results_to_json detailed field tests ───────────────────────

    #[test]
    fn results_to_json_connector_name_present() {
        let connectors = sample_connectors();
        let results = search_operations(
            &connectors,
            "github.create_issue",
            &SearchFilters::default(),
        );
        let json = results_to_json(&results, 10);
        assert!(!json.is_empty());
        assert_eq!(json[0]["connector_name"], "Github Connector");
    }

    #[test]
    fn results_to_json_selector_present() {
        let connectors = sample_connectors();
        let results = search_operations(
            &connectors,
            "github.create_issue",
            &SearchFilters::default(),
        );
        let json = results_to_json(&results, 10);
        assert!(!json.is_empty());
        assert_eq!(json[0]["selector"], "create_issue");
    }

    #[test]
    fn results_to_json_summary_present() {
        let connectors = sample_connectors();
        let results = search_operations(
            &connectors,
            "github.create_issue",
            &SearchFilters::default(),
        );
        let json = results_to_json(&results, 10);
        assert!(!json.is_empty());
        assert_eq!(json[0]["summary"], "Create a GitHub issue");
    }

    #[test]
    fn results_to_json_capability_present() {
        let connectors = sample_connectors();
        let results = search_operations(
            &connectors,
            "github.create_issue",
            &SearchFilters::default(),
        );
        let json = results_to_json(&results, 10);
        assert!(!json.is_empty());
        assert_eq!(json[0]["capability"], "github.write");
    }

    #[test]
    fn results_to_json_idempotency_present() {
        let connectors = sample_connectors();
        let results = search_operations(
            &connectors,
            "github.create_issue",
            &SearchFilters::default(),
        );
        let json = results_to_json(&results, 10);
        assert!(!json.is_empty());
        assert_eq!(json[0]["idempotency"], "strict");
    }

    #[test]
    fn results_to_json_match_reasons_is_array() {
        let connectors = sample_connectors();
        let results = search_operations(
            &connectors,
            "github.create_issue",
            &SearchFilters::default(),
        );
        let json = results_to_json(&results, 10);
        assert!(!json.is_empty());
        assert!(json[0]["match_reasons"].is_array());
    }

    // ── SearchFilters default ──────────────────────────────────────

    #[test]
    fn search_filters_default_has_no_constraints() {
        let f = SearchFilters::default();
        assert!(f.connector.is_none());
        assert!(f.capability.is_none());
        assert!(f.risk_max.is_none());
        assert!(f.safety_max.is_none());
        assert!(f.archetype.is_none());
        assert!(f.category.is_none());
        assert!(!f.idempotent_only);
        assert!(f.zone.is_none());
        assert!(!f.include_hidden);
    }

    #[test]
    fn search_filters_debug_format() {
        let f = SearchFilters {
            connector: Some("test".to_owned()),
            ..Default::default()
        };
        let dbg = format!("{f:?}");
        assert!(dbg.contains("test"));
    }

    // ── SearchResult serialize ──────────────────────────────────────

    #[test]
    fn search_result_serializes_to_json() {
        let connectors = sample_connectors();
        let results = search_operations(
            &connectors,
            "github.create_issue",
            &SearchFilters::default(),
        );
        assert!(!results.is_empty());
        let json_str = serde_json::to_string(&results[0]).unwrap();
        assert!(json_str.contains("github.create_issue"));
        assert!(json_str.contains("connector_status"));
        assert!(json_str.contains("score"));
    }

    #[test]
    fn search_result_debug_format() {
        let connectors = sample_connectors();
        let results = search_operations(
            &connectors,
            "github.create_issue",
            &SearchFilters::default(),
        );
        assert!(!results.is_empty());
        let dbg = format!("{:?}", results[0]);
        assert!(dbg.contains("github.create_issue"));
    }

    // ── Multi-token scoring interactions ───────────────────────────

    #[test]
    fn multi_token_all_miss_returns_empty() {
        let connectors = sample_connectors();
        let results = search_operations(&connectors, "xyzzy foobar", &SearchFilters::default());
        assert!(results.is_empty());
    }

    #[test]
    fn multi_token_one_hit_returns_results() {
        let connectors = sample_connectors();
        // "create" hits, "xyzzy" misses
        let results = search_operations(&connectors, "create xyzzy", &SearchFilters::default());
        assert!(!results.is_empty());
    }

    #[test]
    fn multi_token_both_hit_boosts_score() {
        let connectors = sample_connectors();
        let single = search_operations(&connectors, "create", &SearchFilters::default());
        let double = search_operations(&connectors, "create issue", &SearchFilters::default());
        // The top result for "create issue" should have higher score than "create" alone
        assert!(!single.is_empty());
        assert!(!double.is_empty());
        assert!(double[0].score >= single[0].score);
    }

    // ── Edge: connector with empty slug ────────────────────────────

    #[test]
    fn empty_slug_connector_still_searchable() {
        let op = stub_operation("x.op", "Some op", "x.read", "low", "safe", "useful");
        let connectors = vec![stub_connector("", vec![op])];
        let results = search_operations(&connectors, "useful", &SearchFilters::default());
        assert!(!results.is_empty());
    }

    // ── Edge: very long query ──────────────────────────────────────

    #[test]
    fn long_query_does_not_panic() {
        let connectors = sample_connectors();
        let long_query = "a ".repeat(500);
        let results = search_operations(&connectors, &long_query, &SearchFilters::default());
        // May or may not find results, just must not panic
        let _ = results;
    }

    // ── Edge: query with only preserved chars ──────────────────────

    #[test]
    fn query_only_dots_and_colons() {
        let tokens = tokenize(".:_-");
        // These chars are preserved, so the whole thing is one token
        assert_eq!(tokens, vec![".:_-"]);
    }

    // ── Idempotency values ─────────────────────────────────────────

    #[test]
    fn idempotent_filter_accepts_strict() {
        let op = stub_operation("t.op", "T", "t.r", "low", "safe", "T");
        // default idempotency is "strict" from stub_operation
        let filters = SearchFilters {
            idempotent_only: true,
            ..Default::default()
        };
        assert!(operation_passes_filters(&op, &filters));
    }

    // ── Combined filter + keyword search ───────────────────────────

    #[test]
    fn filter_connector_nonexistent_returns_empty() {
        let connectors = sample_connectors();
        let filters = SearchFilters {
            connector: Some("nonexistent".to_owned()),
            ..Default::default()
        };
        let results = search_operations(&connectors, "create", &filters);
        assert!(results.is_empty());
    }

    #[test]
    fn filter_archetype_case_insensitive() {
        let connectors = sample_connectors();
        let filters = SearchFilters {
            archetype: Some("OPERATIONAL".to_owned()),
            ..Default::default()
        };
        let results = search_operations(&connectors, "list", &filters);
        assert!(!results.is_empty());
    }

    #[test]
    fn filter_zone_case_sensitive() {
        let connectors = sample_connectors();
        // zones are exact match, "Z:WORK" != "z:work"
        let filters = SearchFilters {
            zone: Some("Z:WORK".to_owned()),
            ..Default::default()
        };
        let results = search_operations(&connectors, "list", &filters);
        assert!(results.is_empty());
    }

    // ── Scoring weight ordering invariants ─────────────────────────

    #[test]
    fn exact_id_weight_is_highest() {
        let weights = [
            WEIGHT_OP_ID_EXACT,
            WEIGHT_WHEN_TO_USE,
            WEIGHT_OP_ID_PARTIAL,
            WEIGHT_SUMMARY,
            WEIGHT_CAPABILITY,
            WEIGHT_CONNECTOR_NAME,
            WEIGHT_COMMON_MISTAKES,
            WEIGHT_RELATED,
        ];
        assert!(weights.windows(2).all(|pair| pair[0] > pair[1]));
    }

    #[test]
    fn all_weights_are_positive() {
        let weights = [
            WEIGHT_OP_ID_EXACT,
            WEIGHT_OP_ID_PARTIAL,
            WEIGHT_OP_ID_FUZZY,
            WEIGHT_WHEN_TO_USE,
            WEIGHT_SUMMARY,
            WEIGHT_CAPABILITY,
            WEIGHT_CONNECTOR_NAME,
            WEIGHT_COMMON_MISTAKES,
            WEIGHT_RELATED,
        ];
        assert!(weights.into_iter().all(|weight| weight > 0));
    }

    // ── stub_operation field mapping ───────────────────────────────

    #[test]
    fn stub_operation_local_id_is_last_segment() {
        let op = stub_operation("github.create_issue", "S", "C", "low", "safe", "W");
        assert_eq!(op.local_id, "create_issue");
    }

    #[test]
    fn stub_operation_no_dot_uses_full_id() {
        let op = stub_operation("noop", "S", "C", "low", "safe", "W");
        assert_eq!(op.local_id, "noop");
        assert_eq!(op.preferred_selector, "noop");
    }

    #[test]
    fn stub_connector_operation_count_matches() {
        let op1 = stub_operation("a.op1", "S1", "C1", "low", "safe", "W1");
        let op2 = stub_operation("a.op2", "S2", "C2", "low", "safe", "W2");
        let connector = stub_connector("a", vec![op1, op2]);
        assert_eq!(connector.detail.summary.operation_count, 2);
        assert_eq!(connector.detail.operations.len(), 2);
    }

    // ── Capitalize helper ──────────────────────────────────────────

    #[test]
    fn capitalize_empty_string() {
        assert_eq!(capitalize(""), "");
    }

    #[test]
    fn capitalize_single_char() {
        assert_eq!(capitalize("a"), "A");
    }

    #[test]
    fn capitalize_already_upper() {
        assert_eq!(capitalize("Hello"), "Hello");
    }

    #[test]
    fn capitalize_preserves_rest() {
        assert_eq!(capitalize("github"), "Github");
    }
}
