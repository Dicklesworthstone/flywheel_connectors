//! Deterministic indexer from repo proof artifacts into a [`ProofGraph`].
//!
//! The first indexer pass consumes structured, redaction-safe summaries of
//! repository artifacts. Markdown, Beads JSONL, shell scripts, and replay
//! bundles should be parsed by callers into this corpus before indexing; raw
//! provider transcripts and private logs are intentionally not accepted here.

#![allow(clippy::module_name_repetitions)]

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::agent_readiness::{
    AgentReadinessError, AgentReadinessReport, ReadinessAction, ReadinessOperatingMode,
    ReadinessStatus,
};
use crate::proof_graph::{
    BeadOwner, ClaimId, ClaimNode, ClaimStatus, EvidenceId, EvidenceKind, EvidenceNode,
    FreshnessWindow, ProofGap, ProofGapId, ProofGapStatus, ProofGraph, ProofGraphError,
    RedactionClass, RerunCommand, RerunCommandId, SuggestedActionId, SuggestedNextAction,
    SupportEdge, SupportRelationship, TruthSource,
};

/// Stable schema for the structured corpus accepted by the `ProofGraph` indexer.
pub const PROOF_GRAPH_INDEXER_CORPUS_SCHEMA: &str = "fcp.proof-graph-indexer-corpus.v1";

const DEFAULT_FRESHNESS_MS: u64 = 7 * 24 * 60 * 60 * 1_000;
const DEFAULT_STALE_BEAD_MS: u64 = 14 * 24 * 60 * 60 * 1_000;
const MAX_ID_TAIL_CHARS: usize = 120;

/// Redaction-safe input corpus for building a [`ProofGraph`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofGraphCorpus {
    /// Schema identifier; must be [`PROOF_GRAPH_INDEXER_CORPUS_SCHEMA`].
    #[serde(default = "default_indexer_corpus_schema")]
    pub schema: String,
    /// Rows from the README feature-status ledger.
    #[serde(default)]
    pub readme_rows: Vec<ReadmeFeatureRow>,
    /// Beads issue excerpts with acceptance and proof comments.
    #[serde(default)]
    pub bead_issues: Vec<BeadIssueRecord>,
    /// E2E or verification scripts that can regenerate evidence.
    #[serde(default)]
    pub verification_scripts: Vec<VerificationScriptRecord>,
    /// Existing fwc/readiness matrix rows.
    #[serde(default)]
    pub readiness_rows: Vec<ReadinessMatrixRow>,
    /// Evidence bundle metadata summaries.
    #[serde(default)]
    pub evidence_bundles: Vec<EvidenceBundleRecord>,
    /// Agent startup/readiness handoff reports.
    #[serde(default)]
    pub agent_readiness_reports: Vec<AgentReadinessProofRecord>,
}

impl Default for ProofGraphCorpus {
    fn default() -> Self {
        Self {
            schema: default_indexer_corpus_schema(),
            readme_rows: Vec::new(),
            bead_issues: Vec::new(),
            verification_scripts: Vec::new(),
            readiness_rows: Vec::new(),
            evidence_bundles: Vec::new(),
            agent_readiness_reports: Vec::new(),
        }
    }
}

fn default_indexer_corpus_schema() -> String {
    PROOF_GRAPH_INDEXER_CORPUS_SCHEMA.to_owned()
}

/// Source location preserved on indexed evidence nodes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SourceLocation {
    /// Stable source id such as `readme.feature-status` or `beads.issue`.
    pub source_id: String,
    /// Repository-relative path to the artifact.
    pub path: String,
    /// Optional one-based line number.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
}

impl SourceLocation {
    /// Return a compact redaction-safe reference for graph nodes.
    #[must_use]
    pub fn source_ref(&self) -> String {
        self.line
            .map_or_else(|| self.path.clone(), |line| format!("{}:{line}", self.path))
    }
}

/// README feature-status row, already parsed from the Markdown table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadmeFeatureRow {
    /// Stable claim key shared with related Beads or evidence.
    pub claim_key: String,
    /// Feature name.
    pub feature: String,
    /// README status label such as `PROVEN`, `IMPLEMENTED`, or `PLANNED`.
    pub status: String,
    /// Redaction-safe summary of the feature promise.
    pub summary: String,
    /// Evidence cell from the README table, with raw endpoints or secrets removed.
    pub evidence_summary: String,
    /// Source location of the row.
    pub source: SourceLocation,
}

/// Beads issue excerpt used as an operator-record source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BeadIssueRecord {
    /// Bead id.
    pub id: String,
    /// Shared claim key.
    pub claim_key: String,
    /// Bead title.
    pub title: String,
    /// Bead status from Beads.
    pub status: String,
    /// Bead priority.
    pub priority: u8,
    /// Redaction-safe acceptance summary.
    pub acceptance_summary: String,
    /// Labels from Beads.
    #[serde(default)]
    pub labels: BTreeSet<String>,
    /// Optional current assignee.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assignee: Option<String>,
    /// Last update time as Unix milliseconds; callers own date parsing.
    pub updated_at_unix_ms: u64,
    /// Source location for the issue record.
    pub source: SourceLocation,
    /// Proof comments or closeout comments linked to the bead.
    #[serde(default)]
    pub proof_comments: Vec<BeadProofComment>,
}

/// Redaction-safe Beads comment excerpt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BeadProofComment {
    /// Beads comment id.
    pub id: u64,
    /// Comment author.
    pub author: String,
    /// Redaction-safe summary or excerpt.
    pub summary: String,
    /// Comment creation time as Unix milliseconds.
    pub created_at_unix_ms: u64,
    /// Optional rerun command explicitly cited by the comment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rerun_argv: Option<Vec<String>>,
    /// Optional artifact path explicitly cited by the comment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_path: Option<String>,
    /// Source location for the comment.
    pub source: SourceLocation,
}

/// Verification script that can regenerate claim evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationScriptRecord {
    /// Shared claim key.
    pub claim_key: String,
    /// Repository-relative script path.
    pub script_path: String,
    /// Redaction-safe script purpose.
    pub purpose: String,
    /// Preferred rerun argv.
    pub rerun_argv: Vec<String>,
    /// Environment keys required for live lanes; values are never stored.
    #[serde(default)]
    pub required_env_keys: BTreeSet<String>,
    /// Source location for the script registration.
    pub source: SourceLocation,
}

/// fwc/readiness row already parsed from a structured matrix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadinessMatrixRow {
    /// Shared claim key.
    pub claim_key: String,
    /// Subject being evaluated.
    pub subject: String,
    /// Redaction-safe state label such as `pass`, `fail`, `blocked`, or `skip`.
    pub state: String,
    /// Truth source behind the readiness row.
    pub truth_source: TruthSource,
    /// Optional rerun argv.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rerun_argv: Option<Vec<String>>,
    /// Source location for the row.
    pub source: SourceLocation,
}

/// Evidence bundle metadata summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceBundleRecord {
    /// Shared claim key.
    pub claim_key: String,
    /// Stable scenario identifier.
    pub scenario_id: String,
    /// Redaction-safe bundle path or artifact id.
    pub bundle_path: String,
    /// Whether the bundle has already passed redaction checks.
    pub redaction_safe: bool,
    /// Number of command records.
    pub command_count: usize,
    /// Number of live evidence records.
    pub live_count: usize,
    /// Number of offline evidence records.
    pub offline_count: usize,
    /// Optional validation command argv.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validation_argv: Option<Vec<String>>,
    /// Source location for the bundle metadata.
    pub source: SourceLocation,
}

/// Agent readiness report already produced by the operator handoff surface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentReadinessProofRecord {
    /// Shared claim key for the readiness decision.
    pub claim_key: String,
    /// Redaction-safe report body.
    pub report: AgentReadinessReport,
    /// Redaction-safe path or artifact id for `report.json`.
    pub report_path: String,
    /// Optional redaction-safe path or artifact id for `events.jsonl`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub events_path: Option<String>,
    /// Optional redaction-safe path or artifact id for `handoff.json`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handoff_path: Option<String>,
    /// Optional command that replays or regenerates the readiness report.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rerun_argv: Option<Vec<String>>,
    /// Source location for the report registration.
    pub source: SourceLocation,
}

/// Deterministic `ProofGraph` indexer configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProofGraphIndexer {
    /// Evaluation time as Unix milliseconds.
    pub now_unix_ms: u64,
    /// Default freshness window assigned to indexed records.
    pub default_freshness_ms: u64,
    /// Beads older than this window are marked stale.
    pub stale_bead_after_ms: u64,
}

impl ProofGraphIndexer {
    /// Construct an indexer using conservative default windows.
    #[must_use]
    pub const fn new(now_unix_ms: u64) -> Self {
        Self {
            now_unix_ms,
            default_freshness_ms: DEFAULT_FRESHNESS_MS,
            stale_bead_after_ms: DEFAULT_STALE_BEAD_MS,
        }
    }

    /// Build a deterministic [`ProofGraph`] from a redaction-safe corpus.
    ///
    /// # Errors
    ///
    /// Returns [`ProofGraphIndexError`] when corpus schema or graph validation
    /// fails.
    pub fn index(&self, corpus: &ProofGraphCorpus) -> Result<ProofGraph, ProofGraphIndexError> {
        if corpus.schema != PROOF_GRAPH_INDEXER_CORPUS_SCHEMA {
            return Err(ProofGraphIndexError::InvalidCorpusSchema {
                expected: PROOF_GRAPH_INDEXER_CORPUS_SCHEMA,
                actual: corpus.schema.clone(),
            });
        }

        let mut accumulator = IndexAccumulator::default();
        self.index_readme_rows(&corpus.readme_rows, &mut accumulator)?;
        self.index_bead_issues(&corpus.bead_issues, &mut accumulator)?;
        self.index_verification_scripts(&corpus.verification_scripts, &mut accumulator)?;
        self.index_readiness_rows(&corpus.readiness_rows, &mut accumulator)?;
        self.index_evidence_bundles(&corpus.evidence_bundles, &mut accumulator)?;
        self.index_agent_readiness_reports(&corpus.agent_readiness_reports, &mut accumulator)?;

        let suggested_next_actions = accumulator.suggested_next_actions()?;
        ProofGraph::from_nodes(
            accumulator.claims.into_nodes(),
            accumulator.evidence,
            accumulator.edges,
            suggested_next_actions,
        )
        .map_err(ProofGraphIndexError::Graph)
    }

    fn index_readme_rows(
        &self,
        rows: &[ReadmeFeatureRow],
        accumulator: &mut IndexAccumulator,
    ) -> Result<(), ProofGraphError> {
        for row in rows {
            let claim_key = canonical_claim_key(&row.claim_key);
            let claim = self.claim_from_readme(row)?;
            accumulator.claims.merge(claim_key.clone(), claim)?;
            let evidence_node = self.readme_evidence(row)?;
            let evidence_id = evidence_node.id.clone();
            accumulator.evidence.push(evidence_node);
            accumulator.edges.push(SupportEdge::new(
                claim_id_for_key(&claim_key)?,
                evidence_id,
                readme_relationship(&row.status),
                "README status row is a documentation claim and evidence pointer",
            )?);
            accumulator.record_rerun(claim_key, false);
        }
        Ok(())
    }

    fn index_agent_readiness_reports(
        &self,
        reports: &[AgentReadinessProofRecord],
        accumulator: &mut IndexAccumulator,
    ) -> Result<(), ProofGraphIndexError> {
        for record in reports {
            record
                .report
                .validate()
                .map_err(|error| readiness_index_error(&error))?;
            let claim_key = canonical_claim_key(&record.claim_key);
            let claim = self.claim_from_agent_readiness(record)?;
            accumulator.claims.merge(claim_key.clone(), claim)?;

            let report_evidence = self.agent_readiness_report_evidence(record)?;
            let mut claim_has_rerun = report_evidence.rerun_command.is_some();
            let report_evidence_id = report_evidence.id.clone();
            accumulator.evidence.push(report_evidence);
            accumulator.edges.push(SupportEdge::new(
                claim_id_for_key(&claim_key)?,
                report_evidence_id,
                readiness_status_relationship(record.report.decision.status),
                "Agent readiness report records current coordination, proof, and push posture",
            )?);

            for blocker_bead_id in readiness_blocker_bead_ids(&record.report) {
                let blocker_evidence =
                    self.agent_readiness_blocker_evidence(record, &blocker_bead_id)?;
                claim_has_rerun |= blocker_evidence.rerun_command.is_some();
                let blocker_evidence_id = blocker_evidence.id.clone();
                accumulator.evidence.push(blocker_evidence);
                accumulator.edges.push(SupportEdge::new(
                    claim_id_for_key(&claim_key)?,
                    blocker_evidence_id,
                    SupportRelationship::DoesNotSupport,
                    "Readiness decision names this Beads issue as an active blocker",
                )?);
            }

            accumulator.record_rerun(claim_key, claim_has_rerun);
        }
        Ok(())
    }

    fn index_bead_issues(
        &self,
        issues: &[BeadIssueRecord],
        accumulator: &mut IndexAccumulator,
    ) -> Result<(), ProofGraphError> {
        for issue in issues {
            let claim_key = canonical_claim_key(&issue.claim_key);
            let claim = self.claim_from_bead(issue)?;
            accumulator.claims.merge(claim_key.clone(), claim)?;
            let issue_evidence = self.bead_issue_evidence(issue)?;
            let issue_evidence_id = issue_evidence.id.clone();
            accumulator.evidence.push(issue_evidence);
            accumulator.edges.push(SupportEdge::new(
                claim_id_for_key(&claim_key)?,
                issue_evidence_id,
                SupportRelationship::PartiallySupports,
                "Beads issue captures acceptance and ownership but is not proof by itself",
            )?);
            let claim_has_rerun = self.index_bead_comments(issue, accumulator)?;
            accumulator.record_rerun(claim_key, claim_has_rerun);
        }
        Ok(())
    }

    fn index_bead_comments(
        &self,
        issue: &BeadIssueRecord,
        accumulator: &mut IndexAccumulator,
    ) -> Result<bool, ProofGraphError> {
        let claim_key = canonical_claim_key(&issue.claim_key);
        let mut claim_has_rerun = false;
        for comment in &issue.proof_comments {
            let (comment_evidence, supports_proof) = self.bead_comment_evidence(issue, comment)?;
            claim_has_rerun |= comment_evidence.rerun_command.is_some();
            let comment_evidence_id = comment_evidence.id.clone();
            accumulator.evidence.push(comment_evidence);
            accumulator.edges.push(SupportEdge::new(
                claim_id_for_key(&claim_key)?,
                comment_evidence_id,
                if supports_proof {
                    SupportRelationship::Supports
                } else {
                    SupportRelationship::PartiallySupports
                },
                if supports_proof {
                    "Beads proof comment cites a rerunnable command or artifact"
                } else {
                    "Beads comment is indexed as an operator pointer, not standalone proof"
                },
            )?);
        }
        Ok(claim_has_rerun)
    }

    fn index_verification_scripts(
        &self,
        scripts: &[VerificationScriptRecord],
        accumulator: &mut IndexAccumulator,
    ) -> Result<(), ProofGraphError> {
        for script in scripts {
            let claim_key = canonical_claim_key(&script.claim_key);
            accumulator.claims.ensure_placeholder(
                &claim_key,
                &script.purpose,
                "Verification script claim",
            )?;
            let script_evidence = self.script_evidence(script)?;
            let evidence_id = script_evidence.id.clone();
            accumulator.evidence.push(script_evidence);
            accumulator.edges.push(SupportEdge::new(
                claim_id_for_key(&claim_key)?,
                evidence_id,
                SupportRelationship::PartiallySupports,
                "Verification script can regenerate evidence but does not prove a current run",
            )?);
            accumulator.record_rerun(claim_key, true);
        }
        Ok(())
    }

    fn index_readiness_rows(
        &self,
        rows: &[ReadinessMatrixRow],
        accumulator: &mut IndexAccumulator,
    ) -> Result<(), ProofGraphError> {
        for row in rows {
            let claim_key = canonical_claim_key(&row.claim_key);
            accumulator.claims.ensure_placeholder(
                &claim_key,
                &row.subject,
                "Readiness matrix claim",
            )?;
            let row_evidence = self.readiness_evidence(row)?;
            let has_rerun = row_evidence.rerun_command.is_some();
            let evidence_id = row_evidence.id.clone();
            accumulator.evidence.push(row_evidence);
            accumulator.edges.push(SupportEdge::new(
                claim_id_for_key(&claim_key)?,
                evidence_id,
                readiness_relationship(&row.state),
                "Readiness matrix row records the current operator-facing state",
            )?);
            accumulator.record_rerun(claim_key, has_rerun);
        }
        Ok(())
    }

    fn index_evidence_bundles(
        &self,
        bundles: &[EvidenceBundleRecord],
        accumulator: &mut IndexAccumulator,
    ) -> Result<(), ProofGraphError> {
        for bundle in bundles {
            let claim_key = canonical_claim_key(&bundle.claim_key);
            accumulator.claims.ensure_placeholder(
                &claim_key,
                &bundle.scenario_id,
                "Evidence bundle claim",
            )?;
            let bundle_evidence = self.bundle_evidence(bundle)?;
            let has_rerun = bundle_evidence.rerun_command.is_some();
            let evidence_id = bundle_evidence.id.clone();
            accumulator.evidence.push(bundle_evidence);
            accumulator.edges.push(SupportEdge::new(
                claim_id_for_key(&claim_key)?,
                evidence_id,
                if bundle.redaction_safe {
                    SupportRelationship::Supports
                } else {
                    SupportRelationship::DoesNotSupport
                },
                if bundle.redaction_safe {
                    "Evidence bundle metadata is redaction-safe and replayable"
                } else {
                    "Evidence bundle metadata is indexed only as an unsafe-redaction signal"
                },
            )?);
            accumulator.record_rerun(claim_key, has_rerun);
        }
        Ok(())
    }

    const fn freshness(self, observed_at_unix_ms: u64) -> FreshnessWindow {
        FreshnessWindow::new(observed_at_unix_ms, self.default_freshness_ms)
    }

    fn claim_from_readme(&self, row: &ReadmeFeatureRow) -> Result<ClaimNode, ProofGraphError> {
        let claim_key = canonical_claim_key(&row.claim_key);
        let mut tags = BTreeSet::from(["readme".to_owned(), "feature-status".to_owned()]);
        tags.insert(slug_tail(&row.status));
        let mut proof_gaps = Vec::new();
        let status = readme_status(&row.status);
        if !matches!(&status, ClaimStatus::Proven) {
            proof_gaps.push(ProofGap {
                id: ProofGapId::new(format!("gap:{}:readme-proof", slug_tail(&claim_key)))?,
                summary: format!("README status {} needs stronger current proof", row.status),
                status: ProofGapStatus::Missing,
                target_truth_source: required_truth_for_claim(&claim_key, &row.feature),
            });
        }
        Ok(ClaimNode {
            id: claim_id_for_key(&claim_key)?,
            title: row.feature.clone(),
            statement: row.summary.clone(),
            status,
            required_truth_source: required_truth_for_claim(&claim_key, &row.feature),
            freshness: self.freshness(self.now_unix_ms),
            redaction_class: RedactionClass::Public,
            owner: None,
            tags,
            proof_gaps,
        })
    }

    fn claim_from_bead(&self, issue: &BeadIssueRecord) -> Result<ClaimNode, ProofGraphError> {
        let claim_key = canonical_claim_key(&issue.claim_key);
        let mut tags = issue.labels.clone();
        tags.insert("beads".to_owned());
        tags.insert(format!("p{}", issue.priority));
        let stale =
            self.now_unix_ms.saturating_sub(issue.updated_at_unix_ms) > self.stale_bead_after_ms;
        let mut proof_gaps = Vec::new();
        let status = if stale && !issue.status.eq_ignore_ascii_case("closed") {
            proof_gaps.push(ProofGap {
                id: ProofGapId::new(format!("gap:{}:stale-bead", slug_tail(&claim_key)))?,
                summary: "Bead has not been updated inside the freshness window".to_owned(),
                status: ProofGapStatus::Stale,
                target_truth_source: TruthSource::NodeLocal,
            });
            ClaimStatus::Stale {
                stale_at_unix_ms: issue
                    .updated_at_unix_ms
                    .saturating_add(self.stale_bead_after_ms),
            }
        } else if issue.status.eq_ignore_ascii_case("blocked") {
            ClaimStatus::Blocked {
                reason: "Beads issue is blocked".to_owned(),
            }
        } else if issue.status.eq_ignore_ascii_case("closed")
            && issue
                .proof_comments
                .iter()
                .any(BeadProofComment::has_rerunnable_pointer)
        {
            ClaimStatus::Proven
        } else {
            ClaimStatus::Missing
        };
        Ok(ClaimNode {
            id: claim_id_for_key(&claim_key)?,
            title: issue.title.clone(),
            statement: issue.acceptance_summary.clone(),
            status,
            required_truth_source: TruthSource::NodeLocal,
            freshness: self.freshness(issue.updated_at_unix_ms),
            redaction_class: RedactionClass::Internal,
            owner: Some(BeadOwner {
                bead_id: issue.id.clone(),
                agent_name: issue.assignee.clone(),
            }),
            tags,
            proof_gaps,
        })
    }

    fn readme_evidence(&self, row: &ReadmeFeatureRow) -> Result<EvidenceNode, ProofGraphError> {
        let claim_key = canonical_claim_key(&row.claim_key);
        Ok(EvidenceNode {
            id: EvidenceId::new(format!("evidence:readme:{}", slug_tail(&claim_key)))?,
            kind: EvidenceKind::Documentation,
            summary: format!("README {} row: {}", row.status, row.evidence_summary),
            truth_source: TruthSource::Offline,
            freshness: self.freshness(self.now_unix_ms),
            redaction_class: RedactionClass::Public,
            source_ref: row.source.source_ref(),
            content_digest: Some(content_digest(&[
                &row.feature,
                &row.status,
                &row.summary,
                &row.evidence_summary,
            ])),
            rerun_command: None,
        })
    }

    fn bead_issue_evidence(
        &self,
        issue: &BeadIssueRecord,
    ) -> Result<EvidenceNode, ProofGraphError> {
        Ok(EvidenceNode {
            id: EvidenceId::new(format!("evidence:bead:{}", slug_tail(&issue.id)))?,
            kind: EvidenceKind::OperatorRecord,
            summary: format!("Bead {} {}: {}", issue.id, issue.status, issue.title),
            truth_source: TruthSource::NodeLocal,
            freshness: self.freshness(issue.updated_at_unix_ms),
            redaction_class: RedactionClass::Internal,
            source_ref: issue.source.source_ref(),
            content_digest: Some(content_digest(&[
                &issue.id,
                &issue.title,
                &issue.status,
                &issue.acceptance_summary,
            ])),
            rerun_command: Some(RerunCommand {
                id: RerunCommandId::new(format!("rerun:br-show:{}", slug_tail(&issue.id)))?,
                argv: vec![
                    "br".to_owned(),
                    "show".to_owned(),
                    issue.id.clone(),
                    "--json".to_owned(),
                ],
                required_env_keys: BTreeSet::new(),
                working_directory: Some(".".to_owned()),
                requires_rch: false,
            }),
        })
    }

    fn bead_comment_evidence(
        &self,
        issue: &BeadIssueRecord,
        comment: &BeadProofComment,
    ) -> Result<(EvidenceNode, bool), ProofGraphError> {
        let supports_proof = comment.has_rerunnable_pointer();
        let rerun_command = comment
            .rerun_argv
            .as_ref()
            .map(|argv| rerun_command_from_argv(format!("rerun:bead-comment:{}", comment.id), argv))
            .transpose()?;
        Ok((
            EvidenceNode {
                id: EvidenceId::new(format!(
                    "evidence:bead-comment:{}:{}",
                    slug_tail(&issue.id),
                    comment.id
                ))?,
                kind: EvidenceKind::OperatorRecord,
                summary: comment.summary.clone(),
                truth_source: TruthSource::NodeLocal,
                freshness: self.freshness(comment.created_at_unix_ms),
                redaction_class: RedactionClass::Internal,
                source_ref: comment.source.source_ref(),
                content_digest: Some(content_digest(&[
                    &issue.id,
                    &comment.id.to_string(),
                    &comment.summary,
                ])),
                rerun_command,
            },
            supports_proof,
        ))
    }

    fn script_evidence(
        &self,
        script: &VerificationScriptRecord,
    ) -> Result<EvidenceNode, ProofGraphError> {
        Ok(EvidenceNode {
            id: EvidenceId::new(format!(
                "evidence:script:{}:{}",
                slug_tail(&script.claim_key),
                slug_tail(&script.script_path)
            ))?,
            kind: EvidenceKind::NodeLocalRun,
            summary: script.purpose.clone(),
            truth_source: TruthSource::NodeLocal,
            freshness: self.freshness(self.now_unix_ms),
            redaction_class: RedactionClass::Internal,
            source_ref: script.source.source_ref(),
            content_digest: Some(content_digest(&[
                &script.claim_key,
                &script.script_path,
                &script.purpose,
            ])),
            rerun_command: Some(RerunCommand {
                id: RerunCommandId::new(format!(
                    "rerun:script:{}",
                    slug_tail(&script.script_path)
                ))?,
                argv: script.rerun_argv.clone(),
                required_env_keys: script.required_env_keys.clone(),
                working_directory: Some(".".to_owned()),
                requires_rch: false,
            }),
        })
    }

    fn readiness_evidence(
        &self,
        row: &ReadinessMatrixRow,
    ) -> Result<EvidenceNode, ProofGraphError> {
        let rerun_command = row
            .rerun_argv
            .as_ref()
            .map(|argv| {
                rerun_command_from_argv(
                    format!("rerun:readiness:{}", slug_tail(&row.subject)),
                    argv,
                )
            })
            .transpose()?;
        Ok(EvidenceNode {
            id: EvidenceId::new(format!(
                "evidence:readiness:{}:{}",
                slug_tail(&row.claim_key),
                slug_tail(&row.subject)
            ))?,
            kind: EvidenceKind::HostIntegration,
            summary: format!("Readiness {}: {}", row.subject, row.state),
            truth_source: row.truth_source.clone(),
            freshness: self.freshness(self.now_unix_ms),
            redaction_class: RedactionClass::Internal,
            source_ref: row.source.source_ref(),
            content_digest: Some(content_digest(&[&row.subject, &row.state])),
            rerun_command,
        })
    }

    fn bundle_evidence(
        &self,
        bundle: &EvidenceBundleRecord,
    ) -> Result<EvidenceNode, ProofGraphError> {
        let rerun_command = bundle
            .validation_argv
            .as_ref()
            .map(|argv| {
                rerun_command_from_argv(
                    format!("rerun:bundle:{}", slug_tail(&bundle.scenario_id)),
                    argv,
                )
            })
            .transpose()?;
        Ok(EvidenceNode {
            id: EvidenceId::new(format!(
                "evidence:bundle:{}:{}",
                slug_tail(&bundle.claim_key),
                slug_tail(&bundle.scenario_id)
            ))?,
            kind: EvidenceKind::OfflineArtifact,
            summary: format!(
                "Evidence bundle {}: commands={}, live={}, offline={}, redaction_safe={}",
                bundle.scenario_id,
                bundle.command_count,
                bundle.live_count,
                bundle.offline_count,
                bundle.redaction_safe
            ),
            truth_source: if bundle.live_count > 0 {
                TruthSource::HostBacked
            } else {
                TruthSource::Offline
            },
            freshness: self.freshness(self.now_unix_ms),
            redaction_class: if bundle.redaction_safe {
                RedactionClass::Internal
            } else {
                RedactionClass::Redacted
            },
            source_ref: bundle.source.source_ref(),
            content_digest: Some(content_digest(&[
                &bundle.scenario_id,
                &bundle.bundle_path,
                &bundle.command_count.to_string(),
                &bundle.live_count.to_string(),
                &bundle.offline_count.to_string(),
            ])),
            rerun_command,
        })
    }

    fn claim_from_agent_readiness(
        &self,
        record: &AgentReadinessProofRecord,
    ) -> Result<ClaimNode, ProofGraphError> {
        let claim_key = canonical_claim_key(&record.claim_key);
        let report = &record.report;
        let mut tags = BTreeSet::from([
            "agent-readiness".to_owned(),
            format!("mode-{}", readiness_mode_label(report.decision.mode)),
            format!("status-{}", readiness_status_label(report.decision.status)),
        ]);
        tags.extend(
            readiness_blocker_bead_ids(report)
                .into_iter()
                .map(|bead_id| format!("blocker-{}", slug_tail(&bead_id))),
        );

        Ok(ClaimNode {
            id: claim_id_for_key(&claim_key)?,
            title: format!("Agent readiness {}", report.run_id),
            statement: format!(
                "Agent readiness mode={} status={} reason={}",
                readiness_mode_label(report.decision.mode),
                readiness_status_label(report.decision.status),
                report
                    .decision
                    .primary_reason_code
                    .as_deref()
                    .unwrap_or("none")
            ),
            status: agent_readiness_claim_status(report.decision.status, report),
            required_truth_source: TruthSource::NodeLocal,
            freshness: self.freshness(report.finished_at_unix_ms),
            redaction_class: RedactionClass::Internal,
            owner: None,
            tags,
            proof_gaps: agent_readiness_proof_gaps(&claim_key, report)?,
        })
    }

    fn agent_readiness_report_evidence(
        &self,
        record: &AgentReadinessProofRecord,
    ) -> Result<EvidenceNode, ProofGraphIndexError> {
        let report = &record.report;
        let blocker_beads = readiness_blocker_bead_ids(report);
        let blockers = if blocker_beads.is_empty() {
            "none".to_owned()
        } else {
            blocker_beads.into_iter().collect::<Vec<_>>().join(",")
        };
        let rerun_command = record
            .rerun_argv
            .as_ref()
            .map(|argv| {
                rerun_command_from_argv(
                    format!("rerun:agent-readiness:{}", slug_tail(&report.run_id)),
                    argv,
                )
            })
            .transpose()?;
        Ok(EvidenceNode {
            id: EvidenceId::new(format!(
                "evidence:agent-readiness:{}:{}",
                slug_tail(&record.claim_key),
                slug_tail(&report.run_id)
            ))?,
            kind: EvidenceKind::NodeLocalRun,
            summary: format!(
                "Agent readiness report {} status={} mode={} blockers={}",
                report.run_id,
                readiness_status_label(report.decision.status),
                readiness_mode_label(report.decision.mode),
                blockers
            ),
            truth_source: TruthSource::NodeLocal,
            freshness: self.freshness(report.finished_at_unix_ms),
            redaction_class: RedactionClass::Internal,
            source_ref: record.source.source_ref(),
            content_digest: Some(content_digest(&[
                &record.report_path,
                &report.run_id,
                readiness_status_label(report.decision.status),
                readiness_mode_label(report.decision.mode),
                &report
                    .record_digest()
                    .map_err(|error| readiness_index_error(&error))?,
            ])),
            rerun_command,
        })
    }

    fn agent_readiness_blocker_evidence(
        &self,
        record: &AgentReadinessProofRecord,
        blocker_bead_id: &str,
    ) -> Result<EvidenceNode, ProofGraphError> {
        Ok(EvidenceNode {
            id: EvidenceId::new(format!(
                "evidence:agent-readiness-blocker:{}:{}",
                slug_tail(&record.report.run_id),
                slug_tail(blocker_bead_id)
            ))?,
            kind: EvidenceKind::OperatorRecord,
            summary: format!("Readiness report links blocker bead {blocker_bead_id}"),
            truth_source: TruthSource::NodeLocal,
            freshness: self.freshness(record.report.finished_at_unix_ms),
            redaction_class: RedactionClass::Internal,
            source_ref: record.source.source_ref(),
            content_digest: Some(content_digest(&[&record.report.run_id, blocker_bead_id])),
            rerun_command: Some(RerunCommand {
                id: RerunCommandId::new(format!(
                    "rerun:agent-readiness-blocker:{}",
                    slug_tail(blocker_bead_id)
                ))?,
                argv: vec![
                    "br".to_owned(),
                    "show".to_owned(),
                    blocker_bead_id.to_owned(),
                    "--json".to_owned(),
                ],
                required_env_keys: BTreeSet::new(),
                working_directory: Some(".".to_owned()),
                requires_rch: false,
            }),
        })
    }
}

impl BeadProofComment {
    fn has_rerunnable_pointer(&self) -> bool {
        self.rerun_argv
            .as_ref()
            .is_some_and(|argv| !argv.is_empty())
            || self
                .artifact_path
                .as_ref()
                .is_some_and(|path| !path.is_empty())
    }
}

/// Errors returned by the `ProofGraph` indexer.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ProofGraphIndexError {
    /// Corpus schema was not recognized.
    #[error("invalid ProofGraph corpus schema: expected {expected}, got {actual}")]
    InvalidCorpusSchema {
        /// Expected schema.
        expected: &'static str,
        /// Actual schema.
        actual: String,
    },
    /// Underlying graph validation failed.
    #[error(transparent)]
    Graph(#[from] ProofGraphError),
    /// Agent readiness report validation failed.
    #[error("invalid agent readiness report: {message}")]
    AgentReadiness {
        /// Redaction-safe validation error.
        message: String,
    },
}

#[derive(Default)]
struct IndexAccumulator {
    claims: ClaimAccumulatorSet,
    evidence: Vec<EvidenceNode>,
    edges: Vec<SupportEdge>,
    rerun_by_claim: BTreeMap<String, bool>,
}

impl IndexAccumulator {
    fn record_rerun(&mut self, claim_key: String, has_rerun: bool) {
        self.rerun_by_claim
            .entry(claim_key)
            .and_modify(|current| *current |= has_rerun)
            .or_insert(has_rerun);
    }

    fn suggested_next_actions(&mut self) -> Result<Vec<SuggestedNextAction>, ProofGraphError> {
        let mut suggested_next_actions = Vec::new();
        self.claims.add_missing_rerun_gaps(&self.rerun_by_claim)?;
        for (claim_key, claim) in &self.claims.claims {
            if !self.rerun_by_claim.get(claim_key).copied().unwrap_or(false) {
                suggested_next_actions.push(SuggestedNextAction {
                    id: SuggestedActionId::new(format!(
                        "action:{}:add-rerun-command",
                        slug_tail(claim_key)
                    ))?,
                    claim_id: claim.id.clone(),
                    summary: format!("Add rerunnable proof command for {}", claim.title),
                    rerun_command: None,
                });
            }
        }
        Ok(suggested_next_actions)
    }
}

#[derive(Default)]
struct ClaimAccumulatorSet {
    claims: BTreeMap<String, ClaimNode>,
}

impl ClaimAccumulatorSet {
    fn merge(&mut self, claim_key: String, claim: ClaimNode) -> Result<(), ProofGraphError> {
        if let Some(existing) = self.claims.get_mut(&claim_key) {
            if claim.title.as_str() < existing.title.as_str() {
                existing.title = claim.title.clone();
            }
            if claim.statement.as_str() < existing.statement.as_str() {
                existing.statement = claim.statement.clone();
            }
            existing.status = merge_status(&existing.status, &claim.status);
            if claim.required_truth_source.rank() > existing.required_truth_source.rank() {
                existing.required_truth_source = claim.required_truth_source;
            }
            if claim.freshness.observed_at_unix_ms > existing.freshness.observed_at_unix_ms {
                existing.freshness = claim.freshness;
            }
            existing.redaction_class = existing.redaction_class.max(claim.redaction_class);
            if existing.owner.is_none() {
                existing.owner = claim.owner;
            }
            existing.tags.extend(claim.tags);
            for gap in claim.proof_gaps {
                if !existing
                    .proof_gaps
                    .iter()
                    .any(|existing_gap| existing_gap.id == gap.id)
                {
                    existing.proof_gaps.push(gap);
                }
            }
            existing
                .proof_gaps
                .sort_by(|left, right| left.id.cmp(&right.id));
            existing.validate()
        } else {
            self.claims.insert(claim_key, claim);
            Ok(())
        }
    }

    fn ensure_placeholder(
        &mut self,
        claim_key: &str,
        title: &str,
        statement: &str,
    ) -> Result<(), ProofGraphError> {
        if self.claims.contains_key(claim_key) {
            return Ok(());
        }
        self.claims.insert(
            claim_key.to_owned(),
            ClaimNode {
                id: claim_id_for_key(claim_key)?,
                title: title.to_owned(),
                statement: statement.to_owned(),
                status: ClaimStatus::Missing,
                required_truth_source: TruthSource::NodeLocal,
                freshness: FreshnessWindow::new(0, DEFAULT_FRESHNESS_MS),
                redaction_class: RedactionClass::Internal,
                owner: None,
                tags: BTreeSet::from(["proofgraph".to_owned()]),
                proof_gaps: Vec::new(),
            },
        );
        Ok(())
    }

    fn add_missing_rerun_gaps(
        &mut self,
        rerun_by_claim: &BTreeMap<String, bool>,
    ) -> Result<(), ProofGraphError> {
        for (claim_key, claim) in &mut self.claims {
            if rerun_by_claim.get(claim_key).copied().unwrap_or(false) {
                continue;
            }
            let gap_id = ProofGapId::new(format!("gap:{}:missing-rerun", slug_tail(claim_key)))?;
            if claim.proof_gaps.iter().any(|gap| gap.id == gap_id) {
                continue;
            }
            claim.proof_gaps.push(ProofGap {
                id: gap_id,
                summary: "No rerunnable command was indexed for this claim".to_owned(),
                status: ProofGapStatus::Missing,
                target_truth_source: claim.required_truth_source.clone(),
            });
            claim
                .proof_gaps
                .sort_by(|left, right| left.id.cmp(&right.id));
        }
        Ok(())
    }

    fn into_nodes(self) -> Vec<ClaimNode> {
        self.claims.into_values().collect()
    }
}

fn canonical_claim_key(value: &str) -> String {
    slug_tail(value)
}

fn claim_id_for_key(claim_key: &str) -> Result<ClaimId, ProofGraphError> {
    ClaimId::new(format!("claim:{}", slug_tail(claim_key)))
}

fn rerun_command_from_argv(id: String, argv: &[String]) -> Result<RerunCommand, ProofGraphError> {
    Ok(RerunCommand {
        id: RerunCommandId::new(id)?,
        argv: argv.to_vec(),
        required_env_keys: BTreeSet::new(),
        working_directory: Some(".".to_owned()),
        requires_rch: argv.iter().any(|arg| arg == "rch"),
    })
}

fn readme_status(status: &str) -> ClaimStatus {
    let normalized = status.to_ascii_uppercase();
    // Negated proof phrasings ("NOT YET PROVEN", "UNPROVEN", "NOT PROVEN",
    // "DISPROVEN") all contain the substring "PROVEN" but mean the opposite,
    // so they MUST be checked before the bare `contains("PROVEN")` test.
    // Otherwise a feature the README explicitly marks as not-proven is
    // classified Proven, and claim_from_readme then suppresses its proof gap —
    // silently reporting unproven work as fully proven.
    let negated_proof = normalized.contains("NOT YET")
        || normalized.contains("NOT PROVEN")
        || normalized.contains("UNPROVEN")
        || normalized.contains("DISPROVEN");
    if negated_proof {
        ClaimStatus::Missing
    } else if normalized.contains("PROVEN") {
        ClaimStatus::Proven
    } else if normalized.contains("BLOCKED") {
        ClaimStatus::Blocked {
            reason: "README row marks the feature blocked".to_owned(),
        }
    } else if normalized.contains("SKIP") {
        ClaimStatus::SkippedWithReason {
            reason: "README row marks the feature skipped".to_owned(),
        }
    } else {
        ClaimStatus::Missing
    }
}

fn readme_relationship(status: &str) -> SupportRelationship {
    if matches!(readme_status(status), ClaimStatus::Proven) {
        SupportRelationship::PartiallySupports
    } else {
        SupportRelationship::DoesNotSupport
    }
}

fn readiness_relationship(state: &str) -> SupportRelationship {
    match state.to_ascii_lowercase().as_str() {
        "pass" | "ready" | "proven" => SupportRelationship::Supports,
        "fail" | "failed" => SupportRelationship::Contradicts,
        "blocked" | "skip" | "skipped" => SupportRelationship::DoesNotSupport,
        _ => SupportRelationship::PartiallySupports,
    }
}

const fn readiness_status_relationship(status: ReadinessStatus) -> SupportRelationship {
    match status {
        ReadinessStatus::Ok => SupportRelationship::Supports,
        ReadinessStatus::Warn => SupportRelationship::PartiallySupports,
        ReadinessStatus::Blocked | ReadinessStatus::Skipped | ReadinessStatus::Error => {
            SupportRelationship::DoesNotSupport
        }
    }
}

fn agent_readiness_claim_status(
    status: ReadinessStatus,
    report: &AgentReadinessReport,
) -> ClaimStatus {
    match status {
        ReadinessStatus::Ok => ClaimStatus::Proven,
        ReadinessStatus::Warn | ReadinessStatus::Blocked => ClaimStatus::Blocked {
            reason: report
                .decision
                .primary_reason_code
                .clone()
                .unwrap_or_else(|| "agent-readiness-degraded".to_owned()),
        },
        ReadinessStatus::Skipped => ClaimStatus::SkippedWithReason {
            reason: report
                .decision
                .primary_reason_code
                .clone()
                .unwrap_or_else(|| "agent-readiness-skipped".to_owned()),
        },
        ReadinessStatus::Error => ClaimStatus::Failed {
            reason: report
                .decision
                .primary_reason_code
                .clone()
                .unwrap_or_else(|| "agent-readiness-error".to_owned()),
        },
    }
}

fn agent_readiness_proof_gaps(
    claim_key: &str,
    report: &AgentReadinessReport,
) -> Result<Vec<ProofGap>, ProofGraphError> {
    let mut gaps = Vec::new();
    for blocker_bead_id in readiness_blocker_bead_ids(report) {
        gaps.push(ProofGap {
            id: ProofGapId::new(format!(
                "gap:{}:blocker:{}",
                slug_tail(claim_key),
                slug_tail(&blocker_bead_id)
            ))?,
            summary: format!("Readiness is blocked by Beads issue {blocker_bead_id}"),
            status: ProofGapStatus::Blocked,
            target_truth_source: TruthSource::NodeLocal,
        });
    }
    for action in &report.decision.refused_actions {
        gaps.push(ProofGap {
            id: ProofGapId::new(format!(
                "gap:{}:refused:{}",
                slug_tail(claim_key),
                readiness_action_label(*action)
            ))?,
            summary: format!(
                "Readiness decision refuses {} while mode is {}",
                readiness_action_label(*action),
                readiness_mode_label(report.decision.mode)
            ),
            status: readiness_gap_status(report.decision.status),
            target_truth_source: TruthSource::NodeLocal,
        });
    }
    gaps.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(gaps)
}

fn readiness_blocker_bead_ids(report: &AgentReadinessReport) -> BTreeSet<String> {
    let mut blocker_bead_ids = report.decision.blocker_bead_ids.clone();
    blocker_bead_ids.extend(report.probes.beads.blocked_infra_bead_ids.iter().cloned());
    blocker_bead_ids
}

fn readiness_index_error(error: &AgentReadinessError) -> ProofGraphIndexError {
    ProofGraphIndexError::AgentReadiness {
        message: error.to_string(),
    }
}

const fn readiness_gap_status(status: ReadinessStatus) -> ProofGapStatus {
    match status {
        ReadinessStatus::Ok => ProofGapStatus::Missing,
        ReadinessStatus::Warn | ReadinessStatus::Blocked => ProofGapStatus::Blocked,
        ReadinessStatus::Skipped => ProofGapStatus::SkippedWithReason,
        ReadinessStatus::Error => ProofGapStatus::Failed,
    }
}

const fn readiness_status_label(status: ReadinessStatus) -> &'static str {
    match status {
        ReadinessStatus::Ok => "ok",
        ReadinessStatus::Warn => "warn",
        ReadinessStatus::Blocked => "blocked",
        ReadinessStatus::Skipped => "skipped",
        ReadinessStatus::Error => "error",
    }
}

const fn readiness_mode_label(mode: ReadinessOperatingMode) -> &'static str {
    match mode {
        ReadinessOperatingMode::FullMailBeadsRch => "full_mail_beads_rch",
        ReadinessOperatingMode::BeadsOnly => "beads_only",
        ReadinessOperatingMode::ReadOnlyPlanning => "read_only_planning",
        ReadinessOperatingMode::ProofBlocked => "proof_blocked",
        ReadinessOperatingMode::OperatorActionRequired => "operator_action_required",
    }
}

const fn readiness_action_label(action: ReadinessAction) -> &'static str {
    match action {
        ReadinessAction::Coordinate => "coordinate",
        ReadinessAction::ClaimBead => "claim_bead",
        ReadinessAction::EditFiles => "edit_files",
        ReadinessAction::CargoProof => "cargo_proof",
        ReadinessAction::Push => "push",
    }
}

fn required_truth_for_claim(claim_key: &str, feature: &str) -> TruthSource {
    let combined = format!("{claim_key} {feature}").to_ascii_lowercase();
    if combined.contains("mesh") || combined.contains("swarm") {
        TruthSource::MeshBacked
    } else if combined.contains("runtime")
        || combined.contains("browser")
        || combined.contains("secretless")
        || combined.contains("telemetry")
    {
        TruthSource::HostBacked
    } else {
        TruthSource::NodeLocal
    }
}

fn merge_status(left: &ClaimStatus, right: &ClaimStatus) -> ClaimStatus {
    if status_rank(right) < status_rank(left) {
        right.clone()
    } else {
        left.clone()
    }
}

const fn status_rank(status: &ClaimStatus) -> u8 {
    match status {
        ClaimStatus::Failed { .. } => 0,
        ClaimStatus::Blocked { .. } => 1,
        ClaimStatus::Stale { .. } => 2,
        ClaimStatus::Missing => 3,
        ClaimStatus::SkippedWithReason { .. } => 4,
        ClaimStatus::Proven => 5,
    }
}

fn content_digest(parts: &[&str]) -> String {
    let mut hasher = blake3::Hasher::new();
    for part in parts {
        hasher.update(part.as_bytes());
        hasher.update(b"\0");
    }
    format!("blake3:{}", hex::encode(hasher.finalize().as_bytes()))
}

fn slug_tail(value: &str) -> String {
    let mut slug = String::new();
    let mut last_was_separator = false;
    for ch in value.chars() {
        let next = if ch.is_ascii_alphanumeric() {
            last_was_separator = false;
            ch.to_ascii_lowercase()
        } else if matches!(ch, '-' | '_' | '.' | ':') {
            last_was_separator = false;
            ch
        } else if last_was_separator {
            continue;
        } else {
            last_was_separator = true;
            '-'
        };
        slug.push(next);
    }
    let slug = slug.trim_matches('-');
    let slug = if slug.is_empty() { "unnamed" } else { slug };
    if slug.len() <= MAX_ID_TAIL_CHARS {
        return slug.to_owned();
    }
    let digest = blake3::hash(value.as_bytes());
    let digest_hex = hex::encode(&digest.as_bytes()[..6]);
    let prefix_len = MAX_ID_TAIL_CHARS - digest_hex.len() - 1;
    format!("{}-{digest_hex}", &slug[..prefix_len])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_readiness::{ReadinessDecision, ReadinessStatus};
    use crate::agent_readiness_probe::{NoNetworkProbeFixture, NoNetworkProbeScenario};

    const NOW: u64 = 1_800_000_000_000;
    const DAY_MS: u64 = 24 * 60 * 60 * 1_000;

    fn source(path: &str, line: u32) -> SourceLocation {
        SourceLocation {
            source_id: "fixture".to_owned(),
            path: path.to_owned(),
            line: Some(line),
        }
    }

    fn row(claim_key: &str, feature: &str, status: &str, line: u32) -> ReadmeFeatureRow {
        ReadmeFeatureRow {
            claim_key: claim_key.to_owned(),
            feature: feature.to_owned(),
            status: status.to_owned(),
            summary: format!("{feature} status row"),
            evidence_summary: "redaction-safe repo evidence paths".to_owned(),
            source: source("README.md", line),
        }
    }

    fn issue(claim_key: &str, id: &str, updated_at_unix_ms: u64) -> BeadIssueRecord {
        BeadIssueRecord {
            id: id.to_owned(),
            claim_key: claim_key.to_owned(),
            title: format!("{claim_key} bead"),
            status: "open".to_owned(),
            priority: 1,
            acceptance_summary: "Acceptance requires rerunnable proof".to_owned(),
            labels: BTreeSet::from(["proofgraph".to_owned()]),
            assignee: Some("Codex".to_owned()),
            updated_at_unix_ms,
            source: source(".beads/issues.jsonl", 42),
            proof_comments: Vec::new(),
        }
    }

    fn readiness_record(
        claim_key: &str,
        run_id: &str,
        scenario: NoNetworkProbeScenario,
        rerun_argv: Option<Vec<&str>>,
    ) -> AgentReadinessProofRecord {
        let report = NoNetworkProbeFixture {
            run_id: run_id.to_owned(),
            agent_name: "Codex".to_owned(),
            observed_at_unix_ms: NOW,
            scenario,
            owned_path_globs: BTreeSet::from(["crates/fcp-evidence/**".to_owned()]),
        }
        .build_report()
        .expect("readiness fixture report");
        AgentReadinessProofRecord {
            claim_key: claim_key.to_owned(),
            report,
            report_path: format!("artifacts/readiness/{run_id}/report.json"),
            events_path: Some(format!("artifacts/readiness/{run_id}/events.jsonl")),
            handoff_path: Some(format!("artifacts/readiness/{run_id}/handoff.json")),
            rerun_argv: rerun_argv.map(|argv| argv.into_iter().map(str::to_owned).collect()),
            source: source("artifacts/readiness/manifest.json", 1),
        }
    }

    fn disk_pressure_record() -> AgentReadinessProofRecord {
        let mut record = readiness_record(
            "agent-readiness-disk-pressure",
            "disk-pressure",
            NoNetworkProbeScenario::Healthy,
            None,
        );
        record.report.probes.disk.check_result.status = ReadinessStatus::Blocked;
        record.report.probes.disk.check_result.reason_code = Some("disk-pressure".to_owned());
        record.report.probes.disk.check_result.remediation =
            Some("defer proof until scratch storage recovers".to_owned());
        record.report.probes.disk.external_scratch_available = false;
        if let Some(mount) = record.report.probes.disk.checked_mounts.first_mut() {
            mount.free_bytes = 42;
            mount.capacity_percent = 100;
            mount.threshold_status = ReadinessStatus::Blocked;
        }
        record.report.decision = ReadinessDecision::from_probes(&record.report.probes);
        record.report.validate().expect("disk pressure report");
        record
    }

    fn fixture_corpus() -> ProofGraphCorpus {
        ProofGraphCorpus {
            readme_rows: vec![
                row(
                    "mesh-native",
                    "Mesh-Native Architecture",
                    "STEADY-STATE TARGET",
                    63,
                ),
                row("secretless", "Secretless Connectors", "IMPLEMENTED", 56),
                row("telemetry-otlp", "Telemetry OTLP", "PROVEN", 90),
                row("browser-cdp", "Browser CDP", "DESIGNED", 91),
                row("swarm-performance", "Swarm Performance", "PLANNED", 92),
            ],
            bead_issues: vec![
                issue("secretless", "flywheel_connectors-e99o6.1.4", NOW - DAY_MS),
                issue(
                    "browser-cdp",
                    "flywheel_connectors-4kw5f.3.3",
                    NOW - 30 * DAY_MS,
                ),
            ],
            verification_scripts: vec![VerificationScriptRecord {
                claim_key: "telemetry-otlp".to_owned(),
                script_path: "scripts/e2e/telemetry_otlp_verification.sh".to_owned(),
                purpose: "Replay Telemetry OTLP verification bundle".to_owned(),
                rerun_argv: vec![
                    "bash".to_owned(),
                    "scripts/e2e/telemetry_otlp_verification.sh".to_owned(),
                ],
                required_env_keys: BTreeSet::new(),
                source: source("scripts/e2e/telemetry_otlp_verification.sh", 1),
            }],
            readiness_rows: vec![ReadinessMatrixRow {
                claim_key: "mesh-native".to_owned(),
                subject: "mesh-cutover-gate".to_owned(),
                state: "blocked".to_owned(),
                truth_source: TruthSource::HostBacked,
                rerun_argv: Some(vec![
                    "fwc".to_owned(),
                    "mesh".to_owned(),
                    "cutover-gates".to_owned(),
                    "--json".to_owned(),
                ]),
                source: source("crates/fwc/tests/readme_status_pinning.rs", 12),
            }],
            evidence_bundles: vec![EvidenceBundleRecord {
                claim_key: "swarm-performance".to_owned(),
                scenario_id: "swarm-high-core-proof".to_owned(),
                bundle_path: "artifacts/e2e/swarm-high-core/latest".to_owned(),
                redaction_safe: true,
                command_count: 2,
                live_count: 0,
                offline_count: 2,
                validation_argv: Some(vec![
                    "bash".to_owned(),
                    "scripts/ci/validate_e2e_artifacts.sh".to_owned(),
                    "--bundle-dir".to_owned(),
                    "artifacts/e2e/swarm-high-core/latest".to_owned(),
                ]),
                source: source("artifacts/e2e/swarm-high-core/manifest.json", 1),
            }],
            ..ProofGraphCorpus::default()
        }
    }

    #[test]
    fn fixture_indexes_representative_corpus() {
        let graph = ProofGraphIndexer::new(NOW)
            .index(&fixture_corpus())
            .expect("index fixture");

        assert_eq!(graph.claims.len(), 5);
        assert_eq!(graph.evidence.len(), 10);
        assert!(
            graph
                .claims
                .contains_key(&ClaimId::new("claim:mesh-native").unwrap())
        );
        assert!(
            graph
                .evidence
                .values()
                .any(|node| node.source_ref == "README.md:63")
        );
        let browser = graph
            .claims
            .get(&ClaimId::new("claim:browser-cdp").unwrap())
            .expect("browser claim");
        assert!(matches!(browser.status, ClaimStatus::Stale { .. }));
        assert!(
            browser
                .proof_gaps
                .iter()
                .any(|gap| gap.status == ProofGapStatus::Stale)
        );
    }

    #[test]
    fn readme_status_does_not_misclassify_negated_proof_as_proven() {
        // Positive phrasings still classify as Proven (including incidental
        // substrings like "NOTE" that are not negations).
        assert!(matches!(readme_status("Proven"), ClaimStatus::Proven));
        assert!(matches!(readme_status("PROVEN"), ClaimStatus::Proven));
        assert!(matches!(
            readme_status("Proven, see note"),
            ClaimStatus::Proven
        ));

        // Negated phrasings all contain the substring "PROVEN" but must NOT be
        // classified Proven, or claim_from_readme suppresses the proof gap and
        // reports unproven work as fully proven.
        for status in [
            "Not yet proven",
            "Not yet",
            "Unproven",
            "UNPROVEN",
            "Not proven",
            "Disproven",
        ] {
            assert!(
                !matches!(readme_status(status), ClaimStatus::Proven),
                "status {status:?} must not classify as Proven"
            );
            assert!(
                matches!(
                    readme_relationship(status),
                    SupportRelationship::DoesNotSupport
                ),
                "status {status:?} must not support the claim"
            );
        }
    }

    #[test]
    fn readme_row_marked_not_proven_yields_a_proof_gap() {
        // End-to-end guard: a README row explicitly marked not-proven must
        // produce a non-Proven claim carrying an outstanding proof gap.
        let indexer = ProofGraphIndexer::new(NOW);
        let claim = indexer
            .claim_from_readme(&row(
                "telemetry-otlp",
                "Telemetry OTLP",
                "Not yet proven",
                90,
            ))
            .expect("claim from readme");
        assert!(!matches!(claim.status, ClaimStatus::Proven));
        assert!(
            !claim.proof_gaps.is_empty(),
            "a not-proven README claim must carry a proof gap"
        );
    }

    #[test]
    fn deterministic_graph_output_ignores_input_order() {
        let corpus = fixture_corpus();
        let mut reversed = corpus.clone();
        reversed.readme_rows.reverse();
        reversed.bead_issues.reverse();
        reversed.verification_scripts.reverse();
        reversed.readiness_rows.reverse();
        reversed.evidence_bundles.reverse();

        let indexer = ProofGraphIndexer::new(NOW);
        let left = serde_json::to_string_pretty(&indexer.index(&corpus).unwrap()).unwrap();
        let right = serde_json::to_string_pretty(&indexer.index(&reversed).unwrap()).unwrap();

        assert_eq!(left, right);
    }

    #[test]
    fn duplicate_claims_merge_into_one_node() {
        let graph = ProofGraphIndexer::new(NOW)
            .index(&ProofGraphCorpus {
                readme_rows: vec![row(
                    "secretless",
                    "Secretless Connectors",
                    "IMPLEMENTED",
                    56,
                )],
                bead_issues: vec![issue(
                    "secretless",
                    "flywheel_connectors-e99o6.1.4",
                    NOW - DAY_MS,
                )],
                ..ProofGraphCorpus::default()
            })
            .expect("index duplicate claim");

        assert_eq!(graph.claims.len(), 1);
        let claim = graph
            .claims
            .get(&ClaimId::new("claim:secretless").unwrap())
            .expect("merged claim");
        assert!(claim.tags.contains("readme"));
        assert!(claim.tags.contains("beads"));
    }

    #[test]
    fn missing_rerun_command_generates_gap_and_action() {
        let graph = ProofGraphIndexer::new(NOW)
            .index(&ProofGraphCorpus {
                readme_rows: vec![row("browser-cdp", "Browser CDP", "DESIGNED", 91)],
                ..ProofGraphCorpus::default()
            })
            .expect("index missing rerun");

        let claim = graph
            .claims
            .get(&ClaimId::new("claim:browser-cdp").unwrap())
            .expect("browser claim");
        assert!(
            claim
                .proof_gaps
                .iter()
                .any(|gap| gap.id.to_string() == "gap:browser-cdp:missing-rerun")
        );
        assert_eq!(graph.suggested_next_actions.len(), 1);
    }

    #[test]
    fn stale_bead_detection_marks_claim_stale() {
        let graph = ProofGraphIndexer::new(NOW)
            .index(&ProofGraphCorpus {
                bead_issues: vec![issue(
                    "browser-cdp",
                    "flywheel_connectors-4kw5f.3.3",
                    NOW - 30 * DAY_MS,
                )],
                ..ProofGraphCorpus::default()
            })
            .expect("index stale bead");

        let claim = graph
            .claims
            .get(&ClaimId::new("claim:browser-cdp").unwrap())
            .expect("browser claim");
        assert!(matches!(claim.status, ClaimStatus::Stale { .. }));
    }

    #[test]
    fn source_locations_are_preserved_on_evidence_nodes() {
        let graph = ProofGraphIndexer::new(NOW)
            .index(&ProofGraphCorpus {
                verification_scripts: vec![VerificationScriptRecord {
                    claim_key: "telemetry-otlp".to_owned(),
                    script_path: "scripts/e2e/telemetry_otlp_verification.sh".to_owned(),
                    purpose: "Replay Telemetry OTLP verification bundle".to_owned(),
                    rerun_argv: vec![
                        "bash".to_owned(),
                        "scripts/e2e/telemetry_otlp_verification.sh".to_owned(),
                    ],
                    required_env_keys: BTreeSet::new(),
                    source: source("scripts/e2e/telemetry_otlp_verification.sh", 151),
                }],
                ..ProofGraphCorpus::default()
            })
            .expect("index script source");

        assert!(
            graph
                .evidence
                .values()
                .any(|node| node.source_ref == "scripts/e2e/telemetry_otlp_verification.sh:151")
        );
    }

    #[test]
    fn shared_artifact_paths_do_not_collide_across_claims() {
        let graph = ProofGraphIndexer::new(NOW)
            .index(&ProofGraphCorpus {
                verification_scripts: vec![
                    VerificationScriptRecord {
                        claim_key: "telemetry-otlp".to_owned(),
                        script_path: "scripts/e2e/shared.sh".to_owned(),
                        purpose: "Replay telemetry proof".to_owned(),
                        rerun_argv: vec!["bash".to_owned(), "scripts/e2e/shared.sh".to_owned()],
                        required_env_keys: BTreeSet::new(),
                        source: source("scripts/e2e/shared.sh", 1),
                    },
                    VerificationScriptRecord {
                        claim_key: "secretless".to_owned(),
                        script_path: "scripts/e2e/shared.sh".to_owned(),
                        purpose: "Replay secretless proof".to_owned(),
                        rerun_argv: vec!["bash".to_owned(), "scripts/e2e/shared.sh".to_owned()],
                        required_env_keys: BTreeSet::new(),
                        source: source("scripts/e2e/shared.sh", 2),
                    },
                ],
                readiness_rows: vec![
                    ReadinessMatrixRow {
                        claim_key: "telemetry-otlp".to_owned(),
                        subject: "same-subject".to_owned(),
                        state: "pass".to_owned(),
                        truth_source: TruthSource::HostBacked,
                        rerun_argv: None,
                        source: source("crates/fwc/tests/readme_status_pinning.rs", 10),
                    },
                    ReadinessMatrixRow {
                        claim_key: "secretless".to_owned(),
                        subject: "same-subject".to_owned(),
                        state: "pass".to_owned(),
                        truth_source: TruthSource::HostBacked,
                        rerun_argv: None,
                        source: source("crates/fwc/tests/readme_status_pinning.rs", 11),
                    },
                ],
                evidence_bundles: vec![
                    EvidenceBundleRecord {
                        claim_key: "telemetry-otlp".to_owned(),
                        scenario_id: "shared-scenario".to_owned(),
                        bundle_path: "artifacts/e2e/shared".to_owned(),
                        redaction_safe: true,
                        command_count: 1,
                        live_count: 1,
                        offline_count: 0,
                        validation_argv: None,
                        source: source("artifacts/e2e/shared/manifest.json", 1),
                    },
                    EvidenceBundleRecord {
                        claim_key: "secretless".to_owned(),
                        scenario_id: "shared-scenario".to_owned(),
                        bundle_path: "artifacts/e2e/shared".to_owned(),
                        redaction_safe: true,
                        command_count: 1,
                        live_count: 1,
                        offline_count: 0,
                        validation_argv: None,
                        source: source("artifacts/e2e/shared/manifest.json", 2),
                    },
                ],
                ..ProofGraphCorpus::default()
            })
            .expect("index shared artifact paths");

        assert_eq!(graph.claims.len(), 2);
        assert_eq!(graph.evidence.len(), 6);
    }

    #[test]
    fn agent_readiness_mail_failure_links_to_blocker_bead_without_greenwash() {
        let graph = ProofGraphIndexer::new(NOW)
            .index(&ProofGraphCorpus {
                agent_readiness_reports: vec![readiness_record(
                    "agent-readiness-mail",
                    "mail-db-error",
                    NoNetworkProbeScenario::AgentMailUnavailable,
                    Some(vec![
                        "fwc",
                        "agent-readiness",
                        "replay",
                        "--report",
                        "artifacts/readiness/mail-db-error/report.json",
                    ]),
                )],
                ..ProofGraphCorpus::default()
            })
            .expect("index readiness mail failure");

        let claim_id = ClaimId::new("claim:agent-readiness-mail").unwrap();
        let claim = graph.claims.get(&claim_id).expect("readiness claim");
        assert!(matches!(
            &claim.status,
            ClaimStatus::Blocked { reason } if reason == "agent-mail-db-error"
        ));
        assert!(claim.proof_gaps.iter().any(|gap| gap.id.to_string()
            == "gap:agent-readiness-mail:blocker:flywheel_connectors-d5yeb"
            && gap.status == ProofGapStatus::Blocked));

        let blocker = graph
            .evidence
            .values()
            .find(|node| {
                node.id
                    .as_str()
                    .contains("agent-readiness-blocker:mail-db-error:flywheel_connectors-d5yeb")
            })
            .expect("d5yeb blocker evidence");
        assert_eq!(
            blocker.rerun_command.as_ref().expect("blocker rerun").argv,
            vec!["br", "show", "flywheel_connectors-d5yeb", "--json"]
        );
        assert!(graph.support_edges.iter().any(|edge| {
            edge.claim_id == claim_id
                && edge.evidence_id == blocker.id
                && edge.relationship == SupportRelationship::DoesNotSupport
        }));
    }

    #[test]
    fn agent_readiness_rch_and_disk_blockers_route_to_rfbrc() {
        let graph = ProofGraphIndexer::new(NOW)
            .index(&ProofGraphCorpus {
                agent_readiness_reports: vec![
                    readiness_record(
                        "agent-readiness-rch",
                        "rch-unavailable",
                        NoNetworkProbeScenario::RchUnavailable,
                        None,
                    ),
                    disk_pressure_record(),
                ],
                ..ProofGraphCorpus::default()
            })
            .expect("index readiness proof blockers");

        for claim_tail in ["agent-readiness-rch", "agent-readiness-disk-pressure"] {
            let claim_id = ClaimId::new(format!("claim:{claim_tail}")).unwrap();
            let claim = graph.claims.get(&claim_id).expect("readiness claim");
            assert!(matches!(&claim.status, ClaimStatus::Blocked { .. }));
            assert!(
                claim.proof_gaps.iter().any(|gap| {
                    gap.id.to_string()
                        == format!("gap:{claim_tail}:blocker:flywheel_connectors-rfbrc")
                        && gap.status == ProofGapStatus::Blocked
                }),
                "{claim_tail} should link rfbrc as blocker proof debt"
            );
        }

        assert!(
            graph
                .evidence
                .values()
                .filter(|node| {
                    node.id.as_str().contains("agent-readiness-blocker")
                        && node.rerun_command.as_ref().is_some_and(|command| {
                            command.argv
                                == vec![
                                    "br".to_owned(),
                                    "show".to_owned(),
                                    "flywheel_connectors-rfbrc".to_owned(),
                                    "--json".to_owned(),
                                ]
                        })
                })
                .count()
                >= 2
        );
    }
}
