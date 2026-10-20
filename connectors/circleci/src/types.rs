//! `CircleCI` API types.

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Pipeline types
// ─────────────────────────────────────────────────────────────────────────────

/// Pipeline representation from `CircleCI` API v2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pipeline {
    pub id: String,
    #[serde(default)]
    pub project_slug: String,
    #[serde(default)]
    pub number: u64,
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trigger: Option<PipelineTrigger>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vcs: Option<PipelineVcs>,
}

/// Pipeline trigger metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineTrigger {
    #[serde(rename = "type")]
    pub trigger_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub received_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor: Option<TriggerActor>,
}

/// Actor who triggered a pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriggerActor {
    pub login: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_url: Option<String>,
}

/// VCS info associated with a pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineVcs {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin_repository_url: Option<String>,
}

/// Request body for triggering a pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriggerPipelineRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    #[serde(default, skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub parameters: std::collections::HashMap<String, serde_json::Value>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Workflow types
// ─────────────────────────────────────────────────────────────────────────────

/// Workflow representation from `CircleCI` API v2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Workflow {
    pub id: String,
    pub name: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stopped_at: Option<String>,
    pub pipeline_id: String,
    pub pipeline_number: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_slug: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Job types
// ─────────────────────────────────────────────────────────────────────────────

/// Job representation from `CircleCI` API v2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Job {
    pub id: String,
    pub name: String,
    pub status: String,
    #[serde(rename = "type")]
    pub job_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stopped_at: Option<String>,
    pub job_number: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_slug: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Project types
// ─────────────────────────────────────────────────────────────────────────────

/// Project representation from `CircleCI` API v2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Project {
    pub slug: String,
    pub name: String,
    pub organization_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vcs_info: Option<ProjectVcsInfo>,
}

/// VCS info for a project.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectVcsInfo {
    pub vcs_url: String,
    pub provider: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_branch: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// API response types
// ─────────────────────────────────────────────────────────────────────────────

/// Paginated list response from `CircleCI`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginatedResponse<T> {
    pub items: Vec<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_page_token: Option<String>,
}

/// `CircleCI` API error response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiErrorResponse {
    pub message: String,
}

/// Simple status message response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageResponse {
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipeline_deserialization() {
        let json = serde_json::json!({
            "id": "pipeline-123",
            "project_slug": "gh/org/repo",
            "number": 42,
            "state": "created",
            "created_at": "2026-01-01T00:00:00Z",
            "trigger": {
                "type": "api",
                "received_at": "2026-01-01T00:00:00Z",
                "actor": {
                    "login": "user1",
                    "avatar_url": "https://example.com/avatar.png"
                }
            },
            "vcs": {
                "branch": "main",
                "revision": "abc123",
                "provider_name": "GitHub"
            }
        });
        let pipeline: Pipeline = serde_json::from_value(json).unwrap();
        assert_eq!(pipeline.id, "pipeline-123");
        assert_eq!(pipeline.number, 42);
        assert_eq!(pipeline.state, "created");
        assert!(pipeline.trigger.is_some());
        assert!(pipeline.vcs.is_some());
    }

    #[test]
    fn workflow_deserialization() {
        let json = serde_json::json!({
            "id": "wf-123",
            "name": "build-and-test",
            "status": "running",
            "created_at": "2026-01-01T00:00:00Z",
            "pipeline_id": "pipeline-123",
            "pipeline_number": 42
        });
        let wf: Workflow = serde_json::from_value(json).unwrap();
        assert_eq!(wf.id, "wf-123");
        assert_eq!(wf.name, "build-and-test");
        assert_eq!(wf.status, "running");
    }

    #[test]
    fn job_deserialization() {
        let json = serde_json::json!({
            "id": "job-123",
            "name": "test",
            "status": "success",
            "type": "build",
            "started_at": "2026-01-01T00:00:00Z",
            "stopped_at": "2026-01-01T00:05:00Z",
            "job_number": 7
        });
        let job: Job = serde_json::from_value(json).unwrap();
        assert_eq!(job.id, "job-123");
        assert_eq!(job.status, "success");
        assert_eq!(job.job_number, 7);
    }

    #[test]
    fn project_deserialization() {
        let json = serde_json::json!({
            "slug": "gh/org/repo",
            "name": "repo",
            "organization_name": "org",
            "vcs_info": {
                "vcs_url": "https://github.com/org/repo",
                "provider": "GitHub",
                "default_branch": "main"
            }
        });
        let proj: Project = serde_json::from_value(json).unwrap();
        assert_eq!(proj.slug, "gh/org/repo");
        assert_eq!(proj.name, "repo");
    }

    #[test]
    fn paginated_response_deserialization() {
        let json = serde_json::json!({
            "items": [
                { "id": "p1", "project_slug": "gh/org/repo", "number": 1, "state": "created" }
            ],
            "next_page_token": "token123"
        });
        let resp: PaginatedResponse<Pipeline> = serde_json::from_value(json).unwrap();
        assert_eq!(resp.items.len(), 1);
        assert_eq!(resp.next_page_token, Some("token123".into()));
    }

    #[test]
    fn trigger_pipeline_request_serialization() {
        let req = TriggerPipelineRequest {
            branch: Some("main".into()),
            tag: None,
            parameters: std::collections::HashMap::new(),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["branch"], "main");
        assert!(json.get("tag").is_none());
        assert!(json.get("parameters").is_none()); // empty map skipped
    }

    #[test]
    fn api_error_deserialization() {
        let json = serde_json::json!({
            "message": "Not Found"
        });
        let err: ApiErrorResponse = serde_json::from_value(json).unwrap();
        assert_eq!(err.message, "Not Found");
    }

    #[test]
    fn pipeline_minimal_deserialization() {
        let json = serde_json::json!({
            "id": "p1",
            "state": "created"
        });
        let pipeline: Pipeline = serde_json::from_value(json).unwrap();
        assert_eq!(pipeline.id, "p1");
        assert_eq!(pipeline.number, 0); // default
    }

    #[test]
    fn workflow_with_project_slug() {
        let json = serde_json::json!({
            "id": "wf-1",
            "name": "deploy",
            "status": "success",
            "pipeline_id": "p1",
            "pipeline_number": 1,
            "project_slug": "gh/org/repo"
        });
        let wf: Workflow = serde_json::from_value(json).unwrap();
        assert_eq!(wf.project_slug, Some("gh/org/repo".into()));
    }

    #[test]
    fn trigger_with_parameters() {
        let mut params = std::collections::HashMap::new();
        params.insert("deploy_env".into(), serde_json::json!("staging"));
        let req = TriggerPipelineRequest {
            branch: Some("develop".into()),
            tag: None,
            parameters: params,
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["parameters"]["deploy_env"], "staging");
    }
}
