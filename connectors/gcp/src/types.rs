use serde::{Deserialize, Serialize};

// ── Auth ──

/// Scopes used for JWT assertion when none are explicitly configured.
pub(crate) const DEFAULT_GCP_SCOPES: &str = "https://www.googleapis.com/auth/cloud-platform";

/// GCP authentication mode.
#[derive(Clone, Deserialize)]
#[serde(tag = "mode")]
pub enum GcpAuth {
    /// Bearer access token (recommended for simplified auth).
    #[serde(rename = "access_token")]
    AccessToken { access_token: String },
    /// Service account JSON key (`client_email`, `private_key`).
    /// The `project_id` is provided at the top-level config, not duplicated here.
    #[serde(rename = "service_account")]
    ServiceAccount {
        client_email: String,
        private_key: String,
    },
}

impl GcpAuth {
    #[must_use]
    pub const fn auth_mode(&self) -> &'static str {
        match self {
            Self::AccessToken { .. } => "access_token",
            Self::ServiceAccount { .. } => "service_account",
        }
    }

    #[must_use]
    pub fn is_secretless(&self) -> bool {
        match self {
            Self::AccessToken { access_token } => access_token.trim().is_empty(),
            Self::ServiceAccount { private_key, .. } => private_key.trim().is_empty(),
        }
    }

    #[must_use]
    pub const fn redacted_label(&self) -> &'static str {
        match self {
            Self::AccessToken { .. } => "access_token",
            Self::ServiceAccount { .. } => "service_account",
        }
    }

    #[must_use]
    pub const fn is_service_account(&self) -> bool {
        matches!(self, Self::ServiceAccount { .. })
    }

    /// Returns the static bearer token for `access_token` mode.
    ///
    /// For `access_token` mode, returns the token directly.
    /// For `service_account` mode, returns `None` — the caller must use
    /// the JWT-based token exchange flow via [`crate::client::GcpClient`].
    #[must_use]
    pub fn static_bearer_token(&self) -> Option<&str> {
        match self {
            Self::AccessToken { access_token } => Some(access_token),
            Self::ServiceAccount { .. } => None,
        }
    }

    /// Returns the service-account credentials if in `service_account` mode.
    #[must_use]
    pub fn service_account_credentials(&self) -> Option<(&str, &str)> {
        match self {
            Self::ServiceAccount {
                client_email,
                private_key,
            } => Some((client_email, private_key)),
            Self::AccessToken { .. } => None,
        }
    }
}

impl std::fmt::Debug for GcpAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AccessToken { .. } => f
                .debug_struct("AccessToken")
                .field("access_token", &"[REDACTED]")
                .finish(),
            Self::ServiceAccount { client_email, .. } => f
                .debug_struct("ServiceAccount")
                .field("client_email", client_email)
                .field("private_key", &"[REDACTED]")
                .finish(),
        }
    }
}

// ── Compute Engine ──

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Instance {
    pub id: Option<String>,
    pub name: String,
    pub status: Option<String>,
    #[serde(rename = "machineType")]
    pub machine_type: Option<String>,
    pub zone: Option<String>,
    #[serde(rename = "creationTimestamp")]
    pub creation_timestamp: Option<String>,
    #[serde(rename = "selfLink")]
    pub self_link: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct InstanceList {
    pub items: Option<Vec<Instance>>,
    #[serde(rename = "nextPageToken")]
    pub next_page_token: Option<String>,
}

// ── Cloud Storage ──

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StorageObject {
    pub name: String,
    pub bucket: Option<String>,
    pub size: Option<String>,
    #[serde(rename = "contentType")]
    pub content_type: Option<String>,
    pub updated: Option<String>,
    #[serde(rename = "selfLink")]
    pub self_link: Option<String>,
    pub generation: Option<String>,
    #[serde(rename = "metageneration")]
    pub meta_generation: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ObjectList {
    pub items: Option<Vec<StorageObject>>,
    #[serde(rename = "nextPageToken")]
    pub next_page_token: Option<String>,
}

// ── Cloud Run ──

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CloudRunService {
    pub name: Option<String>,
    pub uid: Option<String>,
    pub generation: Option<String>,
    #[serde(rename = "createTime")]
    pub create_time: Option<String>,
    #[serde(rename = "updateTime")]
    pub update_time: Option<String>,
    pub uri: Option<String>,
    #[serde(rename = "reconciling")]
    pub reconciling: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CloudRunServiceList {
    pub services: Option<Vec<CloudRunService>>,
    #[serde(rename = "nextPageToken")]
    pub next_page_token: Option<String>,
}

// ── Projects ──

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Project {
    #[serde(rename = "projectId")]
    pub project_id: Option<String>,
    #[serde(rename = "projectNumber")]
    pub project_number: Option<String>,
    pub name: Option<String>,
    #[serde(rename = "lifecycleState")]
    pub lifecycle_state: Option<String>,
    #[serde(rename = "createTime")]
    pub create_time: Option<String>,
}

// ── GCP API error ──

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GcpApiError {
    pub error: Option<GcpErrorDetail>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GcpErrorDetail {
    pub code: Option<u32>,
    pub message: Option<String>,
    pub status: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_instance() {
        let json = serde_json::json!({
            "id": "123456",
            "name": "my-instance",
            "status": "RUNNING",
            "machineType": "zones/us-central1-a/machineTypes/e2-medium",
            "zone": "projects/my-project/zones/us-central1-a",
            "creationTimestamp": "2026-01-01T00:00:00.000-07:00"
        });
        let inst: Instance = serde_json::from_value(json).unwrap();
        assert_eq!(inst.name, "my-instance");
        assert_eq!(inst.status.unwrap(), "RUNNING");
        assert_eq!(inst.id.unwrap(), "123456");
    }

    #[test]
    fn deserialize_instance_list() {
        let json = serde_json::json!({
            "items": [{
                "id": "1",
                "name": "vm-1",
                "status": "RUNNING"
            }, {
                "id": "2",
                "name": "vm-2",
                "status": "TERMINATED"
            }]
        });
        let list: InstanceList = serde_json::from_value(json).unwrap();
        let items = list.items.unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].name, "vm-1");
        assert_eq!(items[1].name, "vm-2");
    }

    #[test]
    fn deserialize_storage_object() {
        let json = serde_json::json!({
            "name": "path/to/file.txt",
            "bucket": "my-bucket",
            "size": "1024",
            "contentType": "text/plain",
            "updated": "2026-01-01T00:00:00.000Z"
        });
        let obj: StorageObject = serde_json::from_value(json).unwrap();
        assert_eq!(obj.name, "path/to/file.txt");
        assert_eq!(obj.bucket.unwrap(), "my-bucket");
        assert_eq!(obj.size.unwrap(), "1024");
    }

    #[test]
    fn deserialize_object_list() {
        let json = serde_json::json!({
            "items": [{
                "name": "obj1.txt",
                "bucket": "b1"
            }],
            "nextPageToken": "token123"
        });
        let list: ObjectList = serde_json::from_value(json).unwrap();
        assert_eq!(list.items.unwrap().len(), 1);
        assert_eq!(list.next_page_token.unwrap(), "token123");
    }

    #[test]
    fn deserialize_cloud_run_service() {
        let json = serde_json::json!({
            "name": "projects/p/locations/us-central1/services/my-svc",
            "uid": "abc-123",
            "uri": "https://my-svc-xyz.run.app",
            "reconciling": false
        });
        let svc: CloudRunService = serde_json::from_value(json).unwrap();
        assert!(svc.name.unwrap().contains("my-svc"));
        assert!(!svc.reconciling.unwrap());
    }

    #[test]
    fn deserialize_project() {
        let json = serde_json::json!({
            "projectId": "my-project",
            "projectNumber": "123456789",
            "name": "My Project",
            "lifecycleState": "ACTIVE"
        });
        let proj: Project = serde_json::from_value(json).unwrap();
        assert_eq!(proj.project_id.unwrap(), "my-project");
        assert_eq!(proj.lifecycle_state.unwrap(), "ACTIVE");
    }

    #[test]
    fn deserialize_gcp_api_error() {
        let json = serde_json::json!({
            "error": {
                "code": 403,
                "message": "Access denied",
                "status": "PERMISSION_DENIED"
            }
        });
        let err: GcpApiError = serde_json::from_value(json).unwrap();
        let detail = err.error.unwrap();
        assert_eq!(detail.code.unwrap(), 403);
        assert_eq!(detail.message.unwrap(), "Access denied");
    }

    #[test]
    fn auth_debug_redacts_secrets() {
        let token_auth = GcpAuth::AccessToken {
            access_token: "ya29.super-secret-token".into(),
        };
        let debug = format!("{token_auth:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("ya29"));

        let sa_auth = GcpAuth::ServiceAccount {
            client_email: "svc@project.iam.gserviceaccount.com".into(),
            private_key: "-----BEGIN RSA PRIVATE KEY-----\nMIIE...".into(),
        };
        let debug = format!("{sa_auth:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(debug.contains("svc@project.iam.gserviceaccount.com"));
        assert!(!debug.contains("BEGIN RSA"));
    }

    #[test]
    fn auth_helpers_report_mode_and_redacted_label() {
        let token_auth = GcpAuth::AccessToken {
            access_token: "token".into(),
        };
        assert_eq!(token_auth.auth_mode(), "access_token");
        assert_eq!(token_auth.redacted_label(), "access_token");
        assert!(!token_auth.is_service_account());

        let sa_auth = GcpAuth::ServiceAccount {
            client_email: "svc@p.iam.gserviceaccount.com".into(),
            private_key: "key".into(),
        };
        assert_eq!(sa_auth.auth_mode(), "service_account");
        assert_eq!(sa_auth.redacted_label(), "service_account");
        assert!(sa_auth.is_service_account());
    }

    #[test]
    fn auth_secretless_detects_empty_material() {
        let token_auth = GcpAuth::AccessToken {
            access_token: " ".into(),
        };
        assert!(token_auth.is_secretless());

        let sa_auth = GcpAuth::ServiceAccount {
            client_email: "svc@p.iam.gserviceaccount.com".into(),
            private_key: String::new(),
        };
        assert!(sa_auth.is_secretless());
    }

    #[test]
    fn static_bearer_token_access_token_mode() {
        let token_auth = GcpAuth::AccessToken {
            access_token: "ya29.token123".into(),
        };
        assert_eq!(token_auth.static_bearer_token().unwrap(), "ya29.token123");
    }

    #[test]
    fn static_bearer_token_service_account_returns_none() {
        let sa_auth = GcpAuth::ServiceAccount {
            client_email: "test@project.iam.gserviceaccount.com".into(),
            private_key: "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----".into(),
        };
        assert!(sa_auth.static_bearer_token().is_none());
    }

    #[test]
    fn service_account_credentials_returns_email_and_key() {
        let sa_auth = GcpAuth::ServiceAccount {
            client_email: "svc@project.iam.gserviceaccount.com".into(),
            private_key: "-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----".into(),
        };
        let (email, key) = sa_auth.service_account_credentials().unwrap();
        assert_eq!(email, "svc@project.iam.gserviceaccount.com");
        assert!(key.contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn service_account_credentials_none_for_access_token() {
        let token_auth = GcpAuth::AccessToken {
            access_token: "ya29.test".into(),
        };
        assert!(token_auth.service_account_credentials().is_none());
    }

    #[test]
    fn serialize_instance() {
        let inst = Instance {
            id: Some("42".into()),
            name: "test-vm".into(),
            status: Some("RUNNING".into()),
            machine_type: Some("e2-micro".into()),
            zone: None,
            creation_timestamp: None,
            self_link: None,
        };
        let json = serde_json::to_value(&inst).unwrap();
        assert_eq!(json["name"], "test-vm");
        assert_eq!(json["id"], "42");
    }

    #[test]
    fn empty_instance_list() {
        let json = serde_json::json!({});
        let list: InstanceList = serde_json::from_value(json).unwrap();
        assert!(list.items.is_none());
    }

    #[test]
    fn empty_object_list() {
        let json = serde_json::json!({});
        let list: ObjectList = serde_json::from_value(json).unwrap();
        assert!(list.items.is_none());
    }

    #[test]
    fn cloud_run_service_list() {
        let json = serde_json::json!({
            "services": [{
                "name": "projects/p/locations/us-central1/services/svc1",
                "uid": "uid1"
            }]
        });
        let list: CloudRunServiceList = serde_json::from_value(json).unwrap();
        assert_eq!(list.services.unwrap().len(), 1);
    }
}
