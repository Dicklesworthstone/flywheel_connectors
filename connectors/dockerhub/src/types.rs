use serde::{Deserialize, Serialize};

// ── Auth ──

/// Docker Hub authentication via access token or username/password.
#[derive(Clone, Deserialize)]
#[serde(tag = "mode")]
pub enum DockerHubAuth {
    /// Personal access token (recommended).
    #[serde(rename = "token")]
    Token { access_token: String },
    /// Username and password (legacy).
    #[serde(rename = "credentials")]
    Credentials { username: String, password: String },
}

impl DockerHubAuth {
    #[must_use]
    pub const fn auth_mode(&self) -> &'static str {
        match self {
            Self::Token { .. } => "token",
            Self::Credentials { .. } => "credentials",
        }
    }

    #[must_use]
    pub fn is_secretless(&self) -> bool {
        match self {
            Self::Token { access_token } => access_token.trim().is_empty(),
            Self::Credentials { password, .. } => password.trim().is_empty(),
        }
    }
}

impl std::fmt::Debug for DockerHubAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Token { .. } => f
                .debug_struct("Token")
                .field("access_token", &"[REDACTED]")
                .finish(),
            Self::Credentials { username, .. } => f
                .debug_struct("Credentials")
                .field("username", username)
                .field("password", &"[REDACTED]")
                .finish(),
        }
    }
}

// ── Paginated response ──

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PaginatedResponse<T> {
    pub count: Option<u64>,
    pub next: Option<String>,
    pub previous: Option<String>,
    pub results: Vec<T>,
}

// ── Repositories ──

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Repository {
    pub name: String,
    pub namespace: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub is_private: Option<bool>,
    #[serde(default)]
    pub star_count: Option<u64>,
    #[serde(default)]
    pub pull_count: Option<u64>,
    #[serde(default)]
    pub last_updated: Option<String>,
    #[serde(default)]
    pub date_registered: Option<String>,
    #[serde(default)]
    pub status: Option<u32>,
    #[serde(default)]
    pub full_description: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateRepositoryRequest {
    pub namespace: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_private: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub full_description: Option<String>,
}

// ── Tags ──

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Tag {
    pub name: String,
    #[serde(default)]
    pub full_size: Option<u64>,
    #[serde(default)]
    pub images: Option<Vec<TagImage>>,
    #[serde(default)]
    pub last_updated: Option<String>,
    #[serde(default)]
    pub last_updater: Option<u64>,
    #[serde(default)]
    pub last_updater_username: Option<String>,
    #[serde(default)]
    pub tag_status: Option<String>,
    #[serde(default)]
    pub digest: Option<String>,
    #[serde(default)]
    pub content_type: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TagImage {
    #[serde(default)]
    pub architecture: Option<String>,
    #[serde(default)]
    pub os: Option<String>,
    #[serde(default)]
    pub size: Option<u64>,
    #[serde(default)]
    pub digest: Option<String>,
}

// ── Organizations ──

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Organization {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub orgname: Option<String>,
    #[serde(default)]
    pub full_name: Option<String>,
    #[serde(default)]
    pub location: Option<String>,
    #[serde(default)]
    pub company: Option<String>,
    #[serde(default)]
    pub date_joined: Option<String>,
}

// ── Login ──

#[derive(Clone, Serialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

impl std::fmt::Debug for LoginRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginRequest")
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Deserialize)]
pub struct LoginResponse {
    pub token: String,
}

impl std::fmt::Debug for LoginResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginResponse")
            .field("token", &"[REDACTED]")
            .finish()
    }
}

// ── User (health check) ──

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct User {
    pub id: String,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub full_name: Option<String>,
    #[serde(default)]
    pub date_joined: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_repository() {
        let json = serde_json::json!({
            "name": "nginx",
            "namespace": "library",
            "description": "Official Nginx image",
            "is_private": false,
            "star_count": 1000,
            "pull_count": 5_000_000
        });
        let repo: Repository = serde_json::from_value(json).unwrap();
        assert_eq!(repo.name, "nginx");
        assert_eq!(repo.namespace, "library");
        assert!(!repo.is_private.unwrap());
    }

    #[test]
    fn deserialize_tag() {
        let json = serde_json::json!({
            "name": "latest",
            "full_size": 50_000_000,
            "digest": "sha256:abc123",
            "last_updated": "2026-01-01T00:00:00Z",
            "images": [{
                "architecture": "amd64",
                "os": "linux",
                "size": 25_000_000
            }]
        });
        let tag: Tag = serde_json::from_value(json).unwrap();
        assert_eq!(tag.name, "latest");
        assert_eq!(tag.full_size.unwrap(), 50_000_000);
        assert_eq!(tag.images.unwrap().len(), 1);
    }

    #[test]
    fn deserialize_organization() {
        let json = serde_json::json!({
            "id": "myorg",
            "full_name": "My Organization",
            "company": "My Company"
        });
        let org: Organization = serde_json::from_value(json).unwrap();
        assert_eq!(org.id, "myorg");
        assert_eq!(org.full_name.as_deref(), Some("My Organization"));
    }

    #[test]
    fn deserialize_paginated_response() {
        let json = serde_json::json!({
            "count": 2,
            "next": null,
            "previous": null,
            "results": [
                {"name": "repo1", "namespace": "ns"},
                {"name": "repo2", "namespace": "ns"}
            ]
        });
        let resp: PaginatedResponse<Repository> = serde_json::from_value(json).unwrap();
        assert_eq!(resp.count.unwrap(), 2);
        assert_eq!(resp.results.len(), 2);
    }

    #[test]
    fn deserialize_user() {
        let json = serde_json::json!({
            "id": "user-1",
            "username": "testuser",
            "full_name": "Test User"
        });
        let user: User = serde_json::from_value(json).unwrap();
        assert_eq!(user.id, "user-1");
        assert_eq!(user.username.as_deref(), Some("testuser"));
    }

    #[test]
    fn auth_debug_redacts_token() {
        let auth = DockerHubAuth::Token {
            access_token: "redaction-fixture-value".into(),
        };
        let debug = format!("{auth:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("redaction-fixture-value"));
    }

    #[test]
    fn auth_debug_redacts_password() {
        let auth = DockerHubAuth::Credentials {
            username: "user".into(),
            password: "redaction-fixture-value".into(),
        };
        let debug = format!("{auth:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(debug.contains("user"));
        assert!(!debug.contains("redaction-fixture-value"));
    }

    #[test]
    fn auth_secretless_empty_token() {
        let auth = DockerHubAuth::Token {
            access_token: " ".into(),
        };
        assert!(auth.is_secretless());
    }

    #[test]
    fn auth_secretless_empty_password() {
        let auth = DockerHubAuth::Credentials {
            username: "user".into(),
            password: String::new(),
        };
        assert!(auth.is_secretless());
    }

    #[test]
    fn auth_not_secretless_with_token() {
        let auth = DockerHubAuth::Token {
            access_token: "fixture-pat-value".into(),
        };
        assert!(!auth.is_secretless());
    }

    #[test]
    fn auth_mode_token() {
        let auth = DockerHubAuth::Token {
            access_token: "t".into(),
        };
        assert_eq!(auth.auth_mode(), "token");
    }

    #[test]
    fn auth_mode_credentials() {
        let auth = DockerHubAuth::Credentials {
            username: "u".into(),
            password: "p".into(),
        };
        assert_eq!(auth.auth_mode(), "credentials");
    }

    #[test]
    fn serialize_create_repository_request() {
        let req = CreateRepositoryRequest {
            namespace: "myuser".into(),
            name: "myrepo".into(),
            description: Some("A test repo".into()),
            is_private: Some(true),
            full_description: None,
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["namespace"], "myuser");
        assert_eq!(json["name"], "myrepo");
        assert!(json.get("full_description").is_none());
    }

    #[test]
    fn serialize_login_request() {
        let req = LoginRequest {
            username: "user".into(),
            password: "pass".into(),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["username"], "user");
    }

    #[test]
    fn deserialize_login_response() {
        let json = serde_json::json!({"token": "login-response-value"});
        let resp: LoginResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.token, "login-response-value");
    }

    #[test]
    fn login_request_debug_redacts_password() {
        let req = LoginRequest {
            username: "myuser".into(),
            password: "redaction-fixture-value".into(),
        };
        let dbg = format!("{req:?}");
        assert!(dbg.contains("[REDACTED]"));
        assert!(dbg.contains("myuser"));
        assert!(!dbg.contains("redaction-fixture-value"));
    }

    #[test]
    fn login_response_debug_redacts_token() {
        let resp = LoginResponse {
            token: "redaction-fixture-value".into(),
        };
        let dbg = format!("{resp:?}");
        assert!(dbg.contains("[REDACTED]"));
        assert!(!dbg.contains("redaction-fixture-value"));
    }
}
