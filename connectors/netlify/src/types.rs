use serde::{Deserialize, Serialize};

// Auth

/// Netlify authentication via personal access token.
#[derive(Clone, Deserialize)]
pub struct NetlifyAuth {
    pub access_token: String,
}

impl NetlifyAuth {
    #[must_use]
    pub fn is_secretless(&self) -> bool {
        self.access_token.trim().is_empty()
    }
}

impl std::fmt::Debug for NetlifyAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetlifyAuth")
            .field("access_token", &"[REDACTED]")
            .finish()
    }
}

// Sites

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Site {
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub ssl_url: Option<String>,
    #[serde(default)]
    pub admin_url: Option<String>,
    #[serde(default)]
    pub custom_domain: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub updated_at: Option<String>,
    #[serde(default)]
    pub managed_dns: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateSiteRequest {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_domain: Option<String>,
}

// Deploys

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Deploy {
    pub id: String,
    #[serde(default)]
    pub site_id: String,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub ssl_url: Option<String>,
    #[serde(default)]
    pub deploy_url: Option<String>,
    #[serde(default)]
    pub admin_url: Option<String>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub updated_at: Option<String>,
    #[serde(default)]
    pub branch: Option<String>,
    #[serde(default)]
    pub commit_ref: Option<String>,
    #[serde(default)]
    pub title: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateDeployRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RollbackDeployRequest {
    pub deploy_id: String,
}

// DNS Zones

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DnsZone {
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub site_id: Option<String>,
    #[serde(default)]
    pub account_id: Option<String>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub updated_at: Option<String>,
    #[serde(default)]
    pub records: Option<Vec<serde_json::Value>>,
    #[serde(default)]
    pub dns_servers: Option<Vec<String>>,
}

// Environment Variables

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EnvVar {
    pub key: String,
    #[serde(default)]
    pub scopes: Option<Vec<String>>,
    #[serde(default)]
    pub values: Option<Vec<EnvVarValue>>,
    #[serde(default)]
    pub updated_at: Option<String>,
    #[serde(default)]
    pub updated_by: Option<serde_json::Value>,
    #[serde(default)]
    pub is_secret: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EnvVarValue {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub value: String,
    #[serde(default)]
    pub context: Option<String>,
    #[serde(default)]
    pub role: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SetEnvVarRequest {
    pub key: String,
    pub values: Vec<SetEnvVarValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_secret: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SetEnvVarValue {
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
}

// User (for health check)

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct User {
    pub id: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub full_name: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_auth_value() -> String {
        ["sample", "netlify", "access"].join("-")
    }

    #[test]
    fn deserialize_site() {
        let json = serde_json::json!({
            "id": "site-123",
            "name": "my-site",
            "url": "https://my-site.netlify.app",
            "state": "current",
            "created_at": "2026-01-01T00:00:00Z"
        });
        let site: Site = serde_json::from_value(json).unwrap();
        assert_eq!(site.id, "site-123");
        assert_eq!(site.name, "my-site");
        assert_eq!(site.state.as_deref(), Some("current"));
    }

    #[test]
    fn deserialize_deploy() {
        let json = serde_json::json!({
            "id": "deploy-456",
            "site_id": "site-123",
            "state": "ready",
            "branch": "main",
            "title": "Production deploy"
        });
        let deploy: Deploy = serde_json::from_value(json).unwrap();
        assert_eq!(deploy.id, "deploy-456");
        assert_eq!(deploy.site_id, "site-123");
        assert_eq!(deploy.branch.as_deref(), Some("main"));
    }

    #[test]
    fn deserialize_dns_zone() {
        let json = serde_json::json!({
            "id": "zone-789",
            "name": "example.com",
            "dns_servers": ["dns1.p01.nsone.net", "dns2.p01.nsone.net"]
        });
        let zone: DnsZone = serde_json::from_value(json).unwrap();
        assert_eq!(zone.id, "zone-789");
        assert_eq!(zone.name, "example.com");
        assert_eq!(zone.dns_servers.unwrap().len(), 2);
    }

    #[test]
    fn deserialize_env_var() {
        let json = serde_json::json!({
            "key": "DATABASE_URL",
            "scopes": ["builds", "functions"],
            "is_secret": true,
            "values": [{
                "id": "val-1",
                "value": "postgres://...",
                "context": "production"
            }]
        });
        let env: EnvVar = serde_json::from_value(json).unwrap();
        assert_eq!(env.key, "DATABASE_URL");
        assert!(env.is_secret.unwrap());
        assert_eq!(env.values.unwrap().len(), 1);
    }

    #[test]
    fn deserialize_user() {
        let json = serde_json::json!({
            "id": "user-1",
            "email": "dev@example.com",
            "full_name": "Test User"
        });
        let user: User = serde_json::from_value(json).unwrap();
        assert_eq!(user.id, "user-1");
        assert_eq!(user.email.as_deref(), Some("dev@example.com"));
    }

    #[test]
    fn auth_debug_redacts_token() {
        let auth_value = sample_auth_value();
        let auth = NetlifyAuth {
            access_token: auth_value.clone(),
        };
        let debug = format!("{auth:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(&auth_value));
    }

    #[test]
    fn auth_secretless_detects_empty() {
        let empty = NetlifyAuth {
            access_token: "  ".into(),
        };
        assert!(empty.is_secretless());

        let configured_auth = NetlifyAuth {
            access_token: sample_auth_value(),
        };
        assert!(!configured_auth.is_secretless());
    }

    #[test]
    fn serialize_create_site_request() {
        let req = CreateSiteRequest {
            name: "my-site".into(),
            custom_domain: Some("example.com".into()),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["name"], "my-site");
        assert_eq!(json["custom_domain"], "example.com");
    }

    #[test]
    fn serialize_create_site_request_no_domain() {
        let req = CreateSiteRequest {
            name: "my-site".into(),
            custom_domain: None,
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["name"], "my-site");
        assert!(json.get("custom_domain").is_none());
    }

    #[test]
    fn serialize_set_env_var_request() {
        let req = SetEnvVarRequest {
            key: "API_KEY".into(),
            values: vec![SetEnvVarValue {
                value: "secret123".into(),
                context: Some("production".into()),
            }],
            scopes: Some(vec!["builds".into()]),
            is_secret: Some(true),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["key"], "API_KEY");
        assert_eq!(json["values"][0]["value"], "secret123");
    }

    #[test]
    fn serialize_create_deploy_request() {
        let req = CreateDeployRequest {
            branch: Some("staging".into()),
            title: Some("Test deploy".into()),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["branch"], "staging");
        assert_eq!(json["title"], "Test deploy");
    }

    #[test]
    fn serialize_create_deploy_request_minimal() {
        let req = CreateDeployRequest {
            branch: None,
            title: None,
        };
        let json = serde_json::to_value(&req).unwrap();
        assert!(json.get("branch").is_none());
    }
}
