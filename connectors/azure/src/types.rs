use fcp_prelude::CredentialId;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

#[derive(Clone, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum AzureAuth {
    BearerToken { bearer_token: String },
    CredentialId { credential_id: CredentialId },
}

impl AzureAuth {
    #[must_use]
    pub const fn redacted_label(&self) -> &'static str {
        match self {
            Self::BearerToken { .. } => "bearer_token",
            Self::CredentialId { .. } => "credential_id",
        }
    }

    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId { .. })
    }
}

impl std::fmt::Debug for AzureAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BearerToken { .. } => f
                .debug_struct("BearerToken")
                .field("bearer_token", &"[REDACTED]")
                .finish(),
            Self::CredentialId { credential_id } => f
                .debug_struct("CredentialId")
                .field("credential_id", credential_id)
                .finish(),
        }
    }
}

// ---------------------------------------------------------------------------
// Azure Resource Manager responses
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriptionListResponse {
    #[serde(default)]
    pub value: Vec<Subscription>,
    #[serde(default, rename = "nextLink")]
    pub next_link: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subscription {
    #[serde(default, rename = "subscriptionId")]
    pub subscription_id: Option<String>,
    #[serde(default, rename = "displayName")]
    pub display_name: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default, rename = "tenantId")]
    pub tenant_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceGroupListResponse {
    #[serde(default)]
    pub value: Vec<ResourceGroup>,
    #[serde(default, rename = "nextLink")]
    pub next_link: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceGroup {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub location: Option<String>,
    #[serde(default)]
    pub tags: Option<serde_json::Value>,
    #[serde(default)]
    pub properties: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceListResponse {
    #[serde(default)]
    pub value: Vec<Resource>,
    #[serde(default, rename = "nextLink")]
    pub next_link: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Resource {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default, rename = "type")]
    pub resource_type: Option<String>,
    #[serde(default)]
    pub location: Option<String>,
    #[serde(default)]
    pub tags: Option<serde_json::Value>,
}

// ---------------------------------------------------------------------------
// Blob Storage responses (XML-based, but we use JSON REST where possible)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobContainerListResponse {
    #[serde(default)]
    pub containers: Vec<BlobContainer>,
    #[serde(default)]
    pub next_marker: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobContainer {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub last_modified: Option<String>,
    #[serde(default, rename = "publicAccess")]
    pub public_access: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobListResponse {
    #[serde(default)]
    pub blobs: Vec<BlobItem>,
    #[serde(default)]
    pub next_marker: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobItem {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub content_length: Option<u64>,
    #[serde(default)]
    pub content_type: Option<String>,
    #[serde(default)]
    pub last_modified: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobGetResponse {
    #[serde(default)]
    pub content_base64: Option<String>,
    #[serde(default)]
    pub content_type: Option<String>,
    #[serde(default)]
    pub content_length: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobPutResponse {
    pub created: bool,
    #[serde(default)]
    pub blob_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobDeleteResponse {
    pub deleted: bool,
    #[serde(default)]
    pub blob_name: Option<String>,
}

// ---------------------------------------------------------------------------
// Key Vault responses
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretListResponse {
    #[serde(default)]
    pub value: Vec<SecretItem>,
    #[serde(default, rename = "nextLink")]
    pub next_link: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretItem {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub attributes: Option<SecretAttributes>,
    #[serde(default)]
    pub tags: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretAttributes {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub created: Option<u64>,
    #[serde(default)]
    pub updated: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretBundle {
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub attributes: Option<SecretAttributes>,
    #[serde(default)]
    pub tags: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetSecretRequest {
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attributes: Option<SetSecretAttributes>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetSecretAttributes {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
}

// ---------------------------------------------------------------------------
// Error response (shared across ARM / Blob / KeyVault)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorResponse {
    #[serde(default)]
    pub error: Option<ApiErrorDetail>,
    #[serde(default)]
    pub message: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorDetail {
    #[serde(default)]
    pub code: Option<String>,
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn azure_auth_debug_redacts_bearer_token() {
        let auth = AzureAuth::BearerToken {
            bearer_token: "redacted-auth-material".into(),
        };
        let debug = format!("{auth:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("redacted-auth-material"));
    }

    #[test]
    fn azure_auth_reports_secretless_mode() {
        let auth = AzureAuth::CredentialId {
            credential_id: CredentialId::parse("12345678-1234-5678-1234-567812345678").unwrap(),
        };
        assert_eq!(auth.redacted_label(), "credential_id");
        assert!(auth.is_secretless());
    }

    #[test]
    fn bearer_token_is_not_secretless() {
        let auth = AzureAuth::BearerToken {
            bearer_token: "tok".into(),
        };
        assert!(!auth.is_secretless());
        assert_eq!(auth.redacted_label(), "bearer_token");
    }

    #[test]
    fn subscription_list_deserializes() {
        let json = serde_json::json!({
            "value": [
                {
                    "subscriptionId": "sub-123",
                    "displayName": "My Sub",
                    "state": "Enabled",
                    "tenantId": "tenant-abc"
                }
            ],
            "nextLink": null
        });
        let resp: SubscriptionListResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.value.len(), 1);
        assert_eq!(resp.value[0].subscription_id.as_deref(), Some("sub-123"));
        assert_eq!(resp.value[0].display_name.as_deref(), Some("My Sub"));
    }

    #[test]
    fn resource_group_list_deserializes() {
        let json = serde_json::json!({
            "value": [
                {
                    "id": "/subscriptions/sub-1/resourceGroups/rg-1",
                    "name": "rg-1",
                    "location": "eastus"
                }
            ]
        });
        let resp: ResourceGroupListResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.value.len(), 1);
        assert_eq!(resp.value[0].name.as_deref(), Some("rg-1"));
    }

    #[test]
    fn resource_list_deserializes() {
        let json = serde_json::json!({
            "value": [
                {
                    "id": "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Compute/virtualMachines/vm-1",
                    "name": "vm-1",
                    "type": "Microsoft.Compute/virtualMachines",
                    "location": "westus2"
                }
            ]
        });
        let resp: ResourceListResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.value.len(), 1);
        assert_eq!(resp.value[0].name.as_deref(), Some("vm-1"));
        assert_eq!(
            resp.value[0].resource_type.as_deref(),
            Some("Microsoft.Compute/virtualMachines")
        );
    }

    #[test]
    fn blob_container_list_deserializes() {
        let json = serde_json::json!({
            "containers": [
                { "name": "my-container", "last_modified": "2024-01-01T00:00:00Z" }
            ]
        });
        let resp: BlobContainerListResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.containers.len(), 1);
        assert_eq!(resp.containers[0].name.as_deref(), Some("my-container"));
    }

    #[test]
    fn blob_item_list_deserializes() {
        let json = serde_json::json!({
            "blobs": [
                {
                    "name": "file.txt",
                    "content_length": 1024,
                    "content_type": "text/plain"
                }
            ]
        });
        let resp: BlobListResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.blobs.len(), 1);
        assert_eq!(resp.blobs[0].name.as_deref(), Some("file.txt"));
        assert_eq!(resp.blobs[0].content_length, Some(1024));
    }

    #[test]
    fn secret_list_deserializes() {
        let json = serde_json::json!({
            "value": [
                {
                    "id": "https://myvault.vault.azure.net/secrets/my-secret",
                    "attributes": { "enabled": true, "created": 1_700_000_000 }
                }
            ]
        });
        let resp: SecretListResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.value.len(), 1);
        assert!(resp.value[0].id.as_deref().unwrap().contains("my-secret"));
    }

    #[test]
    fn secret_bundle_deserializes() {
        let json = serde_json::json!({
            "value": "redacted-vault-value",
            "id": "https://myvault.vault.azure.net/secrets/my-secret/abc123",
            "attributes": { "enabled": true }
        });
        let bundle: SecretBundle = serde_json::from_value(json).unwrap();
        assert_eq!(bundle.value.as_deref(), Some("redacted-vault-value"));
    }

    #[test]
    fn set_secret_request_serializes() {
        let req = SetSecretRequest {
            value: "my-value".into(),
            tags: Some(serde_json::json!({ "env": "prod" })),
            content_type: Some("text/plain".into()),
            attributes: Some(SetSecretAttributes {
                enabled: Some(true),
            }),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["value"], "my-value");
        assert_eq!(json["tags"]["env"], "prod");
        assert_eq!(json["content_type"], "text/plain");
    }

    #[test]
    fn set_secret_request_omits_none_fields() {
        let req = SetSecretRequest {
            value: "val".into(),
            tags: None,
            content_type: None,
            attributes: None,
        };
        let json = serde_json::to_value(&req).unwrap();
        assert!(json.get("tags").is_none());
        assert!(json.get("content_type").is_none());
        assert!(json.get("attributes").is_none());
    }

    #[test]
    fn api_error_response_deserializes() {
        let json = serde_json::json!({
            "error": {
                "code": "AuthorizationFailed",
                "message": "The client does not have permission"
            }
        });
        let resp: ApiErrorResponse = serde_json::from_value(json).unwrap();
        assert_eq!(
            resp.error.as_ref().unwrap().code.as_deref(),
            Some("AuthorizationFailed")
        );
    }
}
