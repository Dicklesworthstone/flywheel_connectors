use serde::{Deserialize, Serialize};

// ── Auth ──

/// AWS authentication credentials.
#[derive(Clone, Deserialize)]
pub struct AwsAuth {
    #[serde(default)]
    pub access_key_id: String,
    #[serde(default)]
    pub secret_access_key: String,
    #[serde(default)]
    pub session_token: Option<String>,
}

impl std::fmt::Debug for AwsAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsAuth")
            .field("access_key_id", &"[REDACTED]")
            .field("secret_access_key", &"[REDACTED]")
            .field(
                "session_token",
                &self.session_token.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

// ── S3 types ──

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct S3Bucket {
    pub name: String,
    pub creation_date: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct S3Object {
    pub key: String,
    pub size: Option<u64>,
    pub last_modified: Option<String>,
    pub etag: Option<String>,
    pub storage_class: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct S3GetObjectResponse {
    pub key: String,
    pub content_type: Option<String>,
    pub content_length: Option<u64>,
    pub etag: Option<String>,
    pub body: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct S3PutObjectResponse {
    pub etag: Option<String>,
    pub version_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct S3DeleteObjectResponse {
    pub delete_marker: bool,
    pub version_id: Option<String>,
}

// ── EC2 types ──

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Ec2Instance {
    pub instance_id: String,
    pub instance_type: Option<String>,
    pub state: Option<String>,
    pub public_ip: Option<String>,
    pub private_ip: Option<String>,
    pub launch_time: Option<String>,
    pub tags: Option<Vec<Ec2Tag>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Ec2Tag {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Ec2StateChange {
    pub instance_id: String,
    pub previous_state: String,
    pub current_state: String,
}

// ── Lambda types ──

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LambdaFunction {
    pub function_name: String,
    pub function_arn: Option<String>,
    pub runtime: Option<String>,
    pub handler: Option<String>,
    pub memory_size: Option<u32>,
    pub timeout: Option<u32>,
    pub last_modified: Option<String>,
    pub state: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LambdaInvokeResponse {
    pub status_code: u16,
    pub function_error: Option<String>,
    pub payload: serde_json::Value,
    pub executed_version: Option<String>,
}

// ── STS types ──

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CallerIdentity {
    pub account: String,
    pub arn: String,
    pub user_id: String,
}

// ── Health check ──

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HealthStatus {
    pub authenticated: bool,
    pub account: Option<String>,
    pub arn: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_ACCESS_KEY_ID: &str = "fcp-test-access-key";
    const TEST_SIGNING_MATERIAL: &str = "fcp-test-signing-material";
    const TEST_SESSION_MATERIAL: &str = "fcp-test-session-material";

    #[test]
    fn deserialize_s3_bucket() {
        let json = serde_json::json!({
            "name": "my-bucket",
            "creation_date": "2026-01-01T00:00:00Z"
        });
        let bucket: S3Bucket = serde_json::from_value(json).unwrap();
        assert_eq!(bucket.name, "my-bucket");
        assert_eq!(bucket.creation_date.unwrap(), "2026-01-01T00:00:00Z");
    }

    #[test]
    fn deserialize_s3_object() {
        let json = serde_json::json!({
            "key": "path/to/file.txt",
            "size": 1024,
            "last_modified": "2026-01-01T00:00:00Z",
            "etag": "\"abc123\"",
            "storage_class": "STANDARD"
        });
        let obj: S3Object = serde_json::from_value(json).unwrap();
        assert_eq!(obj.key, "path/to/file.txt");
        assert_eq!(obj.size.unwrap(), 1024);
        assert_eq!(obj.storage_class.unwrap(), "STANDARD");
    }

    #[test]
    fn deserialize_ec2_instance() {
        let json = serde_json::json!({
            "instance_id": "i-0123456789abcdef0",
            "instance_type": "t3.micro",
            "state": "running",
            "public_ip": "54.1.2.3",
            "private_ip": "10.0.0.5",
            "launch_time": "2026-01-01T00:00:00Z",
            "tags": [{"key": "Name", "value": "my-server"}]
        });
        let inst: Ec2Instance = serde_json::from_value(json).unwrap();
        assert_eq!(inst.instance_id, "i-0123456789abcdef0");
        assert_eq!(inst.instance_type.unwrap(), "t3.micro");
        assert_eq!(inst.state.unwrap(), "running");
        assert_eq!(inst.tags.unwrap().len(), 1);
    }

    #[test]
    fn deserialize_ec2_state_change() {
        let json = serde_json::json!({
            "instance_id": "i-abc",
            "previous_state": "stopped",
            "current_state": "pending"
        });
        let sc: Ec2StateChange = serde_json::from_value(json).unwrap();
        assert_eq!(sc.previous_state, "stopped");
        assert_eq!(sc.current_state, "pending");
    }

    #[test]
    fn deserialize_lambda_function() {
        let json = serde_json::json!({
            "function_name": "my-func",
            "function_arn": "arn:aws:lambda:us-east-1:123456789:function:my-func",
            "runtime": "nodejs20.x",
            "handler": "index.handler",
            "memory_size": 256,
            "timeout": 30,
            "state": "Active"
        });
        let func: LambdaFunction = serde_json::from_value(json).unwrap();
        assert_eq!(func.function_name, "my-func");
        assert_eq!(func.runtime.unwrap(), "nodejs20.x");
        assert_eq!(func.memory_size.unwrap(), 256);
    }

    #[test]
    fn deserialize_lambda_invoke_response() {
        let json = serde_json::json!({
            "status_code": 200,
            "function_error": null,
            "payload": {"result": "ok"},
            "executed_version": "$LATEST"
        });
        let resp: LambdaInvokeResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.status_code, 200);
        assert!(resp.function_error.is_none());
        assert_eq!(resp.payload["result"], "ok");
    }

    #[test]
    fn deserialize_caller_identity() {
        let json = serde_json::json!({
            "account": "123456789012",
            "arn": "arn:aws:iam::123456789012:user/test",
            "user_id": "AIDAEXAMPLE"
        });
        let id: CallerIdentity = serde_json::from_value(json).unwrap();
        assert_eq!(id.account, "123456789012");
        assert_eq!(id.user_id, "AIDAEXAMPLE");
    }

    #[test]
    fn auth_debug_redacts_secrets() {
        let auth = AwsAuth {
            access_key_id: TEST_ACCESS_KEY_ID.into(),
            secret_access_key: TEST_SIGNING_MATERIAL.into(),
            session_token: Some(TEST_SESSION_MATERIAL.into()),
        };
        let debug = format!("{auth:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(TEST_ACCESS_KEY_ID));
        assert!(!debug.contains(TEST_SIGNING_MATERIAL));
        assert!(!debug.contains(TEST_SESSION_MATERIAL));
    }

    #[test]
    fn auth_debug_no_session_token() {
        let auth = AwsAuth {
            access_key_id: "AKID".into(),
            secret_access_key: TEST_SIGNING_MATERIAL.into(),
            session_token: None,
        };
        let debug = format!("{auth:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(debug.contains("None"));
        assert!(!debug.contains("AKID"));
        assert!(!debug.contains(TEST_SIGNING_MATERIAL));
    }

    #[test]
    fn serialize_s3_put_response() {
        let resp = S3PutObjectResponse {
            etag: Some("\"abc\"".into()),
            version_id: None,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["etag"], "\"abc\"");
    }

    #[test]
    fn serialize_health_status() {
        let status = HealthStatus {
            authenticated: true,
            account: Some("123456789012".into()),
            arn: Some("arn:aws:iam::123456789012:user/test".into()),
        };
        let json = serde_json::to_value(&status).unwrap();
        assert!(json["authenticated"].as_bool().unwrap());
        assert_eq!(json["account"], "123456789012");
    }

    #[test]
    fn deserialize_s3_delete_response() {
        let json = serde_json::json!({
            "delete_marker": true,
            "version_id": "v1"
        });
        let resp: S3DeleteObjectResponse = serde_json::from_value(json).unwrap();
        assert!(resp.delete_marker);
        assert_eq!(resp.version_id.unwrap(), "v1");
    }
}
