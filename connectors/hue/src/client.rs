//! `HTTP` client for the `Hue` bridge `API`.

use reqwest::header::{HeaderMap, HeaderValue};
use serde_json::{Value, json};

use crate::error::{HueError, HueResult};
use crate::types::{HueConfig, RecallSceneInput, SetLightStateInput};

#[derive(Clone)]
pub struct HueClient {
    client: reqwest::Client,
    bridge_url: String,
    app_key: String,
}

impl std::fmt::Debug for HueClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HueClient")
            .field("bridge_url", &self.bridge_url)
            .field("app_key", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Validate a Hue resource id before interpolating it into the CLIP v2 path.
///
/// Hue light/scene ids are UUIDs (`[0-9a-fA-F-]`). Stripping dangerous bytes
/// (the previous behavior) silently retargeted a malformed id — `a/b` became
/// `ab`, a *different* light — and let a bare `..` survive to hit the collection
/// endpoint. Rejecting instead keeps every request pinned to the addressed
/// resource and surfaces a clear error.
fn sanitize_path_segment(s: &str) -> HueResult<&str> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err(HueError::Config("resource id must not be empty".into()));
    }
    if trimmed.contains('/')
        || trimmed.contains('\\')
        || trimmed.contains("..")
        || trimmed.contains('?')
        || trimmed.contains('#')
        || trimmed.contains('&')
        || trimmed.contains('%')
        || trimmed.contains('\0')
    {
        return Err(HueError::Config(
            "resource id contains path traversal or URL control characters".into(),
        ));
    }
    Ok(trimmed)
}

impl HueClient {
    pub fn from_config(config: &HueConfig) -> HueResult<Self> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(config.request_timeout_ms))
            .danger_accept_invalid_certs(config.allow_insecure_ssl)
            .build()?;
        Ok(Self {
            client,
            bridge_url: config.normalized_bridge_url(),
            app_key: config.app_key.clone(),
        })
    }

    #[must_use]
    pub fn bridge_url(&self) -> &str {
        &self.bridge_url
    }

    fn headers(&self) -> HueResult<HeaderMap> {
        let mut headers = HeaderMap::new();
        headers.insert(
            "hue-application-key",
            HeaderValue::from_str(&self.app_key)
                .map_err(|error| HueError::Config(error.to_string()))?,
        );
        Ok(headers)
    }

    async fn decode_response(response: reqwest::Response) -> HueResult<Value> {
        let status = response.status();
        let body = response.text().await?;
        if !status.is_success() {
            let truncated = if body.len() > 500 {
                format!("{}...[truncated]", &body[..500])
            } else {
                body
            };
            return Err(HueError::Api {
                status: status.as_u16(),
                message: truncated,
            });
        }
        Ok(serde_json::from_str(&body).unwrap_or_else(|_| json!({ "body": body })))
    }

    pub async fn health(&self) -> HueResult<Value> {
        let response = self
            .client
            .get(format!("{}/clip/v2/resource/bridge", self.bridge_url))
            .headers(self.headers()?)
            .send()
            .await?;
        Self::decode_response(response).await
    }

    pub async fn list_lights(&self) -> HueResult<Value> {
        let response = self
            .client
            .get(format!("{}/clip/v2/resource/light", self.bridge_url))
            .headers(self.headers()?)
            .send()
            .await?;
        Self::decode_response(response).await
    }

    pub async fn list_scenes(&self) -> HueResult<Value> {
        let response = self
            .client
            .get(format!("{}/clip/v2/resource/scene", self.bridge_url))
            .headers(self.headers()?)
            .send()
            .await?;
        Self::decode_response(response).await
    }

    pub async fn set_light_state(&self, input: &SetLightStateInput) -> HueResult<Value> {
        input.validate().map_err(|error| match error {
            fcp_core::FcpError::InvalidRequest { message, .. } => HueError::Config(message),
            other => HueError::Config(other.to_string()),
        })?;
        let light_id = sanitize_path_segment(&input.light_id)?;
        let mut body = json!({ "on": { "on": input.on } });
        if let Some(brightness) = input.brightness {
            body["dimming"] = json!({ "brightness": brightness });
        }
        let response = self
            .client
            .put(format!(
                "{}/clip/v2/resource/light/{}",
                self.bridge_url, light_id
            ))
            .headers(self.headers()?)
            .json(&body)
            .send()
            .await?;
        Self::decode_response(response).await
    }

    pub async fn recall_scene(&self, input: &RecallSceneInput) -> HueResult<Value> {
        input.validate().map_err(|error| match error {
            fcp_core::FcpError::InvalidRequest { message, .. } => HueError::Config(message),
            other => HueError::Config(other.to_string()),
        })?;
        let scene_id = sanitize_path_segment(&input.scene_id)?;
        let response = self
            .client
            .put(format!(
                "{}/clip/v2/resource/scene/{}",
                self.bridge_url, scene_id
            ))
            .headers(self.headers()?)
            .json(&json!({ "recall": { "action": "active" } }))
            .send()
            .await?;
        Self::decode_response(response).await
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn debug_redacts_app_key() {
        let config = HueConfig::from_value(json!({
            "bridge_url": "https://192.168.1.100",
            "app_key": "super-secret-key"
        }))
        .expect("config should parse");
        let client = HueClient::from_config(&config).expect("client should build");
        let debug = format!("{client:?}");
        assert!(!debug.contains("super-secret-key"));
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn sanitize_path_segment_rejects_traversal() {
        // Rejecting (vs. the old silent stripping) keeps requests pinned to the
        // addressed resource instead of retargeting a corrupted id.
        for bad in [
            "",
            "   ",
            "../../etc/passwd",
            "..",
            "id/../../admin",
            "foo/bar",
            "a\\b",
            "a?b",
            "a#b",
            "a&b",
            "a%2fb",
        ] {
            assert!(
                sanitize_path_segment(bad).is_err(),
                "expected `{bad}` to be rejected"
            );
        }
        assert_eq!(sanitize_path_segment("light-1").unwrap(), "light-1");
        assert_eq!(
            sanitize_path_segment(" normal-uuid-v4 ").unwrap(),
            "normal-uuid-v4"
        );
    }
}
