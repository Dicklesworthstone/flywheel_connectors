use std::collections::BTreeMap;
use std::time::Duration;

use quick_xml::de::from_str as from_xml_str;
use reqwest::{Client, RequestBuilder};
use serde::Deserialize;
use tracing::debug;

use fcp_sdk::ConnectorRuntime;
use fcp_sdk::migration::{
    AttemptOutcome, HttpRetryConfig, RetryLoop, transport_error_reached_service,
};
use fcp_sdk::sigv4::{
    AwsCredentials, EMPTY_PAYLOAD_HASH, SigV4Signer, SignableRequest, SigningScope,
};

use crate::error::{AwsError, AwsResult};
use crate::types::*;

#[derive(Debug, Default, Deserialize)]
struct S3ListBucketResultXml {
    #[serde(rename = "Contents", default)]
    contents: Vec<S3ObjectXml>,
}

impl S3ListBucketResultXml {
    fn into_objects(self) -> Vec<S3Object> {
        self.contents.into_iter().map(S3Object::from).collect()
    }
}

#[derive(Debug, Default, Deserialize)]
struct S3ObjectXml {
    #[serde(rename = "Key", default)]
    key: Option<String>,
    #[serde(rename = "LastModified", default)]
    last_modified: Option<String>,
    #[serde(rename = "ETag", default)]
    etag: Option<String>,
    #[serde(rename = "Size", default)]
    size: Option<u64>,
    #[serde(rename = "StorageClass", default)]
    storage_class: Option<String>,
}

impl From<S3ObjectXml> for S3Object {
    fn from(value: S3ObjectXml) -> Self {
        Self {
            key: value.key.unwrap_or_default(),
            size: value.size,
            last_modified: value.last_modified,
            etag: value.etag,
            storage_class: value.storage_class,
        }
    }
}

/// Validate a user-supplied path segment to prevent URL path injection.
fn sanitize_path_segment<'a>(value: &'a str, field: &str) -> AwsResult<&'a str> {
    if value.trim().is_empty() {
        return Err(AwsError::InvalidInput(format!("{field} must not be empty")));
    }
    let lower = value.to_ascii_lowercase();
    if value.contains('/')
        || value.contains('\\')
        || value.contains("..")
        || lower.contains("%2f")
        || lower.contains("%5c")
    {
        return Err(AwsError::InvalidInput(format!(
            "{field} contains path traversal characters"
        )));
    }
    Ok(value)
}

/// Sanitize an S3 object key — allows `/` since S3 keys use hierarchical paths
/// (e.g., `photos/2024/sunset.jpg`), but blocks `..` and backslash.
fn sanitize_object_key<'a>(value: &'a str, field: &str) -> AwsResult<&'a str> {
    if value.trim().is_empty() {
        return Err(AwsError::InvalidInput(format!("{field} must not be empty")));
    }
    let lower = value.to_ascii_lowercase();
    if value.contains('\\') || value.contains("..") || lower.contains("%5c") {
        return Err(AwsError::InvalidInput(format!(
            "{field} contains path traversal characters"
        )));
    }
    // Reject URL-structure delimiters. `sign_request` parses the assembled URL
    // with `url::Url`, which treats `?`/`#` as the start of the query/fragment.
    // A key like `reports/Q?x.pdf` would be silently truncated to `reports/Q`,
    // so the request (and, for `s3_delete_object`, the deletion) would target a
    // DIFFERENT object than the caller named. Fail closed rather than act on the
    // wrong key. (`&` is intentionally allowed: with no `?` it is an ordinary
    // path byte and the SigV4 canonicalizer percent-encodes it consistently.)
    if value.contains('?') || value.contains('#') {
        return Err(AwsError::InvalidInput(format!(
            "{field} contains URL control characters ('?' or '#')"
        )));
    }
    Ok(value)
}

/// Validate a query string parameter to prevent injection.
fn sanitize_query_param<'a>(value: &'a str, field: &str) -> AwsResult<&'a str> {
    if value.contains('&') || value.contains('?') || value.contains('#') {
        return Err(AwsError::InvalidInput(format!(
            "{field} contains query injection characters"
        )));
    }
    Ok(value)
}

fn normalize_base_url_override(base_url: Option<String>) -> Option<String> {
    base_url.and_then(|value| {
        let trimmed = value.trim().trim_end_matches('/').to_string();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    })
}

/// AWS API client with retry support and real SigV4 request signing.
pub struct AwsClient {
    client: Client,
    auth: AwsAuth,
    region: String,
    retry_config: HttpRetryConfig,
    s3_base_url: Option<String>,
    ec2_base_url: Option<String>,
    lambda_base_url: Option<String>,
    sts_base_url: Option<String>,
}

impl std::fmt::Debug for AwsClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsClient")
            .field("region", &self.region)
            .field("auth", &self.auth)
            .finish()
    }
}

impl AwsClient {
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        auth: AwsAuth,
        region: &str,
        retry_config: HttpRetryConfig,
        request_timeout_ms: u64,
        s3_base_url: Option<String>,
        ec2_base_url: Option<String>,
        lambda_base_url: Option<String>,
        sts_base_url: Option<String>,
    ) -> AwsResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_millis(request_timeout_ms))
            .build()
            .map_err(AwsError::Http)?;

        Ok(Self {
            client,
            auth,
            region: region.to_string(),
            retry_config,
            s3_base_url: normalize_base_url_override(s3_base_url),
            ec2_base_url: normalize_base_url_override(ec2_base_url),
            lambda_base_url: normalize_base_url_override(lambda_base_url),
            sts_base_url: normalize_base_url_override(sts_base_url),
        })
    }

    pub fn region(&self) -> &str {
        &self.region
    }

    pub fn is_secretless(&self) -> bool {
        self.auth.access_key_id.is_empty()
    }

    fn s3_url(&self) -> String {
        self.s3_base_url
            .clone()
            .unwrap_or_else(|| format!("https://s3.{}.amazonaws.com", self.region))
    }

    fn ec2_url(&self) -> String {
        self.ec2_base_url
            .clone()
            .unwrap_or_else(|| format!("https://ec2.{}.amazonaws.com", self.region))
    }

    fn lambda_url(&self) -> String {
        self.lambda_base_url
            .clone()
            .unwrap_or_else(|| format!("https://lambda.{}.amazonaws.com", self.region))
    }

    fn sts_url(&self) -> String {
        self.sts_base_url
            .clone()
            .unwrap_or_else(|| "https://sts.amazonaws.com".to_string())
    }

    // ── S3 operations ──

    pub async fn s3_list_buckets(&self, runtime: &ConnectorRuntime) -> AwsResult<Vec<S3Bucket>> {
        let url = self.s3_url();
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let auth = self.auth.clone();
            let region = self.region.clone();
            async move {
                debug!(attempt, "S3 list buckets");
                let req = sign_request(client.get(&url), &auth, &region, "s3", "GET", &url, &[]);
                handle_json_response::<Vec<S3Bucket>>(req, attempt, true).await
            }
        })
        .await
    }

    pub async fn s3_list_objects(
        &self,
        runtime: &ConnectorRuntime,
        bucket: &str,
        prefix: Option<&str>,
    ) -> AwsResult<Vec<S3Object>> {
        let bucket = sanitize_path_segment(bucket, "bucket")?;
        let mut url = format!("{}/{bucket}", self.s3_url());
        if let Some(p) = prefix {
            let p = sanitize_query_param(p, "prefix")?;
            url = format!("{url}?prefix={p}&list-type=2");
        } else {
            url = format!("{url}?list-type=2");
        }
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let auth = self.auth.clone();
            let region = self.region.clone();
            async move {
                debug!(attempt, bucket, "S3 list objects");
                let req = sign_request(client.get(&url), &auth, &region, "s3", "GET", &url, &[]);
                handle_s3_list_objects_response(req, attempt).await
            }
        })
        .await
    }

    pub async fn s3_get_object(
        &self,
        runtime: &ConnectorRuntime,
        bucket: &str,
        key: &str,
    ) -> AwsResult<S3GetObjectResponse> {
        let bucket = sanitize_path_segment(bucket, "bucket")?;
        let key = sanitize_object_key(key, "key")?;
        let url = format!("{}/{bucket}/{key}", self.s3_url());
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let auth = self.auth.clone();
            let region = self.region.clone();
            let key = key.to_string();
            async move {
                debug!(attempt, bucket, key = %key, "S3 get object");
                let req = sign_request(client.get(&url), &auth, &region, "s3", "GET", &url, &[]);
                let resp = match req.send().await {
                    Ok(r) => r,
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: AwsError::Http(e),
                            retry_after: None,
                        };
                    }
                };
                let status = resp.status().as_u16();
                if let Some(outcome) = check_error_status::<S3GetObjectResponse>(status) {
                    return outcome;
                }
                if status == 429 || status == 503 {
                    let retry_after = resp
                        .headers()
                        .get("retry-after")
                        .and_then(|v| v.to_str().ok())
                        .and_then(|v| v.parse::<u64>().ok())
                        .map(Duration::from_secs);
                    return AttemptOutcome::Retryable {
                        error: AwsError::RateLimited {
                            retry_after_ms: retry_after
                                .unwrap_or(Duration::from_secs(30))
                                .as_millis() as u64,
                        },
                        retry_after,
                    };
                }
                let content_type = resp
                    .headers()
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .map(String::from);
                let content_length = resp
                    .headers()
                    .get("content-length")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse::<u64>().ok());
                let etag = resp
                    .headers()
                    .get("etag")
                    .and_then(|v| v.to_str().ok())
                    .map(String::from);
                match resp.text().await {
                    Ok(body) => AttemptOutcome::Success(S3GetObjectResponse {
                        key,
                        content_type,
                        content_length,
                        etag,
                        body,
                    }),
                    Err(e) => AttemptOutcome::Terminal(AwsError::Http(e)),
                }
            }
        })
        .await
    }

    pub async fn s3_put_object(
        &self,
        runtime: &ConnectorRuntime,
        bucket: &str,
        key: &str,
        body: &str,
        content_type: Option<&str>,
    ) -> AwsResult<S3PutObjectResponse> {
        let bucket = sanitize_path_segment(bucket, "bucket")?;
        let key = sanitize_object_key(key, "key")?;
        let url = format!("{}/{bucket}/{key}", self.s3_url());
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let body_owned = body.to_string();
        let ct = content_type
            .unwrap_or("application/octet-stream")
            .to_string();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let auth = self.auth.clone();
            let region = self.region.clone();
            let body = body_owned.clone();
            let ct = ct.clone();
            async move {
                debug!(attempt, bucket, key, "S3 put object");
                let req = sign_request(
                    client.put(&url),
                    &auth,
                    &region,
                    "s3",
                    "PUT",
                    &url,
                    body.as_bytes(),
                )
                .header("Content-Type", ct)
                .body(body);
                handle_s3_put_object_response(req, attempt).await
            }
        })
        .await
    }

    pub async fn s3_delete_object(
        &self,
        runtime: &ConnectorRuntime,
        bucket: &str,
        key: &str,
    ) -> AwsResult<S3DeleteObjectResponse> {
        let bucket = sanitize_path_segment(bucket, "bucket")?;
        let key = sanitize_object_key(key, "key")?;
        let url = format!("{}/{bucket}/{key}", self.s3_url());
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let auth = self.auth.clone();
            let region = self.region.clone();
            async move {
                debug!(attempt, bucket, key, "S3 delete object");
                let req = sign_request(
                    client.delete(&url),
                    &auth,
                    &region,
                    "s3",
                    "DELETE",
                    &url,
                    &[],
                );
                handle_s3_delete_object_response(req, attempt).await
            }
        })
        .await
    }

    // ── EC2 operations ──

    pub async fn ec2_describe_instances(
        &self,
        runtime: &ConnectorRuntime,
    ) -> AwsResult<Vec<Ec2Instance>> {
        let url = format!(
            "{}?Action=DescribeInstances&Version=2016-11-15",
            self.ec2_url()
        );
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let auth = self.auth.clone();
            let region = self.region.clone();
            async move {
                debug!(attempt, "EC2 describe instances");
                let req = sign_request(client.get(&url), &auth, &region, "ec2", "GET", &url, &[]);
                handle_json_response::<Vec<Ec2Instance>>(req, attempt, true).await
            }
        })
        .await
    }

    pub async fn ec2_start_instance(
        &self,
        runtime: &ConnectorRuntime,
        instance_id: &str,
    ) -> AwsResult<Ec2StateChange> {
        let instance_id = sanitize_query_param(
            sanitize_path_segment(instance_id, "instance_id")?,
            "instance_id",
        )?;
        let url = format!(
            "{}?Action=StartInstances&InstanceId.1={instance_id}&Version=2016-11-15",
            self.ec2_url()
        );
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let auth = self.auth.clone();
            let region = self.region.clone();
            async move {
                debug!(attempt, instance_id, "EC2 start instance");
                let req = sign_request(client.post(&url), &auth, &region, "ec2", "POST", &url, &[]);
                handle_json_response::<Ec2StateChange>(req, attempt, true).await
            }
        })
        .await
    }

    pub async fn ec2_stop_instance(
        &self,
        runtime: &ConnectorRuntime,
        instance_id: &str,
    ) -> AwsResult<Ec2StateChange> {
        let instance_id = sanitize_query_param(
            sanitize_path_segment(instance_id, "instance_id")?,
            "instance_id",
        )?;
        let url = format!(
            "{}?Action=StopInstances&InstanceId.1={instance_id}&Version=2016-11-15",
            self.ec2_url()
        );
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let auth = self.auth.clone();
            let region = self.region.clone();
            async move {
                debug!(attempt, instance_id, "EC2 stop instance");
                let req = sign_request(client.post(&url), &auth, &region, "ec2", "POST", &url, &[]);
                handle_json_response::<Ec2StateChange>(req, attempt, true).await
            }
        })
        .await
    }

    pub async fn ec2_terminate_instance(
        &self,
        runtime: &ConnectorRuntime,
        instance_id: &str,
    ) -> AwsResult<Ec2StateChange> {
        let instance_id = sanitize_query_param(
            sanitize_path_segment(instance_id, "instance_id")?,
            "instance_id",
        )?;
        let url = format!(
            "{}?Action=TerminateInstances&InstanceId.1={instance_id}&Version=2016-11-15",
            self.ec2_url()
        );
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let auth = self.auth.clone();
            let region = self.region.clone();
            async move {
                debug!(attempt, instance_id, "EC2 terminate instance");
                let req = sign_request(client.post(&url), &auth, &region, "ec2", "POST", &url, &[]);
                handle_json_response::<Ec2StateChange>(req, attempt, true).await
            }
        })
        .await
    }

    // ── Lambda operations ──

    pub async fn lambda_list_functions(
        &self,
        runtime: &ConnectorRuntime,
    ) -> AwsResult<Vec<LambdaFunction>> {
        let url = format!("{}/2015-03-31/functions", self.lambda_url());
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let auth = self.auth.clone();
            let region = self.region.clone();
            async move {
                debug!(attempt, "Lambda list functions");
                let req =
                    sign_request(client.get(&url), &auth, &region, "lambda", "GET", &url, &[]);
                handle_json_response::<Vec<LambdaFunction>>(req, attempt, true).await
            }
        })
        .await
    }

    pub async fn lambda_invoke(
        &self,
        runtime: &ConnectorRuntime,
        function_name: &str,
        payload: &serde_json::Value,
    ) -> AwsResult<LambdaInvokeResponse> {
        let function_name = sanitize_path_segment(function_name, "function_name")?;
        let url = format!(
            "{}/2015-03-31/functions/{function_name}/invocations",
            self.lambda_url()
        );
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let payload = payload.clone();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let auth = self.auth.clone();
            let region = self.region.clone();
            let payload = payload.clone();
            async move {
                debug!(attempt, function_name, "Lambda invoke");
                let payload_bytes = serde_json::to_vec(&payload).unwrap_or_default();
                let req = sign_request(
                    client.post(&url),
                    &auth,
                    &region,
                    "lambda",
                    "POST",
                    &url,
                    &payload_bytes,
                )
                .json(&payload);
                // NOT replay-safe: a replay runs the function a SECOND time,
                // with whatever side effects it has. Lambda's Invoke API has
                // no idempotency token — AWS's own guidance is to make the
                // FUNCTION idempotent, which this connector cannot verify.
                handle_json_response::<LambdaInvokeResponse>(req, attempt, false).await
            }
        })
        .await
    }

    // ── STS operations ──

    pub async fn sts_get_caller_identity(
        &self,
        runtime: &ConnectorRuntime,
    ) -> AwsResult<CallerIdentity> {
        let url = format!(
            "{}?Action=GetCallerIdentity&Version=2011-06-15",
            self.sts_url()
        );
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let auth = self.auth.clone();
            let region = self.region.clone();
            async move {
                debug!(attempt, "STS get caller identity");
                let req = sign_request(client.post(&url), &auth, &region, "sts", "POST", &url, &[]);
                handle_json_response::<CallerIdentity>(req, attempt, true).await
            }
        })
        .await
    }

    // ── Health check ──

    pub async fn health_check(&self, runtime: &ConnectorRuntime) -> AwsResult<HealthStatus> {
        match self.sts_get_caller_identity(runtime).await {
            Ok(identity) => Ok(HealthStatus {
                authenticated: true,
                account: Some(identity.account),
                arn: Some(identity.arn),
            }),
            Err(e) => Err(e),
        }
    }
}

// ── Free functions for request handling ──

/// Sign an HTTP request with AWS SigV4 and apply auth headers.
///
/// # Arguments
///
/// * `req` - The request builder to sign.
/// * `auth` - AWS credentials.
/// * `region` - AWS region (e.g., "us-east-1").
/// * `service` - AWS service (e.g., "s3", "ec2", "lambda", "sts").
/// * `method` - HTTP method (e.g., "GET", "POST").
/// * `url` - Full request URL.
/// * `payload` - Request body bytes (empty for GET).
fn sign_request(
    req: RequestBuilder,
    auth: &AwsAuth,
    region: &str,
    service: &str,
    method: &str,
    url: &str,
    payload: &[u8],
) -> RequestBuilder {
    if auth.access_key_id.is_empty() {
        return req; // secretless mode — egress proxy injects credentials
    }

    let credentials = AwsCredentials {
        access_key_id: auth.access_key_id.clone(),
        secret_access_key: auth.secret_access_key.clone(),
        session_token: auth.session_token.clone(),
    };

    let scope = SigningScope {
        region: region.to_string(),
        service: service.to_string(),
    };

    let signer = SigV4Signer::new(credentials, scope);

    // Parse URL to extract path and query parameters
    let parsed = url::Url::parse(url).unwrap_or_else(|_| {
        // Fallback: treat as path-only
        url::Url::parse(&format!("https://localhost{url}")).unwrap()
    });

    let uri = parsed.path().to_string();
    let query_params: BTreeMap<String, String> = parsed
        .query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    let mut headers = BTreeMap::new();
    if let Some(host) = parsed.host_str() {
        headers.insert("host".to_string(), host.to_string());
    }

    let payload_hash = if payload.is_empty() {
        EMPTY_PAYLOAD_HASH.to_string()
    } else {
        SignableRequest::hash_payload(payload)
    };

    let signable = SignableRequest {
        method: method.to_string(),
        uri,
        query_params,
        headers,
        payload_hash: payload_hash.clone(),
    };

    let signed = signer.sign(&signable);

    let mut req = req
        .header("Authorization", &signed.authorization)
        .header("X-Amz-Date", &signed.x_amz_date)
        .header("X-Amz-Content-Sha256", &payload_hash);

    if let Some(token) = &signed.x_amz_security_token {
        req = req.header("X-Amz-Security-Token", token);
    }

    req
}

fn check_error_status<T>(status: u16) -> Option<AttemptOutcome<T, AwsError>> {
    if status == 401 || status == 403 {
        return Some(AttemptOutcome::Terminal(AwsError::Unauthorized(format!(
            "Authentication failed (HTTP {status})"
        ))));
    }
    if status == 404 {
        return Some(AttemptOutcome::Terminal(AwsError::NotFound(format!(
            "Resource not found (HTTP {status})"
        ))));
    }
    None
}

/// Classify an AWS JSON response.
///
/// `replay_safe` states whether repeating this request can duplicate a side
/// effect (br-kxd3e). Note the 503 handling below: this client maps 503 to a
/// rate limit, which is right for S3 (`SlowDown`) but NOT for Lambda, where a
/// 503 `ServiceException` means the request DID reach the service. So 503 is
/// only treated as a safe throttle when the caller is replay-safe anyway; a
/// non-replay-safe caller gets it as terminal. A 429 is a throttle everywhere
/// and stays retryable unconditionally.
async fn handle_json_response<T: serde::de::DeserializeOwned>(
    req: RequestBuilder,
    _attempt: u32,
    replay_safe: bool,
) -> AttemptOutcome<T, AwsError> {
    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            // Only a connect-phase failure proves the request never left us.
            let replayable = replay_safe || !transport_error_reached_service(&e);
            return AttemptOutcome::retryable_if_replayable(AwsError::Http(e), None, replayable);
        }
    };

    let status = resp.status().as_u16();

    if let Some(outcome) = check_error_status::<T>(status) {
        return outcome;
    }

    if status == 429 || (status == 503 && replay_safe) {
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            .map(Duration::from_secs);
        return AttemptOutcome::Retryable {
            error: AwsError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(Duration::from_secs(30)).as_millis() as u64,
            },
            retry_after,
        };
    }

    if !resp.status().is_success() {
        let text = resp.text().await.unwrap_or_default();
        let err = AwsError::Api {
            code: u32::from(status),
            message: text,
        };
        if status >= 500 {
            // A 5xx means AWS received the request; for lambda_invoke that
            // means the function may already have run.
            return AttemptOutcome::retryable_if_replayable(err, None, replay_safe);
        }
        return AttemptOutcome::Terminal(err);
    }

    let text = match resp.text().await {
        Ok(t) => t,
        Err(e) => return AttemptOutcome::Terminal(AwsError::Http(e)),
    };

    match serde_json::from_str::<T>(&text) {
        Ok(v) => AttemptOutcome::Success(v),
        Err(e) => {
            // For successful responses that can't be parsed, return a default-ish error
            debug!("Failed to parse AWS response: {e}");
            AttemptOutcome::Terminal(AwsError::Json(e))
        }
    }
}

async fn handle_s3_list_objects_response(
    req: RequestBuilder,
    _attempt: u32,
) -> AttemptOutcome<Vec<S3Object>, AwsError> {
    let resp = match req.send().await {
        Ok(response) => response,
        Err(error) => {
            return AttemptOutcome::Retryable {
                error: AwsError::Http(error),
                retry_after: None,
            };
        }
    };

    let status = resp.status().as_u16();
    let retry_after = retry_after(&resp);

    if let Some(outcome) = check_error_status::<Vec<S3Object>>(status) {
        return outcome;
    }

    if status == 429 || status == 503 {
        return AttemptOutcome::Retryable {
            error: AwsError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(Duration::from_secs(30)).as_millis() as u64,
            },
            retry_after,
        };
    }

    let text = match resp.text().await {
        Ok(body) => body,
        Err(error) => return AttemptOutcome::Terminal(AwsError::Http(error)),
    };

    if !(200..300).contains(&status) {
        return api_error_outcome(status, text);
    }

    if text.trim().is_empty() {
        return AttemptOutcome::Success(Vec::new());
    }

    if let Ok(value) = serde_json::from_str::<Vec<S3Object>>(&text) {
        return AttemptOutcome::Success(value);
    }

    match from_xml_str::<S3ListBucketResultXml>(&text) {
        Ok(value) => AttemptOutcome::Success(value.into_objects()),
        Err(error) => AttemptOutcome::Terminal(AwsError::ServiceError {
            service: "aws_s3".into(),
            message: format!("failed to parse S3 list objects XML response: {error}"),
        }),
    }
}

async fn handle_s3_put_object_response(
    req: RequestBuilder,
    _attempt: u32,
) -> AttemptOutcome<S3PutObjectResponse, AwsError> {
    let resp = match req.send().await {
        Ok(response) => response,
        Err(error) => {
            return AttemptOutcome::Retryable {
                error: AwsError::Http(error),
                retry_after: None,
            };
        }
    };

    let status = resp.status().as_u16();
    let retry_after = retry_after(&resp);
    let etag = response_header(&resp, "etag");
    let version_id = response_header(&resp, "x-amz-version-id");

    if let Some(outcome) = check_error_status::<S3PutObjectResponse>(status) {
        return outcome;
    }

    if status == 429 || status == 503 {
        return AttemptOutcome::Retryable {
            error: AwsError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(Duration::from_secs(30)).as_millis() as u64,
            },
            retry_after,
        };
    }

    let text = match resp.text().await {
        Ok(body) => body,
        Err(error) => return AttemptOutcome::Terminal(AwsError::Http(error)),
    };

    if !(200..300).contains(&status) {
        return api_error_outcome(status, text);
    }

    if !text.trim().is_empty() {
        match serde_json::from_str::<S3PutObjectResponse>(&text) {
            Ok(value) => return AttemptOutcome::Success(value),
            Err(error) => {
                debug!("Failed to parse AWS S3 put JSON response: {error}");
            }
        }
    }

    AttemptOutcome::Success(S3PutObjectResponse { etag, version_id })
}

async fn handle_s3_delete_object_response(
    req: RequestBuilder,
    _attempt: u32,
) -> AttemptOutcome<S3DeleteObjectResponse, AwsError> {
    let resp = match req.send().await {
        Ok(response) => response,
        Err(error) => {
            return AttemptOutcome::Retryable {
                error: AwsError::Http(error),
                retry_after: None,
            };
        }
    };

    let status = resp.status().as_u16();
    let retry_after = retry_after(&resp);
    let delete_marker = response_header(&resp, "x-amz-delete-marker")
        .as_deref()
        .is_some_and(|value| value.eq_ignore_ascii_case("true"));
    let version_id = response_header(&resp, "x-amz-version-id");

    if let Some(outcome) = check_error_status::<S3DeleteObjectResponse>(status) {
        return outcome;
    }

    if status == 429 || status == 503 {
        return AttemptOutcome::Retryable {
            error: AwsError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(Duration::from_secs(30)).as_millis() as u64,
            },
            retry_after,
        };
    }

    let text = match resp.text().await {
        Ok(body) => body,
        Err(error) => return AttemptOutcome::Terminal(AwsError::Http(error)),
    };

    if !(200..300).contains(&status) {
        return api_error_outcome(status, text);
    }

    if !text.trim().is_empty() {
        match serde_json::from_str::<S3DeleteObjectResponse>(&text) {
            Ok(value) => return AttemptOutcome::Success(value),
            Err(error) => {
                debug!("Failed to parse AWS S3 delete JSON response: {error}");
            }
        }
    }

    AttemptOutcome::Success(S3DeleteObjectResponse {
        delete_marker,
        version_id,
    })
}

fn retry_after(response: &reqwest::Response) -> Option<Duration> {
    response
        .headers()
        .get("retry-after")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .map(Duration::from_secs)
}

fn response_header(response: &reqwest::Response, header: &str) -> Option<String> {
    response
        .headers()
        .get(header)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned)
}

fn api_error_outcome<T>(status: u16, text: String) -> AttemptOutcome<T, AwsError> {
    let error = AwsError::Api {
        code: u32::from(status),
        message: text,
    };
    if status >= 500 {
        AttemptOutcome::Retryable {
            error,
            retry_after: None,
        }
    } else {
        AttemptOutcome::Terminal(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_ACCESS_KEY_ID: &str = "fcp-test-access-key";
    const TEST_SIGNING_MATERIAL: &str = "fcp-test-signing-material";
    const TEST_SESSION_MATERIAL: &str = "fcp-test-session-material";

    #[test]
    fn client_debug_redacts_auth() {
        let rt = fcp_async_core::runtime::block_on_sync(async {
            AwsClient::new(
                AwsAuth {
                    access_key_id: TEST_ACCESS_KEY_ID.into(),
                    secret_access_key: TEST_SIGNING_MATERIAL.into(),
                    session_token: None,
                },
                "us-east-1",
                HttpRetryConfig::default(),
                30_000,
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap()
        })
        .unwrap();

        let debug = format!("{rt:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(TEST_ACCESS_KEY_ID));
        assert!(!debug.contains(TEST_SIGNING_MATERIAL));
    }

    #[test]
    fn secretless_detection() {
        let rt = fcp_async_core::runtime::block_on_sync(async {
            AwsClient::new(
                AwsAuth {
                    access_key_id: String::new(),
                    secret_access_key: String::new(),
                    session_token: None,
                },
                "us-east-1",
                HttpRetryConfig::default(),
                30_000,
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap()
        })
        .unwrap();
        assert!(rt.is_secretless());

        let rt2 = fcp_async_core::runtime::block_on_sync(async {
            AwsClient::new(
                AwsAuth {
                    access_key_id: "AKID".into(),
                    secret_access_key: TEST_SIGNING_MATERIAL.into(),
                    session_token: None,
                },
                "us-east-1",
                HttpRetryConfig::default(),
                30_000,
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap()
        })
        .unwrap();
        assert!(!rt2.is_secretless());
    }

    #[test]
    fn region_stored() {
        let rt = fcp_async_core::runtime::block_on_sync(async {
            AwsClient::new(
                AwsAuth {
                    access_key_id: "k".into(),
                    secret_access_key: "s".into(),
                    session_token: None,
                },
                "eu-west-1",
                HttpRetryConfig::default(),
                30_000,
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap()
        })
        .unwrap();
        assert_eq!(rt.region(), "eu-west-1");
    }

    #[test]
    fn custom_base_urls() {
        let rt = fcp_async_core::runtime::block_on_sync(async {
            AwsClient::new(
                AwsAuth {
                    access_key_id: "k".into(),
                    secret_access_key: "s".into(),
                    session_token: None,
                },
                "us-east-1",
                HttpRetryConfig::default(),
                30_000,
                Some(" http://localhost:4566/ ".into()),
                Some("http://localhost:4567///".into()),
                Some("http://localhost:4568".into()),
                Some(" http://localhost:4569 ".into()),
            )
            .await
            .unwrap()
        })
        .unwrap();
        assert_eq!(rt.s3_url(), "http://localhost:4566");
        assert_eq!(rt.ec2_url(), "http://localhost:4567");
        assert_eq!(rt.lambda_url(), "http://localhost:4568");
        assert_eq!(rt.sts_url(), "http://localhost:4569");
    }

    #[test]
    fn sanitize_path_segment_rejects_traversal() {
        assert!(sanitize_path_segment("../admin", "bucket").is_err());
        assert!(sanitize_path_segment("foo/bar", "bucket").is_err());
        assert!(sanitize_path_segment("foo\\bar", "bucket").is_err());
        assert!(sanitize_path_segment("foo%2fbar", "bucket").is_err());
        assert!(sanitize_path_segment("foo%5Cbar", "bucket").is_err());
        assert!(sanitize_path_segment("", "bucket").is_err());
        assert!(sanitize_path_segment("  ", "bucket").is_err());
    }

    #[test]
    fn sanitize_path_segment_accepts_valid() {
        assert_eq!(
            sanitize_path_segment("my-bucket", "bucket").unwrap(),
            "my-bucket"
        );
    }

    #[test]
    fn sanitize_query_param_rejects_injection() {
        assert!(sanitize_query_param("foo&bar=baz", "prefix").is_err());
        assert!(sanitize_query_param("foo?x", "prefix").is_err());
        assert!(sanitize_query_param("foo#frag", "prefix").is_err());
    }

    #[test]
    fn sanitize_query_param_accepts_valid() {
        assert_eq!(
            sanitize_query_param("logs/2024/", "prefix").unwrap(),
            "logs/2024/"
        );
    }

    #[test]
    fn default_urls_use_region() {
        let rt = fcp_async_core::runtime::block_on_sync(async {
            AwsClient::new(
                AwsAuth {
                    access_key_id: "k".into(),
                    secret_access_key: "s".into(),
                    session_token: None,
                },
                "ap-southeast-1",
                HttpRetryConfig::default(),
                30_000,
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap()
        })
        .unwrap();
        assert_eq!(rt.s3_url(), "https://s3.ap-southeast-1.amazonaws.com");
        assert_eq!(rt.ec2_url(), "https://ec2.ap-southeast-1.amazonaws.com");
        assert_eq!(
            rt.lambda_url(),
            "https://lambda.ap-southeast-1.amazonaws.com"
        );
        assert_eq!(rt.sts_url(), "https://sts.amazonaws.com");
    }

    #[test]
    fn normalize_base_url_override_trims_empty_values() {
        assert_eq!(normalize_base_url_override(None), None);
        assert_eq!(normalize_base_url_override(Some("   ".into())), None);
        assert_eq!(
            normalize_base_url_override(Some(" https://example.test/api/ ".into())),
            Some("https://example.test/api".into())
        );
    }

    // ── Cross-Cloud Auth Regression: AWS SigV4 Integration ──────

    #[test]
    fn sanitize_path_segment_blocks_traversal() {
        assert!(sanitize_path_segment("../etc/passwd", "test").is_err());
        assert!(sanitize_path_segment("..\\windows\\system32", "test").is_err());
        assert!(sanitize_path_segment("valid-name-123", "test").is_ok());
        assert!(sanitize_path_segment("%2F..%2F", "test").is_err());
    }

    #[test]
    fn sanitize_path_segment_rejects_empty() {
        assert!(sanitize_path_segment("", "test").is_err());
        assert!(sanitize_path_segment("   ", "test").is_err());
    }

    #[test]
    fn sanitize_query_param_blocks_injection() {
        assert!(sanitize_query_param("normal-value", "test").is_ok());
        assert!(sanitize_query_param("value&injected=true", "test").is_err());
        assert!(sanitize_query_param("value#fragment", "test").is_err());
        assert!(sanitize_query_param("value?param", "test").is_err());
    }

    #[test]
    fn sanitize_object_key_allows_slashes_blocks_traversal() {
        assert!(sanitize_object_key("path/to/file.txt", "test").is_ok());
        assert!(sanitize_object_key("../etc/passwd", "test").is_err());
        assert!(sanitize_object_key("path\\to\\file", "test").is_err());
        // `?`/`#` would be split off as query/fragment by the URL parser in
        // `sign_request`, retargeting the operation at the wrong S3 object.
        assert!(sanitize_object_key("reports/Q?x.pdf", "test").is_err());
        assert!(sanitize_object_key("reports/Q#x.pdf", "test").is_err());
        // `&` stays valid: without a `?` it is an ordinary path byte and the
        // SigV4 canonical URI encodes it the same way AWS does.
        assert!(sanitize_object_key("reports/Q&A.pdf", "test").is_ok());
    }

    #[test]
    fn aws_auth_debug_redacts_all_secrets() {
        let auth = AwsAuth {
            access_key_id: TEST_ACCESS_KEY_ID.into(),
            secret_access_key: TEST_SIGNING_MATERIAL.into(),
            session_token: Some(TEST_SESSION_MATERIAL.into()),
        };
        let debug = format!("{auth:?}");
        assert!(
            !debug.contains(TEST_SIGNING_MATERIAL),
            "secret access key must not appear in debug: {debug}"
        );
        assert!(
            !debug.contains(TEST_SESSION_MATERIAL),
            "session token must not appear in debug: {debug}"
        );
    }

    #[test]
    fn aws_auth_debug_redacts_access_key_id() {
        let auth = AwsAuth {
            access_key_id: TEST_ACCESS_KEY_ID.into(),
            secret_access_key: TEST_SIGNING_MATERIAL.into(),
            session_token: None,
        };
        let debug = format!("{auth:?}");
        assert!(
            !debug.contains(TEST_ACCESS_KEY_ID),
            "access key must be redacted in debug: {debug}"
        );
        assert!(debug.contains("[REDACTED]"));
    }
}
