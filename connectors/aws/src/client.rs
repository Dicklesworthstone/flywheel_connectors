use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use base64::Engine;
use fcp_async_core::ExecutionContext;
use fcp_manifest::{
    Base64Bytes, HostEgressContext, HostEgressHttpHeader, HostEgressHttpRequest,
    HostEgressHttpResponse,
};
use fcp_prelude::{CredentialId, InvokeRequest};
use reqwest::{Client, RequestBuilder};
use tracing::debug;

use fcp_sdk::ConnectorRuntime;
use fcp_sdk::migration::{
    AttemptOutcome, HostEgressProxyClient, HttpRetryConfig, RetryLoop,
    transport_error_reached_service,
};
use fcp_sdk::sigv4::{
    AwsCredentials, EMPTY_PAYLOAD_HASH, SigV4Signer, SignableRequest, SigningScope,
};

use crate::error::{AwsError, AwsResult};
use crate::protocol::{
    ProviderPage, parse_caller_identity, parse_ec2_instances, parse_ec2_state_change,
    parse_lambda_functions, parse_lambda_invoke, parse_s3_buckets, parse_s3_objects,
};
use crate::types::{
    AwsAuth, CallerIdentity, Ec2Instance, Ec2StateChange, HealthStatus, LambdaFunction,
    LambdaInvokeResponse, S3Bucket, S3DeleteObjectResponse, S3GetObjectResponse, S3Object,
    S3PutObjectResponse,
};

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

/// AWS API client with local or host-mediated `SigV4` signing.
#[derive(Clone)]
pub struct AwsClient {
    client: Client,
    auth: AwsAuth,
    region: String,
    retry_config: HttpRetryConfig,
    s3_base_url: Option<String>,
    ec2_base_url: Option<String>,
    lambda_base_url: Option<String>,
    sts_base_url: Option<String>,
    proxy: Option<ProxyTransport>,
}

#[derive(Clone)]
struct ProxyTransport {
    client: HostEgressProxyClient,
    credential_ids: BTreeMap<String, CredentialId>,
    context: Option<HostEgressContext>,
}

impl std::fmt::Debug for AwsClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsClient")
            .field("client", &self.client)
            .field("region", &self.region)
            .field("auth", &self.auth)
            .field("retry_config", &self.retry_config)
            .field("s3_base_url", &self.s3_base_url)
            .field("ec2_base_url", &self.ec2_base_url)
            .field("lambda_base_url", &self.lambda_base_url)
            .field("sts_base_url", &self.sts_base_url)
            .field("host_egress", &self.proxy.is_some())
            .finish()
    }
}

impl AwsClient {
    /// Construct a new AWS API client.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying HTTP client cannot be constructed.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
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
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .user_agent("fcp-aws")
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
            proxy: None,
        })
    }

    /// Use service-specific host credential bindings. AWS host profiles pin both
    /// the signing region and service, so one reference cannot sign every API.
    ///
    /// # Errors
    ///
    /// Rejects mixed authentication and empty or unknown service bindings.
    pub fn with_credential_ids(
        mut self,
        credential_ids: BTreeMap<String, CredentialId>,
        proxy: HostEgressProxyClient,
    ) -> AwsResult<Self> {
        if !self.auth.access_key_id.is_empty()
            || !self.auth.secret_access_key.is_empty()
            || self.auth.session_token.is_some()
        {
            return Err(AwsError::Config(
                "static AWS credentials and host credential references are mutually exclusive"
                    .into(),
            ));
        }
        if credential_ids.is_empty()
            || credential_ids
                .keys()
                .any(|service| !matches!(service.as_str(), "s3" | "ec2" | "lambda" | "sts"))
        {
            return Err(AwsError::Config(
                "credential_ids must contain known AWS services: s3, ec2, lambda, sts".into(),
            ));
        }
        let distinct: BTreeSet<_> = credential_ids.values().map(ToString::to_string).collect();
        if distinct.len() != credential_ids.len() {
            return Err(AwsError::Config(
                "each AWS service requires its own SigV4 credential binding".into(),
            ));
        }
        self.proxy = Some(ProxyTransport {
            client: proxy,
            credential_ids,
            context: None,
        });
        Ok(self)
    }

    /// Bind this client clone to the original capability verified by the connector.
    ///
    /// # Errors
    ///
    /// Returns an error if the capability cannot be encoded for host verification.
    pub fn for_invocation(&self, request: &InvokeRequest) -> AwsResult<Self> {
        let mut client = self.clone();
        if let Some(proxy) = client.proxy.as_mut() {
            let capability = request.capability_token.raw().to_cbor().map_err(|_| {
                AwsError::InvalidInput("capability cannot be encoded for host egress".into())
            })?;
            proxy.context = Some(HostEgressContext {
                connector_id: request.connector_id.to_string(),
                operation_id: request.operation.to_string(),
                zone_id: request.zone_id.to_string(),
                request_id: request.id.to_string(),
                correlation_id: request.correlation_id.as_ref().map(ToString::to_string),
                capability_token_cbor_b64: base64::engine::general_purpose::STANDARD
                    .encode(capability),
            });
        }
        Ok(client)
    }

    fn transport(&self, operation: &str, service: &str) -> AwsResult<Option<ProxyTransport>> {
        if let Some(proxy) = &self.proxy {
            let context = proxy.context.as_ref().ok_or_else(|| {
                AwsError::InvalidInput(
                    "host credential injection requires an admitted invocation".into(),
                )
            })?;
            if context.operation_id != operation {
                return Err(AwsError::InvalidInput(
                    "host egress operation does not match invocation authority".into(),
                ));
            }
            if !proxy.credential_ids.contains_key(service) {
                return Err(AwsError::Config(format!(
                    "credential_ids has no binding for the {service} service"
                )));
            }
            return Ok(Some(proxy.clone()));
        }
        if self.auth.access_key_id.is_empty() || self.auth.secret_access_key.is_empty() {
            return Err(AwsError::Config(
                "AWS requests require static credentials or a configured host egress proxy".into(),
            ));
        }
        Ok(None)
    }

    #[must_use]
    pub fn region(&self) -> &str {
        &self.region
    }

    #[must_use]
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
            .unwrap_or_else(|| format!("https://sts.{}.amazonaws.com", self.region))
    }

    /// Execute one provider call under a single invocation deadline.
    #[allow(clippy::too_many_arguments)]
    async fn execute_request(
        &self,
        ctx: &ExecutionContext,
        operation: &str,
        service: &str,
        method: &str,
        url: &str,
        body: Option<&[u8]>,
        content_type: Option<&str>,
        replay_safe: bool,
    ) -> AwsResult<ProviderReply> {
        // Validate authority and the service binding before constructing a request.
        let proxy = self.transport(operation, service)?;
        let method = reqwest::Method::from_bytes(method.as_bytes())
            .map_err(|_| AwsError::InvalidInput("invalid AWS HTTP method".into()))?;
        let policy = self.retry_config.to_retry_policy();
        let response_limit = provider_response_limit(operation);
        RetryLoop::execute(ctx, &policy, |attempt| {
            let proxy = proxy.clone();
            let method = method.clone();
            async move {
                debug!(attempt, operation, "AWS provider request");
                let response = if let Some(proxy) = proxy {
                    proxy
                        .request(
                            service,
                            method.as_str(),
                            url,
                            body,
                            content_type,
                            response_limit,
                        )
                        .await
                } else {
                    let mut request = sign_request(
                        self.client.request(method.clone(), url),
                        &self.auth,
                        &self.region,
                        service,
                        method.as_str(),
                        url,
                        body.unwrap_or_default(),
                    );
                    if let Some(content_type) = content_type {
                        request = request.header("content-type", content_type);
                    }
                    if let Some(body) = body {
                        request = request.body(body.to_vec());
                    }
                    request
                        .send()
                        .await
                        .map(ProviderResponse::Direct)
                        .map_err(AwsError::Http)
                };
                let response = match response {
                    Ok(response) => response,
                    Err(AwsError::Http(error)) => {
                        if !replay_safe && transport_error_reached_service(&error) {
                            return AttemptOutcome::Terminal(AwsError::UncertainOutcome {
                                status: error.status().map(|status| status.as_u16()),
                            });
                        }
                        return AttemptOutcome::Retryable {
                            error: AwsError::Http(error),
                            retry_after: None,
                        };
                    }
                    // A proxy failure can occur after AWS accepted a request.
                    // Never replay uncertain host failures or bypass the host.
                    Err(error) => return AttemptOutcome::Terminal(error),
                };
                handle_response(response, replay_safe, response_limit).await
            }
        })
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn list_pages<T>(
        &self,
        runtime: &ConnectorRuntime,
        operation: &str,
        service: &str,
        url: String,
        token_parameter: &str,
        decode: fn(&[u8]) -> AwsResult<ProviderPage<T>>,
    ) -> AwsResult<Vec<T>> {
        let ctx = runtime.request_context();
        let mut url =
            url::Url::parse(&url).map_err(|_| AwsError::Config("invalid AWS endpoint".into()))?;
        let mut items = Vec::new();
        let mut seen_tokens = BTreeSet::new();
        let mut response_bytes = 0usize;
        for _ in 0..MAX_LIST_PAGES {
            let response = self
                .execute_request(
                    &ctx,
                    operation,
                    service,
                    "GET",
                    url.as_str(),
                    None,
                    None,
                    true,
                )
                .await?;
            response_bytes = response_bytes.saturating_add(response.body.len());
            if response_bytes > MAX_LIST_RESPONSE_BYTES {
                return Err(pagination_error(
                    "inventory exceeds the aggregate response limit",
                ));
            }
            let page = decode(&response.body)?;
            if items.len().saturating_add(page.items.len()) > MAX_LIST_ITEMS {
                return Err(pagination_error("inventory exceeds the item limit"));
            }
            items.extend(page.items);
            let Some(next_token) = page.next_token else {
                return Ok(items);
            };
            if next_token.is_empty() || next_token.len() > MAX_CONTINUATION_TOKEN_BYTES {
                return Err(pagination_error(
                    "AWS returned an invalid continuation token",
                ));
            }
            if !seen_tokens.insert(next_token.clone()) {
                return Err(pagination_error("AWS repeated a continuation token"));
            }
            let query: Vec<(String, String)> = url
                .query_pairs()
                .filter(|(key, _)| key != token_parameter)
                .map(|(key, value)| (key.into_owned(), value.into_owned()))
                .collect();
            url.query_pairs_mut()
                .clear()
                .extend_pairs(query)
                .append_pair(token_parameter, &next_token);
        }
        Err(pagination_error("inventory exceeds the page limit"))
    }

    /// List all S3 buckets, following AWS continuation tokens.
    ///
    /// # Errors
    ///
    /// Returns an error if dispatch, native decoding, or pagination fails.
    pub async fn s3_list_buckets(&self, runtime: &ConnectorRuntime) -> AwsResult<Vec<S3Bucket>> {
        self.list_pages(
            runtime,
            "aws.s3.list_buckets",
            "s3",
            format!("{}?max-buckets=1000", self.s3_url()),
            "continuation-token",
            |body| Ok(parse_s3_buckets(body)?),
        )
        .await
    }

    /// List all objects in an S3 bucket matching an optional prefix.
    ///
    /// # Errors
    ///
    /// Returns an error if input validation, dispatch, or pagination fails.
    pub async fn s3_list_objects(
        &self,
        runtime: &ConnectorRuntime,
        bucket: &str,
        prefix: Option<&str>,
    ) -> AwsResult<Vec<S3Object>> {
        let bucket = sanitize_path_segment(bucket, "bucket")?;
        let mut url = url::Url::parse(&format!("{}/{bucket}", self.s3_url()))
            .map_err(|_| AwsError::Config("invalid S3 endpoint".into()))?;
        url.query_pairs_mut().append_pair("list-type", "2");
        if let Some(prefix) = prefix {
            let prefix = sanitize_query_param(prefix, "prefix")?;
            url.query_pairs_mut().append_pair("prefix", prefix);
        }
        self.list_pages(
            runtime,
            "aws.s3.list_objects",
            "s3",
            url.into(),
            "continuation-token",
            |body| Ok(parse_s3_objects(body)?),
        )
        .await
    }

    /// Fetch an S3 object's UTF-8 content and response metadata.
    ///
    /// # Errors
    ///
    /// Returns an error if input validation or provider dispatch fails.
    pub async fn s3_get_object(
        &self,
        runtime: &ConnectorRuntime,
        bucket: &str,
        key: &str,
    ) -> AwsResult<S3GetObjectResponse> {
        let bucket = sanitize_path_segment(bucket, "bucket")?;
        let key = sanitize_object_key(key, "key")?;
        let url = format!("{}/{bucket}/{key}", self.s3_url());
        let response = self
            .execute_request(
                &runtime.request_context(),
                "aws.s3.get_object",
                "s3",
                "GET",
                &url,
                None,
                None,
                true,
            )
            .await?;
        Ok(S3GetObjectResponse {
            key: key.to_string(),
            content_type: response.header("content-type"),
            content_length: response
                .header("content-length")
                .and_then(|value| value.parse().ok()),
            etag: response.header("etag"),
            body: String::from_utf8_lossy(&response.body).into_owned(),
        })
    }

    /// Upload an object to S3.
    ///
    /// # Errors
    ///
    /// Returns an error if input validation or provider dispatch fails.
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
        let response = self
            .execute_request(
                &runtime.request_context(),
                "aws.s3.put_object",
                "s3",
                "PUT",
                &url,
                Some(body.as_bytes()),
                Some(content_type.unwrap_or("application/octet-stream")),
                false,
            )
            .await?;
        Ok(S3PutObjectResponse {
            etag: response.header("etag"),
            version_id: response.header("x-amz-version-id"),
        })
    }

    /// Delete an object from S3.
    ///
    /// # Errors
    ///
    /// Returns an error if input validation or provider dispatch fails.
    pub async fn s3_delete_object(
        &self,
        runtime: &ConnectorRuntime,
        bucket: &str,
        key: &str,
    ) -> AwsResult<S3DeleteObjectResponse> {
        let bucket = sanitize_path_segment(bucket, "bucket")?;
        let key = sanitize_object_key(key, "key")?;
        let url = format!("{}/{bucket}/{key}", self.s3_url());
        let response = self
            .execute_request(
                &runtime.request_context(),
                "aws.s3.delete_object",
                "s3",
                "DELETE",
                &url,
                None,
                None,
                false,
            )
            .await?;
        Ok(S3DeleteObjectResponse {
            delete_marker: response
                .header("x-amz-delete-marker")
                .is_some_and(|value| value.eq_ignore_ascii_case("true")),
            version_id: response.header("x-amz-version-id"),
        })
    }

    /// Describe all EC2 instances visible to the credentials.
    ///
    /// # Errors
    ///
    /// Returns an error if dispatch, native decoding, or pagination fails.
    pub async fn ec2_describe_instances(
        &self,
        runtime: &ConnectorRuntime,
    ) -> AwsResult<Vec<Ec2Instance>> {
        self.list_pages(
            runtime,
            "aws.ec2.describe_instances",
            "ec2",
            format!(
                "{}?Action=DescribeInstances&Version=2016-11-15&MaxResults=1000",
                self.ec2_url()
            ),
            "NextToken",
            |body| Ok(parse_ec2_instances(body)?),
        )
        .await
    }

    async fn ec2_state_change(
        &self,
        runtime: &ConnectorRuntime,
        operation: &str,
        action: &str,
        instance_id: &str,
    ) -> AwsResult<Ec2StateChange> {
        let instance_id = sanitize_query_param(
            sanitize_path_segment(instance_id, "instance_id")?,
            "instance_id",
        )?;
        let mut url = url::Url::parse(&self.ec2_url())
            .map_err(|_| AwsError::Config("invalid EC2 endpoint".into()))?;
        url.query_pairs_mut()
            .append_pair("Action", action)
            .append_pair("InstanceId.1", instance_id)
            .append_pair("Version", "2016-11-15");
        let response = self
            .execute_request(
                &runtime.request_context(),
                operation,
                "ec2",
                "POST",
                url.as_str(),
                None,
                None,
                true,
            )
            .await?;
        Ok(parse_ec2_state_change(&response.body, action, instance_id)?)
    }

    /// Start one EC2 instance.
    ///
    /// # Errors
    ///
    /// Returns an error if input validation, dispatch, or native decoding fails.
    pub async fn ec2_start_instance(
        &self,
        runtime: &ConnectorRuntime,
        instance_id: &str,
    ) -> AwsResult<Ec2StateChange> {
        self.ec2_state_change(
            runtime,
            "aws.ec2.start_instance",
            "StartInstances",
            instance_id,
        )
        .await
    }

    /// Stop one EC2 instance.
    ///
    /// # Errors
    ///
    /// Returns an error if input validation, dispatch, or native decoding fails.
    pub async fn ec2_stop_instance(
        &self,
        runtime: &ConnectorRuntime,
        instance_id: &str,
    ) -> AwsResult<Ec2StateChange> {
        self.ec2_state_change(
            runtime,
            "aws.ec2.stop_instance",
            "StopInstances",
            instance_id,
        )
        .await
    }

    /// Terminate one EC2 instance.
    ///
    /// # Errors
    ///
    /// Returns an error if input validation, dispatch, or native decoding fails.
    pub async fn ec2_terminate_instance(
        &self,
        runtime: &ConnectorRuntime,
        instance_id: &str,
    ) -> AwsResult<Ec2StateChange> {
        self.ec2_state_change(
            runtime,
            "aws.ec2.terminate_instance",
            "TerminateInstances",
            instance_id,
        )
        .await
    }

    /// List all Lambda functions, following the provider's marker.
    ///
    /// # Errors
    ///
    /// Returns an error if dispatch, native decoding, or pagination fails.
    pub async fn lambda_list_functions(
        &self,
        runtime: &ConnectorRuntime,
    ) -> AwsResult<Vec<LambdaFunction>> {
        self.list_pages(
            runtime,
            "aws.lambda.list_functions",
            "lambda",
            format!("{}/2015-03-31/functions", self.lambda_url()),
            "Marker",
            |body| Ok(parse_lambda_functions(body)?),
        )
        .await
    }

    /// Invoke a Lambda function once. Uncertain provider or proxy failures are terminal.
    ///
    /// # Errors
    ///
    /// Returns an error if input validation, dispatch, or native decoding fails.
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
        let payload = serde_json::to_vec(payload)?;
        let response = self
            .execute_request(
                &runtime.request_context(),
                "aws.lambda.invoke",
                "lambda",
                "POST",
                &url,
                Some(&payload),
                Some("application/json"),
                false,
            )
            .await?;
        Ok(parse_lambda_invoke(
            response.status,
            response.header("x-amz-function-error"),
            response.header("x-amz-executed-version"),
            &response.body,
        )?)
    }

    async fn caller_identity(
        &self,
        runtime: &ConnectorRuntime,
        operation: &str,
    ) -> AwsResult<CallerIdentity> {
        let url = format!(
            "{}?Action=GetCallerIdentity&Version=2011-06-15",
            self.sts_url()
        );
        let response = self
            .execute_request(
                &runtime.request_context(),
                operation,
                "sts",
                "POST",
                &url,
                None,
                None,
                true,
            )
            .await?;
        Ok(parse_caller_identity(&response.body)?)
    }

    /// Get the caller's native STS identity.
    ///
    /// # Errors
    ///
    /// Returns an error if dispatch or native decoding fails.
    pub async fn sts_get_caller_identity(
        &self,
        runtime: &ConnectorRuntime,
    ) -> AwsResult<CallerIdentity> {
        self.caller_identity(runtime, "aws.sts.get_caller_identity")
            .await
    }

    /// Probe STS under the signed `aws.health` operation's authority.
    ///
    /// # Errors
    ///
    /// Returns an error if dispatch or native decoding fails.
    pub async fn health_check(&self, runtime: &ConnectorRuntime) -> AwsResult<HealthStatus> {
        let identity = self.caller_identity(runtime, "aws.health").await?;
        Ok(HealthStatus {
            authenticated: true,
            account: Some(identity.account),
            arn: Some(identity.arn),
        })
    }
}

// ── Free functions for request handling ──

fn duration_ms(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// Sign an HTTP request with AWS `SigV4` and apply auth headers.
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
    if parsed.host_str().is_some() {
        headers.insert(
            "host".to_string(),
            parsed[url::Position::BeforeHost..url::Position::AfterPort].to_string(),
        );
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

    let sig_output = signer.sign(&signable);

    let mut req = req
        .header("Authorization", &sig_output.authorization)
        .header("X-Amz-Date", &sig_output.x_amz_date)
        .header("X-Amz-Content-Sha256", &payload_hash);

    if let Some(token) = &sig_output.x_amz_security_token {
        req = req.header("X-Amz-Security-Token", token);
    }

    req
}

const MAX_LIST_RESPONSE_BYTES: usize = 10 * 1024 * 1024;
const MAX_OBJECT_RESPONSE_BYTES: usize = 100 * 1024 * 1024;
const MAX_MUTATION_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_LIST_PAGES: usize = 100;
const MAX_LIST_ITEMS: usize = 100_000;
const MAX_CONTINUATION_TOKEN_BYTES: usize = 8192;

fn provider_response_limit(operation: &str) -> usize {
    match operation {
        "aws.s3.get_object" => MAX_OBJECT_RESPONSE_BYTES,
        "aws.s3.list_buckets"
        | "aws.s3.list_objects"
        | "aws.ec2.describe_instances"
        | "aws.lambda.list_functions"
        | "aws.lambda.invoke" => MAX_LIST_RESPONSE_BYTES,
        _ => MAX_MUTATION_RESPONSE_BYTES,
    }
}

fn pagination_error(message: &str) -> AwsError {
    AwsError::ServiceError {
        service: "aws".into(),
        message: message.into(),
    }
}

struct ProviderReply {
    status: u16,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

impl ProviderReply {
    fn header(&self, name: &str) -> Option<String> {
        self.headers.get(name).cloned()
    }
}

enum ProviderResponse {
    Direct(reqwest::Response),
    Proxy(HostEgressHttpResponse),
}

impl ProviderResponse {
    fn status(&self) -> u16 {
        match self {
            Self::Direct(response) => response.status().as_u16(),
            Self::Proxy(response) => response.status,
        }
    }

    fn header(&self, name: &str) -> Option<String> {
        match self {
            Self::Direct(response) => response
                .headers()
                .get(name)
                .and_then(|value| value.to_str().ok())
                .map(ToOwned::to_owned),
            Self::Proxy(response) => response
                .headers
                .iter()
                .find(|header| header.name.eq_ignore_ascii_case(name))
                .map(|header| header.value.clone()),
        }
    }

    async fn read(self, limit: usize) -> AwsResult<ProviderReply> {
        let status = self.status();
        let headers = match &self {
            Self::Direct(response) => response
                .headers()
                .iter()
                .filter_map(|(name, value)| {
                    value
                        .to_str()
                        .ok()
                        .map(|value| (name.as_str().to_owned(), value.to_owned()))
                })
                .collect(),
            Self::Proxy(response) => response
                .headers
                .iter()
                .map(|header| (header.name.to_ascii_lowercase(), header.value.clone()))
                .collect(),
        };
        let body = match self {
            Self::Direct(mut response) => {
                if response
                    .content_length()
                    .is_some_and(|size| size > limit as u64)
                {
                    return Err(AwsError::ResponseTooLarge { limit });
                }
                let mut body = Vec::new();
                while let Some(chunk) = response.chunk().await.map_err(AwsError::Http)? {
                    if chunk.len() > limit.saturating_sub(body.len()) {
                        return Err(AwsError::ResponseTooLarge { limit });
                    }
                    body.extend_from_slice(&chunk);
                }
                body
            }
            Self::Proxy(response) => {
                let body = response.body.as_bytes();
                if body.len() > limit {
                    return Err(AwsError::ResponseTooLarge { limit });
                }
                body.to_vec()
            }
        };
        Ok(ProviderReply {
            status,
            headers,
            body,
        })
    }
}

impl ProxyTransport {
    #[allow(clippy::too_many_arguments)]
    async fn request(
        &self,
        service: &str,
        method: &str,
        url: &str,
        body: Option<&[u8]>,
        content_type: Option<&str>,
        response_limit: usize,
    ) -> AwsResult<ProviderResponse> {
        let context = self.context.clone().ok_or_else(|| {
            AwsError::InvalidInput(
                "host credential injection requires an admitted invocation".into(),
            )
        })?;
        let credential_id = self.credential_ids.get(service).ok_or_else(|| {
            AwsError::Config(format!(
                "credential_ids has no binding for the {service} service"
            ))
        })?;
        let mut headers = Vec::new();
        if let Some(content_type) = content_type {
            content_type
                .parse::<reqwest::header::HeaderValue>()
                .map_err(|_| AwsError::InvalidInput("invalid content_type header".into()))?;
            headers.push(HostEgressHttpHeader {
                name: "content-type".into(),
                value: content_type.into(),
            });
        }
        let request = HostEgressHttpRequest {
            context,
            url: url.to_string(),
            method: method.to_string(),
            headers,
            body: body.map(|body| Base64Bytes::from_vec(body.to_vec())),
            credential_id: Some(credential_id.to_string()),
        };
        // Allow base64 expansion and bounded attribution metadata, while the
        // provider body still has its operation-specific manifest bound.
        let proxy = self
            .client
            .clone()
            .with_max_response_bytes(response_limit.saturating_mul(2).saturating_add(64 * 1024))
            .map_err(|_| AwsError::HostProxy { status: None })?;
        let response = proxy.http(&request).await.map_err(|error| {
            // A rejected host may echo capability material. Retain only status.
            AwsError::HostProxy {
                status: error.status(),
            }
        })?;
        if !response.egress.credential_injected {
            return Err(AwsError::HostProxy { status: None });
        }
        Ok(ProviderResponse::Proxy(response))
    }
}

async fn handle_response(
    response: ProviderResponse,
    replay_safe: bool,
    response_limit: usize,
) -> AttemptOutcome<ProviderReply, AwsError> {
    let status = response.status();
    if status == 401 || status == 403 {
        return AttemptOutcome::Terminal(AwsError::Unauthorized(format!(
            "Authentication failed (HTTP {status})"
        )));
    }
    if status == 404 {
        return AttemptOutcome::Terminal(AwsError::NotFound(format!(
            "Resource not found (HTTP {status})"
        )));
    }
    // Lambda Invoke can execute twice; versioned S3 writes/deletes can create
    // additional versions or delete markers. Only an explicit 429 is known to
    // reject the request before a side effect for those operations.
    if status == 429 || (status == 503 && replay_safe) {
        let retry_after = response
            .header("retry-after")
            .and_then(|value| value.parse::<u64>().ok())
            .map(Duration::from_secs);
        return AttemptOutcome::Retryable {
            error: AwsError::RateLimited {
                retry_after_ms: duration_ms(retry_after.unwrap_or(Duration::from_secs(30))),
            },
            retry_after,
        };
    }
    let response = match response.read(response_limit).await {
        Ok(response) => response,
        Err(AwsError::Http(_)) if !replay_safe => {
            return AttemptOutcome::Terminal(AwsError::UncertainOutcome {
                status: Some(status),
            });
        }
        Err(error) => return AttemptOutcome::Terminal(error),
    };
    if !(200..300).contains(&status) {
        let error = AwsError::Api {
            code: u32::from(status),
            message: String::from_utf8_lossy(&response.body).into_owned(),
        };
        if status >= 500 {
            if !replay_safe {
                return AttemptOutcome::Terminal(AwsError::UncertainOutcome {
                    status: Some(status),
                });
            }
            return AttemptOutcome::Retryable {
                error,
                retry_after: None,
            };
        }
        return AttemptOutcome::Terminal(error);
    }
    AttemptOutcome::Success(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_ACCESS_KEY_ID: &str = "fcp-test-access-key";
    const TEST_SIGNING_MATERIAL: &str = "fcp-test-signing-material";
    const TEST_SESSION_MATERIAL: &str = "fcp-test-session-material";

    fn host_invocation(
        operation: &str,
        id: &str,
        credential_ids: &BTreeMap<String, CredentialId>,
    ) -> InvokeRequest {
        use chrono::{Duration as ChronoDuration, Utc};
        use fcp_core::{CapabilityConstraints, CapabilityToken};
        use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};

        let constraints = CapabilityConstraints {
            resource_allow: vec!["aws:*".into(), "http://127.0.0.1:*".into()],
            credential_allow: credential_ids.values().copied().collect(),
            ..CapabilityConstraints::default()
        };
        let mut cbor = Vec::new();
        ciborium::into_writer(&constraints, &mut cbor).unwrap();
        let key = Ed25519SigningKey::from_bytes(&[72; 32]).unwrap();
        let now = Utc::now();
        let capability = match operation {
            "aws.s3.put_object" | "aws.s3.delete_object" => "aws.s3.write",
            operation if operation.starts_with("aws.s3.") => "aws.s3.read",
            "aws.ec2.describe_instances" => "aws.ec2.read",
            operation if operation.starts_with("aws.ec2.") => "aws.ec2.write",
            "aws.lambda.invoke" => "aws.lambda.write",
            "aws.lambda.list_functions" => "aws.lambda.read",
            _ => "aws.iam.read",
        };
        let token = CapabilityTokenBuilder::new()
            .capability_id(capability)
            .zone_id("z:work")
            .principal("user:aws-proxy-test")
            .operations(&[operation])
            .issuer("node:aws-proxy-test")
            .target_instance("aws-proxy-test")
            .token_id(id.as_bytes())
            .validity(
                now - ChronoDuration::minutes(1),
                now + ChronoDuration::hours(1),
            )
            .try_constraints_cbor(&cbor)
            .unwrap()
            .sign(&key)
            .unwrap();
        serde_json::from_value(serde_json::json!({
            "type": "invoke",
            "id": id,
            "connector_id": "fcp.aws",
            "operation": operation,
            "zone_id": "z:work",
            "input": {},
            "correlation_id": "99c09d94-3189-4608-b390-8fa5e9508a00",
            "capability_token": CapabilityToken::from_raw(token),
        }))
        .unwrap()
    }

    fn host_reply(request: &HostEgressHttpRequest, body: Vec<u8>) -> HostEgressHttpResponse {
        HostEgressHttpResponse {
            status: 200,
            headers: Vec::new(),
            body: Base64Bytes::from_vec(body),
            egress: fcp_manifest::HostEgressDecisionMetadata {
                connector_id: request.context.connector_id.clone(),
                operation_id: request.context.operation_id.clone(),
                zone_id: request.context.zone_id.clone(),
                request_id: request.context.request_id.clone(),
                correlation_id: request.context.correlation_id.clone(),
                execution_mode: "host_egress_proxy".into(),
                constraint_source: "manifest".into(),
                decision: "allow".into(),
                resolved_host: "127.0.0.1".into(),
                resolved_port: 443,
                credential_injected: true,
                elapsed_ms: 1,
            },
        }
    }

    fn service_credentials() -> BTreeMap<String, CredentialId> {
        ["s3", "ec2", "lambda", "sts"]
            .into_iter()
            .map(|service| (service.to_string(), CredentialId::new()))
            .collect()
    }

    fn host_client(
        proxy: &str,
        provider: &str,
        credentials: BTreeMap<String, CredentialId>,
    ) -> AwsClient {
        AwsClient::new(
            AwsAuth {
                access_key_id: String::new(),
                secret_access_key: String::new(),
                session_token: None,
            },
            "us-west-2",
            HttpRetryConfig::default(),
            2000,
            Some(provider.into()),
            Some(provider.into()),
            Some(provider.into()),
            Some(provider.into()),
        )
        .unwrap()
        .with_credential_ids(credentials, HostEgressProxyClient::new(proxy).unwrap())
        .unwrap()
    }

    fn native_host_body(operation: &str) -> Vec<u8> {
        match operation {
            "aws.s3.list_buckets" =>
                b"<ListAllMyBucketsResult><Buckets><Bucket><Name>bucket</Name></Bucket></Buckets></ListAllMyBucketsResult>".to_vec(),
            "aws.s3.list_objects" =>
                b"<ListBucketResult><IsTruncated>false</IsTruncated><Contents><Key>key</Key></Contents></ListBucketResult>".to_vec(),
            "aws.s3.get_object" => b"object body".to_vec(),
            "aws.s3.put_object" | "aws.s3.delete_object" => Vec::new(),
            "aws.ec2.describe_instances" =>
                b"<DescribeInstancesResponse><reservationSet><item><instancesSet><item><instanceId>i-test</instanceId></item></instancesSet></item></reservationSet></DescribeInstancesResponse>".to_vec(),
            "aws.ec2.start_instance" | "aws.ec2.stop_instance" | "aws.ec2.terminate_instance" => {
                let action = match operation {
                    "aws.ec2.start_instance" => "StartInstances",
                    "aws.ec2.stop_instance" => "StopInstances",
                    _ => "TerminateInstances",
                };
                format!("<{action}Response><instancesSet><item><instanceId>i-test</instanceId><previousState><name>stopped</name></previousState><currentState><name>pending</name></currentState></item></instancesSet></{action}Response>").into_bytes()
            }
            "aws.lambda.list_functions" => br#"{"Functions":[{"FunctionName":"test-function"}]}"#.to_vec(),
            "aws.lambda.invoke" => br#"{"result":"ok"}"#.to_vec(),
            "aws.sts.get_caller_identity" | "aws.health" =>
                b"<GetCallerIdentityResponse><GetCallerIdentityResult><Account>123456789012</Account><Arn>arn:aws:iam::123456789012:user/test</Arn><UserId>test-user</UserId></GetCallerIdentityResult></GetCallerIdentityResponse>".to_vec(),
            _ => panic!("unexpected test operation"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn every_operation_uses_its_service_reference_and_original_signed_authority() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let proxy = MockServer::start().await;
        let provider = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/rpc/egress/http"))
            .respond_with(|wire: &wiremock::Request| {
                let request: HostEgressHttpRequest = serde_json::from_slice(&wire.body).unwrap();
                let mut response =
                    host_reply(&request, native_host_body(&request.context.operation_id));
                response.headers = vec![
                    HostEgressHttpHeader {
                        name: "ETag".into(),
                        value: "\"etag\"".into(),
                    },
                    HostEgressHttpHeader {
                        name: "X-Amz-Delete-Marker".into(),
                        value: "true".into(),
                    },
                    HostEgressHttpHeader {
                        name: "X-Amz-Executed-Version".into(),
                        value: "42".into(),
                    },
                ];
                ResponseTemplate::new(200).set_body_json(response)
            })
            .expect(13)
            .mount(&proxy)
            .await;
        let credentials = service_credentials();
        let client = host_client(&proxy.uri(), &provider.uri(), credentials.clone());
        let runtime = ConnectorRuntime::new(fcp_sdk::ConnectorRuntimeConfig::default());
        let operations = [
            "aws.s3.list_buckets",
            "aws.s3.list_objects",
            "aws.s3.get_object",
            "aws.s3.put_object",
            "aws.s3.delete_object",
            "aws.ec2.describe_instances",
            "aws.ec2.start_instance",
            "aws.ec2.stop_instance",
            "aws.ec2.terminate_instance",
            "aws.lambda.list_functions",
            "aws.lambda.invoke",
            "aws.sts.get_caller_identity",
            "aws.health",
        ];
        let mut invocations = Vec::new();
        for (index, operation) in operations.iter().enumerate() {
            let invocation =
                host_invocation(operation, &format!("aws-proxy-{index}"), &credentials);
            let bound = client.for_invocation(&invocation).unwrap();
            match index {
                0 => assert_eq!(
                    bound.s3_list_buckets(&runtime).await.unwrap()[0].name,
                    "bucket"
                ),
                1 => assert_eq!(
                    bound
                        .s3_list_objects(&runtime, "bucket", None)
                        .await
                        .unwrap()[0]
                        .key,
                    "key"
                ),
                2 => assert_eq!(
                    bound
                        .s3_get_object(&runtime, "bucket", "key")
                        .await
                        .unwrap()
                        .body,
                    "object body"
                ),
                3 => assert_eq!(
                    bound
                        .s3_put_object(&runtime, "bucket", "key", "uploaded", Some("text/plain"))
                        .await
                        .unwrap()
                        .etag
                        .as_deref(),
                    Some("\"etag\"")
                ),
                4 => assert!(
                    bound
                        .s3_delete_object(&runtime, "bucket", "key")
                        .await
                        .unwrap()
                        .delete_marker
                ),
                5 => assert_eq!(
                    bound.ec2_describe_instances(&runtime).await.unwrap()[0].instance_id,
                    "i-test"
                ),
                6 => assert_eq!(
                    bound
                        .ec2_start_instance(&runtime, "i-test")
                        .await
                        .unwrap()
                        .instance_id,
                    "i-test"
                ),
                7 => assert_eq!(
                    bound
                        .ec2_stop_instance(&runtime, "i-test")
                        .await
                        .unwrap()
                        .instance_id,
                    "i-test"
                ),
                8 => assert_eq!(
                    bound
                        .ec2_terminate_instance(&runtime, "i-test")
                        .await
                        .unwrap()
                        .instance_id,
                    "i-test"
                ),
                9 => assert_eq!(
                    bound.lambda_list_functions(&runtime).await.unwrap()[0].function_name,
                    "test-function"
                ),
                10 => {
                    let result = bound
                        .lambda_invoke(
                            &runtime,
                            "test-function",
                            &serde_json::json!({"hello":"world"}),
                        )
                        .await
                        .unwrap();
                    assert_eq!(result.payload, serde_json::json!({"result":"ok"}));
                    assert_eq!(result.executed_version.as_deref(), Some("42"));
                }
                11 => assert_eq!(
                    bound
                        .sts_get_caller_identity(&runtime)
                        .await
                        .unwrap()
                        .account,
                    "123456789012"
                ),
                12 => assert!(bound.health_check(&runtime).await.unwrap().authenticated),
                _ => unreachable!(),
            }
            invocations.push(invocation);
        }
        let observed = proxy.received_requests().await.unwrap();
        for (wire, invocation) in observed.iter().zip(invocations.iter()) {
            let request: HostEgressHttpRequest = serde_json::from_slice(&wire.body).unwrap();
            let service = if invocation.operation.as_str() == "aws.health" {
                "sts"
            } else {
                invocation.operation.as_str().split('.').nth(1).unwrap()
            };
            assert_eq!(
                request.credential_id,
                Some(credentials[service].to_string())
            );
            assert_eq!(request.context.connector_id, "fcp.aws");
            assert_eq!(
                request.context.operation_id,
                invocation.operation.to_string()
            );
            assert_eq!(request.context.zone_id, invocation.zone_id.to_string());
            assert_eq!(request.context.request_id, invocation.id.to_string());
            assert_eq!(
                request.context.correlation_id,
                invocation.correlation_id.as_ref().map(ToString::to_string)
            );
            assert_eq!(
                request.context.capability_token_cbor_b64,
                base64::engine::general_purpose::STANDARD
                    .encode(invocation.capability_token.raw().to_cbor().unwrap())
            );
            assert!(request.url.starts_with(&provider.uri()));
            assert!(
                request
                    .headers
                    .iter()
                    .all(|header| header.name == "content-type")
            );
            if invocation.operation.as_str() == "aws.s3.put_object" {
                assert_eq!(request.method, "PUT");
                assert_eq!(request.body.as_ref().unwrap().as_bytes(), b"uploaded");
                assert_eq!(request.headers[0].value, "text/plain");
            }
            if invocation.operation.as_str() == "aws.lambda.invoke" {
                assert_eq!(request.method, "POST");
                assert_eq!(
                    serde_json::from_slice::<serde_json::Value>(
                        request.body.as_ref().unwrap().as_bytes()
                    )
                    .unwrap(),
                    serde_json::json!({"hello":"world"})
                );
            }
        }
        assert!(provider.received_requests().await.unwrap().is_empty());
        let debug = format!("{client:?}");
        assert!(
            !debug.contains(
                &base64::engine::general_purpose::STANDARD
                    .encode(invocations[0].capability_token.raw().to_cbor().unwrap())
            )
        );
        assert!(!debug.contains("capability_token"));
    }

    #[fcp_async_core::runtime::test]
    async fn absent_host_authority_or_service_binding_never_reaches_any_endpoint() {
        use wiremock::MockServer;
        let proxy = MockServer::start().await;
        let provider = MockServer::start().await;
        let mut credentials = service_credentials();
        credentials.remove("lambda");
        let client = host_client(&proxy.uri(), &provider.uri(), credentials.clone());
        let runtime = ConnectorRuntime::new(fcp_sdk::ConnectorRuntimeConfig::default());
        assert!(client.s3_list_buckets(&runtime).await.is_err());
        let request = host_invocation("aws.lambda.list_functions", "missing-service", &credentials);
        assert!(
            client
                .for_invocation(&request)
                .unwrap()
                .lambda_list_functions(&runtime)
                .await
                .is_err()
        );
        let request = host_invocation("aws.s3.list_buckets", "wrong-operation", &credentials);
        assert!(
            client
                .for_invocation(&request)
                .unwrap()
                .s3_get_object(&runtime, "bucket", "key")
                .await
                .is_err()
        );
        let unsigned = AwsClient::new(
            AwsAuth {
                access_key_id: String::new(),
                secret_access_key: String::new(),
                session_token: None,
            },
            "us-east-1",
            HttpRetryConfig::default(),
            2000,
            Some(provider.uri()),
            None,
            None,
            None,
        )
        .unwrap();
        assert!(matches!(
            unsigned.s3_list_buckets(&runtime).await,
            Err(AwsError::Config(_))
        ));
        assert!(proxy.received_requests().await.unwrap().is_empty());
        assert!(provider.received_requests().await.unwrap().is_empty());
    }

    #[fcp_async_core::runtime::test]
    async fn host_failures_are_terminal_redacted_and_never_fall_back_to_direct_aws() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let proxy = MockServer::start().await;
        let provider = MockServer::start().await;
        let credentials = service_credentials();
        let client = host_client(&proxy.uri(), &provider.uri(), credentials.clone());
        let invocation = host_invocation("aws.lambda.invoke", "host-denial", &credentials);
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(503).set_body_string("secret-capability-sentinel"))
            .expect(1)
            .mount(&proxy)
            .await;
        let error = client
            .for_invocation(&invocation)
            .unwrap()
            .lambda_invoke(
                &ConnectorRuntime::new(fcp_sdk::ConnectorRuntimeConfig::default()),
                "test-function",
                &serde_json::json!({}),
            )
            .await
            .unwrap_err();
        assert!(matches!(error, AwsError::HostProxy { status: Some(503) }));
        assert!(!error.is_retryable());
        assert!(!format!("{error:?} {error}").contains("secret-capability-sentinel"));
        assert!(provider.received_requests().await.unwrap().is_empty());
    }

    #[fcp_async_core::runtime::test]
    async fn host_response_requires_credential_injection_and_matching_attribution() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};
        for wrong_attribution in [false, true] {
            let proxy = MockServer::start().await;
            let provider = MockServer::start().await;
            Mock::given(method("POST"))
                .respond_with(move |wire: &wiremock::Request| {
                    let request: HostEgressHttpRequest =
                        serde_json::from_slice(&wire.body).unwrap();
                    let mut response =
                        host_reply(&request, native_host_body("aws.s3.list_buckets"));
                    if wrong_attribution {
                        response.egress.operation_id = "aws.ec2.describe_instances".into();
                    } else {
                        response.egress.credential_injected = false;
                    }
                    ResponseTemplate::new(200).set_body_json(response)
                })
                .expect(1)
                .mount(&proxy)
                .await;
            let credentials = service_credentials();
            let invocation = host_invocation("aws.s3.list_buckets", "host-response", &credentials);
            let error = host_client(&proxy.uri(), &provider.uri(), credentials)
                .for_invocation(&invocation)
                .unwrap()
                .s3_list_buckets(&ConnectorRuntime::new(
                    fcp_sdk::ConnectorRuntimeConfig::default(),
                ))
                .await
                .unwrap_err();
            assert!(matches!(error, AwsError::HostProxy { .. }));
            assert!(provider.received_requests().await.unwrap().is_empty());
        }
    }

    #[fcp_async_core::runtime::test]
    async fn host_lists_follow_opaque_continuations_without_changing_authority() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};
        const TOKEN: &str = "opaque+/=&next";
        let proxy = MockServer::start().await;
        let provider = MockServer::start().await;
        Mock::given(method("POST")).respond_with(|wire: &wiremock::Request| {
            let request: HostEgressHttpRequest = serde_json::from_slice(&wire.body).unwrap();
            let url = url::Url::parse(&request.url).unwrap();
            let operation = request.context.operation_id.as_str();
            let token_parameter = match operation {
                "aws.ec2.describe_instances" => "NextToken",
                "aws.lambda.list_functions" => "Marker",
                _ => "continuation-token",
            };
            let token = url.query_pairs().find(|(name, _)| name == token_parameter);
            let second = token.is_some();
            if let Some((_, value)) = token {
                assert_eq!(value, TOKEN);
            }
            let name = if second { "second" } else { "first" };
            let body = match operation {
                "aws.s3.list_buckets" => format!(
                    "<ListAllMyBucketsResult><Buckets><Bucket><Name>{name}</Name></Bucket></Buckets>{}</ListAllMyBucketsResult>",
                    if second { "" } else { "<ContinuationToken>opaque+/=&amp;next</ContinuationToken>" }
                ),
                "aws.s3.list_objects" => {
                    assert!(url.query_pairs().any(|(key, value)| key == "prefix" && value == "logs/2026/"));
                    format!("<ListBucketResult><IsTruncated>{}</IsTruncated><Contents><Key>{name}</Key></Contents>{}</ListBucketResult>",
                        !second,
                        if second { "" } else { "<NextContinuationToken>opaque+/=&amp;next</NextContinuationToken>" })
                }
                "aws.ec2.describe_instances" => {
                    assert!(url.query_pairs().any(|(key, value)| key == "Action" && value == "DescribeInstances"));
                    format!("<DescribeInstancesResponse><reservationSet><item><instancesSet><item><instanceId>{name}</instanceId></item></instancesSet></item></reservationSet>{}</DescribeInstancesResponse>",
                        if second { "" } else { "<nextToken>opaque+/=&amp;next</nextToken>" })
                }
                "aws.lambda.list_functions" => {
                    if second {
                        serde_json::json!({"Functions":[{"FunctionName":name}]}).to_string()
                    } else {
                        serde_json::json!({"Functions":[{"FunctionName":name}],"NextMarker":TOKEN}).to_string()
                    }
                }
                _ => panic!("unexpected list operation"),
            };
            ResponseTemplate::new(200).set_body_json(host_reply(&request, body.into_bytes()))
        }).expect(8).mount(&proxy).await;
        let credentials = service_credentials();
        let client = host_client(&proxy.uri(), &provider.uri(), credentials.clone());
        let runtime = ConnectorRuntime::new(fcp_sdk::ConnectorRuntimeConfig::default());
        for operation in [
            "aws.s3.list_buckets",
            "aws.s3.list_objects",
            "aws.ec2.describe_instances",
            "aws.lambda.list_functions",
        ] {
            let invocation = host_invocation(operation, operation, &credentials);
            let bound = client.for_invocation(&invocation).unwrap();
            let names: Vec<String> = match operation {
                "aws.s3.list_buckets" => bound
                    .s3_list_buckets(&runtime)
                    .await
                    .unwrap()
                    .into_iter()
                    .map(|item| item.name)
                    .collect(),
                "aws.s3.list_objects" => bound
                    .s3_list_objects(&runtime, "bucket", Some("logs/2026/"))
                    .await
                    .unwrap()
                    .into_iter()
                    .map(|item| item.key)
                    .collect(),
                "aws.ec2.describe_instances" => bound
                    .ec2_describe_instances(&runtime)
                    .await
                    .unwrap()
                    .into_iter()
                    .map(|item| item.instance_id)
                    .collect(),
                _ => bound
                    .lambda_list_functions(&runtime)
                    .await
                    .unwrap()
                    .into_iter()
                    .map(|item| item.function_name)
                    .collect(),
            };
            assert_eq!(names, ["first", "second"]);
        }
        let requests = proxy.received_requests().await.unwrap();
        for pair in requests.chunks_exact(2) {
            let first: HostEgressHttpRequest = serde_json::from_slice(&pair[0].body).unwrap();
            let second: HostEgressHttpRequest = serde_json::from_slice(&pair[1].body).unwrap();
            assert_eq!(first.context.request_id, second.context.request_id);
            assert_eq!(
                first.context.capability_token_cbor_b64,
                second.context.capability_token_cbor_b64
            );
            assert_eq!(first.credential_id, second.credential_id);
            assert_ne!(first.url, second.url);
        }
        assert!(provider.received_requests().await.unwrap().is_empty());
    }

    #[fcp_async_core::runtime::test]
    async fn repeated_continuation_refuses_partial_inventory() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let proxy = MockServer::start().await;
        let provider = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(|wire: &wiremock::Request| {
                let request: HostEgressHttpRequest = serde_json::from_slice(&wire.body).unwrap();
                let body = br#"{"Functions":[{"FunctionName":"partial"}],"NextMarker":"repeated"}"#
                    .to_vec();
                ResponseTemplate::new(200).set_body_json(host_reply(&request, body))
            })
            .expect(2)
            .mount(&proxy)
            .await;
        let credentials = service_credentials();
        let invocation = host_invocation("aws.lambda.list_functions", "cycle", &credentials);
        let error = host_client(&proxy.uri(), &provider.uri(), credentials)
            .for_invocation(&invocation)
            .unwrap()
            .lambda_list_functions(&ConnectorRuntime::new(
                fcp_sdk::ConnectorRuntimeConfig::default(),
            ))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("repeated a continuation token"));
        assert!(provider.received_requests().await.unwrap().is_empty());
    }

    #[fcp_async_core::runtime::test]
    async fn proxied_lambda_server_failure_is_not_replayed() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let proxy = MockServer::start().await;
        let provider = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(|wire: &wiremock::Request| {
                let request: HostEgressHttpRequest = serde_json::from_slice(&wire.body).unwrap();
                let mut response =
                    host_reply(&request, b"function may already have executed".to_vec());
                response.status = 503;
                ResponseTemplate::new(200).set_body_json(response)
            })
            .expect(1)
            .mount(&proxy)
            .await;
        let credentials = service_credentials();
        let invocation = host_invocation("aws.lambda.invoke", "lambda-failure", &credentials);
        let result = host_client(&proxy.uri(), &provider.uri(), credentials)
            .for_invocation(&invocation)
            .unwrap()
            .lambda_invoke(
                &ConnectorRuntime::new(fcp_sdk::ConnectorRuntimeConfig::default()),
                "test-function",
                &serde_json::json!({}),
            )
            .await;
        assert!(matches!(
            result,
            Err(AwsError::UncertainOutcome { status: Some(503) })
        ));
        assert!(provider.received_requests().await.unwrap().is_empty());
    }

    #[fcp_async_core::runtime::test]
    async fn direct_transport_still_signs_and_refuses_redirects_and_error_object_bodies() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let provider = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/bucket/key"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("object")
                    .insert_header("content-type", "text/plain")
                    .insert_header("etag", "\"direct\""),
            )
            .expect(1)
            .mount(&provider)
            .await;
        Mock::given(method("GET"))
            .and(path("/bucket/redirect"))
            .respond_with(ResponseTemplate::new(307).insert_header("location", "/bucket/key"))
            .expect(1)
            .mount(&provider)
            .await;
        Mock::given(method("GET"))
            .and(path("/bucket/error"))
            .respond_with(ResponseTemplate::new(400).set_body_string("not an object"))
            .expect(1)
            .mount(&provider)
            .await;
        let client = AwsClient::new(
            AwsAuth {
                access_key_id: TEST_ACCESS_KEY_ID.into(),
                secret_access_key: TEST_SIGNING_MATERIAL.into(),
                session_token: Some(TEST_SESSION_MATERIAL.into()),
            },
            "us-west-2",
            HttpRetryConfig::default(),
            2000,
            Some(provider.uri()),
            None,
            None,
            None,
        )
        .unwrap();
        let runtime = ConnectorRuntime::new(fcp_sdk::ConnectorRuntimeConfig::default());
        let response = client
            .s3_get_object(&runtime, "bucket", "key")
            .await
            .unwrap();
        assert_eq!(response.body, "object");
        assert_eq!(response.etag.as_deref(), Some("\"direct\""));
        assert!(matches!(
            client.s3_get_object(&runtime, "bucket", "redirect").await,
            Err(AwsError::Api { code: 307, .. })
        ));
        assert!(matches!(
            client.s3_get_object(&runtime, "bucket", "error").await,
            Err(AwsError::Api { code: 400, .. })
        ));
        let requests = provider.received_requests().await.unwrap();
        assert_eq!(requests.len(), 3);
        for request in requests {
            let authorization = request
                .headers
                .get("authorization")
                .unwrap()
                .to_str()
                .unwrap();
            assert!(authorization.contains("/us-west-2/s3/aws4_request"));
            assert!(authorization.contains("SignedHeaders=host"));
            assert!(request.headers.contains_key("x-amz-date"));
            assert!(request.headers.contains_key("x-amz-content-sha256"));
            assert_eq!(
                request
                    .headers
                    .get("x-amz-security-token")
                    .unwrap()
                    .to_str()
                    .unwrap(),
                TEST_SESSION_MATERIAL
            );
        }
    }

    #[test]
    fn response_bounds_match_large_lambda_and_small_sts_contracts() {
        assert_eq!(provider_response_limit("aws.lambda.invoke"), 10_485_760);
        assert_eq!(
            provider_response_limit("aws.sts.get_caller_identity"),
            1_048_576
        );
        assert_eq!(provider_response_limit("aws.health"), 1_048_576);
        assert_eq!(provider_response_limit("aws.s3.get_object"), 104_857_600);
    }

    #[fcp_async_core::runtime::test]
    async fn mutating_requests_never_replay_uncertain_provider_errors_in_either_transport() {
        use wiremock::matchers::any;
        use wiremock::{Mock, MockServer, ResponseTemplate};
        for mediated in [false, true] {
            for operation in [
                "aws.s3.put_object",
                "aws.s3.delete_object",
                "aws.lambda.invoke",
            ] {
                let provider = MockServer::start().await;
                let proxy = MockServer::start().await;
                Mock::given(any())
                    .respond_with(
                        ResponseTemplate::new(503).set_body_string("provider-payload-sentinel"),
                    )
                    .expect(if mediated { 0 } else { 1 })
                    .mount(&provider)
                    .await;
                Mock::given(any())
                    .respond_with(|wire: &wiremock::Request| {
                        let request: HostEgressHttpRequest =
                            serde_json::from_slice(&wire.body).unwrap();
                        let mut response =
                            host_reply(&request, b"provider-payload-sentinel".to_vec());
                        response.status = 503;
                        ResponseTemplate::new(200).set_body_json(response)
                    })
                    .expect(if mediated { 1 } else { 0 })
                    .mount(&proxy)
                    .await;
                let credentials = service_credentials();
                let client = if mediated {
                    let request = host_invocation(operation, operation, &credentials);
                    host_client(&proxy.uri(), &provider.uri(), credentials)
                        .for_invocation(&request)
                        .unwrap()
                } else {
                    AwsClient::new(
                        AwsAuth {
                            access_key_id: TEST_ACCESS_KEY_ID.into(),
                            secret_access_key: TEST_SIGNING_MATERIAL.into(),
                            session_token: None,
                        },
                        "us-west-2",
                        HttpRetryConfig::default(),
                        2000,
                        Some(provider.uri()),
                        Some(provider.uri()),
                        Some(provider.uri()),
                        Some(provider.uri()),
                    )
                    .unwrap()
                };
                let runtime = ConnectorRuntime::new(fcp_sdk::ConnectorRuntimeConfig::default());
                let error = match operation {
                    "aws.s3.put_object" => client
                        .s3_put_object(&runtime, "bucket", "key", "body", None)
                        .await
                        .map(|_| ())
                        .unwrap_err(),
                    "aws.s3.delete_object" => client
                        .s3_delete_object(&runtime, "bucket", "key")
                        .await
                        .map(|_| ())
                        .unwrap_err(),
                    _ => client
                        .lambda_invoke(&runtime, "function", &serde_json::json!({}))
                        .await
                        .map(|_| ())
                        .unwrap_err(),
                };
                assert!(matches!(
                    error,
                    AwsError::UncertainOutcome { status: Some(503) }
                ));
                assert!(!error.is_retryable());
                assert!(!format!("{error:?} {error}").contains("provider-payload-sentinel"));
                assert!(matches!(
                    error.to_fcp_error(),
                    fcp_prelude::FcpError::External {
                        retryable: false,
                        status_code: Some(503),
                        ..
                    }
                ));
            }
        }
    }

    #[fcp_async_core::runtime::test]
    async fn timed_out_object_upload_reports_uncertainty_without_retry_hints() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let provider = MockServer::start().await;
        Mock::given(method("PUT"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_millis(400)))
            .expect(1)
            .mount(&provider)
            .await;
        let client = AwsClient::new(
            AwsAuth {
                access_key_id: TEST_ACCESS_KEY_ID.into(),
                secret_access_key: TEST_SIGNING_MATERIAL.into(),
                session_token: None,
            },
            "us-west-2",
            HttpRetryConfig::default(),
            100,
            Some(provider.uri()),
            None,
            None,
            None,
        )
        .unwrap();
        let error = client
            .s3_put_object(
                &ConnectorRuntime::new(fcp_sdk::ConnectorRuntimeConfig::default()),
                "bucket",
                "key",
                "body",
                None,
            )
            .await
            .unwrap_err();
        assert!(matches!(error, AwsError::UncertainOutcome { .. }));
        assert!(matches!(
            error.to_fcp_error(),
            fcp_prelude::FcpError::External {
                retryable: false,
                ..
            }
        ));
    }

    #[test]
    fn client_debug_redacts_auth() {
        let rt = AwsClient::new(
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
        .unwrap();

        let debug = format!("{rt:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(TEST_ACCESS_KEY_ID));
        assert!(!debug.contains(TEST_SIGNING_MATERIAL));
    }

    #[test]
    fn secretless_detection() {
        let rt = AwsClient::new(
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
        .unwrap();
        assert!(rt.is_secretless());

        let rt2 = AwsClient::new(
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
        .unwrap();
        assert!(!rt2.is_secretless());
    }

    #[test]
    fn region_stored() {
        let rt = AwsClient::new(
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
        .unwrap();
        assert_eq!(rt.region(), "eu-west-1");
    }

    #[test]
    fn custom_base_urls() {
        let rt = AwsClient::new(
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
        let rt = AwsClient::new(
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
        .unwrap();
        assert_eq!(rt.s3_url(), "https://s3.ap-southeast-1.amazonaws.com");
        assert_eq!(rt.ec2_url(), "https://ec2.ap-southeast-1.amazonaws.com");
        assert_eq!(
            rt.lambda_url(),
            "https://lambda.ap-southeast-1.amazonaws.com"
        );
        assert_eq!(rt.sts_url(), "https://sts.ap-southeast-1.amazonaws.com");
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
