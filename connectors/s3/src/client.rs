//! S3 API client.
//!
//! Bounded, SigV4-authenticated S3 REST operations. Object bodies are bytes,
//! metadata comes from headers, and bucket/copy/list/error documents are XML.
//! Redirects and automatic transport retries are disabled. Mutations are never
//! replayed after dispatch, including an incomplete or malformed response.

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use base64::Engine;
use fcp_prelude::CredentialId;
use fcp_sdk::migration::{AttemptOutcome, HttpRetryConfig, RetryLoop};
use fcp_sdk::sigv4::{AwsCredentials, SigV4Signer, SignableRequest, SigningScope};
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use reqwest::{Client, Method, Response, StatusCode, header::HeaderMap};
use serde::Deserialize;
use tracing::debug;

use crate::{
    error::{S3Error, S3Result},
    types::{
        ApiErrorResponse, BucketInfo, CreateBucketResponse, DeleteBucketResponse,
        GetObjectResponse, HeadObjectResponse, ListBucketsResponse, ListObjectsResponse,
        ObjectInfo, PresignedUrlResponse, PutObjectResponse,
    },
};

/// Default S3 base URL.
pub const DEFAULT_BASE_URL: &str = "https://s3.amazonaws.com";

/// Maximum raw object bytes in one native invocation (before JSON/base64).
pub const MAX_OBJECT_BYTES: usize = 2 * 1024 * 1024;
const MAX_XML_BYTES: usize = 2 * 1024 * 1024;
const MAX_ERROR_BYTES: usize = 64 * 1024;

/// Authentication mode for S3.
#[derive(Clone)]
pub enum S3Auth {
    /// Direct AWS credentials (access key + secret + region).
    Keys {
        access_key_id: String,
        secret_access_key: String,
        region: String,
    },
    /// Secretless credential reference (egress proxy injection).
    CredentialId(CredentialId),
}

impl S3Auth {
    /// Render a redacted label suitable for logs/diagnostics.
    #[must_use]
    pub fn redacted_label(&self) -> String {
        match self {
            Self::Keys { region, .. } => format!("keys:[redacted]@{region}"),
            Self::CredentialId(id) => format!("credential_id:{id}"),
        }
    }

    /// Whether this auth mode requires egress proxy credential injection.
    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId(_))
    }
}

impl fmt::Debug for S3Auth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Keys { region, .. } => f
                .debug_struct("Keys")
                .field("region", region)
                .field("access_key_id", &"<redacted>")
                .field("secret_access_key", &"<redacted>")
                .finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

/// Percent-encoding set for S3 bucket names in URL path segments. Encodes
/// slashes and other injection vectors while preserving characters valid in
/// S3 bucket names: lowercase alphanumeric, hyphens, dots.
const S3_BUCKET_SET: &percent_encoding::AsciiSet = &percent_encoding::CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'/')
    .add(b'\\')
    .add(b'?')
    .add(b'&')
    .add(b'=')
    .add(b'<')
    .add(b'>')
    .add(b'{')
    .add(b'}')
    .add(b'[')
    .add(b']')
    .add(b'^')
    .add(b'|')
    .add(b'`')
    .add(b'@')
    .add(b':')
    .add(b';')
    .add(b'+')
    .add(b',');

/// Percent-encoding set for S3 object key paths. Preserves `/`, `-`, `_`, `.`, `~`
/// which are valid in S3 key names and URL paths.
const S3_PATH_SET: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~')
    .remove(b'/');

/// S3 API client.
pub struct S3Client {
    client: Client,
    auth: S3Auth,
    base_url: String,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
    session_token: Option<String>,
}

impl fmt::Debug for S3Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("S3Client")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .field("retry_config", &self.retry_config)
            .finish_non_exhaustive()
    }
}

impl S3Client {
    /// Create a new S3 client with direct credentials.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client cannot be constructed.
    pub fn new(
        access_key_id: impl Into<String>,
        secret_access_key: impl Into<String>,
        region: impl Into<String>,
    ) -> S3Result<Self> {
        Self::new_with_auth(S3Auth::Keys {
            access_key_id: access_key_id.into(),
            secret_access_key: secret_access_key.into(),
            region: region.into(),
        })
    }

    /// Create a new S3 client with explicit auth mode.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client cannot be constructed.
    pub fn new_with_auth(auth: S3Auth) -> S3Result<Self> {
        let S3Auth::Keys {
            access_key_id,
            secret_access_key,
            region,
        } = &auth
        else {
            return Err(S3Error::InvalidInput(
                "credential_id requires a host SigV4 signing transport; configure direct AWS credentials".into(),
            ));
        };
        if access_key_id.is_empty()
            || access_key_id.len() > 128
            || !access_key_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric())
            || secret_access_key.is_empty()
            || secret_access_key.len() > 1024
            || region.is_empty()
            || region.len() > 63
            || !region
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(S3Error::InvalidInput(
                "invalid AWS credentials or region".into(),
            ));
        }
        let base_url = if region == "us-east-1" {
            DEFAULT_BASE_URL.to_owned()
        } else if region.starts_with("cn-") {
            format!("https://s3.{region}.amazonaws.com.cn")
        } else {
            format!("https://s3.{region}.amazonaws.com")
        };
        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(300))
            .build()
            .map_err(S3Error::Http)?;

        Ok(Self {
            client,
            auth,
            base_url,
            runtime: ConnectorRuntime::new(
                ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_secs(30)),
            ),
            retry_config: HttpRetryConfig {
                max_retries: 2,
                ..HttpRetryConfig::default()
            },
            session_token: None,
        })
    }

    /// Set the base URL for alternate S3-compatible endpoints.
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> S3Result<Self> {
        let base_url = base_url.into();
        let parsed = url::Url::parse(&base_url)
            .map_err(|_| S3Error::InvalidInput("invalid S3 endpoint".into()))?;
        let loopback = parsed.host_str().is_some_and(|host| {
            host == "localhost"
                || host
                    .trim_matches(['[', ']'])
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|address| address.is_loopback())
        });
        if !(parsed.scheme() == "https" || parsed.scheme() == "http" && loopback)
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || parsed.path() != "/"
        {
            return Err(S3Error::InvalidInput(
                "S3 endpoint must be an HTTPS origin (or loopback HTTP) without credentials, path, query or fragment".into(),
            ));
        }
        self.base_url = parsed.as_str().trim_end_matches('/').to_owned();
        Ok(self)
    }

    /// Attach temporary AWS credentials without exposing the token in diagnostics.
    pub fn with_session_token(mut self, token: Option<String>) -> S3Result<Self> {
        if token.as_ref().is_some_and(|value| {
            value.is_empty()
                || value.len() > 16_384
                || value.parse::<reqwest::header::HeaderValue>().is_err()
        }) {
            return Err(S3Error::InvalidInput("invalid AWS session token".into()));
        }
        self.session_token = token;
        Ok(self)
    }

    /// Perform a lightweight health check (list buckets).
    ///
    /// # Errors
    ///
    /// Returns an error if the API call fails.
    pub async fn health_check(&self) -> S3Result<()> {
        let _ = self.list_buckets().await?;
        Ok(())
    }

    /// Set retry configuration.
    #[must_use]
    pub fn with_retry_config(
        mut self,
        max_retries: u32,
        initial_delay_ms: u64,
        max_delay_ms: u64,
    ) -> Self {
        self.retry_config = HttpRetryConfig {
            max_retries,
            initial_delay_ms,
            max_delay_ms,
            ..HttpRetryConfig::default()
        };
        self
    }

    /// Trigger graceful shutdown.
    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    /// Upload an object to a bucket.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failures, auth errors, or if the bucket does not exist.
    pub async fn put_object(
        &self,
        bucket: &str,
        key: &str,
        body: &[u8],
        content_type: Option<&str>,
    ) -> S3Result<PutObjectResponse> {
        Self::validate_body(body, content_type)?;
        let url = self.checked_object_url(bucket, key)?;
        let headers = BTreeMap::from([(
            "content-type".into(),
            content_type.unwrap_or("application/octet-stream").into(),
        )]);
        let response = self
            .request(Method::PUT, &url, headers, body, MAX_XML_BYTES)
            .await?;
        require_empty_body(&response)?;
        let etag = required_header(&response.headers, "etag")?;
        Ok(PutObjectResponse { etag })
    }

    /// Download an object from a bucket.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failures, auth errors, or if the object does not exist.
    pub async fn get_object(&self, bucket: &str, key: &str) -> S3Result<GetObjectResponse> {
        let url = self.checked_object_url(bucket, key)?;
        let response = self
            .request(Method::GET, &url, BTreeMap::new(), &[], MAX_OBJECT_BYTES)
            .await?;
        let content_type = optional_header(&response.headers, "content-type")?
            .unwrap_or_else(|| "application/octet-stream".into());
        let (body, body_encoding) = match String::from_utf8(response.body) {
            Ok(text) => (text, "utf8".into()),
            Err(error) => (
                base64::engine::general_purpose::STANDARD.encode(error.into_bytes()),
                "base64".into(),
            ),
        };
        Ok(GetObjectResponse {
            body,
            content_type,
            body_encoding,
        })
    }

    /// Delete an object from a bucket.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failures or auth errors.
    pub async fn delete_object(&self, bucket: &str, key: &str) -> S3Result<bool> {
        let url = self.checked_object_url(bucket, key)?;
        let response = self
            .request(Method::DELETE, &url, BTreeMap::new(), &[], MAX_XML_BYTES)
            .await?;
        require_empty_body(&response)?;
        Ok(true)
    }

    /// List objects in a bucket with optional prefix and max keys.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failures, auth errors, or if the bucket does not exist.
    pub async fn list_objects(
        &self,
        bucket: &str,
        prefix: Option<&str>,
        max_keys: Option<u64>,
        continuation_token: Option<&str>,
    ) -> S3Result<ListObjectsResponse> {
        Self::validate_bucket(bucket)?;
        Self::validate_listing(prefix, max_keys, continuation_token)?;
        let mut url = url::Url::parse(&self.bucket_url(bucket))
            .map_err(|_| S3Error::InvalidInput("invalid S3 bucket URL".into()))?;
        {
            let mut query = url.query_pairs_mut();
            query
                .append_pair("list-type", "2")
                .append_pair("encoding-type", "url");
            if let Some(prefix) = prefix {
                query.append_pair("prefix", prefix);
            }
            if let Some(max_keys) = max_keys {
                query.append_pair("max-keys", &max_keys.to_string());
            }
            if let Some(token) = continuation_token {
                query.append_pair("continuation-token", token);
            }
        }
        // SigV4 uses RFC 3986 query encoding, not form '+' encoding for spaces.
        let query = url.query().unwrap_or("").replace('+', "%20");
        url.set_query(Some(&query));
        let response = self
            .request(
                Method::GET,
                url.as_str(),
                BTreeMap::new(),
                &[],
                MAX_XML_BYTES,
            )
            .await?;
        let document: ListBucketDocument = parse_xml(&response.body, "ListBucketResult")?;
        if document.name != bucket
            || document.contents.len() > usize::try_from(max_keys.unwrap_or(1000)).unwrap_or(1000)
            || document.is_truncated
                && document
                    .next_continuation_token
                    .as_ref()
                    .is_none_or(|token| {
                        token.is_empty() || Some(token.as_str()) == continuation_token
                    })
            || !document.is_truncated && document.next_continuation_token.is_some()
        {
            return Err(invalid_response(
                "invalid S3 list identity, page size or continuation",
            ));
        }
        if let Some(token) = &document.next_continuation_token {
            Self::validate_listing(None, None, Some(token))
                .map_err(|_| invalid_response("invalid S3 continuation token"))?;
        }
        let encoded = match document.encoding_type.as_deref() {
            Some("url") => true,
            None => false,
            Some(_) => return Err(invalid_response("unsupported S3 list key encoding")),
        };
        let mut contents = Vec::with_capacity(document.contents.len());
        for object in document.contents {
            let key = if encoded {
                decode_list_key(&object.key)?
            } else {
                object.key
            };
            if key.is_empty()
                || key.len() > 1024
                || prefix.is_some_and(|prefix| !key.starts_with(prefix))
            {
                return Err(invalid_response(
                    "S3 list returned an invalid or out-of-prefix key",
                ));
            }
            contents.push(ObjectInfo {
                key,
                size: object.size,
                last_modified: object.last_modified,
                etag: object.etag,
                storage_class: object.storage_class,
            });
        }
        Ok(ListObjectsResponse {
            contents,
            is_truncated: document.is_truncated,
            next_continuation_token: document.next_continuation_token,
        })
    }

    /// Get object metadata (HEAD request).
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failures, auth errors, or if the object does not exist.
    pub async fn head_object(&self, bucket: &str, key: &str) -> S3Result<HeadObjectResponse> {
        let url = self.checked_object_url(bucket, key)?;
        let response = self
            .request(Method::HEAD, &url, BTreeMap::new(), &[], 0)
            .await?;
        let content_type = optional_header(&response.headers, "content-type")?
            .unwrap_or_else(|| "application/octet-stream".into());
        let content_length = required_header(&response.headers, "content-length")?
            .parse()
            .map_err(|_| invalid_response("S3 metadata has invalid content length"))?;
        let etag = optional_header(&response.headers, "etag")?;
        let last_modified = optional_header(&response.headers, "last-modified")?;
        Ok(HeadObjectResponse {
            content_type,
            content_length,
            etag,
            last_modified,
        })
    }

    /// Copy an object within or between buckets.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failures, auth errors, or if the source does not exist.
    pub async fn copy_object(
        &self,
        source_bucket: &str,
        source_key: &str,
        dest_bucket: &str,
        dest_key: &str,
    ) -> S3Result<PutObjectResponse> {
        Self::validate_bucket(source_bucket)?;
        Self::validate_key(source_key)?;
        let url = self.checked_object_url(dest_bucket, dest_key)?;
        let encoded_source_bucket = Self::encode_bucket(source_bucket);
        let encoded_source_key = percent_encoding::utf8_percent_encode(source_key, S3_PATH_SET);
        let copy_source = format!("/{encoded_source_bucket}/{encoded_source_key}");
        let headers = BTreeMap::from([("x-amz-copy-source".into(), copy_source)]);
        let response = self
            .request(Method::PUT, &url, headers, &[], MAX_XML_BYTES)
            .await?;
        let document: CopyObjectDocument = parse_xml(&response.body, "CopyObjectResult")?;
        if document.etag.is_empty() {
            return Err(invalid_response("S3 copy omitted its ETag"));
        }
        Ok(PutObjectResponse {
            etag: document.etag,
        })
    }

    /// List all buckets.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failures or auth errors.
    pub async fn list_buckets(&self) -> S3Result<ListBucketsResponse> {
        let response = self
            .request(
                Method::GET,
                &format!("{}/", self.base_url),
                BTreeMap::new(),
                &[],
                MAX_XML_BYTES,
            )
            .await?;
        let document: ListBucketsDocument = parse_xml(&response.body, "ListAllMyBucketsResult")?;
        if document.continuation_token.is_some() {
            return Err(invalid_response(
                "S3 bucket listing requires pagination; a partial catalog is not a complete result",
            ));
        }
        let mut buckets = Vec::with_capacity(document.buckets.bucket.len());
        for bucket in document.buckets.bucket {
            Self::validate_bucket(&bucket.name)
                .map_err(|_| invalid_response("S3 returned an invalid bucket name"))?;
            buckets.push(BucketInfo {
                name: bucket.name,
                creation_date: bucket.creation_date,
            });
        }
        Ok(ListBucketsResponse { buckets })
    }

    /// Create a new bucket.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failures or auth errors.
    pub async fn create_bucket(&self, bucket: &str) -> S3Result<CreateBucketResponse> {
        Self::validate_bucket(bucket)?;
        let url = self.bucket_url(bucket);
        let S3Auth::Keys { region, .. } = &self.auth else {
            return Err(S3Error::InvalidInput(
                "AWS signing credentials required".into(),
            ));
        };
        let body = if region == "us-east-1" {
            String::new()
        } else {
            format!(
                "<CreateBucketConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><LocationConstraint>{region}</LocationConstraint></CreateBucketConfiguration>"
            )
        };
        let headers = BTreeMap::from([("content-type".into(), "application/xml".into())]);
        let response = self
            .request(Method::PUT, &url, headers, body.as_bytes(), MAX_XML_BYTES)
            .await?;
        require_empty_body(&response)?;
        Ok(CreateBucketResponse {
            bucket: bucket.to_string(),
            created: true,
        })
    }

    /// Delete an empty bucket.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failures or auth errors.
    pub async fn delete_bucket(&self, bucket: &str) -> S3Result<DeleteBucketResponse> {
        Self::validate_bucket(bucket)?;
        let url = self.bucket_url(bucket);
        let response = self
            .request(Method::DELETE, &url, BTreeMap::new(), &[], MAX_XML_BYTES)
            .await?;
        require_empty_body(&response)?;
        Ok(DeleteBucketResponse {
            bucket: bucket.to_string(),
            deleted: true,
        })
    }

    /// Generate a presigned URL for temporary access using real SigV4 query signing.
    pub fn generate_presigned_url(
        &self,
        bucket: &str,
        key: &str,
        expires_in: u64,
    ) -> S3Result<PresignedUrlResponse> {
        if !(1..=604_800).contains(&expires_in) {
            return Err(S3Error::InvalidInput(
                "presigned expiry must be between 1 and 604800 seconds".into(),
            ));
        }
        let object_url = self.checked_object_url(bucket, key)?;
        let url = url::Url::parse(&object_url)
            .map_err(|_| S3Error::InvalidInput("invalid S3 object URL".into()))?;
        let headers = BTreeMap::from([("host".into(), url_authority(&url))]);
        let signable = SignableRequest {
            method: "GET".into(),
            uri: url.path().into(),
            query_params: BTreeMap::new(),
            headers,
            payload_hash: fcp_sdk::sigv4::UNSIGNED_PAYLOAD.into(),
        };
        let presigned = self.signer()?.presign(&signable, expires_in);
        let query = presigned
            .url
            .split_once('?')
            .ok_or_else(|| invalid_response("presigner omitted query"))?
            .1;
        // The shared signer uses HTTPS. Preserve the explicitly configured
        // origin (including a loopback HTTP scheme and any non-default port).
        Ok(PresignedUrlResponse {
            url: format!("{object_url}?{query}"),
        })
    }

    // ── Internal helpers ─────────────────────────────────────────────────

    /// Percent-encode a bucket name for safe inclusion in a URL path segment.
    /// Preserves characters valid in S3 bucket names (alphanumeric, hyphens, dots)
    /// while encoding slashes, query chars, and other injection vectors.
    fn encode_bucket(bucket: &str) -> String {
        percent_encoding::utf8_percent_encode(bucket, S3_BUCKET_SET).to_string()
    }

    /// Build the URL for an object in a bucket.
    fn object_url(&self, bucket: &str, key: &str) -> String {
        let encoded_bucket = Self::encode_bucket(bucket);
        let encoded_key = percent_encoding::utf8_percent_encode(key, S3_PATH_SET);
        format!("{}/{encoded_bucket}/{encoded_key}", self.base_url)
    }

    /// Build the URL for a bucket.
    fn bucket_url(&self, bucket: &str) -> String {
        let encoded_bucket = Self::encode_bucket(bucket);
        format!("{}/{encoded_bucket}", self.base_url)
    }

    /// Validate exactly the general-purpose bucket namespace supported here.
    pub fn validate_bucket(bucket: &str) -> S3Result<()> {
        if !(3..=63).contains(&bucket.len())
            || !bucket.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
            })
            || !bucket
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            || !bucket
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric)
            || bucket.contains("..")
            || bucket.contains(".-")
            || bucket.contains("-.")
            || bucket.parse::<std::net::Ipv4Addr>().is_ok()
            || bucket.ends_with("--x-s3")
            || bucket.ends_with("--ol-s3")
            || bucket.ends_with("-s3alias")
        {
            return Err(S3Error::InvalidInput(
                "invalid or unsupported general-purpose S3 bucket".into(),
            ));
        }
        Ok(())
    }

    /// Refuse keys the URL transport would normalize to a different object.
    pub fn validate_key(key: &str) -> S3Result<()> {
        if key.is_empty()
            || key.len() > 1024
            || key.split('/').any(|segment| matches!(segment, "." | ".."))
        {
            return Err(S3Error::InvalidInput(
                "S3 key must be 1..1024 UTF-8 bytes without dot-only path segments".into(),
            ));
        }
        Ok(())
    }

    /// Validate upload bounds and header syntax before admission or dispatch.
    pub fn validate_body(body: &[u8], content_type: Option<&str>) -> S3Result<()> {
        if body.len() > MAX_OBJECT_BYTES {
            return Err(S3Error::InvalidInput(
                "S3 object exceeds the 2 MiB invocation limit".into(),
            ));
        }
        if content_type.is_some_and(|value| {
            value.is_empty()
                || value.len() > 1024
                || value.parse::<reqwest::header::HeaderValue>().is_err()
        }) {
            return Err(S3Error::InvalidInput("invalid S3 content type".into()));
        }
        Ok(())
    }

    /// Bound one individually authorized listing page and its opaque cursor.
    pub fn validate_listing(
        prefix: Option<&str>,
        max_keys: Option<u64>,
        token: Option<&str>,
    ) -> S3Result<()> {
        if prefix.is_some_and(|value| value.len() > 1024)
            || max_keys.is_some_and(|value| !(1..=1000).contains(&value))
            || token.is_some_and(|value| {
                value.is_empty() || value.len() > 8192 || value.chars().any(char::is_control)
            })
        {
            return Err(S3Error::InvalidInput(
                "invalid S3 prefix, page size or continuation token".into(),
            ));
        }
        Ok(())
    }

    fn checked_object_url(&self, bucket: &str, key: &str) -> S3Result<String> {
        Self::validate_bucket(bucket)?;
        Self::validate_key(key)?;
        Ok(self.object_url(bucket, key))
    }

    fn signer(&self) -> S3Result<SigV4Signer> {
        let S3Auth::Keys {
            access_key_id,
            secret_access_key,
            region,
        } = &self.auth
        else {
            return Err(S3Error::InvalidInput(
                "AWS signing credentials required".into(),
            ));
        };
        Ok(SigV4Signer::new(
            AwsCredentials {
                access_key_id: access_key_id.clone(),
                secret_access_key: secret_access_key.clone(),
                session_token: self.session_token.clone(),
            },
            SigningScope {
                region: region.clone(),
                service: "s3".into(),
            },
        ))
    }

    fn signed_request(
        &self,
        method: Method,
        url: &str,
        mut headers: BTreeMap<String, String>,
        body: &[u8],
    ) -> S3Result<reqwest::Request> {
        let url = url::Url::parse(url)
            .map_err(|_| S3Error::InvalidInput("invalid S3 request URL".into()))?;
        headers.insert("host".into(), url_authority(&url));
        let signable = SignableRequest {
            method: method.to_string(),
            uri: url.path().into(),
            query_params: url
                .query_pairs()
                .map(|(key, value)| (key.into_owned(), value.into_owned()))
                .collect(),
            headers: headers.clone(),
            payload_hash: SignableRequest::hash_payload(body),
        };
        let signed = self.signer()?.sign(&signable);
        let mut builder = self
            .client
            .request(method, url)
            .header("authorization", signed.authorization)
            .header("x-amz-date", signed.x_amz_date)
            .header("x-amz-content-sha256", signed.x_amz_content_sha256)
            .body(body.to_vec());
        if let Some(token) = signed.x_amz_security_token {
            builder = builder.header("x-amz-security-token", token);
        }
        for (name, value) in headers {
            builder = builder.header(name, value);
        }
        builder
            .build()
            .map_err(|_| S3Error::InvalidInput("invalid S3 request headers".into()))
    }

    /// One shared deadline includes connect, response consumption and backoff.
    async fn request(
        &self,
        method: Method,
        url: &str,
        headers: BTreeMap<String, String>,
        body: &[u8],
        limit: usize,
    ) -> S3Result<WireResponse> {
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let read_only = method == Method::GET || method == Method::HEAD;
        RetryLoop::execute(&ctx, &policy, |attempt| {
            let method = method.clone();
            let headers = headers.clone();
            async move {
                debug!(attempt, read_only, "S3 signed request");
                let request = match self.signed_request(method.clone(), url, headers, body) {
                    Ok(request) => request,
                    Err(error) => return AttemptOutcome::Terminal(error),
                };
                let response = match self.client.execute(request).await {
                    Ok(response) => response,
                    Err(error) if read_only && error.is_connect() => {
                        return AttemptOutcome::Retryable {
                            error: S3Error::Http(error),
                            retry_after: None,
                        };
                    }
                    Err(error) => return AttemptOutcome::Terminal(S3Error::Http(error)),
                };
                let status = response.status();
                let response_limit = if status.is_success() {
                    limit
                } else {
                    MAX_ERROR_BYTES
                };
                let response =
                    match read_bounded_response(response, response_limit, method == Method::HEAD)
                        .await
                    {
                        Ok(response) => response,
                        Err(error) => return AttemptOutcome::Terminal(error),
                    };
                if status == StatusCode::OK
                    || method == Method::DELETE && status == StatusCode::NO_CONTENT
                {
                    return AttemptOutcome::Success(response);
                }
                if status.is_success() || status.is_redirection() {
                    return AttemptOutcome::Terminal(invalid_response(
                        "unexpected S3 HTTP status; redirects and partial results are refused",
                    ));
                }
                if !read_only
                    && (status.is_server_error() || status == StatusCode::TOO_MANY_REQUESTS)
                {
                    return AttemptOutcome::Terminal(invalid_response(
                        "S3 mutation failed after dispatch; reconcile its outcome before retrying",
                    ));
                }
                let error = if status == StatusCode::TOO_MANY_REQUESTS {
                    S3Error::RateLimited {
                        retry_after_ms: retry_after_millis(&response.headers).unwrap_or(30_000),
                    }
                } else {
                    parse_error_response(status, &response.body)
                };
                if read_only && error.is_retryable() {
                    let retry_after = retry_after_millis(&response.headers)
                        .map(Duration::from_millis)
                        .or_else(|| error.retry_after());
                    AttemptOutcome::Retryable { error, retry_after }
                } else {
                    AttemptOutcome::Terminal(error)
                }
            }
        })
        .await
    }
}

struct WireResponse {
    headers: HeaderMap,
    body: Vec<u8>,
}

fn require_empty_body(response: &WireResponse) -> S3Result<()> {
    if !response.body.is_empty() {
        return Err(invalid_response(
            "unexpected S3 mutation response body; outcome is unknown",
        ));
    }
    Ok(())
}

fn invalid_response(message: &str) -> S3Error {
    S3Error::InvalidResponse(message.into())
}

fn url_authority(url: &url::Url) -> String {
    url[url::Position::BeforeHost..url::Position::AfterPort].to_owned()
}

fn optional_header(headers: &HeaderMap, name: &str) -> S3Result<Option<String>> {
    let values = headers.get_all(name);
    if values.iter().count() > 1 {
        return Err(invalid_response("ambiguous S3 response metadata"));
    }
    headers
        .get(name)
        .map(|value| {
            value
                .to_str()
                .map(str::to_owned)
                .map_err(|_| invalid_response("invalid S3 response metadata"))
        })
        .transpose()
}

fn required_header(headers: &HeaderMap, name: &str) -> S3Result<String> {
    optional_header(headers, name)?
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid_response("required S3 response metadata is absent"))
}

async fn read_bounded_response(
    mut response: Response,
    limit: usize,
    head: bool,
) -> S3Result<WireResponse> {
    let headers = response.headers().clone();
    // HEAD's Content-Length describes the object, not a body on this response.
    if head {
        return Ok(WireResponse {
            headers,
            body: Vec::new(),
        });
    }
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err(invalid_response("S3 response exceeds its byte limit"));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| invalid_response("S3 response was interrupted; outcome is unknown"))?
    {
        if chunk.len() > limit.saturating_sub(body.len()) {
            return Err(invalid_response("S3 response exceeds its byte limit"));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(WireResponse { headers, body })
}

fn retry_after_millis(headers: &HeaderMap) -> Option<u64> {
    let value = headers.get("retry-after")?.to_str().ok()?.trim();
    if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Some(
            value
                .parse::<u64>()
                .unwrap_or(u64::MAX)
                .saturating_mul(1000),
        );
    }
    let deadline = chrono::DateTime::parse_from_rfc2822(value).ok()?;
    let remaining = deadline
        .signed_duration_since(chrono::Utc::now())
        .num_milliseconds();
    Some(u64::try_from(remaining).unwrap_or(0))
}

/// Validate a single complete XML document before deserializing its schema.
/// Never accept a success-shaped fragment, concatenated result, DTD or deep tree.
fn parse_xml<T: serde::de::DeserializeOwned>(bytes: &[u8], root: &str) -> S3Result<T> {
    use quick_xml::events::Event;
    let mut reader = quick_xml::Reader::from_reader(bytes);
    let mut depth = 0_u32;
    let mut seen_root = false;
    loop {
        let event = reader
            .read_event()
            .map_err(|_| invalid_response("malformed S3 XML response"))?;
        let empty = matches!(&event, Event::Empty(_));
        match event {
            Event::Start(element) | Event::Empty(element) => {
                if depth == 0 {
                    if seen_root || element.local_name().as_ref() != root.as_bytes() {
                        return Err(invalid_response("unexpected S3 XML result"));
                    }
                    seen_root = true;
                }
                if !empty {
                    depth += 1;
                }
                if depth > 32 {
                    return Err(invalid_response("S3 XML nesting exceeds limit"));
                }
            }
            Event::End(_) => {
                depth = depth
                    .checked_sub(1)
                    .ok_or_else(|| invalid_response("invalid S3 XML nesting"))?;
            }
            Event::DocType(_) => return Err(invalid_response("S3 XML DTD is forbidden")),
            Event::Decl(_) if seen_root => {
                return Err(invalid_response("unexpected S3 XML declaration"));
            }
            Event::Text(text)
                if depth == 0 && !text.as_ref().iter().all(u8::is_ascii_whitespace) =>
            {
                return Err(invalid_response("data outside S3 XML result"));
            }
            Event::CData(_) | Event::GeneralRef(_) if depth == 0 => {
                return Err(invalid_response("data outside S3 XML result"));
            }
            Event::Eof => break,
            _ => {}
        }
    }
    if !seen_root || depth != 0 {
        return Err(invalid_response("incomplete S3 XML response"));
    }
    quick_xml::de::from_reader(bytes).map_err(|_| invalid_response("invalid S3 XML result fields"))
}

fn decode_list_key(value: &str) -> S3Result<String> {
    let bytes = value.as_bytes();
    for (index, byte) in bytes.iter().enumerate() {
        if *byte == b'%'
            && (index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit())
        {
            return Err(invalid_response("malformed URL-encoded S3 key"));
        }
    }
    percent_encoding::percent_decode_str(value)
        .decode_utf8()
        .map(std::borrow::Cow::into_owned)
        .map_err(|_| invalid_response("S3 key is not valid UTF-8"))
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ListBucketDocument {
    name: String,
    is_truncated: bool,
    #[serde(default)]
    encoding_type: Option<String>,
    #[serde(default)]
    contents: Vec<ListedObject>,
    #[serde(default)]
    next_continuation_token: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ListedObject {
    key: String,
    size: u64,
    #[serde(default)]
    last_modified: Option<String>,
    #[serde(default, rename = "ETag")]
    etag: Option<String>,
    #[serde(default)]
    storage_class: Option<String>,
}

#[derive(Deserialize)]
struct CopyObjectDocument {
    #[serde(rename = "ETag")]
    etag: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ListBucketsDocument {
    buckets: BucketList,
    #[serde(default)]
    continuation_token: Option<String>,
}

#[derive(Deserialize)]
struct BucketList {
    #[serde(default, rename = "Bucket")]
    bucket: Vec<ListedBucket>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ListedBucket {
    name: String,
    #[serde(default)]
    creation_date: Option<String>,
}

/// Keep provider payloads, object identifiers and credentials out of diagnostics.
fn parse_error_response(status: StatusCode, bytes: &[u8]) -> S3Error {
    if matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) {
        return S3Error::Unauthorized;
    }
    let document = if bytes.is_empty() {
        None
    } else {
        match parse_xml::<ApiErrorResponse>(bytes, "Error") {
            Ok(document) => Some(document),
            Err(error) => return error,
        }
    };
    if status == StatusCode::NOT_FOUND {
        return if document
            .as_ref()
            .is_some_and(|error| error.code == "NoSuchBucket")
        {
            S3Error::BucketNotFound {
                bucket: "requested bucket".into(),
            }
        } else {
            S3Error::NotFound {
                key: "requested object".into(),
            }
        };
    }
    S3Error::Api {
        code: document
            .filter(|error| {
                matches!(
                    error.code.as_str(),
                    "AccessDenied"
                        | "InvalidAccessKeyId"
                        | "SignatureDoesNotMatch"
                        | "ExpiredToken"
                        | "NoSuchBucket"
                        | "NoSuchKey"
                        | "BucketAlreadyExists"
                        | "BucketAlreadyOwnedByYou"
                        | "BucketNotEmpty"
                        | "InvalidBucketName"
                        | "InvalidArgument"
                        | "InvalidRequest"
                        | "AuthorizationHeaderMalformed"
                        | "PermanentRedirect"
                        | "TemporaryRedirect"
                        | "RequestTimeTooSkewed"
                        | "RequestTimeout"
                        | "SlowDown"
                        | "ServiceUnavailable"
                        | "InternalError"
                        | "OperationAborted"
                        | "PreconditionFailed"
                )
            })
            .map_or_else(|| "HttpError".into(), |error| error.code),
        message: "S3 rejected the request".into(),
        status_code: Some(status.as_u16()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reconstruct the signature from the finished HTTP request, including its
    /// actual bytes, URI, authority and signed header values.
    fn signature_from_wire(client: &S3Client, request: &reqwest::Request) -> String {
        let authorization = request.headers()["authorization"].to_str().unwrap();
        let signed_headers = authorization
            .split_once("SignedHeaders=")
            .unwrap()
            .1
            .split(',')
            .next()
            .unwrap();
        let date = request.headers()["x-amz-date"].to_str().unwrap();
        let time = chrono::NaiveDateTime::parse_from_str(date, "%Y%m%dT%H%M%SZ")
            .unwrap()
            .and_utc();
        let signable = SignableRequest {
            method: request.method().to_string(),
            uri: request.url().path().to_owned(),
            query_params: request
                .url()
                .query_pairs()
                .map(|(name, value)| (name.into_owned(), value.into_owned()))
                .collect(),
            headers: signed_headers
                .split(';')
                .map(|name| {
                    (
                        name.to_owned(),
                        request.headers()[name].to_str().unwrap().to_owned(),
                    )
                })
                .collect(),
            payload_hash: SignableRequest::hash_payload(
                request.body().unwrap().as_bytes().unwrap(),
            ),
        };
        client
            .signer()
            .unwrap()
            .with_fixed_time(time)
            .sign(&signable)
            .authorization
    }

    #[test]
    fn test_presigned_url_generation() {
        let client = S3Client::new("AKIAIOSFODNN7EXAMPLE", "secret", "us-east-1")
            .unwrap()
            .with_base_url("https://s3.amazonaws.com")
            .unwrap();

        let result = client
            .generate_presigned_url("my-bucket", "my-file.txt", 3600)
            .unwrap();

        assert!(result.url.contains("my-bucket"));
        assert!(result.url.contains("X-Amz-Algorithm=AWS4-HMAC-SHA256"));
        assert!(result.url.contains("X-Amz-Expires=3600"));
        assert!(result.url.contains("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn test_error_is_retryable() {
        assert!(
            S3Error::RateLimited {
                retry_after_ms: 1000
            }
            .is_retryable()
        );

        assert!(!S3Error::Unauthorized.is_retryable());

        assert!(!S3Error::NotFound { key: "test".into() }.is_retryable());

        assert!(
            S3Error::Api {
                code: "InternalError".into(),
                message: "Internal".into(),
                status_code: Some(500),
            }
            .is_retryable()
        );

        assert!(
            !S3Error::Api {
                code: "NoSuchKey".into(),
                message: "Not found".into(),
                status_code: Some(404),
            }
            .is_retryable()
        );
    }

    // --- URL encoding safety tests ---

    #[test]
    fn encode_bucket_normal_name() {
        // Standard bucket names use lowercase, digits, hyphens, dots
        let encoded = S3Client::encode_bucket("my-bucket-123");
        assert_eq!(encoded, "my-bucket-123");
        assert!(!encoded.contains('/'));
    }

    #[test]
    fn encode_bucket_prevents_path_traversal() {
        let encoded = S3Client::encode_bucket("../../../etc/passwd");
        // Slashes must be encoded to prevent path traversal
        assert!(!encoded.contains('/'));
        assert!(encoded.contains("%2F"));
    }

    #[test]
    fn encode_bucket_encodes_slashes() {
        let encoded = S3Client::encode_bucket("bucket/injection");
        assert!(!encoded.contains('/'));
        assert!(encoded.contains("%2F"));
    }

    #[test]
    fn encode_bucket_encodes_query_chars() {
        let encoded = S3Client::encode_bucket("bucket?param=value");
        assert!(!encoded.contains('?'));
        assert!(!encoded.contains('='));
    }

    #[test]
    fn object_url_encodes_bucket_and_key() {
        let client = S3Client::new("key", "secret", "us-east-1")
            .unwrap()
            .with_base_url("https://s3.example.com")
            .unwrap();

        let url = client
            .checked_object_url("my-bucket", "path/to/file.txt")
            .unwrap();
        assert_eq!(url, "https://s3.example.com/my-bucket/path/to/file.txt");
    }

    #[test]
    fn object_url_encodes_special_key_chars() {
        let client = S3Client::new("key", "secret", "us-east-1")
            .unwrap()
            .with_base_url("https://s3.example.com")
            .unwrap();

        let url = client
            .checked_object_url("bucket", "file with spaces.txt")
            .unwrap();
        assert!(!url.contains(' '));
        assert!(url.contains("%20"));
    }

    #[test]
    fn object_url_bucket_traversal_blocked() {
        let client = S3Client::new("key", "secret", "us-east-1")
            .unwrap()
            .with_base_url("https://s3.example.com")
            .unwrap();

        assert!(matches!(
            client.checked_object_url("../evil-bucket", "key.txt"),
            Err(S3Error::InvalidInput(_))
        ));
    }

    #[test]
    fn bucket_url_encodes_bucket() {
        let client = S3Client::new("key", "secret", "us-east-1")
            .unwrap()
            .with_base_url("https://s3.example.com")
            .unwrap();

        let url = client.bucket_url("safe-bucket");
        assert!(url.starts_with("https://s3.example.com/"));
    }

    #[test]
    fn bucket_url_prevents_traversal() {
        assert!(matches!(
            S3Client::validate_bucket("../../admin"),
            Err(S3Error::InvalidInput(_))
        ));
    }

    #[test]
    fn presigned_url_encodes_bucket() {
        let client = S3Client::new("AKIAEXAMPLE", "secret", "us-east-1")
            .unwrap()
            .with_base_url("https://s3.amazonaws.com")
            .unwrap();

        let result = client
            .generate_presigned_url("my-bucket", "file.txt", 3600)
            .unwrap();
        // Bucket should not allow injection
        assert!(result.url.contains("X-Amz-Expires=3600"));
    }

    #[test]
    fn copy_source_header_is_encoded() {
        let client = S3Client::new("AKIAEXAMPLE", "secret", "us-east-1").unwrap();
        let source_bucket = "src-bucket";
        let source_key = "path/to/雪 +?%.txt";
        let encoded_bucket = S3Client::encode_bucket(source_bucket);
        let encoded_key = percent_encoding::utf8_percent_encode(source_key, S3_PATH_SET);
        let copy_source = format!("/{encoded_bucket}/{encoded_key}");
        assert_eq!(copy_source, "/src-bucket/path/to/%E9%9B%AA%20%2B%3F%25.txt");
        let url = client
            .checked_object_url("dest-bucket", "copied.bin")
            .unwrap();
        let request = client
            .signed_request(
                Method::PUT,
                &url,
                BTreeMap::from([("x-amz-copy-source".to_owned(), copy_source.clone())]),
                &[],
            )
            .unwrap();
        assert_eq!(request.headers()["x-amz-copy-source"], copy_source);
        assert_eq!(
            request.headers()["x-amz-content-sha256"],
            fcp_sdk::sigv4::EMPTY_PAYLOAD_HASH
        );
        let authorization = request.headers()["authorization"].to_str().unwrap();
        assert!(
            authorization
                .contains("SignedHeaders=host;x-amz-content-sha256;x-amz-copy-source;x-amz-date,")
        );
        assert_eq!(signature_from_wire(&client, &request), authorization);
        let mut altered = request.try_clone().unwrap();
        altered
            .headers_mut()
            .insert("x-amz-copy-source", "/src-bucket/other".parse().unwrap());
        assert_ne!(signature_from_wire(&client, &altered), authorization);
    }

    #[test]
    fn copy_source_bucket_traversal_blocked() {
        assert!(S3Client::validate_bucket("../other-bucket").is_err());
        for source_key in [".", "..", "path/./key", "path/../key"] {
            assert!(S3Client::validate_key(source_key).is_err(), "{source_key}");
        }
    }

    // ── Cross-Cloud Auth Regression: S3 Presigning ──────────────

    #[test]
    fn presigned_url_contains_credential_with_region() {
        let client = S3Client::new("AKIAIOSFODNN7EXAMPLE", "secret", "eu-west-1")
            .unwrap()
            .with_base_url("https://s3.eu-west-1.amazonaws.com")
            .unwrap();

        let result = client
            .generate_presigned_url("test-bucket", "test-key", 3600)
            .unwrap();
        assert!(
            result.url.contains("eu-west-1"),
            "presigned URL credential must include region: {}",
            result.url
        );
        assert!(
            result.url.contains("AKIAIOSFODNN7EXAMPLE"),
            "presigned URL must include access key: {}",
            result.url
        );
    }

    #[test]
    fn presigned_url_different_expiry_produces_different_signature() {
        let client = S3Client::new("AKIAIOSFODNN7EXAMPLE", "secret", "us-east-1")
            .unwrap()
            .with_base_url("https://s3.amazonaws.com")
            .unwrap();

        let url_300 = client.generate_presigned_url("bucket", "key", 300).unwrap();
        let url_3600 = client
            .generate_presigned_url("bucket", "key", 3600)
            .unwrap();

        assert!(url_300.url.contains("X-Amz-Expires=300"));
        assert!(url_3600.url.contains("X-Amz-Expires=3600"));

        // Different expiry should produce different signatures (canonical request differs)
        let sig_300 = url_300
            .url
            .split("X-Amz-Signature=")
            .nth(1)
            .unwrap_or("")
            .split('&')
            .next()
            .unwrap_or("");
        let sig_3600 = url_3600
            .url
            .split("X-Amz-Signature=")
            .nth(1)
            .unwrap_or("")
            .split('&')
            .next()
            .unwrap_or("");
        assert_ne!(
            sig_300, sig_3600,
            "different expiry values must produce different signatures"
        );
    }

    #[test]
    fn presigned_url_different_keys_produce_different_urls() {
        let client = S3Client::new("AKIAEXAMPLE", "secret", "us-east-1")
            .unwrap()
            .with_base_url("https://s3.amazonaws.com")
            .unwrap();

        let url1 = client
            .generate_presigned_url("bucket", "key1.txt", 3600)
            .unwrap();
        let url2 = client
            .generate_presigned_url("bucket", "key2.txt", 3600)
            .unwrap();

        assert_ne!(
            url1.url, url2.url,
            "different keys must produce different presigned URLs"
        );
    }

    #[test]
    fn s3_client_debug_redacts_credentials() {
        let client = S3Client::new("AKIAEXAMPLE", "super-secret-key", "us-east-1").unwrap();
        let debug = format!("{client:?}");
        assert!(
            !debug.contains("super-secret-key"),
            "secret key must not appear in debug output: {debug}"
        );
    }

    #[test]
    fn presigned_url_key_with_special_chars_is_encoded() {
        let client = S3Client::new("AKIAEXAMPLE", "secret", "us-east-1")
            .unwrap()
            .with_base_url("https://s3.amazonaws.com")
            .unwrap();

        let result = client
            .generate_presigned_url("bucket", "path/to/file with spaces.txt", 3600)
            .unwrap();
        assert!(
            !result.url.contains(' '),
            "presigned URL must not contain raw spaces: {}",
            result.url
        );
    }

    #[test]
    fn signed_requests_bind_binary_bytes_origin_and_session_credentials() {
        let payload = [0, 0xff, 0x80, b'\n'];
        for (endpoint, authority) in [
            ("http://127.0.0.1:9000", "127.0.0.1:9000"),
            ("https://s3.example.com:9443", "s3.example.com:9443"),
            ("http://[::1]:9001", "[::1]:9001"),
        ] {
            let client = S3Client::new("AKIAEXAMPLE", "secret", "eu-west-1")
                .unwrap()
                .with_base_url(endpoint)
                .unwrap()
                .with_session_token(Some("STS+/=token".to_owned()))
                .unwrap();
            let url = client
                .checked_object_url("my-bucket", "dir/雪 +?%#&.bin")
                .unwrap();
            let request = client
                .signed_request(
                    Method::PUT,
                    &url,
                    BTreeMap::from([(
                        "content-type".to_owned(),
                        "application/octet-stream".to_owned(),
                    )]),
                    &payload,
                )
                .unwrap();
            assert_eq!(
                request.url().path(),
                "/my-bucket/dir/%E9%9B%AA%20%2B%3F%25%23%26.bin"
            );
            assert_eq!(request.headers()["host"], authority);
            assert_eq!(request.headers()["x-amz-security-token"], "STS+/=token");
            assert_eq!(
                request.headers()["content-type"],
                "application/octet-stream"
            );
            assert_eq!(request.body().unwrap().as_bytes().unwrap(), payload);
            assert_eq!(
                request.headers()["x-amz-content-sha256"],
                SignableRequest::hash_payload(&payload)
            );
            let authorization = request.headers()["authorization"].to_str().unwrap();
            assert!(authorization.starts_with("AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE/"));
            assert!(authorization.contains("/eu-west-1/s3/aws4_request,"));
            assert!(authorization.contains("SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date;x-amz-security-token,"));
            assert_eq!(signature_from_wire(&client, &request), authorization);
            let mut altered = request.try_clone().unwrap();
            *altered.body_mut() = Some(b"different object".to_vec().into());
            assert_ne!(signature_from_wire(&client, &altered), authorization);
        }
    }

    #[test]
    fn presigning_retains_endpoint_sts_and_exact_object_path() {
        for endpoint in ["http://127.0.0.1:9000", "https://s3.example.com:9443"] {
            let client = S3Client::new("AKIAEXAMPLE", "secret", "eu-west-1")
                .unwrap()
                .with_base_url(endpoint)
                .unwrap()
                .with_session_token(Some("STS+/=token".to_owned()))
                .unwrap();
            let presigned = client
                .generate_presigned_url("my-bucket", "path//雪 +%2F", 604_800)
                .unwrap();
            let url = url::Url::parse(&presigned.url).unwrap();
            let endpoint = url::Url::parse(endpoint).unwrap();
            assert_eq!(url.origin(), endpoint.origin());
            assert_eq!(url.path(), "/my-bucket/path//%E9%9B%AA%20%2B%252F");
            let query = url.query_pairs().into_owned().collect::<BTreeMap<_, _>>();
            assert_eq!(query["X-Amz-Security-Token"], "STS+/=token");
            assert_eq!(query["X-Amz-Expires"], "604800");
            assert_eq!(query["X-Amz-SignedHeaders"], "host");
            assert!(
                presigned
                    .url
                    .contains("X-Amz-Security-Token=STS%2B%2F%3Dtoken")
            );
            let time =
                chrono::NaiveDateTime::parse_from_str(&query["X-Amz-Date"], "%Y%m%dT%H%M%SZ")
                    .unwrap()
                    .and_utc();
            let expected = client.signer().unwrap().with_fixed_time(time).presign(
                &SignableRequest {
                    method: "GET".into(),
                    uri: url.path().into(),
                    query_params: BTreeMap::new(),
                    headers: BTreeMap::from([("host".into(), url_authority(&url))]),
                    payload_hash: fcp_sdk::sigv4::UNSIGNED_PAYLOAD.into(),
                },
                604_800,
            );
            assert_eq!(url.query(), url::Url::parse(&expected.url).unwrap().query());
        }
    }

    #[test]
    fn endpoint_and_presigning_reject_ambiguous_authority_or_resources() {
        for endpoint in [
            "http://s3.example.com",
            "https://user:PRIVATESECRET@s3.example.com",
            "https://s3.example.com/bucket",
            "https://s3.example.com/?token=PRIVATESECRET",
            "https://s3.example.com/#PRIVATESECRET",
            "ftp://s3.example.com",
        ] {
            let error = S3Client::new("AKIAEXAMPLE", "secret", "us-east-1")
                .unwrap()
                .with_base_url(endpoint)
                .unwrap_err();
            assert!(matches!(error, S3Error::InvalidInput(_)));
            assert!(!error.to_string().contains("PRIVATESECRET"));
        }
        let client = S3Client::new("AKIAEXAMPLE", "secret", "us-east-1").unwrap();
        for bucket in [
            "../bucket",
            "ab",
            "bucket?x=y",
            "192.168.0.1",
            "UPPER",
            "bucket--x-s3",
        ] {
            assert!(matches!(
                client.generate_presigned_url(bucket, "key", 3600),
                Err(S3Error::InvalidInput(_))
            ));
        }
        for key in ["", ".", "..", "path/./key", "path/../key"] {
            assert!(matches!(
                client.generate_presigned_url("my-bucket", key, 3600),
                Err(S3Error::InvalidInput(_))
            ));
        }
        for expiry in [0, 604_801, u64::MAX] {
            assert!(matches!(
                client.generate_presigned_url("my-bucket", "key", expiry),
                Err(S3Error::InvalidInput(_))
            ));
        }
        assert!(
            client
                .checked_object_url("my-bucket", "path//literal%2E/key")
                .is_ok()
        );
    }

    #[test]
    fn xml_parses_real_list_copy_and_empty_bucket_documents() {
        let listing: ListBucketDocument = parse_xml(br#"<?xml version="1.0" encoding="UTF-8"?>
            <ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                <Name>my-bucket</Name><EncodingType>url</EncodingType><IsTruncated>true</IsTruncated>
                <Contents><Key>path%2Ffile%20%2B%25.txt</Key><Size>3</Size><ETag>&quot;etag&quot;</ETag></Contents>
                <NextContinuationToken>opaque+/=&amp;more</NextContinuationToken>
            </ListBucketResult>"#, "ListBucketResult").unwrap();
        assert_eq!(listing.name, "my-bucket");
        assert!(listing.is_truncated);
        assert_eq!(listing.encoding_type.as_deref(), Some("url"));
        assert_eq!(
            listing.next_continuation_token.as_deref(),
            Some("opaque+/=&more")
        );
        assert_eq!(listing.contents.len(), 1);
        assert_eq!(
            decode_list_key(&listing.contents[0].key).unwrap(),
            "path/file +%.txt"
        );
        assert_eq!(listing.contents[0].size, 3);
        assert_eq!(listing.contents[0].etag.as_deref(), Some("\"etag\""));
        let copy: CopyObjectDocument = parse_xml(
            b"<CopyObjectResult><ETag>&quot;copy-etag&quot;</ETag></CopyObjectResult>",
            "CopyObjectResult",
        )
        .unwrap();
        assert_eq!(copy.etag, "\"copy-etag\"");
        let buckets: ListBucketsDocument = parse_xml(
            b"<ListAllMyBucketsResult><Buckets /></ListAllMyBucketsResult>",
            "ListAllMyBucketsResult",
        )
        .unwrap();
        assert!(buckets.buckets.bucket.is_empty());
        assert!(buckets.continuation_token.is_none());
    }

    #[test]
    fn xml_rejects_embedded_copy_errors_and_incomplete_or_hostile_documents() {
        // CopyObject may deliver HTTP 200 with an Error document. The expected
        // root and complete body must both be verified before reporting success.
        for document in [
            "",
            "<CopyObjectResult/>",
            "<CopyObjectResult><ETag>x</ETag>",
            "<CopyObjectResult><ETag>x</ETag></Wrong>",
            "<CopyObjectResult><ETag>one</ETag><ETag>two</ETag></CopyObjectResult>",
            "<Error><Code>SlowDown</Code><Message>PRIVATESECRET</Message></Error>",
            "<CopyObjectResult><ETag>x</ETag></CopyObjectResult><CopyObjectResult><ETag>y</ETag></CopyObjectResult>",
            "<!DOCTYPE CopyObjectResult [<!ENTITY x 'PRIVATESECRET'>]><CopyObjectResult><ETag>&x;</ETag></CopyObjectResult>",
            "PRIVATESECRET<CopyObjectResult><ETag>x</ETag></CopyObjectResult>",
            "<CopyObjectResult><ETag>x</ETag></CopyObjectResult>PRIVATESECRET",
            "<![CDATA[PRIVATESECRET]]><CopyObjectResult><ETag>x</ETag></CopyObjectResult>",
            "<CopyObjectResult><ETag>x</ETag><?xml version=\"1.0\"?></CopyObjectResult>",
        ] {
            let error = parse_xml::<CopyObjectDocument>(document.as_bytes(), "CopyObjectResult")
                .err()
                .expect("invalid XML must not establish copy success");
            assert!(matches!(error, S3Error::InvalidResponse(_)), "{document}");
            assert!(!error.is_retryable());
            assert!(!error.to_string().contains("PRIVATESECRET"));
        }
        let deep = format!(
            "<CopyObjectResult>{}<ETag>x</ETag>{}</CopyObjectResult>",
            "<nested>".repeat(33),
            "</nested>".repeat(33)
        );
        assert!(parse_xml::<CopyObjectDocument>(deep.as_bytes(), "CopyObjectResult").is_err());
        for fields in [
            "<Name>a</Name><Name>b</Name><IsTruncated>false</IsTruncated>",
            "<Name>a</Name><IsTruncated>true</IsTruncated><IsTruncated>false</IsTruncated>",
            "<Name>a</Name><IsTruncated>true</IsTruncated><NextContinuationToken>one</NextContinuationToken><NextContinuationToken>two</NextContinuationToken>",
        ] {
            let document = format!("<ListBucketResult>{fields}</ListBucketResult>");
            assert!(
                parse_xml::<ListBucketDocument>(document.as_bytes(), "ListBucketResult").is_err()
            );
        }
    }

    #[test]
    fn list_key_decoding_preserves_literal_plus_and_decodes_exactly_once() {
        assert_eq!(
            decode_list_key("dir%2F%252F+%20%E9%9B%AA").unwrap(),
            "dir/%2F+ 雪"
        );
        for invalid in ["%", "%2", "%GG", "%FF", "%C3%28"] {
            assert!(
                matches!(decode_list_key(invalid), Err(S3Error::InvalidResponse(_))),
                "{invalid}"
            );
        }
    }

    #[test]
    fn response_metadata_rejects_missing_and_duplicate_values() {
        let mut headers = HeaderMap::new();
        assert!(required_header(&headers, "etag").is_err());
        headers.insert("etag", "\"first\"".parse().unwrap());
        assert_eq!(required_header(&headers, "etag").unwrap(), "\"first\"");
        headers.append("etag", "\"second\"".parse().unwrap());
        assert!(matches!(
            optional_header(&headers, "etag"),
            Err(S3Error::InvalidResponse(_))
        ));
    }

    #[test]
    fn provider_errors_expose_only_known_codes_and_no_provider_payload() {
        for code in ["SlowDown", "PRIVATESECRET"] {
            let body =
                format!("<Error><Code>{code}</Code><Message>PRIVATESECRET</Message></Error>");
            let error = parse_error_response(StatusCode::SERVICE_UNAVAILABLE, body.as_bytes());
            assert!(!error.to_string().contains("PRIVATESECRET"));
            assert!(error.is_retryable());
            match error {
                S3Error::Api { code: actual, .. } => assert_eq!(
                    actual,
                    if code == "SlowDown" {
                        "SlowDown"
                    } else {
                        "HttpError"
                    }
                ),
                other => panic!("expected sanitized provider error, got {other:?}"),
            }
        }
        let missing = parse_error_response(
            StatusCode::NOT_FOUND,
            b"<Error><Code>NoSuchBucket</Code><Message>PRIVATESECRET</Message></Error>",
        );
        assert!(matches!(missing, S3Error::BucketNotFound { .. }));
        assert!(!missing.to_string().contains("PRIVATESECRET"));
        let malformed = parse_error_response(StatusCode::BAD_GATEWAY, b"PRIVATESECRET");
        assert!(matches!(malformed, S3Error::InvalidResponse(_)));
        assert!(!malformed.to_string().contains("PRIVATESECRET"));
        assert!(matches!(
            parse_error_response(StatusCode::FORBIDDEN, b"PRIVATESECRET"),
            S3Error::Unauthorized
        ));
    }
}
