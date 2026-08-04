//! Matrix Client-Server API client.

use std::time::Duration;

use reqwest::header::{CONTENT_DISPOSITION, CONTENT_TYPE, HeaderMap, HeaderValue};
use reqwest::{Client, RequestBuilder};

use crate::error::{MatrixError, MatrixResult};
use crate::types::{
    CreateRoomRequest, CreateRoomResponse, DownloadedMedia, Event, JoinedRoomsResponse,
    MatrixDeviceKeysClaimRequest, MatrixDeviceKeysClaimResponse, MatrixDeviceKeysQueryRequest,
    MatrixDeviceKeysQueryResponse, MatrixDeviceKeysUploadResponse,
    MatrixRoomKeyBackupUploadResponse, MatrixRoomKeyBackupVersionResponse, MediaUploadResponse,
    MembersResponse, MessagesResponse, SendEventResponse, SyncResponse, WhoAmIResponse,
};

const CREDENTIAL_ID_HEADER_NAME: &str = "x-fcp-credential-id";

/// Matrix API client.
#[derive(Clone)]
pub struct MatrixClient {
    client: Client,
    homeserver_url: String,
    access_token: String,
    credential_id_header: Option<HeaderValue>,
    is_secretless: bool,
}

impl std::fmt::Debug for MatrixClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MatrixClient")
            .field("homeserver_url", &self.homeserver_url)
            .field("access_token", &"[REDACTED]")
            .field(
                "credential_id",
                &self.credential_id_header.as_ref().map(|_| "[REDACTED]"),
            )
            .field("is_secretless", &self.is_secretless)
            .finish_non_exhaustive()
    }
}

impl MatrixClient {
    /// Create a new Matrix client.
    ///
    /// # Errors
    /// Returns `MatrixError::Config` if the HTTP client cannot be built.
    pub fn new(homeserver_url: &str, access_token: &str, timeout: Duration) -> MatrixResult<Self> {
        let client = Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|e| MatrixError::Config(format!("Failed to build HTTP client: {e}")))?;

        let base = homeserver_url.trim_end_matches('/').to_string();
        let secretless = access_token.is_empty();

        Ok(Self {
            client,
            homeserver_url: base,
            access_token: access_token.to_string(),
            credential_id_header: None,
            is_secretless: secretless,
        })
    }

    /// Create a Matrix client for secretless credential injection.
    ///
    /// # Errors
    /// Returns `MatrixError::Config` if the credential header is invalid or the client cannot be
    /// built.
    pub fn new_secretless(
        homeserver_url: &str,
        credential_id: &str,
        timeout: Duration,
    ) -> MatrixResult<Self> {
        let credential_id_header = HeaderValue::from_str(credential_id)
            .map_err(|e| MatrixError::Config(format!("Invalid credential_id header: {e}")))?;

        let client = Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|e| MatrixError::Config(format!("Failed to build HTTP client: {e}")))?;

        let base = homeserver_url.trim_end_matches('/').to_string();

        Ok(Self {
            client,
            homeserver_url: base,
            access_token: String::new(),
            credential_id_header: Some(credential_id_header),
            is_secretless: true,
        })
    }

    /// Whether running in secretless mode.
    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        self.is_secretless
    }

    /// Get the homeserver URL.
    #[must_use]
    pub fn homeserver_url(&self) -> &str {
        &self.homeserver_url
    }

    // ─── Identity ───────────────────────────────────────────────────────────

    /// Get the authenticated user's identity.
    ///
    /// # Errors
    /// Returns `MatrixError` on transport or auth errors.
    pub async fn whoami(&self) -> MatrixResult<WhoAmIResponse> {
        let url = format!("{}/_matrix/client/v3/account/whoami", self.homeserver_url);
        self.api_get(&url).await
    }

    // ─── Rooms ──────────────────────────────────────────────────────────────

    /// List joined rooms.
    ///
    /// # Errors
    /// Returns `MatrixError` on transport or API errors.
    pub async fn joined_rooms(&self) -> MatrixResult<Vec<String>> {
        let url = format!("{}/_matrix/client/v3/joined_rooms", self.homeserver_url);
        let resp: JoinedRoomsResponse = self.api_get(&url).await?;
        Ok(resp.joined_rooms)
    }

    /// Fetch the full room state event set.
    ///
    /// # Errors
    /// Returns `MatrixError` on transport or API errors.
    pub async fn get_room_state(&self, room_id: &str) -> MatrixResult<Vec<Event>> {
        let encoded = urlencoded(room_id);
        let url = format!(
            "{}/_matrix/client/v3/rooms/{encoded}/state",
            self.homeserver_url
        );
        self.api_get(&url).await
    }

    /// List room members, optionally filtering by membership state.
    ///
    /// # Errors
    /// Returns `MatrixError` on transport or API errors.
    pub async fn list_members(
        &self,
        room_id: &str,
        membership: Option<&str>,
    ) -> MatrixResult<Vec<Event>> {
        let encoded = urlencoded(room_id);
        let mut url = reqwest::Url::parse(&format!(
            "{}/_matrix/client/v3/rooms/{encoded}/members",
            self.homeserver_url
        ))
        .map_err(|e| MatrixError::Config(format!("Invalid members URL: {e}")))?;
        if let Some(membership) = membership {
            url.query_pairs_mut().append_pair("membership", membership);
        }
        let resp: MembersResponse = self.api_get(url.as_str()).await?;
        Ok(resp.chunk)
    }

    /// Create a room.
    ///
    /// # Errors
    /// Returns `MatrixError` on transport or API errors.
    pub async fn create_room(&self, req: &CreateRoomRequest) -> MatrixResult<CreateRoomResponse> {
        let url = format!("{}/_matrix/client/v3/createRoom", self.homeserver_url);
        self.api_post(&url, &serde_json::to_value(req).map_err(MatrixError::Json)?)
            .await
    }

    /// Join a room by ID or alias.
    ///
    /// # Errors
    /// Returns `MatrixError` on transport or API errors.
    pub async fn join_room(&self, room_id_or_alias: &str) -> MatrixResult<serde_json::Value> {
        let encoded = urlencoded(room_id_or_alias);
        let url = format!("{}/_matrix/client/v3/join/{encoded}", self.homeserver_url);
        self.api_post(&url, &serde_json::json!({})).await
    }

    /// Leave a room.
    ///
    /// # Errors
    /// Returns `MatrixError` on transport or API errors.
    pub async fn leave_room(&self, room_id: &str) -> MatrixResult<serde_json::Value> {
        let encoded = urlencoded(room_id);
        let url = format!(
            "{}/_matrix/client/v3/rooms/{encoded}/leave",
            self.homeserver_url
        );
        self.api_post(&url, &serde_json::json!({})).await
    }

    // ─── Messages ───────────────────────────────────────────────────────────

    /// Send a text message to a room.
    ///
    /// # Errors
    /// Returns `MatrixError` on transport or API errors.
    pub async fn send_message(
        &self,
        room_id: &str,
        body: &str,
        msgtype: &str,
    ) -> MatrixResult<SendEventResponse> {
        let encoded = urlencoded(room_id);
        let txn_id = uuid::Uuid::new_v4();
        let url = format!(
            "{}/_matrix/client/v3/rooms/{encoded}/send/m.room.message/{txn_id}",
            self.homeserver_url
        );
        let content = serde_json::json!({
            "msgtype": msgtype,
            "body": body,
        });
        self.api_put(&url, &content).await
    }

    /// Get messages from a room (paginated).
    ///
    /// # Errors
    /// Returns `MatrixError` on transport or API errors.
    pub async fn get_messages(
        &self,
        room_id: &str,
        from: Option<&str>,
        limit: u32,
    ) -> MatrixResult<MessagesResponse> {
        let encoded = urlencoded(room_id);
        let mut url = reqwest::Url::parse(&format!(
            "{}/_matrix/client/v3/rooms/{encoded}/messages",
            self.homeserver_url
        ))
        .map_err(|e| MatrixError::Config(format!("Invalid messages URL: {e}")))?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("dir", "b");
            query.append_pair("limit", &limit.to_string());
            if let Some(from_token) = from {
                query.append_pair("from", from_token);
            }
        }
        self.api_get(url.as_str()).await
    }

    /// Upload media to the homeserver.
    ///
    /// # Errors
    /// Returns `MatrixError` on transport or API errors.
    pub async fn upload_media(
        &self,
        content_type: &str,
        data: Vec<u8>,
        filename: Option<&str>,
    ) -> MatrixResult<MediaUploadResponse> {
        let mut url =
            reqwest::Url::parse(&format!("{}/_matrix/media/v3/upload", self.homeserver_url))
                .map_err(|e| MatrixError::Config(format!("Invalid upload URL: {e}")))?;
        if let Some(filename) = filename {
            url.query_pairs_mut().append_pair("filename", filename);
        }

        let resp = self
            .authorize(self.client.post(url))
            .header(CONTENT_TYPE, content_type)
            .body(data)
            .send()
            .await
            .map_err(MatrixError::Http)?;
        self.handle_response(resp).await
    }

    /// Download media from the homeserver.
    ///
    /// # Errors
    /// Returns `MatrixError` on transport or API errors.
    pub async fn download_media(
        &self,
        server_name: &str,
        media_id: &str,
        allow_remote: bool,
    ) -> MatrixResult<DownloadedMedia> {
        let encoded_server = urlencoded(server_name);
        let encoded_media = urlencoded(media_id);
        let mut url = reqwest::Url::parse(&format!(
            "{}/_matrix/media/v3/download/{encoded_server}/{encoded_media}",
            self.homeserver_url
        ))
        .map_err(|e| MatrixError::Config(format!("Invalid download URL: {e}")))?;
        if !allow_remote {
            url.query_pairs_mut().append_pair("allow_remote", "false");
        }

        let resp = self
            .authorize(self.client.get(url))
            .send()
            .await
            .map_err(MatrixError::Http)?;
        self.handle_binary_response(resp).await
    }

    // ─── Sync ───────────────────────────────────────────────────────────────

    /// Perform a sync (long-poll).
    ///
    /// # Errors
    /// Returns `MatrixError` on transport or API errors.
    pub async fn sync(&self, since: Option<&str>, timeout_ms: u32) -> MatrixResult<SyncResponse> {
        let mut url =
            reqwest::Url::parse(&format!("{}/_matrix/client/v3/sync", self.homeserver_url))
                .map_err(|e| MatrixError::Config(format!("Invalid sync URL: {e}")))?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("timeout", &timeout_ms.to_string());
            if let Some(since_token) = since {
                query.append_pair("since", since_token);
            }
        }
        self.api_get(url.as_str()).await
    }

    /// Query public Matrix device and cross-signing keys through the connector transport.
    ///
    /// # Errors
    /// Returns `MatrixError` on transport, auth, or homeserver response errors.
    pub async fn query_device_keys(
        &self,
        request: &MatrixDeviceKeysQueryRequest,
    ) -> MatrixResult<MatrixDeviceKeysQueryResponse> {
        let url = format!("{}/_matrix/client/v3/keys/query", self.homeserver_url);
        self.api_post(
            &url,
            &serde_json::to_value(request).map_err(MatrixError::Json)?,
        )
        .await
    }

    /// Upload public device keys and one-time-key counts.
    ///
    /// # Errors
    /// Returns `MatrixError` on transport, auth, or homeserver response errors.
    pub async fn upload_device_keys(
        &self,
        request: &serde_json::Value,
    ) -> MatrixResult<MatrixDeviceKeysUploadResponse> {
        let url = format!("{}/_matrix/client/v3/keys/upload", self.homeserver_url);
        self.api_post(&url, request).await
    }

    /// Claim one-time keys for Olm session establishment.
    ///
    /// # Errors
    /// Returns `MatrixError` on transport, auth, or homeserver response errors.
    pub async fn claim_one_time_keys(
        &self,
        request: &MatrixDeviceKeysClaimRequest,
    ) -> MatrixResult<MatrixDeviceKeysClaimResponse> {
        let url = format!("{}/_matrix/client/v3/keys/claim", self.homeserver_url);
        self.api_post(
            &url,
            &serde_json::to_value(request).map_err(MatrixError::Json)?,
        )
        .await
    }

    /// Send an E2EE to-device message such as room-key requests or key shares.
    ///
    /// # Errors
    /// Returns `MatrixError` on transport, auth, or homeserver response errors.
    pub async fn send_to_device(
        &self,
        event_type: &str,
        txn_id: &str,
        messages: &serde_json::Value,
    ) -> MatrixResult<serde_json::Value> {
        let encoded_event_type = urlencoded(event_type);
        let encoded_txn = urlencoded(txn_id);
        let url = format!(
            "{}/_matrix/client/v3/sendToDevice/{encoded_event_type}/{encoded_txn}",
            self.homeserver_url
        );
        self.api_put(&url, messages).await
    }

    /// Fetch the active room-key backup version metadata.
    ///
    /// # Errors
    /// Returns `MatrixError` on transport, auth, or homeserver response errors.
    pub async fn room_key_backup_version(
        &self,
    ) -> MatrixResult<MatrixRoomKeyBackupVersionResponse> {
        let url = format!(
            "{}/_matrix/client/v3/room_keys/version",
            self.homeserver_url
        );
        self.api_get(&url).await
    }

    /// Upload room-key backup records for a known backup version.
    ///
    /// # Errors
    /// Returns `MatrixError` on transport, auth, or homeserver response errors.
    pub async fn upload_room_keys(
        &self,
        version: &str,
        request: &serde_json::Value,
    ) -> MatrixResult<MatrixRoomKeyBackupUploadResponse> {
        let mut url = reqwest::Url::parse(&format!(
            "{}/_matrix/client/v3/room_keys/keys",
            self.homeserver_url
        ))
        .map_err(|e| MatrixError::Config(format!("Invalid room-key backup URL: {e}")))?;
        url.query_pairs_mut().append_pair("version", version);
        self.api_put(url.as_str(), request).await
    }

    /// Delete a stale backed-up room key before reuploading corrected material.
    ///
    /// # Errors
    /// Returns `MatrixError` on transport, auth, or homeserver response errors.
    pub async fn delete_room_key(
        &self,
        version: &str,
        room_id: &str,
        session_id: &str,
    ) -> MatrixResult<serde_json::Value> {
        let encoded_room = urlencoded(room_id);
        let encoded_session = urlencoded(session_id);
        let mut url = reqwest::Url::parse(&format!(
            "{}/_matrix/client/v3/room_keys/keys/{encoded_room}/{encoded_session}",
            self.homeserver_url
        ))
        .map_err(|e| MatrixError::Config(format!("Invalid room-key delete URL: {e}")))?;
        url.query_pairs_mut().append_pair("version", version);
        self.api_delete(url.as_str()).await
    }

    // ─── Health ─────────────────────────────────────────────────────────────

    /// Lightweight health check.
    ///
    /// # Errors
    /// Returns `MatrixError` if the homeserver is unreachable or authentication fails.
    pub async fn health_check(&self) -> MatrixResult<()> {
        let url = format!("{}/_matrix/client/v3/account/whoami", self.homeserver_url);
        let resp = self
            .authorize(self.client.get(&url))
            .send()
            .await
            .map_err(MatrixError::Http)?;
        let status = resp.status().as_u16();
        if status == 200 {
            Ok(())
        } else {
            let body = resp.text().await.unwrap_or_default();
            Err(MatrixError::from_matrix_response(status, &body))
        }
    }

    // ─── Internals ──────────────────────────────────────────────────────────

    async fn api_get<T: serde::de::DeserializeOwned>(&self, url: &str) -> MatrixResult<T> {
        let resp = self
            .authorize(self.client.get(url))
            .send()
            .await
            .map_err(MatrixError::Http)?;
        self.handle_response(resp).await
    }

    async fn api_post<T: serde::de::DeserializeOwned>(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> MatrixResult<T> {
        let resp = self
            .authorize(self.client.post(url))
            .json(body)
            .send()
            .await
            .map_err(MatrixError::Http)?;
        self.handle_response(resp).await
    }

    async fn api_put<T: serde::de::DeserializeOwned>(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> MatrixResult<T> {
        let resp = self
            .authorize(self.client.put(url))
            .json(body)
            .send()
            .await
            .map_err(MatrixError::Http)?;
        self.handle_response(resp).await
    }

    async fn api_delete<T: serde::de::DeserializeOwned>(&self, url: &str) -> MatrixResult<T> {
        let resp = self
            .authorize(self.client.delete(url))
            .send()
            .await
            .map_err(MatrixError::Http)?;
        self.handle_response(resp).await
    }

    fn authorize(&self, request: RequestBuilder) -> RequestBuilder {
        if let Some(credential_id_header) = &self.credential_id_header {
            let mut headers = HeaderMap::with_capacity(1);
            headers.insert(CREDENTIAL_ID_HEADER_NAME, credential_id_header.clone());
            request.headers(headers)
        } else if self.access_token.is_empty() {
            request
        } else {
            request.bearer_auth(&self.access_token)
        }
    }

    async fn handle_response<T: serde::de::DeserializeOwned>(
        &self,
        resp: reqwest::Response,
    ) -> MatrixResult<T> {
        let status = resp.status().as_u16();
        if status == 429 {
            let retry_after = resp
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok())
                .map_or(30_000, |s| s * 1000);
            return Err(MatrixError::RateLimited {
                retry_after_ms: retry_after,
            });
        }
        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(MatrixError::from_matrix_response(status, &body));
        }
        resp.json().await.map_err(MatrixError::Http)
    }

    async fn handle_binary_response(
        &self,
        resp: reqwest::Response,
    ) -> MatrixResult<DownloadedMedia> {
        let status = resp.status().as_u16();
        if status == 429 {
            let retry_after = resp
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok())
                .map_or(30_000, |s| s * 1000);
            return Err(MatrixError::RateLimited {
                retry_after_ms: retry_after,
            });
        }
        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(MatrixError::from_matrix_response(status, &body));
        }

        let content_type = resp
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(ToOwned::to_owned);
        let content_disposition = resp
            .headers()
            .get(CONTENT_DISPOSITION)
            .and_then(|value| value.to_str().ok())
            .map(ToOwned::to_owned);
        let data = resp.bytes().await.map_err(MatrixError::Http)?.to_vec();
        Ok(DownloadedMedia {
            content_type,
            content_disposition,
            data,
        })
    }
}

/// Minimal URL encoding for path segments.
///
/// `/` and every other reserved byte is percent-encoded, so a caller-supplied
/// value can never introduce extra path structure. The one remaining hazard is
/// a segment consisting solely of dot characters (`.`, `..`, `...`): that is a
/// relative dot-segment which `Url::parse` normalizes away, letting the value
/// collapse a path level (e.g. `room_id = ".."` turns `/rooms/../members` into
/// `/members`). Percent-encode the dots in that case; a single `.` inside an
/// otherwise-normal identifier (server names, event types like
/// `m.room.message`) is left readable.
fn urlencoded(s: &str) -> String {
    let is_dot_segment = !s.is_empty() && s.bytes().all(|b| b == b'.');
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'.' if is_dot_segment => out.push_str("%2E"),
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                use std::fmt::Write;
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread::{self, JoinHandle};
    use std::time::{Duration as StdDuration, Instant};

    #[test]
    fn urlencoded_neutralizes_dot_segments_but_keeps_dotted_ids_readable() {
        // Pure dot-segments would normalize away in the request path.
        assert_eq!(urlencoded(".."), "%2E%2E");
        assert_eq!(urlencoded("."), "%2E");
        assert_eq!(urlencoded("..."), "%2E%2E%2E");
        // Slashes are always encoded, so multi-segment traversal can't form.
        assert_eq!(urlencoded("a/b"), "a%2Fb");
        // Dots inside a normal identifier stay readable (server decodes either way).
        assert_eq!(urlencoded("m.room.message"), "m.room.message");
        assert_eq!(urlencoded("!abc123:matrix.org"), "%21abc123%3Amatrix.org");
    }

    enum TestHttpPath {
        Exact(&'static str),
        Prefix(&'static str),
    }

    enum TestHttpBody {
        Json(serde_json::Value),
        Text(&'static str),
        Bytes(&'static [u8]),
    }

    struct TestHttpResponse {
        method: &'static str,
        path: TestHttpPath,
        status: u16,
        query_contains: Vec<&'static str>,
        request_header_equals: Vec<(&'static str, &'static str)>,
        request_header_present: Vec<&'static str>,
        request_header_absent: Vec<&'static str>,
        json_body_fields: Option<serde_json::Value>,
        response_headers: Vec<(&'static str, &'static str)>,
        body: TestHttpBody,
    }

    struct TestHttpServer {
        url: String,
        handle: Option<JoinHandle<()>>,
    }

    impl TestHttpResponse {
        fn json(
            method: &'static str,
            path: &'static str,
            status: u16,
            body: serde_json::Value,
        ) -> Self {
            Self {
                method,
                path: TestHttpPath::Exact(path),
                status,
                query_contains: Vec::new(),
                request_header_equals: Vec::new(),
                request_header_present: Vec::new(),
                request_header_absent: Vec::new(),
                json_body_fields: None,
                response_headers: Vec::new(),
                body: TestHttpBody::Json(body),
            }
        }

        fn json_path_prefix(
            method: &'static str,
            path_prefix: &'static str,
            status: u16,
            body: serde_json::Value,
        ) -> Self {
            Self {
                method,
                path: TestHttpPath::Prefix(path_prefix),
                status,
                query_contains: Vec::new(),
                request_header_equals: Vec::new(),
                request_header_present: Vec::new(),
                request_header_absent: Vec::new(),
                json_body_fields: None,
                response_headers: Vec::new(),
                body: TestHttpBody::Json(body),
            }
        }

        fn text(method: &'static str, path: &'static str, status: u16, body: &'static str) -> Self {
            Self {
                method,
                path: TestHttpPath::Exact(path),
                status,
                query_contains: Vec::new(),
                request_header_equals: Vec::new(),
                request_header_present: Vec::new(),
                request_header_absent: Vec::new(),
                json_body_fields: None,
                response_headers: Vec::new(),
                body: TestHttpBody::Text(body),
            }
        }

        fn bytes(
            method: &'static str,
            path: &'static str,
            status: u16,
            body: &'static [u8],
        ) -> Self {
            Self {
                method,
                path: TestHttpPath::Exact(path),
                status,
                query_contains: Vec::new(),
                request_header_equals: Vec::new(),
                request_header_present: Vec::new(),
                request_header_absent: Vec::new(),
                json_body_fields: None,
                response_headers: Vec::new(),
                body: TestHttpBody::Bytes(body),
            }
        }

        fn with_query_contains(mut self, fragment: &'static str) -> Self {
            self.query_contains.push(fragment);
            self
        }

        fn with_request_header(mut self, name: &'static str, value: &'static str) -> Self {
            self.request_header_equals.push((name, value));
            self
        }

        fn with_request_header_present(mut self, name: &'static str) -> Self {
            self.request_header_present.push(name);
            self
        }

        fn with_request_header_absent(mut self, name: &'static str) -> Self {
            self.request_header_absent.push(name);
            self
        }

        fn with_json_body_fields(mut self, fields: serde_json::Value) -> Self {
            self.json_body_fields = Some(fields);
            self
        }

        fn with_response_header(mut self, name: &'static str, value: &'static str) -> Self {
            self.response_headers.push((name, value));
            self
        }
    }

    impl TestHttpServer {
        fn respond(responses: Vec<TestHttpResponse>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let handle = thread::spawn(move || {
                listener.set_nonblocking(true).unwrap();
                for response in responses {
                    let stream = accept_test_connection(&listener);
                    handle_test_request(stream, response);
                }
            });
            Self {
                url,
                handle: Some(handle),
            }
        }

        fn uri(&self) -> &str {
            &self.url
        }
    }

    impl Drop for TestHttpServer {
        fn drop(&mut self) {
            if let Some(handle) = self.handle.take() {
                if thread::panicking() {
                    let _ = handle.join();
                } else {
                    handle.join().unwrap();
                }
            }
        }
    }

    fn accept_test_connection(listener: &TcpListener) -> TcpStream {
        let deadline = Instant::now() + StdDuration::from_secs(5);
        loop {
            match listener.accept() {
                Ok((stream, _)) => {
                    stream.set_nonblocking(false).unwrap();
                    return stream;
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        Instant::now() < deadline,
                        "test listener did not receive expected request"
                    );
                    thread::sleep(StdDuration::from_millis(10));
                }
                Err(err) => panic!("test listener failed: {err}"),
            }
        }
    }

    fn handle_test_request(stream: TcpStream, response: TestHttpResponse) {
        stream
            .set_read_timeout(Some(StdDuration::from_secs(2)))
            .unwrap();
        let mut reader = BufReader::new(stream);
        let mut request_line = String::new();
        reader.read_line(&mut request_line).unwrap();
        let mut request_parts = request_line.split_whitespace();
        assert_eq!(request_parts.next(), Some(response.method));
        let target = request_parts.next().unwrap_or_default();
        let actual_path = target.split('?').next().unwrap_or_default();
        match response.path {
            TestHttpPath::Exact(path) => assert_eq!(actual_path, path),
            TestHttpPath::Prefix(prefix) => assert!(
                actual_path.starts_with(prefix),
                "request path {actual_path:?} did not start with {prefix:?}"
            ),
        }
        for fragment in &response.query_contains {
            assert!(
                target.contains(fragment),
                "request target {target:?} did not contain query fragment {fragment:?}"
            );
        }

        let mut headers = Vec::new();
        let mut content_length = 0usize;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let trimmed = line.trim_end_matches(['\r', '\n']);
            if trimmed.is_empty() {
                break;
            }
            if let Some((name, value)) = trimmed.split_once(':') {
                let value = value.trim().to_string();
                if name.eq_ignore_ascii_case("content-length") {
                    content_length = value.parse().unwrap();
                }
                headers.push((name.to_string(), value));
            }
        }
        for (name, expected_value) in &response.request_header_equals {
            let values = request_header_values(&headers, name);
            assert!(
                values.contains(expected_value),
                "request header {name:?} values {values:?} did not include {expected_value:?}"
            );
        }
        for name in &response.request_header_present {
            assert!(
                !request_header_values(&headers, name).is_empty(),
                "request header {name:?} should be present"
            );
        }
        for name in &response.request_header_absent {
            assert!(
                request_header_values(&headers, name).is_empty(),
                "request header {name:?} should be absent"
            );
        }

        let mut request_body = vec![0u8; content_length];
        if content_length > 0 {
            reader.read_exact(&mut request_body).unwrap();
        }
        if let Some(expected_fields) = response.json_body_fields {
            let actual_body: serde_json::Value =
                serde_json::from_slice(&request_body).expect("request body should be JSON");
            assert_json_contains(&actual_body, &expected_fields);
        }

        let mut stream = reader.into_inner();
        let (body, content_type) = match response.body {
            TestHttpBody::Json(body) => (body.to_string().into_bytes(), Some("application/json")),
            TestHttpBody::Text(body) => (body.as_bytes().to_vec(), None),
            TestHttpBody::Bytes(body) => (body.to_vec(), None),
        };
        let reason = match response.status {
            400 => "Bad Request",
            401 => "Unauthorized",
            429 => "Too Many Requests",
            _ => "OK",
        };
        write!(
            stream,
            "HTTP/1.1 {} {}\r\ncontent-length: {}\r\nconnection: close\r\n",
            response.status,
            reason,
            body.len()
        )
        .unwrap();
        if let Some(content_type) = content_type {
            write!(stream, "content-type: {content_type}\r\n").unwrap();
        }
        for (name, value) in response.response_headers {
            write!(stream, "{name}: {value}\r\n").unwrap();
        }
        write!(stream, "\r\n").unwrap();
        stream.write_all(&body).unwrap();
        stream.flush().unwrap();
    }

    fn request_header_values<'a>(headers: &'a [(String, String)], name: &str) -> Vec<&'a str> {
        headers
            .iter()
            .filter(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
            .collect()
    }

    fn assert_json_contains(actual: &serde_json::Value, expected: &serde_json::Value) {
        match (actual, expected) {
            (serde_json::Value::Object(actual_map), serde_json::Value::Object(expected_map)) => {
                for (key, expected_value) in expected_map {
                    let actual_value = actual_map
                        .get(key)
                        .unwrap_or_else(|| panic!("request JSON should contain field {key:?}"));
                    assert_json_contains(actual_value, expected_value);
                }
            }
            _ => assert_eq!(actual, expected),
        }
    }

    #[test]
    fn new_client_trims_slash() {
        let c = MatrixClient::new("https://matrix.org/", "tok", Duration::from_secs(30)).unwrap();
        assert_eq!(c.homeserver_url(), "https://matrix.org");
    }

    #[test]
    fn secretless_detection() {
        let c = MatrixClient::new("https://matrix.org", "", Duration::from_secs(30)).unwrap();
        assert!(c.is_secretless());
    }

    #[test]
    fn secretless_constructor_preserves_credential_reference() {
        let c =
            MatrixClient::new_secretless("https://matrix.org", "cred_1", Duration::from_secs(30))
                .unwrap();
        assert!(c.is_secretless());
    }

    #[test]
    fn not_secretless() {
        let c = MatrixClient::new("https://matrix.org", "tok", Duration::from_secs(30)).unwrap();
        assert!(!c.is_secretless());
    }

    #[test]
    fn urlencoded_room_id() {
        let encoded = urlencoded("!room:matrix.org");
        assert_eq!(encoded, "%21room%3Amatrix.org");
    }

    #[fcp_async_core::runtime::test]
    async fn whoami_parses() {
        let server = TestHttpServer::respond(vec![TestHttpResponse::json(
            "GET",
            "/_matrix/client/v3/account/whoami",
            200,
            serde_json::json!({
                "user_id": "@bot:matrix.org",
                "device_id": "DEV1"
            }),
        )]);

        let c = MatrixClient::new(server.uri(), "tok", Duration::from_secs(10)).unwrap();
        let resp = c.whoami().await.unwrap();
        assert_eq!(resp.user_id, "@bot:matrix.org");
    }

    #[fcp_async_core::runtime::test]
    async fn secretless_client_sends_credential_header() {
        let server = TestHttpServer::respond(vec![
            TestHttpResponse::json(
                "GET",
                "/_matrix/client/v3/account/whoami",
                200,
                serde_json::json!({
                    "user_id": "@bot:matrix.org"
                }),
            )
            .with_request_header(CREDENTIAL_ID_HEADER_NAME, "cred_1")
            .with_request_header_absent("authorization"),
        ]);

        let c =
            MatrixClient::new_secretless(server.uri(), "cred_1", Duration::from_secs(10)).unwrap();
        let _ = c.whoami().await.unwrap();
    }

    #[fcp_async_core::runtime::test]
    async fn joined_rooms_parses() {
        let server = TestHttpServer::respond(vec![TestHttpResponse::json(
            "GET",
            "/_matrix/client/v3/joined_rooms",
            200,
            serde_json::json!({
                "joined_rooms": ["!a:m.org", "!b:m.org"]
            }),
        )]);

        let c = MatrixClient::new(server.uri(), "tok", Duration::from_secs(10)).unwrap();
        let rooms = c.joined_rooms().await.unwrap();
        assert_eq!(rooms.len(), 2);
    }

    #[fcp_async_core::runtime::test]
    async fn send_message_returns_event_id() {
        let server = TestHttpServer::respond(vec![
            TestHttpResponse::json_path_prefix(
                "PUT",
                "/_matrix/client/v3/rooms/%21room%3Am.org/send/m.room.message/",
                200,
                serde_json::json!({
                    "event_id": "$new_event"
                }),
            )
            .with_json_body_fields(serde_json::json!({
                "msgtype": "m.text",
                "body": "Hello"
            })),
        ]);

        let c = MatrixClient::new(server.uri(), "tok", Duration::from_secs(10)).unwrap();
        let resp = c
            .send_message("!room:m.org", "Hello", "m.text")
            .await
            .unwrap();
        assert_eq!(resp.event_id, "$new_event");
    }

    #[fcp_async_core::runtime::test]
    async fn get_messages_encodes_from_token() {
        let server = TestHttpServer::respond(vec![
            TestHttpResponse::json(
                "GET",
                "/_matrix/client/v3/rooms/%21room%3Am.org/messages",
                200,
                serde_json::json!({
                    "chunk": [],
                    "end": "next"
                }),
            )
            .with_query_contains("dir=b")
            .with_query_contains("limit=20")
            .with_query_contains("from=a%2Fb%2Bc%3D%3D"),
        ]);

        let c = MatrixClient::new(server.uri(), "tok", Duration::from_secs(10)).unwrap();
        let resp = c
            .get_messages("!room:m.org", Some("a/b+c=="), 20)
            .await
            .unwrap();
        assert_eq!(resp.end.as_deref(), Some("next"));
    }

    #[fcp_async_core::runtime::test]
    async fn query_device_keys_posts_request_and_parses_trust_material_shape() {
        let server = TestHttpServer::respond(vec![
            TestHttpResponse::json(
                "POST",
                "/_matrix/client/v3/keys/query",
                200,
                serde_json::json!({
                    "device_keys": {
                        "@bot:matrix.org": {
                            "DEVICE123": {
                                "user_id": "@bot:matrix.org",
                                "device_id": "DEVICE123",
                                "algorithms": ["m.olm.v1.curve25519-aes-sha2"],
                                "keys": {
                                    "ed25519:DEVICE123": "public-ed25519"
                                },
                                "signatures": {
                                    "@bot:matrix.org": {
                                        "ed25519:DEVICE123": "public-signature"
                                    }
                                }
                            }
                        }
                    },
                    "master_keys": {
                        "@bot:matrix.org": {
                            "user_id": "@bot:matrix.org",
                            "usage": ["master"],
                            "keys": {
                                "ed25519:MASTER": "public-master"
                            }
                        }
                    },
                    "self_signing_keys": {},
                    "user_signing_keys": {},
                    "failures": {}
                }),
            )
            .with_json_body_fields(serde_json::json!({
                "device_keys": {
                    "@bot:matrix.org": ["DEVICE123"]
                },
                "timeout": 5000,
                "token": "sync_token"
            })),
        ]);

        let c = MatrixClient::new(server.uri(), "tok", Duration::from_secs(10)).unwrap();
        let response = c
            .query_device_keys(&MatrixDeviceKeysQueryRequest {
                device_keys: std::collections::BTreeMap::from([(
                    "@bot:matrix.org".to_string(),
                    vec!["DEVICE123".to_string()],
                )]),
                timeout: Some(5000),
                token: Some("sync_token".into()),
            })
            .await
            .unwrap();

        assert_eq!(
            response
                .device_keys
                .get("@bot:matrix.org")
                .and_then(|devices| devices.get("DEVICE123"))
                .map(|device| device.keys.contains_key("ed25519:DEVICE123")),
            Some(true)
        );
        assert_eq!(
            response
                .master_keys
                .get("@bot:matrix.org")
                .map(|key| key.usage.clone()),
            Some(vec!["master".to_string()])
        );
    }

    #[fcp_async_core::runtime::test]
    async fn e2ee_maintenance_methods_use_explicit_matrix_endpoints() {
        let server = TestHttpServer::respond(vec![
            TestHttpResponse::json(
                "POST",
                "/_matrix/client/v3/keys/upload",
                200,
                serde_json::json!({
                    "one_time_key_counts": { "signed_curve25519": 2 }
                }),
            )
            .with_request_header_present("authorization"),
            TestHttpResponse::json(
                "POST",
                "/_matrix/client/v3/keys/claim",
                200,
                serde_json::json!({
                    "failures": {},
                    "one_time_keys": {}
                }),
            )
            .with_request_header_present("authorization"),
            TestHttpResponse::json(
                "PUT",
                "/_matrix/client/v3/sendToDevice/m.room.encrypted/txn-1",
                200,
                serde_json::json!({}),
            )
            .with_request_header_present("authorization"),
            TestHttpResponse::json(
                "GET",
                "/_matrix/client/v3/room_keys/version",
                200,
                serde_json::json!({
                    "algorithm": "m.megolm_backup.v1.curve25519-aes-sha2",
                    "auth_data": {},
                    "count": "0",
                    "etag": "etag-1",
                    "version": "1"
                }),
            )
            .with_request_header_present("authorization"),
            TestHttpResponse::json(
                "PUT",
                "/_matrix/client/v3/room_keys/keys",
                200,
                serde_json::json!({
                    "count": "1",
                    "etag": "etag-2"
                }),
            )
            .with_query_contains("version=1")
            .with_request_header_present("authorization"),
            TestHttpResponse::json(
                "DELETE",
                "/_matrix/client/v3/room_keys/keys/%21room%3Am.org/session-1",
                200,
                serde_json::json!({}),
            )
            .with_query_contains("version=1")
            .with_request_header_present("authorization"),
        ]);

        let c = MatrixClient::new(server.uri(), "tok", Duration::from_secs(10)).unwrap();
        let upload = c
            .upload_device_keys(&serde_json::json!({
                "device_keys": { "user_id": "@bot:m.org", "device_id": "DEV1" }
            }))
            .await
            .unwrap();
        let claim = c
            .claim_one_time_keys(&MatrixDeviceKeysClaimRequest {
                one_time_keys: std::collections::BTreeMap::from([(
                    "@alice:m.org".to_string(),
                    std::collections::BTreeMap::from([(
                        "ALICEDEVICE".to_string(),
                        "signed_curve25519".to_string(),
                    )]),
                )]),
                timeout: Some(1000),
            })
            .await
            .unwrap();
        let to_device = c
            .send_to_device(
                "m.room.encrypted",
                "txn-1",
                &serde_json::json!({ "messages": {} }),
            )
            .await
            .unwrap();
        let backup = c.room_key_backup_version().await.unwrap();
        let room_keys = c
            .upload_room_keys("1", &serde_json::json!({ "rooms": {} }))
            .await
            .unwrap();
        let delete = c
            .delete_room_key("1", "!room:m.org", "session-1")
            .await
            .unwrap();

        assert_eq!(
            upload.one_time_key_counts.get("signed_curve25519"),
            Some(&2)
        );
        assert!(claim.failures.is_empty());
        assert_eq!(to_device, serde_json::json!({}));
        assert_eq!(backup.version.as_deref(), Some("1"));
        assert_eq!(room_keys.etag.as_deref(), Some("etag-2"));
        assert_eq!(delete, serde_json::json!({}));
    }

    #[fcp_async_core::runtime::test]
    async fn get_room_state_parses_events() {
        let server = TestHttpServer::respond(vec![TestHttpResponse::json(
            "GET",
            "/_matrix/client/v3/rooms/%21room%3Am.org/state",
            200,
            serde_json::json!([
                {
                    "type": "m.room.name",
                    "state_key": "",
                    "content": { "name": "General" }
                }
            ]),
        )]);

        let c = MatrixClient::new(server.uri(), "tok", Duration::from_secs(10)).unwrap();
        let events = c.get_room_state("!room:m.org").await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].state_key.as_deref(), Some(""));
    }

    #[fcp_async_core::runtime::test]
    async fn list_members_supports_membership_filter() {
        let server = TestHttpServer::respond(vec![
            TestHttpResponse::json(
                "GET",
                "/_matrix/client/v3/rooms/%21room%3Am.org/members",
                200,
                serde_json::json!({
                    "chunk": [
                        {
                            "type": "m.room.member",
                            "state_key": "@alice:m.org",
                            "content": { "membership": "join", "displayname": "Alice" }
                        }
                    ]
                }),
            )
            .with_query_contains("membership=join"),
        ]);

        let c = MatrixClient::new(server.uri(), "tok", Duration::from_secs(10)).unwrap();
        let members = c.list_members("!room:m.org", Some("join")).await.unwrap();
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].state_key.as_deref(), Some("@alice:m.org"));
    }

    #[fcp_async_core::runtime::test]
    async fn sync_includes_since_and_timeout() {
        let server = TestHttpServer::respond(vec![
            TestHttpResponse::json(
                "GET",
                "/_matrix/client/v3/sync",
                200,
                serde_json::json!({
                    "next_batch": "batch_2"
                }),
            )
            .with_query_contains("since=batch_1")
            .with_query_contains("timeout=5000"),
        ]);

        let c = MatrixClient::new(server.uri(), "tok", Duration::from_secs(10)).unwrap();
        let response = c.sync(Some("batch_1"), 5000).await.unwrap();
        assert_eq!(response.next_batch, "batch_2");
    }

    #[fcp_async_core::runtime::test]
    async fn upload_media_sends_filename_query_and_content_type() {
        let server = TestHttpServer::respond(vec![
            TestHttpResponse::json(
                "POST",
                "/_matrix/media/v3/upload",
                200,
                serde_json::json!({
                    "content_uri": "mxc://matrix.org/media123"
                }),
            )
            .with_query_contains("filename=greeting.txt")
            .with_request_header("content-type", "text/plain"),
        ]);

        let c = MatrixClient::new(server.uri(), "tok", Duration::from_secs(10)).unwrap();
        let response = c
            .upload_media("text/plain", b"hello".to_vec(), Some("greeting.txt"))
            .await
            .unwrap();
        assert_eq!(response.content_uri, "mxc://matrix.org/media123");
    }

    #[fcp_async_core::runtime::test]
    async fn download_media_returns_headers_and_bytes() {
        let server = TestHttpServer::respond(vec![
            TestHttpResponse::bytes(
                "GET",
                "/_matrix/media/v3/download/matrix.org/media123",
                200,
                b"pngdata",
            )
            .with_query_contains("allow_remote=false")
            .with_response_header("content-type", "image/png")
            .with_response_header("content-disposition", "inline; filename=\"cat.png\""),
        ]);

        let c = MatrixClient::new(server.uri(), "tok", Duration::from_secs(10)).unwrap();
        let media = c
            .download_media("matrix.org", "media123", false)
            .await
            .unwrap();
        assert_eq!(media.content_type.as_deref(), Some("image/png"));
        assert_eq!(
            media.content_disposition.as_deref(),
            Some("inline; filename=\"cat.png\"")
        );
        assert_eq!(media.data, b"pngdata".to_vec());
    }

    #[fcp_async_core::runtime::test]
    async fn handles_401_unauthorized() {
        let server = TestHttpServer::respond(vec![TestHttpResponse::json(
            "GET",
            "/_matrix/client/v3/joined_rooms",
            401,
            serde_json::json!({
                "errcode": "M_UNKNOWN_TOKEN",
                "error": "Unrecognised access token."
            }),
        )]);

        let c = MatrixClient::new(server.uri(), "tok", Duration::from_secs(10)).unwrap();
        let result = c.joined_rooms().await;
        assert!(matches!(result.unwrap_err(), MatrixError::Unauthorized(_)));
    }

    #[fcp_async_core::runtime::test]
    async fn handles_429_rate_limited() {
        let server = TestHttpServer::respond(vec![
            TestHttpResponse::text(
                "GET",
                "/_matrix/client/v3/joined_rooms",
                429,
                "rate limited",
            )
            .with_response_header("retry-after", "60"),
        ]);

        let c = MatrixClient::new(server.uri(), "tok", Duration::from_secs(10)).unwrap();
        let result = c.joined_rooms().await;
        assert!(matches!(
            result,
            Err(MatrixError::RateLimited {
                retry_after_ms: 60_000
            })
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn health_check_ok() {
        let server = TestHttpServer::respond(vec![TestHttpResponse::json(
            "GET",
            "/_matrix/client/v3/account/whoami",
            200,
            serde_json::json!({
                "user_id": "@bot:m.org"
            }),
        )]);

        let c = MatrixClient::new(server.uri(), "tok", Duration::from_secs(10)).unwrap();
        assert!(c.health_check().await.is_ok());
    }

    #[fcp_async_core::runtime::test]
    async fn health_check_401_is_unauthorized() {
        let server = TestHttpServer::respond(vec![TestHttpResponse::json(
            "GET",
            "/_matrix/client/v3/account/whoami",
            401,
            serde_json::json!({
                "errcode": "M_UNKNOWN_TOKEN",
                "error": "Unrecognised access token."
            }),
        )]);

        let c = MatrixClient::new(server.uri(), "tok", Duration::from_secs(10)).unwrap();
        let err = c.health_check().await.unwrap_err();
        assert!(matches!(err, MatrixError::Unauthorized(_)));
    }
}
