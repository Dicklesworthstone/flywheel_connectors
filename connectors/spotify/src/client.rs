//! `Spotify` API client.

use fcp_prelude::log_redaction::redact_url;
use std::fmt::{self, Write as _};
use std::time::Duration;

use fcp_prelude::CredentialId;
use fcp_sdk::migration::HttpRetryConfig;
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use reqwest::{Client, Response, StatusCode};
use tracing::{debug, instrument};

use crate::{
    error::{SpotifyError, SpotifyResult},
    history::HistoryQuery,
    types::ApiErrorResponse,
};

/// Default `Spotify` Web API base URL.
pub const DEFAULT_BASE_URL: &str = "https://api.spotify.com/v1";

/// Authentication mode for the `Spotify` API.
#[derive(Clone)]
pub enum SpotifyAuth {
    /// `OAuth2` access token (passed as `Authorization: Bearer <token>`).
    AccessToken(String),
    /// Secretless credential reference (egress proxy injection).
    CredentialId(CredentialId),
}

impl SpotifyAuth {
    #[must_use]
    pub fn redacted_label(&self) -> String {
        match self {
            Self::AccessToken(_) => "access_token:redacted".to_string(),
            Self::CredentialId(id) => format!("credential_id:{id}"),
        }
    }

    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId(_))
    }
}

impl fmt::Debug for SpotifyAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AccessToken(_) => f.debug_tuple("AccessToken").field(&"<redacted>").finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

/// `Spotify` API client.
pub struct SpotifyClient {
    client: Client,
    auth: SpotifyAuth,
    base_url: String,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
}

impl fmt::Debug for SpotifyClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SpotifyClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .field("retry_config", &self.retry_config)
            .finish_non_exhaustive()
    }
}

impl SpotifyClient {
    /// Create a new `Spotify` client.
    pub fn new(auth: SpotifyAuth, base_url: Option<&str>) -> SpotifyResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-spotify/0.1.0 (FCP connector)")
            .build()?;

        Ok(Self {
            client,
            auth,
            base_url: base_url
                .unwrap_or(DEFAULT_BASE_URL)
                .trim_end_matches('/')
                .to_string(),
            runtime: ConnectorRuntime::new(
                ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_secs(30)),
            ),
            retry_config: HttpRetryConfig {
                max_retries: 2,
                ..HttpRetryConfig::default()
            },
        })
    }

    /// Trigger graceful shutdown.
    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    fn add_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.auth {
            SpotifyAuth::AccessToken(token) => req.bearer_auth(token),
            SpotifyAuth::CredentialId(id) => req.header("X-FCP-Credential-Id", id.to_string()),
        }
    }

    async fn handle_response(&self, resp: Response) -> SpotifyResult<serde_json::Value> {
        self.handle_response_with_empty_action(resp, false).await
    }

    async fn handle_response_with_empty_action(
        &self,
        resp: Response,
        allow_empty_ok: bool,
    ) -> SpotifyResult<serde_json::Value> {
        let status = resp.status();
        if status.is_success() {
            let body = resp.text().await?;
            decode_success_body(status, &body, allow_empty_ok)
        } else {
            self.handle_error(status, resp).await
        }
    }

    async fn handle_error(
        &self,
        status: StatusCode,
        resp: Response,
    ) -> SpotifyResult<serde_json::Value> {
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        let mut body = resp.text().await.unwrap_or_default();
        body.truncate(2048);

        // Spotify returns {"error": {"status": 401, "message": "..."}} on errors.
        let detail = serde_json::from_str::<ApiErrorResponse>(&body)
            .ok()
            .and_then(|e| e.error)
            .and_then(|e| e.message)
            .unwrap_or_else(|| {
                if body.is_empty() {
                    format!("HTTP {}", status.as_u16())
                } else {
                    body.clone()
                }
            });

        match status.as_u16() {
            401 => Err(SpotifyError::Unauthorized),
            403 => Err(SpotifyError::Forbidden),
            404 => Err(SpotifyError::NotFound { resource: detail }),
            429 => Err(SpotifyError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(60) * 1000,
            }),
            code => Err(SpotifyError::Api {
                status_code: code,
                message: detail,
            }),
        }
    }

    #[instrument(skip(self), fields(url))]
    async fn get(&self, path: &str) -> SpotifyResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %redact_url(&url), "GET request");
        let req = self
            .add_auth(self.client.get(&url))
            .header("Accept", "application/json");
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    #[instrument(skip(self, body), fields(url))]
    async fn put(&self, path: &str, body: &serde_json::Value) -> SpotifyResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %redact_url(&url), "PUT request");
        let req = self
            .add_auth(self.client.put(&url))
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .json(body);
        let resp = req.send().await?;
        self.handle_response_with_empty_action(resp, true).await
    }

    #[instrument(skip(self), fields(url))]
    async fn put_empty(&self, path: &str) -> SpotifyResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %redact_url(&url), "PUT (empty body) request");
        let req = self
            .add_auth(self.client.put(&url))
            .header("Accept", "application/json")
            .header("Content-Length", "0");
        let resp = req.send().await?;
        self.handle_response_with_empty_action(resp, true).await
    }

    #[instrument(skip(self, body), fields(url))]
    async fn post(&self, path: &str, body: &serde_json::Value) -> SpotifyResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %redact_url(&url), "POST request");
        let req = self
            .add_auth(self.client.post(&url))
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .json(body);
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    #[instrument(skip(self), fields(url))]
    async fn post_empty(&self, path: &str) -> SpotifyResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %redact_url(&url), "POST (empty body) request");
        let req = self
            .add_auth(self.client.post(&url))
            .header("Accept", "application/json")
            .header("Content-Length", "0");
        let resp = req.send().await?;
        self.handle_response_with_empty_action(resp, true).await
    }

    #[instrument(skip(self), fields(url))]
    async fn delete(&self, path: &str) -> SpotifyResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %redact_url(&url), "DELETE request");
        let req = self
            .add_auth(self.client.delete(&url))
            .header("Accept", "application/json");
        let resp = req.send().await?;
        self.handle_response_with_empty_action(resp, true).await
    }

    #[instrument(skip(self, body), fields(url))]
    async fn delete_with_body(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> SpotifyResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %redact_url(&url), "DELETE (with body) request");
        let req = self
            .add_auth(self.client.delete(&url))
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .json(body);
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    #[instrument(skip(self, body), fields(url))]
    async fn delete_with_body_empty_action(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> SpotifyResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %redact_url(&url), "DELETE (with body, empty action) request");
        let req = self
            .add_auth(self.client.delete(&url))
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .json(body);
        let resp = req.send().await?;
        self.handle_response_with_empty_action(resp, true).await
    }

    // -- Profile --

    /// Get the current user's profile.
    pub async fn get_current_profile(&self) -> SpotifyResult<serde_json::Value> {
        self.get("/me").await
    }

    // -- Search --

    /// Search for tracks, albums, artists, playlists, etc.
    pub async fn search(
        &self,
        query: &str,
        types: &str,
        limit: u32,
    ) -> SpotifyResult<serde_json::Value> {
        let encoded_query = percent_encode(query);
        self.get(&format!(
            "/search?q={encoded_query}&type={types}&limit={limit}"
        ))
        .await
    }

    /// Search for tracks only.
    pub async fn search_tracks(
        &self,
        query: &str,
        limit: u32,
        market: Option<&str>,
    ) -> SpotifyResult<serde_json::Value> {
        let encoded_query = percent_encode(query);
        let mut url = format!("/search?q={encoded_query}&type=track&limit={limit}");
        if let Some(m) = market {
            url = format!("{url}&market={m}");
        }
        self.get(&url).await
    }

    /// Search for albums only.
    pub async fn search_albums(
        &self,
        query: &str,
        limit: u32,
        market: Option<&str>,
    ) -> SpotifyResult<serde_json::Value> {
        let encoded_query = percent_encode(query);
        let mut url = format!("/search?q={encoded_query}&type=album&limit={limit}");
        if let Some(m) = market {
            url = format!("{url}&market={m}");
        }
        self.get(&url).await
    }

    /// Search for artists only.
    pub async fn search_artists(
        &self,
        query: &str,
        limit: u32,
        market: Option<&str>,
    ) -> SpotifyResult<serde_json::Value> {
        let encoded_query = percent_encode(query);
        let mut url = format!("/search?q={encoded_query}&type=artist&limit={limit}");
        if let Some(m) = market {
            url = format!("{url}&market={m}");
        }
        self.get(&url).await
    }

    /// Search for shows (podcasts) only.
    pub async fn search_shows(
        &self,
        query: &str,
        limit: u32,
        market: Option<&str>,
    ) -> SpotifyResult<serde_json::Value> {
        let encoded_query = percent_encode(query);
        let mut url = format!("/search?q={encoded_query}&type=show&limit={limit}");
        if let Some(m) = market {
            url = format!("{url}&market={m}");
        }
        self.get(&url).await
    }

    /// Search for episodes only.
    pub async fn search_episodes(
        &self,
        query: &str,
        limit: u32,
        market: Option<&str>,
    ) -> SpotifyResult<serde_json::Value> {
        let encoded_query = percent_encode(query);
        let mut url = format!("/search?q={encoded_query}&type=episode&limit={limit}");
        if let Some(m) = market {
            url = format!("{url}&market={m}");
        }
        self.get(&url).await
    }

    // -- Tracks --

    /// Get a track by ID.
    pub async fn get_track(&self, track_id: &str) -> SpotifyResult<serde_json::Value> {
        self.get(&format!("/tracks/{track_id}")).await
    }

    // -- Albums --

    /// Get an album by ID.
    pub async fn get_album(&self, album_id: &str) -> SpotifyResult<serde_json::Value> {
        self.get(&format!("/albums/{album_id}")).await
    }

    // -- Artists --

    /// Get an artist by ID.
    pub async fn get_artist(&self, artist_id: &str) -> SpotifyResult<serde_json::Value> {
        self.get(&format!("/artists/{artist_id}")).await
    }

    // -- Playlists --

    /// Get a playlist by ID.
    pub async fn get_playlist(&self, playlist_id: &str) -> SpotifyResult<serde_json::Value> {
        self.get(&format!("/playlists/{playlist_id}")).await
    }

    /// List the current user's playlists.
    pub async fn list_playlists(&self) -> SpotifyResult<serde_json::Value> {
        self.get("/me/playlists").await
    }

    // -- Player --

    /// Get the current user's recently played tracks.
    pub async fn get_recently_played(
        &self,
        query: &HistoryQuery,
    ) -> SpotifyResult<serde_json::Value> {
        let mut path = format!("/me/player/recently-played?limit={}", query.limit);
        if let Some(after) = query.after {
            write!(&mut path, "&after={after}").map_err(|error| SpotifyError::Api {
                status_code: 500,
                message: format!("failed to build recently played query: {error}"),
            })?;
        }
        if let Some(before) = query.before {
            write!(&mut path, "&before={before}").map_err(|error| SpotifyError::Api {
                status_code: 500,
                message: format!("failed to build recently played query: {error}"),
            })?;
        }
        self.get(&path).await
    }

    // -- Top Items --

    /// Get the current user's top artists or tracks.
    pub async fn get_top_items(
        &self,
        item_type: &str,
        time_range: &str,
        limit: u32,
    ) -> SpotifyResult<serde_json::Value> {
        self.get(&format!(
            "/me/top/{item_type}?time_range={time_range}&limit={limit}"
        ))
        .await
    }

    // -- Recommendations --

    /// Get track recommendations based on seed artists and genres.
    pub async fn get_recommendations(
        &self,
        seed_artists: &str,
        seed_genres: &str,
        limit: u32,
    ) -> SpotifyResult<serde_json::Value> {
        self.get(&format!(
            "/recommendations?seed_artists={seed_artists}&seed_genres={seed_genres}&limit={limit}"
        ))
        .await
    }

    /// Get available genre seeds for recommendations.
    pub async fn get_genre_seeds(&self) -> SpotifyResult<serde_json::Value> {
        self.get("/recommendations/available-genre-seeds").await
    }

    // -- Podcasts (Shows & Episodes) --

    /// Get a show (podcast) by ID.
    pub async fn get_show(
        &self,
        show_id: &str,
        market: Option<&str>,
    ) -> SpotifyResult<serde_json::Value> {
        let mut url = format!("/shows/{show_id}");
        if let Some(m) = market {
            url = format!("{url}?market={m}");
        }
        self.get(&url).await
    }

    /// Get episodes of a show (podcast).
    pub async fn get_show_episodes(
        &self,
        show_id: &str,
        limit: u32,
        offset: u32,
        market: Option<&str>,
    ) -> SpotifyResult<serde_json::Value> {
        let mut url = format!("/shows/{show_id}/episodes?limit={limit}&offset={offset}");
        if let Some(m) = market {
            url = format!("{url}&market={m}");
        }
        self.get(&url).await
    }

    /// Get an episode by ID.
    pub async fn get_episode(
        &self,
        episode_id: &str,
        market: Option<&str>,
    ) -> SpotifyResult<serde_json::Value> {
        let mut url = format!("/episodes/{episode_id}");
        if let Some(m) = market {
            url = format!("{url}?market={m}");
        }
        self.get(&url).await
    }

    // -- Playback Control --

    /// Get the current playback state.
    pub async fn get_playback_state(&self) -> SpotifyResult<serde_json::Value> {
        self.get("/me/player").await
    }

    /// Get available devices.
    pub async fn get_devices(&self) -> SpotifyResult<serde_json::Value> {
        self.get("/me/player/devices").await
    }

    /// Start or resume playback.
    pub async fn play(
        &self,
        device_id: Option<&str>,
        context_uri: Option<&str>,
        uris: Option<&[String]>,
    ) -> SpotifyResult<serde_json::Value> {
        let mut path = "/me/player/play".to_string();
        if let Some(did) = device_id {
            path = format!("{path}?device_id={}", percent_encode(did));
        }
        let mut body = serde_json::json!({});
        if let Some(ctx) = context_uri {
            body["context_uri"] = serde_json::json!(ctx);
        }
        if let Some(u) = uris {
            body["uris"] = serde_json::json!(u);
        }
        self.put(&path, &body).await
    }

    /// Pause playback.
    pub async fn pause(&self, device_id: Option<&str>) -> SpotifyResult<serde_json::Value> {
        let mut path = "/me/player/pause".to_string();
        if let Some(did) = device_id {
            path = format!("{path}?device_id={}", percent_encode(did));
        }
        self.put_empty(&path).await
    }

    /// Skip to next track.
    pub async fn skip_next(&self, device_id: Option<&str>) -> SpotifyResult<serde_json::Value> {
        let mut path = "/me/player/next".to_string();
        if let Some(did) = device_id {
            path = format!("{path}?device_id={}", percent_encode(did));
        }
        self.post_empty(&path).await
    }

    /// Skip to previous track.
    pub async fn skip_previous(&self, device_id: Option<&str>) -> SpotifyResult<serde_json::Value> {
        let mut path = "/me/player/previous".to_string();
        if let Some(did) = device_id {
            path = format!("{path}?device_id={}", percent_encode(did));
        }
        self.post_empty(&path).await
    }

    /// Seek to a position in the currently playing track.
    pub async fn seek(
        &self,
        position_ms: u64,
        device_id: Option<&str>,
    ) -> SpotifyResult<serde_json::Value> {
        let mut path = format!("/me/player/seek?position_ms={position_ms}");
        if let Some(did) = device_id {
            path = format!("{path}&device_id={}", percent_encode(did));
        }
        self.put_empty(&path).await
    }

    /// Set the playback volume.
    pub async fn set_volume(
        &self,
        volume_percent: u32,
        device_id: Option<&str>,
    ) -> SpotifyResult<serde_json::Value> {
        let mut path = format!("/me/player/volume?volume_percent={volume_percent}");
        if let Some(did) = device_id {
            path = format!("{path}&device_id={}", percent_encode(did));
        }
        self.put_empty(&path).await
    }

    /// Set shuffle mode.
    pub async fn set_shuffle(
        &self,
        state: bool,
        device_id: Option<&str>,
    ) -> SpotifyResult<serde_json::Value> {
        let mut path = format!("/me/player/shuffle?state={state}");
        if let Some(did) = device_id {
            path = format!("{path}&device_id={}", percent_encode(did));
        }
        self.put_empty(&path).await
    }

    /// Set repeat mode.
    pub async fn set_repeat(
        &self,
        state: &str,
        device_id: Option<&str>,
    ) -> SpotifyResult<serde_json::Value> {
        let mut path = format!("/me/player/repeat?state={}", percent_encode(state));
        if let Some(did) = device_id {
            path = format!("{path}&device_id={}", percent_encode(did));
        }
        self.put_empty(&path).await
    }

    /// Transfer playback to a new device.
    pub async fn transfer_playback(
        &self,
        device_id: &str,
        play: bool,
    ) -> SpotifyResult<serde_json::Value> {
        let body = serde_json::json!({
            "device_ids": [device_id],
            "play": play,
        });
        self.put("/me/player", &body).await
    }

    // -- Library Management --

    /// Get the current user's saved tracks.
    pub async fn get_saved_tracks(
        &self,
        limit: u32,
        offset: u32,
    ) -> SpotifyResult<serde_json::Value> {
        self.get(&format!("/me/tracks?limit={limit}&offset={offset}"))
            .await
    }

    /// Save tracks to the current user's library.
    pub async fn save_tracks(&self, ids: &[String]) -> SpotifyResult<serde_json::Value> {
        let body = serde_json::json!({ "ids": ids });
        self.put("/me/tracks", &body).await
    }

    /// Remove tracks from the current user's library.
    pub async fn remove_saved_tracks(&self, ids: &[String]) -> SpotifyResult<serde_json::Value> {
        let body = serde_json::json!({ "ids": ids });
        self.delete_with_body_empty_action("/me/tracks", &body)
            .await
    }

    /// Check if tracks are saved in the current user's library.
    pub async fn check_saved_tracks(&self, ids: &[String]) -> SpotifyResult<serde_json::Value> {
        let ids_str = ids.join(",");
        self.get(&format!("/me/tracks/contains?ids={ids_str}"))
            .await
    }

    /// Get the current user's saved albums.
    pub async fn get_saved_albums(
        &self,
        limit: u32,
        offset: u32,
    ) -> SpotifyResult<serde_json::Value> {
        self.get(&format!("/me/albums?limit={limit}&offset={offset}"))
            .await
    }

    /// Save albums to the current user's library.
    pub async fn save_albums(&self, ids: &[String]) -> SpotifyResult<serde_json::Value> {
        let body = serde_json::json!({ "ids": ids });
        self.put("/me/albums", &body).await
    }

    /// Remove albums from the current user's library.
    pub async fn remove_saved_albums(&self, ids: &[String]) -> SpotifyResult<serde_json::Value> {
        let body = serde_json::json!({ "ids": ids });
        self.delete_with_body_empty_action("/me/albums", &body)
            .await
    }

    // -- Playlist CRUD --

    /// Create a new playlist.
    pub async fn create_playlist(
        &self,
        user_id: &str,
        name: &str,
        public: bool,
        description: Option<&str>,
    ) -> SpotifyResult<serde_json::Value> {
        let mut body = serde_json::json!({
            "name": name,
            "public": public,
        });
        if let Some(desc) = description {
            body["description"] = serde_json::json!(desc);
        }
        self.post(&format!("/users/{user_id}/playlists"), &body)
            .await
    }

    /// Update an existing playlist's details.
    pub async fn update_playlist(
        &self,
        playlist_id: &str,
        name: Option<&str>,
        public: Option<bool>,
        description: Option<&str>,
    ) -> SpotifyResult<serde_json::Value> {
        let mut body = serde_json::json!({});
        if let Some(n) = name {
            body["name"] = serde_json::json!(n);
        }
        if let Some(p) = public {
            body["public"] = serde_json::json!(p);
        }
        if let Some(d) = description {
            body["description"] = serde_json::json!(d);
        }
        self.put(&format!("/playlists/{playlist_id}"), &body).await
    }

    /// Add tracks to a playlist.
    pub async fn add_tracks_to_playlist(
        &self,
        playlist_id: &str,
        uris: &[String],
        position: Option<u32>,
    ) -> SpotifyResult<serde_json::Value> {
        let mut body = serde_json::json!({ "uris": uris });
        if let Some(pos) = position {
            body["position"] = serde_json::json!(pos);
        }
        self.post(&format!("/playlists/{playlist_id}/tracks"), &body)
            .await
    }

    /// Remove tracks from a playlist.
    pub async fn remove_tracks_from_playlist(
        &self,
        playlist_id: &str,
        uris: &[String],
    ) -> SpotifyResult<serde_json::Value> {
        let tracks: Vec<serde_json::Value> =
            uris.iter().map(|u| serde_json::json!({"uri": u})).collect();
        let body = serde_json::json!({ "tracks": tracks });
        self.delete_with_body(&format!("/playlists/{playlist_id}/tracks"), &body)
            .await
    }

    /// Get tracks from a playlist.
    pub async fn get_playlist_tracks(
        &self,
        playlist_id: &str,
        limit: u32,
        offset: u32,
    ) -> SpotifyResult<serde_json::Value> {
        self.get(&format!(
            "/playlists/{playlist_id}/tracks?limit={limit}&offset={offset}"
        ))
        .await
    }
}

/// Simple percent-encoding for query strings.
fn percent_encode(s: &str) -> String {
    s.replace('%', "%25")
        .replace(' ', "%20")
        .replace('&', "%26")
        .replace('=', "%3D")
        .replace('+', "%2B")
        .replace('#', "%23")
}

fn decode_success_body(
    status: StatusCode,
    body: &str,
    allow_empty_ok: bool,
) -> SpotifyResult<serde_json::Value> {
    if status == StatusCode::NO_CONTENT
        || (allow_empty_ok && status == StatusCode::OK && body.trim().is_empty())
    {
        return Ok(serde_json::json!({}));
    }
    if body.trim().is_empty() {
        return Err(SpotifyError::Api {
            status_code: status.as_u16(),
            message: "empty response body".into(),
        });
    }
    Ok(serde_json::from_str(body)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_debug_redacts_token() {
        let auth = SpotifyAuth::AccessToken("secret-access-token".into());
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("secret-access-token"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn auth_secretless_detection() {
        let token = SpotifyAuth::AccessToken("tok".into());
        assert!(!token.is_secretless());
        let cred = SpotifyAuth::CredentialId(CredentialId::new());
        assert!(cred.is_secretless());
    }

    #[test]
    fn auth_redacted_label() {
        let token = SpotifyAuth::AccessToken("tok".into());
        assert_eq!(token.redacted_label(), "access_token:redacted");
    }

    #[test]
    fn auth_credential_label() {
        let cred = SpotifyAuth::CredentialId(CredentialId::new());
        let label = cred.redacted_label();
        assert!(label.starts_with("credential_id:"));
    }

    #[test]
    fn client_new_default_url() {
        let client = SpotifyClient::new(SpotifyAuth::AccessToken("tok".into()), None).unwrap();
        assert_eq!(client.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn client_new_custom_url() {
        let client = SpotifyClient::new(
            SpotifyAuth::AccessToken("tok".into()),
            Some("https://test.example.com/v1/"),
        )
        .unwrap();
        assert_eq!(client.base_url, "https://test.example.com/v1");
    }

    #[test]
    fn client_debug_redacts() {
        let client = SpotifyClient::new(SpotifyAuth::AccessToken("secret".into()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(!dbg.contains("secret"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn percent_encode_spaces() {
        assert_eq!(percent_encode("hello world"), "hello%20world");
    }

    #[test]
    fn percent_encode_special_chars() {
        assert_eq!(percent_encode("a&b=c"), "a%26b%3Dc");
    }

    #[test]
    fn percent_encode_hash() {
        assert_eq!(percent_encode("test#1"), "test%231");
    }

    #[test]
    fn percent_encode_plus() {
        assert_eq!(percent_encode("a+b"), "a%2Bb");
    }

    #[test]
    fn percent_encode_percent() {
        assert_eq!(percent_encode("100%"), "100%25");
    }

    #[test]
    fn percent_encode_no_change() {
        assert_eq!(percent_encode("simple"), "simple");
    }

    #[test]
    fn decode_success_body_rejects_empty_json_ok() {
        let err = decode_success_body(StatusCode::OK, "", false).unwrap_err();
        assert!(matches!(
            err,
            SpotifyError::Api {
                status_code: 200,
                message
            } if message == "empty response body"
        ));
    }

    #[test]
    fn decode_success_body_rejects_whitespace_json_ok() {
        let err = decode_success_body(StatusCode::OK, "  \n\t", false).unwrap_err();
        assert!(matches!(
            err,
            SpotifyError::Api {
                status_code: 200,
                message
            } if message == "empty response body"
        ));
    }

    #[test]
    fn decode_success_body_allows_empty_no_content() {
        assert_eq!(
            decode_success_body(StatusCode::NO_CONTENT, "", false).unwrap(),
            serde_json::json!({})
        );
    }

    #[test]
    fn decode_success_body_allows_empty_ok_for_action() {
        assert_eq!(
            decode_success_body(StatusCode::OK, "", true).unwrap(),
            serde_json::json!({})
        );
    }

    // ── Additional client coverage ───────────────────────────────

    #[test]
    fn auth_debug_credential_id() {
        let cred = SpotifyAuth::CredentialId(CredentialId::new());
        let dbg = format!("{cred:?}");
        assert!(dbg.contains("CredentialId"));
    }

    #[test]
    fn auth_clone() {
        let auth = SpotifyAuth::AccessToken("secret".into());
        #[allow(clippy::redundant_clone)]
        let auth2 = auth.clone();
        assert_eq!(auth2.redacted_label(), "access_token:redacted");
    }

    #[test]
    fn auth_credential_id_clone() {
        let id = CredentialId::new();
        let auth = SpotifyAuth::CredentialId(id);
        #[allow(clippy::redundant_clone)]
        let auth2 = auth.clone();
        assert!(auth2.is_secretless());
    }

    #[test]
    fn client_debug_contains_base_url() {
        let client = SpotifyClient::new(SpotifyAuth::AccessToken("tok".into()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("SpotifyClient"));
        assert!(dbg.contains(DEFAULT_BASE_URL));
    }

    #[test]
    fn client_custom_url_trimmed() {
        let client = SpotifyClient::new(
            SpotifyAuth::AccessToken("tok".into()),
            Some("https://api.example.com/v1///"),
        )
        .unwrap();
        // Only trailing slashes should be stripped
        assert!(!client.base_url.ends_with('/'));
    }

    #[test]
    fn default_base_url_constant() {
        assert_eq!(DEFAULT_BASE_URL, "https://api.spotify.com/v1");
    }

    #[test]
    fn percent_encode_empty_string() {
        assert_eq!(percent_encode(""), "");
    }

    #[test]
    fn percent_encode_all_special() {
        let result = percent_encode("% & = + #");
        assert!(result.contains("%25"));
        assert!(result.contains("%26"));
        assert!(result.contains("%3D"));
        assert!(result.contains("%2B"));
        assert!(result.contains("%23"));
    }

    #[test]
    fn percent_encode_unicode_untouched() {
        // Non-special ASCII chars pass through
        let result = percent_encode("abc123");
        assert_eq!(result, "abc123");
    }

    #[test]
    fn client_with_credential_id_auth() {
        let client =
            SpotifyClient::new(SpotifyAuth::CredentialId(CredentialId::new()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("CredentialId"));
    }

    #[test]
    fn percent_encode_multiple_spaces() {
        let result = percent_encode("a b c d");
        assert_eq!(result, "a%20b%20c%20d");
    }

    #[test]
    fn percent_encode_consecutive_specials() {
        let result = percent_encode("&&==");
        assert_eq!(result, "%26%26%3D%3D");
    }
}
