//! YouTube Data API v3 types.

use serde::{Deserialize, Serialize};

// ── Common ──────────────────────────────────────────────────────

/// Thumbnail information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Thumbnail {
    pub url: String,
    pub width: Option<u32>,
    pub height: Option<u32>,
}

/// Set of thumbnails at different resolutions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThumbnailSet {
    pub default: Option<Thumbnail>,
    pub medium: Option<Thumbnail>,
    pub high: Option<Thumbnail>,
    pub standard: Option<Thumbnail>,
    pub maxres: Option<Thumbnail>,
}

/// Page info for paginated responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PageInfo {
    pub total_results: u32,
    pub results_per_page: u32,
}

// ── Search ──────────────────────────────────────────────────────

/// A search result item.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchResult {
    pub kind: String,
    pub etag: String,
    pub id: SearchResultId,
    pub snippet: Option<SearchSnippet>,
}

/// The ID portion of a search result (can be video, channel, or playlist).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchResultId {
    pub kind: String,
    pub video_id: Option<String>,
    pub channel_id: Option<String>,
    pub playlist_id: Option<String>,
}

/// Snippet data from a search result.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchSnippet {
    pub published_at: Option<String>,
    pub channel_id: Option<String>,
    pub title: String,
    pub description: String,
    pub thumbnails: Option<ThumbnailSet>,
    pub channel_title: Option<String>,
    pub live_broadcast_content: Option<String>,
}

/// Search list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchListResponse {
    pub kind: String,
    pub etag: String,
    pub next_page_token: Option<String>,
    pub prev_page_token: Option<String>,
    pub page_info: Option<PageInfo>,
    pub items: Vec<SearchResult>,
}

// ── Video ───────────────────────────────────────────────────────

/// Video resource.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Video {
    pub kind: String,
    pub etag: String,
    pub id: String,
    pub snippet: Option<VideoSnippet>,
    pub content_details: Option<ContentDetails>,
    pub statistics: Option<VideoStatistics>,
}

/// Video snippet data.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VideoSnippet {
    pub published_at: Option<String>,
    pub channel_id: Option<String>,
    pub title: String,
    pub description: String,
    pub thumbnails: Option<ThumbnailSet>,
    pub channel_title: Option<String>,
    pub tags: Option<Vec<String>>,
    pub category_id: Option<String>,
    pub live_broadcast_content: Option<String>,
    pub default_language: Option<String>,
    pub default_audio_language: Option<String>,
}

/// Video content details (duration, definition, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContentDetails {
    pub duration: Option<String>,
    pub dimension: Option<String>,
    pub definition: Option<String>,
    pub caption: Option<String>,
    pub licensed_content: Option<bool>,
    pub projection: Option<String>,
}

/// Video statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VideoStatistics {
    pub view_count: Option<String>,
    pub like_count: Option<String>,
    pub dislike_count: Option<String>,
    pub favorite_count: Option<String>,
    pub comment_count: Option<String>,
}

/// Video list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VideoListResponse {
    pub kind: String,
    pub etag: String,
    pub page_info: Option<PageInfo>,
    pub items: Vec<Video>,
}

// ── Channel ─────────────────────────────────────────────────────

/// Channel resource.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Channel {
    pub kind: String,
    pub etag: String,
    pub id: String,
    pub snippet: Option<ChannelSnippet>,
    pub statistics: Option<ChannelStatistics>,
    pub content_details: Option<ChannelContentDetails>,
}

/// Channel snippet.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelSnippet {
    pub title: String,
    pub description: String,
    pub custom_url: Option<String>,
    pub published_at: Option<String>,
    pub thumbnails: Option<ThumbnailSet>,
    pub country: Option<String>,
}

/// Channel statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelStatistics {
    pub view_count: Option<String>,
    pub subscriber_count: Option<String>,
    pub hidden_subscriber_count: Option<bool>,
    pub video_count: Option<String>,
}

/// Channel content details (related playlists).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelContentDetails {
    pub related_playlists: Option<RelatedPlaylists>,
}

/// Related playlists for a channel (uploads, likes, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelatedPlaylists {
    pub likes: Option<String>,
    pub uploads: Option<String>,
}

/// Channel list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelListResponse {
    pub kind: String,
    pub etag: String,
    pub page_info: Option<PageInfo>,
    pub items: Vec<Channel>,
}

// ── Playlists ───────────────────────────────────────────────────

/// Playlist resource.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Playlist {
    pub kind: String,
    pub etag: String,
    pub id: String,
    pub snippet: Option<PlaylistSnippet>,
    pub content_details: Option<PlaylistContentDetails>,
}

/// Playlist snippet.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlaylistSnippet {
    pub published_at: Option<String>,
    pub channel_id: Option<String>,
    pub title: String,
    pub description: String,
    pub thumbnails: Option<ThumbnailSet>,
    pub channel_title: Option<String>,
}

/// Playlist content details.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlaylistContentDetails {
    pub item_count: Option<u32>,
}

/// Playlist list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlaylistListResponse {
    pub kind: String,
    pub etag: String,
    pub next_page_token: Option<String>,
    pub prev_page_token: Option<String>,
    pub page_info: Option<PageInfo>,
    pub items: Vec<Playlist>,
}

// ── Playlist Items ──────────────────────────────────────────────

/// Playlist item resource.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlaylistItem {
    pub kind: String,
    pub etag: String,
    pub id: String,
    pub snippet: Option<PlaylistItemSnippet>,
    pub content_details: Option<PlaylistItemContentDetails>,
}

/// Playlist item snippet.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlaylistItemSnippet {
    pub published_at: Option<String>,
    pub channel_id: Option<String>,
    pub title: String,
    pub description: String,
    pub thumbnails: Option<ThumbnailSet>,
    pub channel_title: Option<String>,
    pub playlist_id: Option<String>,
    pub position: Option<u32>,
    pub resource_id: Option<ResourceId>,
}

/// Resource ID for a playlist item.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceId {
    pub kind: String,
    pub video_id: Option<String>,
}

/// Playlist item content details.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlaylistItemContentDetails {
    pub video_id: Option<String>,
    pub video_published_at: Option<String>,
}

/// Playlist items list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlaylistItemListResponse {
    pub kind: String,
    pub etag: String,
    pub next_page_token: Option<String>,
    pub prev_page_token: Option<String>,
    pub page_info: Option<PageInfo>,
    pub items: Vec<PlaylistItem>,
}

// ── Comments ────────────────────────────────────────────────────

/// Comment thread (top-level comment + replies).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CommentThread {
    pub kind: String,
    pub etag: String,
    pub id: String,
    pub snippet: Option<CommentThreadSnippet>,
}

/// Comment thread snippet.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CommentThreadSnippet {
    pub channel_id: Option<String>,
    pub video_id: Option<String>,
    pub top_level_comment: Option<Comment>,
    pub can_reply: Option<bool>,
    pub total_reply_count: Option<u32>,
    pub is_public: Option<bool>,
}

/// A single comment.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Comment {
    pub kind: Option<String>,
    pub etag: Option<String>,
    pub id: String,
    pub snippet: Option<CommentSnippet>,
}

/// Comment snippet data.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CommentSnippet {
    pub author_display_name: Option<String>,
    pub author_profile_image_url: Option<String>,
    pub author_channel_url: Option<String>,
    pub text_display: Option<String>,
    pub text_original: Option<String>,
    pub parent_id: Option<String>,
    pub video_id: Option<String>,
    pub viewer_rating: Option<String>,
    pub like_count: Option<u32>,
    pub published_at: Option<String>,
    pub updated_at: Option<String>,
}

/// Comment thread list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CommentThreadListResponse {
    pub kind: String,
    pub etag: String,
    pub next_page_token: Option<String>,
    pub page_info: Option<PageInfo>,
    pub items: Vec<CommentThread>,
}

// ── Captions ────────────────────────────────────────────────────

/// Caption track resource.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptionTrack {
    pub kind: String,
    pub etag: String,
    pub id: String,
    pub snippet: Option<CaptionSnippet>,
}

/// Caption snippet data.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptionSnippet {
    pub video_id: Option<String>,
    pub last_updated: Option<String>,
    pub track_kind: Option<String>,
    pub language: Option<String>,
    pub name: Option<String>,
    pub audio_track_type: Option<String>,
    pub is_cc: Option<bool>,
    pub is_draft: Option<bool>,
    pub is_auto_synced: Option<bool>,
    pub status: Option<String>,
    /// Provider processing failure, when the track exists but is not usable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<String>,
}

/// Caption list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptionListResponse {
    pub kind: String,
    pub etag: String,
    pub items: Vec<CaptionTrack>,
}

// ── API Error ───────────────────────────────────────────────────

/// YouTube API error response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiErrorResponse {
    pub error: Option<ApiError>,
}

/// YouTube API error details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiError {
    pub code: Option<u16>,
    pub message: Option<String>,
    pub errors: Option<Vec<ApiErrorDetail>>,
}

/// Individual error detail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiErrorDetail {
    pub message: Option<String>,
    pub domain: Option<String>,
    pub reason: Option<String>,
}

// ── Analytics ─────────────────────────────────────────────────

/// Aggregated analytics for a channel's recent videos.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelAnalytics {
    pub channel_id: String,
    pub video_count: u32,
    pub total_views: u64,
    pub total_likes: u64,
    pub total_comments: u64,
    pub videos: Vec<VideoAnalyticsSummary>,
}

/// Per-video analytics summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VideoAnalyticsSummary {
    pub video_id: String,
    pub title: String,
    pub published_at: Option<String>,
    pub view_count: u64,
    pub like_count: u64,
    pub comment_count: u64,
    pub duration: Option<String>,
}

// ── Upload ────────────────────────────────────────────────────

/// Video upload metadata (sent as part of resumable upload init).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VideoUploadMetadata {
    pub snippet: VideoUploadSnippet,
    pub status: VideoUploadStatus,
}

/// Snippet for a video being uploaded.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VideoUploadSnippet {
    pub title: String,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_language: Option<String>,
}

/// Privacy and publish status for an uploaded video.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VideoUploadStatus {
    pub privacy_status: PrivacyStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub self_declared_made_for_kids: Option<bool>,
}

/// Video privacy status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PrivacyStatus {
    Private,
    Unlisted,
    Public,
}

/// Result of a video upload operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VideoUploadResult {
    pub video_id: String,
    pub title: String,
    pub privacy_status: String,
    pub upload_status: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ---- PageInfo (camelCase) ----

    #[test]
    fn page_info_camel_case_serde() {
        let json = json!({"totalResults": 100, "resultsPerPage": 25});
        let pi: PageInfo = serde_json::from_value(json).unwrap();
        assert_eq!(pi.total_results, 100);
        assert_eq!(pi.results_per_page, 25);

        let out = serde_json::to_value(&pi).unwrap();
        assert_eq!(out["totalResults"], 100);
    }

    // ---- SearchResult ----

    #[test]
    fn search_result_serde() {
        let json = json!({
            "kind": "youtube#searchResult",
            "etag": "abc",
            "id": {
                "kind": "youtube#video",
                "videoId": "dQw4w9WgXcQ"
            },
            "snippet": {
                "title": "Rick Astley",
                "description": "Never gonna give you up",
                "publishedAt": "2009-10-25T06:57:33Z",
                "channelId": "UCuAXFkgsw1L7xaCfnd5JJOw",
                "channelTitle": "Rick Astley",
                "thumbnails": {
                    "default": {"url": "https://i.ytimg.com/vi/dQw4w9WgXcQ/default.jpg", "width": 120, "height": 90}
                }
            }
        });
        let sr: SearchResult = serde_json::from_value(json).unwrap();
        assert_eq!(sr.kind, "youtube#searchResult");
        assert_eq!(sr.id.video_id, Some("dQw4w9WgXcQ".into()));
        assert!(sr.id.channel_id.is_none());
        let snippet = sr.snippet.unwrap();
        assert_eq!(snippet.title, "Rick Astley");
    }

    #[test]
    fn search_list_response_serde() {
        let json = json!({
            "kind": "youtube#searchListResponse",
            "etag": "xyz",
            "nextPageToken": "CAUQAA",
            "pageInfo": {"totalResults": 50, "resultsPerPage": 5},
            "items": []
        });
        let resp: SearchListResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.next_page_token, Some("CAUQAA".into()));
        assert!(resp.items.is_empty());
    }

    // ---- Video ----

    #[test]
    fn video_serde_roundtrip() {
        let json = json!({
            "kind": "youtube#video",
            "etag": "abc",
            "id": "dQw4w9WgXcQ",
            "snippet": {
                "title": "Never Gonna Give You Up",
                "description": "The official video",
                "tags": ["music", "rick astley"],
                "categoryId": "10"
            },
            "contentDetails": {
                "duration": "PT3M33S",
                "dimension": "2d",
                "definition": "hd",
                "caption": "true",
                "licensedContent": true
            },
            "statistics": {
                "viewCount": "1500000000",
                "likeCount": "15000000",
                "commentCount": "3000000"
            }
        });
        let video: Video = serde_json::from_value(json).unwrap();
        assert_eq!(video.id, "dQw4w9WgXcQ");
        let snippet = video.snippet.unwrap();
        assert_eq!(snippet.tags.as_ref().unwrap().len(), 2);
        let cd = video.content_details.unwrap();
        assert_eq!(cd.duration, Some("PT3M33S".into()));
        let stats = video.statistics.unwrap();
        assert_eq!(stats.view_count, Some("1500000000".into()));
    }

    #[test]
    fn video_minimal_fields() {
        let json = json!({
            "kind": "youtube#video",
            "etag": "min",
            "id": "abc123"
        });
        let video: Video = serde_json::from_value(json).unwrap();
        assert!(video.snippet.is_none());
        assert!(video.content_details.is_none());
        assert!(video.statistics.is_none());
    }

    // ---- Channel ----

    #[test]
    fn channel_serde() {
        let json = json!({
            "kind": "youtube#channel",
            "etag": "ch_etag",
            "id": "UCuAXFkgsw1L7xaCfnd5JJOw",
            "snippet": {
                "title": "Rick Astley",
                "description": "Official channel",
                "customUrl": "@rickastley",
                "country": "GB"
            },
            "statistics": {
                "viewCount": "2000000000",
                "subscriberCount": "14000000",
                "hiddenSubscriberCount": false,
                "videoCount": "120"
            },
            "contentDetails": {
                "relatedPlaylists": {
                    "likes": "LL",
                    "uploads": "UUuAXFkgsw1L7xaCfnd5JJOw"
                }
            }
        });
        let ch: Channel = serde_json::from_value(json).unwrap();
        assert_eq!(ch.id, "UCuAXFkgsw1L7xaCfnd5JJOw");
        let snippet = ch.snippet.unwrap();
        assert_eq!(snippet.custom_url, Some("@rickastley".into()));
        let stats = ch.statistics.unwrap();
        assert_eq!(stats.hidden_subscriber_count, Some(false));
        let cd = ch.content_details.unwrap();
        assert!(cd.related_playlists.is_some());
    }

    // ---- Playlist ----

    #[test]
    fn playlist_serde() {
        let json = json!({
            "kind": "youtube#playlist",
            "etag": "pl_etag",
            "id": "PLrAXtmErZgOeiKm4sgNOknGvNjby9efdf",
            "snippet": {
                "title": "My Playlist",
                "description": "Favorites",
                "publishedAt": "2020-01-01T00:00:00Z"
            },
            "contentDetails": {
                "itemCount": 42
            }
        });
        let pl: Playlist = serde_json::from_value(json).unwrap();
        assert_eq!(pl.content_details.unwrap().item_count, Some(42));
    }

    // ---- PlaylistItem ----

    #[test]
    fn playlist_item_serde() {
        let json = json!({
            "kind": "youtube#playlistItem",
            "etag": "pi_etag",
            "id": "UExYYWIxMjM",
            "snippet": {
                "title": "Song Title",
                "description": "A song",
                "position": 0,
                "resourceId": {
                    "kind": "youtube#video",
                    "videoId": "abc123"
                }
            },
            "contentDetails": {
                "videoId": "abc123",
                "videoPublishedAt": "2020-06-15T12:00:00Z"
            }
        });
        let pi: PlaylistItem = serde_json::from_value(json).unwrap();
        let snippet = pi.snippet.unwrap();
        assert_eq!(snippet.position, Some(0));
        let rid = snippet.resource_id.unwrap();
        assert_eq!(rid.video_id, Some("abc123".into()));
    }

    // ---- CommentThread ----

    #[test]
    fn comment_thread_serde() {
        let json = json!({
            "kind": "youtube#commentThread",
            "etag": "ct_etag",
            "id": "ct_001",
            "snippet": {
                "videoId": "dQw4w9WgXcQ",
                "topLevelComment": {
                    "id": "c_001",
                    "snippet": {
                        "authorDisplayName": "User1",
                        "textDisplay": "Great video!",
                        "likeCount": 42,
                        "publishedAt": "2026-01-01T00:00:00Z"
                    }
                },
                "canReply": true,
                "totalReplyCount": 5,
                "isPublic": true
            }
        });
        let ct: CommentThread = serde_json::from_value(json).unwrap();
        let snippet = ct.snippet.unwrap();
        assert_eq!(snippet.total_reply_count, Some(5));
        let comment = snippet.top_level_comment.unwrap();
        let cs = comment.snippet.unwrap();
        assert_eq!(cs.like_count, Some(42));
    }

    // ---- CaptionTrack ----

    #[test]
    fn caption_track_serde() {
        let json = json!({
            "kind": "youtube#caption",
            "etag": "cap_etag",
            "id": "cap_001",
            "snippet": {
                "videoId": "dQw4w9WgXcQ",
                "language": "en",
                "name": "English",
                "trackKind": "standard",
                "isCc": false,
                "isDraft": false,
                "isAutoSynced": true,
                "status": "serving"
            }
        });
        let ct: CaptionTrack = serde_json::from_value(json).unwrap();
        let snippet = ct.snippet.unwrap();
        assert_eq!(snippet.language, Some("en".into()));
        assert_eq!(snippet.is_cc, Some(false));
        assert_eq!(snippet.is_auto_synced, Some(true));
    }

    // ---- ApiErrorResponse ----

    #[test]
    fn api_error_response_serde() {
        let json = json!({
            "error": {
                "code": 403,
                "message": "The request cannot be completed because you have exceeded your quota.",
                "errors": [{
                    "message": "The request cannot be completed because you have exceeded your quota.",
                    "domain": "youtube.quota",
                    "reason": "quotaExceeded"
                }]
            }
        });
        let resp: ApiErrorResponse = serde_json::from_value(json).unwrap();
        let err = resp.error.unwrap();
        assert_eq!(err.code, Some(403));
        let details = err.errors.unwrap();
        assert_eq!(details[0].reason, Some("quotaExceeded".into()));
    }

    #[test]
    fn api_error_response_empty() {
        let json = json!({});
        let resp: ApiErrorResponse = serde_json::from_value(json).unwrap();
        assert!(resp.error.is_none());
    }

    // ---- ThumbnailSet ----

    #[test]
    fn thumbnail_set_partial() {
        let json = json!({
            "default": {"url": "https://example.com/thumb.jpg", "width": 120, "height": 90},
            "medium": null,
            "high": null
        });
        let ts: ThumbnailSet = serde_json::from_value(json).unwrap();
        assert!(ts.default.is_some());
        assert_eq!(ts.default.unwrap().width, Some(120));
        assert!(ts.medium.is_none());
    }

    // ════════════════════════════════════════════════════════════════
    //  Thumbnail
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn thumbnail_roundtrip_full() {
        let json =
            json!({"url": "https://i.ytimg.com/vi/abc/default.jpg", "width": 120, "height": 90});
        let t: Thumbnail = serde_json::from_value(json).unwrap();
        assert_eq!(t.url, "https://i.ytimg.com/vi/abc/default.jpg");
        assert_eq!(t.width, Some(120));
        assert_eq!(t.height, Some(90));
        let rt = serde_json::to_value(&t).unwrap();
        assert_eq!(rt["url"], "https://i.ytimg.com/vi/abc/default.jpg");
        assert_eq!(rt["width"], 120);
        assert_eq!(rt["height"], 90);
    }

    #[test]
    fn thumbnail_optional_dimensions() {
        let json = json!({"url": "https://example.com/t.jpg"});
        let t: Thumbnail = serde_json::from_value(json).unwrap();
        assert_eq!(t.url, "https://example.com/t.jpg");
        assert!(t.width.is_none());
        assert!(t.height.is_none());
    }

    #[test]
    fn thumbnail_clone_debug() {
        let t = Thumbnail {
            url: "https://x.com/t.jpg".into(),
            width: Some(320),
            height: Some(180),
        };
        let t2 = t.clone();
        assert_eq!(t2.url, t.url);
        assert_eq!(t2.width, t.width);
        let dbg = format!("{t:?}");
        assert!(dbg.contains("Thumbnail"));
        assert!(dbg.contains("320"));
    }

    // ════════════════════════════════════════════════════════════════
    //  ThumbnailSet (extended)
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn thumbnail_set_all_fields() {
        let json = json!({
            "default":  {"url": "https://d.jpg", "width": 120, "height": 90},
            "medium":   {"url": "https://m.jpg", "width": 320, "height": 180},
            "high":     {"url": "https://h.jpg", "width": 480, "height": 360},
            "standard": {"url": "https://s.jpg", "width": 640, "height": 480},
            "maxres":   {"url": "https://x.jpg", "width": 1280, "height": 720}
        });
        let ts: ThumbnailSet = serde_json::from_value(json).unwrap();
        assert!(ts.default.is_some());
        assert!(ts.medium.is_some());
        assert!(ts.high.is_some());
        assert!(ts.standard.is_some());
        assert!(ts.maxres.is_some());
        assert_eq!(ts.maxres.unwrap().width, Some(1280));
    }

    #[test]
    fn thumbnail_set_empty() {
        let json = json!({});
        let ts: ThumbnailSet = serde_json::from_value(json).unwrap();
        assert!(ts.default.is_none());
        assert!(ts.medium.is_none());
        assert!(ts.high.is_none());
        assert!(ts.standard.is_none());
        assert!(ts.maxres.is_none());
    }

    #[test]
    fn thumbnail_set_clone_debug() {
        let ts = ThumbnailSet {
            default: Some(Thumbnail {
                url: "u".into(),
                width: None,
                height: None,
            }),
            medium: None,
            high: None,
            standard: None,
            maxres: None,
        };
        let ts2 = ts.clone();
        assert_eq!(ts2.default.as_ref().unwrap().url, "u");
        let dbg = format!("{ts:?}");
        assert!(dbg.contains("ThumbnailSet"));
    }

    #[test]
    fn thumbnail_set_roundtrip_json() {
        let ts = ThumbnailSet {
            default: Some(Thumbnail {
                url: "a".into(),
                width: Some(120),
                height: Some(90),
            }),
            medium: None,
            high: None,
            standard: None,
            maxres: None,
        };
        let v = serde_json::to_value(&ts).unwrap();
        let ts2: ThumbnailSet = serde_json::from_value(v).unwrap();
        assert_eq!(ts2.default.as_ref().unwrap().url, "a");
        assert!(ts2.medium.is_none());
    }

    // ════════════════════════════════════════════════════════════════
    //  VideoSnippet
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn video_snippet_roundtrip_full() {
        let json = json!({
            "publishedAt": "2009-10-25T06:57:33Z",
            "channelId": "UCuAXFkgsw1L7xaCfnd5JJOw",
            "title": "Never Gonna Give You Up",
            "description": "The official video",
            "tags": ["music", "rick", "astley"],
            "categoryId": "10",
            "liveBroadcastContent": "none",
            "defaultLanguage": "en",
            "defaultAudioLanguage": "en"
        });
        let vs: VideoSnippet = serde_json::from_value(json).unwrap();
        assert_eq!(vs.title, "Never Gonna Give You Up");
        assert_eq!(vs.tags.as_ref().unwrap().len(), 3);
        assert_eq!(vs.category_id, Some("10".into()));
        assert_eq!(vs.live_broadcast_content, Some("none".into()));
        assert_eq!(vs.default_language, Some("en".into()));
        assert_eq!(vs.default_audio_language, Some("en".into()));

        // camelCase roundtrip
        let v = serde_json::to_value(&vs).unwrap();
        assert_eq!(v["publishedAt"], "2009-10-25T06:57:33Z");
        assert_eq!(v["channelId"], "UCuAXFkgsw1L7xaCfnd5JJOw");
        assert_eq!(v["categoryId"], "10");
        assert_eq!(v["liveBroadcastContent"], "none");
        assert_eq!(v["defaultLanguage"], "en");
        assert_eq!(v["defaultAudioLanguage"], "en");
    }

    #[test]
    fn video_snippet_minimal() {
        let json = json!({"title": "T", "description": "D"});
        let vs: VideoSnippet = serde_json::from_value(json).unwrap();
        assert_eq!(vs.title, "T");
        assert_eq!(vs.description, "D");
        assert!(vs.published_at.is_none());
        assert!(vs.channel_id.is_none());
        assert!(vs.thumbnails.is_none());
        assert!(vs.channel_title.is_none());
        assert!(vs.tags.is_none());
        assert!(vs.category_id.is_none());
        assert!(vs.live_broadcast_content.is_none());
        assert!(vs.default_language.is_none());
        assert!(vs.default_audio_language.is_none());
    }

    #[test]
    fn video_snippet_with_empty_tags() {
        let json = json!({"title": "T", "description": "D", "tags": []});
        let vs: VideoSnippet = serde_json::from_value(json).unwrap();
        assert!(vs.tags.as_ref().unwrap().is_empty());
    }

    #[test]
    fn video_snippet_clone_debug() {
        let vs = VideoSnippet {
            published_at: None,
            channel_id: None,
            title: "Title".into(),
            description: "Desc".into(),
            thumbnails: None,
            channel_title: None,
            tags: None,
            category_id: None,
            live_broadcast_content: None,
            default_language: None,
            default_audio_language: None,
        };
        let vs2 = vs.clone();
        assert_eq!(vs2.title, "Title");
        let dbg = format!("{vs:?}");
        assert!(dbg.contains("VideoSnippet"));
    }

    // ════════════════════════════════════════════════════════════════
    //  ContentDetails
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn content_details_all_fields() {
        let json = json!({
            "duration": "PT3M33S",
            "dimension": "2d",
            "definition": "hd",
            "caption": "true",
            "licensedContent": true,
            "projection": "rectangular"
        });
        let cd: ContentDetails = serde_json::from_value(json).unwrap();
        assert_eq!(cd.duration, Some("PT3M33S".into()));
        assert_eq!(cd.dimension, Some("2d".into()));
        assert_eq!(cd.definition, Some("hd".into()));
        assert_eq!(cd.caption, Some("true".into()));
        assert_eq!(cd.licensed_content, Some(true));
        assert_eq!(cd.projection, Some("rectangular".into()));

        // camelCase roundtrip
        let v = serde_json::to_value(&cd).unwrap();
        assert_eq!(v["licensedContent"], true);
        assert!(v.get("licensed_content").is_none());
    }

    #[test]
    fn content_details_minimal_all_none() {
        let json = json!({});
        let cd: ContentDetails = serde_json::from_value(json).unwrap();
        assert!(cd.duration.is_none());
        assert!(cd.dimension.is_none());
        assert!(cd.definition.is_none());
        assert!(cd.caption.is_none());
        assert!(cd.licensed_content.is_none());
        assert!(cd.projection.is_none());
    }

    #[test]
    fn content_details_clone_debug() {
        let cd = ContentDetails {
            duration: Some("PT1H".into()),
            dimension: None,
            definition: None,
            caption: None,
            licensed_content: None,
            projection: None,
        };
        let cd2 = cd.clone();
        assert_eq!(cd2.duration, Some("PT1H".into()));
        let dbg = format!("{cd:?}");
        assert!(dbg.contains("ContentDetails"));
    }

    // ════════════════════════════════════════════════════════════════
    //  VideoStatistics
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn video_statistics_all_fields() {
        let json = json!({
            "viewCount": "1500000",
            "likeCount": "50000",
            "dislikeCount": "1000",
            "favoriteCount": "0",
            "commentCount": "5000"
        });
        let vs: VideoStatistics = serde_json::from_value(json).unwrap();
        assert_eq!(vs.view_count, Some("1500000".into()));
        assert_eq!(vs.like_count, Some("50000".into()));
        assert_eq!(vs.dislike_count, Some("1000".into()));
        assert_eq!(vs.favorite_count, Some("0".into()));
        assert_eq!(vs.comment_count, Some("5000".into()));

        // camelCase roundtrip
        let v = serde_json::to_value(&vs).unwrap();
        assert_eq!(v["viewCount"], "1500000");
        assert_eq!(v["likeCount"], "50000");
        assert_eq!(v["dislikeCount"], "1000");
        assert_eq!(v["favoriteCount"], "0");
        assert_eq!(v["commentCount"], "5000");
    }

    #[test]
    fn video_statistics_minimal() {
        let json = json!({});
        let vs: VideoStatistics = serde_json::from_value(json).unwrap();
        assert!(vs.view_count.is_none());
        assert!(vs.like_count.is_none());
        assert!(vs.dislike_count.is_none());
        assert!(vs.favorite_count.is_none());
        assert!(vs.comment_count.is_none());
    }

    #[test]
    fn video_statistics_clone_debug() {
        let vs = VideoStatistics {
            view_count: Some("100".into()),
            like_count: None,
            dislike_count: None,
            favorite_count: None,
            comment_count: None,
        };
        let vs2 = vs.clone();
        assert_eq!(vs2.view_count, Some("100".into()));
        let dbg = format!("{vs:?}");
        assert!(dbg.contains("VideoStatistics"));
        assert!(dbg.contains("100"));
    }

    // ════════════════════════════════════════════════════════════════
    //  VideoListResponse
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn video_list_response_empty_items() {
        let json = json!({
            "kind": "youtube#videoListResponse",
            "etag": "etag1",
            "items": []
        });
        let resp: VideoListResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.kind, "youtube#videoListResponse");
        assert!(resp.items.is_empty());
        assert!(resp.page_info.is_none());
    }

    #[test]
    fn video_list_response_with_page_info() {
        let json = json!({
            "kind": "youtube#videoListResponse",
            "etag": "etag2",
            "pageInfo": {"totalResults": 3, "resultsPerPage": 5},
            "items": [
                {"kind": "youtube#video", "etag": "v1", "id": "id1"},
                {"kind": "youtube#video", "etag": "v2", "id": "id2"}
            ]
        });
        let resp: VideoListResponse = serde_json::from_value(json).unwrap();
        let pi = resp.page_info.unwrap();
        assert_eq!(pi.total_results, 3);
        assert_eq!(pi.results_per_page, 5);
        assert_eq!(resp.items.len(), 2);
    }

    #[test]
    fn video_list_response_camel_case_roundtrip() {
        let resp = VideoListResponse {
            kind: "youtube#videoListResponse".into(),
            etag: "e".into(),
            page_info: Some(PageInfo {
                total_results: 1,
                results_per_page: 10,
            }),
            items: vec![],
        };
        let v = serde_json::to_value(&resp).unwrap();
        assert_eq!(v["pageInfo"]["totalResults"], 1);
        assert_eq!(v["pageInfo"]["resultsPerPage"], 10);
        assert!(v.get("page_info").is_none());
    }

    // ════════════════════════════════════════════════════════════════
    //  ChannelSnippet
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn channel_snippet_all_fields() {
        let json = json!({
            "title": "TechChannel",
            "description": "A tech channel",
            "customUrl": "@techchannel",
            "publishedAt": "2015-03-01T00:00:00Z",
            "thumbnails": {
                "default": {"url": "https://d.jpg"}
            },
            "country": "US"
        });
        let cs: ChannelSnippet = serde_json::from_value(json).unwrap();
        assert_eq!(cs.title, "TechChannel");
        assert_eq!(cs.description, "A tech channel");
        assert_eq!(cs.custom_url, Some("@techchannel".into()));
        assert_eq!(cs.published_at, Some("2015-03-01T00:00:00Z".into()));
        assert!(cs.thumbnails.is_some());
        assert_eq!(cs.country, Some("US".into()));

        let v = serde_json::to_value(&cs).unwrap();
        assert_eq!(v["customUrl"], "@techchannel");
        assert_eq!(v["publishedAt"], "2015-03-01T00:00:00Z");
    }

    #[test]
    fn channel_snippet_minimal() {
        let json = json!({"title": "Ch", "description": ""});
        let cs: ChannelSnippet = serde_json::from_value(json).unwrap();
        assert_eq!(cs.title, "Ch");
        assert!(cs.custom_url.is_none());
        assert!(cs.published_at.is_none());
        assert!(cs.thumbnails.is_none());
        assert!(cs.country.is_none());
    }

    #[test]
    fn channel_snippet_clone_debug() {
        let cs = ChannelSnippet {
            title: "T".into(),
            description: "D".into(),
            custom_url: None,
            published_at: None,
            thumbnails: None,
            country: None,
        };
        let cs2 = cs.clone();
        assert_eq!(cs2.title, "T");
        let dbg = format!("{cs:?}");
        assert!(dbg.contains("ChannelSnippet"));
    }

    // ════════════════════════════════════════════════════════════════
    //  ChannelStatistics
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn channel_statistics_all_fields() {
        let json = json!({
            "viewCount": "5000000",
            "subscriberCount": "100000",
            "hiddenSubscriberCount": true,
            "videoCount": "250"
        });
        let cs: ChannelStatistics = serde_json::from_value(json).unwrap();
        assert_eq!(cs.view_count, Some("5000000".into()));
        assert_eq!(cs.subscriber_count, Some("100000".into()));
        assert_eq!(cs.hidden_subscriber_count, Some(true));
        assert_eq!(cs.video_count, Some("250".into()));

        let v = serde_json::to_value(&cs).unwrap();
        assert_eq!(v["viewCount"], "5000000");
        assert_eq!(v["subscriberCount"], "100000");
        assert_eq!(v["hiddenSubscriberCount"], true);
        assert_eq!(v["videoCount"], "250");
    }

    #[test]
    fn channel_statistics_minimal() {
        let json = json!({});
        let cs: ChannelStatistics = serde_json::from_value(json).unwrap();
        assert!(cs.view_count.is_none());
        assert!(cs.subscriber_count.is_none());
        assert!(cs.hidden_subscriber_count.is_none());
        assert!(cs.video_count.is_none());
    }

    #[test]
    fn channel_statistics_clone_debug() {
        let cs = ChannelStatistics {
            view_count: Some("1".into()),
            subscriber_count: None,
            hidden_subscriber_count: None,
            video_count: None,
        };
        let cs2 = cs.clone();
        assert_eq!(cs2.view_count, Some("1".into()));
        let dbg = format!("{cs:?}");
        assert!(dbg.contains("ChannelStatistics"));
    }

    // ════════════════════════════════════════════════════════════════
    //  ChannelContentDetails + RelatedPlaylists
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn channel_content_details_with_playlists() {
        let json = json!({
            "relatedPlaylists": {
                "likes": "LL",
                "uploads": "UUabc"
            }
        });
        let ccd: ChannelContentDetails = serde_json::from_value(json).unwrap();
        let rp = ccd.related_playlists.unwrap();
        assert_eq!(rp.likes, Some("LL".into()));
        assert_eq!(rp.uploads, Some("UUabc".into()));
    }

    #[test]
    fn channel_content_details_empty() {
        let json = json!({});
        let ccd: ChannelContentDetails = serde_json::from_value(json).unwrap();
        assert!(ccd.related_playlists.is_none());
    }

    #[test]
    fn channel_content_details_camel_case_roundtrip() {
        let ccd = ChannelContentDetails {
            related_playlists: Some(RelatedPlaylists {
                likes: Some("LL".into()),
                uploads: Some("UU123".into()),
            }),
        };
        let v = serde_json::to_value(&ccd).unwrap();
        assert_eq!(v["relatedPlaylists"]["likes"], "LL");
        assert_eq!(v["relatedPlaylists"]["uploads"], "UU123");
        assert!(v.get("related_playlists").is_none());
    }

    #[test]
    fn related_playlists_roundtrip() {
        let rp = RelatedPlaylists {
            likes: Some("LL".into()),
            uploads: Some("UU".into()),
        };
        let v = serde_json::to_value(&rp).unwrap();
        let rp2: RelatedPlaylists = serde_json::from_value(v).unwrap();
        assert_eq!(rp2.likes, Some("LL".into()));
        assert_eq!(rp2.uploads, Some("UU".into()));
    }

    #[test]
    fn related_playlists_all_none() {
        let json = json!({});
        let rp: RelatedPlaylists = serde_json::from_value(json).unwrap();
        assert!(rp.likes.is_none());
        assert!(rp.uploads.is_none());
    }

    #[test]
    fn related_playlists_clone_debug() {
        let rp = RelatedPlaylists {
            likes: Some("LL".into()),
            uploads: None,
        };
        let rp2 = rp.clone();
        assert_eq!(rp2.likes, Some("LL".into()));
        let dbg = format!("{rp:?}");
        assert!(dbg.contains("RelatedPlaylists"));
    }

    // ════════════════════════════════════════════════════════════════
    //  ChannelListResponse
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn channel_list_response_empty() {
        let json = json!({
            "kind": "youtube#channelListResponse",
            "etag": "e1",
            "items": []
        });
        let resp: ChannelListResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.kind, "youtube#channelListResponse");
        assert!(resp.items.is_empty());
        assert!(resp.page_info.is_none());
    }

    #[test]
    fn channel_list_response_with_items() {
        let json = json!({
            "kind": "youtube#channelListResponse",
            "etag": "e2",
            "pageInfo": {"totalResults": 1, "resultsPerPage": 5},
            "items": [{
                "kind": "youtube#channel",
                "etag": "ce",
                "id": "UCabc"
            }]
        });
        let resp: ChannelListResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.items.len(), 1);
        assert_eq!(resp.items[0].id, "UCabc");
        assert_eq!(resp.page_info.unwrap().total_results, 1);
    }

    #[test]
    fn channel_list_response_camel_case_roundtrip() {
        let resp = ChannelListResponse {
            kind: "youtube#channelListResponse".into(),
            etag: "e".into(),
            page_info: Some(PageInfo {
                total_results: 2,
                results_per_page: 10,
            }),
            items: vec![],
        };
        let v = serde_json::to_value(&resp).unwrap();
        assert_eq!(v["pageInfo"]["totalResults"], 2);
        assert!(v.get("page_info").is_none());
    }

    // ════════════════════════════════════════════════════════════════
    //  PlaylistSnippet
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn playlist_snippet_roundtrip() {
        let json = json!({
            "publishedAt": "2020-01-01T00:00:00Z",
            "channelId": "UCabc",
            "title": "My Playlist",
            "description": "All my favorites",
            "thumbnails": {"default": {"url": "https://t.jpg"}},
            "channelTitle": "My Channel"
        });
        let ps: PlaylistSnippet = serde_json::from_value(json).unwrap();
        assert_eq!(ps.title, "My Playlist");
        assert_eq!(ps.channel_id, Some("UCabc".into()));
        assert_eq!(ps.channel_title, Some("My Channel".into()));
        assert!(ps.thumbnails.is_some());

        let v = serde_json::to_value(&ps).unwrap();
        assert_eq!(v["publishedAt"], "2020-01-01T00:00:00Z");
        assert_eq!(v["channelId"], "UCabc");
        assert_eq!(v["channelTitle"], "My Channel");
    }

    #[test]
    fn playlist_snippet_minimal() {
        let json = json!({"title": "P", "description": ""});
        let ps: PlaylistSnippet = serde_json::from_value(json).unwrap();
        assert_eq!(ps.title, "P");
        assert!(ps.published_at.is_none());
        assert!(ps.channel_id.is_none());
        assert!(ps.thumbnails.is_none());
        assert!(ps.channel_title.is_none());
    }

    #[test]
    fn playlist_snippet_clone_debug() {
        let ps = PlaylistSnippet {
            published_at: None,
            channel_id: None,
            title: "PL".into(),
            description: String::new(),
            thumbnails: None,
            channel_title: None,
        };
        let ps2 = ps.clone();
        assert_eq!(ps2.title, "PL");
        let dbg = format!("{ps:?}");
        assert!(dbg.contains("PlaylistSnippet"));
    }

    // ════════════════════════════════════════════════════════════════
    //  PlaylistContentDetails
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn playlist_content_details_with_count() {
        let json = json!({"itemCount": 42});
        let pcd: PlaylistContentDetails = serde_json::from_value(json).unwrap();
        assert_eq!(pcd.item_count, Some(42));

        let v = serde_json::to_value(&pcd).unwrap();
        assert_eq!(v["itemCount"], 42);
        assert!(v.get("item_count").is_none());
    }

    #[test]
    fn playlist_content_details_absent() {
        let json = json!({});
        let pcd: PlaylistContentDetails = serde_json::from_value(json).unwrap();
        assert!(pcd.item_count.is_none());
    }

    #[test]
    fn playlist_content_details_zero() {
        let json = json!({"itemCount": 0});
        let pcd: PlaylistContentDetails = serde_json::from_value(json).unwrap();
        assert_eq!(pcd.item_count, Some(0));
    }

    // ════════════════════════════════════════════════════════════════
    //  PlaylistListResponse
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn playlist_list_response_with_pagination_tokens() {
        let json = json!({
            "kind": "youtube#playlistListResponse",
            "etag": "ple",
            "nextPageToken": "NEXT",
            "prevPageToken": "PREV",
            "pageInfo": {"totalResults": 20, "resultsPerPage": 5},
            "items": []
        });
        let resp: PlaylistListResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.next_page_token, Some("NEXT".into()));
        assert_eq!(resp.prev_page_token, Some("PREV".into()));
        assert_eq!(resp.page_info.unwrap().total_results, 20);
    }

    #[test]
    fn playlist_list_response_no_tokens() {
        let json = json!({
            "kind": "youtube#playlistListResponse",
            "etag": "ple2",
            "items": []
        });
        let resp: PlaylistListResponse = serde_json::from_value(json).unwrap();
        assert!(resp.next_page_token.is_none());
        assert!(resp.prev_page_token.is_none());
        assert!(resp.page_info.is_none());
    }

    #[test]
    fn playlist_list_response_camel_case_roundtrip() {
        let resp = PlaylistListResponse {
            kind: "youtube#playlistListResponse".into(),
            etag: "e".into(),
            next_page_token: Some("NXT".into()),
            prev_page_token: None,
            page_info: Some(PageInfo {
                total_results: 5,
                results_per_page: 5,
            }),
            items: vec![],
        };
        let v = serde_json::to_value(&resp).unwrap();
        assert_eq!(v["nextPageToken"], "NXT");
        assert!(v.get("next_page_token").is_none());
        assert!(v.get("prev_page_token").is_none());
    }

    // ════════════════════════════════════════════════════════════════
    //  PlaylistItemSnippet
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn playlist_item_snippet_full() {
        let json = json!({
            "publishedAt": "2020-06-15T12:00:00Z",
            "channelId": "UCabc",
            "title": "Track One",
            "description": "First track",
            "thumbnails": {"default": {"url": "https://t.jpg"}},
            "channelTitle": "My Channel",
            "playlistId": "PLabc",
            "position": 3,
            "resourceId": {
                "kind": "youtube#video",
                "videoId": "vid123"
            }
        });
        let pis: PlaylistItemSnippet = serde_json::from_value(json).unwrap();
        assert_eq!(pis.title, "Track One");
        assert_eq!(pis.playlist_id, Some("PLabc".into()));
        assert_eq!(pis.position, Some(3));
        let rid = pis.resource_id.as_ref().unwrap();
        assert_eq!(rid.kind, "youtube#video");
        assert_eq!(rid.video_id, Some("vid123".into()));

        let v = serde_json::to_value(&pis).unwrap();
        assert_eq!(v["playlistId"], "PLabc");
        assert_eq!(v["resourceId"]["videoId"], "vid123");
    }

    #[test]
    fn playlist_item_snippet_minimal() {
        let json = json!({"title": "T", "description": ""});
        let pis: PlaylistItemSnippet = serde_json::from_value(json).unwrap();
        assert_eq!(pis.title, "T");
        assert!(pis.published_at.is_none());
        assert!(pis.playlist_id.is_none());
        assert!(pis.position.is_none());
        assert!(pis.resource_id.is_none());
    }

    // ════════════════════════════════════════════════════════════════
    //  ResourceId
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn resource_id_roundtrip_with_video() {
        let json = json!({"kind": "youtube#video", "videoId": "abc123"});
        let rid: ResourceId = serde_json::from_value(json).unwrap();
        assert_eq!(rid.kind, "youtube#video");
        assert_eq!(rid.video_id, Some("abc123".into()));

        let v = serde_json::to_value(&rid).unwrap();
        assert_eq!(v["videoId"], "abc123");
        assert!(v.get("video_id").is_none());
    }

    #[test]
    fn resource_id_without_video_id() {
        let json = json!({"kind": "youtube#playlist"});
        let rid: ResourceId = serde_json::from_value(json).unwrap();
        assert_eq!(rid.kind, "youtube#playlist");
        assert!(rid.video_id.is_none());
    }

    #[test]
    fn resource_id_clone_debug() {
        let rid = ResourceId {
            kind: "youtube#video".into(),
            video_id: Some("v".into()),
        };
        let rid2 = rid.clone();
        assert_eq!(rid2.kind, "youtube#video");
        let dbg = format!("{rid:?}");
        assert!(dbg.contains("ResourceId"));
    }

    // ════════════════════════════════════════════════════════════════
    //  PlaylistItemContentDetails
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn playlist_item_content_details_roundtrip() {
        let json = json!({
            "videoId": "vid_abc",
            "videoPublishedAt": "2021-01-15T10:30:00Z"
        });
        let picd: PlaylistItemContentDetails = serde_json::from_value(json).unwrap();
        assert_eq!(picd.video_id, Some("vid_abc".into()));
        assert_eq!(picd.video_published_at, Some("2021-01-15T10:30:00Z".into()));

        let v = serde_json::to_value(&picd).unwrap();
        assert_eq!(v["videoId"], "vid_abc");
        assert_eq!(v["videoPublishedAt"], "2021-01-15T10:30:00Z");
        assert!(v.get("video_id").is_none());
        assert!(v.get("video_published_at").is_none());
    }

    #[test]
    fn playlist_item_content_details_empty() {
        let json = json!({});
        let picd: PlaylistItemContentDetails = serde_json::from_value(json).unwrap();
        assert!(picd.video_id.is_none());
        assert!(picd.video_published_at.is_none());
    }

    // ════════════════════════════════════════════════════════════════
    //  PlaylistItemListResponse
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn playlist_item_list_response_pagination() {
        let json = json!({
            "kind": "youtube#playlistItemListResponse",
            "etag": "pile",
            "nextPageToken": "TOKEN_NEXT",
            "prevPageToken": "TOKEN_PREV",
            "pageInfo": {"totalResults": 100, "resultsPerPage": 50},
            "items": [{
                "kind": "youtube#playlistItem",
                "etag": "pi1",
                "id": "PIabc"
            }]
        });
        let resp: PlaylistItemListResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.next_page_token, Some("TOKEN_NEXT".into()));
        assert_eq!(resp.prev_page_token, Some("TOKEN_PREV".into()));
        assert_eq!(resp.items.len(), 1);
        assert_eq!(resp.items[0].id, "PIabc");
    }

    #[test]
    fn playlist_item_list_response_empty() {
        let json = json!({
            "kind": "youtube#playlistItemListResponse",
            "etag": "pile2",
            "items": []
        });
        let resp: PlaylistItemListResponse = serde_json::from_value(json).unwrap();
        assert!(resp.items.is_empty());
        assert!(resp.next_page_token.is_none());
        assert!(resp.prev_page_token.is_none());
        assert!(resp.page_info.is_none());
    }

    #[test]
    fn playlist_item_list_response_camel_case_roundtrip() {
        let resp = PlaylistItemListResponse {
            kind: "youtube#playlistItemListResponse".into(),
            etag: "e".into(),
            next_page_token: Some("N".into()),
            prev_page_token: Some("P".into()),
            page_info: Some(PageInfo {
                total_results: 10,
                results_per_page: 5,
            }),
            items: vec![],
        };
        let v = serde_json::to_value(&resp).unwrap();
        assert_eq!(v["nextPageToken"], "N");
        assert_eq!(v["prevPageToken"], "P");
        assert!(v.get("next_page_token").is_none());
        assert!(v.get("prev_page_token").is_none());
    }

    // ════════════════════════════════════════════════════════════════
    //  CommentThreadSnippet
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn comment_thread_snippet_all_fields() {
        let json = json!({
            "channelId": "UCch1",
            "videoId": "vid1",
            "topLevelComment": {
                "id": "c001",
                "snippet": {
                    "textDisplay": "Hello!",
                    "likeCount": 10
                }
            },
            "canReply": true,
            "totalReplyCount": 3,
            "isPublic": true
        });
        let cts: CommentThreadSnippet = serde_json::from_value(json).unwrap();
        assert_eq!(cts.channel_id, Some("UCch1".into()));
        assert_eq!(cts.video_id, Some("vid1".into()));
        assert_eq!(cts.can_reply, Some(true));
        assert_eq!(cts.total_reply_count, Some(3));
        assert_eq!(cts.is_public, Some(true));
        assert!(cts.top_level_comment.is_some());

        let v = serde_json::to_value(&cts).unwrap();
        assert_eq!(v["channelId"], "UCch1");
        assert_eq!(v["videoId"], "vid1");
        assert_eq!(v["canReply"], true);
        assert_eq!(v["totalReplyCount"], 3);
        assert_eq!(v["isPublic"], true);
        assert_eq!(v["topLevelComment"]["id"], "c001");
    }

    #[test]
    fn comment_thread_snippet_minimal() {
        let json = json!({});
        let cts: CommentThreadSnippet = serde_json::from_value(json).unwrap();
        assert!(cts.channel_id.is_none());
        assert!(cts.video_id.is_none());
        assert!(cts.top_level_comment.is_none());
        assert!(cts.can_reply.is_none());
        assert!(cts.total_reply_count.is_none());
        assert!(cts.is_public.is_none());
    }

    // ════════════════════════════════════════════════════════════════
    //  Comment
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn comment_with_snippet() {
        let json = json!({
            "kind": "youtube#comment",
            "etag": "ce",
            "id": "c100",
            "snippet": {
                "authorDisplayName": "Alice",
                "authorProfileImageUrl": "https://img.jpg",
                "authorChannelUrl": "https://youtube.com/channel/UCabc",
                "textDisplay": "Great video!",
                "textOriginal": "Great video!",
                "videoId": "vid1",
                "viewerRating": "none",
                "likeCount": 5,
                "publishedAt": "2026-01-01T00:00:00Z",
                "updatedAt": "2026-01-01T00:00:00Z"
            }
        });
        let c: Comment = serde_json::from_value(json).unwrap();
        assert_eq!(c.kind, Some("youtube#comment".into()));
        assert_eq!(c.etag, Some("ce".into()));
        assert_eq!(c.id, "c100");
        let cs = c.snippet.unwrap();
        assert_eq!(cs.author_display_name, Some("Alice".into()));
        assert_eq!(cs.text_display, Some("Great video!".into()));
        assert_eq!(cs.like_count, Some(5));
    }

    #[test]
    fn comment_minimal() {
        let json = json!({"id": "c200"});
        let c: Comment = serde_json::from_value(json).unwrap();
        assert_eq!(c.id, "c200");
        assert!(c.kind.is_none());
        assert!(c.etag.is_none());
        assert!(c.snippet.is_none());
    }

    #[test]
    fn comment_clone_debug() {
        let c = Comment {
            kind: Some("youtube#comment".into()),
            etag: None,
            id: "c1".into(),
            snippet: None,
        };
        let c2 = c.clone();
        assert_eq!(c2.id, "c1");
        let dbg = format!("{c:?}");
        assert!(dbg.contains("Comment"));
    }

    // ════════════════════════════════════════════════════════════════
    //  CommentSnippet
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn comment_snippet_all_fields() {
        let json = json!({
            "authorDisplayName": "Bob",
            "authorProfileImageUrl": "https://profile.jpg",
            "authorChannelUrl": "https://youtube.com/channel/UCxyz",
            "textDisplay": "<b>Wow!</b>",
            "textOriginal": "Wow!",
            "parentId": "c100",
            "videoId": "vid1",
            "viewerRating": "like",
            "likeCount": 15,
            "publishedAt": "2026-02-01T00:00:00Z",
            "updatedAt": "2026-02-02T00:00:00Z"
        });
        let cs: CommentSnippet = serde_json::from_value(json).unwrap();
        assert_eq!(cs.author_display_name, Some("Bob".into()));
        assert_eq!(
            cs.author_profile_image_url,
            Some("https://profile.jpg".into())
        );
        assert_eq!(
            cs.author_channel_url,
            Some("https://youtube.com/channel/UCxyz".into())
        );
        assert_eq!(cs.text_display, Some("<b>Wow!</b>".into()));
        assert_eq!(cs.text_original, Some("Wow!".into()));
        assert_eq!(cs.parent_id, Some("c100".into()));
        assert_eq!(cs.video_id, Some("vid1".into()));
        assert_eq!(cs.viewer_rating, Some("like".into()));
        assert_eq!(cs.like_count, Some(15));
        assert_eq!(cs.published_at, Some("2026-02-01T00:00:00Z".into()));
        assert_eq!(cs.updated_at, Some("2026-02-02T00:00:00Z".into()));

        let v = serde_json::to_value(&cs).unwrap();
        assert_eq!(v["authorDisplayName"], "Bob");
        assert_eq!(v["authorProfileImageUrl"], "https://profile.jpg");
        assert_eq!(v["authorChannelUrl"], "https://youtube.com/channel/UCxyz");
        assert_eq!(v["textDisplay"], "<b>Wow!</b>");
        assert_eq!(v["textOriginal"], "Wow!");
        assert_eq!(v["parentId"], "c100");
        assert_eq!(v["viewerRating"], "like");
        assert_eq!(v["likeCount"], 15);
        assert_eq!(v["publishedAt"], "2026-02-01T00:00:00Z");
        assert_eq!(v["updatedAt"], "2026-02-02T00:00:00Z");
    }

    #[test]
    fn comment_snippet_reply_with_parent_id() {
        let json = json!({
            "parentId": "c100",
            "textDisplay": "I agree!",
            "authorDisplayName": "ReplyUser"
        });
        let cs: CommentSnippet = serde_json::from_value(json).unwrap();
        assert_eq!(cs.parent_id, Some("c100".into()));
        assert_eq!(cs.text_display, Some("I agree!".into()));
    }

    #[test]
    fn comment_snippet_minimal() {
        let json = json!({});
        let cs: CommentSnippet = serde_json::from_value(json).unwrap();
        assert!(cs.author_display_name.is_none());
        assert!(cs.text_display.is_none());
        assert!(cs.parent_id.is_none());
        assert!(cs.like_count.is_none());
        assert!(cs.published_at.is_none());
        assert!(cs.updated_at.is_none());
    }

    // ════════════════════════════════════════════════════════════════
    //  CommentThreadListResponse
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn comment_thread_list_response_with_pagination() {
        let json = json!({
            "kind": "youtube#commentThreadListResponse",
            "etag": "ctle",
            "nextPageToken": "CTNEXT",
            "pageInfo": {"totalResults": 200, "resultsPerPage": 20},
            "items": [{
                "kind": "youtube#commentThread",
                "etag": "ct1",
                "id": "thread1"
            }]
        });
        let resp: CommentThreadListResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.next_page_token, Some("CTNEXT".into()));
        assert_eq!(resp.items.len(), 1);
        assert_eq!(resp.page_info.unwrap().total_results, 200);
    }

    #[test]
    fn comment_thread_list_response_empty() {
        let json = json!({
            "kind": "youtube#commentThreadListResponse",
            "etag": "ctle2",
            "items": []
        });
        let resp: CommentThreadListResponse = serde_json::from_value(json).unwrap();
        assert!(resp.items.is_empty());
        assert!(resp.next_page_token.is_none());
        assert!(resp.page_info.is_none());
    }

    #[test]
    fn comment_thread_list_response_camel_case_roundtrip() {
        let resp = CommentThreadListResponse {
            kind: "youtube#commentThreadListResponse".into(),
            etag: "e".into(),
            next_page_token: Some("NK".into()),
            page_info: Some(PageInfo {
                total_results: 50,
                results_per_page: 20,
            }),
            items: vec![],
        };
        let v = serde_json::to_value(&resp).unwrap();
        assert_eq!(v["nextPageToken"], "NK");
        assert!(v.get("next_page_token").is_none());
    }

    // ════════════════════════════════════════════════════════════════
    //  CaptionSnippet
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn caption_snippet_all_fields() {
        let json = json!({
            "videoId": "vid1",
            "lastUpdated": "2026-01-15T00:00:00Z",
            "trackKind": "standard",
            "language": "en",
            "name": "English",
            "audioTrackType": "primary",
            "isCc": true,
            "isDraft": false,
            "isAutoSynced": false,
            "status": "serving"
        });
        let cs: CaptionSnippet = serde_json::from_value(json).unwrap();
        assert_eq!(cs.video_id, Some("vid1".into()));
        assert_eq!(cs.last_updated, Some("2026-01-15T00:00:00Z".into()));
        assert_eq!(cs.track_kind, Some("standard".into()));
        assert_eq!(cs.language, Some("en".into()));
        assert_eq!(cs.name, Some("English".into()));
        assert_eq!(cs.audio_track_type, Some("primary".into()));
        assert_eq!(cs.is_cc, Some(true));
        assert_eq!(cs.is_draft, Some(false));
        assert_eq!(cs.is_auto_synced, Some(false));
        assert_eq!(cs.status, Some("serving".into()));

        let v = serde_json::to_value(&cs).unwrap();
        assert_eq!(v["videoId"], "vid1");
        assert_eq!(v["lastUpdated"], "2026-01-15T00:00:00Z");
        assert_eq!(v["trackKind"], "standard");
        assert_eq!(v["audioTrackType"], "primary");
        assert_eq!(v["isCc"], true);
        assert_eq!(v["isDraft"], false);
        assert_eq!(v["isAutoSynced"], false);
    }

    #[test]
    fn caption_snippet_minimal() {
        let json = json!({});
        let cs: CaptionSnippet = serde_json::from_value(json).unwrap();
        assert!(cs.video_id.is_none());
        assert!(cs.last_updated.is_none());
        assert!(cs.track_kind.is_none());
        assert!(cs.language.is_none());
        assert!(cs.name.is_none());
        assert!(cs.audio_track_type.is_none());
        assert!(cs.is_cc.is_none());
        assert!(cs.is_draft.is_none());
        assert!(cs.is_auto_synced.is_none());
        assert!(cs.status.is_none());
    }

    #[test]
    fn caption_snippet_booleans_all_true() {
        let json = json!({"isCc": true, "isDraft": true, "isAutoSynced": true});
        let cs: CaptionSnippet = serde_json::from_value(json).unwrap();
        assert_eq!(cs.is_cc, Some(true));
        assert_eq!(cs.is_draft, Some(true));
        assert_eq!(cs.is_auto_synced, Some(true));
    }

    // ════════════════════════════════════════════════════════════════
    //  CaptionListResponse
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn caption_list_response_empty() {
        let json = json!({
            "kind": "youtube#captionListResponse",
            "etag": "cle1",
            "items": []
        });
        let resp: CaptionListResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.kind, "youtube#captionListResponse");
        assert!(resp.items.is_empty());
    }

    #[test]
    fn caption_list_response_with_items() {
        let json = json!({
            "kind": "youtube#captionListResponse",
            "etag": "cle2",
            "items": [
                {"kind": "youtube#caption", "etag": "c1e", "id": "cap1"},
                {"kind": "youtube#caption", "etag": "c2e", "id": "cap2"}
            ]
        });
        let resp: CaptionListResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.items.len(), 2);
        assert_eq!(resp.items[0].id, "cap1");
        assert_eq!(resp.items[1].id, "cap2");
    }

    #[test]
    fn caption_list_response_clone_debug() {
        let resp = CaptionListResponse {
            kind: "youtube#captionListResponse".into(),
            etag: "e".into(),
            items: vec![],
        };
        let resp2 = resp.clone();
        assert_eq!(resp2.kind, resp.kind);
        let dbg = format!("{resp:?}");
        assert!(dbg.contains("CaptionListResponse"));
    }

    // ════════════════════════════════════════════════════════════════
    //  ApiError
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn api_error_with_errors_list() {
        let json = json!({
            "code": 404,
            "message": "Not found",
            "errors": [
                {"message": "not found", "domain": "youtube.resource", "reason": "notFound"},
                {"message": "invalid", "domain": "youtube.param", "reason": "invalidParam"}
            ]
        });
        let ae: ApiError = serde_json::from_value(json).unwrap();
        assert_eq!(ae.code, Some(404));
        assert_eq!(ae.message, Some("Not found".into()));
        let errors = ae.errors.unwrap();
        assert_eq!(errors.len(), 2);
        assert_eq!(errors[0].reason, Some("notFound".into()));
        assert_eq!(errors[1].domain, Some("youtube.param".into()));
    }

    #[test]
    fn api_error_without_errors_list() {
        let json = json!({"code": 500, "message": "Internal error"});
        let ae: ApiError = serde_json::from_value(json).unwrap();
        assert_eq!(ae.code, Some(500));
        assert_eq!(ae.message, Some("Internal error".into()));
        assert!(ae.errors.is_none());
    }

    #[test]
    fn api_error_empty() {
        let json = json!({});
        let ae: ApiError = serde_json::from_value(json).unwrap();
        assert!(ae.code.is_none());
        assert!(ae.message.is_none());
        assert!(ae.errors.is_none());
    }

    #[test]
    fn api_error_clone_debug() {
        let ae = ApiError {
            code: Some(403),
            message: Some("Forbidden".into()),
            errors: None,
        };
        let ae2 = ae.clone();
        assert_eq!(ae2.code, Some(403));
        let dbg = format!("{ae:?}");
        assert!(dbg.contains("ApiError"));
        assert!(dbg.contains("403"));
    }

    // ════════════════════════════════════════════════════════════════
    //  ApiErrorDetail
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn api_error_detail_all_fields() {
        let json = json!({
            "message": "quota exceeded",
            "domain": "youtube.quota",
            "reason": "quotaExceeded"
        });
        let d: ApiErrorDetail = serde_json::from_value(json).unwrap();
        assert_eq!(d.message, Some("quota exceeded".into()));
        assert_eq!(d.domain, Some("youtube.quota".into()));
        assert_eq!(d.reason, Some("quotaExceeded".into()));

        let v = serde_json::to_value(&d).unwrap();
        assert_eq!(v["message"], "quota exceeded");
        assert_eq!(v["domain"], "youtube.quota");
        assert_eq!(v["reason"], "quotaExceeded");
    }

    #[test]
    fn api_error_detail_minimal() {
        let json = json!({});
        let d: ApiErrorDetail = serde_json::from_value(json).unwrap();
        assert!(d.message.is_none());
        assert!(d.domain.is_none());
        assert!(d.reason.is_none());
    }

    #[test]
    fn api_error_detail_clone_debug() {
        let d = ApiErrorDetail {
            message: Some("m".into()),
            domain: Some("d".into()),
            reason: Some("r".into()),
        };
        let d2 = d.clone();
        assert_eq!(d2.reason, Some("r".into()));
        let dbg = format!("{d:?}");
        assert!(dbg.contains("ApiErrorDetail"));
    }

    // ════════════════════════════════════════════════════════════════
    //  SearchResultId
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn search_result_id_video_variant() {
        let json = json!({"kind": "youtube#video", "videoId": "dQw4w9WgXcQ"});
        let sri: SearchResultId = serde_json::from_value(json).unwrap();
        assert_eq!(sri.kind, "youtube#video");
        assert_eq!(sri.video_id, Some("dQw4w9WgXcQ".into()));
        assert!(sri.channel_id.is_none());
        assert!(sri.playlist_id.is_none());

        let v = serde_json::to_value(&sri).unwrap();
        assert_eq!(v["videoId"], "dQw4w9WgXcQ");
        assert!(v.get("video_id").is_none());
    }

    #[test]
    fn search_result_id_channel_variant() {
        let json = json!({"kind": "youtube#channel", "channelId": "UCabc"});
        let sri: SearchResultId = serde_json::from_value(json).unwrap();
        assert_eq!(sri.kind, "youtube#channel");
        assert_eq!(sri.channel_id, Some("UCabc".into()));
        assert!(sri.video_id.is_none());
        assert!(sri.playlist_id.is_none());

        let v = serde_json::to_value(&sri).unwrap();
        assert_eq!(v["channelId"], "UCabc");
    }

    #[test]
    fn search_result_id_playlist_variant() {
        let json = json!({"kind": "youtube#playlist", "playlistId": "PLxyz"});
        let sri: SearchResultId = serde_json::from_value(json).unwrap();
        assert_eq!(sri.kind, "youtube#playlist");
        assert_eq!(sri.playlist_id, Some("PLxyz".into()));
        assert!(sri.video_id.is_none());
        assert!(sri.channel_id.is_none());

        let v = serde_json::to_value(&sri).unwrap();
        assert_eq!(v["playlistId"], "PLxyz");
    }

    #[test]
    fn search_result_id_clone_debug() {
        let sri = SearchResultId {
            kind: "youtube#video".into(),
            video_id: Some("v1".into()),
            channel_id: None,
            playlist_id: None,
        };
        let sri2 = sri.clone();
        assert_eq!(sri2.video_id, Some("v1".into()));
        let dbg = format!("{sri:?}");
        assert!(dbg.contains("SearchResultId"));
    }

    // ════════════════════════════════════════════════════════════════
    //  SearchSnippet
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn search_snippet_full() {
        let json = json!({
            "publishedAt": "2020-01-01T00:00:00Z",
            "channelId": "UCabc",
            "title": "Search Result Title",
            "description": "A search result",
            "thumbnails": {"default": {"url": "https://t.jpg"}},
            "channelTitle": "My Channel",
            "liveBroadcastContent": "live"
        });
        let ss: SearchSnippet = serde_json::from_value(json).unwrap();
        assert_eq!(ss.title, "Search Result Title");
        assert_eq!(ss.description, "A search result");
        assert_eq!(ss.published_at, Some("2020-01-01T00:00:00Z".into()));
        assert_eq!(ss.channel_id, Some("UCabc".into()));
        assert_eq!(ss.channel_title, Some("My Channel".into()));
        assert_eq!(ss.live_broadcast_content, Some("live".into()));
        assert!(ss.thumbnails.is_some());

        let v = serde_json::to_value(&ss).unwrap();
        assert_eq!(v["publishedAt"], "2020-01-01T00:00:00Z");
        assert_eq!(v["channelId"], "UCabc");
        assert_eq!(v["channelTitle"], "My Channel");
        assert_eq!(v["liveBroadcastContent"], "live");
    }

    #[test]
    fn search_snippet_minimal() {
        let json = json!({"title": "T", "description": "D"});
        let ss: SearchSnippet = serde_json::from_value(json).unwrap();
        assert_eq!(ss.title, "T");
        assert_eq!(ss.description, "D");
        assert!(ss.published_at.is_none());
        assert!(ss.channel_id.is_none());
        assert!(ss.thumbnails.is_none());
        assert!(ss.channel_title.is_none());
        assert!(ss.live_broadcast_content.is_none());
    }

    #[test]
    fn search_snippet_live_broadcast_none_value() {
        let json = json!({
            "title": "T", "description": "D",
            "liveBroadcastContent": "none"
        });
        let ss: SearchSnippet = serde_json::from_value(json).unwrap();
        assert_eq!(ss.live_broadcast_content, Some("none".into()));
    }

    #[test]
    fn search_snippet_clone_debug() {
        let ss = SearchSnippet {
            published_at: None,
            channel_id: None,
            title: "Title".into(),
            description: "Desc".into(),
            thumbnails: None,
            channel_title: None,
            live_broadcast_content: None,
        };
        let ss2 = ss.clone();
        assert_eq!(ss2.title, "Title");
        let dbg = format!("{ss:?}");
        assert!(dbg.contains("SearchSnippet"));
    }

    // ════════════════════════════════════════════════════════════════
    //  Existing types — additional camelCase & clone/debug tests
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn page_info_clone_debug() {
        let pi = PageInfo {
            total_results: 10,
            results_per_page: 5,
        };
        let pi2 = pi.clone();
        assert_eq!(pi2.total_results, 10);
        let dbg = format!("{pi:?}");
        assert!(dbg.contains("PageInfo"));
    }

    #[test]
    fn search_result_clone_debug() {
        let sr = SearchResult {
            kind: "youtube#searchResult".into(),
            etag: "e".into(),
            id: SearchResultId {
                kind: "youtube#video".into(),
                video_id: Some("v1".into()),
                channel_id: None,
                playlist_id: None,
            },
            snippet: None,
        };
        let sr2 = sr.clone();
        assert_eq!(sr2.kind, "youtube#searchResult");
        let dbg = format!("{sr:?}");
        assert!(dbg.contains("SearchResult"));
    }

    #[test]
    fn search_list_response_camel_case_roundtrip() {
        let resp = SearchListResponse {
            kind: "youtube#searchListResponse".into(),
            etag: "e".into(),
            next_page_token: Some("NT".into()),
            prev_page_token: Some("PT".into()),
            page_info: Some(PageInfo {
                total_results: 100,
                results_per_page: 10,
            }),
            items: vec![],
        };
        let v = serde_json::to_value(&resp).unwrap();
        assert_eq!(v["nextPageToken"], "NT");
        assert_eq!(v["prevPageToken"], "PT");
        assert_eq!(v["pageInfo"]["totalResults"], 100);
        assert!(v.get("next_page_token").is_none());
        assert!(v.get("prev_page_token").is_none());
    }

    #[test]
    fn video_clone_debug() {
        let v = Video {
            kind: "youtube#video".into(),
            etag: "e".into(),
            id: "vid1".into(),
            snippet: None,
            content_details: None,
            statistics: None,
        };
        let v2 = v.clone();
        assert_eq!(v2.id, "vid1");
        let dbg = format!("{v:?}");
        assert!(dbg.contains("Video"));
    }

    #[test]
    fn video_camel_case_roundtrip() {
        let v = Video {
            kind: "youtube#video".into(),
            etag: "e".into(),
            id: "vid1".into(),
            snippet: None,
            content_details: Some(ContentDetails {
                duration: Some("PT5M".into()),
                dimension: None,
                definition: None,
                caption: None,
                licensed_content: Some(false),
                projection: None,
            }),
            statistics: Some(VideoStatistics {
                view_count: Some("100".into()),
                like_count: None,
                dislike_count: None,
                favorite_count: None,
                comment_count: None,
            }),
        };
        let out = serde_json::to_value(&v).unwrap();
        assert_eq!(out["contentDetails"]["licensedContent"], false);
        assert_eq!(out["statistics"]["viewCount"], "100");
        assert!(out.get("content_details").is_none());
    }

    #[test]
    fn channel_clone_debug() {
        let ch = Channel {
            kind: "youtube#channel".into(),
            etag: "e".into(),
            id: "UCx".into(),
            snippet: None,
            statistics: None,
            content_details: None,
        };
        let ch2 = ch.clone();
        assert_eq!(ch2.id, "UCx");
        let dbg = format!("{ch:?}");
        assert!(dbg.contains("Channel"));
    }

    #[test]
    fn playlist_clone_debug() {
        let pl = Playlist {
            kind: "youtube#playlist".into(),
            etag: "e".into(),
            id: "PL1".into(),
            snippet: None,
            content_details: None,
        };
        let pl2 = pl.clone();
        assert_eq!(pl2.id, "PL1");
        let dbg = format!("{pl:?}");
        assert!(dbg.contains("Playlist"));
    }

    #[test]
    fn playlist_item_clone_debug() {
        let pi = PlaylistItem {
            kind: "youtube#playlistItem".into(),
            etag: "e".into(),
            id: "PI1".into(),
            snippet: None,
            content_details: None,
        };
        let pi2 = pi.clone();
        assert_eq!(pi2.id, "PI1");
        let dbg = format!("{pi:?}");
        assert!(dbg.contains("PlaylistItem"));
    }

    #[test]
    fn comment_thread_clone_debug() {
        let ct = CommentThread {
            kind: "youtube#commentThread".into(),
            etag: "e".into(),
            id: "CT1".into(),
            snippet: None,
        };
        let ct2 = ct.clone();
        assert_eq!(ct2.id, "CT1");
        let dbg = format!("{ct:?}");
        assert!(dbg.contains("CommentThread"));
    }

    #[test]
    fn caption_track_clone_debug() {
        let ct = CaptionTrack {
            kind: "youtube#caption".into(),
            etag: "e".into(),
            id: "cap1".into(),
            snippet: None,
        };
        let ct2 = ct.clone();
        assert_eq!(ct2.id, "cap1");
        let dbg = format!("{ct:?}");
        assert!(dbg.contains("CaptionTrack"));
    }

    #[test]
    fn api_error_response_roundtrip() {
        let resp = ApiErrorResponse {
            error: Some(ApiError {
                code: Some(429),
                message: Some("Rate limit".into()),
                errors: Some(vec![ApiErrorDetail {
                    message: Some("rate limit".into()),
                    domain: Some("youtube.quota".into()),
                    reason: Some("rateLimitExceeded".into()),
                }]),
            }),
        };
        let v = serde_json::to_value(&resp).unwrap();
        let resp2: ApiErrorResponse = serde_json::from_value(v).unwrap();
        let err = resp2.error.unwrap();
        assert_eq!(err.code, Some(429));
        assert_eq!(
            err.errors.unwrap()[0].reason,
            Some("rateLimitExceeded".into())
        );
    }

    #[test]
    fn api_error_response_clone_debug() {
        let resp = ApiErrorResponse { error: None };
        let resp2 = resp.clone();
        assert!(resp2.error.is_none());
        let dbg = format!("{resp:?}");
        assert!(dbg.contains("ApiErrorResponse"));
    }
}
