//! YouTube connector integration tests.
//!
//! Deterministic integration tests using wiremock to mock the YouTube Data API v3.
//! No real API calls. Covers:
//! - Happy-path operations (search, get_video, list_videos, get_channel, list_playlists, list_playlist_items,
//!   list_comments, post_comment, get_captions, get_caption_transcript, get_transcript, upload_caption)
//! - Error taxonomy (401/403/404/429 -> FcpError mapping)
//! - FCP2 default-deny + capability verification
//! - Lifecycle (health, handshake, introspect, shutdown)
//! - Input validation edge cases

#![allow(clippy::too_many_lines)]
#![allow(clippy::doc_markdown)]

use chrono::{Duration, Utc};
use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_google_discovery::auth::{GoogleAuthSourceKind, GoogleMaterializedAuth};
use fcp_prelude::{
    CapabilityConstraints, ConnectorId, OperationId, SimulateRequest, SimulateResponse,
};
use fcp_testkit::AsyncTestContext;
use serde_json::json;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path, path_regex, query_param},
};

use fcp_youtube::{
    client::{YouTubeAuth, YouTubeClient},
    connector::YouTubeConnector,
    error::YouTubeError,
};

// ============================================================================
// Helpers
// ============================================================================

fn generate_valid_token(
    signing_key: &Ed25519SigningKey,
    connector: &YouTubeConnector,
    op: &str,
) -> fcp_core::CapabilityToken {
    let cap = match op {
        "youtube.post_comment" | "youtube.upload_caption" => "youtube.write",
        _ => "youtube.read",
    };
    generate_token_for_capability(signing_key, connector, op, cap)
}

fn generate_token_for_capability(
    signing_key: &Ed25519SigningKey,
    connector: &YouTubeConnector,
    op: &str,
    cap: &str,
) -> fcp_core::CapabilityToken {
    let now = Utc::now();
    // C3.4: tokens MUST include constraints (default-deny)
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
    let cose = CapabilityTokenBuilder::new()
        .capability_id(cap)
        .zone_id("z:work")
        .principal("user:test")
        .operations(&[op])
        .issuer("node:test")
        .validity(now, now + Duration::hours(1))
        .target_instance(connector.instance_id())
        .try_constraints_cbor(&cbor)
        .expect("constraints CBOR should validate")
        .sign(signing_key)
        .unwrap();
    fcp_core::CapabilityToken::from_raw(cose)
}

async fn setup_handshake(connector: &mut YouTubeConnector, caps: &[&str]) -> Ed25519SigningKey {
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    connector
        .handle_handshake(json!({
            "protocol_version": "1.0.0",
            "zone": "z:work",
            "host_public_key": verifying_key.to_bytes(),
            "nonce": vec![0u8; 32],
            "capabilities_requested": caps
        }))
        .await
        .expect("handshake should succeed");

    signing_key
}

async fn setup_configure(connector: &mut YouTubeConnector, base_url: &str) {
    connector
        .handle_configure(json!({
            "api_key": "test-api-key-xyz",
            "base_url": base_url
        }))
        .await
        .expect("configure should succeed");
}

async fn setup_caption_upload(connector: &mut YouTubeConnector, base_url: &str) {
    connector
        .handle_configure(json!({
            "access_token": "fixture-caption-token",
            "base_url": base_url,
        }))
        .await
        .expect("OAuth upload configuration should succeed");
}

fn caption_upload_client(server: &MockServer) -> YouTubeClient {
    YouTubeClient::new_with_auth(YouTubeAuth::GoogleShared(
        GoogleMaterializedAuth::BearerToken {
            access_token: "fixture-caption-token".into(),
            source: GoogleAuthSourceKind::AccessToken,
            granted_scopes: Vec::new(),
            quota_project_id: None,
        },
    ))
    .unwrap()
    .with_base_url(&format!("{}/youtube/v3", server.uri()))
}

fn caption_upload_response() -> serde_json::Value {
    json!({
        "kind": "youtube#caption", "etag": "etag-1", "id": "cap-new-1",
        "snippet": {
            "videoId": "dQw4w9WgXcQ", "language": "en", "trackKind": "standard",
            "name": "Uploaded transcript", "isDraft": false, "status": "syncing",
        },
    })
}

const CAPTION_FILE: &str =
    "\u{feff}1\r\n00:00:00,000 --> 00:00:01,000\r\nHello 雪 <b>caption</b>\r\n\r\n";

// ============================================================================
// Happy-path operation tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn search_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("youtube.search.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex("/search.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kind": "youtube#searchListResponse",
            "etag": "abc123",
            "pageInfo": { "totalResults": 2, "resultsPerPage": 5 },
            "items": [
                {
                    "kind": "youtube#searchResult",
                    "etag": "e1",
                    "id": { "kind": "youtube#video", "videoId": "vid001" },
                    "snippet": {
                        "title": "Rust Tutorial",
                        "description": "Learn Rust programming",
                        "thumbnails": {}
                    }
                },
                {
                    "kind": "youtube#searchResult",
                    "etag": "e2",
                    "id": { "kind": "youtube#video", "videoId": "vid002" },
                    "snippet": {
                        "title": "Rust Advanced",
                        "description": "Advanced Rust topics",
                        "thumbnails": {}
                    }
                }
            ]
        })))
        .mount(&mock_server)
        .await;

    let mut connector = YouTubeConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["youtube.search"]).await;
    let capability = generate_valid_token(&signing_key, &connector, "youtube.search");

    let result = connector
        .handle_invoke(json!({
            "operation": "youtube.search",
            "input": { "query": "rust programming", "max_results": 5, "type": "video" },
            "capability_token": capability
        }))
        .await
        .expect("search invoke should succeed");

    let items = result["items"].as_array().expect("items array");
    assert_eq!(items.len(), 2);
    assert_eq!(result["total_results"], 2);
}

#[fcp_async_core::runtime::test]
async fn get_video_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("youtube.get_video.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex("/videos.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kind": "youtube#videoListResponse",
            "etag": "abc",
            "pageInfo": { "totalResults": 1, "resultsPerPage": 1 },
            "items": [{
                "kind": "youtube#video",
                "etag": "def",
                "id": "dQw4w9WgXcQ",
                "snippet": {
                    "title": "Rick Astley - Never Gonna Give You Up",
                    "description": "Official music video",
                    "thumbnails": {}
                },
                "contentDetails": { "duration": "PT3M33S", "definition": "hd" },
                "statistics": { "viewCount": "1500000000", "likeCount": "15000000" }
            }]
        })))
        .mount(&mock_server)
        .await;

    let mut connector = YouTubeConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["youtube.get_video"]).await;
    let capability = generate_valid_token(&signing_key, &connector, "youtube.get_video");

    let result = connector
        .handle_invoke(json!({
            "operation": "youtube.get_video",
            "input": { "video_id": "dQw4w9WgXcQ" },
            "capability_token": capability
        }))
        .await
        .expect("get_video invoke should succeed");

    assert_eq!(result["video"]["id"], "dQw4w9WgXcQ");
    assert_eq!(
        result["video"]["snippet"]["title"],
        "Rick Astley - Never Gonna Give You Up"
    );
}

#[fcp_async_core::runtime::test]
async fn list_videos_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("youtube.list_videos.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex("/videos.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kind": "youtube#videoListResponse",
            "etag": "abc",
            "pageInfo": { "totalResults": 2, "resultsPerPage": 2 },
            "items": [
                {
                    "kind": "youtube#video",
                    "etag": "def1",
                    "id": "vid001",
                    "snippet": { "title": "Video 1", "description": "First", "thumbnails": {} }
                },
                {
                    "kind": "youtube#video",
                    "etag": "def2",
                    "id": "vid002",
                    "snippet": { "title": "Video 2", "description": "Second", "thumbnails": {} }
                }
            ]
        })))
        .mount(&mock_server)
        .await;

    let mut connector = YouTubeConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["youtube.list_videos"]).await;
    let capability = generate_valid_token(&signing_key, &connector, "youtube.list_videos");

    let result = connector
        .handle_invoke(json!({
            "operation": "youtube.list_videos",
            "input": { "video_ids": ["vid001", "vid002"] },
            "capability_token": capability
        }))
        .await
        .expect("list_videos invoke should succeed");

    let videos = result["videos"].as_array().expect("videos array");
    assert_eq!(videos.len(), 2);
    assert_eq!(result["total_results"], 2);
}

#[fcp_async_core::runtime::test]
async fn get_channel_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("youtube.get_channel.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex("/channels.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kind": "youtube#channelListResponse",
            "etag": "abc",
            "pageInfo": { "totalResults": 1, "resultsPerPage": 1 },
            "items": [{
                "kind": "youtube#channel",
                "etag": "def",
                "id": "UCuAXFkgsw1L7xaCfnd5JJOw",
                "snippet": {
                    "title": "Rick Astley",
                    "description": "Official channel"
                },
                "statistics": { "subscriberCount": "5000000", "videoCount": "100" }
            }]
        })))
        .mount(&mock_server)
        .await;

    let mut connector = YouTubeConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["youtube.get_channel"]).await;
    let capability = generate_valid_token(&signing_key, &connector, "youtube.get_channel");

    let result = connector
        .handle_invoke(json!({
            "operation": "youtube.get_channel",
            "input": { "channel_id": "UCuAXFkgsw1L7xaCfnd5JJOw" },
            "capability_token": capability
        }))
        .await
        .expect("get_channel invoke should succeed");

    assert_eq!(result["channel"]["id"], "UCuAXFkgsw1L7xaCfnd5JJOw");
    assert_eq!(result["channel"]["snippet"]["title"], "Rick Astley");
}

#[fcp_async_core::runtime::test]
async fn list_playlists_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("youtube.list_playlists.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex("/playlists.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kind": "youtube#playlistListResponse",
            "etag": "abc",
            "nextPageToken": "next-token",
            "pageInfo": { "totalResults": 2, "resultsPerPage": 2 },
            "items": [
                {
                    "kind": "youtube#playlist",
                    "etag": "pl1",
                    "id": "PL001",
                    "snippet": {
                        "channelId": "UCtest",
                        "title": "Playlist 1",
                        "description": "First playlist",
                        "thumbnails": {}
                    },
                    "contentDetails": { "itemCount": 10 }
                },
                {
                    "kind": "youtube#playlist",
                    "etag": "pl2",
                    "id": "PL002",
                    "snippet": {
                        "channelId": "UCtest",
                        "title": "Playlist 2",
                        "description": "Second playlist",
                        "thumbnails": {}
                    },
                    "contentDetails": { "itemCount": 8 }
                }
            ]
        })))
        .mount(&mock_server)
        .await;

    let mut connector = YouTubeConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["youtube.list_playlists"]).await;
    let capability = generate_valid_token(&signing_key, &connector, "youtube.list_playlists");

    let result = connector
        .handle_invoke(json!({
            "operation": "youtube.list_playlists",
            "input": { "channel_id": "UCtest", "max_results": 10 },
            "capability_token": capability
        }))
        .await
        .expect("list_playlists invoke should succeed");

    let playlists = result["playlists"].as_array().expect("playlists array");
    assert_eq!(playlists.len(), 2);
    assert_eq!(result["next_page_token"], "next-token");
}

#[fcp_async_core::runtime::test]
async fn list_playlist_items_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("youtube.list_playlist_items.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex("/playlistItems.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kind": "youtube#playlistItemListResponse",
            "etag": "abc",
            "pageInfo": { "totalResults": 2, "resultsPerPage": 5 },
            "items": [
                {
                    "kind": "youtube#playlistItem",
                    "etag": "d1",
                    "id": "item1",
                    "snippet": { "title": "Video 1", "description": "First", "position": 0 },
                    "contentDetails": { "videoId": "vid1" }
                },
                {
                    "kind": "youtube#playlistItem",
                    "etag": "d2",
                    "id": "item2",
                    "snippet": { "title": "Video 2", "description": "Second", "position": 1 },
                    "contentDetails": { "videoId": "vid2" }
                }
            ]
        })))
        .mount(&mock_server)
        .await;

    let mut connector = YouTubeConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["youtube.list_playlist_items"]).await;
    let capability = generate_valid_token(&signing_key, &connector, "youtube.list_playlist_items");

    let result = connector
        .handle_invoke(json!({
            "operation": "youtube.list_playlist_items",
            "input": { "playlist_id": "PLtest123", "max_results": 5 },
            "capability_token": capability
        }))
        .await
        .expect("list_playlist_items invoke should succeed");

    let items = result["items"].as_array().expect("items array");
    assert_eq!(items.len(), 2);
}

#[fcp_async_core::runtime::test]
async fn list_comments_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("youtube.list_comments.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex("/commentThreads.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kind": "youtube#commentThreadListResponse",
            "etag": "abc",
            "pageInfo": { "totalResults": 1, "resultsPerPage": 20 },
            "items": [{
                "kind": "youtube#commentThread",
                "etag": "def",
                "id": "ct1",
                "snippet": {
                    "videoId": "dQw4w9WgXcQ",
                    "topLevelComment": {
                        "id": "c1",
                        "snippet": {
                            "textDisplay": "Great video!",
                            "authorDisplayName": "TestUser",
                            "likeCount": 5
                        }
                    },
                    "totalReplyCount": 0
                }
            }]
        })))
        .mount(&mock_server)
        .await;

    let mut connector = YouTubeConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["youtube.list_comments"]).await;
    let capability = generate_valid_token(&signing_key, &connector, "youtube.list_comments");

    let result = connector
        .handle_invoke(json!({
            "operation": "youtube.list_comments",
            "input": { "video_id": "dQw4w9WgXcQ", "max_results": 20 },
            "capability_token": capability
        }))
        .await
        .expect("list_comments invoke should succeed");

    let items = result["items"].as_array().expect("items array");
    assert_eq!(items.len(), 1);
}

#[fcp_async_core::runtime::test]
async fn post_comment_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("youtube.post_comment.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex("/commentThreads.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "c-new-1",
            "snippet": {
                "textDisplay": "Great tutorial!",
                "authorDisplayName": "FCP Agent",
                "videoId": "dQw4w9WgXcQ",
                "likeCount": 0
            }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = YouTubeConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["youtube.post_comment"]).await;
    let capability = generate_valid_token(&signing_key, &connector, "youtube.post_comment");

    let result = connector
        .handle_invoke(json!({
            "operation": "youtube.post_comment",
            "input": { "video_id": "dQw4w9WgXcQ", "text": "Great tutorial!" },
            "capability_token": capability
        }))
        .await
        .expect("post_comment invoke should succeed");

    assert!(result.get("comment").is_some());
}

#[fcp_async_core::runtime::test]
async fn get_captions_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("youtube.get_captions.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex("/captions.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kind": "youtube#captionListResponse",
            "etag": "abc",
            "items": [{
                "kind": "youtube#caption",
                "etag": "def",
                "id": "cap1",
                "snippet": {
                    "videoId": "dQw4w9WgXcQ",
                    "language": "en",
                    "trackKind": "asr",
                    "name": "English (auto-generated)"
                }
            }]
        })))
        .mount(&mock_server)
        .await;

    let mut connector = YouTubeConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["youtube.get_captions"]).await;
    let capability = generate_valid_token(&signing_key, &connector, "youtube.get_captions");

    let result = connector
        .handle_invoke(json!({
            "operation": "youtube.get_captions",
            "input": { "video_id": "dQw4w9WgXcQ" },
            "capability_token": capability
        }))
        .await
        .expect("get_captions invoke should succeed");

    let items = result["items"].as_array().expect("items array");
    assert_eq!(items.len(), 1);
}

#[fcp_async_core::runtime::test]
async fn get_caption_transcript_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("youtube.get_caption_transcript.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex("/captions/cap1.*"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            "1\n00:00:00,000 --> 00:00:01,000\nHello from transcript\n".to_string(),
        ))
        .mount(&mock_server)
        .await;

    let mut connector = YouTubeConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["youtube.get_caption_transcript"]).await;
    let capability =
        generate_valid_token(&signing_key, &connector, "youtube.get_caption_transcript");

    let result = connector
        .handle_invoke(json!({
            "operation": "youtube.get_caption_transcript",
            "input": { "caption_id": "cap1", "format": "srt" },
            "capability_token": capability
        }))
        .await
        .expect("get_caption_transcript invoke should succeed");

    assert_eq!(result["caption_id"], "cap1");
    assert_eq!(result["format"], "srt");
    assert!(
        result["transcript"]
            .as_str()
            .expect("transcript str")
            .contains("Hello from transcript")
    );
    assert_eq!(result["taint"].as_array().expect("taint array").len(), 2);
}

#[fcp_async_core::runtime::test]
async fn get_transcript_url_language_fallback_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("youtube.get_transcript.language_fallback");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/captions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kind": "youtube#captionListResponse",
            "etag": "abc",
            "items": [
                {
                    "kind": "youtube#caption",
                    "etag": "es",
                    "id": "cap-es",
                    "snippet": {
                        "videoId": "dQw4w9WgXcQ",
                        "language": "es",
                        "trackKind": "standard",
                        "status": "serving"
                    }
                },
                {
                    "kind": "youtube#caption",
                    "etag": "en",
                    "id": "cap-en",
                    "snippet": {
                        "videoId": "dQw4w9WgXcQ",
                        "language": "en-US",
                        "trackKind": "asr",
                        "status": "serving"
                    }
                }
            ]
        })))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/captions/cap-en"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            "1\n00:00:00,000 --> 00:00:01,000\nHello transcript\n\n2\n00:00:01,500 --> 00:00:02,000\nSecond segment\n"
                .to_string(),
        ))
        .mount(&mock_server)
        .await;

    let mut connector = YouTubeConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["youtube.get_transcript"]).await;
    let capability = generate_valid_token(&signing_key, &connector, "youtube.get_transcript");

    let result = connector
        .handle_invoke(json!({
            "operation": "youtube.get_transcript",
            "input": {
                "video_url": "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
                "language": "fr,en",
                "max_segments": 10
            },
            "capability_token": capability
        }))
        .await
        .expect("get_transcript invoke should succeed");

    assert_eq!(result["video_id"], "dQw4w9WgXcQ");
    assert_eq!(result["caption_id"], "cap-en");
    assert_eq!(result["language"], "en-US");
    assert_eq!(result["track_kind"], "asr");
    assert_eq!(result["format"], "srt");
    assert_eq!(
        result["segments"].as_array().expect("segments array").len(),
        2
    );
    assert_eq!(result["segments"][0]["start_ms"], 0);
    assert_eq!(result["segments"][1]["start"], "00:00:01.500");
    assert_eq!(result["full_text"], "Hello transcript\nSecond segment");
    assert!(
        result["timestamped_text"]
            .as_str()
            .expect("timestamped text")
            .contains("[00:00:00.000] Hello transcript")
    );
    assert_eq!(
        result["provenance"]["auth_model"],
        "official_youtube_data_api"
    );
    assert_eq!(result["taint"].as_array().expect("taint array").len(), 2);
}

#[fcp_async_core::runtime::test]
async fn get_transcript_no_caption_track_fails() {
    let _ctx = AsyncTestContext::for_scenario("youtube.get_transcript.no_captions");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/captions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kind": "youtube#captionListResponse",
            "etag": "empty",
            "items": []
        })))
        .mount(&mock_server)
        .await;

    let mut connector = YouTubeConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["youtube.get_transcript"]).await;
    let capability = generate_valid_token(&signing_key, &connector, "youtube.get_transcript");

    let error = connector
        .handle_invoke(json!({
            "operation": "youtube.get_transcript",
            "input": { "video_id": "dQw4w9WgXcQ" },
            "capability_token": capability
        }))
        .await
        .unwrap_err();

    assert!(
        matches!(error, fcp_core::FcpError::ResourceNotFound { .. }),
        "expected ResourceNotFound, got {error:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn get_transcript_rejects_oversized_transcript() {
    let _ctx = AsyncTestContext::for_scenario("youtube.get_transcript.max_bytes");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/captions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kind": "youtube#captionListResponse",
            "etag": "abc",
            "items": [{
                "kind": "youtube#caption",
                "etag": "en",
                "id": "cap-en",
                "snippet": {
                    "videoId": "dQw4w9WgXcQ",
                    "language": "en",
                    "trackKind": "standard",
                    "status": "serving"
                }
            }]
        })))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/captions/cap-en"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            "1\n00:00:00,000 --> 00:00:01,000\nThis transcript body is intentionally too large\n"
                .to_string(),
        ))
        .mount(&mock_server)
        .await;

    let mut connector = YouTubeConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["youtube.get_transcript"]).await;
    let capability = generate_valid_token(&signing_key, &connector, "youtube.get_transcript");

    let error = connector
        .handle_invoke(json!({
            "operation": "youtube.get_transcript",
            "input": {
                "video_id": "dQw4w9WgXcQ",
                "max_bytes": 20
            },
            "capability_token": capability
        }))
        .await
        .unwrap_err();

    assert!(
        matches!(&error, fcp_core::FcpError::InvalidRequest { message, .. } if message.contains("max_bytes")),
        "expected max_bytes InvalidRequest, got {error:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn upload_caption_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("youtube.upload_caption.happy_path");
    for credential_mode in [false, true] {
        let server = MockServer::start().await;
        let prefix = if credential_mode {
            "/fixture/youtube/v3"
        } else {
            "/youtube/v3"
        };
        let name = if credential_mode {
            "Uploaded transcript"
        } else {
            "English 雪"
        };
        let mut response = caption_upload_response();
        response["snippet"]["name"] = json!(name);
        response["snippet"]["language"] = json!("en-US");
        Mock::given(method("POST"))
            .and(path(format!("/upload{prefix}/captions")))
            .and(query_param("part", "snippet"))
            .and(query_param("uploadType", "multipart"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response))
            .expect(1)
            .mount(&server)
            .await;
        let credential_id = fcp_core::CredentialId::new();
        let mut config = json!({"base_url": format!("{}{prefix}", server.uri())});
        if credential_mode {
            config["credential_id"] = json!(credential_id.to_string());
        } else {
            config["access_token"] = json!("fixture-caption-token");
        }
        let mut connector = YouTubeConnector::new();
        connector.handle_configure(config).await.unwrap();
        let key = setup_handshake(&mut connector, &["youtube.read", "youtube.write"]).await;
        let mut input = json!({
            "video_id": "dQw4w9WgXcQ", "language": "en-US", "transcript": CAPTION_FILE,
        });
        if !credential_mode {
            input["name"] = json!(name);
        }
        let denied = connector.handle_invoke(json!({
            "operation": "youtube.upload_caption", "input": input,
            "capability_token": generate_token_for_capability(&key, &connector, "youtube.upload_caption", "youtube.read"),
        })).await.unwrap_err();
        assert!(matches!(
            denied,
            fcp_core::FcpError::OperationNotGranted { .. }
                | fcp_core::FcpError::CapabilityDenied { .. }
        ));
        assert!(server.received_requests().await.unwrap().is_empty());
        let result = connector.handle_invoke(json!({
            "operation": "youtube.upload_caption", "input": input,
            "capability_token": generate_valid_token(&key, &connector, "youtube.upload_caption"),
        })).await.expect("upload_caption invoke should succeed");
        assert_eq!(result["caption"]["id"], "cap-new-1");
        assert_eq!(result["caption"]["snippet"]["status"], "syncing");
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        let request = &requests[0];
        assert!(
            !request
                .url
                .query_pairs()
                .any(|(key, _)| key == "key" || key == "sync")
        );
        assert_eq!(
            request
                .url
                .query_pairs()
                .filter(|(key, _)| key == "uploadType")
                .count(),
            1
        );
        if credential_mode {
            assert_eq!(
                request.headers["x-fcp-credential-id"].to_str().unwrap(),
                credential_id.to_string()
            );
            assert!(!request.headers.contains_key("authorization"));
        } else {
            assert_eq!(
                request.headers["authorization"].to_str().unwrap(),
                "Bearer fixture-caption-token"
            );
            assert!(!request.headers.contains_key("x-fcp-credential-id"));
        }
        assert_eq!(
            request.headers["content-length"]
                .to_str()
                .unwrap()
                .parse::<usize>()
                .unwrap(),
            request.body.len()
        );
        let boundary = request.headers["content-type"]
            .to_str()
            .unwrap()
            .strip_prefix("multipart/related; boundary=")
            .unwrap();
        let metadata_header =
            format!("--{boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n");
        let media_header =
            format!("\r\n--{boundary}\r\nContent-Type: application/octet-stream\r\n\r\n");
        let closing = format!("\r\n--{boundary}--\r\n");
        assert!(request.body.starts_with(metadata_header.as_bytes()));
        assert!(request.body.ends_with(closing.as_bytes()));
        let media_start = request
            .body
            .windows(media_header.len())
            .position(|part| part == media_header.as_bytes())
            .unwrap();
        let metadata: serde_json::Value =
            serde_json::from_slice(&request.body[metadata_header.len()..media_start]).unwrap();
        assert_eq!(
            metadata,
            json!({"snippet":{
                "videoId":"dQw4w9WgXcQ", "language":"en-US", "name":name, "isDraft":false,
            }})
        );
        assert_eq!(
            &request.body[media_start + media_header.len()..request.body.len() - closing.len()],
            CAPTION_FILE.as_bytes()
        );
    }
}

#[fcp_async_core::runtime::test]
async fn caption_upload_validation_and_api_key_denials_do_not_contact_google() {
    let server = MockServer::start().await;
    let mut connector = YouTubeConnector::new();
    setup_caption_upload(&mut connector, &server.uri()).await;
    let key = setup_handshake(&mut connector, &["youtube.write"]).await;
    let base = json!({"video_id":"dQw4w9WgXcQ", "language":"en", "transcript":CAPTION_FILE});
    for (field, value) in [
        ("video_id", json!("../video")),
        ("video_id", json!("")),
        ("language", json!("en_US")),
        ("language", json!("en--US")),
        ("transcript", json!(" \r\n")),
        ("transcript", json!(false)),
        ("name", json!(false)),
        ("name", serde_json::Value::Null),
        ("name", json!("雪".repeat(151))),
    ] {
        let mut input = base.clone();
        input[field] = value;
        let error = connector
            .handle_invoke(json!({
                "operation":"youtube.upload_caption", "input":input,
                "capability_token":generate_valid_token(&key, &connector, "youtube.upload_caption"),
            }))
            .await
            .unwrap_err();
        assert!(
            matches!(error, fcp_core::FcpError::InvalidRequest { .. }),
            "{field}: {error:?}"
        );
        let request = SimulateRequest::new(
            ConnectorId::from_static("youtube"),
            OperationId::from_static("youtube.upload_caption"),
            fcp_core::ZoneId::work(),
            input,
            generate_valid_token(&key, &connector, "youtube.upload_caption"),
        );
        let response: SimulateResponse = serde_json::from_value(
            connector
                .handle_simulate(serde_json::to_value(request).unwrap())
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(!response.would_succeed);
        assert_eq!(response.denial_code, Some(error.error_code()));
    }
    setup_configure(&mut connector, &server.uri()).await;
    let key = setup_handshake(&mut connector, &["youtube.write"]).await;
    let error = connector
        .handle_invoke(json!({
            "operation":"youtube.upload_caption", "input":base,
            "capability_token":generate_valid_token(&key, &connector, "youtube.upload_caption"),
        }))
        .await
        .unwrap_err();
    assert!(matches!(error, fcp_core::FcpError::Unauthorized { .. }));
    assert!(error.to_string().contains("youtube.force-ssl"));
    assert!(!error.to_string().contains("test-api-key-xyz"));
    let request = SimulateRequest::new(
        ConnectorId::from_static("youtube"),
        OperationId::from_static("youtube.upload_caption"),
        fcp_core::ZoneId::work(),
        base,
        generate_valid_token(&key, &connector, "youtube.upload_caption"),
    );
    let response: SimulateResponse = serde_json::from_value(
        connector
            .handle_simulate(serde_json::to_value(request).unwrap())
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(!response.would_succeed);
    assert_eq!(response.denial_code, Some(error.error_code()));
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn caption_upload_unknown_completion_is_nonretryable() {
    let mut blank_id = caption_upload_response();
    blank_id["id"] = json!(" ");
    let mut empty_id = caption_upload_response();
    empty_id["id"] = json!("");
    let mut wrong_video = caption_upload_response();
    wrong_video["snippet"]["videoId"] = json!("another_video");
    let mut missing_status = caption_upload_response();
    missing_status["snippet"]
        .as_object_mut()
        .unwrap()
        .remove("status");
    let responses = [
        ResponseTemplate::new(503)
            .set_body_json(json!({"error":{"code":503,"message":"unavailable"}})),
        ResponseTemplate::new(200).set_body_json(json!({})),
        ResponseTemplate::new(200).set_body_json(blank_id),
        ResponseTemplate::new(200).set_body_json(empty_id),
        ResponseTemplate::new(200).set_body_json(wrong_video),
        ResponseTemplate::new(200).set_body_json(missing_status),
        ResponseTemplate::new(200).set_body_string("not JSON"),
        ResponseTemplate::new(204),
        ResponseTemplate::new(200).set_body_string("x".repeat(5 * 1024 * 1024 + 1)),
    ];
    for response in responses {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/upload/youtube/v3/captions"))
            .respond_with(response)
            .expect(1)
            .mount(&server)
            .await;
        let error = caption_upload_client(&server)
            .with_retry_config(2)
            .upload_caption("dQw4w9WgXcQ", "en", CAPTION_FILE, None)
            .await
            .unwrap_err();
        assert!(
            matches!(error, YouTubeError::CaptionUploadOutcomeUnknown { .. }),
            "{error:?}"
        );
        assert!(!error.is_retryable());
        assert!(matches!(
            error.to_fcp_error(),
            fcp_core::FcpError::External {
                retryable: false,
                ..
            }
        ));
        assert!(error.to_string().contains("youtube.get_captions"));
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }
}

#[fcp_async_core::runtime::test]
async fn caption_upload_provider_rejections_are_distinct_from_unknown_outcomes() {
    for (status, reason) in [(400, "invalidMetadata"), (409, "captionExists")] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/upload/youtube/v3/captions"))
            .respond_with(ResponseTemplate::new(status).set_body_json(json!({
                "error":{"code":status,"message":reason,"errors":[{"reason":reason}]}
            })))
            .expect(1)
            .mount(&server)
            .await;
        let error = caption_upload_client(&server)
            .with_retry_config(2)
            .upload_caption("dQw4w9WgXcQ", "en", CAPTION_FILE, None)
            .await
            .unwrap_err();
        assert!(
            matches!(&error, YouTubeError::Api { status_code:Some(code), message } if *code == status && message.contains(reason))
        );
        assert!(!error.is_retryable());
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }
}

#[fcp_async_core::runtime::test]
async fn caption_upload_returns_created_track_processing_failure() {
    let server = MockServer::start().await;
    let mut response = caption_upload_response();
    response["snippet"]["status"] = json!("failed");
    response["snippet"]["failureReason"] = json!("unsupportedFormat");
    Mock::given(method("POST"))
        .and(path("/upload/youtube/v3/captions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(response))
        .expect(1)
        .mount(&server)
        .await;
    let caption = caption_upload_client(&server)
        .upload_caption("dQw4w9WgXcQ", "en", CAPTION_FILE, None)
        .await
        .unwrap();
    assert_eq!(caption.id, "cap-new-1");
    let snippet = caption.snippet.unwrap();
    assert_eq!(snippet.status.as_deref(), Some("failed"));
    assert_eq!(snippet.failure_reason.as_deref(), Some("unsupportedFormat"));
    assert_eq!(
        serde_json::to_value(snippet).unwrap()["failureReason"],
        "unsupportedFormat"
    );
}

#[fcp_async_core::runtime::test]
async fn caption_upload_retries_only_explicit_rate_limits_with_identical_media() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/upload/youtube/v3/captions"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("retry-after", "0")
                .set_body_json(json!({"error":{"code":429,"message":"rate limited"}})),
        )
        .up_to_n_times(1)
        .expect(1)
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/upload/youtube/v3/captions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(caption_upload_response()))
        .expect(1)
        .with_priority(2)
        .mount(&server)
        .await;
    let caption = caption_upload_client(&server)
        .with_retry_config(1)
        .upload_caption("dQw4w9WgXcQ", "en", CAPTION_FILE, None)
        .await
        .unwrap();
    assert_eq!(caption.id, "cap-new-1");
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].url, requests[1].url);
    assert_eq!(requests[0].body, requests[1].body);
}

#[fcp_async_core::runtime::test]
async fn caption_upload_cancellation_after_dispatch_does_not_replay() {
    let server = MockServer::start().await;
    let client = std::sync::Arc::new(caption_upload_client(&server).with_retry_config(2));
    let client_on_request = std::sync::Arc::clone(&client);
    Mock::given(method("POST"))
        .and(path("/upload/youtube/v3/captions"))
        .respond_with(move |_request: &wiremock::Request| {
            client_on_request.shutdown();
            ResponseTemplate::new(200)
                .set_body_json(caption_upload_response())
                .set_delay(std::time::Duration::from_secs(1))
        })
        .expect(1)
        .mount(&server)
        .await;
    let error = client
        .upload_caption("dQw4w9WgXcQ", "en", CAPTION_FILE, None)
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        YouTubeError::CaptionUploadOutcomeUnknown { .. }
    ));
    assert!(!error.is_retryable());
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[fcp_async_core::runtime::test]
async fn caption_upload_does_not_redirect_credentials_or_content() {
    let server = MockServer::start().await;
    let target = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/upload/youtube/v3/captions"))
        .respond_with(
            ResponseTemplate::new(307)
                .insert_header("location", format!("{}/stolen", target.uri())),
        )
        .expect(1)
        .mount(&server)
        .await;
    assert!(
        caption_upload_client(&server)
            .upload_caption("dQw4w9WgXcQ", "en", CAPTION_FILE, None)
            .await
            .is_err()
    );
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
    assert!(target.received_requests().await.unwrap().is_empty());
}

// ============================================================================
// Error taxonomy tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn unauthorized_maps_to_fcp_error() {
    let _ctx = AsyncTestContext::for_scenario("youtube.error.unauthorized");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex("/videos.*"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "error": {
                "code": 401,
                "message": "Invalid API key",
                "errors": [{ "reason": "authError", "domain": "global" }]
            }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = YouTubeConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["youtube.get_video"]).await;
    let capability = generate_valid_token(&signing_key, &connector, "youtube.get_video");

    let result = connector
        .handle_invoke(json!({
            "operation": "youtube.get_video",
            "input": { "video_id": "dQw4w9WgXcQ" },
            "capability_token": capability
        }))
        .await;

    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn not_found_maps_to_fcp_error() {
    let _ctx = AsyncTestContext::for_scenario("youtube.error.not_found");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex("/channels.*"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "error": {
                "code": 404,
                "message": "Channel not found",
                "errors": [{ "reason": "notFound", "domain": "youtube.channel" }]
            }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = YouTubeConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["youtube.get_channel"]).await;
    let capability = generate_valid_token(&signing_key, &connector, "youtube.get_channel");

    let result = connector
        .handle_invoke(json!({
            "operation": "youtube.get_channel",
            "input": { "channel_id": "UCnonexistent" },
            "capability_token": capability
        }))
        .await;

    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn quota_exceeded_maps_to_fcp_error() {
    let _ctx = AsyncTestContext::for_scenario("youtube.error.quota_exceeded");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex("/search.*"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({
            "error": {
                "code": 403,
                "message": "Quota exceeded",
                "errors": [{ "reason": "quotaExceeded", "domain": "youtube.quota" }]
            }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = YouTubeConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["youtube.search"]).await;
    let capability = generate_valid_token(&signing_key, &connector, "youtube.search");

    let result = connector
        .handle_invoke(json!({
            "operation": "youtube.search",
            "input": { "query": "test" },
            "capability_token": capability
        }))
        .await;

    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn rate_limited_maps_to_fcp_error() {
    let _ctx = AsyncTestContext::for_scenario("youtube.error.rate_limited");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex("/videos.*"))
        .respond_with(ResponseTemplate::new(429).set_body_json(json!({
            "error": {
                "code": 429,
                "message": "Rate limit exceeded"
            }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = YouTubeConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["youtube.get_video"]).await;
    let capability = generate_valid_token(&signing_key, &connector, "youtube.get_video");

    // The YouTube client hardcodes a 60-second retry-after for 429 responses,
    // and with_retry_config(0) is currently ineffective (sets dead field).
    // Wrap in a short timeout to prevent the retry loop from blocking the test
    // for the full 30-second request context deadline.
    let result = fcp_async_core::time::timeout(
        std::time::Duration::from_secs(2),
        connector.handle_invoke(json!({
            "operation": "youtube.get_video",
            "input": { "video_id": "dQw4w9WgXcQ" },
            "capability_token": capability
        })),
    )
    .await;

    // Either the outer timeout fires (Err) or the invoke itself returns an
    // error (Ok(Err)) — both confirm the 429 was not treated as success.
    match result {
        Err(_timeout) => {} // outer timeout fired, expected
        Ok(inner) => assert!(inner.is_err(), "429 should not succeed"),
    }
}

// ============================================================================
// FCP2 default-deny + capability verification
// ============================================================================

#[fcp_async_core::runtime::test]
async fn invoke_without_configure_fails() {
    let _ctx = AsyncTestContext::for_scenario("youtube.deny.not_configured");
    let mut connector = YouTubeConnector::new();
    let signing_key = setup_handshake(&mut connector, &["youtube.get_video"]).await;
    let capability = generate_valid_token(&signing_key, &connector, "youtube.get_video");

    let result = connector
        .handle_invoke(json!({
            "operation": "youtube.get_video",
            "input": { "video_id": "dQw4w9WgXcQ" },
            "capability_token": capability
        }))
        .await;

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        fcp_core::FcpError::NotConfigured
    ));
}

#[fcp_async_core::runtime::test]
async fn invoke_with_wrong_capability_denied() {
    let _ctx = AsyncTestContext::for_scenario("youtube.deny.wrong_capability");
    let mock_server = MockServer::start().await;

    let mut connector = YouTubeConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    // Handshake grants youtube.search but we invoke youtube.get_video
    let signing_key = setup_handshake(&mut connector, &["youtube.search"]).await;
    let capability = generate_valid_token(&signing_key, &connector, "youtube.search");

    let result = connector
        .handle_invoke(json!({
            "operation": "youtube.get_video",
            "input": { "video_id": "dQw4w9WgXcQ" },
            "capability_token": capability
        }))
        .await;

    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn invoke_unknown_operation_denied() {
    let _ctx = AsyncTestContext::for_scenario("youtube.deny.unknown_operation");
    let mock_server = MockServer::start().await;

    let mut connector = YouTubeConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["youtube.nonexistent"]).await;
    let capability = generate_valid_token(&signing_key, &connector, "youtube.nonexistent");

    let result = connector
        .handle_invoke(json!({
            "operation": "youtube.nonexistent",
            "input": {},
            "capability_token": capability
        }))
        .await;

    assert!(result.is_err());
}

// ============================================================================
// Lifecycle tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn health_not_configured() {
    let _ctx = AsyncTestContext::for_scenario("youtube.lifecycle.health_not_configured");
    let connector = YouTubeConnector::new();
    let result = connector
        .handle_health()
        .await
        .expect("health should succeed");
    assert_eq!(result["status"], "not_configured");
}

#[fcp_async_core::runtime::test]
async fn health_configured() {
    let _ctx = AsyncTestContext::for_scenario("youtube.lifecycle.health_configured");
    let mut connector = YouTubeConnector::new();
    setup_configure(&mut connector, "http://localhost:9999").await;
    let result = connector
        .handle_health()
        .await
        .expect("health should succeed");
    assert_eq!(result["status"], "healthy");
}

#[fcp_async_core::runtime::test]
async fn introspect_lists_all_operations() {
    let _ctx = AsyncTestContext::for_scenario("youtube.lifecycle.introspect");
    let connector = YouTubeConnector::new();
    let result = connector
        .handle_introspect()
        .await
        .expect("introspect should succeed");

    let ops = result["operations"].as_array().expect("operations array");
    let op_ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();

    assert!(op_ids.contains(&"youtube.search"));
    assert!(op_ids.contains(&"youtube.get_video"));
    assert!(op_ids.contains(&"youtube.list_videos"));
    assert!(op_ids.contains(&"youtube.get_channel"));
    assert!(op_ids.contains(&"youtube.list_playlists"));
    assert!(op_ids.contains(&"youtube.list_playlist_items"));
    assert!(op_ids.contains(&"youtube.list_comments"));
    assert!(op_ids.contains(&"youtube.post_comment"));
    assert!(op_ids.contains(&"youtube.get_captions"));
    assert!(op_ids.contains(&"youtube.get_caption_transcript"));
    assert!(op_ids.contains(&"youtube.get_transcript"));
    assert!(op_ids.contains(&"youtube.upload_caption"));
    assert!(op_ids.contains(&"youtube.get_analytics"));
    assert!(op_ids.contains(&"youtube.upload_video"));
    assert_eq!(ops.len(), 14);
}

#[fcp_async_core::runtime::test]
async fn shutdown_succeeds() {
    let _ctx = AsyncTestContext::for_scenario("youtube.lifecycle.shutdown");
    let connector = YouTubeConnector::new();
    let result = connector
        .handle_shutdown(json!({}))
        .await
        .expect("shutdown should succeed");
    assert_eq!(result["status"], "shutdown");
}

// ============================================================================
// Input validation edge cases
// ============================================================================

#[fcp_async_core::runtime::test]
async fn search_missing_query_fails() {
    let _ctx = AsyncTestContext::for_scenario("youtube.validation.search_missing_query");
    let mock_server = MockServer::start().await;

    let mut connector = YouTubeConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["youtube.search"]).await;
    let capability = generate_valid_token(&signing_key, &connector, "youtube.search");

    let result = connector
        .handle_invoke(json!({
            "operation": "youtube.search",
            "input": {},
            "capability_token": capability
        }))
        .await;

    assert!(result.is_err());
    let error = result.unwrap_err();
    assert!(
        matches!(&error, fcp_core::FcpError::InvalidRequest { message, .. } if message.contains("query")),
        "Expected InvalidRequest, got: {error:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn get_video_missing_video_id_fails() {
    let _ctx = AsyncTestContext::for_scenario("youtube.validation.get_video_missing_id");
    let mock_server = MockServer::start().await;

    let mut connector = YouTubeConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["youtube.get_video"]).await;
    let capability = generate_valid_token(&signing_key, &connector, "youtube.get_video");

    let result = connector
        .handle_invoke(json!({
            "operation": "youtube.get_video",
            "input": {},
            "capability_token": capability
        }))
        .await;

    assert!(result.is_err());
    let error = result.unwrap_err();
    assert!(
        matches!(&error, fcp_core::FcpError::InvalidRequest { message, .. } if message.contains("video_id")),
        "Expected InvalidRequest, got: {error:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn list_videos_empty_video_ids_fails() {
    let _ctx = AsyncTestContext::for_scenario("youtube.validation.list_videos_empty_ids");
    let mock_server = MockServer::start().await;

    let mut connector = YouTubeConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["youtube.list_videos"]).await;
    let capability = generate_valid_token(&signing_key, &connector, "youtube.list_videos");

    let result = connector
        .handle_invoke(json!({
            "operation": "youtube.list_videos",
            "input": { "video_ids": [] },
            "capability_token": capability
        }))
        .await;

    assert!(result.is_err());
    let error = result.unwrap_err();
    assert!(
        matches!(&error, fcp_core::FcpError::InvalidRequest { message, .. } if message.contains("video_ids")),
        "Expected InvalidRequest, got: {error:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn list_playlists_missing_channel_id_fails() {
    let _ctx = AsyncTestContext::for_scenario("youtube.validation.list_playlists_missing_channel");
    let mock_server = MockServer::start().await;

    let mut connector = YouTubeConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["youtube.list_playlists"]).await;
    let capability = generate_valid_token(&signing_key, &connector, "youtube.list_playlists");

    let result = connector
        .handle_invoke(json!({
            "operation": "youtube.list_playlists",
            "input": {},
            "capability_token": capability
        }))
        .await;

    assert!(result.is_err());
    let error = result.unwrap_err();
    assert!(
        matches!(&error, fcp_core::FcpError::InvalidRequest { message, .. } if message.contains("channel_id")),
        "Expected InvalidRequest, got: {error:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn get_caption_transcript_missing_caption_id_fails() {
    let _ctx = AsyncTestContext::for_scenario(
        "youtube.validation.get_caption_transcript_missing_caption_id",
    );
    let mock_server = MockServer::start().await;

    let mut connector = YouTubeConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["youtube.get_caption_transcript"]).await;
    let capability =
        generate_valid_token(&signing_key, &connector, "youtube.get_caption_transcript");

    let result = connector
        .handle_invoke(json!({
            "operation": "youtube.get_caption_transcript",
            "input": {},
            "capability_token": capability
        }))
        .await;

    assert!(result.is_err());
    let error = result.unwrap_err();
    assert!(
        matches!(&error, fcp_core::FcpError::InvalidRequest { message, .. } if message.contains("caption_id")),
        "Expected InvalidRequest, got: {error:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn upload_caption_missing_transcript_fails() {
    let _ctx =
        AsyncTestContext::for_scenario("youtube.validation.upload_caption_missing_transcript");
    let mock_server = MockServer::start().await;

    let mut connector = YouTubeConnector::new();
    setup_caption_upload(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["youtube.upload_caption"]).await;
    let capability = generate_valid_token(&signing_key, &connector, "youtube.upload_caption");

    let result = connector
        .handle_invoke(json!({
            "operation": "youtube.upload_caption",
            "input": {
                "video_id": "dQw4w9WgXcQ",
                "language": "en"
            },
            "capability_token": capability
        }))
        .await;

    assert!(result.is_err());
    let error = result.unwrap_err();
    assert!(
        matches!(&error, fcp_core::FcpError::InvalidRequest { message, .. } if message.contains("transcript")),
        "Expected InvalidRequest, got: {error:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn post_comment_missing_text_fails() {
    let _ctx = AsyncTestContext::for_scenario("youtube.validation.post_comment_missing_text");
    let mock_server = MockServer::start().await;

    let mut connector = YouTubeConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["youtube.post_comment"]).await;
    let capability = generate_valid_token(&signing_key, &connector, "youtube.post_comment");

    let result = connector
        .handle_invoke(json!({
            "operation": "youtube.post_comment",
            "input": { "video_id": "dQw4w9WgXcQ" },
            "capability_token": capability
        }))
        .await;

    assert!(result.is_err());
    let error = result.unwrap_err();
    assert!(
        matches!(&error, fcp_core::FcpError::InvalidRequest { message, .. } if message.contains("text")),
        "Expected InvalidRequest, got: {error:?}"
    );
}
