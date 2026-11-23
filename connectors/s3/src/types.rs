//! S3 API types.

use serde::{Deserialize, Serialize};

/// S3 object metadata returned from list and head operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectInfo {
    /// Object key
    pub key: String,
    /// Object size in bytes
    pub size: u64,
    /// Last modified timestamp (ISO 8601)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_modified: Option<String>,
    /// ETag (entity tag)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub etag: Option<String>,
    /// Storage class
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage_class: Option<String>,
}

/// S3 bucket info returned from list buckets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BucketInfo {
    /// Bucket name
    pub name: String,
    /// Creation date (ISO 8601)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub creation_date: Option<String>,
}

/// Response from put_object / copy_object operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PutObjectResponse {
    /// ETag of the uploaded/copied object
    pub etag: String,
}

/// Response from get_object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetObjectResponse {
    /// Object body as a string (base64-encoded for binary content)
    pub body: String,
    /// Content type of the object
    pub content_type: String,
    /// Explicit representation of `body`: `utf8` or `base64`.
    pub body_encoding: String,
}

/// Response from head_object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeadObjectResponse {
    /// Content type
    pub content_type: String,
    /// Content length in bytes
    pub content_length: u64,
    /// ETag
    #[serde(skip_serializing_if = "Option::is_none")]
    pub etag: Option<String>,
    /// Last modified timestamp
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_modified: Option<String>,
}

/// Response from list_objects.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListObjectsResponse {
    /// List of objects
    pub contents: Vec<ObjectInfo>,
    /// Whether results are truncated
    pub is_truncated: bool,
    /// Opaque continuation for the next individually authorized page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_continuation_token: Option<String>,
}

/// Response from list_buckets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListBucketsResponse {
    /// List of buckets
    pub buckets: Vec<BucketInfo>,
}

/// Response from create_bucket.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateBucketResponse {
    /// Bucket name
    pub bucket: String,
    /// Whether the bucket was created
    pub created: bool,
}

/// Response from delete_bucket.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteBucketResponse {
    /// Bucket name
    pub bucket: String,
    /// Whether the bucket was deleted
    pub deleted: bool,
}

/// Response from generate_presigned_url.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresignedUrlResponse {
    /// The presigned URL
    pub url: String,
}

/// S3 API error structure returned from the service.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorResponse {
    /// Error code (e.g., "NoSuchKey", "NoSuchBucket")
    #[serde(alias = "Code")]
    pub code: String,
    /// Error message
    #[serde(alias = "Message")]
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn object_info_skip_none() {
        let obj = ObjectInfo {
            key: "photos/cat.jpg".into(),
            size: 2048,
            last_modified: None,
            etag: None,
            storage_class: None,
        };
        let json_str = serde_json::to_string(&obj).unwrap();
        assert!(!json_str.contains("last_modified"));
        assert!(!json_str.contains("etag"));
        assert!(!json_str.contains("storage_class"));
    }

    #[test]
    fn object_info_full() {
        let obj = ObjectInfo {
            key: "data.csv".into(),
            size: 1_000_000,
            last_modified: Some("2026-03-01T00:00:00Z".into()),
            etag: Some("\"abc123\"".into()),
            storage_class: Some("STANDARD".into()),
        };
        let json_str = serde_json::to_string(&obj).unwrap();
        let back: ObjectInfo = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.size, 1_000_000);
        assert_eq!(back.storage_class.as_deref(), Some("STANDARD"));
    }

    #[test]
    fn bucket_info_serde() {
        let b = BucketInfo {
            name: "my-bucket".into(),
            creation_date: Some("2026-01-01T00:00:00Z".into()),
        };
        let json_str = serde_json::to_string(&b).unwrap();
        let back: BucketInfo = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.name, "my-bucket");
    }

    #[test]
    fn put_object_response_serde() {
        let resp = PutObjectResponse {
            etag: "\"def456\"".into(),
        };
        let json_str = serde_json::to_string(&resp).unwrap();
        let back: PutObjectResponse = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.etag, "\"def456\"");
    }

    #[test]
    fn get_object_response_serde() {
        let resp = GetObjectResponse {
            body: "{\"ok\":true}".into(),
            content_type: "application/json".into(),
            body_encoding: "utf8".into(),
        };
        let json_str = serde_json::to_string(&resp).unwrap();
        let back: GetObjectResponse = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.body, "{\"ok\":true}");
        assert_eq!(back.content_type, "application/json");
        assert_eq!(back.body_encoding, "utf8");
    }

    #[test]
    fn head_object_response_skip_none() {
        let resp = HeadObjectResponse {
            content_type: "text/plain".into(),
            content_length: 512,
            etag: None,
            last_modified: None,
        };
        let json_str = serde_json::to_string(&resp).unwrap();
        assert!(!json_str.contains("etag"));
        assert!(!json_str.contains("last_modified"));
    }

    #[test]
    fn list_objects_response_serde() {
        let resp = ListObjectsResponse {
            contents: vec![ObjectInfo {
                key: "file.txt".into(),
                size: 100,
                last_modified: None,
                etag: None,
                storage_class: None,
            }],
            is_truncated: false,
            next_continuation_token: None,
        };
        let json_str = serde_json::to_string(&resp).unwrap();
        let back: ListObjectsResponse = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.contents.len(), 1);
        assert!(!back.is_truncated);
    }

    #[test]
    fn list_buckets_response_serde() {
        let json = json!({"buckets": [{"name": "b1"}, {"name": "b2"}]});
        let resp: ListBucketsResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.buckets.len(), 2);
    }

    #[test]
    fn create_bucket_response_serde() {
        let resp = CreateBucketResponse {
            bucket: "new-bucket".into(),
            created: true,
        };
        let json_str = serde_json::to_string(&resp).unwrap();
        let back: CreateBucketResponse = serde_json::from_str(&json_str).unwrap();
        assert!(back.created);
    }

    #[test]
    fn delete_bucket_response_serde() {
        let resp = DeleteBucketResponse {
            bucket: "old-bucket".into(),
            deleted: true,
        };
        let json_str = serde_json::to_string(&resp).unwrap();
        let back: DeleteBucketResponse = serde_json::from_str(&json_str).unwrap();
        assert!(back.deleted);
    }

    #[test]
    fn presigned_url_response_serde() {
        let resp = PresignedUrlResponse {
            url: "https://s3.example.com/signed".into(),
        };
        let json_str = serde_json::to_string(&resp).unwrap();
        let back: PresignedUrlResponse = serde_json::from_str(&json_str).unwrap();
        assert!(back.url.starts_with("https://"));
    }

    #[test]
    fn api_error_lowercase() {
        let json = json!({"code": "NoSuchKey", "message": "Key not found"});
        let err: ApiErrorResponse = serde_json::from_value(json).unwrap();
        assert_eq!(err.code, "NoSuchKey");
    }

    #[test]
    fn api_error_uppercase_alias() {
        let json = json!({"Code": "NoSuchBucket", "Message": "Bucket not found"});
        let err: ApiErrorResponse = serde_json::from_value(json).unwrap();
        assert_eq!(err.code, "NoSuchBucket");
        assert_eq!(err.message, "Bucket not found");
    }

    // ---- ObjectInfo edge cases ----

    #[test]
    fn object_info_roundtrip_all_none() {
        let obj = ObjectInfo {
            key: String::new(),
            size: 0,
            last_modified: None,
            etag: None,
            storage_class: None,
        };
        let json_str = serde_json::to_string(&obj).unwrap();
        let back: ObjectInfo = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.key, "");
        assert_eq!(back.size, 0);
        assert!(back.last_modified.is_none());
        assert!(back.etag.is_none());
        assert!(back.storage_class.is_none());
    }

    #[test]
    fn object_info_from_json_missing_optional_fields() {
        let json = json!({"key": "test.txt", "size": 42});
        let obj: ObjectInfo = serde_json::from_value(json).unwrap();
        assert_eq!(obj.key, "test.txt");
        assert_eq!(obj.size, 42);
        assert!(obj.last_modified.is_none());
        assert!(obj.etag.is_none());
        assert!(obj.storage_class.is_none());
    }

    #[test]
    fn object_info_clone() {
        let obj = ObjectInfo {
            key: "clone-me.bin".into(),
            size: 999,
            last_modified: Some("2026-03-05T12:00:00Z".into()),
            etag: Some("\"etag1\"".into()),
            storage_class: Some("GLACIER".into()),
        };
        let cloned = obj.clone();
        assert_eq!(cloned.key, "clone-me.bin");
        assert_eq!(cloned.size, 999);
        assert_eq!(cloned.storage_class.as_deref(), Some("GLACIER"));
        assert_eq!(obj.key, "clone-me.bin");
    }

    #[test]
    fn object_info_debug() {
        let obj = ObjectInfo {
            key: "debug.txt".into(),
            size: 1,
            last_modified: None,
            etag: None,
            storage_class: None,
        };
        let dbg = format!("{obj:?}");
        assert!(dbg.contains("ObjectInfo"));
        assert!(dbg.contains("debug.txt"));
    }

    #[test]
    fn object_info_large_size() {
        let obj = ObjectInfo {
            key: "huge.bin".into(),
            size: u64::MAX,
            last_modified: None,
            etag: None,
            storage_class: None,
        };
        let json_str = serde_json::to_string(&obj).unwrap();
        let back: ObjectInfo = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.size, u64::MAX);
    }

    #[test]
    fn object_info_skip_serializing_partial() {
        let obj = ObjectInfo {
            key: "partial.txt".into(),
            size: 10,
            last_modified: Some("2026-01-01T00:00:00Z".into()),
            etag: None,
            storage_class: Some("STANDARD_IA".into()),
        };
        let json_str = serde_json::to_string(&obj).unwrap();
        assert!(json_str.contains("last_modified"));
        assert!(!json_str.contains("etag"));
        assert!(json_str.contains("storage_class"));
    }

    #[test]
    fn object_info_special_chars_in_key() {
        let obj = ObjectInfo {
            key: "path/to/my file (1).txt".into(),
            size: 100,
            last_modified: None,
            etag: None,
            storage_class: None,
        };
        let json_str = serde_json::to_string(&obj).unwrap();
        let back: ObjectInfo = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.key, "path/to/my file (1).txt");
    }

    // ---- BucketInfo edge cases ----

    #[test]
    fn bucket_info_skip_none_creation_date() {
        let b = BucketInfo {
            name: "no-date".into(),
            creation_date: None,
        };
        let json_str = serde_json::to_string(&b).unwrap();
        assert!(!json_str.contains("creation_date"));
    }

    #[test]
    fn bucket_info_from_json_no_creation_date() {
        let json = json!({"name": "minimal"});
        let b: BucketInfo = serde_json::from_value(json).unwrap();
        assert_eq!(b.name, "minimal");
        assert!(b.creation_date.is_none());
    }

    #[test]
    fn bucket_info_clone() {
        let b = BucketInfo {
            name: "cloned".into(),
            creation_date: Some("2026-01-01T00:00:00Z".into()),
        };
        let c = b.clone();
        assert_eq!(c.name, "cloned");
        assert_eq!(c.creation_date.as_deref(), Some("2026-01-01T00:00:00Z"));
        assert_eq!(b.name, "cloned");
    }

    #[test]
    fn bucket_info_debug() {
        let b = BucketInfo {
            name: "debug-bucket".into(),
            creation_date: None,
        };
        let dbg = format!("{b:?}");
        assert!(dbg.contains("BucketInfo"));
        assert!(dbg.contains("debug-bucket"));
    }

    // ---- PutObjectResponse edge cases ----

    #[test]
    fn put_object_response_empty_etag() {
        let resp = PutObjectResponse {
            etag: String::new(),
        };
        let json_str = serde_json::to_string(&resp).unwrap();
        let back: PutObjectResponse = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.etag, "");
    }

    #[test]
    fn put_object_response_clone() {
        let resp = PutObjectResponse {
            etag: "\"abc\"".into(),
        };
        let c = resp.clone();
        assert_eq!(c.etag, "\"abc\"");
        assert_eq!(resp.etag, "\"abc\"");
    }

    #[test]
    fn put_object_response_debug() {
        let resp = PutObjectResponse {
            etag: "\"etag\"".into(),
        };
        let dbg = format!("{resp:?}");
        assert!(dbg.contains("PutObjectResponse"));
    }

    // ---- GetObjectResponse edge cases ----

    #[test]
    fn get_object_response_empty_body() {
        let resp = GetObjectResponse {
            body: String::new(),
            content_type: "application/octet-stream".into(),
            body_encoding: "utf8".into(),
        };
        let json_str = serde_json::to_string(&resp).unwrap();
        let back: GetObjectResponse = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.body, "");
        assert_eq!(back.body_encoding, "utf8");
    }

    #[test]
    fn get_object_response_clone() {
        let resp = GetObjectResponse {
            body: "data".into(),
            content_type: "text/plain".into(),
            body_encoding: "utf8".into(),
        };
        let c = resp.clone();
        assert_eq!(c.body, "data");
        assert_eq!(c.content_type, "text/plain");
        assert_eq!(c.body_encoding, "utf8");
        assert_eq!(resp.body, "data");
    }

    #[test]
    fn get_object_response_debug() {
        let resp = GetObjectResponse {
            body: "x".into(),
            content_type: "text/html".into(),
            body_encoding: "utf8".into(),
        };
        let dbg = format!("{resp:?}");
        assert!(dbg.contains("GetObjectResponse"));
    }

    #[test]
    fn get_object_response_roundtrip_json() {
        let json = json!({
            "body": "AP+A",
            "content_type": "application/octet-stream",
            "body_encoding": "base64"
        });
        let resp: GetObjectResponse = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(resp.body_encoding, "base64");
        let bytes =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &resp.body).unwrap();
        assert_eq!(bytes, [0, 0xff, 0x80]);
        let re_json = serde_json::to_value(&resp).unwrap();
        assert_eq!(re_json, json);
    }

    // ---- HeadObjectResponse edge cases ----

    #[test]
    fn head_object_response_full_roundtrip() {
        let resp = HeadObjectResponse {
            content_type: "application/pdf".into(),
            content_length: 1_048_576,
            etag: Some("\"xyz789\"".into()),
            last_modified: Some("2026-03-05T15:30:00Z".into()),
        };
        let json_str = serde_json::to_string(&resp).unwrap();
        assert!(json_str.contains("etag"));
        assert!(json_str.contains("last_modified"));
        let back: HeadObjectResponse = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.content_length, 1_048_576);
        assert_eq!(back.etag.as_deref(), Some("\"xyz789\""));
    }

    #[test]
    fn head_object_response_from_json_missing_optionals() {
        let json = json!({"content_type": "text/plain", "content_length": 0});
        let resp: HeadObjectResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.content_type, "text/plain");
        assert_eq!(resp.content_length, 0);
        assert!(resp.etag.is_none());
        assert!(resp.last_modified.is_none());
    }

    #[test]
    fn head_object_response_clone() {
        let resp = HeadObjectResponse {
            content_type: "text/csv".into(),
            content_length: 42,
            etag: None,
            last_modified: None,
        };
        let c = resp.clone();
        assert_eq!(c.content_type, "text/csv");
        assert_eq!(c.content_length, 42);
        assert_eq!(resp.content_type, "text/csv");
    }

    #[test]
    fn head_object_response_debug() {
        let resp = HeadObjectResponse {
            content_type: "application/json".into(),
            content_length: 100,
            etag: Some("\"e\"".into()),
            last_modified: None,
        };
        let dbg = format!("{resp:?}");
        assert!(dbg.contains("HeadObjectResponse"));
    }

    // ---- ListObjectsResponse edge cases ----

    #[test]
    fn list_objects_response_empty_contents() {
        let resp = ListObjectsResponse {
            contents: vec![],
            is_truncated: false,
            next_continuation_token: None,
        };
        let json_str = serde_json::to_string(&resp).unwrap();
        assert!(!json_str.contains("next_continuation_token"));
        let back: ListObjectsResponse = serde_json::from_str(&json_str).unwrap();
        assert!(back.contents.is_empty());
        assert!(!back.is_truncated);
        assert!(back.next_continuation_token.is_none());
    }

    #[test]
    fn list_objects_response_truncated() {
        let resp = ListObjectsResponse {
            contents: vec![ObjectInfo {
                key: "a".into(),
                size: 1,
                last_modified: None,
                etag: None,
                storage_class: None,
            }],
            is_truncated: true,
            next_continuation_token: Some("opaque+/=%2F token".into()),
        };
        let json_str = serde_json::to_string(&resp).unwrap();
        let back: ListObjectsResponse = serde_json::from_str(&json_str).unwrap();
        assert!(back.is_truncated);
        assert_eq!(back.contents.len(), 1);
        assert_eq!(
            back.next_continuation_token.as_deref(),
            Some("opaque+/=%2F token")
        );
    }

    #[test]
    fn list_objects_response_from_json_value() {
        let json = json!({
            "contents": [
                {"key": "x", "size": 10},
                {"key": "y", "size": 20, "etag": "\"e\""}
            ],
            "is_truncated": true,
            "next_continuation_token": "next-page"
        });
        let resp: ListObjectsResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.contents.len(), 2);
        assert!(resp.is_truncated);
        assert_eq!(resp.next_continuation_token.as_deref(), Some("next-page"));
        assert!(resp.contents[0].etag.is_none());
        assert_eq!(resp.contents[1].etag.as_deref(), Some("\"e\""));
    }

    #[test]
    fn list_objects_response_clone() {
        let resp = ListObjectsResponse {
            contents: vec![],
            is_truncated: false,
            next_continuation_token: None,
        };
        let c = resp.clone();
        assert!(c.contents.is_empty());
        assert!(resp.contents.is_empty());
    }

    #[test]
    fn list_objects_response_debug() {
        let resp = ListObjectsResponse {
            contents: vec![],
            is_truncated: false,
            next_continuation_token: None,
        };
        let dbg = format!("{resp:?}");
        assert!(dbg.contains("ListObjectsResponse"));
    }

    // ---- ListBucketsResponse edge cases ----

    #[test]
    fn list_buckets_response_empty() {
        let json = json!({"buckets": []});
        let resp: ListBucketsResponse = serde_json::from_value(json).unwrap();
        assert!(resp.buckets.is_empty());
    }

    #[test]
    fn list_buckets_response_with_creation_dates() {
        let json = json!({
            "buckets": [
                {"name": "b1", "creation_date": "2026-01-01T00:00:00Z"},
                {"name": "b2"}
            ]
        });
        let resp: ListBucketsResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.buckets.len(), 2);
        assert!(resp.buckets[0].creation_date.is_some());
        assert!(resp.buckets[1].creation_date.is_none());
    }

    #[test]
    fn list_buckets_response_clone() {
        let resp = ListBucketsResponse { buckets: vec![] };
        let c = resp.clone();
        assert!(c.buckets.is_empty());
        assert!(resp.buckets.is_empty());
    }

    #[test]
    fn list_buckets_response_debug() {
        let resp = ListBucketsResponse { buckets: vec![] };
        let dbg = format!("{resp:?}");
        assert!(dbg.contains("ListBucketsResponse"));
    }

    // ---- CreateBucketResponse edge cases ----

    #[test]
    fn create_bucket_response_not_created() {
        let resp = CreateBucketResponse {
            bucket: "exists".into(),
            created: false,
        };
        let json_str = serde_json::to_string(&resp).unwrap();
        let back: CreateBucketResponse = serde_json::from_str(&json_str).unwrap();
        assert!(!back.created);
        assert_eq!(back.bucket, "exists");
    }

    #[test]
    fn create_bucket_response_clone() {
        let resp = CreateBucketResponse {
            bucket: "new".into(),
            created: true,
        };
        let c = resp.clone();
        assert_eq!(c.bucket, "new");
        assert!(c.created);
        assert_eq!(resp.bucket, "new");
    }

    #[test]
    fn create_bucket_response_debug() {
        let resp = CreateBucketResponse {
            bucket: "dbg".into(),
            created: true,
        };
        let dbg = format!("{resp:?}");
        assert!(dbg.contains("CreateBucketResponse"));
    }

    // ---- DeleteBucketResponse edge cases ----

    #[test]
    fn delete_bucket_response_not_deleted() {
        let resp = DeleteBucketResponse {
            bucket: "still-there".into(),
            deleted: false,
        };
        let json_str = serde_json::to_string(&resp).unwrap();
        let back: DeleteBucketResponse = serde_json::from_str(&json_str).unwrap();
        assert!(!back.deleted);
    }

    #[test]
    fn delete_bucket_response_clone() {
        let resp = DeleteBucketResponse {
            bucket: "gone".into(),
            deleted: true,
        };
        let c = resp.clone();
        assert_eq!(c.bucket, "gone");
        assert!(c.deleted);
        assert_eq!(resp.bucket, "gone");
    }

    #[test]
    fn delete_bucket_response_debug() {
        let resp = DeleteBucketResponse {
            bucket: "d".into(),
            deleted: true,
        };
        let dbg = format!("{resp:?}");
        assert!(dbg.contains("DeleteBucketResponse"));
    }

    // ---- PresignedUrlResponse edge cases ----

    #[test]
    fn presigned_url_response_empty_url() {
        let resp = PresignedUrlResponse { url: String::new() };
        let json_str = serde_json::to_string(&resp).unwrap();
        let back: PresignedUrlResponse = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.url, "");
    }

    #[test]
    fn presigned_url_response_clone() {
        let resp = PresignedUrlResponse {
            url: "https://example.com/signed".into(),
        };
        let c = resp.clone();
        assert_eq!(c.url, "https://example.com/signed");
        assert_eq!(resp.url, "https://example.com/signed");
    }

    #[test]
    fn presigned_url_response_debug() {
        let resp = PresignedUrlResponse {
            url: "https://s3.example.com".into(),
        };
        let dbg = format!("{resp:?}");
        assert!(dbg.contains("PresignedUrlResponse"));
    }

    // ---- ApiErrorResponse edge cases ----

    #[test]
    fn api_error_response_clone() {
        let err = ApiErrorResponse {
            code: "NoSuchKey".into(),
            message: "not found".into(),
        };
        let c = err.clone();
        assert_eq!(c.code, "NoSuchKey");
        assert_eq!(c.message, "not found");
        assert_eq!(err.code, "NoSuchKey");
    }

    #[test]
    fn api_error_response_debug() {
        let err = ApiErrorResponse {
            code: "X".into(),
            message: "Y".into(),
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("ApiErrorResponse"));
        assert!(dbg.contains('X'));
    }

    #[test]
    fn api_error_mixed_case() {
        // Test that both lowercase "code" and uppercase "Code" alias work
        let json_lower = json!({"code": "A", "message": "B"});
        let json_upper = json!({"Code": "A", "Message": "B"});
        let lower: ApiErrorResponse = serde_json::from_value(json_lower).unwrap();
        let upper: ApiErrorResponse = serde_json::from_value(json_upper).unwrap();
        assert_eq!(lower.code, upper.code);
        assert_eq!(lower.message, upper.message);
    }

    #[test]
    fn api_error_empty_strings() {
        let json = json!({"code": "", "message": ""});
        let err: ApiErrorResponse = serde_json::from_value(json).unwrap();
        assert_eq!(err.code, "");
        assert_eq!(err.message, "");
    }

    // ---- Deserialization failure tests ----

    #[test]
    fn object_info_missing_required_key_fails() {
        let json = json!({"size": 100});
        let result = serde_json::from_value::<ObjectInfo>(json);
        assert!(result.is_err());
    }

    #[test]
    fn object_info_missing_required_size_fails() {
        let json = json!({"key": "test"});
        let result = serde_json::from_value::<ObjectInfo>(json);
        assert!(result.is_err());
    }

    #[test]
    fn bucket_info_missing_name_fails() {
        let json = json!({"creation_date": "2026-01-01"});
        let result = serde_json::from_value::<BucketInfo>(json);
        assert!(result.is_err());
    }

    #[test]
    fn put_object_response_missing_etag_fails() {
        let json = json!({});
        let result = serde_json::from_value::<PutObjectResponse>(json);
        assert!(result.is_err());
    }

    #[test]
    fn get_object_response_missing_body_fails() {
        let json = json!({"content_type": "text/plain", "body_encoding": "utf8"});
        let result = serde_json::from_value::<GetObjectResponse>(json);
        assert!(result.is_err());
    }

    #[test]
    fn get_object_response_requires_explicit_encoding() {
        let json = json!({"body": "AP+A", "content_type": "application/octet-stream"});
        let result = serde_json::from_value::<GetObjectResponse>(json);
        assert!(result.is_err());
    }

    #[test]
    fn head_object_response_missing_content_type_fails() {
        let json = json!({"content_length": 100});
        let result = serde_json::from_value::<HeadObjectResponse>(json);
        assert!(result.is_err());
    }

    #[test]
    fn list_objects_response_missing_contents_fails() {
        let json = json!({"is_truncated": false});
        let result = serde_json::from_value::<ListObjectsResponse>(json);
        assert!(result.is_err());
    }

    #[test]
    fn create_bucket_response_missing_bucket_fails() {
        let json = json!({"created": true});
        let result = serde_json::from_value::<CreateBucketResponse>(json);
        assert!(result.is_err());
    }

    #[test]
    fn delete_bucket_response_missing_deleted_fails() {
        let json = json!({"bucket": "b"});
        let result = serde_json::from_value::<DeleteBucketResponse>(json);
        assert!(result.is_err());
    }

    #[test]
    fn presigned_url_response_missing_url_fails() {
        let json = json!({});
        let result = serde_json::from_value::<PresignedUrlResponse>(json);
        assert!(result.is_err());
    }

    #[test]
    fn api_error_response_missing_code_fails() {
        let json = json!({"message": "oops"});
        let result = serde_json::from_value::<ApiErrorResponse>(json);
        assert!(result.is_err());
    }

    #[test]
    fn api_error_response_missing_message_fails() {
        let json = json!({"code": "X"});
        let result = serde_json::from_value::<ApiErrorResponse>(json);
        assert!(result.is_err());
    }

    // ---- Serialize value structure ----

    #[test]
    fn object_info_serialized_value_structure() {
        let obj = ObjectInfo {
            key: "a.txt".into(),
            size: 50,
            last_modified: Some("t".into()),
            etag: Some("e".into()),
            storage_class: Some("s".into()),
        };
        let val = serde_json::to_value(&obj).unwrap();
        assert!(val.is_object());
        assert_eq!(val["key"], "a.txt");
        assert_eq!(val["size"], 50);
        assert_eq!(val["last_modified"], "t");
        assert_eq!(val["etag"], "e");
        assert_eq!(val["storage_class"], "s");
    }

    #[test]
    fn list_objects_response_serialized_value_structure() {
        let resp = ListObjectsResponse {
            contents: vec![
                ObjectInfo {
                    key: "a".into(),
                    size: 1,
                    last_modified: None,
                    etag: None,
                    storage_class: None,
                },
                ObjectInfo {
                    key: "b".into(),
                    size: 2,
                    last_modified: None,
                    etag: None,
                    storage_class: None,
                },
            ],
            is_truncated: true,
            next_continuation_token: Some("next-page".into()),
        };
        let val = serde_json::to_value(&resp).unwrap();
        assert!(val["contents"].is_array());
        assert_eq!(val["contents"].as_array().unwrap().len(), 2);
        assert_eq!(val["is_truncated"], true);
        assert_eq!(val["next_continuation_token"], "next-page");
    }

    // ---- Extra field handling (serde default: ignore unknown) ----

    #[test]
    fn object_info_ignores_extra_fields() {
        let json = json!({"key": "x", "size": 1, "extra_field": "ignored"});
        let obj: ObjectInfo = serde_json::from_value(json).unwrap();
        assert_eq!(obj.key, "x");
    }

    #[test]
    fn bucket_info_ignores_extra_fields() {
        let json = json!({"name": "b", "region": "us-east-1"});
        let b: BucketInfo = serde_json::from_value(json).unwrap();
        assert_eq!(b.name, "b");
    }

    // ── ObjectInfo additional ─────────────────────────────────────

    #[test]
    fn object_info_all_none_optionals() {
        let json = json!({"key": "test.txt", "size": 0});
        let obj: ObjectInfo = serde_json::from_value(json).unwrap();
        assert!(obj.last_modified.is_none());
        assert!(obj.etag.is_none());
        assert!(obj.storage_class.is_none());
    }

    #[test]
    fn object_info_zero_size() {
        let json = json!({"key": "empty", "size": 0});
        let obj: ObjectInfo = serde_json::from_value(json).unwrap();
        assert_eq!(obj.size, 0);
    }

    #[test]
    fn object_info_max_u64_size() {
        let json = json!({"key": "big", "size": u64::MAX});
        let obj: ObjectInfo = serde_json::from_value(json).unwrap();
        assert_eq!(obj.size, u64::MAX);
    }

    #[test]
    fn object_info_unicode_key() {
        let json = json!({"key": "日本語/ファイル.txt", "size": 100});
        let obj: ObjectInfo = serde_json::from_value(json).unwrap();
        assert!(obj.key.contains("日本語"));
    }

    // ── BucketInfo additional ─────────────────────────────────────

    #[test]
    fn bucket_info_with_creation_date_present() {
        let json = json!({"name": "my-bucket", "creation_date": "2026-01-01T00:00:00Z"});
        let b: BucketInfo = serde_json::from_value(json).unwrap();
        assert_eq!(b.creation_date.as_deref(), Some("2026-01-01T00:00:00Z"));
    }

    #[test]
    fn bucket_info_no_creation_date_field() {
        let json = json!({"name": "no-date"});
        let b: BucketInfo = serde_json::from_value(json).unwrap();
        assert!(b.creation_date.is_none());
    }

    // ── GetObjectResponse additional ──────────────────────────────

    #[test]
    fn get_object_response_body_and_content_type() {
        let json = json!({"body": "data", "content_type": "text/plain", "body_encoding": "utf8"});
        let resp: GetObjectResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.body, "data");
        assert_eq!(resp.content_type, "text/plain");
        assert_eq!(resp.body_encoding, "utf8");
    }

    // ── HeadObjectResponse additional ─────────────────────────────

    #[test]
    fn head_object_response_with_all_fields() {
        let json = json!({
            "content_type": "application/json",
            "content_length": 1024,
            "etag": "\"abc123\"",
            "last_modified": "2026-01-01"
        });
        let resp: HeadObjectResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.content_type, "application/json");
        assert_eq!(resp.content_length, 1024);
        assert_eq!(resp.etag.as_deref(), Some("\"abc123\""));
    }

    // ── CreateBucketResponse additional ───────────────────────────

    #[test]
    fn create_bucket_response_debug_format() {
        let resp = CreateBucketResponse {
            bucket: "new-bucket".into(),
            created: true,
        };
        let dbg = format!("{resp:?}");
        assert!(dbg.contains("CreateBucketResponse"));
        assert!(dbg.contains("new-bucket"));
    }

    // ── PutObjectResponse additional ──────────────────────────────

    #[test]
    fn put_object_response_etag_roundtrip() {
        let json = json!({"etag": "\"xyz\""});
        let resp: PutObjectResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.etag, "\"xyz\"");
    }

    #[test]
    fn put_object_response_zero_length_etag() {
        let json = json!({"etag": ""});
        let resp: PutObjectResponse = serde_json::from_value(json).unwrap();
        assert!(resp.etag.is_empty());
    }

    #[test]
    fn list_objects_response_with_truncated_flag() {
        let json = json!({
            "contents": [{"key": "a", "size": 1}],
            "is_truncated": true,
            "next_continuation_token": "next-page"
        });
        let resp: ListObjectsResponse = serde_json::from_value(json).unwrap();
        assert!(resp.is_truncated);
        assert_eq!(resp.contents.len(), 1);
        assert_eq!(resp.next_continuation_token.as_deref(), Some("next-page"));
    }

    #[test]
    fn list_objects_response_no_contents() {
        let json = json!({"contents": [], "is_truncated": false});
        let resp: ListObjectsResponse = serde_json::from_value(json).unwrap();
        assert!(resp.contents.is_empty());
        assert!(!resp.is_truncated);
        assert!(resp.next_continuation_token.is_none());
    }

    #[test]
    fn delete_bucket_response_false_deleted() {
        let resp = DeleteBucketResponse {
            bucket: "still-there".into(),
            deleted: false,
        };
        assert!(!resp.deleted);
    }

    #[test]
    fn create_bucket_response_false_created() {
        let resp = CreateBucketResponse {
            bucket: "existing".into(),
            created: false,
        };
        assert!(!resp.created);
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn object_info_clone_preserves_fields() {
        let obj = ObjectInfo {
            key: "test.txt".into(),
            size: 100,
            last_modified: Some("2026-01-01".into()),
            etag: Some("\"abc\"".into()),
            storage_class: Some("STANDARD".into()),
        };
        let cloned = obj.clone();
        assert_eq!(obj.key, cloned.key);
        assert_eq!(obj.size, cloned.size);
    }
}
