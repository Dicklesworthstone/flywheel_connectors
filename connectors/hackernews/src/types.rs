//! Hacker News API types.

use serde::{Deserialize, Serialize};

/// A Hacker News item (story, comment, job, poll, or pollopt).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Item {
    /// The item's unique ID.
    pub id: u64,

    /// The type of item: "job", "story", "comment", "poll", or "pollopt".
    #[serde(rename = "type")]
    pub item_type: Option<String>,

    /// The username of the item's author.
    pub by: Option<String>,

    /// Creation date of the item, in Unix Time.
    pub time: Option<u64>,

    /// The comment, story, or poll text (HTML).
    pub text: Option<String>,

    /// `true` if the item is dead.
    #[serde(default)]
    pub dead: bool,

    /// The comment's parent item ID.
    pub parent: Option<u64>,

    /// The pollopt's associated poll ID.
    pub poll: Option<u64>,

    /// The IDs of the item's comments, in display order.
    #[serde(default)]
    pub kids: Vec<u64>,

    /// The URL of the story.
    pub url: Option<String>,

    /// The story's score.
    pub score: Option<i64>,

    /// The title of the story, poll, or job.
    pub title: Option<String>,

    /// A list of related pollopts, in display order.
    #[serde(default)]
    pub parts: Vec<u64>,

    /// The total comment count for stories and polls.
    pub descendants: Option<u64>,

    /// `true` if the item is deleted.
    #[serde(default)]
    pub deleted: bool,
}

/// A Hacker News user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    /// The user's unique username (case-sensitive).
    pub id: String,

    /// Creation date of the user, in Unix Time.
    pub created: u64,

    /// The user's karma.
    pub karma: i64,

    /// The user's optional self-description (HTML).
    pub about: Option<String>,

    /// List of the user's stories, polls, and comments.
    #[serde(default)]
    pub submitted: Vec<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn story_deserialization() {
        let json = serde_json::json!({
            "id": 8863,
            "type": "story",
            "by": "dhouston",
            "time": 1_175_714_200,
            "title": "My YC app: Dropbox - Throw away your USB drive",
            "url": "http://www.getdropbox.com/u/2/screencast.html",
            "score": 111,
            "descendants": 71,
            "kids": [8952, 9224, 8917]
        });
        let item: Item = serde_json::from_value(json).unwrap();
        assert_eq!(item.id, 8863);
        assert_eq!(item.item_type.as_deref(), Some("story"));
        assert_eq!(item.by.as_deref(), Some("dhouston"));
        assert_eq!(item.score, Some(111));
        assert_eq!(item.kids.len(), 3);
    }

    #[test]
    fn comment_deserialization() {
        let json = serde_json::json!({
            "id": 2_921_983,
            "type": "comment",
            "by": "norvig",
            "time": 1_314_211_127,
            "text": "<p>Aw shucks, thanks...</p>",
            "parent": 2_921_506,
            "kids": [2_922_097, 2_922_429]
        });
        let item: Item = serde_json::from_value(json).unwrap();
        assert_eq!(item.item_type.as_deref(), Some("comment"));
        assert_eq!(item.parent, Some(2_921_506));
        assert!(item.text.is_some());
    }

    #[test]
    fn job_deserialization() {
        let json = serde_json::json!({
            "id": 192_327,
            "type": "job",
            "by": "justin",
            "time": 1_210_981_217,
            "title": "Justin.tv is looking for a lead architect",
            "url": "http://www.justin.tv/jobs",
            "score": 6
        });
        let item: Item = serde_json::from_value(json).unwrap();
        assert_eq!(item.item_type.as_deref(), Some("job"));
        assert_eq!(
            item.title.as_deref(),
            Some("Justin.tv is looking for a lead architect")
        );
    }

    #[test]
    fn poll_deserialization() {
        let json = serde_json::json!({
            "id": 126_809,
            "type": "poll",
            "by": "pg",
            "time": 1_204_403_652,
            "title": "Poll: What would you work on?",
            "text": "",
            "score": 46,
            "descendants": 54,
            "kids": [126_822, 126_823],
            "parts": [126_810, 126_811]
        });
        let item: Item = serde_json::from_value(json).unwrap();
        assert_eq!(item.item_type.as_deref(), Some("poll"));
        assert_eq!(item.parts.len(), 2);
    }

    #[test]
    fn deleted_item_deserialization() {
        let json = serde_json::json!({
            "id": 99999,
            "deleted": true
        });
        let item: Item = serde_json::from_value(json).unwrap();
        assert!(item.deleted);
        assert!(item.item_type.is_none());
    }

    #[test]
    fn user_deserialization() {
        let json = serde_json::json!({
            "id": "jl",
            "created": 1_173_923_446,
            "karma": 2937,
            "about": "This is a test",
            "submitted": [8_265_435, 8_168_423, 8_090_946]
        });
        let user: User = serde_json::from_value(json).unwrap();
        assert_eq!(user.id, "jl");
        assert_eq!(user.karma, 2937);
        assert_eq!(user.submitted.len(), 3);
    }

    #[test]
    fn user_without_about() {
        let json = serde_json::json!({
            "id": "anon",
            "created": 1_234_567_890,
            "karma": 1
        });
        let user: User = serde_json::from_value(json).unwrap();
        assert!(user.about.is_none());
        assert!(user.submitted.is_empty());
    }

    #[test]
    fn dead_item() {
        let json = serde_json::json!({
            "id": 55555,
            "type": "comment",
            "dead": true,
            "by": "spammer",
            "time": 1_234_567_890,
            "text": "spam",
            "parent": 55554
        });
        let item: Item = serde_json::from_value(json).unwrap();
        assert!(item.dead);
    }

    #[test]
    fn item_serialization_roundtrip() {
        let item = Item {
            id: 12345,
            item_type: Some("story".into()),
            by: Some("user".into()),
            time: Some(1_234_567_890),
            text: None,
            dead: false,
            parent: None,
            poll: None,
            kids: vec![100, 200],
            url: Some("https://example.com".into()),
            score: Some(42),
            title: Some("Test".into()),
            parts: Vec::new(),
            descendants: Some(5),
            deleted: false,
        };
        let json = serde_json::to_value(&item).unwrap();
        let roundtrip: Item = serde_json::from_value(json).unwrap();
        assert_eq!(roundtrip.id, item.id);
        assert_eq!(roundtrip.score, item.score);
    }
}
