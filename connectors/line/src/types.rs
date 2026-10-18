//! LINE Messaging API types.

use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ─────────────────────────────────────────────────────────────────────────────
// Message types
// ─────────────────────────────────────────────────────────────────────────────

/// A LINE message object.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Message {
    #[serde(rename = "text")]
    Text { text: String },
    #[serde(rename = "image")]
    Image {
        #[serde(rename = "originalContentUrl")]
        original_content_url: String,
        #[serde(rename = "previewImageUrl")]
        preview_image_url: String,
    },
    #[serde(rename = "sticker")]
    Sticker {
        #[serde(rename = "packageId")]
        package_id: String,
        #[serde(rename = "stickerId")]
        sticker_id: String,
    },
    #[serde(rename = "template")]
    Template {
        #[serde(rename = "altText")]
        alt_text: String,
        template: Template,
    },
    #[serde(rename = "flex")]
    Flex {
        #[serde(rename = "altText")]
        alt_text: String,
        contents: Value,
    },
}

/// LINE template payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Template {
    #[serde(rename = "confirm")]
    Confirm { text: String, actions: Vec<Action> },
    #[serde(rename = "buttons")]
    Buttons {
        #[serde(rename = "thumbnailImageUrl", skip_serializing_if = "Option::is_none")]
        thumbnail_image_url: Option<String>,
        #[serde(rename = "imageAspectRatio", skip_serializing_if = "Option::is_none")]
        image_aspect_ratio: Option<ImageAspectRatio>,
        #[serde(rename = "imageSize", skip_serializing_if = "Option::is_none")]
        image_size: Option<ImageSize>,
        #[serde(
            rename = "imageBackgroundColor",
            skip_serializing_if = "Option::is_none"
        )]
        image_background_color: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        title: Option<String>,
        text: String,
        #[serde(rename = "defaultAction", skip_serializing_if = "Option::is_none")]
        default_action: Option<Action>,
        actions: Vec<Action>,
    },
    #[serde(rename = "carousel")]
    Carousel {
        columns: Vec<CarouselColumn>,
        #[serde(rename = "imageAspectRatio", skip_serializing_if = "Option::is_none")]
        image_aspect_ratio: Option<ImageAspectRatio>,
        #[serde(rename = "imageSize", skip_serializing_if = "Option::is_none")]
        image_size: Option<ImageSize>,
    },
    #[serde(rename = "image_carousel")]
    ImageCarousel { columns: Vec<ImageCarouselColumn> },
}

/// Template action object.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Action {
    #[serde(rename = "message")]
    Message { label: String, text: String },
    #[serde(rename = "postback")]
    Postback {
        label: String,
        data: String,
        #[serde(rename = "displayText", skip_serializing_if = "Option::is_none")]
        display_text: Option<String>,
        #[serde(rename = "inputOption", skip_serializing_if = "Option::is_none")]
        input_option: Option<InputOption>,
        #[serde(rename = "fillInText", skip_serializing_if = "Option::is_none")]
        fill_in_text: Option<String>,
    },
    #[serde(rename = "uri")]
    Uri {
        label: String,
        uri: String,
        #[serde(rename = "altUri", skip_serializing_if = "Option::is_none")]
        alt_uri: Option<AltUri>,
    },
}

/// Desktop-specific URI action fallback.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AltUri {
    pub desktop: String,
}

/// Postback input display option.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InputOption {
    #[serde(rename = "closeRichMenu")]
    CloseRichMenu,
    #[serde(rename = "openRichMenu")]
    OpenRichMenu,
    #[serde(rename = "openKeyboard")]
    OpenKeyboard,
    #[serde(rename = "openVoice")]
    OpenVoice,
}

/// Template image aspect ratio.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImageAspectRatio {
    #[serde(rename = "rectangle")]
    Rectangle,
    #[serde(rename = "square")]
    Square,
}

/// Template image sizing mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImageSize {
    #[serde(rename = "cover")]
    Cover,
    #[serde(rename = "contain")]
    Contain,
}

/// Carousel template column.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CarouselColumn {
    #[serde(rename = "thumbnailImageUrl", skip_serializing_if = "Option::is_none")]
    pub thumbnail_image_url: Option<String>,
    #[serde(
        rename = "imageBackgroundColor",
        skip_serializing_if = "Option::is_none"
    )]
    pub image_background_color: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    pub text: String,
    #[serde(rename = "defaultAction", skip_serializing_if = "Option::is_none")]
    pub default_action: Option<Action>,
    pub actions: Vec<Action>,
}

/// Image carousel template column.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageCarouselColumn {
    #[serde(rename = "imageUrl")]
    pub image_url: String,
    pub action: Action,
}

/// Message validation error with the offending field path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageValidationError {
    pub field: String,
    pub message: String,
}

impl MessageValidationError {
    fn new(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for MessageValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.field, self.message)
    }
}

impl std::error::Error for MessageValidationError {}

pub const MAX_MESSAGES_PER_REQUEST: usize = 5;

const ALT_TEXT_MAX: usize = 1500;
const TEMPLATE_ACTION_LABEL_MAX: usize = 20;
const IMAGE_CAROUSEL_ACTION_LABEL_MAX: usize = 12;
const MESSAGE_ACTION_TEXT_MAX: usize = 300;
const POSTBACK_DATA_MAX: usize = 300;
const URI_MAX: usize = 1000;
const IMAGE_URL_MAX: usize = 2000;
const CONFIRM_TEXT_MAX: usize = 240;
const BUTTONS_TITLE_MAX: usize = 40;
const BUTTONS_TEXT_MAX_NO_IMAGE_OR_TITLE: usize = 160;
const BUTTONS_TEXT_MAX_WITH_IMAGE_OR_TITLE: usize = 60;
const BUTTONS_ACTIONS_MAX: usize = 4;
const CAROUSEL_COLUMNS_MAX: usize = 10;
const CAROUSEL_TITLE_MAX: usize = 40;
const CAROUSEL_TEXT_MAX_NO_IMAGE_OR_TITLE: usize = 120;
const CAROUSEL_TEXT_MAX_WITH_IMAGE_OR_TITLE: usize = 60;
const CAROUSEL_ACTIONS_MAX: usize = 3;
const FLEX_CAROUSEL_BUBBLES_MAX: usize = 12;

/// Validate a LINE message batch before sending it to the Messaging API.
pub fn validate_messages(messages: &[Message]) -> Result<(), MessageValidationError> {
    validate_count(
        "messages",
        messages.len(),
        1,
        MAX_MESSAGES_PER_REQUEST,
        "message objects",
    )?;

    for (index, message) in messages.iter().enumerate() {
        message.validate(&format!("messages[{index}]"))?;
    }

    Ok(())
}

impl Message {
    /// Validate this message object against the LINE Messaging API shape.
    pub fn validate(&self, field: &str) -> Result<(), MessageValidationError> {
        match self {
            Self::Text { text } => validate_non_empty(field_path(field, "text"), text),
            Self::Image {
                original_content_url,
                preview_image_url,
            } => {
                validate_https_url(
                    &field_path(field, "originalContentUrl"),
                    original_content_url,
                    IMAGE_URL_MAX,
                )?;
                validate_https_url(
                    &field_path(field, "previewImageUrl"),
                    preview_image_url,
                    IMAGE_URL_MAX,
                )
            }
            Self::Sticker {
                package_id,
                sticker_id,
            } => {
                validate_non_empty(field_path(field, "packageId"), package_id)?;
                validate_non_empty(field_path(field, "stickerId"), sticker_id)
            }
            Self::Template { alt_text, template } => {
                validate_length(field_path(field, "altText"), alt_text, 1, ALT_TEXT_MAX)?;
                template.validate(&field_path(field, "template"))
            }
            Self::Flex { alt_text, contents } => {
                validate_length(field_path(field, "altText"), alt_text, 1, ALT_TEXT_MAX)?;
                validate_flex_contents(&field_path(field, "contents"), contents)
            }
        }
    }
}

impl Template {
    fn validate(&self, field: &str) -> Result<(), MessageValidationError> {
        match self {
            Self::Confirm { text, actions } => {
                validate_length(field_path(field, "text"), text, 1, CONFIRM_TEXT_MAX)?;
                validate_count(field_path(field, "actions"), actions.len(), 2, 2, "actions")?;
                validate_actions(field, actions, TEMPLATE_ACTION_LABEL_MAX)
            }
            Self::Buttons {
                thumbnail_image_url,
                title,
                text,
                default_action,
                actions,
                ..
            } => {
                if let Some(url) = thumbnail_image_url {
                    validate_https_url(
                        &field_path(field, "thumbnailImageUrl"),
                        url,
                        IMAGE_URL_MAX,
                    )?;
                }
                if let Some(title) = title {
                    validate_length(field_path(field, "title"), title, 1, BUTTONS_TITLE_MAX)?;
                }
                let has_image_or_title = thumbnail_image_url.is_some() || title.is_some();
                let text_max = if has_image_or_title {
                    BUTTONS_TEXT_MAX_WITH_IMAGE_OR_TITLE
                } else {
                    BUTTONS_TEXT_MAX_NO_IMAGE_OR_TITLE
                };
                validate_length(field_path(field, "text"), text, 1, text_max)?;
                if let Some(action) = default_action {
                    action.validate(
                        &field_path(field, "defaultAction"),
                        TEMPLATE_ACTION_LABEL_MAX,
                    )?;
                }
                validate_count(
                    field_path(field, "actions"),
                    actions.len(),
                    1,
                    BUTTONS_ACTIONS_MAX,
                    "actions",
                )?;
                validate_actions(field, actions, TEMPLATE_ACTION_LABEL_MAX)
            }
            Self::Carousel { columns, .. } => {
                validate_count(
                    field_path(field, "columns"),
                    columns.len(),
                    1,
                    CAROUSEL_COLUMNS_MAX,
                    "columns",
                )?;
                let expected_shape = columns
                    .first()
                    .is_some_and(CarouselColumn::uses_image_or_title);
                let expected_action_count =
                    columns.first().map_or(0, |column| column.actions.len());
                for (index, column) in columns.iter().enumerate() {
                    let column_field = format!("{field}.columns[{index}]");
                    column.validate(&column_field)?;
                    if column.uses_image_or_title() != expected_shape {
                        return Err(MessageValidationError::new(
                            column_field,
                            "all carousel columns must consistently use image/title or omit both",
                        ));
                    }
                    if column.actions.len() != expected_action_count {
                        return Err(MessageValidationError::new(
                            field_path(&column_field, "actions"),
                            "all carousel columns must have the same number of actions",
                        ));
                    }
                }
                Ok(())
            }
            Self::ImageCarousel { columns } => {
                validate_count(
                    field_path(field, "columns"),
                    columns.len(),
                    1,
                    CAROUSEL_COLUMNS_MAX,
                    "columns",
                )?;
                for (index, column) in columns.iter().enumerate() {
                    column.validate(&format!("{field}.columns[{index}]"))?;
                }
                Ok(())
            }
        }
    }
}

impl Action {
    fn validate(&self, field: &str, label_max: usize) -> Result<(), MessageValidationError> {
        match self {
            Self::Message { label, text } => {
                validate_length(field_path(field, "label"), label, 1, label_max)?;
                validate_length(field_path(field, "text"), text, 1, MESSAGE_ACTION_TEXT_MAX)
            }
            Self::Postback {
                label,
                data,
                display_text,
                fill_in_text,
                ..
            } => {
                validate_length(field_path(field, "label"), label, 1, label_max)?;
                validate_length(field_path(field, "data"), data, 1, POSTBACK_DATA_MAX)?;
                if let Some(display_text) = display_text {
                    validate_length(
                        field_path(field, "displayText"),
                        display_text,
                        1,
                        POSTBACK_DATA_MAX,
                    )?;
                }
                if let Some(fill_in_text) = fill_in_text {
                    validate_length(
                        field_path(field, "fillInText"),
                        fill_in_text,
                        1,
                        POSTBACK_DATA_MAX,
                    )?;
                }
                Ok(())
            }
            Self::Uri {
                label,
                uri,
                alt_uri,
            } => {
                validate_length(field_path(field, "label"), label, 1, label_max)?;
                validate_uri(&field_path(field, "uri"), uri)?;
                if let Some(alt_uri) = alt_uri {
                    validate_uri(&field_path(field, "altUri.desktop"), &alt_uri.desktop)?;
                }
                Ok(())
            }
        }
    }
}

impl CarouselColumn {
    const fn uses_image_or_title(&self) -> bool {
        self.thumbnail_image_url.is_some() || self.title.is_some()
    }

    fn validate(&self, field: &str) -> Result<(), MessageValidationError> {
        if let Some(url) = &self.thumbnail_image_url {
            validate_https_url(&field_path(field, "thumbnailImageUrl"), url, IMAGE_URL_MAX)?;
        }
        if let Some(title) = &self.title {
            validate_length(field_path(field, "title"), title, 1, CAROUSEL_TITLE_MAX)?;
        }
        let text_max = if self.uses_image_or_title() {
            CAROUSEL_TEXT_MAX_WITH_IMAGE_OR_TITLE
        } else {
            CAROUSEL_TEXT_MAX_NO_IMAGE_OR_TITLE
        };
        validate_length(field_path(field, "text"), &self.text, 1, text_max)?;
        if let Some(action) = &self.default_action {
            action.validate(
                &field_path(field, "defaultAction"),
                TEMPLATE_ACTION_LABEL_MAX,
            )?;
        }
        validate_count(
            field_path(field, "actions"),
            self.actions.len(),
            1,
            CAROUSEL_ACTIONS_MAX,
            "actions",
        )?;
        validate_actions(field, &self.actions, TEMPLATE_ACTION_LABEL_MAX)
    }
}

impl ImageCarouselColumn {
    fn validate(&self, field: &str) -> Result<(), MessageValidationError> {
        validate_https_url(
            &field_path(field, "imageUrl"),
            &self.image_url,
            IMAGE_URL_MAX,
        )?;
        self.action.validate(
            &field_path(field, "action"),
            IMAGE_CAROUSEL_ACTION_LABEL_MAX,
        )
    }
}

fn validate_actions(
    field: &str,
    actions: &[Action],
    label_max: usize,
) -> Result<(), MessageValidationError> {
    for (index, action) in actions.iter().enumerate() {
        action.validate(&format!("{field}.actions[{index}]"), label_max)?;
    }
    Ok(())
}

fn validate_flex_contents(field: &str, contents: &Value) -> Result<(), MessageValidationError> {
    let object = contents.as_object().ok_or_else(|| {
        MessageValidationError::new(field, "Flex contents must be a non-empty object")
    })?;
    if object.is_empty() {
        return Err(MessageValidationError::new(
            field,
            "Flex contents must be a non-empty object",
        ));
    }
    let Some(container_type) = object.get("type").and_then(Value::as_str) else {
        return Err(MessageValidationError::new(
            field_path(field, "type"),
            "Flex contents must include a string type",
        ));
    };
    match container_type {
        "bubble" => Ok(()),
        "carousel" => {
            let contents = object
                .get("contents")
                .and_then(Value::as_array)
                .ok_or_else(|| {
                    MessageValidationError::new(
                        field_path(field, "contents"),
                        "Flex carousel must include contents array",
                    )
                })?;
            validate_count(
                field_path(field, "contents"),
                contents.len(),
                1,
                FLEX_CAROUSEL_BUBBLES_MAX,
                "bubbles",
            )
        }
        other => Err(MessageValidationError::new(
            field_path(field, "type"),
            format!("unsupported Flex container type `{other}`"),
        )),
    }
}

fn validate_non_empty(field: impl Into<String>, value: &str) -> Result<(), MessageValidationError> {
    validate_length(field, value, 1, usize::MAX)
}

fn validate_length(
    field: impl Into<String>,
    value: &str,
    min: usize,
    max: usize,
) -> Result<(), MessageValidationError> {
    let field = field.into();
    let len = value.chars().count();
    if len < min {
        return Err(MessageValidationError::new(
            field,
            format!("must contain at least {min} character(s)"),
        ));
    }
    if len > max {
        return Err(MessageValidationError::new(
            field,
            format!("must contain at most {max} character(s); got {len}"),
        ));
    }
    Ok(())
}

fn validate_count(
    field: impl Into<String>,
    count: usize,
    min: usize,
    max: usize,
    label: &str,
) -> Result<(), MessageValidationError> {
    let field = field.into();
    if count < min {
        return Err(MessageValidationError::new(
            field,
            format!("must contain at least {min} {label}; got {count}"),
        ));
    }
    if count > max {
        return Err(MessageValidationError::new(
            field,
            format!("must contain at most {max} {label}; got {count}"),
        ));
    }
    Ok(())
}

fn validate_https_url(field: &str, value: &str, max: usize) -> Result<(), MessageValidationError> {
    validate_length(field, value, 1, max)?;
    if !value.starts_with("https://") {
        return Err(MessageValidationError::new(
            field,
            "must use an https:// URL",
        ));
    }
    Ok(())
}

fn validate_uri(field: &str, value: &str) -> Result<(), MessageValidationError> {
    validate_length(field, value, 1, URI_MAX)?;
    let scheme = value
        .split_once(':')
        .map(|(scheme, _)| scheme.to_ascii_lowercase())
        .ok_or_else(|| MessageValidationError::new(field, "must include a URI scheme"))?;
    if matches!(scheme.as_str(), "http" | "https" | "line" | "tel") {
        Ok(())
    } else {
        Err(MessageValidationError::new(
            field,
            "scheme must be one of http, https, line, or tel",
        ))
    }
}

fn field_path(parent: &str, child: &str) -> String {
    format!("{parent}.{child}")
}

/// Push message request body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushMessageRequest {
    pub to: String,
    pub messages: Vec<Message>,
}

/// Reply message request body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplyMessageRequest {
    #[serde(rename = "replyToken")]
    pub reply_token: String,
    pub messages: Vec<Message>,
}

/// Multicast message request body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MulticastRequest {
    pub to: Vec<String>,
    pub messages: Vec<Message>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Response types
// ─────────────────────────────────────────────────────────────────────────────

/// Sent message response (LINE returns an empty 200 for most messaging ops).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SentMessageResponse {
    #[serde(rename = "sentMessages", default)]
    pub sent_messages: Vec<SentMessageRef>,
}

/// Reference to a sent message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SentMessageRef {
    pub id: String,
    #[serde(rename = "quoteToken", skip_serializing_if = "Option::is_none")]
    pub quote_token: Option<String>,
}

/// User profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserProfile {
    #[serde(rename = "displayName")]
    pub display_name: String,
    #[serde(rename = "userId")]
    pub user_id: String,
    #[serde(rename = "pictureUrl", skip_serializing_if = "Option::is_none")]
    pub picture_url: Option<String>,
    #[serde(rename = "statusMessage", skip_serializing_if = "Option::is_none")]
    pub status_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
}

/// Group summary (profile).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupSummary {
    #[serde(rename = "groupId")]
    pub group_id: String,
    #[serde(rename = "groupName")]
    pub group_name: String,
    #[serde(rename = "pictureUrl", skip_serializing_if = "Option::is_none")]
    pub picture_url: Option<String>,
}

/// Group member list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMembersResponse {
    #[serde(rename = "memberIds")]
    pub member_ids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Rich Menu types
// ─────────────────────────────────────────────────────────────────────────────

/// Rich menu object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RichMenu {
    #[serde(rename = "richMenuId", skip_serializing_if = "Option::is_none")]
    pub rich_menu_id: Option<String>,
    pub size: RichMenuSize,
    pub selected: bool,
    pub name: String,
    #[serde(rename = "chatBarText")]
    pub chat_bar_text: String,
    pub areas: Vec<RichMenuArea>,
}

/// Rich menu size.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RichMenuSize {
    pub width: u32,
    pub height: u32,
}

/// Rich menu area.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RichMenuArea {
    pub bounds: RichMenuBounds,
    pub action: RichMenuAction,
}

/// Rich menu bounds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RichMenuBounds {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

/// Rich menu action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RichMenuAction {
    #[serde(rename = "type")]
    pub action_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

/// Rich menu list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RichMenuListResponse {
    pub richmenus: Vec<RichMenu>,
}

/// Rich menu create response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RichMenuCreateResponse {
    #[serde(rename = "richMenuId")]
    pub rich_menu_id: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// Error response
// ─────────────────────────────────────────────────────────────────────────────

/// LINE API error response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiErrorResponse {
    pub message: String,
    #[serde(default)]
    pub details: Vec<ApiErrorDetail>,
}

/// Individual error detail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiErrorDetail {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub property: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn message_action(label: &str, text: &str) -> Action {
        Action::Message {
            label: label.into(),
            text: text.into(),
        }
    }

    fn postback_action(label: &str, data: &str) -> Action {
        Action::Postback {
            label: label.into(),
            data: data.into(),
            display_text: Some(label.into()),
            input_option: None,
            fill_in_text: None,
        }
    }

    fn uri_action(label: &str, uri: &str) -> Action {
        Action::Uri {
            label: label.into(),
            uri: uri.into(),
            alt_uri: None,
        }
    }

    #[test]
    fn text_message_serialization() {
        let msg = Message::Text {
            text: "Hello!".into(),
        };
        let json = serde_json::to_value(&msg).unwrap();
        assert_eq!(json["type"], "text");
        assert_eq!(json["text"], "Hello!");
    }

    #[test]
    fn sticker_message_serialization() {
        let msg = Message::Sticker {
            package_id: "446".into(),
            sticker_id: "1988".into(),
        };
        let json = serde_json::to_value(&msg).unwrap();
        assert_eq!(json["type"], "sticker");
        assert_eq!(json["packageId"], "446");
    }

    #[test]
    fn push_request_serialization() {
        let req = PushMessageRequest {
            to: "U1234".into(),
            messages: vec![Message::Text { text: "hi".into() }],
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["to"], "U1234");
        assert_eq!(json["messages"][0]["type"], "text");
    }

    #[test]
    fn reply_request_serialization() {
        let req = ReplyMessageRequest {
            reply_token: "tok_abc".into(),
            messages: vec![Message::Text {
                text: "reply".into(),
            }],
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["replyToken"], "tok_abc");
    }

    #[test]
    fn multicast_request_serialization() {
        let req = MulticastRequest {
            to: vec!["U1".into(), "U2".into()],
            messages: vec![Message::Text {
                text: "broadcast".into(),
            }],
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["to"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn confirm_template_message_serialization() {
        let msg = Message::Template {
            alt_text: "Confirm booking".into(),
            template: Template::Confirm {
                text: "Book the room?".into(),
                actions: vec![
                    message_action("Yes", "book yes"),
                    postback_action("No", "book=no"),
                ],
            },
        };

        msg.validate("message").unwrap();
        let json = serde_json::to_value(&msg).unwrap();
        assert_eq!(
            json,
            json!({
                "type": "template",
                "altText": "Confirm booking",
                "template": {
                    "type": "confirm",
                    "text": "Book the room?",
                    "actions": [
                        { "type": "message", "label": "Yes", "text": "book yes" },
                        {
                            "type": "postback",
                            "label": "No",
                            "data": "book=no",
                            "displayText": "No"
                        }
                    ]
                }
            })
        );
        let round_trip: Message = serde_json::from_value(json).unwrap();
        round_trip.validate("message").unwrap();
    }

    #[test]
    fn buttons_template_message_serialization() {
        let msg = Message::Template {
            alt_text: "Choose a tool".into(),
            template: Template::Buttons {
                thumbnail_image_url: Some("https://example.com/tool.png".into()),
                image_aspect_ratio: Some(ImageAspectRatio::Rectangle),
                image_size: Some(ImageSize::Cover),
                image_background_color: Some("#FFFFFF".into()),
                title: Some("Tools".into()),
                text: "Pick one".into(),
                default_action: Some(uri_action("Open", "https://example.com")),
                actions: vec![
                    message_action("Build", "build"),
                    uri_action("Docs", "line://app/123"),
                ],
            },
        };

        msg.validate("message").unwrap();
        let json = serde_json::to_value(&msg).unwrap();
        assert_eq!(json["type"], "template");
        assert_eq!(json["template"]["type"], "buttons");
        assert_eq!(
            json["template"]["thumbnailImageUrl"],
            "https://example.com/tool.png"
        );
        assert_eq!(json["template"]["imageAspectRatio"], "rectangle");
        assert_eq!(json["template"]["imageSize"], "cover");
        assert_eq!(json["template"]["defaultAction"]["type"], "uri");
        assert_eq!(json["template"]["actions"].as_array().unwrap().len(), 2);
        let round_trip: Message = serde_json::from_value(json).unwrap();
        round_trip.validate("message").unwrap();
    }

    #[test]
    fn carousel_template_message_serialization() {
        let column = CarouselColumn {
            thumbnail_image_url: Some("https://example.com/card.png".into()),
            image_background_color: None,
            title: Some("Card".into()),
            text: "First card".into(),
            default_action: None,
            actions: vec![message_action("Select", "card 1")],
        };
        let msg = Message::Template {
            alt_text: "View carousel".into(),
            template: Template::Carousel {
                columns: vec![column.clone(), column],
                image_aspect_ratio: Some(ImageAspectRatio::Square),
                image_size: Some(ImageSize::Contain),
            },
        };

        msg.validate("message").unwrap();
        let json = serde_json::to_value(&msg).unwrap();
        assert_eq!(json["template"]["type"], "carousel");
        assert_eq!(json["template"]["columns"].as_array().unwrap().len(), 2);
        assert_eq!(json["template"]["imageAspectRatio"], "square");
        assert_eq!(json["template"]["imageSize"], "contain");
        let round_trip: Message = serde_json::from_value(json).unwrap();
        round_trip.validate("message").unwrap();
    }

    #[test]
    fn image_carousel_template_message_serialization() {
        let msg = Message::Template {
            alt_text: "View images".into(),
            template: Template::ImageCarousel {
                columns: vec![ImageCarouselColumn {
                    image_url: "https://example.com/image.png".into(),
                    action: uri_action("Open", "tel:+15555550100"),
                }],
            },
        };

        msg.validate("message").unwrap();
        let json = serde_json::to_value(&msg).unwrap();
        assert_eq!(json["template"]["type"], "image_carousel");
        assert_eq!(
            json["template"]["columns"][0]["imageUrl"],
            "https://example.com/image.png"
        );
        let round_trip: Message = serde_json::from_value(json).unwrap();
        round_trip.validate("message").unwrap();
    }

    #[test]
    fn flex_message_serialization_and_validation() {
        let msg = Message::Flex {
            alt_text: "Status card".into(),
            contents: json!({
                "type": "bubble",
                "body": {
                    "type": "box",
                    "layout": "vertical",
                    "contents": [
                        { "type": "text", "text": "Ready" }
                    ]
                }
            }),
        };

        msg.validate("message").unwrap();
        let json = serde_json::to_value(&msg).unwrap();
        assert_eq!(json["type"], "flex");
        assert_eq!(json["altText"], "Status card");
        assert_eq!(json["contents"]["type"], "bubble");
        let round_trip: Message = serde_json::from_value(json).unwrap();
        round_trip.validate("message").unwrap();
    }

    #[test]
    fn message_batch_allows_five_mixed_messages() {
        let messages = vec![
            Message::Text { text: "one".into() },
            Message::Sticker {
                package_id: "446".into(),
                sticker_id: "1988".into(),
            },
            Message::Template {
                alt_text: "Confirm".into(),
                template: Template::Confirm {
                    text: "Proceed?".into(),
                    actions: vec![message_action("Yes", "yes"), message_action("No", "no")],
                },
            },
            Message::Flex {
                alt_text: "Card".into(),
                contents: json!({ "type": "bubble" }),
            },
            Message::Image {
                original_content_url: "https://example.com/full.jpg".into(),
                preview_image_url: "https://example.com/preview.jpg".into(),
            },
        ];

        validate_messages(&messages).unwrap();
        let json = serde_json::to_value(&messages).unwrap();
        assert_eq!(json.as_array().unwrap().len(), MAX_MESSAGES_PER_REQUEST);
    }

    #[test]
    fn message_batch_rejects_more_than_five_messages() {
        let messages = vec![Message::Text { text: "x".into() }; MAX_MESSAGES_PER_REQUEST + 1];
        let err = validate_messages(&messages).unwrap_err();
        assert_eq!(err.field, "messages");
        assert!(err.message.contains("at most 5"));
    }

    #[test]
    fn alt_text_uses_current_line_limit() {
        let ok = Message::Flex {
            alt_text: "a".repeat(ALT_TEXT_MAX),
            contents: json!({ "type": "bubble" }),
        };
        ok.validate("message").unwrap();

        let too_long = Message::Flex {
            alt_text: "a".repeat(ALT_TEXT_MAX + 1),
            contents: json!({ "type": "bubble" }),
        };
        let err = too_long.validate("message").unwrap_err();
        assert_eq!(err.field, "message.altText");
        assert!(err.message.contains("at most 1500"));
    }

    #[test]
    fn buttons_template_text_limit_switches_on_image_or_title() {
        let no_image = Message::Template {
            alt_text: "No image".into(),
            template: Template::Buttons {
                thumbnail_image_url: None,
                image_aspect_ratio: None,
                image_size: None,
                image_background_color: None,
                title: None,
                text: "a".repeat(BUTTONS_TEXT_MAX_NO_IMAGE_OR_TITLE),
                default_action: None,
                actions: vec![message_action("A", "a")],
            },
        };
        no_image.validate("message").unwrap();

        let with_title = Message::Template {
            alt_text: "With title".into(),
            template: Template::Buttons {
                thumbnail_image_url: None,
                image_aspect_ratio: None,
                image_size: None,
                image_background_color: None,
                title: Some("Title".into()),
                text: "a".repeat(BUTTONS_TEXT_MAX_WITH_IMAGE_OR_TITLE + 1),
                default_action: None,
                actions: vec![message_action("A", "a")],
            },
        };
        let err = with_title.validate("message").unwrap_err();
        assert_eq!(err.field, "message.template.text");
        assert!(err.message.contains("at most 60"));
    }

    #[test]
    fn carousel_column_count_rejects_zero_and_eleven() {
        let empty = Message::Template {
            alt_text: "Empty".into(),
            template: Template::Carousel {
                columns: vec![],
                image_aspect_ratio: None,
                image_size: None,
            },
        };
        assert!(
            empty
                .validate("message")
                .unwrap_err()
                .message
                .contains("at least 1")
        );

        let column = CarouselColumn {
            thumbnail_image_url: None,
            image_background_color: None,
            title: None,
            text: "column".into(),
            default_action: None,
            actions: vec![message_action("A", "a")],
        };
        let too_many = Message::Template {
            alt_text: "Too many".into(),
            template: Template::Carousel {
                columns: vec![column; CAROUSEL_COLUMNS_MAX + 1],
                image_aspect_ratio: None,
                image_size: None,
            },
        };
        assert!(
            too_many
                .validate("message")
                .unwrap_err()
                .message
                .contains("at most 10")
        );
    }

    #[test]
    fn image_carousel_column_count_rejects_zero_and_eleven() {
        let empty = Message::Template {
            alt_text: "Empty".into(),
            template: Template::ImageCarousel { columns: vec![] },
        };
        assert!(
            empty
                .validate("message")
                .unwrap_err()
                .message
                .contains("at least 1")
        );

        let column = ImageCarouselColumn {
            image_url: "https://example.com/image.png".into(),
            action: uri_action("Open", "https://example.com"),
        };
        let too_many = Message::Template {
            alt_text: "Too many".into(),
            template: Template::ImageCarousel {
                columns: vec![column; CAROUSEL_COLUMNS_MAX + 1],
            },
        };
        assert!(
            too_many
                .validate("message")
                .unwrap_err()
                .message
                .contains("at most 10")
        );
    }

    #[test]
    fn actions_enforce_lengths_and_current_uri_schemes() {
        assert!(
            message_action("a", &"x".repeat(MESSAGE_ACTION_TEXT_MAX))
                .validate("action", 20)
                .is_ok()
        );
        assert!(
            postback_action("a", &"x".repeat(POSTBACK_DATA_MAX))
                .validate("action", 20)
                .is_ok()
        );
        assert!(
            uri_action("Web", "http://example.com")
                .validate("action", 20)
                .is_ok()
        );
        assert!(
            uri_action("Line", "line://app/123")
                .validate("action", 20)
                .is_ok()
        );
        assert!(
            uri_action("Call", "tel:+15555550100")
                .validate("action", 20)
                .is_ok()
        );

        let err = uri_action("Bad", "ftp://example.com")
            .validate("action", 20)
            .unwrap_err();
        assert_eq!(err.field, "action.uri");
    }

    #[test]
    fn flex_contents_requires_root_type() {
        let missing_type = Message::Flex {
            alt_text: "Broken".into(),
            contents: json!({ "body": {} }),
        };
        let err = missing_type.validate("message").unwrap_err();
        assert_eq!(err.field, "message.contents.type");

        let carousel = Message::Flex {
            alt_text: "Carousel".into(),
            contents: json!({
                "type": "carousel",
                "contents": [{ "type": "bubble" }]
            }),
        };
        carousel.validate("message").unwrap();
    }

    #[test]
    fn user_profile_deserialization() {
        let json = serde_json::json!({
            "displayName": "Test User",
            "userId": "U1234567890",
            "pictureUrl": "https://example.com/pic.jpg",
            "statusMessage": "Hello",
            "language": "en"
        });
        let profile: UserProfile = serde_json::from_value(json).unwrap();
        assert_eq!(profile.display_name, "Test User");
        assert_eq!(profile.user_id, "U1234567890");
    }

    #[test]
    fn group_summary_deserialization() {
        let json = serde_json::json!({
            "groupId": "C1234",
            "groupName": "Test Group",
            "pictureUrl": "https://example.com/group.jpg"
        });
        let summary: GroupSummary = serde_json::from_value(json).unwrap();
        assert_eq!(summary.group_id, "C1234");
    }

    #[test]
    fn group_members_deserialization() {
        let json = serde_json::json!({
            "memberIds": ["U1", "U2", "U3"],
            "next": "token123"
        });
        let members: GroupMembersResponse = serde_json::from_value(json).unwrap();
        assert_eq!(members.member_ids.len(), 3);
        assert_eq!(members.next, Some("token123".into()));
    }

    #[test]
    fn rich_menu_serialization() {
        let menu = RichMenu {
            rich_menu_id: None,
            size: RichMenuSize {
                width: 2500,
                height: 1686,
            },
            selected: false,
            name: "Test Menu".into(),
            chat_bar_text: "Tap here".into(),
            areas: vec![RichMenuArea {
                bounds: RichMenuBounds {
                    x: 0,
                    y: 0,
                    width: 2500,
                    height: 1686,
                },
                action: RichMenuAction {
                    action_type: "message".into(),
                    text: Some("hello".into()),
                    uri: None,
                    label: Some("Hello".into()),
                },
            }],
        };
        let json = serde_json::to_value(&menu).unwrap();
        assert_eq!(json["size"]["width"], 2500);
        assert_eq!(json["areas"][0]["action"]["type"], "message");
    }

    #[test]
    fn rich_menu_create_response_deserialization() {
        let json = serde_json::json!({ "richMenuId": "richmenu-abc123" });
        let resp: RichMenuCreateResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.rich_menu_id, "richmenu-abc123");
    }

    #[test]
    fn api_error_response_deserialization() {
        let json = serde_json::json!({
            "message": "Invalid reply token",
            "details": [{ "message": "token expired", "property": "replyToken" }]
        });
        let err: ApiErrorResponse = serde_json::from_value(json).unwrap();
        assert_eq!(err.message, "Invalid reply token");
        assert_eq!(err.details.len(), 1);
    }

    #[test]
    fn image_message_serialization() {
        let msg = Message::Image {
            original_content_url: "https://example.com/img.jpg".into(),
            preview_image_url: "https://example.com/thumb.jpg".into(),
        };
        let json = serde_json::to_value(&msg).unwrap();
        assert_eq!(json["type"], "image");
        assert!(json["originalContentUrl"].as_str().is_some());
    }

    #[test]
    fn sent_message_response_deserialization() {
        let json = serde_json::json!({
            "sentMessages": [{ "id": "msg123", "quoteToken": "qt_abc" }]
        });
        let resp: SentMessageResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.sent_messages.len(), 1);
        assert_eq!(resp.sent_messages[0].id, "msg123");
    }

    #[test]
    fn rich_menu_list_response_deserialization() {
        let json = serde_json::json!({
            "richmenus": [{
                "richMenuId": "rm1",
                "size": { "width": 2500, "height": 1686 },
                "selected": false,
                "name": "Menu 1",
                "chatBarText": "Open",
                "areas": []
            }]
        });
        let resp: RichMenuListResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.richmenus.len(), 1);
    }

    #[test]
    fn user_profile_minimal_deserialization() {
        let json = serde_json::json!({
            "displayName": "User",
            "userId": "U999"
        });
        let profile: UserProfile = serde_json::from_value(json).unwrap();
        assert!(profile.picture_url.is_none());
        assert!(profile.status_message.is_none());
    }
}
