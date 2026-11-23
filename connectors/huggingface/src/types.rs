//! Request and response types for the Hugging Face Inference API.

use serde::{Deserialize, Serialize};

// ── Text Generation (Inference API) ──

/// Request body for the HF Inference API text generation endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TextGenerationRequest {
    pub inputs: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters: Option<TextGenerationParameters>,
}

/// Optional parameters for text generation.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TextGenerationParameters {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_new_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_p: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_k: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repetition_penalty: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub do_sample: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub return_full_text: Option<bool>,
}

/// Single generation result from the Inference API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TextGenerationResponse {
    pub generated_text: String,
}

// ── Summarization ──

/// Request body for the HF Inference API summarization endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SummarizationRequest {
    pub inputs: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_summarization_parameters",
        deserialize_with = "deserialize_summarization_parameters"
    )]
    pub parameters: Option<SummarizationParameters>,
}

/// HF task inference separates generation controls from tokenizer settings.
/// Keep the connector's typed controls together while emitting that wire shape.
fn serialize_summarization_parameters<S: serde::Serializer>(
    parameters: &Option<SummarizationParameters>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    #[derive(Serialize)]
    struct Parameters<'a> {
        generate_parameters: &'a SummarizationParameters,
    }
    parameters
        .as_ref()
        .map(|parameters| Parameters {
            generate_parameters: parameters,
        })
        .serialize(serializer)
}

fn deserialize_summarization_parameters<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<SummarizationParameters>, D::Error> {
    #[derive(Deserialize)]
    struct Parameters {
        generate_parameters: SummarizationParameters,
    }
    Option::<Parameters>::deserialize(deserializer)
        .map(|parameters| parameters.map(|parameters| parameters.generate_parameters))
}

/// Optional parameters for summarization.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SummarizationParameters {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_length: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_length: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub do_sample: Option<bool>,
}

/// Single summarization result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SummarizationResponse {
    pub summary_text: String,
}

// ── Model Info (Hub API) ──

/// Model metadata from the Hugging Face Hub API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelInfo {
    #[serde(rename = "_id", default)]
    pub id_internal: String,
    #[serde(rename = "modelId", default)]
    pub model_id: String,
    #[serde(default)]
    pub sha: String,
    #[serde(default)]
    pub pipeline_tag: Option<String>,
    #[serde(default)]
    pub library_name: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub downloads: u64,
    #[serde(default)]
    pub likes: u64,
    #[serde(default)]
    pub private: bool,
    #[serde(default)]
    pub author: Option<String>,
    #[serde(rename = "lastModified", default)]
    pub last_modified: Option<String>,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default)]
    pub gated: Option<serde_json::Value>,
}

/// Query parameters for the Hugging Face Hub model catalog.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ModelListRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub search: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pipeline_tag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

// ── API error envelope ──

/// Error response from Hugging Face APIs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HfApiError {
    #[serde(default)]
    pub error: String,
    /// Present when the model is still loading (503 with `estimated_time`).
    #[serde(default)]
    pub estimated_time: Option<f64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_generation_request_serializes() {
        let req = TextGenerationRequest {
            inputs: "Hello, world!".into(),
            parameters: Some(TextGenerationParameters {
                max_new_tokens: Some(50),
                temperature: Some(0.7),
                ..Default::default()
            }),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["inputs"], "Hello, world!");
        assert_eq!(json["parameters"]["max_new_tokens"], 50);
        assert_eq!(json["parameters"]["temperature"], 0.7);
        assert!(json["parameters"].get("top_p").is_none());
    }

    #[test]
    fn text_generation_response_deserializes() {
        let json = r#"{"generated_text": "Hello, world! How are you?"}"#;
        let resp: TextGenerationResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.generated_text, "Hello, world! How are you?");
    }

    #[test]
    fn model_info_deserializes_minimal() {
        let json = r#"{"_id":"abc","modelId":"gpt2","sha":"deadbeef","downloads":1000,"likes":50}"#;
        let info: ModelInfo = serde_json::from_str(json).unwrap();
        assert_eq!(info.model_id, "gpt2");
        assert_eq!(info.downloads, 1000);
        assert_eq!(info.likes, 50);
    }

    #[test]
    fn model_info_deserializes_with_optional_fields() {
        let json = r#"{
            "_id": "abc",
            "modelId": "facebook/bart-large-cnn",
            "sha": "beef",
            "pipeline_tag": "summarization",
            "library_name": "transformers",
            "tags": ["summarization", "pytorch"],
            "downloads": 500,
            "likes": 10,
            "private": false,
            "author": "facebook",
            "lastModified": "2024-01-01T00:00:00Z",
            "disabled": false
        }"#;
        let info: ModelInfo = serde_json::from_str(json).unwrap();
        assert_eq!(info.pipeline_tag.as_deref(), Some("summarization"));
        assert_eq!(info.author.as_deref(), Some("facebook"));
        assert_eq!(info.tags.len(), 2);
    }

    #[test]
    fn model_list_request_serializes_filters() {
        let req = ModelListRequest {
            search: Some("bart".into()),
            pipeline_tag: Some("summarization".into()),
            limit: Some(5),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["search"], "bart");
        assert_eq!(json["pipeline_tag"], "summarization");
        assert_eq!(json["limit"], 5);
    }

    #[test]
    fn hf_api_error_deserializes_model_loading() {
        let json = r#"{"error": "Model is loading", "estimated_time": 20.5}"#;
        let err: HfApiError = serde_json::from_str(json).unwrap();
        assert_eq!(err.error, "Model is loading");
        assert!((err.estimated_time.unwrap() - 20.5).abs() < f64::EPSILON);
    }

    #[test]
    fn summarization_request_serializes() {
        let req = SummarizationRequest {
            inputs: "Long text to summarize...".into(),
            parameters: Some(SummarizationParameters {
                max_length: Some(100),
                min_length: Some(30),
                do_sample: Some(false),
            }),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["inputs"], "Long text to summarize...");
        assert_eq!(json["parameters"]["generate_parameters"]["max_length"], 100);
        assert_eq!(
            json["parameters"]["generate_parameters"]["do_sample"],
            false
        );
        assert!(json["parameters"].get("max_length").is_none());
        let decoded: SummarizationRequest = serde_json::from_value(json).unwrap();
        let parameters = decoded.parameters.unwrap();
        assert_eq!(parameters.min_length, Some(30));
        assert_eq!(parameters.do_sample, Some(false));
    }

    #[test]
    fn summarization_response_deserializes() {
        let json = r#"{"summary_text": "A brief summary."}"#;
        let resp: SummarizationResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.summary_text, "A brief summary.");
    }

    #[test]
    fn text_generation_request_no_params() {
        let req = TextGenerationRequest {
            inputs: "test".into(),
            parameters: None,
        };
        let json = serde_json::to_value(&req).unwrap();
        assert!(json.get("parameters").is_none());
    }
}
