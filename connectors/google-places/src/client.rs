//! `HTTP` client for the `Google Places API (New)`.

use fcp_prelude::log_redaction::redact_url;
use reqwest::header::{HeaderMap, HeaderValue};
use serde::de::DeserializeOwned;
use serde_json::json;
use tracing::debug;

use crate::error::{GooglePlacesError, GooglePlacesResult};
use crate::types::{
    AutocompleteInput, AutocompleteResponse, GetPlaceInput, GooglePlacesConfig, PlaceRecord,
    SearchTextInput, SearchTextResponse,
};

#[derive(Clone)]
pub struct GooglePlacesClient {
    client: reqwest::Client,
    base_url: String,
    api_key: String,
    search_text_field_mask: String,
    autocomplete_field_mask: String,
    place_details_field_mask: String,
}

impl std::fmt::Debug for GooglePlacesClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GooglePlacesClient")
            .field("base_url", &self.base_url)
            .field("api_key", &"[REDACTED]")
            .field("search_text_field_mask", &self.search_text_field_mask)
            .field("autocomplete_field_mask", &self.autocomplete_field_mask)
            .field("place_details_field_mask", &self.place_details_field_mask)
            .finish_non_exhaustive()
    }
}

impl GooglePlacesClient {
    pub fn from_config(config: &GooglePlacesConfig) -> GooglePlacesResult<Self> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(config.request_timeout_ms))
            .build()?;
        Ok(Self {
            client,
            base_url: config.normalized_base_url(),
            api_key: config.api_key.clone(),
            search_text_field_mask: config.search_text_field_mask.clone(),
            autocomplete_field_mask: config.autocomplete_field_mask.clone(),
            place_details_field_mask: config.place_details_field_mask.clone(),
        })
    }

    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    fn headers_with_mask(&self, field_mask: &str) -> GooglePlacesResult<HeaderMap> {
        let mut headers = HeaderMap::new();
        headers.insert(
            "X-Goog-Api-Key",
            HeaderValue::from_str(&self.api_key)
                .map_err(|error| GooglePlacesError::Config(error.to_string()))?,
        );
        headers.insert(
            "X-Goog-FieldMask",
            HeaderValue::from_str(field_mask)
                .map_err(|error| GooglePlacesError::Config(error.to_string()))?,
        );
        Ok(headers)
    }

    fn resolve_field_mask<'a>(
        override_mask: Option<&'a str>,
        default_mask: &'a str,
        field_name: &str,
    ) -> GooglePlacesResult<&'a str> {
        let mask = override_mask.unwrap_or(default_mask).trim();
        if mask.is_empty() {
            return Err(GooglePlacesError::Config(format!(
                "{field_name} must not be empty"
            )));
        }
        Ok(mask)
    }

    async fn decode_response<T: DeserializeOwned>(
        response: reqwest::Response,
    ) -> GooglePlacesResult<T> {
        let status = response.status();
        let body = response.text().await?;
        if !status.is_success() {
            return Err(GooglePlacesError::Api {
                status: status.as_u16(),
                message: body,
            });
        }
        Ok(serde_json::from_str(&body)?)
    }

    pub async fn search_text(
        &self,
        input: &SearchTextInput,
    ) -> GooglePlacesResult<SearchTextResponse> {
        let url = format!("{}/v1/places:searchText", self.base_url);
        let field_mask = Self::resolve_field_mask(
            input.field_mask.as_deref(),
            &self.search_text_field_mask,
            "search_text field mask",
        )?;
        let mut body = json!({ "textQuery": input.query.as_str() });
        if let Some(max_result_count) = input.max_result_count {
            body["maxResultCount"] = json!(max_result_count);
        }
        if let Some(open_now) = input.open_now {
            body["openNow"] = json!(open_now);
        }
        debug!(url = %redact_url(&url), query = %input.query, "Google Places text search");
        let response = self
            .client
            .post(url)
            .headers(self.headers_with_mask(field_mask)?)
            .json(&body)
            .send()
            .await?;
        Self::decode_response(response).await
    }

    pub async fn autocomplete(
        &self,
        input: &AutocompleteInput,
    ) -> GooglePlacesResult<AutocompleteResponse> {
        let url = format!("{}/v1/places:autocomplete", self.base_url);
        let field_mask = Self::resolve_field_mask(
            input.field_mask.as_deref(),
            &self.autocomplete_field_mask,
            "autocomplete field mask",
        )?;
        let mut body = json!({ "input": input.input.as_str() });
        if let Some(session_token) = &input.session_token {
            body["sessionToken"] = json!(session_token);
        }
        let response = self
            .client
            .post(url)
            .headers(self.headers_with_mask(field_mask)?)
            .json(&body)
            .send()
            .await?;
        Self::decode_response(response).await
    }

    pub async fn get_place(&self, input: &GetPlaceInput) -> GooglePlacesResult<PlaceRecord> {
        let field_mask = Self::resolve_field_mask(
            input.field_mask.as_deref(),
            &self.place_details_field_mask,
            "place_details field mask",
        )?;
        let place = input.place.trim_start_matches('/');
        validate_place_resource(place)?;
        let url = format!("{}/v1/{}", self.base_url, place);
        let mut request = self
            .client
            .get(url)
            .headers(self.headers_with_mask(field_mask)?);
        if let Some(language_code) = input.language_code.as_deref() {
            request = request.query(&[("languageCode", language_code)]);
        }
        let response = request.send().await?;
        Self::decode_response(response).await
    }
}

/// Validate a Places resource name before interpolating it into the request
/// path (`{base}/v1/{place}`).
///
/// A valid place resource is `places/{PLACE_ID}`, so the single structural `/`
/// is allowed, but a literal `?` or `#` would inject a query string or fragment
/// against the allowlisted Google host, and `..` / encoded slashes would
/// traverse to a sibling endpoint. Mirrors the resource-name guard used by the
/// google-chat / google-docs connectors.
fn validate_place_resource(place: &str) -> GooglePlacesResult<()> {
    let lower = place.to_ascii_lowercase();
    if place.is_empty()
        || place.contains("..")
        || place.contains('?')
        || place.contains('#')
        || place.contains('\\')
        || lower.contains("%2f")
        || lower.contains("%5c")
    {
        return Err(GooglePlacesError::Config(format!(
            "place resource name contains invalid characters: {place:?}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_place_resource_accepts_resource_name() {
        assert!(validate_place_resource("places/ChIJN1t_tDeuEmsRUsoyG83frY4").is_ok());
    }

    #[test]
    fn validate_place_resource_rejects_injection() {
        assert!(validate_place_resource("").is_err());
        assert!(validate_place_resource("places/abc?key=evil").is_err());
        assert!(validate_place_resource("places/abc#frag").is_err());
        assert!(validate_place_resource("places/../v1/other").is_err());
        assert!(validate_place_resource("places\\abc").is_err());
        assert!(validate_place_resource("places/abc%2f..").is_err());
    }
}
