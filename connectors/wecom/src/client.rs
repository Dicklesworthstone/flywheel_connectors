#![allow(clippy::missing_errors_doc)]

//! HTTP client and token-cache runtime for the `WeCom` connector.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use aes::Aes256;
use aes::cipher::{BlockDecryptMut, KeyIvInit, block_padding::NoPadding};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use cbc::Decryptor;
use fcp_async_core::sync::Mutex;
use fcp_prelude::FcpError;
use quick_xml::{Reader, escape::unescape, events::Event};
use reqwest::{Url, header, multipart};
use serde_json::Value;
use sha1::{Digest as _, Sha1};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::error::{WeComError, WeComResult};
use crate::types::{
    AccessTokenResponse, TOKEN_REFRESH_SAFETY_MARGIN_SECS, WeComCallbackEnvelope,
    WeComCallbackIngestRequest, WeComCallbackVerifyRequest, WeComConfig,
    WeComDepartmentListRequest, WeComMediaDownload, WeComMediaDownloadRequest,
    WeComMediaUploadRequest, WeComMessageRequest, WeComStateModel, WeComUserLookupRequest,
};

type Aes256CbcDec = Decryptor<Aes256>;
const MAX_CALLBACK_BODY_BYTES: usize = 1024 * 1024;
const CALLBACK_RANDOM_PREFIX_BYTES: usize = 16;
const CALLBACK_LENGTH_PREFIX_BYTES: usize = 4;
const CALLBACK_PKCS7_BLOCK_SIZE: usize = 32;

#[derive(Clone)]
struct CachedAccessToken {
    token: String,
    expires_at: Instant,
}

impl std::fmt::Debug for CachedAccessToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedAccessToken")
            .field("token", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

#[derive(Clone)]
pub struct WeComClient {
    config: WeComConfig,
    client: reqwest::Client,
    token_cache: Arc<Mutex<Option<CachedAccessToken>>>,
}

impl std::fmt::Debug for WeComClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WeComClient")
            .field("config", &self.config)
            .field("token_cache", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
struct CallbackCrypto {
    token: String,
    aes_key: [u8; 32],
    receive_id: String,
}

impl std::fmt::Debug for CallbackCrypto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CallbackCrypto")
            .field("token", &"[REDACTED]")
            .field("aes_key", &"[REDACTED]")
            .field("receive_id", &self.receive_id)
            .finish()
    }
}

impl WeComClient {
    pub fn new(config: WeComConfig) -> WeComResult<Self> {
        config.validate().map_err(map_config_error)?;
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(config.request_timeout_ms()))
            .build()?;
        Ok(Self {
            config,
            client,
            token_cache: Arc::new(Mutex::new(None)),
        })
    }

    #[must_use]
    pub const fn config(&self) -> &WeComConfig {
        &self.config
    }

    pub async fn state_model(&self) -> WeComStateModel {
        let token_cached = {
            let cache = self.token_cache.lock().await;
            cache
                .as_ref()
                .is_some_and(|cached| Instant::now() < cached.expires_at)
        };
        self.config.state_model(token_cached)
    }

    pub async fn access_token(&self) -> WeComResult<String> {
        {
            let cache = self.token_cache.lock().await;
            if let Some(cached) = cache.as_ref()
                && Instant::now() < cached.expires_at
            {
                return Ok(cached.token.clone());
            }
        }

        let mut url = self.url("/cgi-bin/gettoken")?;
        url.query_pairs_mut()
            .append_pair("corpid", self.config.corp_id())
            .append_pair("corpsecret", self.config.agent_secret());

        let response = self.client.get(url).send().await?;
        let body = ensure_wecom_success(response.json().await?)?;
        let token: AccessTokenResponse = serde_json::from_value(body).map_err(|error| {
            WeComError::Token(format!("failed to parse access token payload: {error}"))
        })?;
        if token.access_token.trim().is_empty() {
            return Err(WeComError::Token(
                "WeCom access token response omitted access_token".into(),
            ));
        }
        let ttl = token
            .expires_in
            .saturating_sub(TOKEN_REFRESH_SAFETY_MARGIN_SECS)
            .max(1);
        *self.token_cache.lock().await = Some(CachedAccessToken {
            token: token.access_token.clone(),
            expires_at: Instant::now() + Duration::from_secs(ttl),
        });
        Ok(token.access_token)
    }

    pub async fn send_message(&self, request: &WeComMessageRequest) -> WeComResult<Value> {
        self.post_json(
            "/cgi-bin/message/send",
            request.to_body(self.config.agent_id()),
        )
        .await
    }

    pub async fn upload_media(&self, request: &WeComMediaUploadRequest) -> WeComResult<Value> {
        let credential = self.access_token().await?;
        let bytes = request.decode_content().map_err(WeComError::InvalidInput)?;
        let mut url = self.url("/cgi-bin/media/upload")?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("access_token", &credential);
            query.append_pair("type", request.media_type());
        }
        let part = multipart::Part::bytes(bytes)
            .file_name(request.file_name().to_string())
            .mime_str(request.mime_type())
            .map_err(|error| WeComError::InvalidInput(format!("invalid mime_type: {error}")))?;
        let response = self
            .client
            .post(url)
            .multipart(multipart::Form::new().part("media", part))
            .send()
            .await?;
        ensure_wecom_success(response.json().await?)
    }

    pub async fn get_user(&self, request: &WeComUserLookupRequest) -> WeComResult<Value> {
        self.get_json(
            "/cgi-bin/user/get",
            &[("userid", request.userid().to_string())],
        )
        .await
    }

    pub async fn list_departments(
        &self,
        request: &WeComDepartmentListRequest,
    ) -> WeComResult<Value> {
        let mut params = Vec::new();
        if let Some(id) = request.id() {
            params.push(("id", id.to_string()));
        }
        self.get_json("/cgi-bin/department/list", &params).await
    }

    async fn get_json(&self, path: &str, params: &[(&str, String)]) -> WeComResult<Value> {
        let credential = self.access_token().await?;
        let mut url = self.url(path)?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("access_token", &credential);
            for (key, value) in params {
                query.append_pair(key, value);
            }
        }
        let response = self.client.get(url).send().await?;
        ensure_wecom_success(response.json().await?)
    }

    const MAX_MEDIA_BYTES: u64 = 50 * 1024 * 1024; // 50 MiB

    pub async fn download_media(
        &self,
        request: &WeComMediaDownloadRequest,
    ) -> WeComResult<WeComMediaDownload> {
        let credential = self.access_token().await?;
        let mut url = self.url("/cgi-bin/media/get")?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("access_token", &credential);
            query.append_pair("media_id", request.media_id());
        }

        let response = self.client.get(url).send().await?;
        let status = response.status();
        let headers = response.headers().clone();
        let max_bytes = Self::MAX_MEDIA_BYTES;
        if let Some(cl) = response.content_length() {
            if cl > max_bytes {
                return Err(WeComError::InvalidInput(format!(
                    "media download too large: {cl} bytes exceeds {max_bytes} byte limit"
                )));
            }
        }
        let bytes = response.bytes().await?;
        let downloaded_len = u64::try_from(bytes.len()).map_err(|_| {
            WeComError::InvalidInput(format!(
                "media download too large: {} bytes exceeds {max_bytes} byte limit",
                bytes.len()
            ))
        })?;
        if downloaded_len > max_bytes {
            return Err(WeComError::InvalidInput(format!(
                "media download too large: {} bytes exceeds {max_bytes} byte limit",
                bytes.len()
            )));
        }

        if let Some(provider_result) = parse_provider_json_response(&bytes) {
            return match provider_result {
                Ok(_) => Err(WeComError::InvalidInput(
                    "WeCom media download returned a JSON payload instead of media bytes".into(),
                )),
                Err(error) => Err(error),
            };
        }

        if !status.is_success() {
            return Err(WeComError::Api {
                errcode: i64::from(status.as_u16()),
                errmsg: format!("media download failed with HTTP status {status}"),
            });
        }

        let mime_type = header_value(&headers, header::CONTENT_TYPE);
        let file_name = content_disposition_filename(&headers);
        let sha256 = hex::encode(Sha256::digest(&bytes));

        Ok(WeComMediaDownload {
            media_id: request.media_id().to_string(),
            file_name,
            mime_type,
            content_length: bytes.len(),
            content_base64: BASE64.encode(&bytes),
            sha256,
        })
    }

    pub fn verify_callback_url(&self, request: &WeComCallbackVerifyRequest) -> WeComResult<String> {
        self.verify_callback_signature(
            request.msg_signature(),
            request.timestamp(),
            request.nonce(),
            request.echostr(),
        )?;
        self.decrypt_callback_message(request.echostr())
    }

    pub fn ingest_callback_event(
        &self,
        request: &WeComCallbackIngestRequest,
    ) -> WeComResult<WeComCallbackEnvelope> {
        if request.body().len() > MAX_CALLBACK_BODY_BYTES {
            return Err(WeComError::InvalidInput(format!(
                "callback body exceeds maximum size of {MAX_CALLBACK_BODY_BYTES} bytes"
            )));
        }

        let wrapper = parse_xml_fields(request.body())?;
        let encrypt = wrapper
            .get("Encrypt")
            .map(String::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                WeComError::InvalidInput("callback body must contain an Encrypt field".into())
            })?;

        self.verify_callback_signature(
            request.msg_signature(),
            request.timestamp(),
            request.nonce(),
            encrypt,
        )?;
        let plaintext_xml = self.decrypt_callback_message(encrypt)?;
        let message = parse_xml_fields(&plaintext_xml)?;

        Ok(WeComCallbackEnvelope {
            receive_id: self.config.callback_receive_id().to_string(),
            wrapper,
            message,
            plaintext_xml,
        })
    }

    async fn post_json(&self, path: &str, body: Value) -> WeComResult<Value> {
        let credential = self.access_token().await?;
        let mut url = self.url(path)?;
        url.query_pairs_mut()
            .append_pair("access_token", &credential);
        let response = self.client.post(url).json(&body).send().await?;
        ensure_wecom_success(response.json().await?)
    }

    fn url(&self, path: &str) -> WeComResult<Url> {
        let mut url = Url::parse(self.config.base_url())
            .map_err(|error| WeComError::Config(format!("stored base_url is invalid: {error}")))?;
        url.set_path(path);
        Ok(url)
    }

    fn callback_crypto(&self) -> WeComResult<CallbackCrypto> {
        let signature_material = self
            .config
            .callback_token()
            .ok_or_else(|| {
                WeComError::Config(
                    "callback_token and callback_encoding_aes_key must be configured for callback verification".into(),
                )
            })?
            .to_string();
        let aes_key = self.config.callback_aes_key().map_err(WeComError::Config)?;

        Ok(CallbackCrypto {
            token: signature_material,
            aes_key,
            receive_id: self.config.callback_receive_id().to_string(),
        })
    }

    fn verify_callback_signature(
        &self,
        msg_signature: &str,
        timestamp: &str,
        nonce: &str,
        encrypted: &str,
    ) -> WeComResult<()> {
        let crypto = self.callback_crypto()?;
        let mut parts = vec![crypto.token.as_str(), timestamp, nonce, encrypted];
        parts.sort_unstable();
        let mut material = String::new();
        for part in parts {
            material.push_str(part);
        }
        let expected = hex::encode(Sha1::digest(material.as_bytes()));
        if bool::from(expected.as_bytes().ct_eq(msg_signature.trim().as_bytes())) {
            Ok(())
        } else {
            Err(WeComError::Unauthorized(
                "WeCom callback signature verification failed".into(),
            ))
        }
    }

    fn decrypt_callback_message(&self, encrypted: &str) -> WeComResult<String> {
        let crypto = self.callback_crypto()?;
        let ciphertext = BASE64.decode(encrypted.trim()).map_err(|error| {
            WeComError::InvalidInput(format!(
                "encrypted callback payload is not valid base64: {error}"
            ))
        })?;

        let iv = crypto
            .aes_key
            .get(..CALLBACK_RANDOM_PREFIX_BYTES)
            .ok_or_else(|| WeComError::Config("invalid callback AES key length".into()))?;
        let decryptor = Aes256CbcDec::new_from_slices(&crypto.aes_key, iv)
            .map_err(|_| WeComError::Config("invalid callback AES key length".into()))?;
        let mut buffer = ciphertext;
        let decrypted = decryptor
            .decrypt_padded_mut::<NoPadding>(&mut buffer)
            .map_err(|_| callback_decrypt_failed())?;
        let plaintext = decode_wecom_callback_padding(decrypted)?;

        if plaintext.len() < CALLBACK_RANDOM_PREFIX_BYTES + CALLBACK_LENGTH_PREFIX_BYTES {
            return Err(WeComError::InvalidInput(
                "decrypted callback payload is too short".into(),
            ));
        }

        let length_start = CALLBACK_RANDOM_PREFIX_BYTES;
        let length_end = CALLBACK_RANDOM_PREFIX_BYTES + CALLBACK_LENGTH_PREFIX_BYTES;
        let length_bytes = plaintext
            .get(length_start..length_end)
            .ok_or_else(|| WeComError::InvalidInput("callback length prefix is invalid".into()))?;
        let message_length_u32 =
            u32::from_be_bytes(length_bytes.try_into().map_err(|_| {
                WeComError::InvalidInput("callback length prefix is invalid".into())
            })?);
        let message_length = usize::try_from(message_length_u32).map_err(|_| {
            WeComError::InvalidInput("callback length prefix cannot fit this platform".into())
        })?;
        let message_end = length_end.saturating_add(message_length);
        if message_end > plaintext.len() {
            return Err(WeComError::InvalidInput(
                "decrypted callback payload length prefix exceeds plaintext size".into(),
            ));
        }

        let message_bytes = plaintext.get(length_end..message_end).ok_or_else(|| {
            WeComError::InvalidInput(
                "decrypted callback payload length prefix exceeds plaintext size".into(),
            )
        })?;
        let receive_id_bytes = plaintext.get(message_end..).ok_or_else(|| {
            WeComError::InvalidInput(
                "decrypted callback payload length prefix exceeds plaintext size".into(),
            )
        })?;
        let message = std::str::from_utf8(message_bytes).map_err(|error| {
            WeComError::InvalidInput(format!("callback plaintext is not valid UTF-8: {error}"))
        })?;
        let receive_id = std::str::from_utf8(receive_id_bytes).map_err(|error| {
            WeComError::InvalidInput(format!("callback receive_id is not valid UTF-8: {error}"))
        })?;
        if !bool::from(receive_id.as_bytes().ct_eq(crypto.receive_id.as_bytes())) {
            return Err(WeComError::Unauthorized(format!(
                "callback receive_id mismatch: expected `{}`, got `{receive_id}`",
                crypto.receive_id
            )));
        }

        Ok(message.to_string())
    }
}

fn callback_decrypt_failed() -> WeComError {
    WeComError::Unauthorized(
        "WeCom callback payload could not be decrypted with the configured AES key".into(),
    )
}

fn decode_wecom_callback_padding(decrypted: &[u8]) -> WeComResult<&[u8]> {
    let Some(&pad) = decrypted.last() else {
        return Err(callback_decrypt_failed());
    };
    let pad_len = usize::from(pad);
    if pad_len == 0 || pad_len > CALLBACK_PKCS7_BLOCK_SIZE || pad_len > decrypted.len() {
        return Err(callback_decrypt_failed());
    }

    let plaintext_len = decrypted.len() - pad_len;
    let (plaintext, padding) = decrypted.split_at(plaintext_len);
    if padding.iter().any(|&byte| byte != pad) {
        return Err(callback_decrypt_failed());
    }

    Ok(plaintext)
}

fn ensure_wecom_success(body: Value) -> WeComResult<Value> {
    let errcode = body.get("errcode").and_then(Value::as_i64).unwrap_or(0);
    if errcode == 0 {
        Ok(body)
    } else {
        let errmsg = body
            .get("errmsg")
            .and_then(Value::as_str)
            .unwrap_or("unknown WeCom error")
            .to_string();
        Err(WeComError::Api { errcode, errmsg })
    }
}

fn map_config_error(error: FcpError) -> WeComError {
    match error {
        FcpError::InvalidRequest { message, .. } => WeComError::Config(message),
        other => WeComError::Config(other.to_string()),
    }
}

fn parse_provider_json_response(bytes: &[u8]) -> Option<WeComResult<Value>> {
    if bytes.is_empty() {
        return None;
    }

    match serde_json::from_slice::<Value>(bytes) {
        Ok(body) if body.get("errcode").is_some() => Some(ensure_wecom_success(body)),
        Ok(_) | Err(_) => None,
    }
}

fn header_value(headers: &header::HeaderMap, name: header::HeaderName) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn content_disposition_filename(headers: &header::HeaderMap) -> Option<String> {
    let value = headers
        .get(header::CONTENT_DISPOSITION)
        .and_then(|header| header.to_str().ok())?;

    for part in value.split(';').map(str::trim) {
        if let Some(name) = part.strip_prefix("filename=") {
            return Some(name.trim_matches('"').to_string());
        }
        if let Some(name) = part.strip_prefix("filename*=UTF-8''") {
            return Some(name.to_string());
        }
    }

    None
}

fn parse_xml_fields(xml: &str) -> WeComResult<BTreeMap<String, String>> {
    let mut reader = Reader::from_reader(xml.as_bytes());
    reader.config_mut().trim_text(false);

    let mut buffer = Vec::new();
    let mut fields: BTreeMap<String, String> = BTreeMap::new();
    let mut depth = 0usize;
    let mut current_field: Option<String> = None;
    let mut saw_root = false;

    loop {
        match reader.read_event_into(&mut buffer) {
            Ok(Event::Start(event)) => {
                let name = xml_name(event.name().as_ref())?;
                depth = depth.saturating_add(1);
                if depth == 1 {
                    if name != "xml" {
                        return Err(WeComError::InvalidInput(format!(
                            "expected XML root element `xml`, found `{name}`"
                        )));
                    }
                    saw_root = true;
                } else if depth == 2 {
                    current_field = Some(name);
                }
            }
            Ok(Event::Empty(event)) => {
                if depth == 1 {
                    let name = xml_name(event.name().as_ref())?;
                    fields.entry(name).or_default();
                }
            }
            Ok(Event::Text(event)) => {
                if depth == 2 {
                    let current = current_field.as_ref().ok_or_else(|| {
                        WeComError::InvalidInput(
                            "encountered XML text without an active field name".into(),
                        )
                    })?;
                    let raw = std::str::from_utf8(event.as_ref()).map_err(|error| {
                        WeComError::InvalidInput(format!(
                            "callback XML text is not valid UTF-8: {error}"
                        ))
                    })?;
                    let decoded = unescape(raw).map_err(|error| {
                        WeComError::InvalidInput(format!(
                            "callback XML text contains invalid escapes: {error}"
                        ))
                    })?;
                    fields
                        .entry(current.clone())
                        .or_default()
                        .push_str(decoded.as_ref());
                }
            }
            Ok(Event::CData(event)) => {
                if depth == 2 {
                    let current = current_field.as_ref().ok_or_else(|| {
                        WeComError::InvalidInput(
                            "encountered XML CDATA without an active field name".into(),
                        )
                    })?;
                    let value = std::str::from_utf8(event.as_ref()).map_err(|error| {
                        WeComError::InvalidInput(format!(
                            "callback XML CDATA is not valid UTF-8: {error}"
                        ))
                    })?;
                    fields.entry(current.clone()).or_default().push_str(value);
                }
            }
            Ok(Event::End(_event)) => {
                if depth == 2 {
                    current_field = None;
                }
                depth = depth.saturating_sub(1);
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(error) => {
                return Err(WeComError::InvalidInput(format!(
                    "failed to parse callback XML: {error}"
                )));
            }
        }

        buffer.clear();
    }

    if !saw_root {
        return Err(WeComError::InvalidInput(
            "callback payload is not a valid XML document".into(),
        ));
    }

    Ok(fields)
}

fn xml_name(name: &[u8]) -> WeComResult<String> {
    std::str::from_utf8(name)
        .map(ToString::to_string)
        .map_err(|error| {
            WeComError::InvalidInput(format!("callback XML tag name is not valid UTF-8: {error}"))
        })
}

#[cfg(test)]
mod tests {
    use aes::cipher::BlockEncryptMut;
    use cbc::Encryptor;
    use serde_json::json;

    use super::*;
    use crate::types::{
        DEFAULT_TIMEOUT_MS, WeComCallbackIngestRequest, WeComCallbackVerifyRequest,
    };

    type Aes256CbcEnc = Encryptor<Aes256>;

    fn sample_callback_key_bytes() -> [u8; 32] {
        [7_u8; 32]
    }

    fn sample_callback_key() -> String {
        BASE64
            .encode(sample_callback_key_bytes())
            .trim_end_matches('=')
            .to_string()
    }

    fn callback_config_json(base_url: &str) -> Value {
        json!({
            "base_url": base_url,
            "corp_id": "corp",
            "agent_id": 1_000_002_u64,
            "agent_secret": "secret",
            "request_timeout_ms": DEFAULT_TIMEOUT_MS,
            "callback_token": "token-123",
            "callback_encoding_aes_key": sample_callback_key(),
        })
    }

    fn encrypt_callback_message(message: &str, receive_id: &str) -> String {
        let key = sample_callback_key_bytes();
        let mut plaintext = Vec::new();
        plaintext.extend_from_slice(b"0123456789ABCDEF");
        let message_len = u32::try_from(message.len()).expect("test fixture should fit in u32");
        plaintext.extend_from_slice(&message_len.to_be_bytes());
        plaintext.extend_from_slice(message.as_bytes());
        plaintext.extend_from_slice(receive_id.as_bytes());

        let pad_len = CALLBACK_PKCS7_BLOCK_SIZE - (plaintext.len() % CALLBACK_PKCS7_BLOCK_SIZE);
        let pad_byte = u8::try_from(pad_len).expect("WeCom callback pad length fits in u8");
        plaintext.extend(std::iter::repeat_n(pad_byte, pad_len));
        let padded_len = plaintext.len();
        let iv = key
            .get(..CALLBACK_RANDOM_PREFIX_BYTES)
            .expect("test callback key must contain an IV prefix");
        let ciphertext = Aes256CbcEnc::new_from_slices(&key, iv)
            .expect("valid key and IV")
            .encrypt_padded_mut::<NoPadding>(&mut plaintext, padded_len)
            .expect("padding should succeed");

        BASE64.encode(ciphertext)
    }

    fn callback_signature(encrypted: &str, timestamp: &str, nonce: &str) -> String {
        let mut parts = vec!["token-123", timestamp, nonce, encrypted];
        parts.sort_unstable();
        let mut material = String::new();
        for part in parts {
            material.push_str(part);
        }
        hex::encode(Sha1::digest(material.as_bytes()))
    }

    #[test]
    fn wecom_callback_padding_accepts_sdk_32_byte_block() {
        let mut payload = b"payload".to_vec();
        payload.extend(std::iter::repeat_n(25_u8, 25));

        let unpadded = decode_wecom_callback_padding(&payload)
            .expect("WeCom SDK-style 32-byte padding should decode");

        assert_eq!(unpadded, b"payload");
    }

    #[test]
    fn wecom_callback_padding_rejects_values_larger_than_sdk_block() {
        let mut payload = b"payload".to_vec();
        payload.extend(std::iter::repeat_n(33_u8, 33));

        let error = decode_wecom_callback_padding(&payload)
            .expect_err("padding larger than WeCom's 32-byte block must fail");

        assert!(matches!(error, WeComError::Unauthorized(_)));
    }

    #[test]
    fn verify_callback_url_returns_plaintext_challenge() {
        let client = WeComClient::new(
            WeComConfig::from_value(callback_config_json("https://qyapi.weixin.qq.com"))
                .expect("config should parse"),
        )
        .expect("client should build");

        let echostr = encrypt_callback_message("verify-challenge", "corp");
        let request = WeComCallbackVerifyRequest::from_value(&json!({
            "msg_signature": callback_signature(&echostr, "1710000000", "nonce-1"),
            "timestamp": "1710000000",
            "nonce": "nonce-1",
            "echostr": echostr,
        }))
        .expect("request should parse");

        let challenge = client
            .verify_callback_url(&request)
            .expect("verify callback should succeed");

        assert_eq!(challenge, "verify-challenge");
    }

    #[test]
    fn ingest_callback_event_decrypts_and_parses_xml() {
        let client = WeComClient::new(
            WeComConfig::from_value(callback_config_json("https://qyapi.weixin.qq.com"))
                .expect("config should parse"),
        )
        .expect("client should build");

        let plaintext = r"<xml><ToUserName><![CDATA[corp]]></ToUserName><FromUserName><![CDATA[alice]]></FromUserName><CreateTime>1710000000</CreateTime><MsgType><![CDATA[text]]></MsgType><Content><![CDATA[hello world]]></Content><MsgId>42</MsgId></xml>";
        let encrypted = encrypt_callback_message(plaintext, "corp");
        let request = WeComCallbackIngestRequest::from_value(&json!({
            "msg_signature": callback_signature(&encrypted, "1710000001", "nonce-2"),
            "timestamp": "1710000001",
            "nonce": "nonce-2",
            "body": format!(
                "<xml><ToUserName><![CDATA[corp]]></ToUserName><AgentID><![CDATA[1000002]]></AgentID><Encrypt><![CDATA[{encrypted}]]></Encrypt></xml>"
            ),
        }))
        .expect("request should parse");

        let envelope = client
            .ingest_callback_event(&request)
            .expect("callback ingest should succeed");

        assert_eq!(
            envelope.wrapper.get("AgentID").map(String::as_str),
            Some("1000002")
        );
        assert_eq!(
            envelope.message.get("FromUserName").map(String::as_str),
            Some("alice")
        );
        assert_eq!(
            envelope.message.get("Content").map(String::as_str),
            Some("hello world")
        );
    }

    #[test]
    fn ingest_callback_event_rejects_bad_signature() {
        let client = WeComClient::new(
            WeComConfig::from_value(callback_config_json("https://qyapi.weixin.qq.com"))
                .expect("config should parse"),
        )
        .expect("client should build");

        let encrypted =
            encrypt_callback_message("<xml><MsgType><![CDATA[text]]></MsgType></xml>", "corp");
        let request = WeComCallbackIngestRequest::from_value(&json!({
            "msg_signature": "bad-signature",
            "timestamp": "1710000002",
            "nonce": "nonce-3",
            "body": format!("<xml><Encrypt><![CDATA[{encrypted}]]></Encrypt></xml>"),
        }))
        .expect("request should parse");

        let error = client
            .ingest_callback_event(&request)
            .expect_err("signature mismatch must fail");
        assert!(matches!(error, WeComError::Unauthorized(_)));
    }

    #[test]
    fn http_transport_error_never_leaks_corpsecret() {
        const SECRET: &str = "corpsecret-DEADBEEF-super-secret-value";
        // Bind then immediately drop a loopback socket so the port refuses
        // connections deterministically (no accept-loop thread, no flakiness).
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        let port = listener.local_addr().expect("listener local addr").port();
        drop(listener);

        let client = WeComClient::new(
            WeComConfig::from_value(json!({
                "base_url": format!("http://127.0.0.1:{port}"),
                "corp_id": "ww-corp-id",
                "agent_id": 1_000_002_u64,
                "agent_secret": SECRET,
                "request_timeout_ms": 500_u64,
            }))
            .expect("loopback config should parse"),
        )
        .expect("client should build");

        // `access_token` sends GET /cgi-bin/gettoken?corpid=..&corpsecret=<SECRET>.
        // The connect failure produces a `reqwest::Error` carrying that URL; the
        // query string (with the long-lived app secret) must never survive into
        // any surfaced message. The assertion is a negative, so it holds for any
        // transport error variant the environment yields.
        let outcome = fcp_async_core::runtime::block_on_sync(client.access_token())
            .expect("runtime should drive the future to completion");
        let error = outcome.expect_err("connection to a closed loopback port must fail");
        assert!(
            matches!(error, WeComError::Http(_)),
            "expected transport error, got {error:?}"
        );

        let display = error.to_string();
        assert!(
            !display.contains(SECRET) && !display.contains("corpsecret"),
            "Display leaked the corpsecret query: {display}"
        );

        match error.to_fcp_error() {
            FcpError::External { message, .. } => {
                assert!(
                    !message.contains(SECRET) && !message.contains("corpsecret"),
                    "FcpError message leaked the corpsecret query: {message}"
                );
            }
            other => panic!("expected External FcpError, got {other:?}"),
        }
    }
}
