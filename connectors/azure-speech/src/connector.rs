use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use fcp_async_core::time;
use fcp_manifest::{ConnectorManifest, ManifestApprovalMode};
use fcp_prelude::{
    ApprovalMode, BaseConnector, CapabilityGrant, CapabilityId, CapabilityToken,
    CapabilityVerifier, ConnectorId, EventCaps, FcpError, FcpResult, HandshakeRequest,
    HandshakeResponse, InstanceId, OperationId, OperationInfo, SessionId,
};
use quick_xml::Reader;
use quick_xml::events::Event;
use reqwest::header::{
    AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue, USER_AGENT,
};
use reqwest::{Client, RequestBuilder, Response, StatusCode, multipart};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use url::Url;

const CONNECTOR_ID: &str = "fcp.azure-speech";
const CONNECTOR_VERSION: &str = "0.1.0";
const AZURE_SPEECH_MANIFEST_TOML: &str = include_str!("../manifest.toml");
const DOC_STT_REST_OVERVIEW: &str =
    "https://learn.microsoft.com/en-us/azure/ai-services/speech-service/rest-speech-to-text";
const DOC_STT_TRANSCRIBE: &str = "https://learn.microsoft.com/en-us/rest/api/speechtotext/transcriptions/transcribe?view=rest-speechtotext-2025-10-15";
const DOC_STT_BATCH_SUBMIT: &str = "https://learn.microsoft.com/en-us/rest/api/speechtotext/transcriptions/submit?view=rest-speechtotext-2025-10-15";
const DOC_STT_2025_MIGRATION: &str =
    "https://learn.microsoft.com/en-us/azure/ai-services/speech-service/migrate-2025-10-15";
const DOC_CUSTOM_SPEECH_PROJECT: &str = "https://learn.microsoft.com/en-us/azure/ai-services/speech-service/how-to-custom-speech-create-project";
const DOC_CUSTOM_SPEECH_DATASET: &str = "https://learn.microsoft.com/en-us/azure/ai-services/speech-service/how-to-custom-speech-upload-data";
const DOC_CUSTOM_SPEECH_MODEL: &str = "https://learn.microsoft.com/en-us/azure/ai-services/speech-service/how-to-custom-speech-train-model";
const DOC_CUSTOM_SPEECH_ENDPOINT: &str = "https://learn.microsoft.com/en-us/azure/ai-services/speech-service/how-to-custom-speech-deploy-model";
const DOC_CUSTOM_PROJECTS_API: &str = "https://learn.microsoft.com/en-us/rest/api/speechtotext/projects?view=rest-speechtotext-2025-10-15";
const DOC_CUSTOM_DATASETS_API: &str = "https://learn.microsoft.com/en-us/rest/api/speechtotext/datasets?view=rest-speechtotext-2025-10-15";
const DOC_CUSTOM_MODELS_API: &str = "https://learn.microsoft.com/en-us/rest/api/speechtotext/models?view=rest-speechtotext-2025-10-15";
const DOC_CUSTOM_ENDPOINTS_API: &str = "https://learn.microsoft.com/en-us/rest/api/speechtotext/endpoints?view=rest-speechtotext-2025-10-15";
const DOC_TTS_REST_AUTH: &str = "https://learn.microsoft.com/en-us/azure/ai-services/speech-service/rest-text-to-speech#authentication";
const DOC_ENTRA_AUTH: &str = "https://learn.microsoft.com/en-us/azure/ai-services/speech-service/how-to-configure-azure-ad-auth";
const DOC_MANAGED_IDENTITY_VM_TOKEN: &str = "https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/how-to-use-vm-token";
const DOC_LLM_SPEECH_AUTH: &str =
    "https://learn.microsoft.com/en-us/azure/ai-services/speech-service/llm-speech";
const DOC_TTS_TEXT_STREAMING: &str = "https://learn.microsoft.com/en-us/azure/ai-services/speech-service/how-to-lower-speech-synthesis-latency#how-to-use-text-streaming";
const DOC_STT_REALTIME: &str =
    "https://learn.microsoft.com/en-us/azure/ai-services/speech-service/how-to-recognize-speech";
const DOC_SDK_CONNECTIONS: &str =
    "https://learn.microsoft.com/en-us/azure/ai-services/speech-service/how-to-control-connections";
const OP_VOICES_LIST: &str = "azure.speech.voices.list";
const OP_TTS_SYNTHESIZE: &str = "azure.speech.tts.synthesize";
const OP_STT_TRANSCRIBE_FAST: &str = "azure.speech.stt.transcribe_fast";
const OP_STT_BATCH_SUBMIT: &str = "azure.speech.stt.batch.submit";
const OP_STT_BATCH_GET: &str = "azure.speech.stt.batch.get";
const OP_STT_BATCH_FILES: &str = "azure.speech.stt.batch.files";
const OP_CUSTOM_PROJECTS_CREATE: &str = "azure.speech.stt.custom.projects.create";
const OP_CUSTOM_PROJECTS_LIST: &str = "azure.speech.stt.custom.projects.list";
const OP_CUSTOM_PROJECTS_GET: &str = "azure.speech.stt.custom.projects.get";
const OP_CUSTOM_PROJECTS_DELETE: &str = "azure.speech.stt.custom.projects.delete";
const OP_CUSTOM_DATASETS_CREATE: &str = "azure.speech.stt.custom.datasets.create";
const OP_CUSTOM_DATASETS_LIST: &str = "azure.speech.stt.custom.datasets.list";
const OP_CUSTOM_DATASETS_GET: &str = "azure.speech.stt.custom.datasets.get";
const OP_CUSTOM_DATASETS_DELETE: &str = "azure.speech.stt.custom.datasets.delete";
const OP_CUSTOM_MODELS_CREATE: &str = "azure.speech.stt.custom.models.create";
const OP_CUSTOM_MODELS_LIST: &str = "azure.speech.stt.custom.models.list";
const OP_CUSTOM_MODELS_GET: &str = "azure.speech.stt.custom.models.get";
const OP_CUSTOM_MODELS_DELETE: &str = "azure.speech.stt.custom.models.delete";
const OP_CUSTOM_ENDPOINTS_CREATE: &str = "azure.speech.stt.custom.endpoints.create";
const OP_CUSTOM_ENDPOINTS_LIST: &str = "azure.speech.stt.custom.endpoints.list";
const OP_CUSTOM_ENDPOINTS_GET: &str = "azure.speech.stt.custom.endpoints.get";
const OP_CUSTOM_ENDPOINTS_DELETE: &str = "azure.speech.stt.custom.endpoints.delete";
const OPERATION_ORDER: [&str; 22] = [
    "azure.speech.voices.list",
    "azure.speech.tts.synthesize",
    "azure.speech.stt.transcribe_fast",
    "azure.speech.stt.batch.submit",
    "azure.speech.stt.batch.get",
    "azure.speech.stt.batch.files",
    "azure.speech.stt.custom.projects.create",
    "azure.speech.stt.custom.projects.list",
    "azure.speech.stt.custom.projects.get",
    "azure.speech.stt.custom.projects.delete",
    "azure.speech.stt.custom.datasets.create",
    "azure.speech.stt.custom.datasets.list",
    "azure.speech.stt.custom.datasets.get",
    "azure.speech.stt.custom.datasets.delete",
    "azure.speech.stt.custom.models.create",
    "azure.speech.stt.custom.models.list",
    "azure.speech.stt.custom.models.get",
    "azure.speech.stt.custom.models.delete",
    "azure.speech.stt.custom.endpoints.create",
    "azure.speech.stt.custom.endpoints.list",
    "azure.speech.stt.custom.endpoints.get",
    "azure.speech.stt.custom.endpoints.delete",
];
const BOUNDARY: &str = "This connector exposes Azure Speech REST token exchange, Microsoft Entra bearer-token handoff, regional voice discovery, REST text-to-speech synthesis, Speech-to-text 2025-10-15 fast transcription, batch submit/status/files, and 2025-10-15 custom speech project/dataset/model/endpoint create/list/get/delete lifecycle surfaces. Realtime WebSocket streaming is blocked until Microsoft documents a direct STT/TTS wire protocol or FCP adopts an equivalent SDK-compatible framing. Connector-local IMDS/MSAL acquisition is formally retained as host-token-broker-only under flywheel_connectors-4kw5f.2.9.6.3 because FCP runtime network policy cannot safely mix link-local IMDS egress and Azure Speech provider egress inside the same runtime-enforced operation.";
const STREAMING_BLOCKER_REASON: &str = "Current Microsoft Learn documentation exposes TTS text streaming through Speech SDK TextStream on the WebSocket v2 endpoint, and realtime STT through Speech SDK SpeechRecognizer/AudioConfig push-stream APIs. It does not publish a direct WebSocket frame protocol for a standalone Rust connector, so this connector must not guess or reverse-engineer the live wire format.";
const DEFAULT_REQUEST_TIMEOUT_MS: usize = 60_000;
const DEFAULT_INLINE_AUDIO_MAX_BYTES: usize = 1_048_576;
const DEFAULT_TTS_MAX_AUDIO_BYTES: usize = 16 * 1_024 * 1_024;
const DEFAULT_STT_MAX_AUDIO_BYTES: usize = 250 * 1_024 * 1_024;
const ACCESS_TOKEN_TTL: Duration = Duration::from_secs(10 * 60);
const ACCESS_TOKEN_REFRESH_AFTER: Duration = Duration::from_secs(9 * 60);
const IMDS_TOKEN_ENDPOINT: &str = "http://169.254.169.254/metadata/identity/oauth2/token";
const IMDS_HOST: &str = "169.254.169.254";
const IMDS_API_VERSION: &str = "2018-02-01";
const COGNITIVE_SERVICES_ENTRA_RESOURCE: &str = "https://cognitiveservices.azure.com/";
const USER_AGENT_VALUE: &str = "fcp-azure-speech/0.1.0";
const STT_API_VERSION: &str = "2025-10-15";
const DEFAULT_TTS_OUTPUT_FORMAT: &str = "riff-24khz-16bit-mono-pcm";
const DEFAULT_STT_LOCALE: &str = "en-US";
const MAX_RETRIES: u64 = 2;
const RETRY_BASE_DELAY_MS: u64 = 100;

const TTS_OUTPUT_FORMATS: &[&str] = &[
    "amr-wb-16000hz",
    "audio-16khz-16bit-32kbps-mono-opus",
    "audio-16khz-32kbitrate-mono-mp3",
    "audio-16khz-64kbitrate-mono-mp3",
    "audio-16khz-128kbitrate-mono-mp3",
    "audio-24khz-16bit-24kbps-mono-opus",
    "audio-24khz-16bit-48kbps-mono-opus",
    "audio-24khz-48kbitrate-mono-mp3",
    "audio-24khz-96kbitrate-mono-mp3",
    "audio-24khz-160kbitrate-mono-mp3",
    "audio-48khz-96kbitrate-mono-mp3",
    "audio-48khz-192kbitrate-mono-mp3",
    "g722-16khz-64kbps",
    "ogg-16khz-16bit-mono-opus",
    "ogg-24khz-16bit-mono-opus",
    "ogg-48khz-16bit-mono-opus",
    "raw-8khz-8bit-mono-alaw",
    "raw-8khz-8bit-mono-mulaw",
    "raw-8khz-16bit-mono-pcm",
    "raw-16khz-16bit-mono-pcm",
    "raw-24khz-16bit-mono-pcm",
    "raw-48khz-16bit-mono-pcm",
    "riff-8khz-8bit-mono-alaw",
    "riff-8khz-8bit-mono-mulaw",
    "riff-8khz-16bit-mono-pcm",
    "riff-22050hz-16bit-mono-pcm",
    "riff-24khz-16bit-mono-pcm",
    "riff-44100hz-16bit-mono-pcm",
    "riff-48khz-16bit-mono-pcm",
];

const STT_CONTENT_TYPES: &[&str] = &[
    "audio/wav",
    "audio/wave",
    "audio/x-wav",
    "audio/mpeg",
    "audio/mp3",
    "audio/ogg",
    "audio/flac",
    "audio/webm",
    "audio/mp4",
];

#[derive(Clone)]
enum Auth {
    SubscriptionKey(HeaderValue),
    EntraAccessToken {
        authorization: HeaderValue,
        resource_id_hash: Option<String>,
        token_source: EntraTokenSource,
        token_format: EntraTokenFormat,
        expires_at: Option<Instant>,
    },
    CredentialId {
        id: HeaderValue,
        redacted_id: String,
    },
}

impl std::fmt::Debug for Auth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SubscriptionKey(_) => f
                .debug_tuple("SubscriptionKey")
                .field(&"[REDACTED]")
                .finish(),
            Self::EntraAccessToken {
                resource_id_hash,
                token_source,
                token_format,
                expires_at,
                ..
            } => f
                .debug_struct("EntraAccessToken")
                .field("authorization", &"[REDACTED]")
                .field("resource_id_hash", resource_id_hash)
                .field("token_source", token_source)
                .field("token_format", token_format)
                .field("expires_at", &expires_at.map(|_| "[REDACTED_INSTANT]"))
                .finish(),
            Self::CredentialId { redacted_id, .. } => f
                .debug_struct("CredentialId")
                .field("id", redacted_id)
                .finish(),
        }
    }
}

impl Auth {
    const fn redacted_label(&self) -> &'static str {
        match self {
            Self::SubscriptionKey(_) => "subscription_key",
            Self::EntraAccessToken { .. } => "entra_access_token",
            Self::CredentialId { .. } => "credential_id",
        }
    }

    const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId { .. })
    }

    const fn direct_live_auth_supported(&self) -> bool {
        !self.is_secretless()
    }

    fn resource_id_hash(&self) -> Option<&str> {
        match self {
            Self::EntraAccessToken {
                resource_id_hash, ..
            } => resource_id_hash.as_deref(),
            Self::SubscriptionKey(_) | Self::CredentialId { .. } => None,
        }
    }

    const fn token_source(&self) -> Option<&'static str> {
        match self {
            Self::EntraAccessToken { token_source, .. } => Some(token_source.as_str()),
            Self::SubscriptionKey(_) | Self::CredentialId { .. } => None,
        }
    }

    const fn token_format(&self) -> Option<&'static str> {
        match self {
            Self::EntraAccessToken { token_format, .. } => Some(token_format.as_str()),
            Self::SubscriptionKey(_) | Self::CredentialId { .. } => None,
        }
    }

    fn ensure_current(&self) -> FcpResult<()> {
        if let Self::EntraAccessToken {
            expires_at: Some(expires_at),
            ..
        } = self
            && Instant::now() >= *expires_at
        {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Microsoft Entra access token is expired; refresh it through the host credential flow and reconfigure".into(),
            });
        }
        Ok(())
    }

    fn subscription_key(&self) -> FcpResult<&HeaderValue> {
        match self {
            Self::SubscriptionKey(value) => Ok(value),
            Self::EntraAccessToken { .. } => Err(FcpError::InvalidRequest {
                code: 1003,
                message: "subscription-key token exchange is not available for Microsoft Entra access-token mode".into(),
            }),
            Self::CredentialId { .. } => Err(FcpError::InvalidRequest {
                code: 1003,
                message: "credential_id mode requires host-side credential injection, which this connector slice does not implement".into(),
            }),
        }
    }

    fn direct_header(&self) -> FcpResult<(HeaderName, HeaderValue)> {
        self.ensure_current()?;
        match self {
            Self::SubscriptionKey(value) => Ok((
                HeaderName::from_static("ocp-apim-subscription-key"),
                value.clone(),
            )),
            Self::EntraAccessToken { authorization, .. } => {
                Ok((AUTHORIZATION, authorization.clone()))
            }
            Self::CredentialId { id, .. } => {
                Ok((HeaderName::from_static("x-fcp-credential-id"), id.clone()))
            }
        }
    }

    fn from_params(params: &Value) -> FcpResult<Self> {
        let subscription_key = optional_config_string(params, "subscription_key")
            .or_else(|| optional_config_string(params, "api_key"));
        let credential_id = optional_config_string(params, "credential_id");
        let entra_bearer_config = optional_config_string(params, "entra_access_token")
            .or_else(|| optional_config_string(params, "aad_access_token"));
        let connector_local_identity = ConnectorLocalIdentityRequest::from_params(params)?;
        let configured_modes = [
            subscription_key.is_some(),
            credential_id.is_some(),
            entra_bearer_config.is_some(),
            connector_local_identity.is_some(),
        ]
        .into_iter()
        .filter(|configured| *configured)
        .count();
        if configured_modes != 1 {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Provide exactly one auth source: subscription_key/api_key, entra_access_token/aad_access_token, credential_id, or connector_local_identity".into(),
            });
        }
        if let Some(key) = subscription_key {
            return Ok(Self::SubscriptionKey(safe_header_value(
                "subscription_key",
                &key,
            )?));
        }
        if let Some(id) = credential_id {
            let header = safe_header_value("credential_id", &id)?;
            return Ok(Self::CredentialId {
                id: header,
                redacted_id: redact_identifier(&id),
            });
        }
        if let Some(identity) = connector_local_identity {
            return Err(identity.unsupported_error());
        }
        let entra_bearer =
            entra_bearer_config.expect("exactly one auth mode means Entra bearer is present here");
        let resource_id = optional_config_string(params, "entra_resource_id")
            .or_else(|| optional_config_string(params, "azure_resource_id"));
        let token_format = EntraTokenFormat::from_params(params, resource_id.is_some())?;
        let token_source = EntraTokenSource::from_params(params)?;
        let authorization_value = match token_format {
            EntraTokenFormat::AadResource => {
                let resource_id = resource_id.as_deref().ok_or_else(|| {
                    FcpError::InvalidRequest {
                        code: 1003,
                        message: "entra_resource_id is required when entra_token_format is aad_resource_token".into(),
                    }
                })?;
                validate_azure_resource_id(resource_id)?;
                format!("aad#{resource_id}#{entra_bearer}")
            }
            EntraTokenFormat::Bearer => entra_bearer,
        };
        Ok(Self::EntraAccessToken {
            authorization: bearer_header(&authorization_value)?,
            resource_id_hash: resource_id
                .as_deref()
                .map(validate_azure_resource_id)
                .transpose()?
                .map(|resource_id| sha256_hex(resource_id.as_bytes())),
            token_source,
            token_format,
            expires_at: entra_token_expires_at(params)?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EntraTokenSource {
    ExternalBearer,
    ManagedIdentity,
}

impl EntraTokenSource {
    const fn as_str(self) -> &'static str {
        match self {
            Self::ExternalBearer => "external_token",
            Self::ManagedIdentity => "managed_identity",
        }
    }

    fn from_params(params: &Value) -> FcpResult<Self> {
        match params
            .get("entra_token_source")
            .and_then(Value::as_str)
            .unwrap_or("external_token")
        {
            "external_token" | "external" => Ok(Self::ExternalBearer),
            "managed_identity" | "managed-identity" => Ok(Self::ManagedIdentity),
            other => Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!(
                    "unsupported entra_token_source {other:?}; expected external_token or managed_identity"
                ),
            }),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EntraTokenFormat {
    AadResource,
    Bearer,
}

impl EntraTokenFormat {
    const fn as_str(self) -> &'static str {
        match self {
            Self::AadResource => "aad_resource_token",
            Self::Bearer => "bearer_token",
        }
    }

    fn from_params(params: &Value, has_resource_id: bool) -> FcpResult<Self> {
        match params.get("entra_token_format").and_then(Value::as_str) {
            Some("aad_resource_token" | "aad-resource-token" | "aad") => Ok(Self::AadResource),
            Some("bearer_token" | "bearer-token" | "bearer") => Ok(Self::Bearer),
            Some(other) => Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!(
                    "unsupported entra_token_format {other:?}; expected aad_resource_token or bearer_token"
                ),
            }),
            None if has_resource_id => Ok(Self::AadResource),
            None => Ok(Self::Bearer),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
struct ConnectorLocalIdentityRequest {
    endpoint: Url,
    resource: String,
    selector: ManagedIdentitySelector,
}

impl std::fmt::Debug for ConnectorLocalIdentityRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectorLocalIdentityRequest")
            .field("endpoint_host", &host(&self.endpoint))
            .field("api_version", &IMDS_API_VERSION)
            .field("resource_hash", &sha256_hex(self.resource.as_bytes()))
            .field("selector", &self.selector)
            .finish()
    }
}

impl ConnectorLocalIdentityRequest {
    fn from_params(params: &Value) -> FcpResult<Option<Self>> {
        let requested = optional_config_bool(params, "connector_local_identity")?.unwrap_or(false)
            || optional_config_bool(params, "managed_identity")?.unwrap_or(false)
            || connector_local_identity_source_requested(params)
            || optional_config_string(params, "managed_identity_client_id").is_some()
            || optional_config_string(params, "managed_identity_object_id").is_some()
            || optional_config_string(params, "managed_identity_msi_res_id").is_some();
        if !requested {
            return Ok(None);
        }

        let endpoint = Url::parse(IMDS_TOKEN_ENDPOINT).map_err(|error| FcpError::Internal {
            message: format!("embedded Azure IMDS endpoint is invalid: {error}"),
        })?;
        let resource = optional_config_string(params, "managed_identity_resource")
            .or_else(|| optional_config_string(params, "imds_resource"))
            .unwrap_or_else(|| COGNITIVE_SERVICES_ENTRA_RESOURCE.to_owned());
        validate_managed_identity_resource(&resource)?;
        let selector = ManagedIdentitySelector::from_params(params)?;
        Ok(Some(Self {
            endpoint,
            resource,
            selector,
        }))
    }

    #[cfg(test)]
    fn request_url(&self) -> Url {
        let mut url = self.endpoint.clone();
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("api-version", IMDS_API_VERSION);
            query.append_pair("resource", &self.resource);
            if let Some((key, value)) = self.selector.query_pair() {
                query.append_pair(key, value);
            }
        }
        url
    }

    fn host_allowlist(&self) -> Vec<String> {
        vec![host(&self.endpoint).to_owned()]
    }

    fn resource_id_hash(&self) -> String {
        sha256_hex(self.resource.as_bytes())
    }

    const fn selector_class(&self) -> &'static str {
        self.selector.class()
    }

    fn unsupported_error(&self) -> FcpError {
        FcpError::InvalidRequest {
            code: 1003,
            message: format!(
                "connector-local Azure managed identity acquisition is disabled for Azure Speech; use host-provided entra_access_token/aad_access_token or credential_id. IMDS requires {} on {} over link-local HTTP with Metadata:true, while FCP runtime network policy cannot safely combine that local/LAN exception with Azure Speech provider egress in one runtime-enforced operation. selector_class={}, resource_id_hash={}",
                IMDS_API_VERSION,
                self.host_allowlist().join(","),
                self.selector_class(),
                self.resource_id_hash()
            ),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
enum ManagedIdentitySelector {
    SystemAssigned,
    ClientId(String),
    ObjectId(String),
    MsiResourceId(String),
}

impl std::fmt::Debug for ManagedIdentitySelector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SystemAssigned => f.write_str("SystemAssigned"),
            Self::ClientId(value) => f
                .debug_struct("ClientId")
                .field("sha256", &sha256_hex(value.as_bytes()))
                .finish(),
            Self::ObjectId(value) => f
                .debug_struct("ObjectId")
                .field("sha256", &sha256_hex(value.as_bytes()))
                .finish(),
            Self::MsiResourceId(value) => f
                .debug_struct("MsiResourceId")
                .field("sha256", &sha256_hex(value.as_bytes()))
                .finish(),
        }
    }
}

impl ManagedIdentitySelector {
    fn from_params(params: &Value) -> FcpResult<Self> {
        let client_id = optional_config_string(params, "managed_identity_client_id");
        let object_id = optional_config_string(params, "managed_identity_object_id");
        let msi_res_id = optional_config_string(params, "managed_identity_msi_res_id");
        let configured = [
            client_id.is_some(),
            object_id.is_some(),
            msi_res_id.is_some(),
        ]
        .into_iter()
        .filter(|value| *value)
        .count();
        if configured > 1 {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Configure at most one managed identity selector: managed_identity_client_id, managed_identity_object_id, or managed_identity_msi_res_id".into(),
            });
        }
        if let Some(value) = client_id {
            validate_managed_identity_selector("managed_identity_client_id", &value)?;
            return Ok(Self::ClientId(value));
        }
        if let Some(value) = object_id {
            validate_managed_identity_selector("managed_identity_object_id", &value)?;
            return Ok(Self::ObjectId(value));
        }
        if let Some(value) = msi_res_id {
            validate_managed_identity_selector("managed_identity_msi_res_id", &value)?;
            return Ok(Self::MsiResourceId(value));
        }
        Ok(Self::SystemAssigned)
    }

    #[cfg(test)]
    fn query_pair(&self) -> Option<(&'static str, &str)> {
        match self {
            Self::SystemAssigned => None,
            Self::ClientId(value) => Some(("client_id", value)),
            Self::ObjectId(value) => Some(("object_id", value)),
            Self::MsiResourceId(value) => Some(("msi_res_id", value)),
        }
    }

    const fn class(&self) -> &'static str {
        match self {
            Self::SystemAssigned => "system_assigned",
            Self::ClientId(_) => "client_id",
            Self::ObjectId(_) => "object_id",
            Self::MsiResourceId(_) => "msi_res_id",
        }
    }
}

#[derive(Clone)]
struct AzureSpeechConfig {
    auth: Auth,
    region: String,
    cloud: SpeechCloud,
    token_url: String,
    tts_base_url: String,
    stt_base_url: String,
    request_timeout_ms: u64,
    inline_audio_max_bytes: usize,
    tts_max_audio_bytes: usize,
    stt_max_audio_bytes: usize,
}

impl std::fmt::Debug for AzureSpeechConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AzureSpeechConfig")
            .field("auth", &self.auth)
            .field("region", &self.region)
            .field("cloud", &self.cloud)
            .field("token_url", &self.token_url)
            .field("tts_base_url", &self.tts_base_url)
            .field("stt_base_url", &self.stt_base_url)
            .field("request_timeout_ms", &self.request_timeout_ms)
            .field("inline_audio_max_bytes", &self.inline_audio_max_bytes)
            .field("tts_max_audio_bytes", &self.tts_max_audio_bytes)
            .field("stt_max_audio_bytes", &self.stt_max_audio_bytes)
            .finish()
    }
}

impl AzureSpeechConfig {
    fn from_params(params: &Value) -> FcpResult<Self> {
        let auth = Auth::from_params(params)?;
        let region = params
            .get("region")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "region is required".into(),
            })?;
        validate_region(region)?;
        let region = region.to_ascii_lowercase();
        let cloud = SpeechCloud::from_params(params)?;
        let endpoints = SpeechEndpoints::from_params(params, &region, cloud)?;

        Ok(Self {
            auth,
            region,
            cloud,
            token_url: endpoints.token,
            tts_base_url: endpoints.tts_base,
            stt_base_url: endpoints.stt_base,
            request_timeout_ms: request_timeout_ms(params)?,
            inline_audio_max_bytes: bounded_usize(
                params.get("inline_audio_max_bytes"),
                "inline_audio_max_bytes",
                DEFAULT_INLINE_AUDIO_MAX_BYTES,
                0,
                DEFAULT_TTS_MAX_AUDIO_BYTES,
            )?,
            tts_max_audio_bytes: bounded_usize(
                params.get("tts_max_audio_bytes"),
                "tts_max_audio_bytes",
                DEFAULT_TTS_MAX_AUDIO_BYTES,
                1,
                DEFAULT_TTS_MAX_AUDIO_BYTES,
            )?,
            stt_max_audio_bytes: bounded_usize(
                params.get("stt_max_audio_bytes"),
                "stt_max_audio_bytes",
                DEFAULT_STT_MAX_AUDIO_BYTES,
                1,
                DEFAULT_STT_MAX_AUDIO_BYTES,
            )?,
        })
    }

    fn host_allowlist(&self) -> Vec<String> {
        let mut hosts = vec![
            host_from_url(&self.token_url),
            host_from_url(&self.tts_base_url),
            host_from_url(&self.stt_base_url),
        ];
        hosts.sort();
        hosts.dedup();
        hosts
    }
}

#[derive(Debug, Clone, Copy)]
enum SpeechCloud {
    Public,
    UsGov,
}

impl SpeechCloud {
    fn from_params(params: &Value) -> FcpResult<Self> {
        match params
            .get("cloud")
            .and_then(Value::as_str)
            .unwrap_or("public")
        {
            "public" => Ok(Self::Public),
            "usgov" | "us-gov" | "azure-us-gov" => Ok(Self::UsGov),
            other => Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!("unsupported cloud {other:?}; expected public or usgov"),
            }),
        }
    }

    const fn token_suffix(self) -> &'static str {
        match self {
            Self::Public => ".api.cognitive.microsoft.com",
            Self::UsGov => ".api.cognitive.microsoft.us",
        }
    }

    const fn tts_suffix(self) -> &'static str {
        match self {
            Self::Public => ".tts.speech.microsoft.com",
            Self::UsGov => ".tts.speech.azure.us",
        }
    }

    fn allows_token_host(self, host: &str) -> bool {
        host.ends_with(self.token_suffix())
    }

    fn allows_tts_host(self, host: &str) -> bool {
        host.ends_with(self.tts_suffix())
    }
}

struct SpeechEndpoints {
    token: String,
    tts_base: String,
    stt_base: String,
}

impl SpeechEndpoints {
    fn for_region(region: &str, cloud: SpeechCloud) -> Self {
        Self {
            token: format!(
                "https://{region}{}/sts/v1.0/issueToken",
                cloud.token_suffix()
            ),
            tts_base: format!("https://{region}{}", cloud.tts_suffix()),
            stt_base: format!("https://{region}{}", cloud.token_suffix()),
        }
    }

    fn from_params(params: &Value, region: &str, cloud: SpeechCloud) -> FcpResult<Self> {
        let defaults = Self::for_region(region, cloud);
        Ok(Self {
            token: normalize_absolute_url(
                params.get("token_url").and_then(Value::as_str),
                &defaults.token,
                "token_url",
                |url| is_loopback_url(url) || cloud.allows_token_host(host(url)),
                true,
            )?,
            tts_base: normalize_base_url(
                params.get("tts_base_url").and_then(Value::as_str),
                &defaults.tts_base,
                "tts_base_url",
                |url| is_loopback_url(url) || cloud.allows_tts_host(host(url)),
            )?,
            stt_base: normalize_base_url(
                params.get("stt_base_url").and_then(Value::as_str),
                &defaults.stt_base,
                "stt_base_url",
                |url| is_loopback_url(url) || cloud.allows_token_host(host(url)),
            )?,
        })
    }
}

struct CachedToken {
    value: HeaderValue,
    issued_at: Instant,
}

impl CachedToken {
    fn is_fresh_at(&self, now: Instant) -> bool {
        now.duration_since(self.issued_at) < ACCESS_TOKEN_REFRESH_AFTER
            && now.duration_since(self.issued_at) < ACCESS_TOKEN_TTL
    }
}

#[derive(Default)]
struct TokenCache {
    token: Mutex<Option<CachedToken>>,
}

impl TokenCache {
    fn get_fresh_at(&self, now: Instant) -> Option<HeaderValue> {
        let guard = self.token.lock().expect("token cache mutex poisoned");
        guard
            .as_ref()
            .filter(|token| token.is_fresh_at(now))
            .map(|token| token.value.clone())
    }

    fn store(&self, value: HeaderValue, issued_at: Instant) {
        let mut guard = self.token.lock().expect("token cache mutex poisoned");
        *guard = Some(CachedToken { value, issued_at });
    }

    fn clear(&self) {
        let mut guard = self.token.lock().expect("token cache mutex poisoned");
        *guard = None;
    }
}

struct AzureSpeechClient {
    http: Client,
    config: AzureSpeechConfig,
    token_cache: TokenCache,
}

impl AzureSpeechClient {
    fn new(config: &AzureSpeechConfig) -> FcpResult<Self> {
        let http = Client::builder()
            .timeout(Duration::from_millis(config.request_timeout_ms))
            .build()
            .map_err(|error| FcpError::Internal {
                message: format!("failed to build Azure Speech HTTP client: {error}"),
            })?;
        Ok(Self {
            http,
            config: config.clone(),
            token_cache: TokenCache::default(),
        })
    }

    async fn bearer_token(&self) -> FcpResult<HeaderValue> {
        if let Some(token) = self.token_cache.get_fresh_at(Instant::now()) {
            return Ok(token);
        }

        let key = self.config.auth.subscription_key()?;
        let response = self
            .send_with_retry(|| {
                with_header(
                    self.http
                        .post(&self.config.token_url)
                        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                        .header(CONTENT_LENGTH, "0"),
                    HeaderName::from_static("ocp-apim-subscription-key"),
                    key,
                )
            })
            .await?;
        let status = response.status();
        if !status.is_success() {
            return Err(provider_error("issueToken", status, &response));
        }
        let token_text = response.text().await.map_err(|error| map_reqwest(&error))?;
        let issued_bearer = token_text.trim();
        if issued_bearer.is_empty() {
            return Err(FcpError::External {
                service: "azure-speech.issueToken".into(),
                message: "issueToken returned an empty token".into(),
                status_code: Some(status.as_u16()),
                retryable: false,
                retry_after: None,
            });
        }
        let header = bearer_header(issued_bearer)?;
        self.token_cache.store(header.clone(), Instant::now());
        Ok(header)
    }

    async fn auth_header(
        &self,
        issue_token_for_subscription_key: bool,
    ) -> FcpResult<(HeaderName, HeaderValue)> {
        if issue_token_for_subscription_key && matches!(self.config.auth, Auth::SubscriptionKey(_))
        {
            Ok((AUTHORIZATION, self.bearer_token().await?))
        } else {
            self.config.auth.direct_header()
        }
    }

    async fn voices_list(&self) -> FcpResult<Value> {
        let (auth_name, auth_value) = self.auth_header(true).await?;
        let url = format!("{}/cognitiveservices/voices/list", self.config.tts_base_url);
        let response = self
            .send_with_retry(|| {
                with_header(
                    self.http.get(&url).header(USER_AGENT, USER_AGENT_VALUE),
                    auth_name.clone(),
                    &auth_value,
                )
            })
            .await?;
        let status = response.status();
        if !status.is_success() {
            return Err(provider_error("voices.list", status, &response));
        }
        let voices: Value = response.json().await.map_err(|error| map_reqwest(&error))?;
        Ok(json!({
            "voices": voices,
            "region": self.config.region,
            "cloud": format!("{:?}", self.config.cloud).to_ascii_lowercase(),
            "host_allow": self.config.host_allowlist(),
        }))
    }

    async fn synthesize(&self, input: &Value) -> FcpResult<Value> {
        let request = TtsRequest::from_input(input, self.config.inline_audio_max_bytes)?;
        let (auth_name, auth_value) = self.auth_header(true).await?;
        let url = format!("{}/cognitiveservices/v1", self.config.tts_base_url);
        let response = self
            .send_with_retry(|| {
                with_header(
                    self.http
                        .post(&url)
                        .header(CONTENT_TYPE, "application/ssml+xml")
                        .header("x-microsoft-outputformat", &request.output_format)
                        .header(USER_AGENT, USER_AGENT_VALUE)
                        .body(request.ssml.clone()),
                    auth_name.clone(),
                    &auth_value,
                )
            })
            .await?;
        let status = response.status();
        if !status.is_success() {
            return Err(provider_error("tts.synthesize", status, &response));
        }
        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(ToOwned::to_owned);
        let bytes = response
            .bytes()
            .await
            .map_err(|error| map_reqwest(&error))?;
        if bytes.len() > self.config.tts_max_audio_bytes {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!(
                    "synthesized audio exceeded configured cap of {} bytes",
                    self.config.tts_max_audio_bytes
                ),
            });
        }
        let sha256 = sha256_hex(&bytes);
        if bytes.len() <= request.inline_audio_max_bytes {
            Ok(json!({
                "mode": "inline",
                "audio_base64": BASE64_STANDARD.encode(&bytes),
                "byte_count": bytes.len(),
                "sha256": sha256,
                "output_format": request.output_format,
                "provider_content_type": content_type,
            }))
        } else {
            Ok(json!({
                "mode": "artifact_reference",
                "artifact": {
                    "storage": "host_artifact_required",
                    "byte_count": bytes.len(),
                    "sha256": sha256,
                    "provider_content_type": content_type,
                    "output_format": request.output_format,
                },
                "audio_base64": Value::Null,
            }))
        }
    }

    async fn transcribe_fast(&self, input: &Value) -> FcpResult<Value> {
        let request = SttRequest::from_input(input, self.config.stt_max_audio_bytes)?;
        let (auth_name, auth_value) = self.auth_header(false).await?;
        let definition =
            serde_json::to_string(&request.definition).map_err(|error| FcpError::Internal {
                message: format!(
                    "failed to serialize Azure Speech transcription definition: {error}"
                ),
            })?;
        let url = format!(
            "{}/speechtotext/transcriptions:transcribe?api-version={STT_API_VERSION}",
            self.config.stt_base_url
        );
        let response = self
            .send_with_retry(|| {
                let audio = multipart::Part::bytes(request.audio.clone())
                    .file_name("audio.bin")
                    .mime_str(&request.content_type)
                    .expect("validated STT content type should be a valid MIME string");
                let form = multipart::Form::new()
                    .text("definition", definition.clone())
                    .part("audio", audio);
                with_header(
                    self.http
                        .post(&url)
                        .header(USER_AGENT, USER_AGENT_VALUE)
                        .multipart(form),
                    auth_name.clone(),
                    &auth_value,
                )
            })
            .await?;
        let status = response.status();
        if !status.is_success() {
            return Err(provider_error("stt.transcribe_fast", status, &response));
        }
        let value: Value = response.json().await.map_err(|error| map_reqwest(&error))?;
        Ok(normalize_transcription_result(&value, &request))
    }

    async fn batch_submit(&self, input: &Value) -> FcpResult<Value> {
        let request = BatchSubmitRequest::from_input(input, &self.config.stt_base_url)?;
        let (auth_name, auth_value) = self.auth_header(false).await?;
        let url = format!(
            "{}/speechtotext/transcriptions:submit?api-version={STT_API_VERSION}",
            self.config.stt_base_url
        );
        let response = self
            .send_with_retry(|| {
                with_header(
                    self.http
                        .post(&url)
                        .header(USER_AGENT, USER_AGENT_VALUE)
                        .json(&request.body),
                    auth_name.clone(),
                    &auth_value,
                )
            })
            .await?;
        let status = response.status();
        if !status.is_success() {
            return Err(provider_error("stt.batch.submit", status, &response));
        }
        let location = response
            .headers()
            .get("location")
            .and_then(|value| value.to_str().ok())
            .map(url_descriptor);
        let value: Value = response.json().await.map_err(|error| map_reqwest(&error))?;
        let transcription_id_hash = transcription_id_hash_from_value(&value);
        Ok(json!({
            "operation": "azure.speech.stt.batch.submit",
            "api_version": STT_API_VERSION,
            "status_code": status.as_u16(),
            "content_source": request.content_source,
            "transcription_id_hash": transcription_id_hash,
            "location": location,
            "transcription": sanitize_provider_urls(&value),
        }))
    }

    async fn custom_speech(&self, operation: &str, input: &Value) -> FcpResult<Value> {
        let route = CustomSpeechRoute::from_operation(operation).ok_or_else(|| {
            FcpError::InvalidRequest {
                code: 1002,
                message: format!("Unknown operation: {operation}"),
            }
        })?;
        let request = CustomSpeechRequest::from_input(input, &self.config.stt_base_url, route)?;
        let (auth_name, auth_value) = self.auth_header(false).await?;
        let response = self
            .send_with_retry(|| {
                let builder = match route.action {
                    CustomSpeechAction::Create => self.http.post(request.url.as_str()),
                    CustomSpeechAction::List | CustomSpeechAction::Get => {
                        self.http.get(request.url.as_str())
                    }
                    CustomSpeechAction::Delete => self.http.delete(request.url.as_str()),
                }
                .header(USER_AGENT, USER_AGENT_VALUE);
                let builder = if let Some(body) = &request.body {
                    builder.json(body)
                } else {
                    builder
                };
                with_header(builder, auth_name.clone(), &auth_value)
            })
            .await?;
        let status = response.status();
        if !status.is_success() {
            return Err(provider_error(
                route.provider_operation(),
                status,
                &response,
            ));
        }
        let location = response
            .headers()
            .get("location")
            .and_then(|value| value.to_str().ok())
            .map(url_descriptor);
        let provider_value = if status == StatusCode::NO_CONTENT {
            Value::Null
        } else {
            response.json().await.map_err(|error| map_reqwest(&error))?
        };
        Ok(json!({
            "operation": operation,
            "api_version": STT_API_VERSION,
            "resource_kind": route.kind.as_str(),
            "action": route.action.as_str(),
            "status_code": status.as_u16(),
            "resource_id_hash": resource_id_hash_from_value(&provider_value),
            "model_id_hash": model_id_hash_for_result(route.kind, &provider_value),
            "project_id_hash": project_id_hash_for_result(route.kind, &provider_value),
            "location": location,
            "resource": sanitize_provider_urls(&provider_value),
        }))
    }

    async fn batch_get(&self, input: &Value) -> FcpResult<Value> {
        let url = BatchResourceRequest::from_input(input, &self.config.stt_base_url)?.status_url;
        let (auth_name, auth_value) = self.auth_header(false).await?;
        let response = self
            .send_with_retry(|| {
                with_header(
                    self.http
                        .get(url.as_str())
                        .header(USER_AGENT, USER_AGENT_VALUE),
                    auth_name.clone(),
                    &auth_value,
                )
            })
            .await?;
        let status = response.status();
        if !status.is_success() {
            return Err(provider_error("stt.batch.get", status, &response));
        }
        let value: Value = response.json().await.map_err(|error| map_reqwest(&error))?;
        Ok(json!({
            "operation": "azure.speech.stt.batch.get",
            "api_version": STT_API_VERSION,
            "status_code": status.as_u16(),
            "transcription_id_hash": transcription_id_hash_from_value(&value),
            "transcription": sanitize_provider_urls(&value),
        }))
    }

    async fn batch_files(&self, input: &Value) -> FcpResult<Value> {
        let url =
            BatchResourceRequest::from_input(input, &self.config.stt_base_url)?.files_url(input)?;
        let (auth_name, auth_value) = self.auth_header(false).await?;
        let response = self
            .send_with_retry(|| {
                with_header(
                    self.http
                        .get(url.as_str())
                        .header(USER_AGENT, USER_AGENT_VALUE),
                    auth_name.clone(),
                    &auth_value,
                )
            })
            .await?;
        let status = response.status();
        if !status.is_success() {
            return Err(provider_error("stt.batch.files", status, &response));
        }
        let value: Value = response.json().await.map_err(|error| map_reqwest(&error))?;
        Ok(json!({
            "operation": "azure.speech.stt.batch.files",
            "api_version": STT_API_VERSION,
            "status_code": status.as_u16(),
            "files": sanitize_provider_urls(&value),
        }))
    }

    async fn send_with_retry<F>(&self, mut build: F) -> FcpResult<Response>
    where
        F: FnMut() -> RequestBuilder,
    {
        let mut attempt = 0;
        loop {
            let response = build().send().await.map_err(|error| map_reqwest(&error))?;
            if !is_retryable_status(response.status()) || attempt >= MAX_RETRIES {
                return Ok(response);
            }
            attempt += 1;
            let delay_ms = retry_after_ms(&response)
                .unwrap_or_else(|| RETRY_BASE_DELAY_MS.saturating_mul(attempt));
            time::sleep(Duration::from_millis(delay_ms.min(1_000))).await;
        }
    }
}

#[derive(Debug)]
struct TtsRequest {
    ssml: String,
    output_format: String,
    inline_audio_max_bytes: usize,
}

impl TtsRequest {
    fn from_input(input: &Value, config_inline_cap: usize) -> FcpResult<Self> {
        let output_format = input
            .get("output_format")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or(DEFAULT_TTS_OUTPUT_FORMAT);
        validate_output_format(output_format)?;
        let inline_audio_max_bytes = match input.get("inline_audio_max_bytes") {
            Some(value) => bounded_usize(
                Some(value),
                "inline_audio_max_bytes",
                config_inline_cap,
                0,
                DEFAULT_TTS_MAX_AUDIO_BYTES,
            )?,
            None => config_inline_cap,
        };
        let ssml = match input.get("ssml").and_then(Value::as_str) {
            Some(ssml) if !ssml.trim().is_empty() => ssml.trim().to_owned(),
            _ => {
                let text = required_string(input, "text")?;
                let voice = required_string(input, "voice")?;
                let locale = input
                    .get("locale")
                    .or_else(|| input.get("language"))
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .unwrap_or("en-US");
                validate_locale(locale)?;
                format!(
                    "<speak version='1.0' xml:lang='{locale}'><voice name='{}'>{}</voice></speak>",
                    xml_escape(voice),
                    xml_escape(text)
                )
            }
        };
        validate_ssml(&ssml)?;
        Ok(Self {
            ssml,
            output_format: output_format.to_owned(),
            inline_audio_max_bytes,
        })
    }
}

#[derive(Debug)]
struct SttRequest {
    audio: Vec<u8>,
    content_type: String,
    definition: Value,
}

impl SttRequest {
    fn from_input(input: &Value, max_audio_bytes: usize) -> FcpResult<Self> {
        let audio = decode_audio(input)?;
        if audio.is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "audio must not be empty".into(),
            });
        }
        let request_max = match input.get("max_audio_bytes") {
            Some(value) => bounded_usize(
                Some(value),
                "max_audio_bytes",
                max_audio_bytes,
                1,
                max_audio_bytes,
            )?,
            None => max_audio_bytes,
        };
        if audio.len() > request_max {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!("audio exceeds max_audio_bytes cap of {request_max}"),
            });
        }
        let content_type = input
            .get("content_type")
            .or_else(|| input.get("mime_type"))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("audio/wav");
        validate_stt_content_type(content_type)?;

        let locales = locales_from_input(input)?;
        let mut definition = json!({ "locales": locales });
        copy_definition_field(
            &mut definition,
            input,
            "profanityFilterMode",
            "profanity_filter_mode",
        );
        copy_definition_field(&mut definition, input, "diarization", "diarization");
        copy_definition_field(&mut definition, input, "channels", "channels");
        copy_definition_field(&mut definition, input, "phraseList", "phrase_list");
        copy_definition_field(&mut definition, input, "enhancedMode", "enhanced_mode");
        Ok(Self {
            audio,
            content_type: content_type.to_owned(),
            definition,
        })
    }
}

struct BatchSubmitRequest {
    body: Value,
    content_source: Value,
}

#[derive(Clone, Copy)]
enum BatchContentSourceInput<'a> {
    Urls(&'a [Value]),
    ContainerUrl(&'a str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CustomSpeechResourceKind {
    Project,
    Dataset,
    Model,
    Endpoint,
}

impl CustomSpeechResourceKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Project => "project",
            Self::Dataset => "dataset",
            Self::Model => "model",
            Self::Endpoint => "endpoint",
        }
    }

    const fn collection_path(self) -> &'static str {
        match self {
            Self::Project => "/speechtotext/projects",
            Self::Dataset => "/speechtotext/datasets",
            Self::Model => "/speechtotext/models",
            Self::Endpoint => "/speechtotext/endpoints",
        }
    }

    const fn id_field(self) -> &'static str {
        match self {
            Self::Project => "project_id",
            Self::Dataset => "dataset_id",
            Self::Model => "model_id",
            Self::Endpoint => "endpoint_id",
        }
    }

    const fn url_field(self) -> &'static str {
        match self {
            Self::Project => "project_url",
            Self::Dataset => "dataset_url",
            Self::Model => "model_url",
            Self::Endpoint => "endpoint_url",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CustomSpeechAction {
    Create,
    List,
    Get,
    Delete,
}

impl CustomSpeechAction {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::List => "list",
            Self::Get => "get",
            Self::Delete => "delete",
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct CustomSpeechRoute {
    kind: CustomSpeechResourceKind,
    action: CustomSpeechAction,
}

impl CustomSpeechRoute {
    const fn provider_operation(self) -> &'static str {
        match (self.kind, self.action) {
            (CustomSpeechResourceKind::Project, CustomSpeechAction::Create) => {
                "custom.projects.create"
            }
            (CustomSpeechResourceKind::Project, CustomSpeechAction::List) => "custom.projects.list",
            (CustomSpeechResourceKind::Project, CustomSpeechAction::Get) => "custom.projects.get",
            (CustomSpeechResourceKind::Project, CustomSpeechAction::Delete) => {
                "custom.projects.delete"
            }
            (CustomSpeechResourceKind::Dataset, CustomSpeechAction::Create) => {
                "custom.datasets.create"
            }
            (CustomSpeechResourceKind::Dataset, CustomSpeechAction::List) => "custom.datasets.list",
            (CustomSpeechResourceKind::Dataset, CustomSpeechAction::Get) => "custom.datasets.get",
            (CustomSpeechResourceKind::Dataset, CustomSpeechAction::Delete) => {
                "custom.datasets.delete"
            }
            (CustomSpeechResourceKind::Model, CustomSpeechAction::Create) => "custom.models.create",
            (CustomSpeechResourceKind::Model, CustomSpeechAction::List) => "custom.models.list",
            (CustomSpeechResourceKind::Model, CustomSpeechAction::Get) => "custom.models.get",
            (CustomSpeechResourceKind::Model, CustomSpeechAction::Delete) => "custom.models.delete",
            (CustomSpeechResourceKind::Endpoint, CustomSpeechAction::Create) => {
                "custom.endpoints.create"
            }
            (CustomSpeechResourceKind::Endpoint, CustomSpeechAction::List) => {
                "custom.endpoints.list"
            }
            (CustomSpeechResourceKind::Endpoint, CustomSpeechAction::Get) => "custom.endpoints.get",
            (CustomSpeechResourceKind::Endpoint, CustomSpeechAction::Delete) => {
                "custom.endpoints.delete"
            }
        }
    }

    fn from_operation(operation: &str) -> Option<Self> {
        match operation {
            OP_CUSTOM_PROJECTS_CREATE => Some(Self {
                kind: CustomSpeechResourceKind::Project,
                action: CustomSpeechAction::Create,
            }),
            OP_CUSTOM_PROJECTS_LIST => Some(Self {
                kind: CustomSpeechResourceKind::Project,
                action: CustomSpeechAction::List,
            }),
            OP_CUSTOM_PROJECTS_GET => Some(Self {
                kind: CustomSpeechResourceKind::Project,
                action: CustomSpeechAction::Get,
            }),
            OP_CUSTOM_PROJECTS_DELETE => Some(Self {
                kind: CustomSpeechResourceKind::Project,
                action: CustomSpeechAction::Delete,
            }),
            OP_CUSTOM_DATASETS_CREATE => Some(Self {
                kind: CustomSpeechResourceKind::Dataset,
                action: CustomSpeechAction::Create,
            }),
            OP_CUSTOM_DATASETS_LIST => Some(Self {
                kind: CustomSpeechResourceKind::Dataset,
                action: CustomSpeechAction::List,
            }),
            OP_CUSTOM_DATASETS_GET => Some(Self {
                kind: CustomSpeechResourceKind::Dataset,
                action: CustomSpeechAction::Get,
            }),
            OP_CUSTOM_DATASETS_DELETE => Some(Self {
                kind: CustomSpeechResourceKind::Dataset,
                action: CustomSpeechAction::Delete,
            }),
            OP_CUSTOM_MODELS_CREATE => Some(Self {
                kind: CustomSpeechResourceKind::Model,
                action: CustomSpeechAction::Create,
            }),
            OP_CUSTOM_MODELS_LIST => Some(Self {
                kind: CustomSpeechResourceKind::Model,
                action: CustomSpeechAction::List,
            }),
            OP_CUSTOM_MODELS_GET => Some(Self {
                kind: CustomSpeechResourceKind::Model,
                action: CustomSpeechAction::Get,
            }),
            OP_CUSTOM_MODELS_DELETE => Some(Self {
                kind: CustomSpeechResourceKind::Model,
                action: CustomSpeechAction::Delete,
            }),
            OP_CUSTOM_ENDPOINTS_CREATE => Some(Self {
                kind: CustomSpeechResourceKind::Endpoint,
                action: CustomSpeechAction::Create,
            }),
            OP_CUSTOM_ENDPOINTS_LIST => Some(Self {
                kind: CustomSpeechResourceKind::Endpoint,
                action: CustomSpeechAction::List,
            }),
            OP_CUSTOM_ENDPOINTS_GET => Some(Self {
                kind: CustomSpeechResourceKind::Endpoint,
                action: CustomSpeechAction::Get,
            }),
            OP_CUSTOM_ENDPOINTS_DELETE => Some(Self {
                kind: CustomSpeechResourceKind::Endpoint,
                action: CustomSpeechAction::Delete,
            }),
            _ => None,
        }
    }
}

struct CustomSpeechRequest {
    url: Url,
    body: Option<Value>,
}

impl CustomSpeechRequest {
    fn from_input(input: &Value, stt_base_url: &str, route: CustomSpeechRoute) -> FcpResult<Self> {
        let base = Url::parse(stt_base_url).map_err(|error| FcpError::Internal {
            message: format!("configured stt_base_url is invalid: {error}"),
        })?;
        let (url, body) = match route.action {
            CustomSpeechAction::Create => (
                custom_speech_collection_url(&base, route.kind, input)?,
                Some(build_custom_speech_create_body(input, route.kind, &base)?),
            ),
            CustomSpeechAction::List => (
                custom_speech_collection_url(&base, route.kind, input)?,
                None,
            ),
            CustomSpeechAction::Get | CustomSpeechAction::Delete => (
                custom_speech_resource_url_from_input(input, route.kind, &base)?,
                None,
            ),
        };
        Ok(Self { url, body })
    }
}

impl BatchSubmitRequest {
    fn from_input(input: &Value, stt_base_url: &str) -> FcpResult<Self> {
        let stt_base = Url::parse(stt_base_url).map_err(|error| FcpError::Internal {
            message: format!("configured stt_base_url is invalid: {error}"),
        })?;
        let display_name = required_string(input, "display_name")?;
        let locale = input
            .get("locale")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or(DEFAULT_STT_LOCALE);
        validate_locale(locale)?;

        let mut body = serde_json::Map::new();
        body.insert("displayName".into(), json!(display_name));
        body.insert("locale".into(), json!(locale));
        copy_optional_string(&mut body, input, "description", "description");
        copy_optional_custom_properties(&mut body, input)?;
        copy_optional_reference_object(
            &mut body,
            input,
            "model",
            CustomSpeechResourceKind::Model,
            &stt_base,
        )?;
        copy_optional_reference_object(
            &mut body,
            input,
            "project",
            CustomSpeechResourceKind::Project,
            &stt_base,
        )?;
        copy_optional_reference_object(
            &mut body,
            input,
            "dataset",
            CustomSpeechResourceKind::Dataset,
            &stt_base,
        )?;
        let content_source =
            append_batch_content_source(&mut body, batch_content_source_input(input)?)?;
        body.insert("properties".into(), batch_properties_from_input(input)?);

        Ok(Self {
            body: Value::Object(body),
            content_source,
        })
    }
}

struct BatchResourceRequest {
    status_url: Url,
}

impl BatchResourceRequest {
    fn from_input(input: &Value, stt_base_url: &str) -> FcpResult<Self> {
        let base = Url::parse(stt_base_url).map_err(|error| FcpError::Internal {
            message: format!("configured stt_base_url is invalid: {error}"),
        })?;
        let status_url = if let Some(raw) = input
            .get("transcription_url")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            normalize_transcription_resource_url(raw, &base)?
        } else {
            let transcription_id = required_string(input, "transcription_id")?;
            validate_transcription_id(transcription_id)?;
            let mut url = base;
            url.set_path(&format!("/speechtotext/transcriptions/{transcription_id}"));
            url.set_query(Some(&format!("api-version={STT_API_VERSION}")));
            url
        };
        Ok(Self { status_url })
    }

    fn files_url(&self, input: &Value) -> FcpResult<Url> {
        let mut url = self.status_url.clone();
        let base_path = url.path().trim_end_matches('/');
        if !base_path.ends_with("/files") {
            url.set_path(&format!("{base_path}/files"));
        }
        let mut pairs = vec![("api-version".to_string(), STT_API_VERSION.to_string())];
        copy_query_integer(
            input,
            &mut pairs,
            "sas_validity_seconds",
            "sasValidityInSeconds",
        )?;
        copy_query_integer(input, &mut pairs, "skip", "skip")?;
        copy_query_integer(input, &mut pairs, "top", "top")?;
        if let Some(filter) = input
            .get("filter")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            pairs.push(("filter".into(), filter.to_owned()));
        }
        url.query_pairs_mut().clear().extend_pairs(pairs);
        Ok(url)
    }
}

pub struct AzureSpeechConnector {
    base: Arc<BaseConnector>,
    config: Option<AzureSpeechConfig>,
    client: Option<Arc<AzureSpeechClient>>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<SessionId>,
    handshaken: bool,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

#[allow(clippy::missing_errors_doc, clippy::unused_async)]
impl AzureSpeechConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static(CONNECTOR_ID))),
            config: None,
            client: None,
            verifier: None,
            session_id: None,
            handshaken: false,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }

    #[must_use]
    pub fn instance_id(&self) -> &InstanceId {
        &self.base.instance_id
    }

    pub async fn handle_configure(&mut self, params: Value) -> FcpResult<Value> {
        let config = AzureSpeechConfig::from_params(&params)?;
        let client = AzureSpeechClient::new(&config)?;
        self.config = Some(config.clone());
        self.client = Some(Arc::new(client));
        self.base.set_configured(true);
        Ok(json!({
            "connector_id": CONNECTOR_ID,
            "configured": true,
            "auth_mode": config.auth.redacted_label(),
            "auth_token_source": config.auth.token_source(),
            "auth_token_format": config.auth.token_format(),
            "entra_resource_id_hash": config.auth.resource_id_hash(),
            "connector_local_identity_acquisition": connector_local_identity_policy_info(),
            "region": config.region,
            "cloud": format!("{:?}", config.cloud).to_ascii_lowercase(),
            "host_allow": config.host_allowlist(),
            "request_timeout_ms": config.request_timeout_ms,
            "inline_audio_max_bytes": config.inline_audio_max_bytes,
            "custom_speech_lifecycle": custom_speech_lifecycle_info(),
        }))
    }

    pub async fn handle_handshake(&mut self, params: Value) -> FcpResult<Value> {
        if self.config.is_none() {
            return Err(FcpError::NotConfigured);
        }
        let req: HandshakeRequest =
            serde_json::from_value(params).map_err(|error| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid Azure Speech handshake request: {error}"),
            })?;
        self.verifier = Some(CapabilityVerifier::new(
            req.host_public_key,
            req.zone.clone(),
            self.base.instance_id.clone(),
        ));
        let session_id = SessionId::new();
        self.session_id = Some(session_id.clone());
        self.handshaken = true;
        self.base.set_handshaken(true);
        let capabilities_granted = req
            .capabilities_requested
            .into_iter()
            .map(|capability| CapabilityGrant {
                capability,
                operation: None,
            })
            .collect::<Vec<_>>();

        serde_json::to_value(HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted,
            session_id,
            manifest_hash: azure_speech_manifest_hash(),
            nonce: req.nonce,
            event_caps: Some(EventCaps {
                streaming: false,
                replay: false,
                min_buffer_events: 0,
                requires_ack: false,
            }),
            auth_caps: None,
            op_catalog_hash: None,
        })
        .map_err(|error| FcpError::Internal {
            message: format!("Failed to serialize Azure Speech handshake response: {error}"),
        })
    }

    pub async fn handle_health(&self) -> FcpResult<Value> {
        let direct_live_auth_supported = self
            .config
            .as_ref()
            .is_some_and(|config| config.auth.direct_live_auth_supported());
        Ok(json!({
            "status": if self.config.is_some() && self.handshaken && direct_live_auth_supported {
                "healthy"
            } else if self.config.is_some() {
                "degraded"
            } else {
                "unconfigured"
            },
            "configured": self.config.is_some(),
            "handshaken": self.handshaken,
            "live_requests_supported": self.config.is_some(),
            "direct_live_auth_supported": direct_live_auth_supported,
            "requests": self.request_count.load(Ordering::Relaxed),
            "errors": self.error_count.load(Ordering::Relaxed),
            "host_allow": self.config.as_ref().map(AzureSpeechConfig::host_allowlist),
        }))
    }

    pub async fn handle_doctor(&self) -> FcpResult<Value> {
        let direct_live_auth_supported = self
            .config
            .as_ref()
            .is_some_and(|config| config.auth.direct_live_auth_supported());
        Ok(json!({
            "status": if self.config.is_some()
                && self.client.is_some()
                && self.handshaken
                && direct_live_auth_supported
            {
                "healthy"
            } else if self.config.is_some() && self.client.is_some() {
                "degraded"
            } else {
                "unhealthy"
            },
            "checks": [
                { "name": "configuration", "passed": self.config.is_some(), "critical": true },
                { "name": "client_initialized", "passed": self.client.is_some(), "critical": true },
                {
                    "name": "credential_injection",
                    "passed": direct_live_auth_supported,
                    "critical": false,
                    "message": if direct_live_auth_supported {
                        Value::Null
                    } else {
                        json!("credential_id mode requires host-side credential injection before live Microsoft endpoints can authenticate.")
                    }
                },
                { "name": "handshake", "passed": self.handshaken, "critical": false },
                {
                    "name": "connector_local_identity",
                    "passed": true,
                    "critical": false,
                    "message": connector_local_identity_policy_info()
                },
                {
                    "name": "custom_speech_lifecycle",
                    "passed": true,
                    "critical": false,
                    "message": custom_speech_lifecycle_info()
                },
                { "name": "surface_boundary", "passed": true, "critical": false, "message": BOUNDARY }
            ],
            "streaming_blocker": streaming_blocker_info(),
        }))
    }

    pub async fn handle_self_check(&self) -> FcpResult<Value> {
        if self
            .config
            .as_ref()
            .is_some_and(|config| config.auth.is_secretless())
        {
            return Ok(json!({
                "status": "degraded",
                "reason_code": "credential_injection_required",
                "message": "Configured with credential_id; this connector slice cannot perform live checks without host-side credential injection."
            }));
        }
        let Some(client) = &self.client else {
            return Ok(json!({
                "status": "degraded",
                "reason_code": "not_configured",
                "message": "Azure Speech is not configured."
            }));
        };
        match client.auth_header(true).await {
            Ok(_) => Ok(json!({
                "status": "ok",
                "auth_mode": client.config.auth.redacted_label(),
                "auth_token_source": client.config.auth.token_source(),
                "auth_token_format": client.config.auth.token_format(),
                "entra_resource_id_hash": client.config.auth.resource_id_hash(),
                "surface_boundary": BOUNDARY,
            })),
            Err(error) => Ok(json!({
                "status": "failed",
                "reason_code": "upstream_token_probe_failed",
                "message": error.to_string(),
            })),
        }
    }

    pub async fn handle_introspect(&self) -> FcpResult<Value> {
        Ok(json!({
            "connector_id": CONNECTOR_ID,
            "version": CONNECTOR_VERSION,
            "operations": operations_info()?,
            "deferred_operations": deferred_operations_info(),
            "events": [],
            "resource_types": [],
            "provider_docs_rechecked": {
                "tts_rest": "https://learn.microsoft.com/en-us/azure/ai-services/speech-service/rest-text-to-speech",
                "stt_rest_overview": DOC_STT_REST_OVERVIEW,
                "stt_fast_2025_10_15": DOC_STT_TRANSCRIBE,
                "stt_batch_submit_2025_10_15": DOC_STT_BATCH_SUBMIT,
                "tts_rest_auth": DOC_TTS_REST_AUTH,
                "stt_2025_10_15_migration": DOC_STT_2025_MIGRATION,
                "custom_speech_project": DOC_CUSTOM_SPEECH_PROJECT,
                "custom_speech_dataset": DOC_CUSTOM_SPEECH_DATASET,
                "custom_speech_model": DOC_CUSTOM_SPEECH_MODEL,
                "custom_speech_endpoint": DOC_CUSTOM_SPEECH_ENDPOINT,
                "custom_speech_projects_api_2025_10_15": DOC_CUSTOM_PROJECTS_API,
                "custom_speech_datasets_api_2025_10_15": DOC_CUSTOM_DATASETS_API,
                "custom_speech_models_api_2025_10_15": DOC_CUSTOM_MODELS_API,
                "custom_speech_endpoints_api_2025_10_15": DOC_CUSTOM_ENDPOINTS_API,
                "entra_auth": DOC_ENTRA_AUTH,
                "managed_identity_vm_token": DOC_MANAGED_IDENTITY_VM_TOKEN,
                "llm_speech_keyless_auth": DOC_LLM_SPEECH_AUTH,
                "tts_text_streaming_sdk": DOC_TTS_TEXT_STREAMING,
                "stt_realtime_sdk": DOC_STT_REALTIME,
                "sdk_connection_reuse": DOC_SDK_CONNECTIONS
            },
            "connector_local_identity_acquisition": connector_local_identity_policy_info(),
            "custom_speech_lifecycle": custom_speech_lifecycle_info()
        }))
    }

    pub async fn handle_invoke(&self, params: Value) -> FcpResult<Value> {
        self.base.check_ready()?;
        let client = self.client.as_ref().ok_or_else(|| FcpError::Internal {
            message: "Azure Speech client not initialized".into(),
        })?;
        let operation = params
            .get("operation_id")
            .or_else(|| params.get("operation"))
            .and_then(Value::as_str)
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing operation_id".into(),
            })?;
        let input = params.get("input").cloned().unwrap_or_else(|| json!({}));
        let capability_token_value =
            params
                .get("capability_token")
                .cloned()
                .ok_or_else(|| FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing capability_token".into(),
                })?;
        let capability_grant = serde_json::from_value::<CapabilityToken>(capability_token_value)
            .map_err(|error| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid capability_token: {error}"),
            })?;
        self.verify_capability(operation, &input, capability_grant)?;
        self.request_count.fetch_add(1, Ordering::Relaxed);
        let result = match operation {
            OP_VOICES_LIST => client.voices_list().await,
            OP_TTS_SYNTHESIZE => client.synthesize(&input).await,
            OP_STT_TRANSCRIBE_FAST => client.transcribe_fast(&input).await,
            OP_STT_BATCH_SUBMIT => client.batch_submit(&input).await,
            OP_STT_BATCH_GET => client.batch_get(&input).await,
            OP_STT_BATCH_FILES => client.batch_files(&input).await,
            _ if CustomSpeechRoute::from_operation(operation).is_some() => {
                client.custom_speech(operation, &input).await
            }
            _ => Err(FcpError::InvalidRequest {
                code: 1002,
                message: format!("Unknown operation: {operation}"),
            }),
        };
        if result.is_err() {
            self.error_count.fetch_add(1, Ordering::Relaxed);
        }
        result
    }

    pub async fn handle_simulate(&self, params: Value) -> FcpResult<Value> {
        let operation = params
            .get("operation_id")
            .or_else(|| params.get("operation"))
            .and_then(Value::as_str)
            .unwrap_or("");
        let supported = OPERATION_ORDER.contains(&operation);
        let blocked_by_secretless_auth = supported
            && self
                .config
                .as_ref()
                .is_some_and(|config| config.auth.is_secretless());
        Ok(json!({
            "allowed": supported,
            "reason": if blocked_by_secretless_auth {
                "Supported through host-side credential injection; direct live Microsoft endpoints require the host to materialize credentials."
            } else if supported {
                "Supported operation."
            } else {
                "Unknown operation."
            }
        }))
    }

    pub async fn handle_shutdown(&mut self, _params: Value) -> FcpResult<Value> {
        if let Some(client) = &self.client {
            client.token_cache.clear();
        }
        self.config = None;
        self.client = None;
        self.verifier = None;
        self.session_id = None;
        self.handshaken = false;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({ "status": "shutdown" }))
    }

    fn verify_capability(
        &self,
        operation: &str,
        input: &Value,
        token: CapabilityToken,
    ) -> FcpResult<()> {
        let verifier = self.verifier.as_ref().ok_or(FcpError::NotHandshaken)?;
        let operation_id: OperationId =
            operation.parse().map_err(|_| FcpError::InvalidRequest {
                code: 1003,
                message: "Invalid operation ID format".into(),
            })?;
        let capability = required_capability(operation)?;
        let resources = resource_uris_for_operation(operation, input);
        verifier
            .verify_bound(token, &capability, &operation_id, &resources)
            .map(|_| ())
    }
}

impl Default for AzureSpeechConnector {
    fn default() -> Self {
        Self::new()
    }
}

fn operations_info() -> FcpResult<Vec<Value>> {
    static OPERATIONS: OnceLock<FcpResult<Vec<Value>>> = OnceLock::new();
    OPERATIONS
        .get_or_init(|| {
            Ok(ordered_manifest_operations()?
                .into_iter()
                .map(|(id, operation)| {
                    let operation_info = operation_info_from_manifest(id, &operation);
                    introspect_operation_from_manifest(operation_info, &operation)
                })
                .collect())
        })
        .clone()
}

fn ordered_manifest_operations() -> FcpResult<Vec<(String, fcp_manifest::OperationSection)>> {
    let manifest =
        ConnectorManifest::parse_str_unchecked(AZURE_SPEECH_MANIFEST_TOML).map_err(|error| {
            FcpError::Internal {
                message: format!("Embedded Azure Speech manifest is invalid: {error}"),
            }
        })?;
    let mut operations: Vec<_> = manifest.provides.operations.into_iter().collect();
    operations.sort_by(|(left, _), (right, _)| {
        operation_order(left)
            .cmp(&operation_order(right))
            .then_with(|| left.cmp(right))
    });
    Ok(operations)
}

fn operation_order(operation_id: &str) -> usize {
    OPERATION_ORDER
        .iter()
        .position(|candidate| *candidate == operation_id)
        .unwrap_or(OPERATION_ORDER.len())
}

fn approval_mode_from_manifest(mode: ManifestApprovalMode) -> Option<ApprovalMode> {
    match mode {
        ManifestApprovalMode::None => None,
        other => Some(ApprovalMode::from(other)),
    }
}

fn introspect_operation_from_manifest(
    operation_info: OperationInfo,
    operation: &fcp_manifest::OperationSection,
) -> Value {
    let mut metadata = serde_json::to_value(operation_info)
        .expect("Azure Speech operation metadata should serialize");
    metadata["requires_approval"] = json!(operation.requires_approval);
    metadata["revocation_freshness"] = json!(operation.revocation_freshness);
    if let Some(network_constraints) = &operation.network_constraints {
        metadata["network_constraints"] = json!(network_constraints);
    }
    metadata
}

fn operation_info_from_manifest(
    id: String,
    operation: &fcp_manifest::OperationSection,
) -> OperationInfo {
    let description = operation.description.clone();
    OperationInfo {
        id: OperationId::new(id).expect("manifest operation id should be canonical"),
        summary: description.clone(),
        description: Some(description),
        input_schema: operation.input_schema.clone(),
        output_schema: operation.output_schema.clone(),
        capability: operation.capability.clone(),
        risk_level: operation.risk_level,
        safety_tier: operation.safety_tier,
        idempotency: operation.idempotency,
        ai_hints: operation.ai_hints.clone(),
        rate_limit: operation
            .rate_limit
            .as_ref()
            .map(|rate_limit| rate_limit.0.clone()),
        requires_approval: approval_mode_from_manifest(operation.requires_approval),
    }
}

fn deferred_operations_info() -> Vec<Value> {
    vec![
        json!({
            "id": "azure.speech.tts.text_stream.websocket",
            "summary": "Azure Speech TTS text streaming over WebSocket v2",
            "outcome": "blocked_official_sdk_only_protocol",
            "tracking_bead": "flywheel_connectors-4kw5f.2.9.6.1.2",
            "host_platform_required": true,
            "rationale": STREAMING_BLOCKER_REASON,
            "official_docs": [DOC_TTS_TEXT_STREAMING, DOC_SDK_CONNECTIONS],
            "implementation_gate": "Do not implement live TTS text streaming until Microsoft documents the direct WebSocket request/response framing or FCP intentionally vendors an SDK-compatible protocol layer."
        }),
        json!({
            "id": "azure.speech.stt.realtime.websocket",
            "summary": "Azure Speech realtime STT WebSocket sessions",
            "outcome": "blocked_official_sdk_only_protocol",
            "tracking_bead": "flywheel_connectors-4kw5f.2.9.6.1.2",
            "host_platform_required": true,
            "rationale": STREAMING_BLOCKER_REASON,
            "official_docs": [DOC_STT_REALTIME, DOC_SDK_CONNECTIONS],
            "implementation_gate": "Do not implement live realtime STT until the direct audio chunk and transcript frame protocol is documented or represented by an approved FCP host-stream adapter."
        }),
        json!({
            "id": "azure.speech.stt.custom_speech.projects",
            "summary": "Azure Speech custom speech project, dataset, model training, and endpoint lifecycle",
            "outcome": "implemented_2025_10_15_create_list_get_delete",
            "tracking_bead": "flywheel_connectors-4kw5f.2.9.6.2",
            "rationale": "The production connector exposes current Speech-to-text REST API 2025-10-15 custom speech project, dataset, model, and endpoint create/list/get/delete operations with api-version pinning, endpoint validation, capability enforcement, and redacted provider outputs. Upload-block, file-download, evaluation, webhook, and model-copy sub-surfaces remain outside this lifecycle slice.",
            "official_docs": [DOC_STT_REST_OVERVIEW, DOC_STT_2025_MIGRATION, DOC_CUSTOM_PROJECTS_API, DOC_CUSTOM_DATASETS_API, DOC_CUSTOM_MODELS_API, DOC_CUSTOM_ENDPOINTS_API],
            "implemented_operations": [
                OP_CUSTOM_PROJECTS_CREATE,
                OP_CUSTOM_PROJECTS_LIST,
                OP_CUSTOM_PROJECTS_GET,
                OP_CUSTOM_PROJECTS_DELETE,
                OP_CUSTOM_DATASETS_CREATE,
                OP_CUSTOM_DATASETS_LIST,
                OP_CUSTOM_DATASETS_GET,
                OP_CUSTOM_DATASETS_DELETE,
                OP_CUSTOM_MODELS_CREATE,
                OP_CUSTOM_MODELS_LIST,
                OP_CUSTOM_MODELS_GET,
                OP_CUSTOM_MODELS_DELETE,
                OP_CUSTOM_ENDPOINTS_CREATE,
                OP_CUSTOM_ENDPOINTS_LIST,
                OP_CUSTOM_ENDPOINTS_GET,
                OP_CUSTOM_ENDPOINTS_DELETE
            ]
        }),
        json!({
            "id": "azure.speech.auth.connector_local_identity",
            "summary": "Connector-local Azure IMDS/MSAL-equivalent identity acquisition",
            "outcome": "host_token_broker_required",
            "tracking_bead": "flywheel_connectors-4kw5f.2.9.6.3",
            "rationale": "Current Microsoft managed identity docs require link-local IMDS HTTP egress to 169.254.169.254 with Metadata:true. FCP runtime network policy only allows local/LAN exceptions as all-local operation policies; Azure Speech operations also require external Microsoft Speech hosts. The safe boundary is therefore host-token-broker acquisition with connector Entra token handoff, not direct connector-local IMDS.",
            "official_docs": [DOC_MANAGED_IDENTITY_VM_TOKEN, DOC_ENTRA_AUTH],
            "implementation_gate": "Do not perform connector-local IMDS/MSAL token acquisition from this connector process unless FCP gains an auth preflight/host-token-broker operation with a separate all-local network policy."
        }),
    ]
}

fn custom_speech_lifecycle_info() -> Value {
    json!({
        "status": "implemented_2025_10_15",
        "tracking_bead": "flywheel_connectors-4kw5f.2.9.6.2",
        "api_version": STT_API_VERSION,
        "operation_families": ["projects", "datasets", "models", "endpoints"],
        "supported_actions": ["create", "list", "get", "delete"],
        "batch_custom_model_boundary": "azure.speech.stt.batch.submit accepts validated project/model/dataset references and sends them to the 2025-10-15 transcriptions:submit API.",
        "official_docs": [
            DOC_STT_REST_OVERVIEW,
            DOC_STT_2025_MIGRATION,
            DOC_CUSTOM_SPEECH_PROJECT,
            DOC_CUSTOM_SPEECH_DATASET,
            DOC_CUSTOM_SPEECH_MODEL,
            DOC_CUSTOM_SPEECH_ENDPOINT,
            DOC_CUSTOM_PROJECTS_API,
            DOC_CUSTOM_DATASETS_API,
            DOC_CUSTOM_MODELS_API,
            DOC_CUSTOM_ENDPOINTS_API
        ],
        "excluded_subsurfaces": [
            "dataset upload blocks and file retrieval",
            "model copy authorization/cross-subscription copy",
            "custom speech evaluations",
            "custom speech web hooks",
            "endpoint logs"
        ],
        "redaction_policy": "Provider self/location/contentUrl values are returned as host/path/query hashes; Azure resource IDs, project IDs, model IDs, SAS URLs, transcripts, audio bytes, provider bodies, and local paths are not logged raw.",
    })
}

fn connector_local_identity_policy_info() -> Value {
    json!({
        "status": "host_token_broker_required",
        "tracking_bead": "flywheel_connectors-4kw5f.2.9.6.3",
        "official_docs": [DOC_MANAGED_IDENTITY_VM_TOKEN, DOC_ENTRA_AUTH],
        "imds": {
            "endpoint_class": "azure_imds_link_local",
            "host_allow": [IMDS_HOST],
            "port_allow": [80],
            "api_version": IMDS_API_VERSION,
            "metadata_header_required": true,
            "target_resource": COGNITIVE_SERVICES_ENTRA_RESOURCE,
        },
        "supported_boundary": "host-provided entra_access_token/aad_access_token or credential_id",
        "host_policy_reason": "Runtime-enforced Azure Speech operations need external Microsoft Speech hosts. Direct IMDS requires a link-local HTTP local/LAN exception, and FCP treats that as a separate all-local policy shape rather than something to mix into every provider operation.",
    })
}

fn streaming_blocker_info() -> Value {
    json!({
        "status": "blocked_official_sdk_only_protocol",
        "reason": STREAMING_BLOCKER_REASON,
        "tts_text_streaming_doc": DOC_TTS_TEXT_STREAMING,
        "stt_realtime_doc": DOC_STT_REALTIME,
        "sdk_connection_doc": DOC_SDK_CONNECTIONS,
    })
}

fn required_capability(operation: &str) -> FcpResult<CapabilityId> {
    match operation {
        OP_VOICES_LIST => Ok(CapabilityId::from_static("azure.speech.voices")),
        OP_TTS_SYNTHESIZE => Ok(CapabilityId::from_static("azure.speech.tts")),
        OP_STT_TRANSCRIBE_FAST | OP_STT_BATCH_SUBMIT | OP_STT_BATCH_GET | OP_STT_BATCH_FILES => {
            Ok(CapabilityId::from_static("azure.speech.stt"))
        }
        _ if CustomSpeechRoute::from_operation(operation).is_some() => {
            Ok(CapabilityId::from_static("azure.speech.stt"))
        }
        _ => Err(FcpError::OperationNotGranted {
            operation: operation.into(),
        }),
    }
}

fn resource_uris_for_operation(operation: &str, input: &Value) -> Vec<String> {
    match operation {
        OP_VOICES_LIST => vec!["azure-speech:voices".into()],
        OP_TTS_SYNTHESIZE => {
            let voice = input
                .get("voice")
                .and_then(Value::as_str)
                .unwrap_or("ssml-provided");
            vec![format!("azure-speech:tts:voice:{voice}")]
        }
        OP_STT_TRANSCRIBE_FAST => {
            let locale = input
                .get("locale")
                .and_then(Value::as_str)
                .or_else(|| {
                    input
                        .get("locales")
                        .and_then(Value::as_array)
                        .and_then(|locales| locales.first())
                        .and_then(Value::as_str)
                })
                .unwrap_or(DEFAULT_STT_LOCALE);
            vec![format!("azure-speech:stt:locale:{locale}")]
        }
        OP_STT_BATCH_SUBMIT => vec!["azure-speech:stt:batch:submit".into()],
        OP_STT_BATCH_GET | OP_STT_BATCH_FILES => {
            let id = input
                .get("transcription_id")
                .and_then(Value::as_str)
                .map_or_else(|| "url-input".into(), |value| sha256_hex(value.as_bytes()));
            vec![format!("azure-speech:stt:batch:{id}")]
        }
        _ => CustomSpeechRoute::from_operation(operation).map_or_else(Vec::new, |route| {
            let id = custom_speech_input_resource_hash(input, route)
                .unwrap_or_else(|| route.action.as_str().to_owned());
            vec![format!(
                "azure-speech:stt:custom:{}:{id}",
                route.kind.as_str()
            )]
        }),
    }
}

fn custom_speech_input_resource_hash(input: &Value, route: CustomSpeechRoute) -> Option<String> {
    input
        .get(route.kind.id_field())
        .and_then(Value::as_str)
        .map(|value| sha256_hex(value.as_bytes()))
        .or_else(|| {
            input
                .get(route.kind.url_field())
                .and_then(Value::as_str)
                .and_then(|raw| Url::parse(raw).ok())
                .and_then(|url| last_path_segment(&url))
                .map(|value| sha256_hex(value.as_bytes()))
        })
}

fn normalize_transcription_result(provider_result: &Value, request: &SttRequest) -> Value {
    let combined_text = provider_result
        .get("combinedPhrases")
        .and_then(Value::as_array)
        .map(|phrases| {
            phrases
                .iter()
                .filter_map(|phrase| phrase.get("text").and_then(Value::as_str))
                .collect::<Vec<_>>()
                .join(" ")
        })
        .filter(|text| !text.trim().is_empty())
        .or_else(|| {
            provider_result
                .get("phrases")
                .and_then(Value::as_array)
                .map(|phrases| {
                    phrases
                        .iter()
                        .filter_map(|phrase| phrase.get("text").and_then(Value::as_str))
                        .collect::<Vec<_>>()
                        .join(" ")
                })
        })
        .unwrap_or_default();
    json!({
        "text": combined_text,
        "duration_milliseconds": provider_result.get("durationMilliseconds").cloned(),
        "combined_phrases": provider_result.get("combinedPhrases").cloned(),
        "phrases": provider_result.get("phrases").cloned(),
        "provider_result": provider_result,
        "audio": {
            "byte_count": request.audio.len(),
            "content_type": request.content_type,
            "sha256": sha256_hex(&request.audio),
        },
        "api_version": STT_API_VERSION,
    })
}

fn validate_region(region: &str) -> FcpResult<()> {
    let valid = region.len() >= 2
        && region.len() <= 64
        && !region.starts_with('-')
        && !region.ends_with('-')
        && region
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
    if valid {
        Ok(())
    } else {
        Err(FcpError::InvalidRequest {
            code: 1003,
            message: "region must be a lowercase Azure region identifier".into(),
        })
    }
}

fn validate_locale(locale: &str) -> FcpResult<()> {
    let valid = locale.len() >= 2
        && locale.len() <= 16
        && locale
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-');
    if valid {
        Ok(())
    } else {
        Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("invalid locale {locale:?}"),
        })
    }
}

fn validate_output_format(output_format: &str) -> FcpResult<()> {
    if TTS_OUTPUT_FORMATS.contains(&output_format) {
        Ok(())
    } else {
        Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("unsupported Azure Speech output_format {output_format:?}"),
        })
    }
}

fn validate_stt_content_type(content_type: &str) -> FcpResult<()> {
    if STT_CONTENT_TYPES.contains(&content_type) {
        Ok(())
    } else {
        Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("unsupported STT content_type {content_type:?}"),
        })
    }
}

fn validate_ssml(ssml: &str) -> FcpResult<()> {
    let mut reader = Reader::from_str(ssml);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();
    let mut first_element: Option<Vec<u8>> = None;
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(start)) => {
                if first_element.is_none() {
                    first_element = Some(start.name().as_ref().to_vec());
                }
            }
            Ok(Event::Empty(empty)) => {
                if first_element.is_none() {
                    first_element = Some(empty.name().as_ref().to_vec());
                }
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(error) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("invalid SSML: {error}"),
                });
            }
        }
        buf.clear();
    }
    if first_element.as_deref() == Some(b"speak") {
        Ok(())
    } else {
        Err(FcpError::InvalidRequest {
            code: 1003,
            message: "SSML root element must be <speak>".into(),
        })
    }
}

fn decode_audio(input: &Value) -> FcpResult<Vec<u8>> {
    let encoded = input
        .get("audio_base64")
        .or_else(|| input.get("audio_b64"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| FcpError::InvalidRequest {
            code: 1003,
            message: "audio_base64 is required".into(),
        })?;
    BASE64_STANDARD
        .decode(encoded)
        .map_err(|error| FcpError::InvalidRequest {
            code: 1003,
            message: format!("audio_base64 is not valid base64: {error}"),
        })
}

fn locales_from_input(input: &Value) -> FcpResult<Vec<String>> {
    if let Some(locales) = input.get("locales").and_then(Value::as_array) {
        let mut values = Vec::with_capacity(locales.len());
        for locale in locales {
            let Some(locale) = locale.as_str() else {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "locales must contain strings".into(),
                });
            };
            validate_locale(locale)?;
            values.push(locale.to_owned());
        }
        if values.is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "locales must not be empty".into(),
            });
        }
        return Ok(values);
    }
    let locale = input
        .get("locale")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(DEFAULT_STT_LOCALE);
    validate_locale(locale)?;
    Ok(vec![locale.to_owned()])
}

fn copy_definition_field(
    definition: &mut Value,
    input: &Value,
    azure_name: &str,
    input_name: &str,
) {
    let Some(value) = input.get(input_name) else {
        return;
    };
    if let Some(object) = definition.as_object_mut() {
        object.insert(azure_name.to_owned(), value.clone());
    }
}

fn copy_optional_string(
    body: &mut serde_json::Map<String, Value>,
    input: &Value,
    azure_name: &str,
    input_name: &str,
) {
    let Some(value) = input
        .get(input_name)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return;
    };
    body.insert(azure_name.to_owned(), json!(value));
}

fn copy_optional_object(
    body: &mut serde_json::Map<String, Value>,
    input: &Value,
    azure_name: &str,
    input_name: &str,
) -> FcpResult<()> {
    let Some(value) = input.get(input_name) else {
        return Ok(());
    };
    if !value.is_object() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{input_name} must be an object"),
        });
    }
    body.insert(azure_name.to_owned(), value.clone());
    Ok(())
}

fn copy_optional_custom_properties(
    body: &mut serde_json::Map<String, Value>,
    input: &Value,
) -> FcpResult<()> {
    let Some(value) = input.get("custom_properties") else {
        return Ok(());
    };
    let Some(properties) = value.as_object() else {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "custom_properties must be an object".into(),
        });
    };
    if properties.len() > 10 {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "custom_properties must contain at most 10 entries".into(),
        });
    }
    for (key, value) in properties {
        if key.is_empty() || key.len() > 64 {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "custom_properties keys must be 1..=64 bytes".into(),
            });
        }
        let Some(text) = value.as_str() else {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "custom_properties values must be strings".into(),
            });
        };
        if text.len() > 256 {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "custom_properties values must be at most 256 bytes".into(),
            });
        }
    }
    body.insert("customProperties".into(), value.clone());
    Ok(())
}

fn copy_optional_reference_object(
    body: &mut serde_json::Map<String, Value>,
    input: &Value,
    field: &str,
    kind: CustomSpeechResourceKind,
    base: &Url,
) -> FcpResult<()> {
    let object = reference_object_from_input(input, field, kind, base)?;
    if let Some(object) = object {
        body.insert(field.to_owned(), object);
    }
    Ok(())
}

fn copy_optional_reference_object_as(
    body: &mut serde_json::Map<String, Value>,
    input: &Value,
    azure_field: &str,
    input_field: &str,
    kind: CustomSpeechResourceKind,
    base: &Url,
) -> FcpResult<()> {
    let object = reference_object_from_input(input, input_field, kind, base)?;
    if let Some(object) = object {
        body.insert(azure_field.to_owned(), object);
    }
    Ok(())
}

fn reference_object_from_input(
    input: &Value,
    field: &str,
    kind: CustomSpeechResourceKind,
    base: &Url,
) -> FcpResult<Option<Value>> {
    if let Some(value) = input.get(field) {
        return normalize_reference_object(value, field, kind, base).map(Some);
    }
    let id_field = format!("{field}_id");
    if let Some(id) = input
        .get(&id_field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        let url = custom_speech_resource_url_from_id(id, kind, base)?;
        return Ok(Some(json!({ "self": url.as_str() })));
    }
    let url_field = format!("{field}_url");
    if let Some(url) = input
        .get(&url_field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        let url = normalize_custom_speech_resource_url(url, base, kind, &url_field)?;
        return Ok(Some(json!({ "self": url.as_str() })));
    }
    Ok(None)
}

fn normalize_reference_object(
    value: &Value,
    field: &str,
    kind: CustomSpeechResourceKind,
    base: &Url,
) -> FcpResult<Value> {
    let Some(object) = value.as_object() else {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{field} must be an object"),
        });
    };
    let mut normalized = object.clone();
    if let Some(self_url) = object.get("self").and_then(Value::as_str) {
        let url = normalize_custom_speech_resource_url(self_url, base, kind, field)?;
        normalized.insert("self".into(), json!(url.as_str()));
    } else {
        let id_field = format!("{field}_id");
        if let Some(id) = object
            .get("id")
            .or_else(|| object.get(&id_field))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            let url = custom_speech_resource_url_from_id(id, kind, base)?;
            normalized.insert("self".into(), json!(url.as_str()));
        } else {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!("{field} must include self or id"),
            });
        }
    }
    Ok(Value::Object(normalized))
}

fn custom_speech_collection_url(
    base: &Url,
    kind: CustomSpeechResourceKind,
    input: &Value,
) -> FcpResult<Url> {
    let mut url = base.clone();
    url.set_path(kind.collection_path());
    let mut pairs = vec![("api-version".to_string(), STT_API_VERSION.to_string())];
    copy_query_integer(input, &mut pairs, "skip", "skip")?;
    copy_query_integer(input, &mut pairs, "top", "top")?;
    if let Some(filter) = input
        .get("filter")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        validate_filter(filter)?;
        pairs.push(("filter".into(), filter.to_owned()));
    }
    url.query_pairs_mut().clear().extend_pairs(pairs);
    Ok(url)
}

fn custom_speech_resource_url_from_input(
    input: &Value,
    kind: CustomSpeechResourceKind,
    base: &Url,
) -> FcpResult<Url> {
    if let Some(raw) = input
        .get(kind.url_field())
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return normalize_custom_speech_resource_url(raw, base, kind, kind.url_field());
    }
    let id = required_string(input, kind.id_field())?;
    custom_speech_resource_url_from_id(id, kind, base)
}

fn custom_speech_resource_url_from_id(
    id: &str,
    kind: CustomSpeechResourceKind,
    base: &Url,
) -> FcpResult<Url> {
    validate_custom_speech_resource_id(id, kind.id_field())?;
    let mut url = base.clone();
    url.set_path(&format!("{}/{}", kind.collection_path(), id));
    url.set_query(Some(&format!("api-version={STT_API_VERSION}")));
    Ok(url)
}

fn normalize_custom_speech_resource_url(
    raw: &str,
    base: &Url,
    kind: CustomSpeechResourceKind,
    label: &str,
) -> FcpResult<Url> {
    let mut parsed = Url::parse(raw).map_err(|error| FcpError::InvalidRequest {
        code: 1003,
        message: format!("{label} is invalid: {error}"),
    })?;
    if parsed.scheme() != base.scheme() || host(&parsed) != host(base) {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{label} must use the configured Azure Speech STT host"),
        });
    }
    if parsed.path().contains("/speechtotext/v3.") || parsed.path().contains("/speechtotext/v3/") {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{label} must not use retired v3.x Speech-to-text URLs"),
        });
    }
    let prefix = format!("{}/", kind.collection_path());
    if !parsed.path().starts_with(&prefix) {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{label} must point at {prefix}{{id}}"),
        });
    }
    let suffix = &parsed.path()[prefix.len()..];
    if suffix.is_empty() || suffix.contains('/') {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{label} must identify exactly one {}", kind.as_str()),
        });
    }
    validate_custom_speech_resource_id(suffix, kind.id_field())?;
    for (key, value) in parsed.query_pairs() {
        if key == "api-version" && value != STT_API_VERSION {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!("{label} api-version must be {STT_API_VERSION}"),
            });
        }
    }
    parsed.set_query(Some(&format!("api-version={STT_API_VERSION}")));
    Ok(parsed)
}

fn build_custom_speech_create_body(
    input: &Value,
    kind: CustomSpeechResourceKind,
    base: &Url,
) -> FcpResult<Value> {
    let display_name = required_string(input, "display_name")?;
    let locale = input
        .get("locale")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(DEFAULT_STT_LOCALE);
    validate_locale(locale)?;
    let mut body = serde_json::Map::new();
    body.insert("displayName".into(), json!(display_name));
    body.insert("locale".into(), json!(locale));
    copy_optional_string(&mut body, input, "description", "description");
    copy_optional_custom_properties(&mut body, input)?;
    copy_optional_object(&mut body, input, "properties", "properties")?;
    match kind {
        CustomSpeechResourceKind::Project => {
            copy_optional_string(
                &mut body,
                input,
                "foundryProjectName",
                "foundry_project_name",
            );
        }
        CustomSpeechResourceKind::Dataset => {
            let dataset_kind = required_string(input, "kind")?;
            validate_dataset_kind(dataset_kind)?;
            body.insert("kind".into(), json!(dataset_kind));
            copy_optional_content_url(&mut body, input)?;
            copy_optional_reference_object(
                &mut body,
                input,
                "project",
                CustomSpeechResourceKind::Project,
                base,
            )?;
        }
        CustomSpeechResourceKind::Model => {
            copy_optional_reference_object(
                &mut body,
                input,
                "project",
                CustomSpeechResourceKind::Project,
                base,
            )?;
            copy_optional_reference_object_as(
                &mut body,
                input,
                "baseModel",
                "base_model",
                CustomSpeechResourceKind::Model,
                base,
            )?;
            copy_optional_reference_array(
                &mut body,
                input,
                "datasets",
                CustomSpeechResourceKind::Dataset,
                base,
            )?;
        }
        CustomSpeechResourceKind::Endpoint => {
            copy_required_reference_object(
                &mut body,
                input,
                "model",
                CustomSpeechResourceKind::Model,
                base,
            )?;
            copy_optional_reference_object(
                &mut body,
                input,
                "project",
                CustomSpeechResourceKind::Project,
                base,
            )?;
            copy_optional_string(&mut body, input, "text", "text");
        }
    }
    Ok(Value::Object(body))
}

fn copy_optional_content_url(
    body: &mut serde_json::Map<String, Value>,
    input: &Value,
) -> FcpResult<()> {
    if let Some(url) = input
        .get("content_url")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        validate_external_https_url(url, "content_url")?;
        body.insert("contentUrl".into(), json!(url));
    }
    Ok(())
}

fn copy_required_reference_object(
    body: &mut serde_json::Map<String, Value>,
    input: &Value,
    field: &str,
    kind: CustomSpeechResourceKind,
    base: &Url,
) -> FcpResult<()> {
    let Some(object) = reference_object_from_input(input, field, kind, base)? else {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{field} reference is required"),
        });
    };
    body.insert(field.to_owned(), object);
    Ok(())
}

fn copy_optional_reference_array(
    body: &mut serde_json::Map<String, Value>,
    input: &Value,
    field: &str,
    kind: CustomSpeechResourceKind,
    base: &Url,
) -> FcpResult<()> {
    let Some(values) = input.get(field).and_then(Value::as_array) else {
        return Ok(());
    };
    if values.is_empty() || values.len() > 32 {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{field} must contain 1..=32 references"),
        });
    }
    let mut normalized = Vec::with_capacity(values.len());
    for value in values {
        normalized.push(normalize_reference_object(value, field, kind, base)?);
    }
    body.insert(field.to_owned(), Value::Array(normalized));
    Ok(())
}

fn validate_dataset_kind(kind: &str) -> FcpResult<()> {
    let allowed = [
        "Acoustic",
        "AudioFiles",
        "Language",
        "LanguageMarkdown",
        "OutputFormatting",
        "Pronunciation",
    ];
    if allowed.contains(&kind) {
        Ok(())
    } else {
        Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("unsupported custom speech dataset kind {kind:?}"),
        })
    }
}

fn validate_custom_speech_resource_id(id: &str, label: &str) -> FcpResult<()> {
    let valid = !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'));
    if valid {
        Ok(())
    } else {
        Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{label} must be a non-empty Azure Speech resource identifier"),
        })
    }
}

fn validate_filter(filter: &str) -> FcpResult<()> {
    if filter.len() <= 512 && !filter.contains(['\r', '\n']) {
        Ok(())
    } else {
        Err(FcpError::InvalidRequest {
            code: 1003,
            message: "filter must be at most 512 bytes and contain no control newlines".into(),
        })
    }
}

fn validated_url_array(
    values: &[Value],
    label: &str,
    min: usize,
    max: usize,
) -> FcpResult<Vec<String>> {
    if values.len() < min || values.len() > max {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{label} must contain between {min} and {max} URLs"),
        });
    }
    let mut urls = Vec::with_capacity(values.len());
    for value in values {
        let Some(url) = value
            .as_str()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!("{label} entries must be non-empty strings"),
            });
        };
        validate_external_https_url(url, label)?;
        urls.push(url.to_owned());
    }
    Ok(urls)
}

fn validate_external_https_url(url: &str, label: &str) -> FcpResult<()> {
    let parsed = Url::parse(url).map_err(|error| FcpError::InvalidRequest {
        code: 1003,
        message: format!("{label} contains an invalid URL: {error}"),
    })?;
    if parsed.scheme() != "https" {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{label} URLs must use https"),
        });
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{label} URLs must not contain embedded credentials"),
        });
    }
    if parsed.fragment().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{label} URLs must not contain fragments"),
        });
    }
    Ok(())
}

fn copy_query_integer(
    input: &Value,
    pairs: &mut Vec<(String, String)>,
    input_name: &str,
    query_name: &str,
) -> FcpResult<()> {
    let Some(value) = input.get(input_name) else {
        return Ok(());
    };
    let value = value.as_u64().ok_or_else(|| FcpError::InvalidRequest {
        code: 1003,
        message: format!("{input_name} must be a non-negative integer"),
    })?;
    pairs.push((query_name.to_owned(), value.to_string()));
    Ok(())
}

fn normalize_transcription_resource_url(raw: &str, base: &Url) -> FcpResult<Url> {
    let mut parsed = Url::parse(raw).map_err(|error| FcpError::InvalidRequest {
        code: 1003,
        message: format!("transcription_url is invalid: {error}"),
    })?;
    if parsed.scheme() != base.scheme() || host(&parsed) != host(base) {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "transcription_url must use the configured Azure Speech STT host".into(),
        });
    }
    if parsed.path().contains("/speechtotext/v3.") || parsed.path().contains("/speechtotext/v3/") {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "retired v3.x Speech-to-text transcription URLs are not accepted".into(),
        });
    }
    if !parsed.path().starts_with("/speechtotext/transcriptions/") {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "transcription_url must point at /speechtotext/transcriptions/{id}".into(),
        });
    }
    if parsed.path().contains("/files") {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "transcription_url must identify the transcription; files are requested by azure.speech.stt.batch.files".into(),
        });
    }
    for (key, value) in parsed.query_pairs() {
        if key == "api-version" && value != STT_API_VERSION {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!("transcription_url api-version must be {STT_API_VERSION}"),
            });
        }
    }
    parsed.set_query(Some(&format!("api-version={STT_API_VERSION}")));
    Ok(parsed)
}

fn validate_transcription_id(transcription_id: &str) -> FcpResult<()> {
    let valid = transcription_id.len() <= 128
        && !transcription_id.is_empty()
        && transcription_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() || byte == b'-');
    if valid {
        Ok(())
    } else {
        Err(FcpError::InvalidRequest {
            code: 1003,
            message: "transcription_id must be a non-empty UUID-style identifier".into(),
        })
    }
}

fn batch_content_source_input(input: &Value) -> FcpResult<BatchContentSourceInput<'_>> {
    let content_urls = input.get("content_urls").and_then(Value::as_array);
    let content_container_url = input
        .get("content_container_url")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());

    match (content_urls, content_container_url) {
        (Some(urls), None) => Ok(BatchContentSourceInput::Urls(urls)),
        (None, Some(url)) => Ok(BatchContentSourceInput::ContainerUrl(url)),
        (Some(_), Some(_)) => Err(FcpError::InvalidRequest {
            code: 1003,
            message: "Provide exactly one of content_urls or content_container_url".into(),
        }),
        (None, None) => Err(FcpError::InvalidRequest {
            code: 1003,
            message: "content_urls or content_container_url is required".into(),
        }),
    }
}

fn append_batch_content_source(
    body: &mut serde_json::Map<String, Value>,
    source: BatchContentSourceInput<'_>,
) -> FcpResult<Value> {
    match source {
        BatchContentSourceInput::Urls(urls) => {
            let urls = validated_url_array(urls, "content_urls", 1, 1000)?;
            let url_hashes = urls
                .iter()
                .map(|url| sha256_hex(url.as_bytes()))
                .collect::<Vec<_>>();
            let count = urls.len();
            body.insert("contentUrls".into(), json!(urls));
            Ok(json!({
                "mode": "content_urls",
                "count": count,
                "url_hashes": url_hashes
            }))
        }
        BatchContentSourceInput::ContainerUrl(url) => {
            validate_external_https_url(url, "content_container_url")?;
            body.insert("contentContainerUrl".into(), json!(url));
            Ok(json!({
                "mode": "content_container_url",
                "url": url_descriptor(url),
            }))
        }
    }
}

fn batch_properties_from_input(input: &Value) -> FcpResult<Value> {
    let mut properties = input
        .get("properties")
        .cloned()
        .unwrap_or_else(|| json!({}));
    if !properties.is_object() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "properties must be an object".into(),
        });
    }
    copy_definition_field(
        &mut properties,
        input,
        "wordLevelTimestampsEnabled",
        "word_level_timestamps_enabled",
    );
    copy_definition_field(
        &mut properties,
        input,
        "displayFormWordLevelTimestampsEnabled",
        "display_form_word_level_timestamps_enabled",
    );
    copy_definition_field(
        &mut properties,
        input,
        "punctuationMode",
        "punctuation_mode",
    );
    copy_definition_field(
        &mut properties,
        input,
        "profanityFilterMode",
        "profanity_filter_mode",
    );
    copy_definition_field(
        &mut properties,
        input,
        "timeToLiveHours",
        "time_to_live_hours",
    );
    copy_definition_field(&mut properties, input, "channels", "channels");
    copy_definition_field(&mut properties, input, "diarization", "diarization");
    copy_definition_field(
        &mut properties,
        input,
        "languageIdentification",
        "language_identification",
    );
    Ok(properties)
}

fn transcription_id_hash_from_value(value: &Value) -> Value {
    value
        .get("self")
        .and_then(Value::as_str)
        .and_then(|url| Url::parse(url).ok())
        .and_then(|url| transcription_id_from_url(&url))
        .map_or(Value::Null, |id| json!(sha256_hex(id.as_bytes())))
}

fn resource_id_hash_from_value(value: &Value) -> Value {
    value
        .get("self")
        .and_then(Value::as_str)
        .and_then(|url| Url::parse(url).ok())
        .and_then(|url| last_path_segment(&url))
        .map_or(Value::Null, |id| json!(sha256_hex(id.as_bytes())))
}

fn model_id_hash_for_result(kind: CustomSpeechResourceKind, value: &Value) -> Value {
    if kind == CustomSpeechResourceKind::Model {
        return resource_id_hash_from_value(value);
    }
    value
        .get("model")
        .and_then(|model| model.get("self"))
        .and_then(Value::as_str)
        .and_then(|url| Url::parse(url).ok())
        .and_then(|url| last_path_segment(&url))
        .map_or(Value::Null, |id| json!(sha256_hex(id.as_bytes())))
}

fn project_id_hash_for_result(kind: CustomSpeechResourceKind, value: &Value) -> Value {
    if kind == CustomSpeechResourceKind::Project {
        return resource_id_hash_from_value(value);
    }
    value
        .get("project")
        .and_then(|project| project.get("self"))
        .and_then(Value::as_str)
        .and_then(|url| Url::parse(url).ok())
        .and_then(|url| last_path_segment(&url))
        .map_or(Value::Null, |id| json!(sha256_hex(id.as_bytes())))
}

fn transcription_id_from_url(url: &Url) -> Option<String> {
    let mut segments = url.path_segments()?;
    while let Some(segment) = segments.next() {
        if segment == "transcriptions" {
            return segments.next().map(ToOwned::to_owned);
        }
    }
    None
}

fn last_path_segment(url: &Url) -> Option<String> {
    url.path_segments()
        .and_then(Iterator::last)
        .filter(|segment| !segment.is_empty())
        .map(ToOwned::to_owned)
}

fn sanitize_provider_urls(value: &Value) -> Value {
    match value {
        Value::String(text) => Url::parse(text)
            .ok()
            .filter(|url| matches!(url.scheme(), "http" | "https"))
            .map_or_else(
                || Value::String(text.clone()),
                |url| url_descriptor(url.as_str()),
            ),
        Value::Array(values) => Value::Array(values.iter().map(sanitize_provider_urls).collect()),
        Value::Object(object) => {
            let sanitized = object
                .iter()
                .map(|(key, value)| (key.clone(), sanitize_provider_urls(value)))
                .collect();
            Value::Object(sanitized)
        }
        other => other.clone(),
    }
}

fn url_descriptor(raw: &str) -> Value {
    let parsed = Url::parse(raw);
    let host = parsed
        .as_ref()
        .ok()
        .and_then(Url::host_str)
        .unwrap_or("unparseable");
    let path = parsed.as_ref().map_or("", Url::path);
    json!({
        "redacted": true,
        "host": host,
        "path_sha256": sha256_hex(path.as_bytes()),
        "query_redacted": parsed.as_ref().is_ok_and(|url| url.query().is_some()),
        "url_sha256": sha256_hex(raw.as_bytes()),
    })
}

fn required_string<'a>(input: &'a Value, field: &str) -> FcpResult<&'a str> {
    input
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| FcpError::InvalidRequest {
            code: 1003,
            message: format!("{field} is required"),
        })
}

fn optional_config_string(input: &Value, field: &str) -> Option<String> {
    input
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn optional_config_bool(input: &Value, field: &str) -> FcpResult<Option<bool>> {
    let Some(value) = input.get(field) else {
        return Ok(None);
    };
    match value {
        Value::Bool(flag) => Ok(Some(*flag)),
        Value::String(text) => match text.trim() {
            "true" | "1" | "yes" => Ok(Some(true)),
            "false" | "0" | "no" => Ok(Some(false)),
            _ => Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!("{field} must be a boolean"),
            }),
        },
        _ => Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{field} must be a boolean"),
        }),
    }
}

fn connector_local_identity_source_requested(params: &Value) -> bool {
    let source = params
        .get("entra_token_source")
        .and_then(Value::as_str)
        .map(str::trim);
    match source {
        Some("connector_local_managed_identity" | "connector-local-managed-identity" | "imds") => {
            true
        }
        Some("managed_identity" | "managed-identity")
            if optional_config_string(params, "entra_access_token")
                .or_else(|| optional_config_string(params, "aad_access_token"))
                .is_none() =>
        {
            true
        }
        _ => false,
    }
}

fn bounded_usize(
    value: Option<&Value>,
    label: &str,
    default: usize,
    min: usize,
    max: usize,
) -> FcpResult<usize> {
    let Some(value) = value else {
        return Ok(default);
    };
    let raw = value.as_u64().ok_or_else(|| FcpError::InvalidRequest {
        code: 1003,
        message: format!("{label} must be an integer"),
    })?;
    let value = usize::try_from(raw).map_err(|_| FcpError::InvalidRequest {
        code: 1003,
        message: format!("{label} is too large"),
    })?;
    if value < min || value > max {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{label} must be between {min} and {max}"),
        });
    }
    Ok(value)
}

fn request_timeout_ms(params: &Value) -> FcpResult<u64> {
    let value = bounded_usize(
        params.get("request_timeout_ms"),
        "request_timeout_ms",
        DEFAULT_REQUEST_TIMEOUT_MS,
        100,
        300_000,
    )?;
    Ok(u64::try_from(value).expect("bounded request timeout fits in u64"))
}

fn entra_token_expires_at(params: &Value) -> FcpResult<Option<Instant>> {
    let Some(value) = params.get("entra_token_expires_in_seconds") else {
        return Ok(None);
    };
    let seconds = value.as_u64().ok_or_else(|| FcpError::InvalidRequest {
        code: 1003,
        message: "entra_token_expires_in_seconds must be an integer".into(),
    })?;
    Ok(Some(Instant::now() + Duration::from_secs(seconds)))
}

fn normalize_base_url<F>(
    override_value: Option<&str>,
    default_value: &str,
    label: &str,
    allowed: F,
) -> FcpResult<String>
where
    F: FnOnce(&Url) -> bool,
{
    normalize_absolute_url(override_value, default_value, label, allowed, false)
}

fn normalize_absolute_url<F>(
    override_value: Option<&str>,
    default_value: &str,
    label: &str,
    allowed: F,
    allow_path: bool,
) -> FcpResult<String>
where
    F: FnOnce(&Url) -> bool,
{
    let candidate = override_value
        .unwrap_or(default_value)
        .trim()
        .trim_end_matches('/');
    let parsed = Url::parse(candidate).map_err(|error| FcpError::InvalidRequest {
        code: 1003,
        message: format!("Invalid {label}: {error}"),
    })?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{label} must not include embedded credentials"),
        });
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{label} must not include query or fragment"),
        });
    }
    if !allow_path && parsed.path() != "/" && !parsed.path().is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{label} must not include a path"),
        });
    }
    let loopback = is_loopback_url(&parsed);
    if parsed.scheme() != "https" && !(loopback && parsed.scheme() == "http") {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{label} must use https, except http loopback for tests"),
        });
    }
    if !loopback && parsed.port_or_known_default() != Some(443) {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{label} must resolve to port 443"),
        });
    }
    if !allowed(&parsed) {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{label} host is not allowed"),
        });
    }
    Ok(parsed.to_string().trim_end_matches('/').to_string())
}

fn is_loopback_url(url: &Url) -> bool {
    matches!(host(url), "localhost" | "127.0.0.1" | "::1") || host(url).ends_with(".localhost")
}

fn host(url: &Url) -> &str {
    url.host_str().unwrap_or("")
}

fn host_from_url(url: &str) -> String {
    Url::parse(url)
        .ok()
        .and_then(|parsed| parsed.host_str().map(ToOwned::to_owned))
        .unwrap_or_default()
}

fn safe_header_value(label: &str, value: &str) -> FcpResult<HeaderValue> {
    HeaderValue::from_str(value).map_err(|error| FcpError::InvalidRequest {
        code: 1003,
        message: format!("{label} cannot be represented as a safe HTTP header: {error}"),
    })
}

fn validate_azure_resource_id(resource_id: &str) -> FcpResult<&str> {
    let normalized = resource_id.trim();
    if normalized != resource_id || normalized.is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "entra_resource_id must be a non-empty trimmed Azure resource ID".into(),
        });
    }
    if resource_id.contains('\r') || resource_id.contains('\n') {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "entra_resource_id must not contain control newlines".into(),
        });
    }
    let lower = resource_id.to_ascii_lowercase();
    if !lower.starts_with("/subscriptions/")
        || !lower.contains("/resourcegroups/")
        || !lower.contains("/providers/microsoft.cognitiveservices/accounts/")
    {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message:
                "entra_resource_id must identify a Microsoft.CognitiveServices account resource"
                    .into(),
        });
    }
    Ok(resource_id)
}

fn validate_managed_identity_resource(resource: &str) -> FcpResult<()> {
    let normalized = resource.trim();
    if normalized != resource || normalized.is_empty() || resource.contains(['\r', '\n']) {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "managed_identity_resource must be a non-empty trimmed URI without newlines"
                .into(),
        });
    }
    let parsed = Url::parse(resource).map_err(|error| FcpError::InvalidRequest {
        code: 1003,
        message: format!("managed_identity_resource must be an absolute URI: {error}"),
    })?;
    if parsed.scheme() != "https" {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "managed_identity_resource must use https".into(),
        });
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "managed_identity_resource must not include query or fragment".into(),
        });
    }
    Ok(())
}

fn validate_managed_identity_selector(label: &str, value: &str) -> FcpResult<()> {
    if value.trim() != value || value.is_empty() || value.len() > 512 {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{label} must be non-empty, trimmed, and at most 512 bytes"),
        });
    }
    if value.contains(['\r', '\n']) {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{label} must not contain control newlines"),
        });
    }
    Ok(())
}

fn redact_identifier(value: &str) -> String {
    let mut chars = value.chars();
    let prefix: String = chars.by_ref().take(8).collect();
    if chars.next().is_some() {
        format!("{prefix}...")
    } else {
        "[REDACTED]".into()
    }
}

fn bearer_header(token: &str) -> FcpResult<HeaderValue> {
    HeaderValue::from_str(&format!("Bearer {token}")).map_err(|error| FcpError::InvalidRequest {
        code: 1003,
        message: format!(
            "Azure Speech token cannot be represented as a safe Authorization header: {error}"
        ),
    })
}

fn with_header(request: RequestBuilder, name: HeaderName, value: &HeaderValue) -> RequestBuilder {
    let mut outbound_map = HeaderMap::new();
    outbound_map.insert(name, value.clone());
    request.headers(outbound_map)
}

fn map_reqwest(error: &reqwest::Error) -> FcpError {
    if error.is_timeout() {
        FcpError::UpstreamTimeout {
            service: "azure-speech".into(),
        }
    } else {
        FcpError::External {
            service: "azure-speech".into(),
            message: error.to_string(),
            status_code: error.status().map(|status| status.as_u16()),
            retryable: error.is_connect() || error.is_timeout(),
            retry_after: None,
        }
    }
}

fn provider_error(operation: &str, status: StatusCode, response: &Response) -> FcpError {
    let retryable = is_retryable_status(status);
    let retry_after = retry_after_ms(response).map(Duration::from_millis);
    if status == StatusCode::TOO_MANY_REQUESTS {
        FcpError::RateLimited {
            retry_after_ms: retry_after.map_or(30_000, |duration| {
                duration.as_millis().try_into().unwrap_or(30_000)
            }),
            violation: None,
        }
    } else {
        FcpError::External {
            service: format!("azure-speech.{operation}"),
            message: format!(
                "Azure Speech provider returned HTTP {} for {operation}; provider response body redacted",
                status.as_u16()
            ),
            status_code: Some(status.as_u16()),
            retryable,
            retry_after,
        }
    }
}

fn is_retryable_status(status: StatusCode) -> bool {
    status == StatusCode::REQUEST_TIMEOUT
        || status == StatusCode::TOO_MANY_REQUESTS
        || status.is_server_error()
}

fn retry_after_ms(response: &Response) -> Option<u64> {
    response
        .headers()
        .get("retry-after-ms")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse().ok())
        .or_else(|| {
            response
                .headers()
                .get("retry-after")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<u64>().ok())
                .map(|seconds| seconds.saturating_mul(1_000))
        })
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn azure_speech_manifest_hash() -> String {
    format!(
        "sha256:{}",
        sha256_hex(AZURE_SPEECH_MANIFEST_TOML.as_bytes())
    )
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_RESOURCE_ID: &str = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts/speech";

    #[test]
    fn handshake_manifest_hash_tracks_bundled_manifest() {
        let expected = format!(
            "sha256:{}",
            sha256_hex(AZURE_SPEECH_MANIFEST_TOML.as_bytes())
        );

        assert_eq!(azure_speech_manifest_hash(), expected);
        assert_ne!(
            azure_speech_manifest_hash(),
            "sha256:azure-speech-connector-v1"
        );
    }

    #[test]
    fn region_validation_rejects_url_like_values() {
        assert!(validate_region("eastus").is_ok());
        assert!(validate_region("westus2").is_ok());
        assert!(validate_region("https://eastus").is_err());
        assert!(validate_region("EastUS").is_err());
    }

    #[test]
    fn config_builds_public_regional_allowlist_without_secret_leakage() {
        let config = AzureSpeechConfig::from_params(&json!({
            "subscription_key": "secret-key",
            "region": "eastus",
        }))
        .expect("config should parse");
        assert_eq!(config.auth.redacted_label(), "subscription_key");
        assert_eq!(
            config.host_allowlist(),
            vec![
                "eastus.api.cognitive.microsoft.com".to_string(),
                "eastus.tts.speech.microsoft.com".to_string(),
            ]
        );
        assert!(!format!("{config:?}").contains("secret-key"));
    }

    #[test]
    fn config_builds_entra_aad_auth_without_secret_leakage() {
        let config = AzureSpeechConfig::from_params(&json!({
            "entra_access_token": "secret-aad-token",
            "entra_resource_id": TEST_RESOURCE_ID,
            "entra_token_source": "managed_identity",
            "region": "eastus",
        }))
        .expect("config should parse");
        assert_eq!(config.auth.redacted_label(), "entra_access_token");
        assert_eq!(config.auth.token_source(), Some("managed_identity"));
        assert_eq!(config.auth.token_format(), Some("aad_resource_token"));
        assert_eq!(
            config.auth.resource_id_hash(),
            Some(sha256_hex(TEST_RESOURCE_ID.as_bytes()).as_str())
        );
        let debug = format!("{config:?}");
        assert!(!debug.contains("secret-aad-token"));
        assert!(!debug.contains(TEST_RESOURCE_ID));
    }

    #[test]
    fn connector_local_identity_request_builds_imds_url_without_leakage() {
        let request = ConnectorLocalIdentityRequest::from_params(&json!({
            "connector_local_identity": true,
            "managed_identity_client_id": "11111111-2222-3333-4444-555555555555",
            "managed_identity_resource": COGNITIVE_SERVICES_ENTRA_RESOURCE,
            "region": "eastus",
        }))
        .expect("request parsing should succeed")
        .expect("connector-local identity should be requested");

        assert_eq!(request.host_allowlist(), vec![IMDS_HOST.to_string()]);
        assert_eq!(request.selector_class(), "client_id");
        assert_eq!(
            request.resource_id_hash(),
            sha256_hex(COGNITIVE_SERVICES_ENTRA_RESOURCE.as_bytes())
        );
        let url = request.request_url();
        assert_eq!(url.scheme(), "http");
        assert_eq!(url.host_str(), Some(IMDS_HOST));
        let pairs = url.query_pairs().collect::<Vec<_>>();
        assert!(
            pairs
                .iter()
                .any(|(key, value)| { key == "api-version" && value == IMDS_API_VERSION })
        );
        assert!(pairs.iter().any(|(key, value)| {
            key == "resource" && value == COGNITIVE_SERVICES_ENTRA_RESOURCE
        }));
        assert!(pairs.iter().any(|(key, value)| {
            key == "client_id" && value == "11111111-2222-3333-4444-555555555555"
        }));
        let debug = format!("{request:?}");
        assert!(!debug.contains("11111111-2222-3333-4444-555555555555"));
        assert!(!debug.contains(COGNITIVE_SERVICES_ENTRA_RESOURCE));
    }

    #[test]
    fn config_rejects_connector_local_identity_with_host_policy_guidance() {
        let error = AzureSpeechConfig::from_params(&json!({
            "connector_local_identity": true,
            "managed_identity_client_id": "11111111-2222-3333-4444-555555555555",
            "region": "eastus",
        }))
        .expect_err("connector-local IMDS should be rejected by policy");
        let message = error.to_string();
        assert!(message.contains("host-provided entra_access_token"));
        assert!(message.contains("runtime network policy"));
        assert!(!message.contains("11111111-2222-3333-4444-555555555555"));
    }

    #[test]
    fn config_rejects_ambiguous_or_invalid_enterprise_auth() {
        let both = AzureSpeechConfig::from_params(&json!({
            "subscription_key": "secret-key",
            "entra_access_token": "secret-aad-token",
            "region": "eastus",
        }));
        assert!(both.is_err());

        let missing_resource = AzureSpeechConfig::from_params(&json!({
            "entra_access_token": "secret-aad-token",
            "entra_token_format": "aad_resource_token",
            "region": "eastus",
        }));
        assert!(missing_resource.is_err());

        let invalid_resource = AzureSpeechConfig::from_params(&json!({
            "entra_access_token": "secret-aad-token",
            "entra_resource_id": "/subscriptions/not-a-speech-resource",
            "region": "eastus",
        }));
        assert!(invalid_resource.is_err());

        let ambiguous_connector_local = AzureSpeechConfig::from_params(&json!({
            "entra_access_token": "secret-aad-token",
            "connector_local_identity": true,
            "region": "eastus",
        }));
        assert!(ambiguous_connector_local.is_err());
    }

    #[test]
    fn token_cache_refreshes_after_nine_minutes() {
        let cache = TokenCache::default();
        let issued_at = Instant::now();
        cache.store(HeaderValue::from_static("Bearer token"), issued_at);
        assert!(
            cache
                .get_fresh_at(issued_at + Duration::from_secs(8 * 60))
                .is_some()
        );
        assert!(
            cache
                .get_fresh_at(issued_at + Duration::from_secs(9 * 60 + 1))
                .is_none()
        );
    }

    #[test]
    fn expired_entra_token_requires_host_refresh() {
        let config = AzureSpeechConfig::from_params(&json!({
            "entra_access_token": "expired-token",
            "entra_token_format": "bearer_token",
            "entra_token_expires_in_seconds": 0,
            "region": "eastus",
        }))
        .expect("expired token config should parse so invoke can report refresh guidance");
        let error = config
            .auth
            .direct_header()
            .expect_err("expired token should not produce an auth header");
        assert!(error.to_string().contains("expired"));
    }

    #[test]
    fn tts_request_accepts_text_or_ssml_and_validates_output_format() {
        let request = TtsRequest::from_input(
            &json!({
                "text": "hello <world>",
                "voice": "en-US-ChristopherNeural",
                "locale": "en-US",
                "output_format": "riff-24khz-16bit-mono-pcm"
            }),
            DEFAULT_INLINE_AUDIO_MAX_BYTES,
        )
        .expect("text input should build SSML");
        assert!(request.ssml.contains("&lt;world&gt;"));
        assert!(TtsRequest::from_input(&json!({"ssml":"<speak></speak>"}), 128).is_ok());
        assert!(
            TtsRequest::from_input(
                &json!({"ssml":"<speak></speak>","output_format":"not-real"}),
                128
            )
            .is_err()
        );
    }

    #[test]
    fn stt_request_validates_audio_content_type_and_size() {
        let audio_base64 = BASE64_STANDARD.encode([1_u8, 2, 3, 4]);
        let request = SttRequest::from_input(
            &json!({
                "audio_base64": audio_base64,
                "content_type": "audio/wav",
                "locale": "en-US"
            }),
            16,
        )
        .expect("audio should parse");
        assert_eq!(request.audio.len(), 4);
        assert_eq!(request.definition["locales"], json!(["en-US"]));
        assert!(
            SttRequest::from_input(
                &json!({
                    "audio_base64": BASE64_STANDARD.encode([1_u8, 2, 3]),
                    "content_type": "application/octet-stream"
                }),
                16,
            )
            .is_err()
        );
        assert!(
            SttRequest::from_input(
                &json!({
                    "audio_base64": BASE64_STANDARD.encode([1_u8, 2, 3]),
                    "content_type": "audio/wav"
                }),
                2,
            )
            .is_err()
        );
    }

    #[test]
    fn transcription_result_preserves_phrase_channel_word_confidence_shape() {
        let request = SttRequest::from_input(
            &json!({
                "audio_base64": BASE64_STANDARD.encode([1_u8, 2, 3]),
                "content_type": "audio/wav",
                "locales": ["en-US"]
            }),
            16,
        )
        .expect("request should parse");
        let value = normalize_transcription_result(
            &json!({
                "durationMilliseconds": 2000,
                "combinedPhrases": [{"channel": 0, "text": "Weather"}],
                "phrases": [{
                    "channel": 0,
                    "offsetMilliseconds": 40,
                    "durationMilliseconds": 320,
                    "text": "Weather",
                    "confidence": 0.78,
                    "words": [{"text": "weather", "confidence": 0.8}]
                }]
            }),
            &request,
        );
        assert_eq!(value["text"], "Weather");
        assert_eq!(value["phrases"][0]["channel"], 0);
        assert_eq!(value["phrases"][0]["words"][0]["confidence"], 0.8);
    }

    #[test]
    fn batch_submit_validates_custom_speech_references_and_pins_api_version() {
        let request = BatchSubmitRequest::from_input(
            &json!({
                "display_name": "redacted batch",
                "locale": "en-US",
                "content_urls": ["https://storage.example/audio.wav?sig=SECRET"],
                "model_id": "model-123",
                "dataset_url": "https://eastus.api.cognitive.microsoft.com/speechtotext/datasets/dataset-456",
                "project": {"id": "project-789"},
                "custom_properties": {"purpose": "loopback"}
            }),
            "https://eastus.api.cognitive.microsoft.com",
        )
        .expect("custom speech batch references should validate");
        assert_eq!(
            request.body["model"]["self"],
            "https://eastus.api.cognitive.microsoft.com/speechtotext/models/model-123?api-version=2025-10-15"
        );
        assert_eq!(
            request.body["dataset"]["self"],
            "https://eastus.api.cognitive.microsoft.com/speechtotext/datasets/dataset-456?api-version=2025-10-15"
        );
        assert_eq!(
            request.body["project"]["self"],
            "https://eastus.api.cognitive.microsoft.com/speechtotext/projects/project-789?api-version=2025-10-15"
        );
        assert_eq!(request.body["customProperties"]["purpose"], "loopback");
        assert!(
            !request
                .content_source
                .to_string()
                .contains("https://storage.example/audio.wav")
        );
    }

    #[test]
    fn custom_speech_references_reject_wrong_host_and_retired_versions() {
        let wrong_host = BatchSubmitRequest::from_input(
            &json!({
                "display_name": "redacted batch",
                "locale": "en-US",
                "content_urls": ["https://storage.example/audio.wav"],
                "model_url": "https://westus.api.cognitive.microsoft.com/speechtotext/models/model-123?api-version=2025-10-15"
            }),
            "https://eastus.api.cognitive.microsoft.com",
        );
        assert!(wrong_host.is_err());

        let retired = BatchSubmitRequest::from_input(
            &json!({
                "display_name": "redacted batch",
                "locale": "en-US",
                "content_urls": ["https://storage.example/audio.wav"],
                "model_url": "https://eastus.api.cognitive.microsoft.com/speechtotext/v3.2-preview.2/models/model-123"
            }),
            "https://eastus.api.cognitive.microsoft.com",
        );
        assert!(retired.is_err());
    }

    #[test]
    fn custom_speech_create_bodies_validate_project_dataset_model_and_endpoint_shapes() {
        let base = Url::parse("https://eastus.api.cognitive.microsoft.com").expect("valid base");
        let project = build_custom_speech_create_body(
            &json!({
                "display_name": "project",
                "locale": "en-US",
                "foundry_project_name": "FoundrySpeech",
                "custom_properties": {"owner": "qa"}
            }),
            CustomSpeechResourceKind::Project,
            &base,
        )
        .expect("project body should validate");
        assert_eq!(project["foundryProjectName"], "FoundrySpeech");

        let dataset = build_custom_speech_create_body(
            &json!({
                "display_name": "dataset",
                "locale": "en-US",
                "kind": "AudioFiles",
                "content_url": "https://storage.example/dataset.zip?sig=SECRET",
                "project_id": "project-123"
            }),
            CustomSpeechResourceKind::Dataset,
            &base,
        )
        .expect("dataset body should validate");
        assert_eq!(dataset["kind"], "AudioFiles");
        assert_eq!(
            dataset["project"]["self"],
            "https://eastus.api.cognitive.microsoft.com/speechtotext/projects/project-123?api-version=2025-10-15"
        );

        let model = build_custom_speech_create_body(
            &json!({
                "display_name": "model",
                "locale": "en-US",
                "project_id": "project-123",
                "base_model_id": "base-model-1",
                "datasets": [{"id": "dataset-123"}]
            }),
            CustomSpeechResourceKind::Model,
            &base,
        )
        .expect("model body should validate");
        assert_eq!(
            model["baseModel"]["self"],
            "https://eastus.api.cognitive.microsoft.com/speechtotext/models/base-model-1?api-version=2025-10-15"
        );
        assert_eq!(
            model["datasets"][0]["self"],
            "https://eastus.api.cognitive.microsoft.com/speechtotext/datasets/dataset-123?api-version=2025-10-15"
        );

        let endpoint = build_custom_speech_create_body(
            &json!({
                "display_name": "endpoint",
                "locale": "en-US",
                "model_id": "model-123",
                "project_id": "project-123"
            }),
            CustomSpeechResourceKind::Endpoint,
            &base,
        )
        .expect("endpoint body should validate");
        assert_eq!(
            endpoint["model"]["self"],
            "https://eastus.api.cognitive.microsoft.com/speechtotext/models/model-123?api-version=2025-10-15"
        );
    }

    #[test]
    fn custom_speech_resource_urls_are_api_version_pinned() {
        let input = json!({
            "project_url": "https://eastus.api.cognitive.microsoft.com/speechtotext/projects/project-123"
        });
        let request = CustomSpeechRequest::from_input(
            &input,
            "https://eastus.api.cognitive.microsoft.com",
            CustomSpeechRoute {
                kind: CustomSpeechResourceKind::Project,
                action: CustomSpeechAction::Get,
            },
        )
        .expect("missing api-version should be pinned");
        assert_eq!(request.url.query(), Some("api-version=2025-10-15"));

        let wrong_version = CustomSpeechRequest::from_input(
            &json!({
                "project_url": "https://eastus.api.cognitive.microsoft.com/speechtotext/projects/project-123?api-version=2024-11-15"
            }),
            "https://eastus.api.cognitive.microsoft.com",
            CustomSpeechRoute {
                kind: CustomSpeechResourceKind::Project,
                action: CustomSpeechAction::Get,
            },
        );
        assert!(wrong_version.is_err());
    }

    #[test]
    fn streaming_surface_is_blocked_on_official_sdk_only_docs() {
        let blocker = streaming_blocker_info();
        assert_eq!(blocker["status"], "blocked_official_sdk_only_protocol");
        assert!(
            blocker["reason"]
                .as_str()
                .expect("blocker reason should be a string")
                .contains("does not publish a direct WebSocket frame protocol")
        );

        let deferred = deferred_operations_info();
        let deferred_ids: Vec<_> = deferred
            .iter()
            .map(|operation| {
                operation
                    .get("id")
                    .and_then(Value::as_str)
                    .expect("deferred operation id should be a string")
            })
            .collect();
        assert!(deferred_ids.contains(&"azure.speech.tts.text_stream.websocket"));
        assert!(deferred_ids.contains(&"azure.speech.stt.realtime.websocket"));
        assert!(deferred_ids.contains(&"azure.speech.stt.custom_speech.projects"));
        assert!(deferred_ids.contains(&"azure.speech.auth.connector_local_identity"));
        let custom = custom_speech_lifecycle_info();
        assert_eq!(custom["status"], "implemented_2025_10_15");
        assert_eq!(custom["api_version"], STT_API_VERSION);
        let identity = connector_local_identity_policy_info();
        assert_eq!(identity["status"], "host_token_broker_required");
        assert_eq!(identity["imds"]["host_allow"][0], IMDS_HOST);
        assert!(
            identity["host_policy_reason"]
                .as_str()
                .expect("host policy reason should be a string")
                .contains("Runtime-enforced Azure Speech operations")
        );
        for operation in deferred.iter().filter(|operation| {
            operation.get("outcome").and_then(Value::as_str)
                == Some("blocked_official_sdk_only_protocol")
        }) {
            assert!(
                operation
                    .get("official_docs")
                    .and_then(Value::as_array)
                    .expect("official docs should be listed")
                    .iter()
                    .all(Value::is_string)
            );
            assert!(
                operation
                    .get("implementation_gate")
                    .and_then(Value::as_str)
                    .expect("implementation gate should be a string")
                    .starts_with("Do not implement live")
            );
        }
    }
}
