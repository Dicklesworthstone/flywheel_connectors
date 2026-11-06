//! Keychain-first credential store for connector authentication.
//!
//! Prefers the OS keychain via the `keyring` crate and falls back to an
//! encrypted file at `~/.fwc/credentials.enc` only when an independent secret
//! key is configured through `FWC_CREDENTIAL_STORE_KEY_FILE`. A missing
//! keychain never authorizes encryption with public machine metadata.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::Zeroizing;

// ── Types ──────────────────────────────────────────────────────────

/// Authentication method used by a connector.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    /// A single bearer/API token.
    BearerToken,
    /// Username + password (HTTP Basic).
    BasicAuth,
    /// `OAuth2` client credentials or token.
    OAuth2,
    /// Custom header-based auth (e.g. X-Api-Key).
    ApiKey,
    /// Session token acquired from a login endpoint.
    SessionToken,
    /// Secretless reference to an external credential provider.
    SecretlessRef,
    /// Custom multi-field auth.
    Custom,
}

impl AuthMethod {
    /// Detect auth method from the fields present in a credential.
    fn detect(fields: &BTreeMap<String, String>) -> Self {
        if fields.contains_key("credential_id") {
            return Self::SecretlessRef;
        }
        if (fields.contains_key("client_id") && fields.contains_key("client_secret"))
            || fields.contains_key("access_token")
            || fields.contains_key("refresh_token")
        {
            return Self::OAuth2;
        }
        if fields.contains_key("username") && fields.contains_key("password") {
            return Self::BasicAuth;
        }
        if fields.contains_key("token") || fields.contains_key("api_token") {
            return Self::BearerToken;
        }
        if fields.contains_key("api_key") {
            return Self::ApiKey;
        }
        if fields.contains_key("session_token") {
            return Self::SessionToken;
        }
        Self::Custom
    }
}

/// A stored credential for a connector.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Credential {
    /// Connector identifier (e.g. "github", "slack").
    pub connector_id: String,
    /// Authentication method.
    pub auth_method: AuthMethod,
    /// Secret fields (key → value). Values are the actual secrets.
    pub fields: BTreeMap<String, String>,
    /// When this credential was created.
    pub created_at: DateTime<Utc>,
    /// When this credential was last updated.
    pub updated_at: DateTime<Utc>,
    /// When this credential was last used for an operation.
    pub last_used_at: Option<DateTime<Utc>>,
    /// Optional human-readable label.
    pub label: Option<String>,
}

impl Credential {
    /// Create a new credential from raw fields.
    pub fn new(
        connector_id: impl Into<String>,
        fields: BTreeMap<String, String>,
        label: Option<String>,
    ) -> Self {
        let auth_method = AuthMethod::detect(&fields);
        let now = Utc::now();
        Self {
            connector_id: connector_id.into(),
            auth_method,
            fields,
            created_at: now,
            updated_at: now,
            last_used_at: None,
            label,
        }
    }

    /// Mark this credential as used now.
    pub fn touch(&mut self) {
        self.last_used_at = Some(Utc::now());
    }

    /// Produce a redacted view safe for display (secrets replaced with `***`).
    pub fn redacted_view(&self) -> Value {
        let mut fields = serde_json::Map::new();
        for (key, value) in &self.fields {
            let redacted = redact_value(value);
            fields.insert(key.clone(), Value::String(redacted));
        }
        serde_json::json!({
            "connector_id": self.connector_id,
            "auth_method": self.auth_method,
            "fields": fields,
            "created_at": self.created_at.to_rfc3339(),
            "updated_at": self.updated_at.to_rfc3339(),
            "last_used_at": self.last_used_at.map(|t| t.to_rfc3339()),
            "label": self.label,
        })
    }

    /// Get a specific secret field value.
    pub fn get_field(&self, key: &str) -> Option<&str> {
        self.fields.get(key).map(String::as_str)
    }
}

/// Redact a secret value for display.
///
/// Shows first and last character with `***` in between for values >= 8 chars.
/// Shorter values become `***`.
fn redact_value(value: &str) -> String {
    if value.len() < 8 {
        return "***".to_string();
    }
    let chars: Vec<char> = value.chars().collect();
    let first = chars[0];
    let last = chars[chars.len() - 1];
    format!("{first}***{last}")
}

// ── Encryption layer ───────────────────────────────────────────────

/// Encryption key length for ChaCha20-Poly1305 (256 bits).
const KEY_LEN: usize = 32;
/// Nonce length for ChaCha20-Poly1305 (96 bits).
const NONCE_LEN: usize = 12;
/// Service name for OS keychain entries.
const KEYCHAIN_SERVICE_NAME: &str = "fwc-credentials";
/// Synthetic keychain entry that stores the connector-id index.
const KEYCHAIN_INDEX_ENTRY: &str = "__fwc_index__";
/// External secret, provisioned independently of the encrypted credential file.
const FILE_KEY_ENV: &str = "FWC_CREDENTIAL_STORE_KEY_FILE";

enum FileEncryptionKey {
    Supplied(Zeroizing<[u8; KEY_LEN]>),
    ConfiguredFile(Option<PathBuf>),
}

impl FileEncryptionKey {
    fn resolve(&self) -> Result<Zeroizing<[u8; KEY_LEN]>, String> {
        match self {
            Self::Supplied(key) => Ok(Zeroizing::new(**key)),
            Self::ConfiguredFile(Some(path)) => read_file_key(path),
            Self::ConfiguredFile(None) => Err(format!(
                "encrypted credential storage requires an independent secret key; configure {FILE_KEY_ENV} with a private 32-byte key file or restore the OS keychain. Legacy machine-identity-encrypted files are not opened automatically; re-import their credentials into a securely keyed store"
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BackendPreference {
    FileOnly,
    PreferKeychain,
}

#[derive(Debug)]
enum KeychainError {
    NoEntry,
    Unavailable(String),
    Other(String),
}

trait KeychainClient: Send + Sync {
    fn set_secret(&self, service: &str, account: &str, secret: &[u8]) -> Result<(), KeychainError>;

    fn get_secret(&self, service: &str, account: &str) -> Result<Vec<u8>, KeychainError>;

    fn delete_credential(&self, service: &str, account: &str) -> Result<(), KeychainError>;
}

struct NativeKeychainClient;

impl NativeKeychainClient {
    fn map_error(error: keyring::Error) -> KeychainError {
        match error {
            keyring::Error::NoEntry => KeychainError::NoEntry,
            keyring::Error::NoStorageAccess(error) => KeychainError::Unavailable(error.to_string()),
            keyring::Error::PlatformFailure(error) => {
                let detail = error.to_string();
                let lower = detail.to_ascii_lowercase();
                if lower.contains("servicenotfound")
                    || lower.contains("service not found")
                    || lower.contains("nobackendfound")
                    || lower.contains("no backend found")
                {
                    KeychainError::Unavailable(detail)
                } else {
                    KeychainError::Other(detail)
                }
            }
            other => KeychainError::Other(other.to_string()),
        }
    }
}

impl KeychainClient for NativeKeychainClient {
    fn set_secret(&self, service: &str, account: &str, secret: &[u8]) -> Result<(), KeychainError> {
        let entry = keyring::Entry::new(service, account).map_err(Self::map_error)?;
        entry.set_secret(secret).map_err(Self::map_error)
    }

    fn get_secret(&self, service: &str, account: &str) -> Result<Vec<u8>, KeychainError> {
        let entry = keyring::Entry::new(service, account).map_err(Self::map_error)?;
        entry.get_secret().map_err(Self::map_error)
    }

    fn delete_credential(&self, service: &str, account: &str) -> Result<(), KeychainError> {
        let entry = keyring::Entry::new(service, account).map_err(Self::map_error)?;
        entry.delete_credential().map_err(Self::map_error)
    }
}

/// Read a provisioned key without deriving secret material from public data.
fn read_file_key(path: &Path) -> Result<Zeroizing<[u8; KEY_LEN]>, String> {
    if !std::fs::symlink_metadata(path)
        .map_err(|e| format!("failed to inspect credential encryption key: {e}"))?
        .is_file()
    {
        return Err(
            "credential encryption key must be a regular file, not a symlink or device".to_owned(),
        );
    }
    let file =
        File::open(path).map_err(|e| format!("failed to open credential encryption key: {e}"))?;
    let metadata = file
        .metadata()
        .map_err(|e| format!("failed to inspect credential encryption key: {e}"))?;
    if !metadata.is_file() {
        return Err("credential encryption key must be a regular file".to_owned());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err("credential encryption key must not be accessible to group or other users (use mode 0600 or 0400)".to_owned());
        }
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(129)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("failed to read credential encryption key: {e}"))?;
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    if bytes.len() == KEY_LEN {
        key.copy_from_slice(&bytes);
        return Ok(key);
    }
    if bytes.len() <= 128
        && let Ok(encoded) = std::str::from_utf8(&bytes)
        && encoded.trim().len() == KEY_LEN * 2
        && hex::decode_to_slice(encoded.trim(), key.as_mut()).is_ok()
    {
        return Ok(key);
    }
    Err(
        "credential encryption key must contain exactly 32 raw bytes or 64 hexadecimal digits"
            .to_owned(),
    )
}

/// Encrypt plaintext with ChaCha20-Poly1305.
///
/// Returns `nonce || ciphertext` concatenated.
fn encrypt(plaintext: &[u8], key: &[u8; KEY_LEN]) -> Result<Vec<u8>, String> {
    use chacha20poly1305::aead::{Aead, KeyInit};
    use chacha20poly1305::{ChaCha20Poly1305, Nonce};
    use rand::Rng;

    let cipher =
        ChaCha20Poly1305::new_from_slice(key).map_err(|e| format!("key init failed: {e}"))?;

    // Generate random nonce.
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| format!("encryption failed: {e}"))?;

    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt data previously encrypted with `encrypt`.
///
/// Expects `nonce || ciphertext` format.
fn decrypt(data: &[u8], key: &[u8; KEY_LEN]) -> Result<Vec<u8>, String> {
    use chacha20poly1305::aead::{Aead, KeyInit};
    use chacha20poly1305::{ChaCha20Poly1305, Nonce};

    if data.len() < NONCE_LEN + 16 {
        // Minimum: nonce + poly1305 tag.
        return Err("ciphertext too short".to_string());
    }

    let (nonce_bytes, ciphertext) = data.split_at(NONCE_LEN);
    let nonce = Nonce::from_slice(nonce_bytes);
    let cipher =
        ChaCha20Poly1305::new_from_slice(key).map_err(|e| format!("key init failed: {e}"))?;

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| format!("decryption failed (wrong key or corrupted data): {e}"))
}

// ── Store ──────────────────────────────────────────────────────────

/// Credential store with a keychain-first backend and encrypted-file fallback.
pub struct CredentialStore {
    path: PathBuf,
    key: FileEncryptionKey,
    backend_preference: BackendPreference,
    keychain_service: String,
    keychain_client: Option<Arc<dyn KeychainClient>>,
}

/// The inner data structure persisted to disk.
#[derive(Default, Serialize, Deserialize)]
struct StoreData {
    credentials: BTreeMap<String, Credential>,
}

impl CredentialStore {
    /// Create a store at the default path (`~/.fwc/credentials.enc`).
    pub fn default_path() -> Self {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        let path = PathBuf::from(home).join(".fwc").join("credentials.enc");
        Self {
            path,
            key: FileEncryptionKey::ConfiguredFile(
                std::env::var_os(FILE_KEY_ENV).map(PathBuf::from),
            ),
            backend_preference: BackendPreference::PreferKeychain,
            keychain_service: KEYCHAIN_SERVICE_NAME.to_owned(),
            keychain_client: Some(Arc::new(NativeKeychainClient)),
        }
    }

    /// Create a store at a custom path with a custom key (for testing).
    pub fn new(path: impl Into<PathBuf>, key: [u8; KEY_LEN]) -> Self {
        Self {
            path: path.into(),
            key: FileEncryptionKey::Supplied(Zeroizing::new(key)),
            backend_preference: BackendPreference::FileOnly,
            keychain_service: KEYCHAIN_SERVICE_NAME.to_owned(),
            keychain_client: None,
        }
    }

    #[cfg(test)]
    fn new_with_keychain(
        path: impl Into<PathBuf>,
        key: [u8; KEY_LEN],
        keychain_client: Arc<dyn KeychainClient>,
    ) -> Self {
        Self {
            path: path.into(),
            key: FileEncryptionKey::Supplied(Zeroizing::new(key)),
            backend_preference: BackendPreference::PreferKeychain,
            keychain_service: KEYCHAIN_SERVICE_NAME.to_owned(),
            keychain_client: Some(keychain_client),
        }
    }

    /// Add or update a credential for a connector.
    pub fn add(&self, credential: Credential) -> Result<(), String> {
        if self.prefers_keychain() {
            match self.add_to_keychain(&credential) {
                Ok(()) => {
                    let _ = self.remove_from_file(&credential.connector_id);
                    return Ok(());
                }
                Err(KeychainError::Unavailable(error)) => self.log_keychain_fallback(&error),
                Err(KeychainError::Other(error)) => {
                    return Err(format!(
                        "failed to store credential in OS keychain: {error}"
                    ));
                }
                Err(KeychainError::NoEntry) => {}
            }
        }
        self.add_to_file(credential)
    }

    /// Get a credential by connector ID.
    pub fn get(&self, connector_id: &str) -> Result<Option<Credential>, String> {
        if self.prefers_keychain() {
            match self.get_from_keychain(connector_id) {
                Ok(Some(credential)) => return Ok(Some(credential)),
                Ok(None) => {}
                Err(KeychainError::Unavailable(error)) => self.log_keychain_fallback(&error),
                Err(KeychainError::Other(error)) => {
                    return Err(format!(
                        "failed to read credential from OS keychain: {error}"
                    ));
                }
                Err(KeychainError::NoEntry) => {}
            }
        }
        self.get_from_file(connector_id)
    }

    /// Remove a credential by connector ID. Returns `true` if it existed.
    pub fn remove(&self, connector_id: &str) -> Result<bool, String> {
        if self.prefers_keychain() {
            match self.remove_from_keychain(connector_id) {
                Ok(true) => {
                    let _ = self.remove_from_file(connector_id);
                    return Ok(true);
                }
                Ok(false) => {}
                Err(KeychainError::Unavailable(error)) => self.log_keychain_fallback(&error),
                Err(KeychainError::Other(error)) => {
                    return Err(format!(
                        "failed to remove credential from OS keychain: {error}"
                    ));
                }
                Err(KeychainError::NoEntry) => {}
            }
        }
        self.remove_from_file(connector_id)
    }

    /// List all stored credentials (redacted).
    pub fn list(&self) -> Result<Vec<Value>, String> {
        if self.prefers_keychain() {
            match self.list_from_keychain() {
                Ok(credentials) if !credentials.is_empty() => return Ok(credentials),
                Ok(_) => {}
                Err(KeychainError::Unavailable(error)) => self.log_keychain_fallback(&error),
                Err(KeychainError::Other(error)) => {
                    return Err(format!(
                        "failed to list credentials from OS keychain: {error}"
                    ));
                }
                Err(KeychainError::NoEntry) => {}
            }
        }
        self.list_from_file()
    }

    /// List all connector IDs that have stored credentials.
    pub fn list_ids(&self) -> Result<Vec<String>, String> {
        if self.prefers_keychain() {
            match self.list_ids_from_keychain() {
                Ok(ids) if !ids.is_empty() => return Ok(ids),
                Ok(_) => {}
                Err(KeychainError::Unavailable(error)) => self.log_keychain_fallback(&error),
                Err(KeychainError::Other(error)) => {
                    return Err(format!(
                        "failed to enumerate credentials from OS keychain: {error}"
                    ));
                }
                Err(KeychainError::NoEntry) => {}
            }
        }
        self.list_ids_from_file()
    }

    /// Update specific fields in an existing credential.
    pub fn update_fields(
        &self,
        connector_id: &str,
        fields: BTreeMap<String, String>,
    ) -> Result<bool, String> {
        let Some(mut credential) = self.get(connector_id)? else {
            return Ok(false);
        };
        for (key, value) in fields {
            credential.fields.insert(key, value);
        }
        credential.auth_method = AuthMethod::detect(&credential.fields);
        credential.updated_at = Utc::now();
        self.add(credential)?;
        Ok(true)
    }

    /// Mark a credential as used.
    pub fn touch(&self, connector_id: &str) -> Result<bool, String> {
        let Some(mut credential) = self.get(connector_id)? else {
            return Ok(false);
        };
        credential.touch();
        self.add(credential)?;
        Ok(true)
    }

    /// Number of stored credentials.
    pub fn count(&self) -> Result<usize, String> {
        Ok(self.list_ids()?.len())
    }

    /// Whether the store file exists on disk.
    pub fn exists(&self) -> bool {
        if self.prefers_keychain() && self.keychain_has_any_entries().unwrap_or(false) {
            return true;
        }
        self.path.exists()
    }

    /// The path to the store file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    // ── Internal ───────────────────────────────────────────────────

    fn prefers_keychain(&self) -> bool {
        self.backend_preference == BackendPreference::PreferKeychain
            && self.keychain_client.is_some()
    }

    fn log_keychain_fallback(&self, error: &str) {
        tracing::warn!(
            keychain_service = %self.keychain_service,
            error = %error,
            "OS keychain unavailable; encrypted file fallback requires an independent secret key."
        );
    }

    fn load_file_data(&self) -> Result<StoreData, String> {
        if !self.path.exists() {
            return Ok(StoreData::default());
        }
        let encrypted = std::fs::read(&self.path)
            .map_err(|e| format!("failed to read credential store: {e}"))?;
        let key = self.key.resolve()?;
        let plaintext = Zeroizing::new(decrypt(&encrypted, &key)?);
        serde_json::from_slice(&plaintext).map_err(|e| format!("credential store corrupted: {e}"))
    }

    fn save_file_data(&self, data: &StoreData) -> Result<(), String> {
        // Resolve the independent key before creating any fallback artifacts.
        let key = self.key.resolve()?;
        if let Some(parent) = self
            .path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
        {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("failed to create credential store directory: {e}"))?;
        }
        let plaintext = Zeroizing::new(
            serde_json::to_vec(data)
                .map_err(|e| format!("failed to serialize credentials: {e}"))?,
        );
        let encrypted = encrypt(&plaintext, &key)?;
        let temporary = self
            .path
            .with_extension(format!("enc.{}.tmp", uuid::Uuid::new_v4()));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&temporary)
            .map_err(|e| format!("failed to create encrypted credential replacement: {e}"))?;
        file.write_all(&encrypted)
            .and_then(|()| file.sync_all())
            .map_err(|e| format!("failed to persist encrypted credential replacement: {e}"))?;
        drop(file);
        std::fs::rename(&temporary, &self.path)
            .map_err(|e| format!("failed to publish encrypted credential replacement: {e}"))?;
        #[cfg(unix)]
        if let Some(parent) = self
            .path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
        {
            File::open(parent)
                .and_then(|file| file.sync_all())
                .map_err(|e| {
                    format!("credential replacement published, but directory sync failed: {e}")
                })?;
        }
        Ok(())
    }

    fn add_to_file(&self, credential: Credential) -> Result<(), String> {
        let mut data = self.load_file_data()?;
        data.credentials
            .insert(credential.connector_id.clone(), credential);
        self.save_file_data(&data)
    }

    fn get_from_file(&self, connector_id: &str) -> Result<Option<Credential>, String> {
        let data = self.load_file_data()?;
        Ok(data.credentials.get(connector_id).cloned())
    }

    fn remove_from_file(&self, connector_id: &str) -> Result<bool, String> {
        let mut data = self.load_file_data()?;
        let existed = data.credentials.remove(connector_id).is_some();
        if existed {
            self.save_file_data(&data)?;
        }
        Ok(existed)
    }

    fn list_from_file(&self) -> Result<Vec<Value>, String> {
        let data = self.load_file_data()?;
        Ok(data
            .credentials
            .values()
            .map(Credential::redacted_view)
            .collect())
    }

    fn list_ids_from_file(&self) -> Result<Vec<String>, String> {
        let data = self.load_file_data()?;
        Ok(data.credentials.keys().cloned().collect())
    }

    fn keychain_client(&self) -> Result<&dyn KeychainClient, KeychainError> {
        self.keychain_client
            .as_deref()
            .ok_or_else(|| KeychainError::Unavailable("keychain client not configured".to_string()))
    }

    fn load_keychain_index(&self) -> Result<Vec<String>, KeychainError> {
        match self
            .keychain_client()?
            .get_secret(&self.keychain_service, KEYCHAIN_INDEX_ENTRY)
        {
            Ok(secret) => serde_json::from_slice::<Vec<String>>(&secret).map_err(|error| {
                KeychainError::Other(format!("keychain index corrupted: {error}"))
            }),
            Err(KeychainError::NoEntry) => Ok(Vec::new()),
            Err(error) => Err(error),
        }
    }

    fn save_keychain_index(&self, ids: &[String]) -> Result<(), KeychainError> {
        let secret = serde_json::to_vec(ids).map_err(|error| {
            KeychainError::Other(format!("failed to serialize keychain index: {error}"))
        })?;
        self.keychain_client()?
            .set_secret(&self.keychain_service, KEYCHAIN_INDEX_ENTRY, &secret)
    }

    fn clear_keychain_index(&self) -> Result<(), KeychainError> {
        match self
            .keychain_client()?
            .delete_credential(&self.keychain_service, KEYCHAIN_INDEX_ENTRY)
        {
            Ok(()) | Err(KeychainError::NoEntry) => Ok(()),
            Err(error) => Err(error),
        }
    }

    fn get_from_keychain(&self, connector_id: &str) -> Result<Option<Credential>, KeychainError> {
        match self
            .keychain_client()?
            .get_secret(&self.keychain_service, connector_id)
        {
            Ok(secret) => serde_json::from_slice::<Credential>(&secret)
                .map(Some)
                .map_err(|error| {
                    KeychainError::Other(format!(
                        "failed to decode keychain credential for `{connector_id}`: {error}"
                    ))
                }),
            Err(KeychainError::NoEntry) => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn add_to_keychain(&self, credential: &Credential) -> Result<(), KeychainError> {
        let secret = serde_json::to_vec(credential).map_err(|error| {
            KeychainError::Other(format!(
                "failed to serialize keychain credential for `{}`: {error}",
                credential.connector_id
            ))
        })?;
        self.keychain_client()?.set_secret(
            &self.keychain_service,
            &credential.connector_id,
            &secret,
        )?;

        let mut ids = self.load_keychain_index()?;
        let mut id_set: BTreeSet<String> = ids.into_iter().collect();
        id_set.insert(credential.connector_id.clone());
        ids = id_set.into_iter().collect();
        self.save_keychain_index(&ids)
    }

    fn remove_from_keychain(&self, connector_id: &str) -> Result<bool, KeychainError> {
        let removed = match self
            .keychain_client()?
            .delete_credential(&self.keychain_service, connector_id)
        {
            Ok(()) => true,
            Err(KeychainError::NoEntry) => false,
            Err(error) => return Err(error),
        };
        if !removed {
            return Ok(false);
        }

        let mut ids = self.load_keychain_index()?;
        ids.retain(|id| id != connector_id);
        if ids.is_empty() {
            self.clear_keychain_index()?;
        } else {
            self.save_keychain_index(&ids)?;
        }
        Ok(true)
    }

    fn list_ids_from_keychain(&self) -> Result<Vec<String>, KeychainError> {
        let ids = self.load_keychain_index()?;
        Ok(ids)
    }

    fn list_from_keychain(&self) -> Result<Vec<Value>, KeychainError> {
        let ids = self.load_keychain_index()?;
        let original_len = ids.len();
        let mut repaired_ids = Vec::new();
        let mut credentials = Vec::new();
        for connector_id in ids {
            if let Some(credential) = self.get_from_keychain(&connector_id)? {
                repaired_ids.push(connector_id);
                credentials.push(credential.redacted_view());
            }
        }

        if repaired_ids.len() != original_len {
            if repaired_ids.is_empty() {
                self.clear_keychain_index()?;
            } else {
                self.save_keychain_index(&repaired_ids)?;
            }
        }

        Ok(credentials)
    }

    fn keychain_has_any_entries(&self) -> Result<bool, KeychainError> {
        Ok(!self.load_keychain_index()?.is_empty())
    }
}

// ── CLI argument parsing helpers ────────────────────────────────────

/// Parse a `KEY=VALUE` credential field from CLI input.
pub fn parse_credential_field(input: &str) -> Option<(String, String)> {
    let (key, value) = input.split_once('=')?;
    let key = key.trim();
    let value = value.trim();
    if key.is_empty() || value.is_empty() {
        return None;
    }
    Some((key.to_owned(), value.to_owned()))
}

/// Parse multiple credential fields from CLI arguments.
pub fn parse_credential_fields(inputs: &[String]) -> Result<BTreeMap<String, String>, String> {
    let mut fields = BTreeMap::new();
    for input in inputs {
        let (key, value) = parse_credential_field(input)
            .ok_or_else(|| format!("invalid credential field `{input}`; expected KEY=VALUE"))?;
        fields.insert(key, value);
    }
    if fields.is_empty() {
        return Err("at least one credential field is required".to_string());
    }
    Ok(fields)
}

/// Validate that a connector ID looks reasonable.
pub fn validate_connector_id(id: &str) -> Result<(), String> {
    if id.is_empty() {
        return Err("connector ID cannot be empty".to_string());
    }
    if id.len() > 64 {
        return Err("connector ID too long (max 64 characters)".to_string());
    }
    if !id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(format!(
            "connector ID `{id}` contains invalid characters; use alphanumeric, dash, underscore, or dot"
        ));
    }
    Ok(())
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct MockKeychainClient {
        unavailable: bool,
        secrets: Mutex<BTreeMap<(String, String), Vec<u8>>>,
    }

    impl MockKeychainClient {
        fn available() -> Self {
            Self::default()
        }

        fn unavailable() -> Self {
            Self {
                unavailable: true,
                ..Self::default()
            }
        }
    }

    impl KeychainClient for MockKeychainClient {
        fn set_secret(
            &self,
            service: &str,
            account: &str,
            secret: &[u8],
        ) -> Result<(), KeychainError> {
            if self.unavailable {
                return Err(KeychainError::Unavailable(
                    "ServiceNotFound: mock keychain unavailable".to_string(),
                ));
            }
            self.secrets
                .lock()
                .unwrap()
                .insert((service.to_owned(), account.to_owned()), secret.to_vec());
            Ok(())
        }

        fn get_secret(&self, service: &str, account: &str) -> Result<Vec<u8>, KeychainError> {
            if self.unavailable {
                return Err(KeychainError::Unavailable(
                    "ServiceNotFound: mock keychain unavailable".to_string(),
                ));
            }
            self.secrets
                .lock()
                .unwrap()
                .get(&(service.to_owned(), account.to_owned()))
                .cloned()
                .ok_or(KeychainError::NoEntry)
        }

        fn delete_credential(&self, service: &str, account: &str) -> Result<(), KeychainError> {
            if self.unavailable {
                return Err(KeychainError::Unavailable(
                    "ServiceNotFound: mock keychain unavailable".to_string(),
                ));
            }
            let removed = self
                .secrets
                .lock()
                .unwrap()
                .remove(&(service.to_owned(), account.to_owned()));
            if removed.is_some() {
                Ok(())
            } else {
                Err(KeychainError::NoEntry)
            }
        }
    }

    fn test_key() -> [u8; KEY_LEN] {
        let mut key = [0u8; KEY_LEN];
        for (i, byte) in key.iter_mut().enumerate() {
            #[allow(clippy::cast_possible_truncation)]
            {
                *byte = (i as u8).wrapping_mul(7).wrapping_add(42);
            }
        }
        key
    }

    fn temp_store() -> CredentialStore {
        use std::time::{SystemTime, UNIX_EPOCH};
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir()
            .join(format!("fwc-cred-test-{unique}"))
            .join("credentials.enc");
        CredentialStore::new(path, test_key())
    }

    fn temp_keychain_store(keychain_client: Arc<dyn KeychainClient>) -> CredentialStore {
        use std::time::{SystemTime, UNIX_EPOCH};
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir()
            .join(format!("fwc-cred-keychain-test-{unique}"))
            .join("credentials.enc");
        CredentialStore::new_with_keychain(path, test_key(), keychain_client)
    }

    fn sample_fields() -> BTreeMap<String, String> {
        let mut fields = BTreeMap::new();
        fields.insert("token".to_owned(), "ghp_abc123def456".to_owned());
        fields
    }

    fn sample_basic_fields() -> BTreeMap<String, String> {
        let mut fields = BTreeMap::new();
        fields.insert("username".to_owned(), "admin".to_owned());
        fields.insert("password".to_owned(), "s3cr3t_password".to_owned());
        fields
    }

    // ── AuthMethod detection ──────────────────────────────────────

    #[test]
    fn detect_bearer_token() {
        let fields = sample_fields();
        assert_eq!(AuthMethod::detect(&fields), AuthMethod::BearerToken);
    }

    #[test]
    fn detect_basic_auth() {
        let fields = sample_basic_fields();
        assert_eq!(AuthMethod::detect(&fields), AuthMethod::BasicAuth);
    }

    #[test]
    fn detect_oauth2() {
        let mut fields = BTreeMap::new();
        fields.insert("client_id".to_owned(), "id123".to_owned());
        fields.insert("client_secret".to_owned(), "secret456".to_owned());
        assert_eq!(AuthMethod::detect(&fields), AuthMethod::OAuth2);
    }

    #[test]
    fn detect_oauth2_access_token() {
        let mut fields = BTreeMap::new();
        fields.insert("access_token".to_owned(), "access-123".to_owned());
        assert_eq!(AuthMethod::detect(&fields), AuthMethod::OAuth2);
    }

    #[test]
    fn detect_oauth2_refresh_token() {
        let mut fields = BTreeMap::new();
        fields.insert("refresh_token".to_owned(), "refresh-123".to_owned());
        assert_eq!(AuthMethod::detect(&fields), AuthMethod::OAuth2);
    }

    #[test]
    fn detect_api_key() {
        let mut fields = BTreeMap::new();
        fields.insert("api_key".to_owned(), "key_abc".to_owned());
        assert_eq!(AuthMethod::detect(&fields), AuthMethod::ApiKey);
    }

    #[test]
    fn detect_session_token() {
        let mut fields = BTreeMap::new();
        fields.insert("session_token".to_owned(), "tok_xyz".to_owned());
        assert_eq!(AuthMethod::detect(&fields), AuthMethod::SessionToken);
    }

    #[test]
    fn detect_secretless_ref() {
        let mut fields = BTreeMap::new();
        fields.insert("credential_id".to_owned(), "cred_abc".to_owned());
        assert_eq!(AuthMethod::detect(&fields), AuthMethod::SecretlessRef);
    }

    #[test]
    fn detect_custom() {
        let mut fields = BTreeMap::new();
        fields.insert("x_custom_header".to_owned(), "val".to_owned());
        assert_eq!(AuthMethod::detect(&fields), AuthMethod::Custom);
    }

    // ── Credential ────────────────────────────────────────────────

    #[test]
    fn credential_new_detects_auth_method() {
        let cred = Credential::new("github", sample_fields(), None);
        assert_eq!(cred.connector_id, "github");
        assert_eq!(cred.auth_method, AuthMethod::BearerToken);
        assert!(cred.last_used_at.is_none());
    }

    #[test]
    fn credential_touch_sets_last_used() {
        let mut cred = Credential::new("github", sample_fields(), None);
        assert!(cred.last_used_at.is_none());
        cred.touch();
        assert!(cred.last_used_at.is_some());
    }

    #[test]
    fn credential_get_field() {
        let cred = Credential::new("github", sample_fields(), None);
        assert_eq!(cred.get_field("token"), Some("ghp_abc123def456"));
        assert_eq!(cred.get_field("missing"), None);
    }

    #[test]
    fn credential_with_label() {
        let cred = Credential::new("github", sample_fields(), Some("work account".to_owned()));
        assert_eq!(cred.label.as_deref(), Some("work account"));
    }

    // ── Redaction ─────────────────────────────────────────────────

    #[test]
    fn redact_short_value() {
        assert_eq!(redact_value("abc"), "***");
        assert_eq!(redact_value(""), "***");
        assert_eq!(redact_value("1234567"), "***");
    }

    #[test]
    fn redact_long_value() {
        assert_eq!(redact_value("ghp_abc123def456"), "g***6");
        assert_eq!(redact_value("12345678"), "1***8");
    }

    #[test]
    fn redacted_view_hides_secrets() {
        let cred = Credential::new("github", sample_fields(), None);
        let view = cred.redacted_view();
        let fields = view["fields"].as_object().unwrap();
        let token_display = fields["token"].as_str().unwrap();
        assert!(!token_display.contains("ghp_abc123def456"));
        assert!(token_display.contains("***"));
    }

    #[test]
    fn redacted_view_shows_metadata() {
        let cred = Credential::new("github", sample_fields(), Some("my github".to_owned()));
        let view = cred.redacted_view();
        assert_eq!(view["connector_id"], "github");
        assert_eq!(view["auth_method"], "bearer_token");
        assert_eq!(view["label"], "my github");
    }

    // ── Encryption roundtrip ──────────────────────────────────────

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = test_key();
        let plaintext = b"hello, credential store!";
        let encrypted = encrypt(plaintext, &key).unwrap();
        assert_ne!(encrypted, plaintext);
        let decrypted = decrypt(&encrypted, &key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn decrypt_with_wrong_key_fails() {
        let key = test_key();
        let plaintext = b"secret data";
        let encrypted = encrypt(plaintext, &key).unwrap();

        let mut wrong_key = [0u8; KEY_LEN];
        wrong_key[0] = 99;
        let result = decrypt(&encrypted, &wrong_key);
        assert!(result.is_err());
    }

    #[test]
    fn decrypt_too_short_fails() {
        let key = test_key();
        let result = decrypt(b"short", &key);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too short"));
    }

    #[test]
    fn encrypt_produces_different_ciphertexts() {
        let key = test_key();
        let plaintext = b"same data";
        let a = encrypt(plaintext, &key).unwrap();
        let b = encrypt(plaintext, &key).unwrap();
        // Different random nonces should produce different ciphertexts.
        assert_ne!(a, b);
    }

    // ── CredentialStore CRUD ──────────────────────────────────────

    #[test]
    fn store_add_and_get() {
        let store = temp_store();
        let cred = Credential::new("github", sample_fields(), None);
        store.add(cred).unwrap();

        let loaded = store.get("github").unwrap().unwrap();
        assert_eq!(loaded.connector_id, "github");
        assert_eq!(loaded.get_field("token"), Some("ghp_abc123def456"));
    }

    #[test]
    fn store_get_missing() {
        let store = temp_store();
        assert!(store.get("nonexistent").unwrap().is_none());
    }

    #[test]
    fn store_remove() {
        let store = temp_store();
        let cred = Credential::new("github", sample_fields(), None);
        store.add(cred).unwrap();
        assert!(store.remove("github").unwrap());
        assert!(store.get("github").unwrap().is_none());
        // Second remove returns false.
        assert!(!store.remove("github").unwrap());
    }

    #[test]
    fn store_list_all() {
        let store = temp_store();
        store
            .add(Credential::new("github", sample_fields(), None))
            .unwrap();
        store
            .add(Credential::new("slack", sample_basic_fields(), None))
            .unwrap();

        let list = store.list().unwrap();
        assert_eq!(list.len(), 2);
        // All entries should be redacted.
        for entry in &list {
            let fields = entry["fields"].as_object().unwrap();
            for (_, v) in fields {
                assert!(v.as_str().unwrap().contains("***"));
            }
        }
    }

    #[test]
    fn store_list_ids() {
        let store = temp_store();
        store
            .add(Credential::new("github", sample_fields(), None))
            .unwrap();
        store
            .add(Credential::new("slack", sample_basic_fields(), None))
            .unwrap();

        let ids = store.list_ids().unwrap();
        assert_eq!(ids, vec!["github", "slack"]);
    }

    #[test]
    fn store_update_fields() {
        let store = temp_store();
        store
            .add(Credential::new("github", sample_fields(), None))
            .unwrap();

        let mut new_fields = BTreeMap::new();
        new_fields.insert("token".to_owned(), "ghp_new_token_value".to_owned());
        assert!(store.update_fields("github", new_fields).unwrap());

        let loaded = store.get("github").unwrap().unwrap();
        assert_eq!(loaded.get_field("token"), Some("ghp_new_token_value"));
    }

    #[test]
    fn store_update_nonexistent_returns_false() {
        let store = temp_store();
        let fields = BTreeMap::new();
        assert!(!store.update_fields("nope", fields).unwrap());
    }

    #[test]
    fn store_touch() {
        let store = temp_store();
        store
            .add(Credential::new("github", sample_fields(), None))
            .unwrap();

        let before = store.get("github").unwrap().unwrap();
        assert!(before.last_used_at.is_none());

        assert!(store.touch("github").unwrap());

        let after = store.get("github").unwrap().unwrap();
        assert!(after.last_used_at.is_some());
    }

    #[test]
    fn store_touch_nonexistent_returns_false() {
        let store = temp_store();
        assert!(!store.touch("nope").unwrap());
    }

    #[test]
    fn store_count() {
        let store = temp_store();
        assert_eq!(store.count().unwrap(), 0);
        store
            .add(Credential::new("github", sample_fields(), None))
            .unwrap();
        assert_eq!(store.count().unwrap(), 1);
        store
            .add(Credential::new("slack", sample_basic_fields(), None))
            .unwrap();
        assert_eq!(store.count().unwrap(), 2);
    }

    #[test]
    fn store_exists_false_before_first_write() {
        let store = temp_store();
        assert!(!store.exists());
    }

    #[test]
    fn store_exists_true_after_write() {
        let store = temp_store();
        store
            .add(Credential::new("github", sample_fields(), None))
            .unwrap();
        assert!(store.exists());
    }

    #[test]
    fn store_overwrite_credential() {
        let store = temp_store();
        store
            .add(Credential::new("github", sample_fields(), None))
            .unwrap();

        let mut new_fields = BTreeMap::new();
        new_fields.insert("api_key".to_owned(), "key_xyz".to_owned());
        store
            .add(Credential::new(
                "github",
                new_fields,
                Some("new label".to_owned()),
            ))
            .unwrap();

        let loaded = store.get("github").unwrap().unwrap();
        assert_eq!(loaded.auth_method, AuthMethod::ApiKey);
        assert_eq!(loaded.label.as_deref(), Some("new label"));
        assert_eq!(store.count().unwrap(), 1);
    }

    #[test]
    fn store_serde_roundtrip() {
        let cred = Credential::new("github", sample_fields(), Some("test".to_owned()));
        let json = serde_json::to_string(&cred).unwrap();
        let restored: Credential = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.connector_id, "github");
        assert_eq!(restored.auth_method, AuthMethod::BearerToken);
        assert_eq!(restored.label.as_deref(), Some("test"));
    }

    // ── CLI parsing helpers ───────────────────────────────────────

    #[test]
    fn parse_credential_field_valid() {
        let (key, value) = parse_credential_field("token=ghp_abc123").unwrap();
        assert_eq!(key, "token");
        assert_eq!(value, "ghp_abc123");
    }

    #[test]
    fn parse_credential_field_with_equals_in_value() {
        let (key, value) = parse_credential_field("token=abc=def=ghi").unwrap();
        assert_eq!(key, "token");
        assert_eq!(value, "abc=def=ghi");
    }

    #[test]
    fn parse_credential_field_trims_whitespace() {
        let (key, value) = parse_credential_field("  token  =  ghp_abc  ").unwrap();
        assert_eq!(key, "token");
        assert_eq!(value, "ghp_abc");
    }

    #[test]
    fn parse_credential_field_empty_key() {
        assert!(parse_credential_field("=value").is_none());
    }

    #[test]
    fn parse_credential_field_empty_value() {
        assert!(parse_credential_field("key=").is_none());
    }

    #[test]
    fn parse_credential_field_no_equals() {
        assert!(parse_credential_field("no-equals-sign").is_none());
    }

    #[test]
    fn parse_credential_fields_multiple() {
        let inputs = vec!["username=admin".to_owned(), "password=secret".to_owned()];
        let fields = parse_credential_fields(&inputs).unwrap();
        assert_eq!(fields.len(), 2);
        assert_eq!(fields["username"], "admin");
        assert_eq!(fields["password"], "secret");
    }

    #[test]
    fn parse_credential_fields_empty_is_error() {
        let result = parse_credential_fields(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_credential_fields_invalid_entry() {
        let inputs = vec!["no-equals".to_owned()];
        let result = parse_credential_fields(&inputs);
        assert!(result.is_err());
    }

    // ── Connector ID validation ───────────────────────────────────

    #[test]
    fn validate_connector_id_valid() {
        assert!(validate_connector_id("github").is_ok());
        assert!(validate_connector_id("my-connector").is_ok());
        assert!(validate_connector_id("fcp.github.v2").is_ok());
        assert!(validate_connector_id("under_score").is_ok());
    }

    #[test]
    fn validate_connector_id_empty() {
        assert!(validate_connector_id("").is_err());
    }

    #[test]
    fn validate_connector_id_too_long() {
        let long = "a".repeat(65);
        assert!(validate_connector_id(&long).is_err());
    }

    #[test]
    fn validate_connector_id_invalid_chars() {
        assert!(validate_connector_id("has space").is_err());
        assert!(validate_connector_id("has/slash").is_err());
        assert!(validate_connector_id("has@at").is_err());
    }

    #[test]
    fn validate_connector_id_max_length_ok() {
        let max = "a".repeat(64);
        assert!(validate_connector_id(&max).is_ok());
    }

    // ── Additional AuthMethod tests ────────────────────────────────

    #[test]
    fn auth_method_serde_all_variants() {
        for (method, expected) in [
            (AuthMethod::BearerToken, "\"bearer_token\""),
            (AuthMethod::BasicAuth, "\"basic_auth\""),
            (AuthMethod::OAuth2, "\"o_auth2\""),
            (AuthMethod::ApiKey, "\"api_key\""),
            (AuthMethod::SessionToken, "\"session_token\""),
            (AuthMethod::SecretlessRef, "\"secretless_ref\""),
            (AuthMethod::Custom, "\"custom\""),
        ] {
            let json = serde_json::to_string(&method).unwrap();
            assert_eq!(json, expected);
            let back: AuthMethod = serde_json::from_str(&json).unwrap();
            assert_eq!(back, method);
        }
    }

    #[test]
    fn auth_method_clone() {
        let method = AuthMethod::OAuth2;
        let cloned = method.clone();
        assert_eq!(method, cloned);
    }

    #[test]
    fn auth_method_debug() {
        let debug = format!("{:?}", AuthMethod::BearerToken);
        assert_eq!(debug, "BearerToken");
    }

    #[test]
    fn detect_api_token_field() {
        let mut fields = BTreeMap::new();
        fields.insert("api_token".to_owned(), "tok_xyz".to_owned());
        assert_eq!(AuthMethod::detect(&fields), AuthMethod::BearerToken);
    }

    #[test]
    fn detect_empty_fields_is_custom() {
        let fields = BTreeMap::new();
        assert_eq!(AuthMethod::detect(&fields), AuthMethod::Custom);
    }

    #[test]
    fn detect_credential_id_takes_priority() {
        let mut fields = BTreeMap::new();
        fields.insert("credential_id".to_owned(), "ref-1".to_owned());
        fields.insert("token".to_owned(), "tok".to_owned());
        assert_eq!(AuthMethod::detect(&fields), AuthMethod::SecretlessRef);
    }

    #[test]
    fn detect_oauth2_takes_priority_over_basic() {
        let mut fields = BTreeMap::new();
        fields.insert("client_id".to_owned(), "id".to_owned());
        fields.insert("client_secret".to_owned(), "sec".to_owned());
        fields.insert("username".to_owned(), "user".to_owned());
        fields.insert("password".to_owned(), "pass".to_owned());
        assert_eq!(AuthMethod::detect(&fields), AuthMethod::OAuth2);
    }

    // ── Additional Credential tests ────────────────────────────────

    #[test]
    fn credential_serde_roundtrip_all_fields() {
        let mut cred = Credential::new("github", sample_fields(), Some("work".to_owned()));
        cred.touch();
        let json = serde_json::to_string_pretty(&cred).unwrap();
        let back: Credential = serde_json::from_str(&json).unwrap();
        assert_eq!(back.connector_id, "github");
        assert_eq!(back.auth_method, AuthMethod::BearerToken);
        assert_eq!(back.label.as_deref(), Some("work"));
        assert!(back.last_used_at.is_some());
        assert_eq!(back.get_field("token"), Some("ghp_abc123def456"));
    }

    #[test]
    fn credential_no_label() {
        let cred = Credential::new("slack", sample_basic_fields(), None);
        assert!(cred.label.is_none());
    }

    #[test]
    fn credential_get_field_multiple() {
        let cred = Credential::new("jira", sample_basic_fields(), None);
        assert_eq!(cred.get_field("username"), Some("admin"));
        assert_eq!(cred.get_field("password"), Some("s3cr3t_password"));
    }

    #[test]
    fn credential_clone() {
        let cred = Credential::new("github", sample_fields(), Some("test".to_owned()));
        let cloned = cred.clone();
        assert_eq!(cloned.connector_id, cred.connector_id);
        assert_eq!(cloned.auth_method, cred.auth_method);
        assert_eq!(cloned.fields, cred.fields);
    }

    #[test]
    fn credential_debug() {
        let cred = Credential::new("github", sample_fields(), None);
        let debug = format!("{cred:?}");
        assert!(debug.contains("github"));
    }

    #[test]
    fn credential_created_equals_updated() {
        let cred = Credential::new("github", sample_fields(), None);
        assert_eq!(cred.created_at, cred.updated_at);
    }

    #[test]
    fn credential_touch_multiple_times() {
        let mut cred = Credential::new("github", sample_fields(), None);
        cred.touch();
        let first = cred.last_used_at.unwrap();
        cred.touch();
        let second = cred.last_used_at.unwrap();
        assert!(second >= first);
    }

    // ── Additional redaction tests ─────────────────────────────────

    #[test]
    fn redact_exactly_8_chars() {
        assert_eq!(redact_value("abcdefgh"), "a***h");
    }

    #[test]
    fn redact_7_chars() {
        assert_eq!(redact_value("abcdefg"), "***");
    }

    #[test]
    fn redact_single_char() {
        assert_eq!(redact_value("x"), "***");
    }

    #[test]
    fn redact_empty() {
        assert_eq!(redact_value(""), "***");
    }

    #[test]
    fn redacted_view_all_fields_redacted() {
        let cred = Credential::new("jira", sample_basic_fields(), None);
        let view = cred.redacted_view();
        let fields = view["fields"].as_object().unwrap();
        for (_, v) in fields {
            assert!(v.as_str().unwrap().contains("***"));
        }
    }

    #[test]
    fn redacted_view_has_auth_method() {
        let cred = Credential::new("github", sample_fields(), None);
        let view = cred.redacted_view();
        assert_eq!(view["auth_method"], "bearer_token");
    }

    #[test]
    fn redacted_view_has_timestamps() {
        let cred = Credential::new("github", sample_fields(), None);
        let view = cred.redacted_view();
        assert!(view["created_at"].is_string());
        assert!(view["updated_at"].is_string());
    }

    // ── Additional encryption tests ────────────────────────────────

    #[test]
    fn encrypt_empty_plaintext() {
        let key = test_key();
        let encrypted = encrypt(b"", &key).unwrap();
        assert!(!encrypted.is_empty());
        let decrypted = decrypt(&encrypted, &key).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn encrypt_large_plaintext() {
        let key = test_key();
        let plaintext = vec![42u8; 10_000];
        let encrypted = encrypt(&plaintext, &key).unwrap();
        let decrypted = decrypt(&encrypted, &key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn decrypt_corrupted_ciphertext() {
        let key = test_key();
        let plaintext = b"test data";
        let mut encrypted = encrypt(plaintext, &key).unwrap();
        // Corrupt the ciphertext portion (after nonce)
        if encrypted.len() > NONCE_LEN + 5 {
            encrypted[NONCE_LEN + 5] ^= 0xFF;
        }
        let result = decrypt(&encrypted, &key);
        assert!(result.is_err());
    }

    #[test]
    fn decrypt_empty_fails() {
        let key = test_key();
        let result = decrypt(&[], &key);
        assert!(result.is_err());
    }

    #[test]
    fn encrypt_output_has_nonce_prefix() {
        let key = test_key();
        let encrypted = encrypt(b"test", &key).unwrap();
        // Output should be at least NONCE_LEN + 16 (tag) + plaintext
        assert!(encrypted.len() >= NONCE_LEN + 16 + 4);
    }

    // ── Additional CredentialStore tests ────────────────────────────

    #[test]
    fn store_multiple_credentials() {
        let store = temp_store();
        for connector in ["github", "slack", "jira", "notion", "linear"] {
            let mut fields = BTreeMap::new();
            fields.insert("token".to_owned(), format!("tok_{connector}"));
            store.add(Credential::new(connector, fields, None)).unwrap();
        }
        assert_eq!(store.count().unwrap(), 5);
        let ids = store.list_ids().unwrap();
        assert!(ids.contains(&"github".to_owned()));
        assert!(ids.contains(&"linear".to_owned()));
    }

    #[test]
    fn store_update_changes_auth_method() {
        let store = temp_store();
        store
            .add(Credential::new("github", sample_fields(), None))
            .unwrap();
        assert_eq!(
            store.get("github").unwrap().unwrap().auth_method,
            AuthMethod::BearerToken
        );

        // Add username and password fields
        let mut new_fields = BTreeMap::new();
        new_fields.insert("username".to_owned(), "user".to_owned());
        new_fields.insert("password".to_owned(), "pass".to_owned());
        store.update_fields("github", new_fields).unwrap();

        // Now it should detect as BasicAuth (has both username+password along with token)
        // Actually: token is still present, but detect checks order: credential_id > oauth2 > basic > bearer > api_key > session
        // Since username+password are present, it should be BasicAuth
        let loaded = store.get("github").unwrap().unwrap();
        assert_eq!(loaded.auth_method, AuthMethod::BasicAuth);
    }

    #[test]
    fn store_list_empty() {
        let store = temp_store();
        let list = store.list().unwrap();
        assert!(list.is_empty());
    }

    #[test]
    fn store_list_ids_empty() {
        let store = temp_store();
        let ids = store.list_ids().unwrap();
        assert!(ids.is_empty());
    }

    #[test]
    fn store_list_ids_sorted() {
        let store = temp_store();
        // BTreeMap keeps keys sorted
        store
            .add(Credential::new("zzz", sample_fields(), None))
            .unwrap();
        store
            .add(Credential::new("aaa", sample_fields(), None))
            .unwrap();
        store
            .add(Credential::new("mmm", sample_fields(), None))
            .unwrap();
        let ids = store.list_ids().unwrap();
        assert_eq!(ids, vec!["aaa", "mmm", "zzz"]);
    }

    #[test]
    fn store_path_method() {
        let store = temp_store();
        assert!(store.path().to_str().unwrap().contains("credentials.enc"));
    }

    #[test]
    fn keychain_store_add_and_get_without_file_fallback() {
        let store = temp_keychain_store(Arc::new(MockKeychainClient::available()));
        store
            .add(Credential::new("github", sample_fields(), None))
            .unwrap();

        let loaded = store.get("github").unwrap().unwrap();
        assert_eq!(loaded.connector_id, "github");
        assert_eq!(loaded.get_field("token"), Some("ghp_abc123def456"));
        assert!(!store.path().exists());
    }

    #[test]
    fn keychain_store_list_and_remove_use_keychain_index() {
        let store = temp_keychain_store(Arc::new(MockKeychainClient::available()));
        store
            .add(Credential::new("github", sample_fields(), None))
            .unwrap();
        store
            .add(Credential::new("slack", sample_basic_fields(), None))
            .unwrap();

        let ids = store.list_ids().unwrap();
        assert_eq!(ids, vec!["github", "slack"]);
        assert_eq!(store.count().unwrap(), 2);

        assert!(store.remove("github").unwrap());
        assert_eq!(store.list_ids().unwrap(), vec!["slack"]);
        assert_eq!(store.count().unwrap(), 1);
    }

    #[test]
    fn keychain_unavailable_falls_back_to_encrypted_file_store() {
        let store = temp_keychain_store(Arc::new(MockKeychainClient::unavailable()));
        store
            .add(Credential::new("github", sample_fields(), None))
            .unwrap();

        assert!(store.path().exists());
        let loaded = store.get("github").unwrap().unwrap();
        assert_eq!(loaded.get_field("token"), Some("ghp_abc123def456"));
        assert_eq!(store.list_ids().unwrap(), vec!["github"]);
    }

    #[test]
    fn unavailable_keychain_without_independent_key_never_writes_credentials() {
        let mut store = temp_keychain_store(Arc::new(MockKeychainClient::unavailable()));
        store.key = FileEncryptionKey::ConfiguredFile(None);
        let error = store
            .add(Credential::new("github", sample_fields(), None))
            .unwrap_err();
        assert!(error.contains(FILE_KEY_ENV));
        assert!(!error.contains("ghp_abc123def456"));
        assert!(!store.path().exists());
        assert!(!store.path().parent().unwrap().exists());
    }

    #[test]
    fn available_keychain_does_not_require_or_create_a_file_key() {
        let mut store = temp_keychain_store(Arc::new(MockKeychainClient::available()));
        store.key = FileEncryptionKey::ConfiguredFile(None);
        store
            .add(Credential::new("github", sample_fields(), None))
            .unwrap();
        assert_eq!(
            store.get("github").unwrap().unwrap().get_field("token"),
            Some("ghp_abc123def456")
        );
        assert_eq!(store.list_ids().unwrap(), vec!["github"]);
        assert!(store.remove("github").unwrap());
        assert!(!store.path().exists());
    }

    fn write_private_key(path: &Path, bytes: &[u8]) {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options.open(path).unwrap().write_all(bytes).unwrap();
    }

    #[test]
    fn independently_keyed_fallback_survives_reopen_and_rejects_another_key() {
        let temp = tempfile::tempdir().unwrap();
        let key_path = temp.path().join("independent.key");
        write_private_key(&key_path, &test_key());
        let path = temp.path().join("credentials.enc");
        let mut store = CredentialStore::new(&path, [0; KEY_LEN]);
        store.key = FileEncryptionKey::ConfiguredFile(Some(key_path.clone()));
        store
            .add(Credential::new("github", sample_fields(), None))
            .unwrap();
        let encrypted = std::fs::read(&path).unwrap();
        assert!(
            !encrypted
                .windows(b"ghp_abc123def456".len())
                .any(|part| part == b"ghp_abc123def456")
        );
        let mut reopened = CredentialStore::new(&path, [0; KEY_LEN]);
        reopened.key = FileEncryptionKey::ConfiguredFile(Some(key_path));
        assert_eq!(
            reopened.get("github").unwrap().unwrap().get_field("token"),
            Some("ghp_abc123def456")
        );
        let wrong = CredentialStore::new(&path, [99; KEY_LEN]);
        assert!(wrong.get("github").is_err());
        assert!(
            wrong
                .add(Credential::new("slack", sample_fields(), None))
                .is_err()
        );
        assert_eq!(std::fs::read(&path).unwrap(), encrypted);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn file_keys_accept_raw_or_hex_and_reject_malformed_or_oversized_input() {
        let temp = tempfile::tempdir().unwrap();
        for (name, contents, valid) in [
            ("raw", test_key().to_vec(), true),
            (
                "hex",
                format!("{}\n", hex::encode(test_key())).into_bytes(),
                true,
            ),
            ("short", b"not-a-secret-key".to_vec(), false),
            ("invalid-hex", vec![b'g'; 64], false),
            ("oversized", vec![b'0'; 4096], false),
        ] {
            let path = temp.path().join(name);
            write_private_key(&path, &contents);
            let result = read_file_key(&path);
            if valid {
                assert_eq!(*result.unwrap(), test_key());
            } else {
                assert!(result.is_err(), "{name}");
            }
        }
        assert!(read_file_key(temp.path()).is_err());
        assert!(read_file_key(&temp.path().join("missing")).is_err());
    }

    #[test]
    fn missing_file_key_preserves_existing_ciphertext_and_never_uses_machine_identity() {
        let store = temp_store();
        store
            .add(Credential::new("github", sample_fields(), None))
            .unwrap();
        let encrypted = std::fs::read(store.path()).unwrap();
        let mut unconfigured = CredentialStore::new(store.path(), test_key());
        unconfigured.key = FileEncryptionKey::ConfiguredFile(None);
        assert!(
            unconfigured
                .get("github")
                .unwrap_err()
                .contains(FILE_KEY_ENV)
        );
        assert!(unconfigured.list().is_err());
        assert!(
            unconfigured
                .add(Credential::new("slack", sample_fields(), None))
                .is_err()
        );
        assert!(unconfigured.remove("github").is_err());
        assert_eq!(std::fs::read(store.path()).unwrap(), encrypted);
        assert!(store.get("github").unwrap().is_some());
    }

    #[cfg(unix)]
    #[test]
    fn file_keys_reject_public_permissions_and_symbolic_links() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("key");
        write_private_key(&path, &test_key());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_file_key(&path).unwrap_err().contains("0600"));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert_eq!(*read_file_key(&path).unwrap(), test_key());
        let alias = temp.path().join("alias");
        symlink(&path, &alias).unwrap();
        assert!(read_file_key(&alias).is_err());
    }

    #[test]
    fn store_remove_nonexistent() {
        let store = temp_store();
        assert!(!store.remove("nope").unwrap());
    }

    // ── Additional CLI parsing tests ───────────────────────────────

    #[test]
    fn parse_field_special_chars_in_value() {
        let (k, v) = parse_credential_field("token=abc!@#$%^&*()").unwrap();
        assert_eq!(k, "token");
        assert_eq!(v, "abc!@#$%^&*()");
    }

    #[test]
    fn parse_field_url_value() {
        let (k, v) = parse_credential_field("base_url=https://api.example.com/v2").unwrap();
        assert_eq!(k, "base_url");
        assert_eq!(v, "https://api.example.com/v2");
    }

    #[test]
    fn parse_fields_single() {
        let inputs = vec!["token=abc".to_owned()];
        let fields = parse_credential_fields(&inputs).unwrap();
        assert_eq!(fields.len(), 1);
        assert_eq!(fields["token"], "abc");
    }

    #[test]
    fn parse_fields_invalid_among_valid() {
        let inputs = vec!["token=abc".to_owned(), "bad-field".to_owned()];
        let result = parse_credential_fields(&inputs);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("bad-field"));
    }

    // ── Additional connector ID validation tests ───────────────────

    #[test]
    fn validate_connector_id_single_char() {
        assert!(validate_connector_id("a").is_ok());
    }

    #[test]
    fn validate_connector_id_numbers() {
        assert!(validate_connector_id("123").is_ok());
    }

    #[test]
    fn validate_connector_id_dots_and_dashes() {
        assert!(validate_connector_id("fcp.github-v2").is_ok());
    }

    #[test]
    fn validate_connector_id_underscore() {
        assert!(validate_connector_id("my_connector").is_ok());
    }

    #[test]
    fn validate_connector_id_unicode_rejected() {
        assert!(validate_connector_id("héllo").is_err());
    }

    #[test]
    fn validate_connector_id_newline_rejected() {
        assert!(validate_connector_id("abc\ndef").is_err());
    }

    #[test]
    fn validate_connector_id_error_message_empty() {
        let err = validate_connector_id("").unwrap_err();
        assert!(err.contains("empty"));
    }

    #[test]
    fn validate_connector_id_error_message_too_long() {
        let long = "x".repeat(65);
        let err = validate_connector_id(&long).unwrap_err();
        assert!(err.contains("too long"));
    }

    #[test]
    fn validate_connector_id_error_message_invalid_chars() {
        let err = validate_connector_id("has space").unwrap_err();
        assert!(err.contains("invalid characters"));
    }

    // ── AuthMethod priority / edge cases ──────────────────────────────

    #[test]
    fn detect_refresh_token_alone_is_oauth2() {
        let mut fields = BTreeMap::new();
        fields.insert("refresh_token".to_owned(), "rtok".to_owned());
        assert_eq!(AuthMethod::detect(&fields), AuthMethod::OAuth2);
    }

    #[test]
    fn detect_client_id_only_is_custom() {
        // client_id without client_secret does not trigger OAuth2
        let mut fields = BTreeMap::new();
        fields.insert("client_id".to_owned(), "id_only".to_owned());
        assert_eq!(AuthMethod::detect(&fields), AuthMethod::Custom);
    }

    #[test]
    fn detect_client_secret_only_is_custom() {
        let mut fields = BTreeMap::new();
        fields.insert("client_secret".to_owned(), "sec_only".to_owned());
        assert_eq!(AuthMethod::detect(&fields), AuthMethod::Custom);
    }

    #[test]
    fn detect_secretless_ref_overrides_oauth2_fields() {
        // credential_id takes highest priority even when oauth2 fields present
        let mut fields = BTreeMap::new();
        fields.insert("credential_id".to_owned(), "ref-1".to_owned());
        fields.insert("access_token".to_owned(), "tok".to_owned());
        fields.insert("refresh_token".to_owned(), "rtok".to_owned());
        assert_eq!(AuthMethod::detect(&fields), AuthMethod::SecretlessRef);
    }

    #[test]
    fn detect_secretless_ref_overrides_basic_auth() {
        let mut fields = BTreeMap::new();
        fields.insert("credential_id".to_owned(), "ref".to_owned());
        fields.insert("username".to_owned(), "user".to_owned());
        fields.insert("password".to_owned(), "pass".to_owned());
        assert_eq!(AuthMethod::detect(&fields), AuthMethod::SecretlessRef);
    }

    #[test]
    fn auth_method_eq_all_variants() {
        assert_eq!(AuthMethod::BearerToken, AuthMethod::BearerToken);
        assert_eq!(AuthMethod::BasicAuth, AuthMethod::BasicAuth);
        assert_eq!(AuthMethod::OAuth2, AuthMethod::OAuth2);
        assert_eq!(AuthMethod::ApiKey, AuthMethod::ApiKey);
        assert_eq!(AuthMethod::SessionToken, AuthMethod::SessionToken);
        assert_eq!(AuthMethod::SecretlessRef, AuthMethod::SecretlessRef);
        assert_eq!(AuthMethod::Custom, AuthMethod::Custom);
    }

    #[test]
    fn auth_method_ne_across_variants() {
        assert_ne!(AuthMethod::BearerToken, AuthMethod::BasicAuth);
        assert_ne!(AuthMethod::OAuth2, AuthMethod::ApiKey);
        assert_ne!(AuthMethod::SessionToken, AuthMethod::Custom);
    }

    // ── Credential field edge cases ────────────────────────────────────

    #[test]
    fn credential_many_fields() {
        let mut fields = BTreeMap::new();
        for i in 0..20u32 {
            fields.insert(format!("field_{i}"), format!("value_{i}"));
        }
        let cred = Credential::new("big-connector", fields, None);
        assert_eq!(cred.fields.len(), 20);
        assert_eq!(cred.get_field("field_0"), Some("value_0"));
        assert_eq!(cred.get_field("field_19"), Some("value_19"));
    }

    #[test]
    fn credential_get_field_missing_returns_none() {
        let cred = Credential::new("github", sample_fields(), None);
        assert_eq!(cred.get_field("nonexistent_field"), None);
        assert_eq!(cred.get_field(""), None);
    }

    #[test]
    fn credential_empty_fields_is_custom() {
        let cred = Credential::new("custom-svc", BTreeMap::new(), None);
        assert_eq!(cred.auth_method, AuthMethod::Custom);
    }

    #[test]
    fn credential_updated_at_equals_created_at_on_new() {
        let cred = Credential::new("svc", sample_fields(), None);
        assert_eq!(cred.created_at, cred.updated_at);
    }

    #[test]
    fn credential_label_none_by_default() {
        let cred = Credential::new("svc", sample_fields(), None);
        assert!(cred.label.is_none());
        let view = cred.redacted_view();
        assert!(view["label"].is_null());
    }

    #[test]
    fn credential_label_present_in_view() {
        let cred = Credential::new("svc", sample_fields(), Some("production API".to_owned()));
        let view = cred.redacted_view();
        assert_eq!(view["label"], "production API");
    }

    // ── Redaction boundary conditions ─────────────────────────────────

    #[test]
    fn redact_exactly_7_chars_returns_stars() {
        assert_eq!(redact_value("abcdefg"), "***");
    }

    #[test]
    fn redact_exactly_8_chars_shows_first_last() {
        // 8 chars: first + *** + last pattern
        let result = redact_value("ABCDEFGH");
        assert_eq!(result, "A***H");
    }

    #[test]
    fn redact_9_chars_shows_first_last() {
        let result = redact_value("123456789");
        assert_eq!(result, "1***9");
    }

    #[test]
    fn redact_long_unicode_value() {
        // Multi-byte unicode characters still work because we use chars()
        let value = "alphàbétàgamma"; // contains multi-byte chars
        let result = redact_value(value);
        // Should show first and last chars with stars if >= 8 chars
        let char_count = value.chars().count();
        if char_count >= 8 {
            assert!(result.contains("***"));
            assert!(!result.contains(&value[..2]));
        } else {
            assert_eq!(result, "***");
        }
    }

    #[test]
    fn redacted_view_last_used_at_null_before_touch() {
        let cred = Credential::new("github", sample_fields(), None);
        let view = cred.redacted_view();
        assert!(view["last_used_at"].is_null());
    }

    #[test]
    fn redacted_view_last_used_at_string_after_touch() {
        let mut cred = Credential::new("github", sample_fields(), None);
        cred.touch();
        let view = cred.redacted_view();
        assert!(view["last_used_at"].is_string());
    }

    #[test]
    fn redacted_view_connector_id_unchanged() {
        let cred = Credential::new("special-connector", sample_fields(), None);
        let view = cred.redacted_view();
        assert_eq!(view["connector_id"], "special-connector");
    }

    // ── Encryption edge cases ──────────────────────────────────────────

    #[test]
    fn encrypt_decrypt_all_zero_key() {
        let key = [0u8; KEY_LEN];
        let plaintext = b"zero key test";
        let encrypted = encrypt(plaintext, &key).unwrap();
        let decrypted = decrypt(&encrypted, &key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypt_decrypt_all_max_key() {
        let key = [0xFFu8; KEY_LEN];
        let plaintext = b"max key test";
        let encrypted = encrypt(plaintext, &key).unwrap();
        let decrypted = decrypt(&encrypted, &key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn decrypt_truncated_just_before_min_length() {
        let key = test_key();
        // Exactly NONCE_LEN + 15 bytes = 1 short of minimum (NONCE_LEN + 16)
        let short = vec![0u8; NONCE_LEN + 15];
        let result = decrypt(&short, &key);
        assert!(result.is_err());
    }

    #[test]
    fn decrypt_exactly_min_length_still_fails_bad_auth() {
        let key = test_key();
        // NONCE_LEN + 16 is minimum, but a fake/zeroed buffer won't decrypt
        let min_buf = vec![0u8; NONCE_LEN + 16];
        let result = decrypt(&min_buf, &key);
        assert!(result.is_err());
    }

    #[test]
    fn encrypt_multiple_keys_cross_decrypt_fail() {
        let key_a = test_key();
        let mut key_b = test_key();
        key_b[31] ^= 0xAA;

        let plaintext = b"cross key test";
        let encrypted_a = encrypt(plaintext, &key_a).unwrap();
        let result = decrypt(&encrypted_a, &key_b);
        assert!(result.is_err());
    }

    // ── CredentialStore edge cases ─────────────────────────────────────

    #[test]
    fn store_add_overwrites_existing_credential() {
        let store = temp_store();
        let cred1 = Credential::new("svc", sample_fields(), Some("v1".to_owned()));
        store.add(cred1).unwrap();

        let mut fields2 = BTreeMap::new();
        fields2.insert("api_key".to_owned(), "new_key_val".to_owned());
        let cred2 = Credential::new("svc", fields2, Some("v2".to_owned()));
        store.add(cred2).unwrap();

        let loaded = store.get("svc").unwrap().unwrap();
        assert_eq!(loaded.label.as_deref(), Some("v2"));
        assert_eq!(loaded.auth_method, AuthMethod::ApiKey);
        assert_eq!(store.count().unwrap(), 1);
    }

    #[test]
    fn store_remove_second_entry_leaves_first() {
        let store = temp_store();
        store
            .add(Credential::new("github", sample_fields(), None))
            .unwrap();
        store
            .add(Credential::new("slack", sample_basic_fields(), None))
            .unwrap();

        assert!(store.remove("slack").unwrap());
        assert_eq!(store.count().unwrap(), 1);
        assert!(store.get("github").unwrap().is_some());
        assert!(store.get("slack").unwrap().is_none());
    }

    #[test]
    fn store_list_returns_redacted_entries() {
        let store = temp_store();
        let mut fields = BTreeMap::new();
        fields.insert("api_key".to_owned(), "should-be-redacted-val".to_owned());
        store.add(Credential::new("svc", fields, None)).unwrap();

        let list = store.list().unwrap();
        assert_eq!(list.len(), 1);
        let api_key_val = list[0]["fields"]["api_key"].as_str().unwrap();
        assert!(!api_key_val.contains("should-be-redacted-val"));
        assert!(api_key_val.contains("***"));
    }

    #[test]
    fn store_update_fields_adds_new_fields() {
        let store = temp_store();
        store
            .add(Credential::new("svc", sample_fields(), None))
            .unwrap();

        let mut extra = BTreeMap::new();
        extra.insert("base_url".to_owned(), "https://api.example.com".to_owned());
        store.update_fields("svc", extra).unwrap();

        let loaded = store.get("svc").unwrap().unwrap();
        assert_eq!(
            loaded.get_field("base_url"),
            Some("https://api.example.com")
        );
        // Original token field still there
        assert_eq!(loaded.get_field("token"), Some("ghp_abc123def456"));
    }

    #[test]
    fn store_update_fields_empty_map_preserves_credential() {
        let store = temp_store();
        store
            .add(Credential::new("svc", sample_fields(), None))
            .unwrap();

        let result = store.update_fields("svc", BTreeMap::new()).unwrap();
        assert!(result); // returned true because it existed
        let loaded = store.get("svc").unwrap().unwrap();
        assert_eq!(loaded.get_field("token"), Some("ghp_abc123def456"));
    }

    #[test]
    fn store_touch_updates_last_used_at_twice() {
        let store = temp_store();
        store
            .add(Credential::new("svc", sample_fields(), None))
            .unwrap();

        assert!(store.touch("svc").unwrap());
        let first_touch = store.get("svc").unwrap().unwrap().last_used_at.unwrap();
        assert!(store.touch("svc").unwrap());
        let second_touch = store.get("svc").unwrap().unwrap().last_used_at.unwrap();
        // second touch should be >= first touch
        assert!(second_touch >= first_touch);
    }

    #[test]
    fn store_count_after_remove() {
        let store = temp_store();
        for id in ["a", "b", "c"] {
            store
                .add(Credential::new(id, sample_fields(), None))
                .unwrap();
        }
        assert_eq!(store.count().unwrap(), 3);
        store.remove("b").unwrap();
        assert_eq!(store.count().unwrap(), 2);
        store.remove("a").unwrap();
        assert_eq!(store.count().unwrap(), 1);
        store.remove("c").unwrap();
        assert_eq!(store.count().unwrap(), 0);
    }

    #[test]
    fn store_list_ids_reflects_add_and_remove_order() {
        let store = temp_store();
        store
            .add(Credential::new("beta", sample_fields(), None))
            .unwrap();
        store
            .add(Credential::new("alpha", sample_fields(), None))
            .unwrap();
        store
            .add(Credential::new("gamma", sample_fields(), None))
            .unwrap();
        // BTreeMap sorts alphabetically
        let ids = store.list_ids().unwrap();
        assert_eq!(ids, vec!["alpha", "beta", "gamma"]);
    }

    #[test]
    fn store_path_is_accessible() {
        let store = temp_store();
        let p = store.path();
        assert!(!p.to_str().unwrap().is_empty());
        assert!(p.ends_with("credentials.enc"));
    }

    // ── Keychain mock tests ────────────────────────────────────────────

    #[test]
    fn keychain_store_update_fields() {
        let store = temp_keychain_store(Arc::new(MockKeychainClient::available()));
        store
            .add(Credential::new("svc", sample_fields(), None))
            .unwrap();

        let mut new_fields = BTreeMap::new();
        new_fields.insert("token".to_owned(), "updated_token_val".to_owned());
        assert!(store.update_fields("svc", new_fields).unwrap());

        let loaded = store.get("svc").unwrap().unwrap();
        assert_eq!(loaded.get_field("token"), Some("updated_token_val"));
    }

    #[test]
    fn keychain_store_count() {
        let store = temp_keychain_store(Arc::new(MockKeychainClient::available()));
        assert_eq!(store.count().unwrap(), 0);
        store
            .add(Credential::new("a", sample_fields(), None))
            .unwrap();
        assert_eq!(store.count().unwrap(), 1);
        store
            .add(Credential::new("b", sample_basic_fields(), None))
            .unwrap();
        assert_eq!(store.count().unwrap(), 2);
    }

    #[test]
    fn keychain_store_touch() {
        let store = temp_keychain_store(Arc::new(MockKeychainClient::available()));
        store
            .add(Credential::new("svc", sample_fields(), None))
            .unwrap();
        assert!(store.touch("svc").unwrap());
        let loaded = store.get("svc").unwrap().unwrap();
        assert!(loaded.last_used_at.is_some());
    }

    #[test]
    fn keychain_store_remove_last_entry_clears_index() {
        let store = temp_keychain_store(Arc::new(MockKeychainClient::available()));
        store
            .add(Credential::new("solo", sample_fields(), None))
            .unwrap();
        assert!(store.remove("solo").unwrap());
        assert_eq!(store.count().unwrap(), 0);
        assert!(store.list_ids().unwrap().is_empty());
    }

    #[test]
    fn keychain_unavailable_list_works_from_file() {
        let store = temp_keychain_store(Arc::new(MockKeychainClient::unavailable()));
        store
            .add(Credential::new("github", sample_fields(), None))
            .unwrap();
        store
            .add(Credential::new("slack", sample_basic_fields(), None))
            .unwrap();

        let list = store.list().unwrap();
        assert_eq!(list.len(), 2);
        let ids = store.list_ids().unwrap();
        assert!(ids.contains(&"github".to_owned()));
        assert!(ids.contains(&"slack".to_owned()));
    }

    // ── CLI parse_credential_field trims and splits edge cases ────────

    #[test]
    fn parse_field_empty_string_returns_none() {
        assert!(parse_credential_field("").is_none());
    }

    #[test]
    fn parse_field_whitespace_only_returns_none() {
        assert!(parse_credential_field("   ").is_none());
    }

    #[test]
    fn parse_field_key_only_with_equals_is_none() {
        // "key=" => value is empty after trim => None
        assert!(parse_credential_field("key=").is_none());
    }

    #[test]
    fn parse_field_value_with_spaces_preserved() {
        // Value portion after trim still contains internal spaces
        let (k, v) = parse_credential_field("note=hello world").unwrap();
        assert_eq!(k, "note");
        assert_eq!(v, "hello world");
    }

    #[test]
    fn parse_fields_deduplicates_last_wins() {
        // BTreeMap: duplicate keys take last value
        let inputs = vec!["token=first".to_owned(), "token=second".to_owned()];
        let fields = parse_credential_fields(&inputs).unwrap();
        assert_eq!(fields["token"], "second");
        assert_eq!(fields.len(), 1);
    }

    // ── validate_connector_id further boundary checks ──────────────────

    #[test]
    fn validate_connector_id_tab_rejected() {
        assert!(validate_connector_id("has\ttab").is_err());
    }

    #[test]
    fn validate_connector_id_null_byte_rejected() {
        assert!(validate_connector_id("has\0null").is_err());
    }

    #[test]
    fn validate_connector_id_exactly_64_chars() {
        let id = "a".repeat(64);
        assert!(validate_connector_id(&id).is_ok());
    }

    #[test]
    fn validate_connector_id_65_chars() {
        let id = "a".repeat(65);
        assert!(validate_connector_id(&id).is_err());
    }

    #[test]
    fn validate_connector_id_mixed_valid_chars() {
        assert!(validate_connector_id("fcp.github-v2_connector").is_ok());
    }

    // ── Serde round-trips for various AuthMethod variants ─────────────

    #[test]
    fn auth_method_deserialization_error_on_bad_value() {
        let result = serde_json::from_str::<AuthMethod>("\"bad_variant\"");
        assert!(result.is_err());
    }

    #[test]
    fn auth_method_serde_bearer_token_string() {
        let json = serde_json::to_string(&AuthMethod::BearerToken).unwrap();
        assert_eq!(json, "\"bearer_token\"");
    }

    #[test]
    fn credential_serde_preserves_fields_map() {
        let mut fields = BTreeMap::new();
        fields.insert("api_key".to_owned(), "secret_key_val".to_owned());
        fields.insert("base_url".to_owned(), "https://example.com".to_owned());
        let cred = Credential::new("svc", fields.clone(), None);
        let json = serde_json::to_string(&cred).unwrap();
        let back: Credential = serde_json::from_str(&json).unwrap();
        assert_eq!(back.fields, fields);
    }
}
