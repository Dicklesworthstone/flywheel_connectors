//! Obsidian vault filesystem client.

use std::collections::HashMap;
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};

use cap_fs_ext::{AccessType, DirExt};
use cap_primitives::fs::AccessModes;
use cap_std::fs::{Dir, OpenOptions};
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};

use crate::error::{ObsidianError, ObsidianResult};
use crate::types::{Backlink, Note, NoteEntry, SearchMatch, SearchResult, TagInfo, VaultHealth};

/// Client for interacting with an Obsidian vault on the local filesystem.
pub struct ObsidianClient {
    vault_path: PathBuf,
    vault: Dir,
}

impl std::fmt::Debug for ObsidianClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ObsidianClient")
            .field("vault_path", &self.vault_path)
            .finish_non_exhaustive()
    }
}

impl ObsidianClient {
    /// Create a new vault client.
    ///
    /// # Errors
    ///
    /// Returns an error if the vault path does not exist or is not a directory.
    pub fn new(vault_path: &str) -> ObsidianResult<Self> {
        let path = PathBuf::from(vault_path);
        if !path.exists() {
            return Err(ObsidianError::InvalidVault(format!(
                "path does not exist: {vault_path}"
            )));
        }
        if !path.is_dir() {
            return Err(ObsidianError::InvalidVault(format!(
                "path is not a directory: {vault_path}"
            )));
        }
        // Canonicalize to resolve any symlinks for later traversal checks
        let canonical = path.canonicalize().map_err(|e| {
            ObsidianError::InvalidVault(format!("failed to canonicalize vault path: {e}"))
        })?;
        let vault = Dir::open_ambient_dir(&canonical, cap_std::ambient_authority())?;
        Ok(Self {
            vault_path: canonical,
            vault,
        })
    }

    /// Resolve an existing note relative to the open vault directory.
    fn existing_note_path(&self, path: &str) -> ObsidianResult<PathBuf> {
        sanitize_path_segment(path)?;
        self.vault.canonicalize(path).map_err(|error| {
            if error.kind() == ErrorKind::NotFound {
                ObsidianError::NotFound(path.into())
            } else {
                error.into()
            }
        })
    }

    /// List all markdown notes in the vault.
    ///
    /// # Errors
    ///
    /// Returns an error if the folder path is invalid or directory traversal fails.
    pub fn list_notes(&self, folder: Option<&str>) -> ObsidianResult<Vec<NoteEntry>> {
        let root = Path::new(folder.unwrap_or("."));
        if let Some(folder) = folder {
            sanitize_path_segment(folder)?;
            if root.components().any(|component| {
                matches!(component, std::path::Component::Normal(name) if name.to_string_lossy().starts_with('.'))
            }) {
                return Ok(Vec::new());
            }
            let normalized = root.strip_prefix(".").unwrap_or(root);
            if !normalized.as_os_str().is_empty() {
                match self.vault.canonicalize(root) {
                    Ok(path) if path == normalized && self.vault.is_dir(root) => {}
                    Ok(_) => return Ok(Vec::new()),
                    Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
                    Err(error) => return Err(error.into()),
                }
            }
        }
        let mut entries = Vec::new();
        self.visit_notes(root, |path| {
            if let Ok(entry) = self.read_note_entry(path) {
                entries.push(entry);
            }
        })?;
        entries.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(entries)
    }

    fn visit_notes(&self, root: &Path, mut visit: impl FnMut(&Path)) -> ObsidianResult<()> {
        let mut pending = vec![root.to_owned()];
        while let Some(dir) = pending.pop() {
            for entry in self.vault.read_dir(&dir)? {
                let entry = entry?;
                let kind = entry.file_type()?;
                let name = entry.file_name();
                let path = if dir == Path::new(".") {
                    PathBuf::from(&name)
                } else {
                    dir.join(&name)
                };
                if kind.is_dir() && !name.to_string_lossy().starts_with('.') {
                    pending.push(path);
                } else if kind.is_file() && path.extension().is_some_and(|ext| ext == "md") {
                    visit(&path);
                }
            }
        }
        Ok(())
    }

    fn read_note_entry(&self, path: &Path) -> ObsidianResult<NoteEntry> {
        let mut file = self.vault.open(path)?.into_std();
        let metadata = file.metadata()?;
        let mut content = String::new();
        file.read_to_string(&mut content)?;
        Ok(NoteEntry {
            path: path.to_string_lossy().into_owned(),
            title: path.file_stem()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned(),
            size: metadata.len(),
            modified: format_system_time(metadata.modified().ok()),
            created: format_system_time(metadata.created().ok()),
            tags: extract_tags(&content),
        })
    }

    /// Get a single note by path.
    ///
    /// # Errors
    ///
    /// Returns an error if the path is invalid, the note does not exist, or reading fails.
    pub fn get_note(&self, note_path: &str) -> ObsidianResult<Note> {
        let path = self.existing_note_path(note_path)?;
        let mut file = self.vault.open(&path)?.into_std();
        let metadata = file.metadata()?;
        let mut content = String::new();
        file.read_to_string(&mut content)?;
        let tags = extract_tags(&content);
        Ok(Note {
            path: path.to_string_lossy().into_owned(),
            title: path.file_stem()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned(),
            content: Some(content),
            size: metadata.len(),
            modified: format_system_time(metadata.modified().ok()),
            created: format_system_time(metadata.created().ok()),
            tags,
        })
    }

    /// Create a new note (atomic: uses `create_new` to avoid TOCTOU).
    ///
    /// # Errors
    ///
    /// Returns an error if the path is invalid, the note already exists, or writing fails.
    pub fn create_note(&self, note_path: &str, content: &str) -> ObsidianResult<Note> {
        sanitize_path_segment(note_path)?;
        if let Some(parent) = Path::new(note_path)
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
        {
            self.vault.create_dir_all(parent)?;
        }
        match self
            .vault
            .open_with(note_path, OpenOptions::new().write(true).create_new(true))
        {
            Ok(mut file) => file.write_all(content.as_bytes())?,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(ObsidianError::AlreadyExists(note_path.to_string()));
            }
            Err(e) => return Err(e.into()),
        }
        self.get_note(note_path)
    }

    /// Update an existing note.
    ///
    /// # Errors
    ///
    /// Returns an error if the path is invalid, the note does not exist, or writing fails.
    pub fn update_note(&self, note_path: &str, content: &str) -> ObsidianResult<Note> {
        let path = self.existing_note_path(note_path)?;
        match self
            .vault
            .open_with(path, OpenOptions::new().write(true).truncate(true))
        {
            Ok(mut file) => file.write_all(content.as_bytes())?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(ObsidianError::NotFound(note_path.to_string()));
            }
            Err(e) => return Err(e.into()),
        }
        self.get_note(note_path)
    }

    /// Delete a note.
    ///
    /// # Errors
    ///
    /// Returns an error if the path is invalid, the note does not exist, or deletion fails.
    pub fn delete_note(&self, note_path: &str) -> ObsidianResult<()> {
        let full_path = self.existing_note_path(note_path)?;
        // Remove directly — if the file doesn't exist, map to NotFound,
        // avoiding TOCTOU between exists() and remove_file().
        match self.vault.remove_file(&full_path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(ObsidianError::NotFound(note_path.to_string()))
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Search notes for a text pattern.
    ///
    /// # Errors
    ///
    /// Returns an error if reading the vault directory fails.
    pub fn search(&self, query: &str) -> ObsidianResult<Vec<SearchResult>> {
        let query_lower = query.to_lowercase();
        let mut results = Vec::new();
        self.visit_notes(Path::new("."), |path| {
            if let Ok(content) = self.vault.read_to_string(path) {
                let matches: Vec<_> = content
                    .lines()
                    .enumerate()
                    .filter(|(_, line)| line.to_lowercase().contains(&query_lower))
                    .map(|(i, line)| SearchMatch {
                        line: i + 1,
                        text: line.to_owned(),
                    })
                    .collect();
                if !matches.is_empty() {
                    results.push(SearchResult {
                        path: path.to_string_lossy().into_owned(),
                        title: path
                            .file_stem()
                            .unwrap_or_default()
                            .to_string_lossy()
                            .into_owned(),
                        matches,
                    });
                }
            }
        })?;
        results.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(results)
    }

    /// List all tags across the vault.
    ///
    /// # Errors
    ///
    /// Returns an error if reading the vault directory fails.
    pub fn list_tags(&self) -> ObsidianResult<Vec<TagInfo>> {
        let mut tag_counts: HashMap<String, usize> = HashMap::new();
        self.visit_notes(Path::new("."), |path| {
            if let Ok(content) = self.vault.read_to_string(path) {
                for tag in extract_tags(&content) {
                    *tag_counts.entry(tag).or_default() += 1;
                }
            }
        })?;
        let mut tags: Vec<TagInfo> = tag_counts
            .into_iter()
            .map(|(tag, count)| TagInfo { tag, count })
            .collect();
        tags.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.tag.cmp(&b.tag)));
        Ok(tags)
    }

    /// Get backlinks for a note (other notes linking to this one).
    ///
    /// # Errors
    ///
    /// Returns an error if the note path is invalid or reading the vault directory fails.
    pub fn get_backlinks(&self, note_path: &str) -> ObsidianResult<Vec<Backlink>> {
        // Derive the link target name from the note path
        let target_name = Path::new(note_path)
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .ok_or_else(|| ObsidianError::InvalidInput("invalid note path".into()))?;

        let link_pattern = format!("[[{target_name}");
        let mut backlinks = Vec::new();
        self.visit_notes(Path::new("."), |path| {
            if path == Path::new(note_path) {
                return;
            }
            if let Ok(content) = self.vault.read_to_string(path) {
                for (i, line) in content.lines().enumerate() {
                    if line.contains(&link_pattern) {
                        backlinks.push(Backlink {
                            source_path: path.to_string_lossy().into_owned(),
                            source_title: path
                                .file_stem()
                                .unwrap_or_default()
                                .to_string_lossy()
                                .into_owned(),
                            line: i + 1,
                            context: line.to_owned(),
                        });
                    }
                }
            }
        })?;
        backlinks.sort_by(|a, b| a.source_path.cmp(&b.source_path));
        Ok(backlinks)
    }

    /// Get vault health information.
    ///
    /// # Errors
    ///
    /// Returns an error if reading the vault directory fails.
    pub fn vault_health(&self) -> ObsidianResult<VaultHealth> {
        let mut note_count = 0_usize;
        let mut total_size = 0_u64;
        self.visit_notes(Path::new("."), |path| {
            note_count += 1;
            if let Ok(metadata) = self.vault.metadata(path) {
                total_size += metadata.len();
            }
        })?;
        let writable = self
            .vault
            .access(
                ".",
                AccessType::Access(AccessModes {
                    readable: false,
                    writable: true,
                    executable: true,
                }),
            )
            .is_ok();

        Ok(VaultHealth {
            vault_path: self.vault_path.to_string_lossy().to_string(),
            note_count,
            total_size_bytes: total_size,
            readable: true,
            writable,
        })
    }

    /// Get the vault path (for diagnostics).
    #[must_use]
    pub fn vault_path(&self) -> &Path {
        &self.vault_path
    }

    /// Create a `ConnectorRuntime` suitable for this connector.
    #[must_use]
    pub fn create_runtime() -> ConnectorRuntime {
        ConnectorRuntime::new(
            ConnectorRuntimeConfig::default()
                .with_request_timeout(std::time::Duration::from_secs(10)),
        )
    }
}

/// Sanitize a path segment to prevent directory traversal attacks.
///
/// # Errors
///
/// Returns an error if the path is empty, absolute, contains `..`, or contains null bytes.
pub fn sanitize_path_segment(path: &str) -> ObsidianResult<()> {
    if path.is_empty() {
        return Err(ObsidianError::InvalidInput("empty path".into()));
    }
    // Reject any path with .. components
    for component in Path::new(path).components() {
        if matches!(component, std::path::Component::ParentDir) {
            return Err(ObsidianError::InvalidInput(
                "path traversal '..' not allowed".into(),
            ));
        }
    }
    // Reject absolute paths
    if Path::new(path).is_absolute() {
        return Err(ObsidianError::InvalidInput(
            "absolute paths not allowed".into(),
        ));
    }
    // Reject null bytes
    if path.contains('\0') {
        return Err(ObsidianError::InvalidInput(
            "null bytes not allowed in path".into(),
        ));
    }
    Ok(())
}

/// Extract tags from note content.
/// Supports:
/// - Frontmatter tags: `tags: [tag1, tag2]` or `tags:\n  - tag1\n  - tag2`
/// - Inline tags: `#tag` (but not `#heading` at start of line)
fn extract_tags(content: &str) -> Vec<String> {
    let mut tags = Vec::new();
    let mut seen = std::collections::HashSet::new();

    // Extract inline #tags (not headings)
    for line in content.lines() {
        let trimmed = line.trim();
        // Skip markdown headings
        if trimmed.starts_with('#') && trimmed.chars().nth(1).is_some_and(|c| c == ' ' || c == '#')
        {
            continue;
        }
        // Find #tag patterns in the line
        let chars: Vec<char> = line.chars().collect();
        let mut i = 0;
        while i < chars.len() {
            if chars[i] == '#' {
                // Check that preceding char is whitespace or start of line
                let valid_start = i == 0 || chars[i - 1].is_whitespace();
                if valid_start {
                    let start = i + 1;
                    let mut end = start;
                    while end < chars.len()
                        && (chars[end].is_alphanumeric()
                            || chars[end] == '_'
                            || chars[end] == '-'
                            || chars[end] == '/')
                    {
                        end += 1;
                    }
                    if end > start {
                        let tag: String = chars[start..end].iter().collect();
                        if seen.insert(tag.clone()) {
                            tags.push(tag);
                        }
                    }
                }
            }
            i += 1;
        }
    }

    // Extract frontmatter tags (YAML-style)
    if let Some(after_open) = content.strip_prefix("---")
        && let Some(end) = after_open.find("---")
    {
        let frontmatter = &after_open[..end];
        for line in frontmatter.lines() {
            let trimmed = line.trim();
            // tags: [tag1, tag2]
            if let Some(rest) = trimmed.strip_prefix("tags:") {
                let rest = rest.trim();
                if rest.starts_with('[') {
                    let inner = rest.trim_start_matches('[').trim_end_matches(']');
                    for tag in inner.split(',') {
                        let tag = tag.trim().trim_matches('"').trim_matches('\'');
                        if !tag.is_empty() && seen.insert(tag.to_string()) {
                            tags.push(tag.to_string());
                        }
                    }
                }
            }
            // - tag (under tags:)
            if let Some(tag) = trimmed.strip_prefix("- ") {
                let tag = tag.trim().trim_matches('"').trim_matches('\'');
                if !tag.is_empty() && seen.insert(tag.to_string()) {
                    tags.push(tag.to_string());
                }
            }
        }
    }

    tags
}

fn format_system_time(time: Option<std::time::SystemTime>) -> String {
    time.map_or_else(
        || "unknown".into(),
        |t| {
            let duration = t.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
            let dt = chrono::DateTime::from_timestamp(
                i64::try_from(duration.as_secs()).unwrap_or(i64::MAX),
                duration.subsec_nanos(),
            );
            dt.map_or_else(|| "unknown".to_string(), |d| d.to_rfc3339())
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn setup_vault() -> (tempfile::TempDir, ObsidianClient) {
        let dir = tempfile::tempdir().unwrap();
        let client = ObsidianClient::new(dir.path().to_str().unwrap()).unwrap();
        (dir, client)
    }

    #[test]
    fn new_client_valid_path() {
        let dir = tempfile::tempdir().unwrap();
        let client = ObsidianClient::new(dir.path().to_str().unwrap());
        assert!(client.is_ok());
    }

    #[test]
    fn new_client_nonexistent_path() {
        let result = ObsidianClient::new("/nonexistent/vault/path");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ObsidianError::InvalidVault(_)
        ));
    }

    #[test]
    fn new_client_file_not_dir() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("not_a_dir.txt");
        fs::write(&file_path, "test").unwrap();
        let result = ObsidianClient::new(file_path.to_str().unwrap());
        assert!(result.is_err());
    }

    #[test]
    fn create_and_get_note() {
        let (_dir, client) = setup_vault();
        let note = client.create_note("test.md", "# Hello\nWorld").unwrap();
        assert_eq!(note.title, "test");
        assert_eq!(note.content.as_deref(), Some("# Hello\nWorld"));

        let fetched = client.get_note("test.md").unwrap();
        assert_eq!(fetched.title, "test");
        assert_eq!(fetched.content.as_deref(), Some("# Hello\nWorld"));
    }

    #[test]
    fn create_duplicate_note() {
        let (_dir, client) = setup_vault();
        client.create_note("test.md", "first").unwrap();
        let result = client.create_note("test.md", "second");
        assert!(matches!(
            result.unwrap_err(),
            ObsidianError::AlreadyExists(_)
        ));
    }

    #[test]
    fn update_note() {
        let (_dir, client) = setup_vault();
        client.create_note("test.md", "original").unwrap();
        let updated = client.update_note("test.md", "modified").unwrap();
        assert_eq!(updated.content.as_deref(), Some("modified"));
    }

    #[test]
    fn update_nonexistent_note() {
        let (_dir, client) = setup_vault();
        let result = client.update_note("missing.md", "content");
        assert!(matches!(result.unwrap_err(), ObsidianError::NotFound(_)));
    }

    #[test]
    fn delete_note() {
        let (_dir, client) = setup_vault();
        client.create_note("test.md", "content").unwrap();
        client.delete_note("test.md").unwrap();
        let result = client.get_note("test.md");
        assert!(matches!(result.unwrap_err(), ObsidianError::NotFound(_)));
    }

    #[test]
    fn delete_nonexistent_note() {
        let (_dir, client) = setup_vault();
        let result = client.delete_note("missing.md");
        assert!(matches!(result.unwrap_err(), ObsidianError::NotFound(_)));
    }

    #[test]
    fn list_notes() {
        let (_dir, client) = setup_vault();
        client.create_note("a.md", "alpha").unwrap();
        client.create_note("b.md", "beta").unwrap();
        let notes = client.list_notes(None).unwrap();
        assert_eq!(notes.len(), 2);
        assert_eq!(notes[0].title, "a");
        assert_eq!(notes[1].title, "b");
    }

    #[test]
    fn list_notes_in_folder() {
        let (dir, client) = setup_vault();
        fs::create_dir_all(dir.path().join("sub")).unwrap();
        client.create_note("sub/a.md", "alpha").unwrap();
        client.create_note("top.md", "top").unwrap();
        let notes = client.list_notes(Some("sub")).unwrap();
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].title, "a");
    }

    #[test]
    fn list_notes_nonexistent_folder() {
        let (_dir, client) = setup_vault();
        let notes = client.list_notes(Some("nope")).unwrap();
        assert!(notes.is_empty());
    }

    #[test]
    fn search_notes() {
        let (_dir, client) = setup_vault();
        client
            .create_note("rust.md", "Rust is great\nI love Rust")
            .unwrap();
        client.create_note("python.md", "Python is nice").unwrap();
        let results = client.search("rust").unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].matches.len(), 2);
    }

    #[test]
    fn search_case_insensitive() {
        let (_dir, client) = setup_vault();
        client.create_note("test.md", "HELLO world").unwrap();
        let results = client.search("hello").unwrap();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn list_tags() {
        let (_dir, client) = setup_vault();
        client.create_note("a.md", "Content #rust #fcp").unwrap();
        client.create_note("b.md", "More #rust stuff").unwrap();
        let tags = client.list_tags().unwrap();
        assert!(tags.len() >= 2);
        // rust should have count 2
        let rust_tag = tags.iter().find(|t| t.tag == "rust").unwrap();
        assert_eq!(rust_tag.count, 2);
    }

    #[test]
    fn get_backlinks() {
        let (_dir, client) = setup_vault();
        client.create_note("target.md", "# Target").unwrap();
        client
            .create_note("source.md", "See [[target]] for details")
            .unwrap();
        let backlinks = client.get_backlinks("target.md").unwrap();
        assert_eq!(backlinks.len(), 1);
        assert_eq!(backlinks[0].source_path, "source.md");
    }

    #[test]
    fn no_self_backlinks() {
        let (_dir, client) = setup_vault();
        client
            .create_note("self.md", "References [[self]] here")
            .unwrap();
        let backlinks = client.get_backlinks("self.md").unwrap();
        assert!(backlinks.is_empty());
    }

    #[test]
    fn vault_health() {
        let (_dir, client) = setup_vault();
        client.create_note("a.md", "hello").unwrap();
        client.create_note("b.md", "world").unwrap();
        let health = client.vault_health().unwrap();
        assert_eq!(health.note_count, 2);
        assert!(health.readable);
        assert!(health.writable);
        assert!(health.total_size_bytes > 0);
    }

    #[test]
    fn diagnostics_and_missing_note_lookups_leave_vault_untouched() {
        let (dir, client) = setup_vault();
        let marker = dir.path().join(".fcp_write_test");
        fs::write(&marker, "keep").unwrap();
        assert!(client.vault_health().unwrap().writable);
        assert_eq!(fs::read_to_string(marker).unwrap(), "keep");
        assert!(client.get_note("absent/sub/n.md").is_err());
        assert!(client.update_note("absent/sub/n.md", "text").is_err());
        assert!(client.delete_note("absent/sub/n.md").is_err());
        assert!(!dir.path().join("absent").exists());
    }

    #[cfg(unix)]
    #[test]
    fn discovery_visits_each_regular_note_once() {
        use std::os::unix::fs::symlink;

        let (dir, client) = setup_vault();
        client.create_note("docs/one.md", "reference [[two]] #shared").unwrap();
        client.create_note("two.md", "target").unwrap();
        symlink("docs", dir.path().join("alias")).unwrap();
        symlink("docs/one.md", dir.path().join("linked.md")).unwrap();
        assert_eq!(client.list_notes(None).unwrap().len(), 2);
        assert_eq!(client.search("reference").unwrap().len(), 1);
        assert_eq!(client.list_tags().unwrap()[0].count, 1);
        assert_eq!(client.get_backlinks("two.md").unwrap().len(), 1);
        assert_eq!(client.vault_health().unwrap().note_count, 2);
    }

    #[cfg(unix)]
    #[test]
    fn open_vault_survives_directory_rename() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("vault");
        fs::create_dir(&root).unwrap();
        let client = ObsidianClient::new(root.to_str().unwrap()).unwrap();
        client.create_note("first.md", "first").unwrap();
        fs::rename(&root, dir.path().join("renamed")).unwrap();
        fs::create_dir(&root).unwrap();

        client.create_note("sub/second.md", "second").unwrap();
        assert_eq!(client.list_notes(None).unwrap().len(), 2);
        assert_eq!(client.get_note("first.md").unwrap().content.as_deref(), Some("first"));
        assert!(root.read_dir().unwrap().next().is_none());
    }

    #[test]
    fn path_traversal_rejected_dotdot() {
        let (_dir, client) = setup_vault();
        let result = client.get_note("../../../etc/passwd");
        assert!(matches!(
            result.unwrap_err(),
            ObsidianError::InvalidInput(_)
        ));
    }

    #[test]
    fn path_traversal_rejected_absolute() {
        let (_dir, client) = setup_vault();
        let result = client.get_note("/etc/passwd");
        assert!(matches!(
            result.unwrap_err(),
            ObsidianError::InvalidInput(_)
        ));
    }

    #[test]
    fn path_traversal_rejected_null_byte() {
        let (_dir, client) = setup_vault();
        let result = client.get_note("test\0.md");
        assert!(matches!(
            result.unwrap_err(),
            ObsidianError::InvalidInput(_)
        ));
    }

    #[test]
    fn sanitize_path_empty() {
        assert!(sanitize_path_segment("").is_err());
    }

    #[test]
    fn sanitize_path_valid() {
        assert!(sanitize_path_segment("notes/test.md").is_ok());
    }

    #[test]
    fn extract_inline_tags() {
        let tags = extract_tags("Hello #world #rust");
        assert!(tags.contains(&"world".to_string()));
        assert!(tags.contains(&"rust".to_string()));
    }

    #[test]
    fn extract_frontmatter_tags() {
        let content = "---\ntags: [alpha, beta]\n---\n# Content";
        let tags = extract_tags(content);
        assert!(tags.contains(&"alpha".to_string()));
        assert!(tags.contains(&"beta".to_string()));
    }

    #[test]
    fn extract_tags_skips_headings() {
        let tags = extract_tags("# Heading\n## Subheading\n#tag");
        assert!(!tags.iter().any(|t| t.starts_with(' ')));
        // The heading lines should be skipped
        assert!(tags.contains(&"tag".to_string()));
    }

    #[test]
    fn nested_note_create() {
        let (_dir, client) = setup_vault();
        let note = client
            .create_note("deep/nested/note.md", "nested content")
            .unwrap();
        assert_eq!(note.title, "note");
        assert!(note.path.contains("deep"));
    }

    #[test]
    fn hidden_dirs_skipped() {
        let (dir, client) = setup_vault();
        fs::create_dir_all(dir.path().join(".obsidian")).unwrap();
        fs::write(dir.path().join(".obsidian/config.md"), "hidden").unwrap();
        client.create_note("visible.md", "ok").unwrap();
        let notes = client.list_notes(None).unwrap();
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].title, "visible");
    }

    #[test]
    fn format_system_time_works() {
        let t = std::time::SystemTime::now();
        let formatted = format_system_time(Some(t));
        assert!(formatted.contains('T')); // ISO 8601
    }

    #[test]
    fn format_system_time_none() {
        assert_eq!(format_system_time(None), "unknown");
    }

    #[test]
    fn debug_client() {
        let dir = tempfile::tempdir().unwrap();
        let client = ObsidianClient::new(dir.path().to_str().unwrap()).unwrap();
        let debug = format!("{client:?}");
        assert!(debug.contains("ObsidianClient"));
    }
}
