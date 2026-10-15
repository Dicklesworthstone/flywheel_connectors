//! Bounded, owner-authenticated selection across membership publishers.
//!
//! Publisher count is not quorum. Every candidate is checked against the same
//! independently pinned trust, and the durable installer still enforces history.
//! A newer authentic document that is expired or excludes this node blocks a
//! fallback to an older grant; an unauthenticated generation claim does not.

use std::collections::BTreeSet;

use fcp_mesh::peer_manifest::MeshPeerDirectoryError;

use super::*;

const MAX_SOURCES: usize = 4;
const MAX_SOURCE_ARGUMENT_BYTES: usize = 20 * 1024;

pub(super) struct SourceSet {
    urls: Vec<Url>,
}

impl SourceSet {
    pub(super) fn from_options(options: &BTreeMap<String, OsString>) -> super::super::Result<Self> {
        let raw = options.get("--url")
            .and_then(|value| value.to_str())
            .ok_or_else(|| "source URL argument is missing or is not UTF-8".to_owned())?;
        Self::parse(raw).map_err(|error| error.to_string())
    }

    /// One URL or a JSON array of up to four independently configured URLs.
    /// Parse and validate the entire set before making any network request.
    fn parse(raw: &str) -> SyncResult<Self> {
        if raw.len() > MAX_SOURCE_ARGUMENT_BYTES {
            return Err(SyncError::Local("source URL argument exceeds its byte limit"));
        }
        let sources: Vec<String> = if raw.trim_start().starts_with('[') {
            serde_json::from_str(raw)
                .map_err(|_| SyncError::Local("source URL array must contain only strings"))?
        } else {
            vec![raw.to_owned()]
        };
        if sources.is_empty() || sources.len() > MAX_SOURCES {
            return Err(SyncError::Local("configure between one and four membership sources"));
        }
        let mut seen = BTreeSet::new();
        let mut urls = Vec::with_capacity(sources.len());
        for raw in sources {
            let url = source_url(&raw)?;
            if !seen.insert(url.as_str().to_owned()) {
                return Err(SyncError::Local("duplicate membership source URL"));
            }
            urls.push(url);
        }
        Ok(Self { urls })
    }

    pub(super) fn fetch(&self, trust: &Trust, timeout: Duration) -> SyncResult<String> {
        self.fetch_with(trust, timeout, fetch)
    }

    fn fetch_with(
        &self,
        trust: &Trust,
        timeout: Duration,
        mut fetch_document: impl FnMut(&Url, Duration) -> SyncResult<String>,
    ) -> SyncResult<String> {
        let started = Instant::now();
        let started_ms = unix_now_ms();
        let mut selection = Selection::default();
        let mut attempted = 0;
        let mut authenticated = 0;
        for (index, url) in self.urls.iter().enumerate() {
            let remaining = timeout.saturating_sub(started.elapsed());
            if remaining.is_zero() {
                break;
            }
            // Reserve time for later sources. A dead first publisher must not
            // consume the entire refresh budget before a healthy mirror is tried.
            let slots = u32::try_from(self.urls.len() - index).unwrap_or(u32::MAX);
            let allowance = remaining / slots;
            if allowance.is_zero() {
                break;
            }
            attempted += 1;
            let text = match fetch_document(url, allowance) {
                Ok(text) => text,
                Err(SyncError::Remote(_)) => continue,
                // Broken local runtime/client setup is not a remote outage.
                Err(error) => return Err(error),
            };
            let now_ms = unix_now_ms();
            if now_ms < started_ms {
                return Err(SyncError::Remote("clock regressed during source selection".to_owned()));
            }
            let candidate = match Candidate::authenticate(trust, text, index, now_ms) {
                Ok(candidate) => candidate,
                Err(SyncError::Remote(_)) => continue,
                Err(error) => return Err(error),
            };
            authenticated += 1;
            selection.observe(candidate)?;
        }
        let chosen = selection.finish()?;
        let now_ms = unix_now_ms();
        if now_ms < started_ms {
            return Err(SyncError::Remote("clock regressed during source selection".to_owned()));
        }
        // The chosen document may have expired while another source was being
        // contacted. Never replace it with a lower generation on that account.
        trust.verify(&chosen.text, now_ms)?;
        tracing::info!(
            event = "mesh_membership_source_selected",
            configured_sources = self.urls.len(),
            attempted_sources = attempted,
            authenticated_sources = authenticated,
            selected_source_index = chosen.source_index,
            selected_generation = chosen.generation,
            "selected highest completed owner-authenticated membership generation"
        );
        Ok(chosen.text)
    }
}

struct Candidate {
    text: String,
    generation: u64,
    payload_hash: [u8; 32],
    source_index: usize,
    refusal: Option<&'static str>,
}

impl Candidate {
    fn authenticate(trust: &Trust, text: String, source_index: usize, now_ms: u64) -> SyncResult<Self> {
        let signed = SignedMeshPeerDirectory::from_json(&text)
            .map_err(|_| SyncError::Remote("source envelope is malformed".to_owned()))?;
        let (generation, refusal) = match signed.verify(
            std::slice::from_ref(&trust.owner), &trust.mesh_id,
            trust.node.clone(), &trust.local, now_ms,
        ) {
            Ok(verified) => (verified.payload().generation, None),
            Err(error @ (MeshPeerDirectoryError::LocalIdentityMismatch
                | MeshPeerDirectoryError::OutsideValidityWindow)) => {
                // These typed failures occur ONLY AFTER independent owner
                // signature, payload structure and mesh-scope verification.
                // Their authenticated generation cannot be hidden by falling
                // back to an older publisher that still authorizes this node.
                let payload: MeshPeerDirectoryPayload = serde_json::from_str(&signed.payload_json)
                    .map_err(|_| SyncError::Remote("authenticated source payload is malformed".to_owned()))?;
                let reason = if matches!(error, MeshPeerDirectoryError::LocalIdentityMismatch) {
                    "highest authenticated generation does not authorize this node's key"
                } else {
                    "highest authenticated generation is outside its validity window"
                };
                (payload.generation, Some(reason))
            }
            Err(_) => return Err(SyncError::Remote(
                "source did not pass owner, scope and membership authentication".to_owned(),
            )),
        };
        Ok(Self {
            payload_hash: *blake3::hash(signed.payload_json.as_bytes()).as_bytes(),
            text,
            generation,
            source_index,
            refusal,
        })
    }
}

#[derive(Default)]
struct Selection {
    payloads: BTreeMap<u64, [u8; 32]>,
    highest: Option<Candidate>,
}

impl Selection {
    fn observe(&mut self, candidate: Candidate) -> SyncResult<()> {
        if self.payloads.get(&candidate.generation)
            .is_some_and(|hash| hash != &candidate.payload_hash)
        {
            return Err(SyncError::Remote(
                "owner-signed sources equivocate at the same membership generation".to_owned(),
            ));
        }
        self.payloads.insert(candidate.generation, candidate.payload_hash);
        if self.highest.as_ref().is_none_or(|current| candidate.generation > current.generation) {
            self.highest = Some(candidate);
        }
        Ok(())
    }

    fn finish(self) -> SyncResult<Candidate> {
        let chosen = self.highest.ok_or_else(|| SyncError::Remote(
            "no membership source supplied an authenticated document within the fetch budget".to_owned(),
        ))?;
        if let Some(reason) = chosen.refusal {
            return Err(SyncError::Remote(reason.to_owned()));
        }
        Ok(chosen)
    }
}

#[cfg(test)]
#[path = "sources/tests.rs"]
mod tests;
