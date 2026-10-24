//! Bounded wire paging for exact-root connector-state replication.
//!
//! Pages transport the existing, fully validated v1 export; they neither widen
//! grants nor publish partial histories. Every page is independently protected
//! by the mesh request/reply signature and nonce. The digest binds all pages to
//! one byte-identical export, not to a new source of authority. A failed download
//! drops its assembly without importing anything. Explicit multi-donor recovery
//! may then start a separate download; import failures are never retried.
//! Optional two-page pipelining overlaps round trips after the first page pins
//! the export. Verified contiguous completions immediately release capacity for
//! another fetch; out-of-order completions remain charged to the same bound.

use std::collections::BTreeMap;
use std::future::Future;
use std::time::{Duration, Instant};

use futures_util::stream::{FuturesUnordered, StreamExt};
use serde::{Deserialize, Serialize};

use crate::connector_state_recovery::{
    MAX_CONNECTOR_STATE_RECOVERY_TIMEOUT_MS, read_while_authorized, within_recovery_budget,
};
use crate::connector_state_replication::runtime::{ExportLookup, TransferPermit};
use crate::{
    ConnectorStateExportRequest, ConnectorStatePullRequest, ConnectorStatePullResponse,
    ConnectorStateReplicationService, HostError, HostResult,
    MAX_CONNECTOR_STATE_EXPORT_REQUEST_BYTES, MAX_CONNECTOR_STATE_TRANSFER_WIRE_BYTES,
};

const PAGE_SCHEMA: &str = "fcp.host.state-transfer-page.v1";
// Hex keeps the signed JSON wrapper free of a second layer of string escaping.
// No peer-controlled URL/cursor is used, even with pipelining enabled.
const PAGE_BYTES: usize = 48 * 1024;
const MAX_PAGE_WIRE_BYTES: usize = 256 * 1024;
// The donor permits at most two service operations per authenticated peer.
const MAX_PAGE_CONCURRENCY: usize = 2;
const TRANSFER_BUDGET: Duration = Duration::from_millis(MAX_CONNECTOR_STATE_RECOVERY_TIMEOUT_MS);

fn export_deadline_error() -> HostError {
    HostError::Unavailable("state-export deadline elapsed; no export response was returned".to_owned())
}

fn pull_deadline_error() -> HostError {
    HostError::Unavailable(
        "state-transfer deadline elapsed; an admitted durable write may still complete".to_owned(),
    )
}

#[derive(Debug, Clone, Copy)]
pub(super) struct PageConcurrency(usize);

impl Default for PageConcurrency {
    fn default() -> Self {
        Self(1)
    }
}

impl PageConcurrency {
    fn new(pages: usize) -> HostResult<Self> {
        if !(1..=MAX_PAGE_CONCURRENCY).contains(&pages) {
            return Err(invalid("state-transfer page concurrency must be 1 or 2"));
        }
        Ok(Self(pages))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PageRequest {
    schema_version: String,
    export: ConnectorStateExportRequest,
    offset: usize,
    wire_digest: Option<String>,
}

impl PageRequest {
    fn first(export: &ConnectorStateExportRequest) -> Self {
        Self {
            schema_version: PAGE_SCHEMA.to_owned(),
            export: export.clone(),
            offset: 0,
            wire_digest: None,
        }
    }

    fn validate(&self) -> HostResult<()> {
        // Reuse the canonical request's metadata and grant-limit validation.
        self.export.to_json()?;
        if self.schema_version != PAGE_SCHEMA
            || self.offset >= self.export.limits.max_wire_bytes
            || self.offset % PAGE_BYTES != 0
            || (self.offset == 0) != self.wire_digest.is_none()
            || self
                .wire_digest
                .as_deref()
                .is_some_and(|digest| !valid_digest(digest))
        {
            return Err(invalid("invalid connector-state page request"));
        }
        Ok(())
    }

    fn to_json(&self) -> HostResult<String> {
        self.validate()?;
        let wire = serde_json::to_string(self)
            .map_err(|_| invalid("connector-state page request cannot be encoded"))?;
        if wire.len() > MAX_CONNECTOR_STATE_EXPORT_REQUEST_BYTES {
            return Err(invalid(
                "connector-state page request exceeds its wire limit",
            ));
        }
        Ok(wire)
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PageResponse {
    schema_version: String,
    request: PageRequest,
    total_bytes: usize,
    wire_digest: String,
    data_hex: String,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ExportWireRequest {
    Page(PageRequest),
    Complete(ConnectorStateExportRequest),
}

fn valid_digest(digest: &str) -> bool {
    digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn invalid(message: &str) -> HostError {
    HostError::InvalidFilter(message.to_owned())
}

fn stable_export_wire(wire: String, limit: usize) -> HostResult<String> {
    if wire.len() > limit {
        return Err(invalid("connector-state export exceeds its wire limit"));
    }
    // Map iteration order is not a stable transfer identity. Sort nested JSON
    // objects even when a downstream dependency enables preserve_order.
    let mut value: serde_json::Value =
        serde_json::from_str(&wire).map_err(|_| invalid("connector-state export is malformed"))?;
    drop(wire);
    value.sort_all_objects();
    let wire = serde_json::to_string(&value)
        .map_err(|_| invalid("connector-state export cannot be encoded"))?;
    if wire.len() > limit {
        return Err(invalid("connector-state export exceeds its wire limit"));
    }
    Ok(wire)
}

#[cfg(test)]
fn encode_page(request: &PageRequest, wire: &str) -> HostResult<String> {
    encode_page_with_digest(
        request,
        wire,
        blake3::hash(wire.as_bytes()).to_hex().as_str(),
    )
}

fn encode_page_with_digest(request: &PageRequest, wire: &str, digest: &str) -> HostResult<String> {
    request.validate()?;
    let total_bytes = wire.len();
    if total_bytes == 0
        || total_bytes > request.export.limits.max_wire_bytes
        || request.offset >= total_bytes
    {
        return Err(invalid(
            "connector-state export does not fit the requested page bounds",
        ));
    }
    if request
        .wire_digest
        .as_deref()
        .is_some_and(|expected| expected != digest)
    {
        return Err(invalid("connector-state export changed between pages"));
    }
    let end = request.offset.saturating_add(PAGE_BYTES).min(total_bytes);
    let response = PageResponse {
        schema_version: PAGE_SCHEMA.to_owned(),
        request: request.clone(),
        total_bytes,
        wire_digest: digest.to_owned(),
        // Offsets are bytes, not UTF-8 indices. Hex can split inside a scalar.
        data_hex: hex::encode(&wire.as_bytes()[request.offset..end]),
    };
    let page = serde_json::to_string(&response)
        .map_err(|_| invalid("connector-state page cannot be encoded"))?;
    if page.len() > MAX_PAGE_WIRE_BYTES {
        return Err(invalid("connector-state page exceeds its envelope limit"));
    }
    Ok(page)
}

#[derive(Default)]
struct Assembly {
    bytes: Vec<u8>,
    total_bytes: Option<usize>,
    digest: Option<String>,
}

/// Fully checked against the exact request and the current assembly anchor.
/// Only decoded payload bytes survive an out-of-order completion, not wire JSON.
struct DecodedPage {
    offset: usize,
    total_bytes: usize,
    digest: String,
    bytes: Vec<u8>,
}

impl DecodedPage {
    /// Decode against immutable first-page evidence, without borrowing the
    /// mutable assembly while another fetch is in flight.
    fn decode(
        request: &PageRequest,
        wire: &str,
        expected_total: Option<usize>,
        expected_digest: Option<&str>,
    ) -> HostResult<Self> {
        request.validate()?;
        if wire.len() > MAX_PAGE_WIRE_BYTES {
            return Err(invalid("connector-state page exceeds its envelope limit"));
        }
        let page: PageResponse =
            serde_json::from_str(wire).map_err(|_| invalid("connector-state page is malformed"))?;
        if page.schema_version != PAGE_SCHEMA
            || page.request != *request
            || request.wire_digest.as_deref() != expected_digest
            || page.total_bytes == 0
            || page.total_bytes > request.export.limits.max_wire_bytes
            || page.total_bytes > MAX_CONNECTOR_STATE_TRANSFER_WIRE_BYTES
            || request.offset >= page.total_bytes
            || !valid_digest(&page.wire_digest)
            || expected_total.is_some_and(|total| total != page.total_bytes)
            || expected_digest.is_some_and(|digest| digest != page.wire_digest.as_str())
        {
            return Err(invalid(
                "connector-state page does not match the admitted transfer",
            ));
        }
        let expected_bytes = PAGE_BYTES.min(page.total_bytes - request.offset);
        if page.data_hex.len() != expected_bytes * 2 {
            return Err(invalid(
                "connector-state page has an invalid payload length",
            ));
        }
        let decoded = hex::decode(&page.data_hex)
            .map_err(|_| invalid("connector-state page payload is malformed"))?;
        Ok(Self {
            offset: request.offset,
            total_bytes: page.total_bytes,
            digest: page.wire_digest,
            bytes: decoded,
        })
    }
}

impl Assembly {
    /// Validate before retaining payload bytes, independently of arrival order.
    fn decode_page(&self, request: &PageRequest, wire: &str) -> HostResult<DecodedPage> {
        DecodedPage::decode(request, wire, self.total_bytes, self.digest.as_deref())
    }

    /// Publish only the next contiguous page from this same immutable export.
    fn append(&mut self, page: DecodedPage) -> HostResult<bool> {
        if page.offset != self.bytes.len()
            || self.total_bytes.is_some_and(|total| total != page.total_bytes)
            || self.digest.as_ref().is_some_and(|digest| digest != &page.digest)
        {
            return Err(invalid("connector-state page does not match the admitted transfer"));
        }
        self.bytes.extend_from_slice(&page.bytes);
        self.total_bytes = Some(page.total_bytes);
        self.digest = Some(page.digest);
        Ok(self.bytes.len() == page.total_bytes)
    }

    /// Validate the complete page before retaining even its first byte.
    fn accept(&mut self, request: &PageRequest, wire: &str) -> HostResult<bool> {
        let page = self.decode_page(request, wire)?;
        self.append(page)
    }

    fn finish(self) -> HostResult<String> {
        if self.total_bytes != Some(self.bytes.len())
            || self.digest.as_deref() != Some(blake3::hash(&self.bytes).to_hex().as_str())
        {
            return Err(invalid(
                "connector-state transfer is incomplete or its digest differs",
            ));
        }
        String::from_utf8(self.bytes).map_err(|_| invalid("connector-state transfer is not UTF-8"))
    }
}

/// Fetches are owned by this future: no detached tasks, retries or donor changes.
async fn fetch_export_pages<F, Fut, A>(
    export: &ConnectorStateExportRequest,
    concurrency: PageConcurrency,
    mut fetch_page: F,
    authorize: A,
) -> HostResult<String>
where
    F: FnMut(String) -> Fut,
    Fut: Future<Output = HostResult<String>>,
    A: Fn() -> HostResult<()>,
{
    authorize()?;
    let first = PageRequest::first(export);
    let fetch = fetch_page(first.to_json()?);
    authorize()?;
    let wire = fetch.await?;
    authorize()?;
    let mut assembly = Assembly::default();
    assembly.accept(&first, &wire)?;
    drop(wire);
    let total_bytes = assembly
        .total_bytes
        .ok_or_else(|| invalid("connector-state transfer has no validated first page"))?;
    let digest = assembly
        .digest
        .clone()
        .ok_or_else(|| invalid("connector-state transfer has no validated first-page digest"))?;
    let mut in_flight = FuturesUnordered::new();
    let mut ready = BTreeMap::new();
    let mut next_offset = assembly.bytes.len();

    while assembly.bytes.len() < total_bytes {
        // A verified out-of-order reply still occupies a slot. Refill only
        // after contiguous assembly frees capacity, never merely on completion.
        while in_flight.len() + ready.len() < concurrency.0 && next_offset < total_bytes {
            let page = PageRequest {
                schema_version: PAGE_SCHEMA.to_owned(),
                export: export.clone(),
                offset: next_offset,
                wire_digest: Some(digest.clone()),
            };
            authorize()?;
            let fetch = fetch_page(page.to_json()?);
            let authority = &authorize;
            let expected_digest = &digest;
            in_flight.push(async move {
                // Construction and first poll need not be adjacent. Recheck
                // before polling a network future and after it completes.
                authority()?;
                let wire = fetch.await?;
                authority()?;
                DecodedPage::decode(&page, &wire, Some(total_bytes), Some(expected_digest))
            });
            next_offset += PAGE_BYTES;
        }

        // Consume whichever reply completes first. A failed or malformed later
        // page must terminate the transfer even if an earlier peer read hangs.
        // All futures are owned here and drop on failure/cancellation; no task
        // is detached, no page is retried, and no import is admitted here.
        let page = in_flight
            .next()
            .await
            .ok_or_else(|| invalid("connector-state transfer has a missing pending page"))??;
        authorize()?;
        if page.offset < assembly.bytes.len() || ready.insert(page.offset, page).is_some() {
            return Err(invalid("connector-state transfer returned a duplicate page"));
        }
        while let Some(page) = ready.remove(&assembly.bytes.len()) {
            authorize()?;
            assembly.append(page)?;
        }
    }
    let wire = assembly.finish()?;
    authorize()?;
    Ok(wire)
}

impl ConnectorStateReplicationService {
    /// Configure one or two concurrent pages per pull, before sharing the service.
    ///
    /// Serial mode is the default. Two-page mode overlaps continuation round
    /// trips only after the first verified page fixes the digest and total size.
    /// Each pull retains one assembly reservation until import completes. The
    /// pipeline charges active fetches and verified out-of-order replies to the
    /// same two-slot bound. Contiguous replies immediately free slots for new
    /// fetches; at most two decoded 48 KiB payloads are retained outside the
    /// assembly. The fetcher must still bound its network response buffering.
    /// All existing per-peer and aggregate admission ceilings remain in force.
    /// A busy donor may refuse a pipelined pull; no automatic retry is implied.
    ///
    /// # Errors
    /// Rejects zero and values greater than two.
    pub fn with_page_concurrency(mut self, pages: usize) -> HostResult<Self> {
        self.page_concurrency = PageConcurrency::new(pages)?;
        Ok(self)
    }

    /// Serve a complete v1 export or one bounded page of that same export.
    ///
    /// The exact-root grant and current transport authority are checked on every
    /// page. Fully validated immutable exports are reused within this service,
    /// keyed by peer and the complete export request, for at most 60 seconds.
    /// The cache retains at most 16 entries / 16 MiB and does not extend age on
    /// use. Expiry/eviction is lazy; no background worker or disk cache exists.
    /// A continuation pins a digest and fails if the serialized export changes.
    /// A cache miss revalidates the complete bounded ancestry. Concurrent builds
    /// of the same export fail fast instead of repeating reads and signatures.
    /// No grant, writer pin or transport authority is inferred from the cache;
    /// replicas are still independently validated before publication.
    /// The complete call, including decoding and serialization, has a 60 second
    /// service ceiling; callers may impose a shorter original request deadline.
    /// Read polls and an owned periodic timer recheck authority even while a
    /// backing-store read is stalled. Abandonment releases the active permit
    /// and any unfinished cache-build claim without returning state bytes.
    ///
    /// # Errors
    /// Rejects malformed requests, stale authority and all ordinary export
    /// failures. Call only after authenticating the peer and consuming its nonce.
    pub async fn export_transfer_for_peer<F>(
        &self,
        authenticated_peer: &str,
        request_json: &str,
        authorize_transport: F,
    ) -> HostResult<String>
    where
        F: Fn() -> HostResult<()> + Send + Sync,
    {
        self.export_transfer_with_budget(
            authenticated_peer,
            request_json,
            authorize_transport,
            Instant::now(),
            TRANSFER_BUDGET,
        )
        .await
    }

    // The private clock/budget seam exercises the exact production admission
    // path with deterministic exhausted budgets, without waiting sixty seconds.
    async fn export_transfer_with_budget<F>(
        &self,
        authenticated_peer: &str,
        request_json: &str,
        authorize_transport: F,
        started: Instant,
        budget: Duration,
    ) -> HostResult<String>
    where
        F: Fn() -> HostResult<()> + Send + Sync,
    {
        let operation = async {
            if request_json.len() > MAX_CONNECTOR_STATE_EXPORT_REQUEST_BYTES {
                return Err(invalid(
                    "connector-state export request exceeds its wire limit",
                ));
            }
            let request: ExportWireRequest = serde_json::from_str(request_json)
                .map_err(|_| invalid("connector-state export request is malformed"))?;
            let export = match &request {
                ExportWireRequest::Complete(export) => export,
                ExportWireRequest::Page(page) => {
                    page.validate()?;
                    &page.export
                }
            };
            let authority = || {
                if started.elapsed() >= budget {
                    return Err(export_deadline_error());
                }
                self.validate_export(authenticated_peer, export)?;
                authorize_transport()
            };
            let read = async {
                match &request {
                    ExportWireRequest::Complete(export) => {
                        self.export_for_peer(authenticated_peer, export, &authority).await
                    }
                    ExportWireRequest::Page(page) => {
                        authority()?;
                        let permit = self.runtime.admit(authenticated_peer, page.export.limits)?;
                        let snapshot = match self.runtime.begin_export(&permit, &page.export)? {
                            ExportLookup::Ready(snapshot) => snapshot,
                            ExportLookup::Build(build) => {
                                let wire = self.export_admitted(
                                    authenticated_peer, &page.export, &authority, &permit,
                                ).await?;
                                let wire = stable_export_wire(wire, page.export.limits.max_wire_bytes)?;
                                authority()?;
                                build.finish(wire)?
                            }
                        };
                        let encoded = encode_page_with_digest(page, snapshot.wire(), snapshot.digest())?;
                        // A cache hit never substitutes for current authority.
                        authority()?;
                        Ok(encoded)
                    }
                }
            };
            read_while_authorized(read, &authority).await
        };
        within_recovery_budget(started, budget, operation)
            .await
            .map_err(|_| export_deadline_error())?
    }

    /// Pull one signed export in bounded pages, then import its complete history.
    ///
    /// `fetch_page` must return only the body of a successful, authenticated,
    /// nonce-bound reply from the selected donor. Each call gets a new signed
    /// request, not a retry of an earlier envelope. Never follow a peer-provided
    /// cursor or URL. One 60 second service budget covers validation, every page
    /// and the single import; callers may impose a shorter original deadline.
    /// With two-page concurrency, fetch futures may run simultaneously and finish
    /// out of order. Their replies are verified on completion, then assembled in
    /// request order. Failure or cancellation drops every outstanding fetch.
    ///
    /// Existing grant limits apply to the reassembled v1 JSON, canonical bytes
    /// and object count. Page framing has a separate fixed cap. `wire_bytes` in
    /// the returned receipt still counts v1 JSON, not hex or mesh framing.
    /// No object is imported before all pages, the digest, and ordinary replica
    /// validation pass. Dropping this future before import drops only an in-memory
    /// assembly. After write admission, the existing persistent-write cancellation
    /// semantics apply. No pages are cached on disk and no automatic retries occur.
    /// Pending downloads use the same per-poll and periodic authority guard as
    /// multi-donor recovery. That guard ends before import: publication retains
    /// its existing admission checks and is never retried on revocation or timeout.
    ///
    /// # Errors
    /// Refuses expired grants, transport failures, missing/reordered/changed pages,
    /// over-budget responses, invalid ancestry and persistence failures.
    pub async fn pull_paged_from_peer<F, Fut, A>(
        &self,
        request: &ConnectorStatePullRequest,
        fetch_page: F,
        authorize_transport: A,
    ) -> HostResult<ConnectorStatePullResponse>
    where
        F: FnMut(String) -> Fut,
        Fut: Future<Output = HostResult<String>>,
        A: Fn() -> HostResult<()> + Send + Sync,
    {
        self.pull_paged_with_budget(
            request,
            fetch_page,
            authorize_transport,
            Instant::now(),
            TRANSFER_BUDGET,
        )
        .await
    }

    async fn pull_paged_with_budget<F, Fut, A>(
        &self,
        request: &ConnectorStatePullRequest,
        fetch_page: F,
        authorize_transport: A,
        started: Instant,
        budget: Duration,
    ) -> HostResult<ConnectorStatePullResponse>
    where
        F: FnMut(String) -> Fut,
        Fut: Future<Output = HostResult<String>>,
        A: Fn() -> HostResult<()> + Send + Sync,
    {
        let operation = async {
            let authority = || {
                if started.elapsed() >= budget {
                    return Err(pull_deadline_error());
                }
                self.validate_pull(request)?;
                authorize_transport()
            };
            authority()?;
            // One reservation owns the assembly through the final import.
            let permit = self
                .runtime
                .admit(&request.peer_node, request.request.limits)?;
            let download = self.download_paged_admitted(request, fetch_page, &authority, &permit);
            let wire = read_while_authorized(download, &authority).await?;
            // No periodic authority cancellation around admitted writes.
            // The ordinary import path rechecks at each publication boundary.
            self.import_admitted(request, &wire, &authority, &permit)
                .await
        };
        within_recovery_budget(started, budget, operation)
            .await
            .map_err(|_| pull_deadline_error())?
    }

    // Download only: this helper cannot write to a replica. Its caller must
    // retain the same permit through either import or destruction of the wire.
    pub(super) async fn download_paged_admitted<F, Fut, A>(
        &self,
        request: &ConnectorStatePullRequest,
        fetch_page: F,
        authorize_transport: A,
        permit: &TransferPermit<'_>,
    ) -> HostResult<String>
    where
        F: FnMut(String) -> Fut,
        Fut: Future<Output = HostResult<String>>,
        A: Fn() -> HostResult<()> + Send + Sync,
    {
        permit.check(&self.runtime, &request.peer_node, request.request.limits)?;
        let wire = fetch_export_pages(
            &request.request,
            self.page_concurrency,
            fetch_page,
            || {
                self.validate_pull(request)?;
                authorize_transport()
            },
        )
        .await?;
        self.validate_pull(request)?;
        authorize_transport()?;
        Ok(wire)
    }
}

#[cfg(test)]
mod tests {
    use std::future::pending;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::task::Poll;

    use fcp_evidence::{ObjectHeader, ObjectIdKey, RetentionClass, StorageMeta, StoredObject};
    use fcp_kernel::{ConnectorId, ObjectId, ZoneId};
    use fcp_store::{
        FcpStoreConnectorStateStore, MemoryObjectStore, MemoryObjectStoreConfig, ObjectStore,
        ObjectStoreError,
    };

    use super::*;
    use crate::{
        ConnectorStateTransferDirection, ConnectorStateTransferGrant, ConnectorStateTransferLimits,
        ConnectorStateTransferScope,
    };

    #[fcp_async_core::runtime::test]
    async fn contiguous_completion_refills_while_the_next_page_is_stalled() {
        let export = request().export;
        let wire = "x".repeat(6 * PAGE_BYTES + 7);
        let release = AtomicBool::new(false);
        let constructed = Mutex::new(Vec::new());
        let completed = Mutex::new(Vec::new());
        let active = AtomicUsize::new(0);
        let mut pull = Box::pin(fetch_export_pages(
            &export,
            PageConcurrency::new(2).unwrap(),
            |json| {
                let page: PageRequest = serde_json::from_str(&json).unwrap();
                constructed.lock().unwrap().push(page.offset);
                let (wire, release, completed, active) =
                    (&wire, &release, &completed, &active);
                async move {
                    let _active = ActiveFetch::new(active);
                    if page.offset == 2 * PAGE_BYTES {
                        std::future::poll_fn(|cx| {
                            if release.load(Ordering::SeqCst) {
                                Poll::Ready(())
                            } else {
                                cx.waker().wake_by_ref();
                                Poll::Pending
                            }
                        })
                        .await;
                    }
                    completed.lock().unwrap().push(page.offset);
                    encode_page(&page, wire)
                }
            },
            || Ok(()),
        ));
        // Allow cooperative stream polling without depending on one poll's
        // exact amount of work. No timers, sleeps or external peers are used.
        for _ in 0..8 {
            assert!(futures_util::poll!(pull.as_mut()).is_pending());
        }
        assert_eq!(
            *constructed.lock().unwrap(),
            vec![0, PAGE_BYTES, 2 * PAGE_BYTES, 3 * PAGE_BYTES],
            "the freed front slot must be reused before the slow sibling finishes",
        );
        assert_eq!(*completed.lock().unwrap(), vec![0, PAGE_BYTES, 3 * PAGE_BYTES]);
        assert_eq!(active.load(Ordering::SeqCst), 1);
        // The buffered third continuation and stalled second continuation fill
        // the entire bound: a fourth continuation must not be constructed.
        release.store(true, Ordering::SeqCst);
        assert_eq!(pull.await.unwrap(), wire);
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }

    #[fcp_async_core::runtime::test]
    async fn refilled_page_failure_cancels_an_earlier_stalled_page() {
        let export = request().export;
        let wire = "x".repeat(6 * PAGE_BYTES);
        let active = AtomicUsize::new(0);
        let constructed = AtomicUsize::new(0);
        let mut pull = Box::pin(fetch_export_pages(
            &export,
            PageConcurrency::new(2).unwrap(),
            |json| {
                let page: PageRequest = serde_json::from_str(&json).unwrap();
                constructed.fetch_add(1, Ordering::SeqCst);
                let (wire, active) = (&wire, &active);
                async move {
                    let _active = ActiveFetch::new(active);
                    if page.offset == 2 * PAGE_BYTES {
                        std::future::pending::<()>().await;
                    }
                    if page.offset == 3 * PAGE_BYTES {
                        return Err(invalid("fixture refilled page failed"));
                    }
                    encode_page(&page, wire)
                }
            },
            || Ok(()),
        ));
        let mut failed = false;
        for _ in 0..8 {
            match futures_util::poll!(pull.as_mut()) {
                Poll::Ready(Err(_)) => {
                    failed = true;
                    break;
                }
                Poll::Ready(Ok(_)) => panic!("failed transfer unexpectedly completed"),
                Poll::Pending => {}
            }
        }
        assert!(failed, "later failure must not wait for the hung earlier page");
        assert_eq!(constructed.load(Ordering::SeqCst), 4);
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }

    #[fcp_async_core::runtime::test]
    async fn cancelling_refilled_pipeline_drops_reads_and_buffered_pages() {
        let export = request().export;
        let wire = "x".repeat(5 * PAGE_BYTES);
        let active = AtomicUsize::new(0);
        let completed = Mutex::new(Vec::new());
        let mut pull = Box::pin(fetch_export_pages(
            &export,
            PageConcurrency::new(2).unwrap(),
            |json| {
                let page: PageRequest = serde_json::from_str(&json).unwrap();
                let (wire, active, completed) = (&wire, &active, &completed);
                async move {
                    let _active = ActiveFetch::new(active);
                    if page.offset == 2 * PAGE_BYTES {
                        std::future::pending::<()>().await;
                    }
                    completed.lock().unwrap().push(page.offset);
                    encode_page(&page, wire)
                }
            },
            || Ok(()),
        ));
        for _ in 0..8 {
            assert!(futures_util::poll!(pull.as_mut()).is_pending());
        }
        assert_eq!(*completed.lock().unwrap(), vec![0, PAGE_BYTES, 3 * PAGE_BYTES]);
        assert_eq!(active.load(Ordering::SeqCst), 1);
        drop(pull);
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }

    #[fcp_async_core::runtime::test]
    async fn serial_mode_never_constructs_a_second_outstanding_continuation() {
        let export = request().export;
        let wire = "x".repeat(4 * PAGE_BYTES);
        let constructed = Mutex::new(Vec::new());
        let active = AtomicUsize::new(0);
        let mut pull = Box::pin(fetch_export_pages(
            &export,
            PageConcurrency::new(1).unwrap(),
            |json| {
                let page: PageRequest = serde_json::from_str(&json).unwrap();
                constructed.lock().unwrap().push(page.offset);
                let (wire, active) = (&wire, &active);
                async move {
                    let _active = ActiveFetch::new(active);
                    if page.offset != 0 {
                        std::future::pending::<()>().await;
                    }
                    encode_page(&page, wire)
                }
            },
            || Ok(()),
        ));
        for _ in 0..8 {
            assert!(futures_util::poll!(pull.as_mut()).is_pending());
        }
        assert_eq!(*constructed.lock().unwrap(), vec![0, PAGE_BYTES]);
        assert_eq!(active.load(Ordering::SeqCst), 1);
        drop(pull);
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }

    fn request() -> PageRequest {
        PageRequest::first(&ConnectorStateExportRequest {
            grant_id: "restore-state".to_owned(),
            scope: ConnectorStateTransferScope {
                connector_id: ConnectorId::from_static("slack:chat:v1"),
                zone_id: ZoneId::work(),
                instance_id: None,
            },
            root_object_id: ObjectId::from_bytes([1; 32]),
            limits: ConnectorStateTransferLimits {
                max_objects: 16,
                max_canonical_bytes: 1024 * 1024,
                max_wire_bytes: 1024 * 1024,
            },
        })
    }

    fn next_request(request: &mut PageRequest, assembly: &Assembly) {
        request.offset = assembly.bytes.len();
        request.wire_digest.clone_from(&assembly.digest);
    }

    #[test]
    fn pages_round_trip_utf8_across_byte_boundaries() {
        let wire = format!(
            "{}{}",
            "x".repeat(PAGE_BYTES - 1),
            "\u{1f642}".repeat(PAGE_BYTES)
        );
        let mut request = request();
        let mut assembly = Assembly::default();
        let mut pages = 0;
        loop {
            let page = encode_page(&request, &wire).unwrap();
            assert!(page.len() <= MAX_PAGE_WIRE_BYTES);
            pages += 1;
            if assembly.accept(&request, &page).unwrap() {
                break;
            }
            next_request(&mut request, &assembly);
        }
        assert!(pages > 2);
        assert_eq!(assembly.finish().unwrap(), wire);
    }

    #[test]
    fn exact_page_boundary_needs_no_empty_final_page() {
        let wire = "x".repeat(PAGE_BYTES * 2);
        let mut request = request();
        let mut assembly = Assembly::default();
        assert!(
            !assembly
                .accept(&request, &encode_page(&request, &wire).unwrap())
                .unwrap()
        );
        next_request(&mut request, &assembly);
        assert!(
            assembly
                .accept(&request, &encode_page(&request, &wire).unwrap())
                .unwrap()
        );
        assert_eq!(assembly.finish().unwrap(), wire);
    }

    #[test]
    fn reordered_or_replayed_pages_do_not_mutate_assembly() {
        let wire = "x".repeat(PAGE_BYTES + 1);
        let first = request();
        let encoded = encode_page(&first, &wire).unwrap();
        let mut assembly = Assembly::default();
        assembly.accept(&first, &encoded).unwrap();
        let saved = assembly.bytes.clone();
        assert!(assembly.accept(&first, &encoded).is_err());
        let mut next = first.clone();
        next_request(&mut next, &assembly);
        assert!(
            Assembly::default()
                .accept(&next, &encode_page(&next, &wire).unwrap())
                .is_err()
        );
        assert_eq!(assembly.bytes, saved);
    }

    #[test]
    fn donor_changes_are_rejected_before_another_page_is_disclosed() {
        let wire = "x".repeat(PAGE_BYTES + 1);
        let mut request = request();
        let mut assembly = Assembly::default();
        assembly
            .accept(&request, &encode_page(&request, &wire).unwrap())
            .unwrap();
        next_request(&mut request, &assembly);
        assert!(encode_page(&request, &"y".repeat(wire.len())).is_err());
    }

    #[test]
    fn page_metadata_payload_and_length_are_bound_to_the_request() {
        let request = request();
        let original: serde_json::Value =
            serde_json::from_str(&encode_page(&request, "secret-state").unwrap()).unwrap();
        for (pointer, value) in [
            ("/schema_version", serde_json::json!("other")),
            ("/request/export/grant_id", serde_json::json!("other")),
            ("/request/offset", serde_json::json!(PAGE_BYTES)),
            ("/total_bytes", serde_json::json!(0)),
            (
                "/total_bytes",
                serde_json::json!(request.export.limits.max_wire_bytes + 1),
            ),
            ("/wire_digest", serde_json::json!("not-a-digest")),
            ("/data_hex", serde_json::json!("00")),
            (
                "/data_hex",
                serde_json::json!("z".repeat("secret-state".len() * 2)),
            ),
        ] {
            let mut value_copy = original.clone();
            *value_copy.pointer_mut(pointer).unwrap() = value;
            let mut assembly = Assembly::default();
            let error = assembly
                .accept(&request, &value_copy.to_string())
                .unwrap_err();
            assert!(assembly.bytes.is_empty());
            assert!(!error.to_string().contains("secret-state"));
        }
    }

    #[test]
    fn valid_hex_with_forged_content_fails_the_final_digest() {
        let request = request();
        let mut page: PageResponse =
            serde_json::from_str(&encode_page(&request, "abc").unwrap()).unwrap();
        page.data_hex = hex::encode("xyz");
        let mut assembly = Assembly::default();
        assert!(
            assembly
                .accept(&request, &serde_json::to_string(&page).unwrap())
                .unwrap()
        );
        assert!(assembly.finish().is_err());
    }

    #[test]
    fn missing_tail_cannot_be_finished() {
        let request = request();
        let mut assembly = Assembly::default();
        let wire = "x".repeat(PAGE_BYTES + 1);
        assert!(
            !assembly
                .accept(&request, &encode_page(&request, &wire).unwrap())
                .unwrap()
        );
        assert!(assembly.finish().is_err());
        assert!(Assembly::default().finish().is_err());
    }

    #[test]
    fn nested_map_order_does_not_change_the_export_digest() {
        let a = stable_export_wire(r#"{"z":[{"b":2,"a":1}],"a":0}"#.into(), 1024).unwrap();
        let b = stable_export_wire(r#"{"a":0,"z":[{"a":1,"b":2}]}"#.into(), 1024).unwrap();
        assert_eq!(a, b);
        assert!(stable_export_wire("{}".into(), 1).is_err());
    }

    #[test]
    fn page_requests_reject_unaligned_offsets_and_unbound_continuations() {
        let mut page = request();
        page.offset = 1;
        assert!(page.validate().is_err());
        page.offset = PAGE_BYTES;
        assert!(page.validate().is_err());
        page.wire_digest = Some("a".repeat(64));
        assert!(page.validate().is_ok());
        page.offset = 0;
        assert!(page.validate().is_err());
    }

    #[test]
    fn missing_import_authority_never_calls_the_fetcher() {
        let service = ConnectorStateReplicationService::new();
        let pull = ConnectorStatePullRequest {
            peer_node: "donor".into(),
            request: request().export,
        };
        let result = fcp_async_core::runtime::block_on_sync(service.pull_paged_from_peer(
            &pull,
            |_| async { panic!("unauthorized transfer reached the network") },
            || Ok(()),
        ))
        .unwrap();
        assert!(result.is_err());
    }

    struct ActiveFetch<'a>(&'a AtomicUsize);

    impl<'a> ActiveFetch<'a> {
        fn new(active: &'a AtomicUsize) -> Self {
            active.fetch_add(1, Ordering::SeqCst);
            Self(active)
        }
    }

    impl Drop for ActiveFetch<'_> {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn page_concurrency_defaults_to_serial_and_rejects_unbounded_windows() {
        let service = ConnectorStateReplicationService::new();
        assert_eq!(service.page_concurrency.0, 1);
        for pages in [1, 2] {
            let service = ConnectorStateReplicationService::new()
                .with_page_concurrency(pages)
                .unwrap();
            assert_eq!(service.page_concurrency.0, pages);
        }
        for pages in [0, 3, usize::MAX] {
            assert!(ConnectorStateReplicationService::new()
                .with_page_concurrency(pages)
                .is_err());
        }
    }

    #[fcp_async_core::runtime::test]
    async fn both_windows_preserve_exact_bytes_and_page_boundaries() {
        let export = request().export;
        for concurrency in [1, 2] {
            for length in [1, PAGE_BYTES, PAGE_BYTES + 1, 2 * PAGE_BYTES, 5 * PAGE_BYTES + 7] {
                let wire = "x".repeat(length);
                let offsets = Mutex::new(Vec::new());
                let recovered = fetch_export_pages(
                    &export,
                    PageConcurrency::new(concurrency).unwrap(),
                    |json| {
                        let page: PageRequest = serde_json::from_str(&json).unwrap();
                        offsets.lock().unwrap().push(page.offset);
                        let response = encode_page(&page, &wire);
                        async move { response }
                    },
                    || Ok(()),
                )
                .await
                .unwrap();
                assert_eq!(recovered, wire);
                assert_eq!(
                    *offsets.lock().unwrap(),
                    (0..length).step_by(PAGE_BYTES).collect::<Vec<_>>(),
                );
            }
        }
    }

    #[fcp_async_core::runtime::test]
    async fn first_page_must_finish_before_any_continuation_is_constructed() {
        let export = request().export;
        let constructed = AtomicUsize::new(0);
        let mut pull = Box::pin(fetch_export_pages(
            &export,
            PageConcurrency::new(2).unwrap(),
            |_| {
                constructed.fetch_add(1, Ordering::SeqCst);
                std::future::pending::<HostResult<String>>()
            },
            || Ok(()),
        ));
        assert!(futures_util::poll!(pull.as_mut()).is_pending());
        assert_eq!(constructed.load(Ordering::SeqCst), 1);
        drop(pull);
    }

    #[fcp_async_core::runtime::test]
    async fn out_of_order_completion_has_a_bounded_window_and_correct_utf8() {
        let export = request().export;
        let wire = format!("{}{}", "x".repeat(PAGE_BYTES - 1), "\u{1f642}".repeat(PAGE_BYTES));
        let release = AtomicBool::new(false);
        let started = Mutex::new(Vec::new());
        let completed = Mutex::new(Vec::new());
        let active = AtomicUsize::new(0);
        let peak = AtomicUsize::new(0);
        let mut pull = Box::pin(fetch_export_pages(
            &export,
            PageConcurrency::new(2).unwrap(),
            |json| {
                let page: PageRequest = serde_json::from_str(&json).unwrap();
                let (wire, release, started, completed, active, peak) =
                    (&wire, &release, &started, &completed, &active, &peak);
                async move {
                    let _active = ActiveFetch::new(active);
                    peak.fetch_max(active.load(Ordering::SeqCst), Ordering::SeqCst);
                    started.lock().unwrap().push(page.offset);
                    if page.offset == PAGE_BYTES {
                        std::future::poll_fn(|cx| {
                            if release.load(Ordering::SeqCst) {
                                Poll::Ready(())
                            } else {
                                cx.waker().wake_by_ref();
                                Poll::Pending
                            }
                        })
                        .await;
                    }
                    completed.lock().unwrap().push(page.offset);
                    encode_page(&page, wire)
                }
            },
            || Ok(()),
        ));
        assert!(futures_util::poll!(pull.as_mut()).is_pending());
        assert_eq!(*started.lock().unwrap(), vec![0, PAGE_BYTES, 2 * PAGE_BYTES]);
        assert_eq!(*completed.lock().unwrap(), vec![0, 2 * PAGE_BYTES]);
        assert_eq!(active.load(Ordering::SeqCst), 1);
        // A completed later page still occupies its window slot; page three
        // cannot race ahead while page one is stalled.
        assert_eq!(peak.load(Ordering::SeqCst), 2);
        release.store(true, Ordering::SeqCst);
        assert_eq!(pull.await.unwrap(), wire);
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }

    #[fcp_async_core::runtime::test]
    async fn later_page_failure_cancels_a_hung_sibling_without_retry() {
        let export = request().export;
        let wire = "x".repeat(4 * PAGE_BYTES);
        let started = AtomicUsize::new(0);
        let active = AtomicUsize::new(0);
        let mut pull = Box::pin(fetch_export_pages(
            &export,
            PageConcurrency::new(2).unwrap(),
            |json| {
                let page: PageRequest = serde_json::from_str(&json).unwrap();
                let (wire, started, active) = (&wire, &started, &active);
                async move {
                    let _active = ActiveFetch::new(active);
                    started.fetch_add(1, Ordering::SeqCst);
                    if page.offset == PAGE_BYTES {
                        std::future::pending::<()>().await;
                    }
                    if page.offset == 2 * PAGE_BYTES {
                        return Err(invalid("fixture later page failed"));
                    }
                    encode_page(&page, wire)
                }
            },
            || Ok(()),
        ));
        assert!(matches!(futures_util::poll!(pull.as_mut()), Poll::Ready(Err(_))));
        assert_eq!(started.load(Ordering::SeqCst), 3);
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }

    #[fcp_async_core::runtime::test]
    async fn cancelling_parallel_fetch_drops_every_owned_network_future() {
        let export = request().export;
        let wire = "x".repeat(4 * PAGE_BYTES);
        let active = AtomicUsize::new(0);
        let mut pull = Box::pin(fetch_export_pages(
            &export,
            PageConcurrency::new(2).unwrap(),
            |json| {
                let page: PageRequest = serde_json::from_str(&json).unwrap();
                let (wire, active) = (&wire, &active);
                async move {
                    let _active = ActiveFetch::new(active);
                    if page.offset != 0 {
                        std::future::pending::<()>().await;
                    }
                    encode_page(&page, wire)
                }
            },
            || Ok(()),
        ));
        assert!(futures_util::poll!(pull.as_mut()).is_pending());
        assert_eq!(active.load(Ordering::SeqCst), 2);
        drop(pull);
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }

    #[fcp_async_core::runtime::test]
    async fn authority_is_rechecked_before_polling_each_constructed_fetch() {
        let export = request().export;
        let wire = "x".repeat(4 * PAGE_BYTES);
        let allowed = AtomicBool::new(true);
        let polled = AtomicUsize::new(0);
        let result = fetch_export_pages(
            &export,
            PageConcurrency::new(2).unwrap(),
            |json| {
                let page: PageRequest = serde_json::from_str(&json).unwrap();
                if page.offset == 2 * PAGE_BYTES {
                    allowed.store(false, Ordering::SeqCst);
                }
                let (wire, polled) = (&wire, &polled);
                async move {
                    polled.fetch_add(1, Ordering::SeqCst);
                    encode_page(&page, wire)
                }
            },
            || {
                if allowed.load(Ordering::SeqCst) { Ok(()) }
                else { Err(invalid("fixture authority revoked")) }
            },
        )
        .await;
        assert!(result.is_err());
        assert_eq!(polled.load(Ordering::SeqCst), 1, "only the anchor reached the network");
    }

    #[fcp_async_core::runtime::test]
    async fn revocation_during_a_reply_cancels_the_other_in_flight_page() {
        let export = request().export;
        let wire = "x".repeat(4 * PAGE_BYTES);
        let active = AtomicUsize::new(0);
        let allowed = AtomicBool::new(true);
        let mut pull = Box::pin(fetch_export_pages(
            &export,
            PageConcurrency::new(2).unwrap(),
            |json| {
                let page: PageRequest = serde_json::from_str(&json).unwrap();
                let (wire, active, allowed) = (&wire, &active, &allowed);
                async move {
                    let _active = ActiveFetch::new(active);
                    if page.offset == PAGE_BYTES {
                        std::future::pending::<()>().await;
                    }
                    if page.offset == 2 * PAGE_BYTES {
                        allowed.store(false, Ordering::SeqCst);
                    }
                    encode_page(&page, wire)
                }
            },
            || {
                if allowed.load(Ordering::SeqCst) { Ok(()) }
                else { Err(invalid("fixture authority revoked")) }
            },
        ));
        assert!(matches!(futures_util::poll!(pull.as_mut()), Poll::Ready(Err(_))));
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }

    #[fcp_async_core::runtime::test]
    async fn changed_or_oversized_later_page_fails_before_a_hung_sibling_finishes() {
        let export = request().export;
        let wire = "x".repeat(4 * PAGE_BYTES);
        for mutation in 0..5 {
            let active = AtomicUsize::new(0);
            let mut pull = Box::pin(fetch_export_pages(
                &export,
                PageConcurrency::new(2).unwrap(),
                |json| {
                    let page: PageRequest = serde_json::from_str(&json).unwrap();
                    let (wire, active) = (&wire, &active);
                    async move {
                        let _active = ActiveFetch::new(active);
                        if page.offset == PAGE_BYTES {
                            std::future::pending::<()>().await;
                        }
                        let encoded = encode_page(&page, wire)?;
                        if page.offset != 2 * PAGE_BYTES {
                            return Ok(encoded);
                        }
                        if mutation == 4 {
                            return Ok(" ".repeat(MAX_PAGE_WIRE_BYTES + 1));
                        }
                        let mut response: PageResponse = serde_json::from_str(&encoded).unwrap();
                        match mutation {
                            0 => response.total_bytes -= 1,
                            1 => response.wire_digest = "f".repeat(64),
                            2 => response.request.offset = PAGE_BYTES,
                            _ => response.data_hex.truncate(2),
                        }
                        Ok(serde_json::to_string(&response).unwrap())
                    }
                },
                || Ok(()),
            ));
            assert!(matches!(futures_util::poll!(pull.as_mut()), Poll::Ready(Err(_))));
            assert_eq!(active.load(Ordering::SeqCst), 0);
        }
    }

    #[fcp_async_core::runtime::test]
    async fn parallel_pages_still_require_the_complete_export_digest() {
        let export = request().export;
        let wire = "x".repeat(3 * PAGE_BYTES);
        let result = fetch_export_pages(
            &export,
            PageConcurrency::new(2).unwrap(),
            |json| {
                let page: PageRequest = serde_json::from_str(&json).unwrap();
                let mut response: PageResponse =
                    serde_json::from_str(&encode_page(&page, &wire).unwrap()).unwrap();
                if page.offset == 2 * PAGE_BYTES {
                    response.data_hex = hex::encode("y".repeat(PAGE_BYTES));
                }
                let wire = serde_json::to_string(&response).unwrap();
                async move { Ok(wire) }
            },
            || Ok(()),
        )
        .await;
        assert!(result.is_err());
    }

    struct StalledStore {
        inner: MemoryObjectStore,
        reads: AtomicUsize,
        active: AtomicUsize,
        puts: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl ObjectStore for StalledStore {
        async fn put(&self, object: StoredObject) -> Result<(), ObjectStoreError> {
            self.puts.fetch_add(1, Ordering::SeqCst);
            self.inner.put(object).await
        }

        async fn get(&self, _id: &ObjectId) -> Result<StoredObject, ObjectStoreError> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            let _active = ActiveFetch::new(&self.active);
            pending().await
        }

        async fn exists(&self, id: &ObjectId) -> bool { self.inner.exists(id).await }
        async fn delete(&self, id: &ObjectId) -> Result<(), ObjectStoreError> {
            self.inner.delete(id).await
        }
        async fn get_header(&self, id: &ObjectId) -> Result<ObjectHeader, ObjectStoreError> {
            self.inner.get_header(id).await
        }
        async fn get_storage_meta(&self, id: &ObjectId) -> Result<StorageMeta, ObjectStoreError> {
            self.inner.get_storage_meta(id).await
        }
        async fn set_retention(&self, id: &ObjectId, retention: RetentionClass) -> Result<(), ObjectStoreError> {
            self.inner.set_retention(id, retention).await
        }
        async fn list_zone(&self, zone: &ZoneId) -> Vec<ObjectId> { self.inner.list_zone(zone).await }
        async fn storage_used(&self) -> u64 { self.inner.storage_used().await }
        async fn storage_quota(&self) -> u64 { self.inner.storage_quota().await }
    }

    fn service_fixture(
        direction: ConnectorStateTransferDirection,
    ) -> (ConnectorStateReplicationService, ConnectorStatePullRequest, Arc<StalledStore>) {
        let objects = Arc::new(StalledStore {
            inner: MemoryObjectStore::new(MemoryObjectStoreConfig::default()),
            reads: AtomicUsize::new(0),
            active: AtomicUsize::new(0),
            puts: AtomicUsize::new(0),
        });
        let request = ConnectorStatePullRequest {
            peer_node: "peer".to_owned(),
            request: request().export,
        };
        let writer = fcp_crypto::Ed25519SigningKey::from_bytes(&[0x5a; 32]).unwrap();
        let adapter = FcpStoreConnectorStateStore::new(
            objects.clone(), ObjectIdKey::from_bytes([42; 32]),
            request.request.scope.connector_id.clone(), request.request.scope.zone_id.clone(),
        ).with_trusted_writer_keys([writer.verifying_key().to_bytes()]);
        let mut service = ConnectorStateReplicationService::new();
        service.register_store(direction, request.request.scope.clone(), Arc::new(adapter)).unwrap();
        service.add_grant(ConnectorStateTransferGrant {
            grant_id: request.request.grant_id.clone(),
            direction,
            peer_node: request.peer_node.clone(),
            scope: request.request.scope.clone(),
            root_object_id: request.request.root_object_id,
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            limits: request.request.limits,
        }).unwrap();
        (service, request, objects)
    }

    #[fcp_async_core::runtime::test]
    async fn live_export_revocation_drops_storage_reads_and_releases_cache_builds() {
        for paged in [false, true] {
            let (service, request, objects) = service_fixture(ConnectorStateTransferDirection::Export);
            let wire = if paged {
                PageRequest::first(&request.request).to_json().unwrap()
            } else {
                request.request.to_json().unwrap()
            };
            let allowed = AtomicBool::new(true);
            let authority = || {
                if allowed.load(Ordering::SeqCst) { Ok(()) }
                else { Err(HostError::PreflightFailed("fixture revoked".to_owned())) }
            };
            let mut export = Box::pin(service.export_transfer_for_peer("peer", &wire, &authority));
            assert!(futures_util::poll!(export.as_mut()).is_pending());
            assert_eq!(objects.reads.load(Ordering::SeqCst), 1);
            assert_eq!(objects.active.load(Ordering::SeqCst), 1);
            assert_eq!(service.runtime.active(), 1);
            allowed.store(false, Ordering::SeqCst);
            assert!(matches!(futures_util::poll!(export.as_mut()), Poll::Ready(Err(HostError::PreflightFailed(_)))));
            assert_eq!(objects.active.load(Ordering::SeqCst), 0);
            assert_eq!(service.runtime.active(), 0);
            assert_eq!(objects.puts.load(Ordering::SeqCst), 0);

            // Explicitly issue a new call to prove a cancelled builder did not
            // strand its key. The service never initiates this second request.
            allowed.store(true, Ordering::SeqCst);
            let mut next = Box::pin(service.export_transfer_for_peer("peer", &wire, &authority));
            assert!(futures_util::poll!(next.as_mut()).is_pending());
            assert_eq!(objects.reads.load(Ordering::SeqCst), 2);
            if paged { assert_eq!(service.runtime.cache_builds_started(), 2); }
            drop(next);
            assert_eq!(objects.active.load(Ordering::SeqCst), 0);
            assert_eq!(service.runtime.active(), 0);
        }
    }

    #[fcp_async_core::runtime::test]
    async fn single_donor_revocation_drops_parallel_pages_without_importing() {
        for pages in [1, 2] {
            let (service, request, objects) = service_fixture(ConnectorStateTransferDirection::Import);
            let service = service.with_page_concurrency(pages).unwrap();
            let wire = "x".repeat(4 * PAGE_BYTES);
            let allowed = AtomicBool::new(true);
            let active = AtomicUsize::new(0);
            let constructed = AtomicUsize::new(0);
            let mut pull = Box::pin(service.pull_paged_from_peer(
                &request,
                |json| {
                    constructed.fetch_add(1, Ordering::SeqCst);
                    let page: PageRequest = serde_json::from_str(&json).unwrap();
                    let (wire, active) = (&wire, &active);
                    async move {
                        let _active = ActiveFetch::new(active);
                        if page.offset != 0 { pending::<()>().await; }
                        encode_page(&page, wire)
                    }
                },
                || {
                    if allowed.load(Ordering::SeqCst) { Ok(()) }
                    else { Err(HostError::PreflightFailed("fixture revoked".to_owned())) }
                },
            ));
            for _ in 0..8 { assert!(futures_util::poll!(pull.as_mut()).is_pending()); }
            assert_eq!(active.load(Ordering::SeqCst), pages);
            assert_eq!(constructed.load(Ordering::SeqCst), pages + 1);
            allowed.store(false, Ordering::SeqCst);
            assert!(matches!(futures_util::poll!(pull.as_mut()), Poll::Ready(Err(HostError::PreflightFailed(_)))));
            assert_eq!(active.load(Ordering::SeqCst), 0);
            assert_eq!(constructed.load(Ordering::SeqCst), pages + 1);
            assert_eq!(service.runtime.active(), 0);
            assert_eq!(objects.reads.load(Ordering::SeqCst), 0);
            assert_eq!(objects.puts.load(Ordering::SeqCst), 0);
        }
    }

    #[fcp_async_core::runtime::test]
    async fn exhausted_service_budgets_do_not_admit_reads_or_network_work() {
        let (exporter, request, objects) = service_fixture(ConnectorStateTransferDirection::Export);
        let wire = PageRequest::first(&request.request).to_json().unwrap();
        let result = exporter.export_transfer_with_budget(
            "peer", &wire, || panic!("expired export reached authorization"),
            Instant::now(), Duration::ZERO,
        ).await;
        assert!(result.unwrap_err().to_string().contains("state-export deadline"));
        assert_eq!(objects.reads.load(Ordering::SeqCst), 0);
        assert_eq!(exporter.runtime.cache_builds_started(), 0);
        assert_eq!(exporter.runtime.active(), 0);

        let (recipient, request, objects) = service_fixture(ConnectorStateTransferDirection::Import);
        let result = recipient.pull_paged_with_budget(
            &request, |_| async { panic!("expired pull reached network") },
            || panic!("expired pull reached authorization"), Instant::now(), Duration::ZERO,
        ).await;
        assert!(result.unwrap_err().to_string().contains("state-transfer deadline"));
        assert_eq!(objects.puts.load(Ordering::SeqCst), 0);
        assert_eq!(recipient.runtime.active(), 0);
    }

    #[fcp_async_core::runtime::test]
    async fn service_deadline_drops_a_never_waking_export_and_its_build_claim() {
        let (service, request, objects) = service_fixture(ConnectorStateTransferDirection::Export);
        let wire = PageRequest::first(&request.request).to_json().unwrap();
        let mut export = Box::pin(service.export_transfer_with_budget(
            "peer", &wire, || Ok(()), Instant::now(), Duration::from_millis(100),
        ));
        assert!(futures_util::poll!(export.as_mut()).is_pending());
        assert_eq!(objects.active.load(Ordering::SeqCst), 1);
        let error = export.await.unwrap_err();
        assert!(error.to_string().contains("state-export deadline"));
        assert_eq!(objects.active.load(Ordering::SeqCst), 0);
        assert_eq!(service.runtime.active(), 0);
        let mut next = Box::pin(service.export_transfer_for_peer("peer", &wire, || Ok(())));
        assert!(futures_util::poll!(next.as_mut()).is_pending());
        assert_eq!(service.runtime.cache_builds_started(), 2);
        drop(next);
        assert_eq!(service.runtime.active(), 0);
    }

    #[fcp_async_core::runtime::test]
    async fn abandoning_a_single_donor_anchor_releases_its_reservation() {
        let (service, request, objects) = service_fixture(ConnectorStateTransferDirection::Import);
        let active = AtomicUsize::new(0);
        let mut pull = Box::pin(service.pull_paged_from_peer(
            &request,
            |_| async {
                let _active = ActiveFetch::new(&active);
                pending::<HostResult<String>>().await
            },
            || Ok(()),
        ));
        assert!(futures_util::poll!(pull.as_mut()).is_pending());
        assert_eq!(active.load(Ordering::SeqCst), 1);
        assert_eq!(service.runtime.active(), 1);
        drop(pull);
        assert_eq!(active.load(Ordering::SeqCst), 0);
        assert_eq!(service.runtime.active(), 0);
        assert_eq!(objects.puts.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn live_transfer_futures_remain_send_with_send_callbacks() {
        fn assert_send<T: Send>(_: &T) {}
        let (service, request, _) = service_fixture(ConnectorStateTransferDirection::Export);
        let wire = request.request.to_json().unwrap();
        assert_send(&service.export_transfer_for_peer("peer", &wire, || Ok(())));
        assert_send(&service.pull_paged_from_peer(
            &request, |_| pending::<HostResult<String>>(), || Ok(()),
        ));
    }
}
