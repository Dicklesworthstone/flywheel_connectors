//! Bounded wire paging for exact-root connector-state replication.
//!
//! Pages transport the existing, fully validated v1 export; they neither widen
//! grants nor publish partial histories. Every page is independently protected
//! by the mesh request/reply signature and nonce. The digest binds all pages to
//! one byte-identical export, not to a new source of authority. A failed pull
//! drops its assembly without importing anything or retrying another donor.

use std::future::Future;

use serde::{Deserialize, Serialize};

use crate::{
    ConnectorStateExportRequest, ConnectorStatePullRequest, ConnectorStatePullResponse,
    ConnectorStateReplicationService, HostError, HostResult,
    MAX_CONNECTOR_STATE_EXPORT_REQUEST_BYTES, MAX_CONNECTOR_STATE_TRANSFER_WIRE_BYTES,
};

const PAGE_SCHEMA: &str = "fcp.host.state-transfer-page.v1";
// Hex keeps the signed JSON wrapper free of a second layer of string escaping.
// Only one page is requested at a time; no peer-controlled URL/cursor is used.
const PAGE_BYTES: usize = 48 * 1024;
const MAX_PAGE_WIRE_BYTES: usize = 256 * 1024;

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
            || self.wire_digest.as_deref().is_some_and(|digest| !valid_digest(digest))
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
            return Err(invalid("connector-state page request exceeds its wire limit"));
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
        && digest.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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
    let mut value: serde_json::Value = serde_json::from_str(&wire)
        .map_err(|_| invalid("connector-state export is malformed"))?;
    drop(wire);
    value.sort_all_objects();
    let wire = serde_json::to_string(&value)
        .map_err(|_| invalid("connector-state export cannot be encoded"))?;
    if wire.len() > limit {
        return Err(invalid("connector-state export exceeds its wire limit"));
    }
    Ok(wire)
}

fn encode_page(request: &PageRequest, wire: &str) -> HostResult<String> {
    request.validate()?;
    let total_bytes = wire.len();
    if total_bytes == 0
        || total_bytes > request.export.limits.max_wire_bytes
        || request.offset >= total_bytes
    {
        return Err(invalid("connector-state export does not fit the requested page bounds"));
    }
    let digest = blake3::hash(wire.as_bytes()).to_hex().to_string();
    if request.wire_digest.as_ref().is_some_and(|expected| expected != &digest) {
        return Err(invalid("connector-state export changed between pages"));
    }
    let end = request.offset.saturating_add(PAGE_BYTES).min(total_bytes);
    let response = PageResponse {
        schema_version: PAGE_SCHEMA.to_owned(),
        request: request.clone(),
        total_bytes,
        wire_digest: digest,
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

impl Assembly {
    /// Validate the complete page before retaining even its first byte.
    fn accept(&mut self, request: &PageRequest, wire: &str) -> HostResult<bool> {
        request.validate()?;
        if wire.len() > MAX_PAGE_WIRE_BYTES {
            return Err(invalid("connector-state page exceeds its envelope limit"));
        }
        let page: PageResponse = serde_json::from_str(wire)
            .map_err(|_| invalid("connector-state page is malformed"))?;
        if page.schema_version != PAGE_SCHEMA
            || page.request != *request
            || request.offset != self.bytes.len()
            || request.wire_digest != self.digest
            || page.total_bytes == 0
            || page.total_bytes > request.export.limits.max_wire_bytes
            || page.total_bytes > MAX_CONNECTOR_STATE_TRANSFER_WIRE_BYTES
            || request.offset >= page.total_bytes
            || !valid_digest(&page.wire_digest)
            || self.total_bytes.is_some_and(|total| total != page.total_bytes)
            || self.digest.as_ref().is_some_and(|digest| digest != &page.wire_digest)
        {
            return Err(invalid("connector-state page does not match the admitted transfer"));
        }
        let expected_bytes = PAGE_BYTES.min(page.total_bytes - request.offset);
        if page.data_hex.len() != expected_bytes * 2 {
            return Err(invalid("connector-state page has an invalid payload length"));
        }
        let decoded = hex::decode(&page.data_hex)
            .map_err(|_| invalid("connector-state page payload is malformed"))?;
        self.bytes.extend_from_slice(&decoded);
        self.total_bytes = Some(page.total_bytes);
        self.digest = Some(page.wire_digest);
        Ok(self.bytes.len() == page.total_bytes)
    }

    fn finish(self) -> HostResult<String> {
        if self.total_bytes != Some(self.bytes.len())
            || self.digest.as_deref() != Some(blake3::hash(&self.bytes).to_hex().as_str())
        {
            return Err(invalid("connector-state transfer is incomplete or its digest differs"));
        }
        String::from_utf8(self.bytes)
            .map_err(|_| invalid("connector-state transfer is not UTF-8"))
    }
}

impl ConnectorStateReplicationService {
    /// Serve a complete v1 export or one bounded page of that same export.
    ///
    /// The complete ancestry, exact-root grant and transport authority are
    /// revalidated on every page. No server-side transfer session is created.
    /// A continuation pins a digest and fails if the serialized export changes.
    /// This currently rereads the complete bounded ancestry for each page;
    /// it is wire paging, not unbounded-history or delta replication.
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
        if request_json.len() > MAX_CONNECTOR_STATE_EXPORT_REQUEST_BYTES {
            return Err(invalid("connector-state export request exceeds its wire limit"));
        }
        let request: ExportWireRequest = serde_json::from_str(request_json)
            .map_err(|_| invalid("connector-state export request is malformed"))?;
        match request {
            ExportWireRequest::Complete(request) => {
                self.export_for_peer(authenticated_peer, &request, authorize_transport).await
            }
            ExportWireRequest::Page(page) => {
                page.validate()?;
                let wire = self.export_for_peer(
                    authenticated_peer, &page.export, &authorize_transport,
                ).await?;
                let wire = stable_export_wire(wire, page.export.limits.max_wire_bytes)?;
                let encoded = encode_page(&page, &wire)?;
                authorize_transport()?;
                Ok(encoded)
            }
        }
    }

    /// Pull one signed export in bounded pages, then import its complete history.
    ///
    /// `fetch_page` must return only the body of a successful, authenticated,
    /// nonce-bound reply from the selected donor. Each call gets a new signed
    /// request, not a retry of an earlier envelope. Never follow a peer-provided
    /// cursor or URL. The host must bound this entire future with one deadline.
    ///
    /// Existing grant limits apply to the reassembled v1 JSON, canonical bytes
    /// and object count. Page framing has a separate fixed cap. `wire_bytes` in
    /// the returned receipt still counts v1 JSON, not hex or mesh framing.
    /// No object is imported before all pages, the digest, and ordinary replica
    /// validation pass. Dropping this future before import drops only an in-memory
    /// assembly. After write admission, the existing persistent-write cancellation
    /// semantics apply. No pages are cached on disk and no automatic retries occur.
    ///
    /// # Errors
    /// Refuses expired grants, transport failures, missing/reordered/changed pages,
    /// over-budget responses, invalid ancestry and persistence failures.
    pub async fn pull_paged_from_peer<F, Fut, A>(
        &self,
        request: &ConnectorStatePullRequest,
        mut fetch_page: F,
        authorize_transport: A,
    ) -> HostResult<ConnectorStatePullResponse>
    where
        F: FnMut(String) -> Fut,
        Fut: Future<Output = HostResult<String>>,
        A: Fn() -> HostResult<()> + Send + Sync,
    {
        let mut page = PageRequest::first(&request.request);
        let mut assembly = Assembly::default();
        // Every accepted page makes exact, nonzero progress. The total grant
        // limit therefore bounds both retained bytes and network round trips.
        loop {
            self.validate_pull(request)?;
            authorize_transport()?;
            let wire = fetch_page(page.to_json()?).await?;
            self.validate_pull(request)?;
            authorize_transport()?;
            if assembly.accept(&page, &wire)? {
                break;
            }
            page.offset = assembly.bytes.len();
            page.wire_digest.clone_from(&assembly.digest);
        }
        let wire = assembly.finish()?;
        self.import_from_peer(request, &wire, authorize_transport).await
    }
}

#[cfg(test)]
mod tests {
    use fcp_kernel::{ConnectorId, ObjectId, ZoneId};
    use crate::{ConnectorStateTransferLimits, ConnectorStateTransferScope};
    use super::*;

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
        let wire = format!("{}{}", "x".repeat(PAGE_BYTES - 1), "\u{1f642}".repeat(PAGE_BYTES));
        let mut request = request();
        let mut assembly = Assembly::default();
        let mut pages = 0;
        loop {
            let page = encode_page(&request, &wire).unwrap();
            assert!(page.len() <= MAX_PAGE_WIRE_BYTES);
            pages += 1;
            if assembly.accept(&request, &page).unwrap() { break; }
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
        assert!(!assembly.accept(&request, &encode_page(&request, &wire).unwrap()).unwrap());
        next_request(&mut request, &assembly);
        assert!(assembly.accept(&request, &encode_page(&request, &wire).unwrap()).unwrap());
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
        assert!(Assembly::default().accept(&next, &encode_page(&next, &wire).unwrap()).is_err());
        assert_eq!(assembly.bytes, saved);
    }

    #[test]
    fn donor_changes_are_rejected_before_another_page_is_disclosed() {
        let wire = "x".repeat(PAGE_BYTES + 1);
        let mut request = request();
        let mut assembly = Assembly::default();
        assembly.accept(&request, &encode_page(&request, &wire).unwrap()).unwrap();
        next_request(&mut request, &assembly);
        assert!(encode_page(&request, &"y".repeat(wire.len())).is_err());
    }

    #[test]
    fn page_metadata_payload_and_length_are_bound_to_the_request() {
        let request = request();
        let original: serde_json::Value = serde_json::from_str(
            &encode_page(&request, "secret-state").unwrap(),
        ).unwrap();
        for (pointer, value) in [
            ("/schema_version", serde_json::json!("other")),
            ("/request/export/grant_id", serde_json::json!("other")),
            ("/request/offset", serde_json::json!(PAGE_BYTES)),
            ("/total_bytes", serde_json::json!(0)),
            ("/total_bytes", serde_json::json!(request.export.limits.max_wire_bytes + 1)),
            ("/wire_digest", serde_json::json!("not-a-digest")),
            ("/data_hex", serde_json::json!("00")),
            ("/data_hex", serde_json::json!("z".repeat("secret-state".len() * 2))),
        ] {
            let mut value_copy = original.clone();
            *value_copy.pointer_mut(pointer).unwrap() = value;
            let mut assembly = Assembly::default();
            let error = assembly.accept(&request, &value_copy.to_string()).unwrap_err();
            assert!(assembly.bytes.is_empty());
            assert!(!error.to_string().contains("secret-state"));
        }
    }

    #[test]
    fn valid_hex_with_forged_content_fails_the_final_digest() {
        let request = request();
        let mut page: PageResponse = serde_json::from_str(
            &encode_page(&request, "abc").unwrap(),
        ).unwrap();
        page.data_hex = hex::encode("xyz");
        let mut assembly = Assembly::default();
        assert!(assembly.accept(&request, &serde_json::to_string(&page).unwrap()).unwrap());
        assert!(assembly.finish().is_err());
    }

    #[test]
    fn missing_tail_cannot_be_finished() {
        let request = request();
        let mut assembly = Assembly::default();
        let wire = "x".repeat(PAGE_BYTES + 1);
        assert!(!assembly.accept(&request, &encode_page(&request, &wire).unwrap()).unwrap());
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
        )).unwrap();
        assert!(result.is_err());
    }
}
