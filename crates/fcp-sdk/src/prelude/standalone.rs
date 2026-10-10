//! Instance-bound authorization for standalone connector processes.
//!
//! The private host-to-connector control channel supplies the handshake key.
//! This layer verifies signed capabilities at the process boundary; it does not
//! replace host revocation, holder-proof, approval, lease or provenance checks.

use std::collections::{BTreeMap, BTreeSet};

use fcp_core::{BoundVerified, CapabilityVerifier};
use fcp_manifest::ConnectorManifest;
use sha2::{Digest, Sha256};

use crate::{
    CapabilityGrant, CapabilityId, CapabilityToken, ConnectorId, EventCaps, FcpError,
    FcpResult, HandshakeRequest, HandshakeResponse, InstanceId, OperationId, SessionId, ZoneId,
};

/// Negotiated capability authority for one standalone connector process.
///
/// A new handshake rotates the actual instance identifier, even if the host
/// repeats its preferred identifier. Hosts must bind tokens to [`Self::instance_id`]
/// returned by the process, not assume that their preference was accepted.
/// Invalid handshakes and explicit invalidation revoke the previous authority.
/// Call [`Self::invalidate`] before reconfiguration or shutdown, including failed
/// reconfiguration attempts, so old credentials cannot retain invocation rights.
///
/// Only signature, validity, zone, operation, instance binding and the verifier's
/// resource-URI checks are proved by the returned `BoundVerified` witness.
/// A host must still perform its higher-level policy and revocation enforcement.
pub struct StandaloneSession {
    connector_id: ConnectorId,
    instance_id: InstanceId,
    manifest_hash: String,
    operations: BTreeMap<String, CapabilityId>,
    authority: Option<Authority>,
}

struct Authority {
    verifier: CapabilityVerifier,
    zone: ZoneId,
    capabilities: BTreeSet<String>,
}

impl StandaloneSession {
    /// Load the exact embedded manifest, validating its declared interface hash.
    ///
    /// # Errors
    /// Returns an internal error if the embedded manifest is invalid.
    pub fn new(manifest_toml: &str) -> FcpResult<Self> {
        let manifest = ConnectorManifest::parse_str(manifest_toml).map_err(|error| {
            FcpError::Internal {
                message: format!("Invalid embedded connector manifest: {error}"),
            }
        })?;
        Ok(Self {
            connector_id: manifest.connector.id,
            instance_id: InstanceId::new(),
            manifest_hash: manifest_hash(manifest_toml),
            operations: manifest.provides.operations.into_iter()
                .map(|(id, operation)| (id, operation.capability)).collect(),
            authority: None,
        })
    }

    /// The actual process instance to which the host must bind capability tokens.
    #[must_use]
    pub const fn instance_id(&self) -> &InstanceId {
        &self.instance_id
    }

    /// Whether a validated handshake currently authorizes this session.
    #[must_use]
    pub const fn is_established(&self) -> bool {
        self.authority.is_some()
    }

    /// Drop negotiated authority and rotate the instance binding.
    pub fn invalidate(&mut self) {
        self.authority = None;
        self.instance_id = InstanceId::new();
    }

    /// Negotiate only capabilities declared by this connector's operations.
    ///
    /// The host key is trusted only because this is a private control channel.
    /// No requested capabilities means no grants, not unrestricted access.
    /// This is the existing FCP 2 JSONL handshake, not an FCP3 transport cutover.
    ///
    /// # Errors
    /// Rejects unsupported protocol versions without retaining prior authority.
    pub fn handshake(&mut self, request: HandshakeRequest) -> FcpResult<HandshakeResponse> {
        self.invalidate();
        if !matches!(request.protocol_version.as_str(), "2.0" | "2.0.0") {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Standalone JSONL handshake requires protocol 2.0 or 2.0.0".into(),
            });
        }
        let negotiated: BTreeMap<String, CapabilityId> = request.capabilities_requested.into_iter()
            .filter(|capability| self.operations.values().any(|known| known == capability))
            .map(|capability| (capability.as_str().to_owned(), capability)).collect();
        let capabilities = negotiated.keys().cloned().collect();
        let capabilities_granted = negotiated.into_values().map(|capability| CapabilityGrant {
            capability,
            operation: None,
        }).collect();
        let response = HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted,
            session_id: SessionId::new(),
            manifest_hash: self.manifest_hash.clone(),
            nonce: request.nonce,
            event_caps: Some(EventCaps::default()),
            auth_caps: None,
            op_catalog_hash: None,
        };
        self.authority = Some(Authority {
            verifier: CapabilityVerifier::new(
                request.host_public_key,
                request.zone.clone(),
                self.instance_id.clone(),
            ),
            zone: request.zone,
            capabilities,
        });
        Ok(response)
    }

    /// Verify one operation before any provider work or network I/O.
    ///
    /// Resource URIs must be extracted from the actual operation input by the
    /// caller, never accepted as an alternate caller-supplied authorization list.
    /// The witness can be required by the provider-dispatch function signature.
    ///
    /// # Errors
    /// Fails closed without a handshake, for a different target/zone, for an
    /// undeclared or unnegotiated capability, or on any token verification error.
    pub fn authorize(
        &self,
        connector_id: &ConnectorId,
        zone: &ZoneId,
        operation: &OperationId,
        token: CapabilityToken,
        resource_uris: &[String],
    ) -> FcpResult<CapabilityToken<BoundVerified>> {
        let authority = self.authority.as_ref().ok_or(FcpError::NotHandshaken)?;
        let capability = self.operations.get(operation.as_str()).ok_or_else(|| {
            FcpError::InvalidRequest {
                code: 1002,
                message: "Operation is not declared by this connector".into(),
            }
        })?;
        let denied = |reason: &str| FcpError::CapabilityDenied {
            capability: capability.as_str().to_owned(),
            reason: reason.to_owned(),
        };
        if connector_id != &self.connector_id {
            return Err(denied("Invocation targets a different connector"));
        }
        if zone != &authority.zone {
            return Err(denied("Invocation zone differs from the negotiated zone"));
        }
        if !authority.capabilities.contains(capability.as_str()) {
            return Err(denied("Required capability was not negotiated in this session"));
        }
        authority.verifier.verify_bound(token, capability, operation, resource_uris)
    }
}

fn manifest_hash(manifest_toml: &str) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(manifest_toml.as_bytes())))
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, Utc};
    use fcp_core::CapabilityConstraints;
    use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};

    use super::*;

    const READ: &str = "fixture.read";
    const WRITE: &str = "fixture.write";
    const GET: &str = "fixture.get";
    const PUT: &str = "fixture.put";

    fn session() -> StandaloneSession {
        StandaloneSession {
            connector_id: ConnectorId::from_static("fcp.fixture"),
            instance_id: InstanceId::new(),
            manifest_hash: manifest_hash("fixture manifest"),
            operations: BTreeMap::from([
                (GET.into(), CapabilityId::from_static(READ)),
                (PUT.into(), CapabilityId::from_static(WRITE)),
            ]),
            authority: None,
        }
    }

    fn handshake(key: &Ed25519SigningKey) -> HandshakeRequest {
        HandshakeRequest {
            protocol_version: "2.0.0".into(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key: key.verifying_key().to_bytes(),
            nonce: [17; 32],
            capabilities_requested: vec![CapabilityId::from_static(READ)],
            host: None,
            transport_caps: None,
            requested_instance_id: None,
        }
    }

    fn token(
        session: &StandaloneSession,
        key: &Ed25519SigningKey,
        capability: &str,
        operation: &str,
        zone: &str,
        seconds_from_now: i64,
    ) -> CapabilityToken {
        let constraints = CapabilityConstraints {
            resource_allow: vec!["urn:fixture:allowed".into()],
            ..Default::default()
        };
        let mut cbor = Vec::new();
        ciborium::into_writer(&constraints, &mut cbor).unwrap();
        let now = Utc::now();
        let raw = CapabilityTokenBuilder::new()
            .capability_id(capability)
            .zone_id(zone)
            .principal("user:test")
            .operations(&[operation])
            .issuer("node:test")
            .target_instance(session.instance_id().as_str())
            .validity(now - Duration::hours(1), now + Duration::seconds(seconds_from_now))
            .try_constraints_cbor(&cbor).unwrap()
            .sign(key).unwrap();
        CapabilityToken::from_raw(raw)
    }

    fn authorize(session: &StandaloneSession, token: CapabilityToken) -> FcpResult<CapabilityToken<BoundVerified>> {
        session.authorize(
            &ConnectorId::from_static("fcp.fixture"),
            &ZoneId::work(), &OperationId::from_static(GET), token,
            &["urn:fixture:allowed".into()],
        )
    }

    fn established() -> (StandaloneSession, Ed25519SigningKey) {
        let mut session = session();
        let key = Ed25519SigningKey::generate();
        session.handshake(handshake(&key)).unwrap();
        (session, key)
    }

    #[test]
    fn valid_signature_produces_instance_bound_witness() {
        let (session, key) = established();
        let verified: CapabilityToken<BoundVerified> = authorize(
            &session, token(&session, &key, READ, GET, "z:work", 3600),
        ).unwrap();
        drop(verified);
    }

    #[test]
    fn missing_handshake_fails_closed() {
        assert!(matches!(authorize(&session(), CapabilityToken::test_token()), Err(FcpError::NotHandshaken)));
    }

    #[test]
    fn undeclared_operation_is_rejected() {
        let (session, key) = established();
        assert!(session.authorize(
            &ConnectorId::from_static("fcp.fixture"), &ZoneId::work(),
            &OperationId::from_static("fixture.unknown"),
            token(&session, &key, READ, GET, "z:work", 3600), &[],
        ).is_err());
    }

    #[test]
    fn foreign_signer_is_rejected() {
        let (session, _) = established();
        let foreign = Ed25519SigningKey::generate();
        assert!(authorize(&session, token(&session, &foreign, READ, GET, "z:work", 3600)).is_err());
    }

    #[test]
    fn expired_token_is_rejected() {
        let (session, key) = established();
        assert!(authorize(&session, token(&session, &key, READ, GET, "z:work", -600)).is_err());
    }

    #[test]
    fn token_zone_must_match_authority() {
        let (session, key) = established();
        assert!(authorize(&session, token(&session, &key, READ, GET, "z:private", 3600)).is_err());
    }

    #[test]
    fn token_operation_must_match_invocation() {
        let (session, key) = established();
        assert!(authorize(&session, token(&session, &key, READ, PUT, "z:work", 3600)).is_err());
    }

    #[test]
    fn token_capability_must_match_manifest() {
        let (session, key) = established();
        assert!(authorize(&session, token(&session, &key, WRITE, GET, "z:work", 3600)).is_err());
    }

    #[test]
    fn negotiated_grants_are_an_intersection_without_duplicates() {
        let mut session = session();
        let key = Ed25519SigningKey::generate();
        let mut request = handshake(&key);
        request.capabilities_requested.extend([
            CapabilityId::from_static(READ), CapabilityId::from_static("unrelated.admin"),
        ]);
        let response = session.handshake(request).unwrap();
        assert_eq!(response.capabilities_granted.len(), 1);
        assert_eq!(response.capabilities_granted[0].capability.as_str(), READ);
        assert_eq!(response.nonce, [17; 32]);
        assert_eq!(response.manifest_hash, manifest_hash("fixture manifest"));
    }

    #[test]
    fn empty_requested_capabilities_do_not_grant_everything() {
        let (mut session, key) = established();
        let mut request = handshake(&key);
        request.capabilities_requested.clear();
        assert!(session.handshake(request).unwrap().capabilities_granted.is_empty());
        assert!(authorize(&session, token(&session, &key, READ, GET, "z:work", 3600)).is_err());
    }

    #[test]
    fn mismatched_request_target_and_zone_are_rejected() {
        let (session, key) = established();
        for (target, zone) in [
            (ConnectorId::from_static("fcp.other"), ZoneId::work()),
            (ConnectorId::from_static("fcp.fixture"), ZoneId::private()),
        ] {
            assert!(session.authorize(&target, &zone, &OperationId::from_static(GET),
                token(&session, &key, READ, GET, "z:work", 3600), &[]).is_err());
        }
    }

    #[test]
    fn actual_resource_uri_is_checked() {
        let (session, key) = established();
        assert!(session.authorize(
            &ConnectorId::from_static("fcp.fixture"), &ZoneId::work(), &OperationId::from_static(GET),
            token(&session, &key, READ, GET, "z:work", 3600), &["urn:fixture:denied".into()],
        ).is_err());
    }

    #[test]
    fn rehandshake_cannot_revive_a_token_for_the_old_instance() {
        let (mut session, key) = established();
        let old_instance = session.instance_id().clone();
        let old_token = token(&session, &key, READ, GET, "z:work", 3600);
        let mut request = handshake(&key);
        request.requested_instance_id = Some(old_instance.clone());
        session.handshake(request).unwrap();
        assert_ne!(session.instance_id(), &old_instance);
        assert!(authorize(&session, old_token).is_err());
        assert!(authorize(&session, token(&session, &key, READ, GET, "z:work", 3600)).is_ok());
    }

    #[test]
    fn invalidate_revokes_authority_immediately() {
        let (mut session, key) = established();
        let old_token = token(&session, &key, READ, GET, "z:work", 3600);
        session.invalidate();
        assert!(!session.is_established());
        assert!(matches!(authorize(&session, old_token), Err(FcpError::NotHandshaken)));
    }

    #[test]
    fn failed_rehandshake_does_not_retain_old_authority() {
        let (mut session, key) = established();
        let mut request = handshake(&key);
        request.protocol_version = "unexpected".into();
        assert!(session.handshake(request).is_err());
        assert!(!session.is_established());
    }

    #[test]
    fn invalid_embedded_manifest_fails_closed() {
        assert!(StandaloneSession::new("not a manifest").is_err());
    }

    #[test]
    fn manifest_hash_is_sha256_of_exact_utf8_bytes() {
        assert_eq!(manifest_hash("abc"), "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_ne!(manifest_hash("abc"), manifest_hash("abc\n"));
    }
}
