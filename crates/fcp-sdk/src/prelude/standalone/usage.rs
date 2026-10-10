//! Session-local accounting for authenticated capability call ceilings.
//!
//! Entries are never evicted while their instance authority is valid. In
//! particular, neither a clock change nor cache pressure can refill a spent
//! grant. The containing session drops this ledger when it rotates authority.

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard};

use fcp_core::{BoundVerified, CapabilityConstraints, CapabilityToken, FcpError, FcpResult};
use fcp_crypto::cose::fcp2_claims;
use fcp_policy::{CapabilityConstraintEnforcer, DefaultConstraintEnforcer};
use sha2::{Digest, Sha256};

const MAX_TRACKED_GRANTS: usize = 4096;

/// A verified invocation whose signed call allowance has been consumed.
///
/// This witness is deliberately not `Clone`. Dropping it never refunds the
/// allowance: a cancelled or failed operation may already have caused effects.
/// It proves process-bound admission, not mesh-wide quota accounting, byte
/// accounting, revocation, holder proof, approval, or lease enforcement.
pub struct StandaloneInvocation {
    token: CapabilityToken<BoundVerified>,
}

impl StandaloneInvocation {
    /// Inspect the authenticated token without consuming the admission witness.
    #[must_use]
    pub const fn token(&self) -> &CapabilityToken<BoundVerified> {
        &self.token
    }
}

impl std::fmt::Debug for StandaloneInvocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StandaloneInvocation")
            .field("token", &"<verified; redacted>")
            .finish_non_exhaustive()
    }
}

pub(super) struct UsageLedger {
    entries: Mutex<BTreeMap<[u8; 32], Account>>,
    capacity: usize,
}

struct Account {
    grant: [u8; 32],
    spent: u32,
}

struct Scope {
    key: Option<[u8; 32]>,
    grant: [u8; 32],
    constraints: CapabilityConstraints,
}

impl Default for UsageLedger {
    fn default() -> Self {
        Self {
            entries: Mutex::new(BTreeMap::new()),
            capacity: MAX_TRACKED_GRANTS,
        }
    }
}

impl Scope {
    fn from_verified(token: &CapabilityToken<BoundVerified>) -> FcpResult<Self> {
        // Never inspect an unverified token or accept a caller's separate
        // constraint object as authority for its budget.
        let claims = token.claims();
        let raw = claims.get(fcp2_claims::CONSTRAINTS).ok_or_else(|| {
            denied("Verified capability has no constraints")
        })?;
        let mut encoded = Vec::new();
        ciborium::into_writer(raw, &mut encoded)
            .map_err(|_| denied("Cannot decode verified capability constraints"))?;
        let constraints: CapabilityConstraints = ciborium::from_reader(encoded.as_slice())
            .map_err(|_| denied("Cannot decode verified capability constraints"))?;
        let key = claims.get_jti().filter(|id| !id.is_empty()).map(|id| {
            let mut hasher = Sha256::new();
            hasher.update(b"FCP-STANDALONE-USAGE-ID-V1");
            hasher.update(id);
            hasher.finalize().into()
        });
        if constraints.max_calls.is_some() && key.is_none() {
            return Err(denied("A call-limited capability requires a non-empty signed token ID"));
        }
        // Bind an account to the canonical SIGNED claims, not a mutable COSE
        // envelope, signature encoding, request ID, operation, or input. A
        // caller cannot reset accounting by changing unprotected headers or
        // alternating between operations granted by the same token.
        let canonical = claims.to_cbor()
            .map_err(|_| denied("Cannot identify verified capability grant"))?;
        let grant = Sha256::digest(&canonical).into();
        Ok(Self { key, grant, constraints })
    }

    fn check_key(&self, supplied: Option<&str>) -> FcpResult<()> {
        if let Some(required) = self.constraints.idempotency_key.as_deref()
            && supplied != Some(required)
        {
            return Err(denied("Invocation does not match the signed idempotency key scope"));
        }
        Ok(())
    }
}

impl UsageLedger {
    fn lock(&self) -> FcpResult<MutexGuard<'_, BTreeMap<[u8; 32], Account>>> {
        self.entries.lock().map_err(|_| FcpError::Internal {
            message: "Capability usage accounting unavailable; admission denied".into(),
        })
    }

    // Check and mutation run under the same mutex. No lock or guard crosses
    // provider execution, an await point, or a user-supplied callback.
    fn check_scope(&self, entries: &BTreeMap<[u8; 32], Account>, scope: &Scope) -> FcpResult<()> {
        let account = scope.key.as_ref().and_then(|key| entries.get(key));
        if account.is_some_and(|account| account.grant != scope.grant) {
            return Err(denied("Signed token ID was reused for a different grant"));
        }
        if let Some(limit) = scope.constraints.max_calls {
            let next = account.map_or(0, |account| account.spent).checked_add(1)
                .ok_or_else(|| denied("Signed capability call budget exhausted"))?;
            if DefaultConstraintEnforcer::new()
                .enforce_scope_ceiling(Some(limit), None, next, 0).is_deny()
            {
                return Err(denied("Signed capability call budget exhausted"));
            }
            if account.is_none() && entries.len() >= self.capacity {
                return Err(FcpError::ResourceExhausted {
                    resource: "standalone capability usage ledger capacity".into(),
                });
            }
        }
        Ok(())
    }

    /// Non-consuming check for authorization and simulation. This is not a
    /// reservation; admission repeats the check atomically before dispatch.
    pub(super) fn check(&self, token: &CapabilityToken<BoundVerified>) -> FcpResult<()> {
        let scope = Scope::from_verified(token)?;
        let entries = self.lock()?;
        self.check_scope(&entries, &scope)
    }

    pub(super) fn admit(
        &self,
        token: CapabilityToken<BoundVerified>,
        idempotency_key: Option<&str>,
    ) -> FcpResult<StandaloneInvocation> {
        let scope = Scope::from_verified(&token)?;
        scope.check_key(idempotency_key)?;
        let mut entries = self.lock()?;
        self.check_scope(&entries, &scope)?;
        if scope.constraints.max_calls.is_some() {
            let key = scope.key.ok_or_else(|| denied("Call-limited capability has no token ID"))?;
            let account = entries.entry(key).or_insert(Account { grant: scope.grant, spent: 0 });
            // check_scope proved this increment fits and is within the signed
            // ceiling. Retain it on every subsequent outcome, including Drop.
            account.spent += 1;
        }
        Ok(StandaloneInvocation { token })
    }
}

fn denied(reason: &str) -> FcpError {
    FcpError::CapabilityDenied {
        capability: "standalone.invocation".into(),
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use chrono::{Duration, Utc};
    use fcp_core::{CapabilityId, CapabilityVerifier, InstanceId, OperationId, ZoneId};
    use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};

    use super::*;

    fn token(limit: Option<u32>, id: &[u8], key_scope: Option<&str>) -> CapabilityToken<BoundVerified> {
        let key = Ed25519SigningKey::from_bytes(&[41; 32]).unwrap();
        let instance = InstanceId::try_from("inst_usage_fixture".to_owned()).unwrap();
        let constraints = CapabilityConstraints {
            resource_allow: vec!["*".into()],
            max_calls: limit,
            idempotency_key: key_scope.map(str::to_owned),
            ..Default::default()
        };
        let mut cbor = Vec::new();
        ciborium::into_writer(&constraints, &mut cbor).unwrap();
        let now = Utc::now();
        let raw = CapabilityTokenBuilder::new()
            .capability_id("fixture.read")
            .zone_id("z:work")
            .principal("user:test")
            .operations(&["fixture.get", "fixture.list"])
            .issuer("node:test")
            .target_instance(instance.as_str())
            .token_id(id)
            .validity(now, now + Duration::hours(1))
            .try_constraints_cbor(&cbor).unwrap()
            .sign(&key).unwrap();
        CapabilityVerifier::new(key.verifying_key().to_bytes(), ZoneId::work(), instance)
            .verify_bound(CapabilityToken::from_raw(raw),
                &CapabilityId::from_static("fixture.read"),
                &OperationId::from_static("fixture.get"), &[]).unwrap()
    }

    #[test]
    fn exact_signed_call_limit_is_consumed_and_drop_never_refunds() {
        let ledger = UsageLedger::default();
        let token = token(Some(2), b"grant", None);
        drop(ledger.admit(token.clone(), None).unwrap());
        ledger.check(&token).unwrap();
        drop(ledger.admit(token.clone(), None).unwrap());
        assert!(ledger.check(&token).is_err());
        assert!(ledger.admit(token, None).is_err());
    }

    #[test]
    fn previews_do_not_consume_or_allocate() {
        let ledger = UsageLedger::default();
        let token = token(Some(1), b"grant", None);
        for _ in 0..20 { ledger.check(&token).unwrap(); }
        assert!(ledger.lock().unwrap().is_empty());
        ledger.admit(token, None).unwrap();
        assert_eq!(ledger.lock().unwrap().len(), 1);
    }

    #[test]
    fn zero_limit_rejects_without_allocating_an_account() {
        let ledger = UsageLedger::default();
        let token = token(Some(0), b"grant", None);
        assert!(ledger.check(&token).is_err());
        assert!(ledger.admit(token, None).is_err());
        assert!(ledger.lock().unwrap().is_empty());
    }

    #[test]
    fn unlimited_tokens_do_not_fill_the_ledger() {
        let ledger = UsageLedger { capacity: 0, ..UsageLedger::default() };
        let token = token(None, b"grant", None);
        for _ in 0..20 { ledger.admit(token.clone(), None).unwrap(); }
        assert!(ledger.lock().unwrap().is_empty());
    }

    #[test]
    fn finite_grants_require_nonempty_signed_identity() {
        let ledger = UsageLedger::default();
        assert!(ledger.admit(token(Some(1), b"", None), None).is_err());
        ledger.admit(token(None, b"", None), None).unwrap();
    }

    #[test]
    fn changed_signed_grant_cannot_refill_the_same_token_id() {
        let ledger = UsageLedger::default();
        ledger.admit(token(Some(1), b"shared", None), None).unwrap();
        assert!(ledger.admit(token(Some(10), b"shared", None), None).is_err());
        assert!(ledger.admit(token(None, b"shared", None), None).is_err());
    }

    #[test]
    fn distinct_signed_token_ids_have_independent_allowances() {
        let ledger = UsageLedger::default();
        ledger.admit(token(Some(1), b"first", None), None).unwrap();
        ledger.admit(token(Some(1), b"second", None), None).unwrap();
        assert_eq!(ledger.lock().unwrap().len(), 2);
    }

    #[test]
    fn capacity_pressure_never_evicts_or_resets_spent_grants() {
        let ledger = UsageLedger { capacity: 1, ..UsageLedger::default() };
        let first = token(Some(2), b"first", None);
        ledger.admit(first.clone(), None).unwrap();
        assert!(matches!(ledger.admit(token(Some(1), b"second", None), None),
            Err(FcpError::ResourceExhausted { .. })));
        ledger.admit(first.clone(), None).unwrap();
        assert!(ledger.admit(first, None).is_err());
        assert_eq!(ledger.lock().unwrap().len(), 1);
    }

    #[test]
    fn signed_idempotency_scope_is_exact_and_denial_does_not_spend() {
        let ledger = UsageLedger::default();
        let token = token(Some(1), b"grant", Some(" key "));
        for key in [None, Some("key"), Some("other")] {
            assert!(ledger.admit(token.clone(), key).is_err());
        }
        assert!(ledger.lock().unwrap().is_empty());
        ledger.admit(token, Some(" key ")).unwrap();
    }

    #[test]
    fn concurrent_admission_cannot_overspend_the_signed_ceiling() {
        let ledger = Arc::new(UsageLedger::default());
        let token = token(Some(7), b"concurrent", None);
        let admitted = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..32).map(|_| {
                let ledger = Arc::clone(&ledger);
                let token = token.clone();
                scope.spawn(move || ledger.admit(token, None).is_ok())
            }).collect();
            handles.into_iter()
                .map(|handle| usize::from(handle.join().unwrap())).sum::<usize>()
        });
        assert_eq!(admitted, 7);
        assert!(ledger.check(&token).is_err());
    }

    #[test]
    fn maximum_u32_allowance_cannot_wrap_back_to_zero() {
        let ledger = UsageLedger::default();
        let token = token(Some(u32::MAX), b"last", None);
        let scope = Scope::from_verified(&token).unwrap();
        ledger.lock().unwrap().insert(scope.key.unwrap(), Account { grant: scope.grant, spent: u32::MAX - 1 });
        ledger.admit(token.clone(), None).unwrap();
        assert!(ledger.admit(token, None).is_err());
    }

    #[test]
    fn poisoned_accounting_fails_closed_instead_of_resetting_allowances() {
        let ledger = UsageLedger::default();
        std::thread::scope(|scope| {
            let ledger = &ledger;
            let _ = scope.spawn(move || {
                let _guard = ledger.entries.lock().unwrap();
                panic!("test poison");
            }).join();
        });
        assert!(matches!(ledger.admit(token(Some(1), b"grant", None), None),
            Err(FcpError::Internal { .. })));
    }

    #[test]
    fn permit_debug_never_prints_authenticated_claims_or_scoped_keys() {
        let ledger = UsageLedger::default();
        let permit = ledger.admit(token(Some(1), b"secret-cti", Some("secret-key")), Some("secret-key")).unwrap();
        let text = format!("{permit:?}");
        assert!(text.contains("redacted"));
        assert!(!text.contains("secret"));
        assert_eq!(permit.token().claims().get_jti(), Some(b"secret-cti".as_slice()));
    }
}
