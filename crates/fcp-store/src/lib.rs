//! FCPS-aligned object and symbol stores (placement, repair, retention).
//!
//! This crate implements the durable storage layer from `FCP_Specification_V3.md`
//! §6 (Durable Object and Evidence Model), §6.5 (Zone Checkpoints), and §11.5
//! (Offline and Repair Behavior):
//!
//! # Overview
//!
//! - **Object Store**: Content-addressed storage for complete mesh objects
//! - **Symbol Store**: Storage for `RaptorQ` symbols enabling partial availability
//! - **Coverage Evaluation**: Quantifiable offline resilience metrics (basis points)
//! - **Repair Controller**: Bounded, convergent repair with rate limiting
//! - **Garbage Collection**: Reachability-based GC with retention classes
//! - **Quarantine Store**: Admission pipeline for untrusted objects
//!
//! # Design Principles
//!
//! 1. **Coverage is measurable**: All metrics use fixed-point basis points for
//!    interop stability across implementations.
//!
//! 2. **Repair is bounded and convergent**: Repair loops push coverage toward
//!    policy targets with rate limiting and admission control.
//!
//! 3. **Retention + GC roots are explicit**: Clear semantics for Pinned, Lease,
//!    and Ephemeral retention with zone checkpoints as canonical roots.
//!
//! 4. **Quarantine by default**: Unknown objects enter a bounded quarantine
//!    store and require explicit promotion to prevent storage exhaustion.

#![forbid(unsafe_code)]
#![allow(clippy::significant_drop_tightening)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::option_if_let_else)]

mod compatibility_ledger;
mod connector_state;
mod coverage;
mod durable;
mod error;
mod gc;
mod object_id_verifier;
mod object_store;
mod offline;
mod process_snapshot;
mod quarantine;
mod repair;
mod resume_handshake;
mod symbol_store;

pub use compatibility_ledger::{
    CompatibilityLedgerStore, CompatibilityLedgerStoreError, DurableCompatibilityLedgerStore,
    MemoryCompatibilityLedgerStore,
};
pub use connector_state::{
    CONNECTOR_STATE_CACHE_HITS_TOTAL_METRIC, CONNECTOR_STATE_CACHE_MARKER,
    CONNECTOR_STATE_COMPACT_EVENT, CONNECTOR_STATE_FALL_THROUGH_EVENT,
    CONNECTOR_STATE_FALL_THROUGH_TOTAL_METRIC, CONNECTOR_STATE_LATENCY_SECONDS_METRIC,
    CONNECTOR_STATE_READ_EVENT, CONNECTOR_STATE_SNAPSHOT_EVENT, CONNECTOR_STATE_TRACING_TARGET,
    CONNECTOR_STATE_WRITE_EVENT, CONNECTOR_STATE_WRITES_TOTAL_METRIC,
    ConnectorStateLeaseYieldFlush, ConnectorStateReplay, ConnectorStateStoreError,
    FcpStoreConnectorStateStore,
};
pub use coverage::{CoverageEvaluation, CoverageHealth, SymbolDistribution};
pub use durable::{
    DurableObjectStore, DurableObjectStoreConfig, DurableSymbolStore, DurableSymbolStoreConfig,
};
pub use error::{
    GcError, LifecycleSnapshotError, ObjectStoreError, QuarantineError, RepairError,
    SymbolStoreError,
};
pub use gc::{
    GarbageCollector, GcConfig, GcDecision, GcDecisionAction, GcReasonCode, GcResult, GcRoots,
    GcRunReport, GcTranscript,
};
pub use object_id_verifier::{KeyedObjectIdVerifier, ObjectIdVerifier};
pub use object_store::{
    LifecycleRootObservation, LifecycleRootRole, LifecycleRootStatus, MemoryObjectStore,
    MemoryObjectStoreConfig, ObjectLeaseState, ObjectLifecycleSnapshot, ObjectStore,
    ZoneLifecycleSnapshot, snapshot_zone_lifecycle,
};
pub use quarantine::{
    ObjectAdmissionClass, ObjectAdmissionPolicy, PromotionReason, QuarantineStats, QuarantineStore,
    QuarantinedObject,
};
pub use repair::{
    PowerState, RepairController, RepairControllerConfig, RepairCycleBudget, RepairCycleUsage,
    RepairEvaluationDecision, RepairEvaluationReasonCode, RepairEvaluationReport, RepairPermit,
    RepairPlan, RepairPlanAction, RepairPlanningOptions, RepairPolicyTargets, RepairQueueAction,
    RepairReasonCode, RepairRequest, RepairResult, RepairSloMetrics, RepairStats,
    TargetedRepairRequest,
};
pub use symbol_store::{
    MemorySymbolStore, MemorySymbolStoreConfig, ObjectSymbolMeta, ObjectTransmissionInfo,
    StoredSymbol, SymbolMeta, SymbolStore, validate_source_symbols,
};

pub use fcp_prelude::{ConnectorStateAppendOutcome, ConnectorStateCanonicalStatus};

pub use offline::{
    AccessPatternTracker, OfflineAccess, OfflineCapability, OfflineStatus, OfflineSummary,
};
pub use process_snapshot::{
    ProcessSnapshotError, ProcessSnapshotFormat, ProcessSnapshotManifest,
    ProcessSnapshotTrustAnchors, pin_capability_token,
};
pub use resume_handshake::{
    CapabilityAvailability, DEFAULT_RESUME_HANDSHAKE_TIMEOUT_MS, RehydrationStatus,
    ResumeHandshakeError, ResumeHandshakeMessage, ResumeHandshakeRequest,
    ResumeHandshakeTranscript, ResumeReplayOp, ResumeRollbackPlan, ResumeRollbackReason,
    ResumeSnapshotSymbol, ResumeSourceLeaseRelease, ResumeTargetAck, ResumeTargetComplete,
    SnapshotFreshness,
};
