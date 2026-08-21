//! Transport-neutral reference implementation of the Aster Mesh Protocol.
//!
//! The public surface intentionally contains only application-level concepts.
//! Cryptography, link selection, fragmentation, and reconciliation remain
//! internal implementation details or adapter contracts.

#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "adapter-sdk"), allow(dead_code, unused_imports))]

pub mod api;
pub(crate) mod bridge;
pub(crate) mod bridge_service;

#[cfg(feature = "adapter-sdk")]
// Temporary: the pure profile is exposed first to conformance; provider/store
// adapters consume the remaining construction helpers in the next integration layer.
#[allow(dead_code)]
pub mod batch;
#[cfg(not(feature = "adapter-sdk"))]
mod batch;

#[cfg(feature = "adapter-sdk")]
pub mod blob;
#[cfg(not(feature = "adapter-sdk"))]
mod blob;
#[cfg(feature = "adapter-sdk")]
pub mod causal;
#[cfg(not(feature = "adapter-sdk"))]
mod causal;
mod crypto;
#[cfg(feature = "adapter-sdk")]
pub mod engine;
#[cfg(not(feature = "adapter-sdk"))]
mod engine;
#[cfg(feature = "adapter-sdk")]
pub mod fragment;
#[cfg(not(feature = "adapter-sdk"))]
mod fragment;
#[cfg(feature = "adapter-sdk")]
pub mod inventory;
#[cfg(not(feature = "adapter-sdk"))]
mod inventory;
#[cfg(feature = "adapter-sdk")]
pub mod link;
#[cfg(not(feature = "adapter-sdk"))]
mod link;
#[cfg(feature = "adapter-sdk")]
pub mod model;
#[cfg(not(feature = "adapter-sdk"))]
mod model;
pub mod provisioning;
#[cfg(feature = "adapter-sdk")]
pub mod runtime;
#[cfg(not(feature = "adapter-sdk"))]
mod runtime;
#[cfg(feature = "adapter-sdk")]
pub mod scheduler;
#[cfg(not(feature = "adapter-sdk"))]
mod scheduler;
#[cfg(feature = "adapter-sdk")]
pub mod store;
#[cfg(not(feature = "adapter-sdk"))]
mod store;
#[cfg(feature = "adapter-sdk")]
pub mod sync;
#[cfg(not(feature = "adapter-sdk"))]
mod sync;
#[cfg(feature = "adapter-sdk")]
pub mod wire;
#[cfg(not(feature = "adapter-sdk"))]
mod wire;

#[cfg(feature = "adapter-sdk")]
pub use api::ApplicationNodeRef;
pub use api::{
    ApplicationMergePolicy, ApplicationNode, ApplicationNodeOptions, BatchPublicationPolicy,
    BatchPublishRequest, BatchPublishResult, BridgeAuthorizationId, BridgeAuthorizationPolicy,
    BridgeAuthorizationResult, BridgeAuthorizationStatus, BridgeCommitStatus, BridgeEdge,
    BridgeEnrollment, BridgeNarrowingPolicy, BridgeRouteHandle, BridgeRouteResult,
    BridgeRouteStatus, Delivery, FinishedBlobBatchItem, FinishedBlobBatchRequest, Item,
    MergeVersion, PublishResult, Query, RekeyRecipient, RekeyRecipientAccess, ScopeRekeyResult,
};
pub use blob::{
    BlobError, BlobId, BlobMetadata, BlobReadStats, BlobStoreConfig, BlobWriteProgress,
    FinishedBlob, ReferenceBlobReader, ReferenceBlobService,
};
#[cfg(feature = "adapter-sdk")]
pub use crypto::{
    ProvisioningAccess, ProvisioningBundle, ReferenceAuthenticatedSession, ReferenceEnvelopeSealer,
    ReferenceNode, ReferenceProvisioner, ReferenceSessionAwaitingFinished,
    ReferenceSessionInitiator, ReferenceSessionResponder, ReferenceSessionResponderPending,
    ScopeRekeyPlan, ScopeRekeyRecipient, open_reference_node,
};
#[cfg(feature = "adapter-sdk")]
pub use engine::{
    ApplicationItem, Delivery as EngineDelivery, PublishReceipt, RecordMergePolicy, RecordVersion,
};
pub use engine::{EmissionPolicy, EngineError, PublishRequest, ResolveRequest};
pub use model::{
    ConflictAnnotation, DataClass, ItemId, NodeId, PeerStatus, Priority, Scope, SyncStatus, Topic,
};
pub use provisioning::{
    MAX_PROTECTED_PROVISIONING_BYTES, MAX_UNPROTECTED_PROVISIONING_BYTES,
    ProtectedProvisioningError, ProvisioningProtectionError, ProvisioningProtector,
    ProvisioningUnprotector, UnprotectedProvisioning, protect_provisioning_artifact,
    unprotect_provisioning_artifact,
};
pub use store::{BridgeFilter, EventGap, PeerSnapshot, QuotaUsage, SubscriptionId};

/// Stable replication-wire, credential, and cryptographic-profile version.
pub const REPLICATION_WIRE_VERSION: u16 = 1;

/// Legacy alias for [`REPLICATION_WIRE_VERSION`].
///
/// This value does not report the semantic version selected by an authenticated
/// session. It remains available so existing callers keep their source and
/// binary expectations while migrating to the unambiguous version surfaces.
pub const PROTOCOL_VERSION: u16 = REPLICATION_WIRE_VERSION;

/// Semantic replication version offered first by a default initiator.
pub const DEFAULT_SEMANTIC_VERSION: u16 = 2;

/// Highest semantic replication version implemented by this build.
pub const HIGHEST_SUPPORTED_SEMANTIC_VERSION: u16 = 2;

const _: () = assert!(batch::DATA_CLASS_EVENT == model::DataClass::Event as u8);

#[cfg(test)]
mod version_surface_tests {
    use super::*;

    #[test]
    fn public_versions_match_the_authenticated_session_defaults() {
        assert_eq!(PROTOCOL_VERSION, REPLICATION_WIRE_VERSION);
        assert_eq!(
            crypto::SUPPORTED_SEMANTIC_PROTOCOL_VERSIONS,
            &[DEFAULT_SEMANTIC_VERSION, 1]
        );
        assert_eq!(HIGHEST_SUPPORTED_SEMANTIC_VERSION, DEFAULT_SEMANTIC_VERSION);
        assert_eq!(batch::DATA_CLASS_EVENT, DataClass::Event as u8);
    }
}
