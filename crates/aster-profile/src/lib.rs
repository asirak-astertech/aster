//! Requirements-owned data profile primitives for Aster replication.
//!
//! This crate owns semantic vocabulary shared by future replica, storage,
//! reconciliation, policy, and security implementations. It intentionally contains no
//! wire codec, database, transport, clock, or evaluator-specific behavior.
//! The selected-stack migration can therefore replace those mechanisms without
//! making any one mechanism the protocol specification.

#![forbid(unsafe_code)]

mod inventory;
mod item;

pub use inventory::InventorySnapshot;
pub use item::{
    CausalContext, CausalDot, CausalStamp, DataClass, ItemHeader, ItemId,
    MAX_CAUSAL_CONTEXT_ENTRIES, MAX_SCOPE_BYTES, MAX_TOPIC_BYTES, Perishability, Priority,
    ProfileError, PublisherId, ReconciliationKey, Scope, Topic,
};
