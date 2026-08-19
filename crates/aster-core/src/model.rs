//! Public data model and validated identifiers.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{self, Display, Formatter};

/// Stable, opaque identifier for a node identity.
pub type NodeId = [u8; 32];

/// Content-derived identifier for an item or other immutable protocol object.
pub type ItemId = [u8; 32];

/// The four protocol data classes.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum DataClass {
    /// Small mutable latest-value data.
    State = 0,
    /// Immutable per-publisher sequence data.
    Event = 1,
    /// Mutable documents that retain concurrent siblings.
    Record = 2,
    /// Immutable content-addressed binary data.
    Blob = 3,
}

/// Fixed message precedence used by scheduling, retry, and eviction policy.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum Priority {
    /// Normal operational traffic.
    #[default]
    Routine = 0,
    /// Traffic sent ahead of routine traffic.
    Priority = 1,
    /// Time-sensitive traffic.
    Immediate = 2,
    /// Highest precedence traffic.
    Flash = 3,
}

impl Priority {
    /// Converts a wire value into a known priority.
    pub const fn from_wire(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Routine),
            1 => Some(Self::Priority),
            2 => Some(Self::Immediate),
            3 => Some(Self::Flash),
            _ => None,
        }
    }
}

/// Error returned for a non-canonical topic or scope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NameError(&'static str);

impl Display for NameError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl Error for NameError {}

fn validate_name(value: &str, hierarchical: bool) -> Result<(), NameError> {
    if value.is_empty() || value.len() > 128 {
        return Err(NameError("name length must be between 1 and 128 bytes"));
    }
    if !value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric()
            || matches!(byte, b'.' | b'_' | b'-')
            || (hierarchical && byte == b'/')
    }) {
        return Err(NameError("name contains a non-canonical character"));
    }
    if hierarchical
        && (value.starts_with('/')
            || value.ends_with('/')
            || value
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == ".."))
    {
        return Err(NameError(
            "scope must contain canonical non-empty path segments",
        ));
    }
    Ok(())
}

/// A canonical content channel name.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Topic(String);

impl Topic {
    /// Creates a validated topic.
    pub fn new(value: impl Into<String>) -> Result<Self, NameError> {
        let value = value.into();
        validate_name(&value, false)?;
        Ok(Self(value))
    }

    /// Returns the canonical wire name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A canonical hierarchical administrative propagation domain.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Scope(String);

impl Scope {
    /// Creates a validated scope path.
    pub fn new(value: impl Into<String>) -> Result<Self, NameError> {
        let value = value.into();
        validate_name(&value, true)?;
        Ok(Self(value))
    }

    /// Returns the canonical wire name.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns whether `self` is the same scope as, or an ancestor of, `other`.
    pub fn contains(&self, other: &Self) -> bool {
        other.0 == self.0
            || other
                .0
                .strip_prefix(&self.0)
                .is_some_and(|suffix| suffix.starts_with('/'))
    }
}

/// A publisher's unique logical event.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Dot {
    /// Publisher whose monotonic counter created this dot.
    pub publisher: NodeId,
    /// Nonzero per-publisher monotonic counter.
    pub counter: u64,
}

/// Compact causal context represented by the largest observed counter per node.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct VersionVector(BTreeMap<NodeId, u64>);

/// Maximum number of publisher entries carried by an authenticated causal context.
pub const MAX_CAUSAL_CONTEXT_ENTRIES: usize = 4_096;

impl VersionVector {
    /// Returns the observed counter for a publisher, or zero.
    pub fn counter(&self, publisher: &NodeId) -> u64 {
        self.0.get(publisher).copied().unwrap_or(0)
    }

    /// Returns whether this context includes `dot`.
    pub fn observes(&self, dot: Dot) -> bool {
        self.counter(&dot.publisher) >= dot.counter
    }

    /// Advances this context to include `dot`.
    pub fn observe(&mut self, dot: Dot) {
        self.0
            .entry(dot.publisher)
            .and_modify(|counter| *counter = (*counter).max(dot.counter))
            .or_insert(dot.counter);
    }

    /// Joins another context into this context.
    pub fn join(&mut self, other: &Self) {
        for (&publisher, &counter) in &other.0 {
            self.observe(Dot { publisher, counter });
        }
    }

    /// Returns the number of distinct publishers in this context.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether this context contains no publisher observations.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Iterates in canonical node identifier order.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = (&NodeId, &u64)> {
        self.0.iter()
    }
}

/// Causal stamp for a published version.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CausalStamp {
    /// Unique publisher event for this version.
    pub dot: Dot,
    /// Events observed before the version was produced.
    pub context: VersionVector,
}

impl CausalStamp {
    /// Returns the full context including this version's dot.
    pub fn clock(&self) -> VersionVector {
        let mut clock = self.context.clone();
        clock.observe(self.dot);
        clock
    }
}

/// A conflict visible to an application.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConflictAnnotation {
    /// Stable logical key with multiple versions.
    pub logical_key: Vec<u8>,
    /// All retained concurrent item identifiers in canonical order.
    pub siblings: Vec<ItemId>,
    /// Identifier of an applied deterministic merge policy, if any.
    pub merge_policy: Option<String>,
}

/// Coarse peer lifecycle surfaced to applications.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerStatus {
    /// Known through provisioning but not currently reachable.
    Offline,
    /// Discovered but not yet mutually authenticated.
    Authenticating,
    /// Authenticated and eligible for synchronization.
    Ready,
    /// Rejected because identity or policy validation failed.
    Rejected,
    /// Excluded by a verified revocation.
    Revoked,
}

/// Coarse synchronization lifecycle surfaced to applications.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncStatus {
    /// No active reconciliation.
    Idle,
    /// Comparing authenticated inventories.
    Reconciling,
    /// Transferring missing immutable objects.
    Transferring,
    /// Both peers committed the same inventory root for the negotiated filter.
    Converged,
    /// Work is paused and can be resumed with any eligible peer.
    Suspended,
}

#[cfg(test)]
mod tests {
    use super::{Scope, Topic};

    #[test]
    fn names_are_canonical() {
        assert!(Topic::new("position.current").is_ok());
        assert!(Topic::new("not/a/topic").is_err());
        assert!(Scope::new("mission/team/alpha").is_ok());
        assert!(Scope::new("mission//alpha").is_err());
    }

    #[test]
    fn scope_containment_uses_segment_boundaries() {
        let team = Scope::new("mission/team").unwrap();
        assert!(team.contains(&Scope::new("mission/team/alpha").unwrap()));
        assert!(!team.contains(&Scope::new("mission/teams").unwrap()));
    }
}
