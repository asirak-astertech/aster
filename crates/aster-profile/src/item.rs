use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::time::Duration;

/// Maximum UTF-8 byte length accepted by the initial implementation for a topic.
///
/// This is an implementation work bound, not a protocol or stakeholder limit.
pub const MAX_TOPIC_BYTES: usize = 128;

/// Maximum UTF-8 byte length accepted by the initial implementation for a scope.
///
/// This is an implementation work bound, not a protocol or stakeholder limit.
pub const MAX_SCOPE_BYTES: usize = 128;

/// Maximum number of publisher entries accepted by one causal context.
///
/// This is an implementation work bound, not a fleet-size requirement.
pub const MAX_CAUSAL_CONTEXT_ENTRIES: usize = 4_096;

/// A stable, opaque item identifier.
///
/// The profile does not choose the identifier derivation algorithm. Producers
/// and decoders must validate that separately when the normative wire profile
/// is introduced.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ItemId([u8; 32]);

impl ItemId {
    /// Constructs an item identifier from its complete stable bytes.
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the complete stable identifier bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns the reconciliation ordering key for this item.
    ///
    /// Ordering is derived solely from the full identifier. It never depends
    /// on replica-local insertion order or wall-clock time.
    pub const fn reconciliation_key(self) -> ReconciliationKey {
        ReconciliationKey(self.0)
    }
}

impl From<[u8; 32]> for ItemId {
    fn from(value: [u8; 32]) -> Self {
        Self::new(value)
    }
}

/// A stable, opaque publisher identifier claim.
///
/// Authentication and binding to an item belong to the future normative
/// profile and security implementation; construction here grants no identity
/// assurance.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PublisherId([u8; 32]);

impl PublisherId {
    /// Constructs a publisher identifier from its complete stable bytes.
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the complete stable identifier bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for PublisherId {
    fn from(value: [u8; 32]) -> Self {
        Self::new(value)
    }
}

/// Stable cross-replica ordering material for set reconciliation.
///
/// The full item identifier is the ordering key. No timestamp, insertion
/// ordinal, or process-local state participates in ordering.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ReconciliationKey([u8; 32]);

impl ReconciliationKey {
    /// Returns the complete ordering bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<ItemId> for ReconciliationKey {
    fn from(value: ItemId) -> Self {
        value.reconciliation_key()
    }
}

/// Requirements-defined item behavior class.
///
/// The representation is opaque so these source-level values cannot be cast
/// into accidental wire discriminants before a normative registry exists.
///
/// ```compile_fail
/// use aster_profile::DataClass;
///
/// let _wire_value = DataClass::State as u8;
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DataClass(DataClassValue);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
enum DataClassValue {
    State,
    Event,
    Record,
    Blob,
}

#[allow(non_upper_case_globals)]
impl DataClass {
    /// Causally selected latest-value state.
    pub const State: Self = Self(DataClassValue::State);
    /// Immutable per-publisher ordered event.
    pub const Event: Self = Self(DataClassValue::Event);
    /// Structured record with registered merge or explicit siblings.
    pub const Record: Self = Self(DataClassValue::Record);
    /// Immutable content-addressed large object.
    pub const Blob: Self = Self(DataClassValue::Blob);
}

/// A provisional four-level publisher-assigned priority vocabulary.
///
/// Names follow the initial implementation profile. Stakeholder validation may
/// revise the vocabulary before a normative wire registry is frozen.
///
/// ```compile_fail
/// use aster_profile::Priority;
///
/// let _wire_value = Priority::Routine as u8;
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Priority(PriorityValue);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
enum PriorityValue {
    Routine,
    Priority,
    Immediate,
    Flash,
}

#[allow(non_upper_case_globals)]
impl Priority {
    /// Normal traffic.
    pub const Routine: Self = Self(PriorityValue::Routine);
    /// Elevated traffic.
    pub const Priority: Self = Self(PriorityValue::Priority);
    /// Urgent traffic.
    pub const Immediate: Self = Self(PriorityValue::Immediate);
    /// Highest-precedence traffic.
    pub const Flash: Self = Self(PriorityValue::Flash);
}

/// Declared item perishability without a wire-unit choice.
///
/// Expiration evaluation belongs to policy and must not become a conflict or
/// reconciliation ordering clock.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Perishability {
    /// The item has no declared expiry.
    Durable,
    /// The item expires after the declared duration.
    ExpiresAfter(Duration),
}

/// A validated topic name.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Topic(String);

impl Topic {
    /// Validates and constructs a topic.
    pub fn new(value: impl Into<String>) -> Result<Self, ProfileError> {
        validate_name(value.into(), NameKind::Topic).map(Self)
    }

    /// Returns the exact validated topic text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Topic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A validated administrative propagation scope.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Scope(String);

impl Scope {
    /// Validates and constructs a scope.
    pub fn new(value: impl Into<String>) -> Result<Self, ProfileError> {
        validate_name(value.into(), NameKind::Scope).map(Self)
    }

    /// Returns the exact validated scope text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Scope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One publisher's unique causal event.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CausalDot {
    publisher: PublisherId,
    counter: u64,
}

impl CausalDot {
    /// Constructs a dot with a nonzero per-publisher monotonic counter.
    pub const fn new(publisher: PublisherId, counter: u64) -> Result<Self, ProfileError> {
        if counter == 0 {
            return Err(ProfileError::ZeroCausalCounter);
        }
        Ok(Self { publisher, counter })
    }

    /// Returns the publisher that issued this event.
    pub const fn publisher(self) -> PublisherId {
        self.publisher
    }

    /// Returns the nonzero per-publisher counter.
    pub const fn counter(self) -> u64 {
        self.counter
    }
}

/// Canonically ordered causal observations by publisher.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CausalContext(BTreeMap<PublisherId, u64>);

impl CausalContext {
    /// Validates and constructs a bounded causal context.
    pub fn new(
        entries: impl IntoIterator<Item = (PublisherId, u64)>,
    ) -> Result<Self, ProfileError> {
        let mut context = BTreeMap::new();
        for (publisher, counter) in entries {
            if counter == 0 {
                return Err(ProfileError::ZeroCausalCounter);
            }
            if context.insert(publisher, counter).is_some() {
                return Err(ProfileError::DuplicateCausalPublisher(publisher));
            }
            if context.len() > MAX_CAUSAL_CONTEXT_ENTRIES {
                return Err(ProfileError::TooManyCausalEntries {
                    actual: context.len(),
                    maximum: MAX_CAUSAL_CONTEXT_ENTRIES,
                });
            }
        }
        Ok(Self(context))
    }

    /// Returns the observed counter for a publisher, or zero when absent.
    pub fn counter(&self, publisher: PublisherId) -> u64 {
        self.0.get(&publisher).copied().unwrap_or(0)
    }

    /// Returns whether this context observes a dot.
    pub fn observes(&self, dot: CausalDot) -> bool {
        self.counter(dot.publisher()) >= dot.counter()
    }

    /// Returns the number of publisher entries.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true when no causal observation is present.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Iterates entries in complete publisher-identifier order.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = (&PublisherId, &u64)> {
        self.0.iter()
    }
}

/// Causality assigned to one published version.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CausalStamp {
    dot: CausalDot,
    context: CausalContext,
}

impl CausalStamp {
    /// Constructs a stamp whose context precedes its own dot.
    pub fn new(dot: CausalDot, context: CausalContext) -> Result<Self, ProfileError> {
        if context.observes(dot) {
            return Err(ProfileError::CausalDotAlreadyObserved);
        }
        Ok(Self { dot, context })
    }

    /// Returns this version's unique publisher event.
    pub const fn dot(&self) -> CausalDot {
        self.dot
    }

    /// Returns the causal events observed before this version.
    pub const fn context(&self) -> &CausalContext {
        &self.context
    }
}

/// Requirements-owned metadata common to every published item.
///
/// This header deliberately has no wall-clock timestamp and no wire encoding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ItemHeader {
    class: DataClass,
    topic: Topic,
    scope: Scope,
    priority: Priority,
    perishability: Perishability,
    publisher: PublisherId,
    causality: CausalStamp,
}

impl ItemHeader {
    /// Constructs a structurally validated item header.
    ///
    /// The future normative encoding and source verifier bind this metadata to
    /// an [`ItemId`]. Keeping that identity separate here prevents unverified
    /// metadata from being presented as a content or signature commitment.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        class: DataClass,
        topic: Topic,
        scope: Scope,
        priority: Priority,
        perishability: Perishability,
        publisher: PublisherId,
        causality: CausalStamp,
    ) -> Result<Self, ProfileError> {
        if publisher != causality.dot().publisher() {
            return Err(ProfileError::CausalPublisherMismatch);
        }
        Ok(Self {
            class,
            topic,
            scope,
            priority,
            perishability,
            publisher,
            causality,
        })
    }

    /// Returns the item behavior class.
    pub const fn class(&self) -> DataClass {
        self.class
    }

    /// Returns the topic.
    pub const fn topic(&self) -> &Topic {
        &self.topic
    }

    /// Returns the propagation scope.
    pub const fn scope(&self) -> &Scope {
        &self.scope
    }

    /// Returns the publisher-assigned priority.
    pub const fn priority(&self) -> Priority {
        self.priority
    }

    /// Returns the declared item perishability.
    pub const fn perishability(&self) -> Perishability {
        self.perishability
    }

    /// Returns the publisher identifier claim.
    pub const fn publisher(&self) -> PublisherId {
        self.publisher
    }

    /// Returns the item's clock-independent causal stamp.
    pub const fn causality(&self) -> &CausalStamp {
        &self.causality
    }
}

/// Validation failure for requirements-owned profile primitives.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ProfileError {
    /// A topic or scope is empty.
    EmptyName(&'static str),
    /// A topic or scope exceeds its implementation work bound.
    NameTooLong {
        /// Field name.
        field: &'static str,
        /// Actual UTF-8 byte length.
        actual: usize,
        /// Maximum admitted UTF-8 byte length.
        maximum: usize,
    },
    /// A topic or scope contains a character or path form outside the admitted syntax.
    NonCanonicalName(&'static str),
    /// A causal counter was zero.
    ZeroCausalCounter,
    /// The same publisher occurred twice in one causal context.
    DuplicateCausalPublisher(PublisherId),
    /// The causal context exceeds the implementation work bound.
    TooManyCausalEntries {
        /// Actual entry count at rejection.
        actual: usize,
        /// Maximum admitted entry count.
        maximum: usize,
    },
    /// A version's causal context already observes its own dot.
    CausalDotAlreadyObserved,
    /// The header publisher and causal-dot publisher differ.
    CausalPublisherMismatch,
}

impl fmt::Display for ProfileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyName(field) => write!(formatter, "{field} must not be empty"),
            Self::NameTooLong {
                field,
                actual,
                maximum,
            } => write!(
                formatter,
                "{field} is {actual} bytes; maximum is {maximum} bytes"
            ),
            Self::NonCanonicalName(field) => write!(
                formatter,
                "{field} contains a noncanonical character or path form"
            ),
            Self::ZeroCausalCounter => formatter.write_str("causal counter must be nonzero"),
            Self::DuplicateCausalPublisher(_) => formatter.write_str("duplicate causal publisher"),
            Self::TooManyCausalEntries { actual, maximum } => write!(
                formatter,
                "causal context count {actual} exceeds maximum {maximum}"
            ),
            Self::CausalDotAlreadyObserved => {
                formatter.write_str("causal context already observes its own dot")
            }
            Self::CausalPublisherMismatch => {
                formatter.write_str("header publisher differs from causal-dot publisher")
            }
        }
    }
}

impl Error for ProfileError {}

#[derive(Clone, Copy)]
enum NameKind {
    Topic,
    Scope,
}

impl NameKind {
    const fn label(self) -> &'static str {
        match self {
            Self::Topic => "topic",
            Self::Scope => "scope",
        }
    }

    const fn maximum(self) -> usize {
        match self {
            Self::Topic => MAX_TOPIC_BYTES,
            Self::Scope => MAX_SCOPE_BYTES,
        }
    }
}

fn validate_name(value: String, kind: NameKind) -> Result<String, ProfileError> {
    let field = kind.label();
    if value.is_empty() {
        return Err(ProfileError::EmptyName(field));
    }
    if value.len() > kind.maximum() {
        return Err(ProfileError::NameTooLong {
            field,
            actual: value.len(),
            maximum: kind.maximum(),
        });
    }
    let hierarchical = matches!(kind, NameKind::Scope);
    if !value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric()
            || matches!(byte, b'.' | b'_' | b'-')
            || (hierarchical && byte == b'/')
    }) || (hierarchical
        && (value.starts_with('/')
            || value.ends_with('/')
            || value
                .split('/')
                .any(|segment| segment.is_empty() || segment == "." || segment == "..")))
    {
        return Err(ProfileError::NonCanonicalName(field));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    fn item(byte: u8) -> ItemId {
        ItemId::new([byte; 32])
    }

    #[test]
    fn current_data_classes_and_priorities_are_distinct_and_extensible() {
        let classes = [
            DataClass::State,
            DataClass::Event,
            DataClass::Record,
            DataClass::Blob,
        ];
        let priorities = [
            Priority::Routine,
            Priority::Priority,
            Priority::Immediate,
            Priority::Flash,
        ];

        assert_eq!(classes.into_iter().collect::<BTreeSet<_>>().len(), 4);
        assert_eq!(priorities.into_iter().collect::<BTreeSet<_>>().len(), 4);
    }

    #[test]
    fn topic_and_scope_enforce_canonical_bounds_without_hidden_normalization() {
        let topic = Topic::new("mission.position").expect("valid topic");
        let scope = Scope::new("unit/alpha").expect("valid scope");
        assert_eq!(topic.as_str(), "mission.position");
        assert_eq!(scope.as_str(), "unit/alpha");

        assert!(Topic::new("x".repeat(MAX_TOPIC_BYTES - 1)).is_ok());
        assert!(Topic::new("x".repeat(MAX_TOPIC_BYTES)).is_ok());
        assert_eq!(Topic::new(""), Err(ProfileError::EmptyName("topic")));
        assert_eq!(
            Scope::new(" alpha"),
            Err(ProfileError::NonCanonicalName("scope"))
        );
        assert_eq!(
            Topic::new("alpha\n"),
            Err(ProfileError::NonCanonicalName("topic"))
        );
        assert_eq!(
            Topic::new("mission/chat"),
            Err(ProfileError::NonCanonicalName("topic"))
        );
        for invalid_scope in ["/alpha", "alpha/", "alpha//bravo", "alpha/../bravo"] {
            assert_eq!(
                Scope::new(invalid_scope),
                Err(ProfileError::NonCanonicalName("scope"))
            );
        }
        assert_eq!(
            Topic::new("x".repeat(MAX_TOPIC_BYTES + 1)),
            Err(ProfileError::NameTooLong {
                field: "topic",
                actual: MAX_TOPIC_BYTES + 1,
                maximum: MAX_TOPIC_BYTES,
            })
        );
    }

    #[test]
    fn causal_context_is_nonzero_unique_bounded_and_canonical() {
        let publisher = |byte| PublisherId::new([byte; 32]);
        let context =
            CausalContext::new([(publisher(3), 4), (publisher(1), 2)]).expect("valid context");
        assert_eq!(
            context.iter().collect::<Vec<_>>(),
            vec![(&publisher(1), &2), (&publisher(3), &4)]
        );
        assert_eq!(
            CausalContext::new([(publisher(1), 1), (publisher(1), 2)]),
            Err(ProfileError::DuplicateCausalPublisher(publisher(1)))
        );
        assert_eq!(
            CausalDot::new(publisher(1), 0),
            Err(ProfileError::ZeroCausalCounter)
        );
        let too_many = (0..=MAX_CAUSAL_CONTEXT_ENTRIES).map(|index| {
            let mut bytes = [0u8; 32];
            bytes[..8].copy_from_slice(&(index as u64).to_be_bytes());
            (PublisherId::new(bytes), 1)
        });
        assert_eq!(
            CausalContext::new(too_many),
            Err(ProfileError::TooManyCausalEntries {
                actual: MAX_CAUSAL_CONTEXT_ENTRIES + 1,
                maximum: MAX_CAUSAL_CONTEXT_ENTRIES,
            })
        );
    }

    #[test]
    fn causal_stamp_rejects_a_dot_already_in_its_context() {
        let publisher = PublisherId::new([0x33; 32]);
        let dot = CausalDot::new(publisher, 2).expect("dot");
        let context = CausalContext::new([(publisher, 2)]).expect("context");
        assert_eq!(
            CausalStamp::new(dot, context),
            Err(ProfileError::CausalDotAlreadyObserved)
        );
    }

    #[test]
    fn reconciliation_order_is_full_id_only_and_permutation_invariant() {
        let left = [item(9), item(1), item(5)];
        let right = [item(5), item(9), item(1)];
        let ordered = |ids: [ItemId; 3]| {
            ids.into_iter()
                .map(ItemId::reconciliation_key)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>()
        };
        assert_eq!(ordered(left), ordered(right));
        assert_eq!(
            ordered(left),
            vec![item(1).into(), item(5).into(), item(9).into()]
        );
    }

    #[test]
    fn shifted_overlap_uses_the_same_key_on_both_replicas() {
        let shared = item(0x80);
        let replica_a = [item(0x10), shared];
        let replica_b = [item(0x01), item(0x20), shared];

        let key_a = replica_a
            .into_iter()
            .find(|id| *id == shared)
            .expect("shared in A")
            .reconciliation_key();
        let key_b = replica_b
            .into_iter()
            .find(|id| *id == shared)
            .expect("shared in B")
            .reconciliation_key();

        assert_eq!(key_a, key_b);
        assert_eq!(key_a.as_bytes(), shared.as_bytes());
    }

    #[test]
    fn header_contains_every_required_common_field_without_a_clock() {
        let header = ItemHeader::new(
            DataClass::Event,
            Topic::new("mission.chat").expect("topic"),
            Scope::new("unit/alpha").expect("scope"),
            Priority::Immediate,
            Perishability::ExpiresAfter(Duration::from_secs(3_600)),
            PublisherId::new([0x55; 32]),
            CausalStamp::new(
                CausalDot::new(PublisherId::new([0x55; 32]), 7).expect("dot"),
                CausalContext::new([(PublisherId::new([0x55; 32]), 6)]).expect("context"),
            )
            .expect("causality"),
        )
        .expect("header");

        assert_eq!(header.class(), DataClass::Event);
        assert_eq!(header.topic().as_str(), "mission.chat");
        assert_eq!(header.scope().as_str(), "unit/alpha");
        assert_eq!(header.priority(), Priority::Immediate);
        assert_eq!(
            header.perishability(),
            Perishability::ExpiresAfter(Duration::from_secs(3_600))
        );
        assert_eq!(header.publisher(), PublisherId::new([0x55; 32]));
        assert_eq!(header.causality().dot().counter(), 7);
        assert_eq!(
            header
                .causality()
                .context()
                .counter(PublisherId::new([0x55; 32])),
            6
        );
    }

    #[test]
    fn header_rejects_a_publisher_that_differs_from_its_causal_dot() {
        let result = ItemHeader::new(
            DataClass::State,
            Topic::new("position").expect("topic"),
            Scope::new("unit/alpha").expect("scope"),
            Priority::Routine,
            Perishability::Durable,
            PublisherId::new([0x77; 32]),
            CausalStamp::new(
                CausalDot::new(PublisherId::new([0x88; 32]), 1).expect("dot"),
                CausalContext::default(),
            )
            .expect("causality"),
        );

        assert_eq!(result, Err(ProfileError::CausalPublisherMismatch));
    }
}
