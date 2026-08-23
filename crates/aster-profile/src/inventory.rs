use std::collections::BTreeSet;

use crate::{ItemId, ReconciliationKey};

/// Canonical, duplicate-free item membership used as reconciliation input.
///
/// This type owns no reconciliation protocol. Future Negentropy integration
/// must map every entry using [`InventorySnapshot::reconciliation_keys`] so a
/// replica-local ordinal or wall clock cannot alter shared-item ordering.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct InventorySnapshot(BTreeSet<ItemId>);

impl InventorySnapshot {
    /// Constructs a canonical snapshot from item identifiers.
    pub fn new(ids: impl IntoIterator<Item = ItemId>) -> Self {
        Self(ids.into_iter().collect())
    }

    /// Inserts an identifier, returning whether membership changed.
    pub fn insert(&mut self, id: ItemId) -> bool {
        self.0.insert(id)
    }

    /// Returns whether the snapshot contains an identifier.
    pub fn contains(&self, id: &ItemId) -> bool {
        self.0.contains(id)
    }

    /// Returns the number of unique identifiers.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true when the snapshot contains no identifier.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Iterates full identifiers in deterministic lexicographic order.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = &ItemId> {
        self.0.iter()
    }

    /// Iterates stable reconciliation keys in the same deterministic order.
    pub fn reconciliation_keys(&self) -> impl ExactSizeIterator<Item = ReconciliationKey> + '_ {
        self.0.iter().copied().map(ItemId::reconciliation_key)
    }
}

impl FromIterator<ItemId> for InventorySnapshot {
    fn from_iter<T: IntoIterator<Item = ItemId>>(iter: T) -> Self {
        Self::new(iter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(byte: u8) -> ItemId {
        ItemId::new([byte; 32])
    }

    #[test]
    fn inventory_uses_full_lexicographic_item_id_order() {
        let inventory = InventorySnapshot::new([item(0xff), item(0x00), item(0x80)]);
        assert_eq!(
            inventory.iter().copied().collect::<Vec<_>>(),
            vec![item(0x00), item(0x80), item(0xff)]
        );
    }

    #[test]
    fn shifted_overlap_is_invariant_to_local_insertion_order() {
        let shared = item(0x78);
        let a = InventorySnapshot::new([shared, item(0x88)]);
        let b = InventorySnapshot::new([item(0x5f), shared]);

        let shared_a = a
            .reconciliation_keys()
            .find(|key| key.as_bytes() == shared.as_bytes())
            .expect("shared A key");
        let shared_b = b
            .reconciliation_keys()
            .find(|key| key.as_bytes() == shared.as_bytes())
            .expect("shared B key");

        assert_eq!(shared_a, shared_b);
        assert_eq!(a.iter().position(|id| *id == shared), Some(0));
        assert_eq!(b.iter().position(|id| *id == shared), Some(1));
    }

    #[test]
    fn duplicate_item_id_is_idempotent() {
        let mut inventory = InventorySnapshot::new([item(1), item(1)]);
        assert_eq!(inventory.len(), 1);
        assert!(!inventory.insert(item(1)));
        assert!(inventory.insert(item(2)));
        assert_eq!(inventory.len(), 2);
    }

    #[test]
    fn every_permutation_produces_the_same_snapshot() {
        let expected = InventorySnapshot::new([item(1), item(2), item(3)]);
        for permutation in [
            [item(1), item(2), item(3)],
            [item(1), item(3), item(2)],
            [item(2), item(1), item(3)],
            [item(2), item(3), item(1)],
            [item(3), item(1), item(2)],
            [item(3), item(2), item(1)],
        ] {
            assert_eq!(InventorySnapshot::new(permutation), expected);
        }
    }
}
