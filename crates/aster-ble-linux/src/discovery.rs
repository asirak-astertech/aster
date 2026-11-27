use aster_contact::TransientLocator;
use bluer::{Address, AddressType};
use std::fmt;

pub use aster_ble::{
    AttemptKind, InboundAdmission, ObservationOutcome, ObservationRejection, ScanSchedule,
    ScanStartOutcome, ScanState, ScanStopReason, ScanWindowCounters,
};

/// Exact transient Linux Bluetooth address and LE address type.
#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub struct CanonicalLocator {
    address: Address,
    address_type: AddressType,
}

impl CanonicalLocator {
    /// Constructs a locator without aliasing or address-type coercion.
    pub fn new(address: Address, address_type: AddressType) -> Result<Self, CanonicalLocatorError> {
        if !matches!(address_type, AddressType::LePublic | AddressType::LeRandom) {
            return Err(CanonicalLocatorError::NonLeAddress);
        }
        Ok(Self {
            address,
            address_type,
        })
    }

    /// Exact transient Bluetooth address bytes.
    pub const fn address(self) -> Address {
        self.address
    }

    /// Exact observed LE address type.
    pub const fn address_type(self) -> AddressType {
        self.address_type
    }

    /// Encodes the exact Linux address and LE address type as bounded carrier evidence.
    pub fn to_transient(self) -> TransientLocator {
        let address_type = match self.address_type {
            AddressType::LePublic => 0,
            AddressType::LeRandom => 1,
            _ => unreachable!("canonical locators contain only LE address types"),
        };
        let mut encoded = Vec::with_capacity(7);
        encoded.extend_from_slice(&self.address.0);
        encoded.push(address_type);
        TransientLocator::new(encoded).expect("canonical Linux locator has fixed bounded length")
    }

    /// Decodes one exact Linux BTLE locator from bounded carrier evidence.
    pub fn from_transient(locator: &TransientLocator) -> Result<Self, CanonicalLocatorError> {
        let [address @ .., address_type] = locator.as_bytes() else {
            return Err(CanonicalLocatorError::InvalidEncoding);
        };
        let address: [u8; 6] = address
            .try_into()
            .map_err(|_| CanonicalLocatorError::InvalidEncoding)?;
        let address_type = match address_type {
            0 => AddressType::LePublic,
            1 => AddressType::LeRandom,
            _ => return Err(CanonicalLocatorError::InvalidEncoding),
        };
        Self::new(Address::new(address), address_type)
    }
}

impl fmt::Debug for CanonicalLocator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CanonicalLocator([REDACTED])")
    }
}

/// Canonical-locator construction failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CanonicalLocatorError {
    /// BR/EDR addresses cannot identify an LE discovery observation.
    NonLeAddress,
    /// Bounded carrier evidence was not the canonical seven-byte Linux encoding.
    InvalidEncoding,
}

/// Portable admission policy fed by canonical Linux BlueZ locators.
pub type DiscoveryAdmission = aster_ble::DiscoveryAdmission;
/// Portable authenticated candidate carrying bounded transient evidence.
pub type DiscoveryCandidate = aster_ble::DiscoveryCandidate;

#[cfg(test)]
mod tests {
    use super::{CanonicalLocator, CanonicalLocatorError};
    use bluer::{Address, AddressType};

    #[test]
    fn canonical_locator_accepts_exact_le_types_and_rejects_bredr() {
        let address = Address::new([2, 0, 0, 0, 0, 9]);
        assert!(CanonicalLocator::new(address, AddressType::LePublic).is_ok());
        assert!(CanonicalLocator::new(address, AddressType::LeRandom).is_ok());
        assert_eq!(
            CanonicalLocator::new(address, AddressType::BrEdr),
            Err(CanonicalLocatorError::NonLeAddress)
        );
    }

    #[test]
    fn canonical_locator_round_trips_through_bounded_transient_locator() {
        let address = Address::new([2, 0, 0, 0, 0, 9]);
        let public = CanonicalLocator::new(address, AddressType::LePublic).unwrap();
        let random = CanonicalLocator::new(address, AddressType::LeRandom).unwrap();

        assert_eq!(
            CanonicalLocator::from_transient(&public.to_transient()),
            Ok(public)
        );
        assert_eq!(
            CanonicalLocator::from_transient(&random.to_transient()),
            Ok(random)
        );
        assert_ne!(public.to_transient(), random.to_transient());
        assert_eq!(
            public.cmp(&random),
            public
                .to_transient()
                .as_bytes()
                .cmp(random.to_transient().as_bytes())
        );

        let higher_address =
            CanonicalLocator::new(Address::new([3, 0, 0, 0, 0, 0]), AddressType::LePublic).unwrap();
        assert_eq!(
            random.cmp(&higher_address),
            random
                .to_transient()
                .as_bytes()
                .cmp(higher_address.to_transient().as_bytes())
        );
    }
}
