use aster_ble_linux::{
    AsterRosterBeaconV1, CanonicalLocator, DiscoveryAdmission, DiscoveryCredential,
    DiscoveryGeneration, DiscoverySecret, LeasedDiscoveryCredentialSet, ObservationOutcome,
    ScanStartOutcome,
};
use bluer::{Address, AddressType};
use std::time::{Duration, Instant};

#[test]
fn linux_locator_flows_through_portable_admission() {
    let now = Instant::now();
    let credentials = LeasedDiscoveryCredentialSet::new(
        DiscoveryCredential::new(
            DiscoveryGeneration::new(7).unwrap(),
            DiscoverySecret::new([0x5a; 32]).unwrap(),
        ),
        None,
        now + Duration::from_secs(30),
    )
    .unwrap();
    let record = AsterRosterBeaconV1::encode(0x0081, [0x3c; 16], &credentials, now).unwrap();
    let locator =
        CanonicalLocator::new(Address::new([2, 0, 0, 0, 0, 9]), AddressType::LeRandom).unwrap();
    let transient = locator.to_transient();
    let mut admission = DiscoveryAdmission::new();

    assert_eq!(admission.start_scan(now), ScanStartOutcome::Started);
    assert_eq!(
        admission.observe(transient.clone(), &record, &credentials, now),
        ObservationOutcome::Accepted
    );
    assert_eq!(
        admission.selected_candidate(now).unwrap().locator(),
        &transient
    );
}
