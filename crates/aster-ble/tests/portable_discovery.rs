use aster_ble::{
    AsterRosterBeaconV1, DiscoveryAdmission, DiscoveryCredential, DiscoveryGeneration,
    DiscoverySecret, LeasedDiscoveryCredentialSet, ObservationOutcome, ScanStartOutcome,
};
use aster_contact::TransientLocator;
use std::time::{Duration, Instant};

#[test]
fn public_admission_api_preserves_the_platform_locator() {
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
    let locator = TransientLocator::new(vec![17]).unwrap();
    let mut admission = DiscoveryAdmission::new();

    assert_eq!(admission.start_scan(now), ScanStartOutcome::Started);
    assert_eq!(
        admission.observe(locator.clone(), &record, &credentials, now),
        ObservationOutcome::Accepted
    );
    assert_eq!(
        admission.selected_candidate(now).unwrap().locator(),
        &locator
    );
}
