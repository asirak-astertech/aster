#![no_main]

use aster_negentropy::{
    Initiator, InitiatorStep, MIN_FRAME_SIZE_LIMIT, ReconciliationError, ReconciliationLimits,
    Responder,
};
use aster_profile::{InventorySnapshot, ItemId};
use libfuzzer_sys::fuzz_target;

const FUZZ_ROUNDS: u32 = 8;
const FUZZ_CARDINALITY: usize = 32;

fn inventory(bytes: &[u8], parity: usize) -> InventorySnapshot {
    InventorySnapshot::new(
        bytes
            .chunks_exact(32)
            .take(FUZZ_CARDINALITY * 2)
            .enumerate()
            .filter(|(index, _)| index % 2 == parity)
            .map(|(_, chunk)| {
                let mut id = [0u8; 32];
                id.copy_from_slice(chunk);
                ItemId::new(id)
            }),
    )
}

fn exercise_valid_exchange(input: &[u8], limits: ReconciliationLimits) {
    let local = inventory(input, 0);
    let remote = inventory(input, 1);
    let mut initiator = Initiator::new(&local, limits).expect("bounded local inventory");
    let mut responder = Responder::new(&remote, limits).expect("bounded remote inventory");
    let mut query = initiator.initiate().expect("valid initial frame");

    loop {
        let response = responder
            .reconcile_query(&query)
            .expect("valid query must produce a bounded response");
        match initiator
            .reconcile_response(&response)
            .expect("valid response must advance the exchange")
        {
            InitiatorStep::Continue(next) => query = next,
            InitiatorStep::Complete(difference) => {
                assert!(difference.local_only.len() <= FUZZ_CARDINALITY);
                assert!(difference.remote_only.len() <= FUZZ_CARDINALITY);
                assert_eq!(initiator.rounds(), responder.rounds());
                assert!(initiator.rounds() <= FUZZ_ROUNDS);
                break;
            }
        }
    }
}

fn exercise_hostile_frame(input: &[u8], limits: ReconciliationLimits) {
    let empty = InventorySnapshot::default();
    let mut responder = Responder::new(&empty, limits).expect("empty responder");
    let _disposition = responder.reconcile_query(input);
    assert!(responder.rounds() <= 1);
    if input.len() > limits.frame_size() {
        assert_eq!(responder.rounds(), 0);
    }

    let mut initiator = Initiator::new(&empty, limits).expect("empty initiator");
    assert!(matches!(
        initiator.reconcile_response(input),
        Err(ReconciliationError::NotInitiated)
    ));
    assert_eq!(initiator.rounds(), 0);
    let _initial = initiator.initiate().expect("initiate empty inventory");
    let _disposition = initiator.reconcile_response(input);
    assert!(initiator.rounds() <= 1);
    if input.len() > limits.frame_size() {
        assert_eq!(initiator.rounds(), 0);
    }
}

fuzz_target!(|input: &[u8]| {
    let limits = ReconciliationLimits::new(MIN_FRAME_SIZE_LIMIT, FUZZ_ROUNDS, FUZZ_CARDINALITY)
        .expect("fixed fuzz limits");
    exercise_valid_exchange(input, limits);
    exercise_hostile_frame(input, limits);
});
