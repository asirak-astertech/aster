#![no_main]

use aster_mesh::engine::{EnvelopeHeader, EnvelopeSealer, SealRequest};
use aster_mesh::model::{CausalStamp, DataClass, Dot, Priority, Scope, Topic, VersionVector};
use aster_mesh::{
    AuthenticatedChannelBinding, ClassicalEnvelopeSealer, ClassicalProvisioningAccess,
    ClassicalProvisioningBundle, ClassicalProvisioner, ClassicalSessionInitiator,
    ClassicalSessionResponder, ProfileProvisioningBundle,
};
use libfuzzer_sys::fuzz_target;
use std::cell::RefCell;

struct Harness {
    valid_bundle: Vec<u8>,
    valid_event: Vec<u8>,
    valid_client_flight: Vec<u8>,
    responder_bundle: Vec<u8>,
    reader: ClassicalEnvelopeSealer,
}

impl Harness {
    fn new() -> Self {
        let scope = Scope::new("fuzz/classical").expect("fixed scope");
        let topic = Topic::new("events").expect("fixed topic");
        let access = ClassicalProvisioningAccess::member(
            scope.clone(),
            vec![1],
            vec![topic.clone()],
        )
        .expect("fixed access");
        let mut provisioner =
            ClassicalProvisioner::from_seed([0x6c; 32], 7).expect("fixed provisioner");
        let publisher_bundle = provisioner
            .issue_node(1, std::slice::from_ref(&access))
            .expect("publisher");
        let valid_bundle = publisher_bundle.to_bytes().expect("bundle bytes");
        let reader_bundle = provisioner
            .issue_node(2, std::slice::from_ref(&access))
            .expect("reader");
        let responder_bundle = provisioner
            .issue_node(3, std::slice::from_ref(&access))
            .expect("responder")
            .to_bytes()
            .expect("responder bytes");
        let initiator_bundle = provisioner
            .issue_node(4, std::slice::from_ref(&access))
            .expect("initiator");

        let mut publisher =
            ClassicalEnvelopeSealer::open(publisher_bundle).expect("publisher sealer");
        let payload = b"nonsecret classical profile fuzz seed";
        let header = EnvelopeHeader {
            class: DataClass::Event,
            topic,
            scope,
            priority: Priority::Routine,
            stamp: CausalStamp {
                dot: Dot {
                    publisher: publisher.identity(),
                    counter: 1,
                },
                context: VersionVector::default(),
            },
            event_sequence: Some(1),
            logical_key: b"seed".to_vec(),
            blob_route: None,
            ttl_ms: Some(30_000),
            content_len: payload.len() as u64,
            tombstone: false,
            key_epoch: 1,
        };
        let valid_event = publisher
            .seal(SealRequest {
                header: &header,
                payload,
            })
            .expect("seed Event")
            .bytes;
        let (_, valid_client_flight) = ClassicalSessionInitiator::start(
            initiator_bundle,
            AuthenticatedChannelBinding::new(b"fixed-fuzz-channel-binding".to_vec())
                .expect("binding"),
        )
        .expect("client flight");

        Self {
            valid_bundle,
            valid_event,
            valid_client_flight,
            responder_bundle,
            reader: ClassicalEnvelopeSealer::open(reader_bundle).expect("reader sealer"),
        }
    }

    fn mutate(seed: &[u8], commands: &[u8]) -> Vec<u8> {
        let mut candidate = seed.to_vec();
        for command in commands.chunks_exact(4) {
            let index = usize::from(u16::from_be_bytes([command[1], command[2]]));
            match command[0] & 0x03 {
                0 if !candidate.is_empty() => {
                    let position = index % candidate.len();
                    candidate[position] ^= command[3];
                }
                1 if !candidate.is_empty() => {
                    let position = index % candidate.len();
                    candidate[position] = command[3];
                }
                2 => candidate.truncate(index.min(candidate.len())),
                _ => candidate.push(command[3]),
            }
        }
        candidate
    }

    fn exercise_bundle(&self, candidate: &[u8]) {
        if let Ok(bundle) = ClassicalProvisioningBundle::from_bytes(candidate) {
            assert_eq!(
                bundle.to_bytes().expect("accepted bundle re-encodes"),
                candidate,
                "accepted provisioning must already be canonical"
            );
        }
        let _ = ProfileProvisioningBundle::from_bytes(candidate);
    }

    fn exercise_event(&mut self, candidate: &[u8]) {
        if let Ok(event) = self.reader.verify_event(candidate) {
            self.reader
                .verify_event_content(event, candidate)
                .expect("a route-accepted Event must verify deterministically");
        }
    }

    fn exercise_client_flight(&self, candidate: &[u8]) {
        let bundle = ClassicalProvisioningBundle::from_bytes(&self.responder_bundle)
            .expect("fixed responder bundle");
        let responder = ClassicalSessionResponder::open(
            bundle,
            AuthenticatedChannelBinding::new(b"fixed-fuzz-channel-binding".to_vec())
                .expect("binding"),
        )
        .expect("responder");
        let _ = responder.receive_client(candidate);
    }

    fn run(&mut self, input: &[u8]) {
        let candidate = match input.first().copied() {
            Some(b'B') => Self::mutate(&self.valid_bundle, &input[1..]),
            Some(b'E') => Self::mutate(&self.valid_event, &input[1..]),
            Some(b'H') => Self::mutate(&self.valid_client_flight, &input[1..]),
            Some(b'R') => input[1..].to_vec(),
            _ => input.to_vec(),
        };
        match input.first().copied() {
            Some(b'B') => self.exercise_bundle(&candidate),
            Some(b'E') => self.exercise_event(&candidate),
            Some(b'H') => self.exercise_client_flight(&candidate),
            _ => {
                self.exercise_bundle(&candidate);
                self.exercise_event(&candidate);
                self.exercise_client_flight(&candidate);
            }
        }
    }
}

thread_local! {
    static HARNESS: RefCell<Harness> = RefCell::new(Harness::new());
}

fuzz_target!(|input: &[u8]| {
    HARNESS.with(|harness| harness.borrow_mut().run(input));
});
