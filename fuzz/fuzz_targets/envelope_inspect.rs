#![no_main]

use aster_mesh::engine::{EnvelopeHeader, EnvelopeSealer, SealRequest};
use aster_mesh::model::{
    CausalStamp, DataClass, Dot, MAX_CAUSAL_CONTEXT_ENTRIES, Priority, Scope, Topic, VersionVector,
};
use aster_mesh::{ProvisioningAccess, ReferenceEnvelopeSealer, ReferenceProvisioner};
use libfuzzer_sys::fuzz_target;
use std::cell::RefCell;

struct Harness {
    sealer: ReferenceEnvelopeSealer,
    valid_envelope: Vec<u8>,
}

impl Harness {
    fn new() -> Self {
        // This fixed seed is test-only, nonsecret provisioning material. It is
        // never used by a shipped node or persisted in the retained corpus.
        let mut provisioner = ReferenceProvisioner::from_seed([0x5a; 32])
            .expect("fixed fuzz provisioning seed must be accepted");
        let scope = Scope::new("fuzz/scope").expect("fixed fuzz scope must be valid");
        let topic = Topic::new("fuzz.topic").expect("fixed fuzz topic must be valid");
        let access = ProvisioningAccess::member(scope.clone(), vec![1], vec![topic.clone()])
            .expect("fixed fuzz access must be valid");
        let bundle = provisioner
            .issue_node(1, &[access])
            .expect("fixed fuzz bundle issuance must succeed");
        let mut sealer =
            ReferenceEnvelopeSealer::open(bundle).expect("fixed fuzz bundle must open");
        let identity = sealer.identity();
        let payload = b"nonsecret envelope-inspection fuzz seed";
        let mut maximal_context = VersionVector::default();
        for index in 0..MAX_CAUSAL_CONTEXT_ENTRIES {
            let mut predecessor = [0u8; 32];
            predecessor[..8].copy_from_slice(&(index as u64 + 1).to_be_bytes());
            if predecessor == identity {
                predecessor[31] = 1;
            }
            maximal_context.observe(Dot {
                publisher: predecessor,
                counter: 1,
            });
        }
        assert_eq!(maximal_context.len(), MAX_CAUSAL_CONTEXT_ENTRIES);
        let header = EnvelopeHeader {
            class: DataClass::State,
            topic,
            scope,
            priority: Priority::Immediate,
            stamp: CausalStamp {
                dot: Dot {
                    publisher: identity,
                    counter: 1,
                },
                context: maximal_context,
            },
            event_sequence: None,
            logical_key: b"fuzz-seed".to_vec(),
            blob_route: None,
            ttl_ms: Some(30_000),
            content_len: payload.len() as u64,
            tombstone: false,
            key_epoch: 1,
        };
        let valid_envelope = sealer
            .seal(SealRequest {
                header: &header,
                payload,
            })
            .expect("fixed fuzz envelope sealing must succeed")
            .bytes;
        Self {
            sealer,
            valid_envelope,
        }
    }

    fn candidate(&self, input: &[u8]) -> Vec<u8> {
        if input.first() != Some(&b'M') {
            return input.to_vec();
        }

        // `M` selects structured mutation of a valid envelope. Each complete
        // four-byte command mutates, truncates, or extends the candidate. A
        // retained corpus containing only `M` therefore reaches the full valid
        // inspection path at the maximal causal-context bound, while
        // libFuzzer mutations explore nearby failures.
        let mut candidate = self.valid_envelope.clone();
        for command in input[1..].chunks_exact(4) {
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

    fn inspect(&mut self, input: &[u8]) {
        let candidate = self.candidate(input);
        if let Ok(verified) = self.sealer.inspect(&candidate) {
            assert_eq!(
                self.sealer
                    .inspect(&candidate)
                    .expect("accepted envelope inspection must be deterministic"),
                verified
            );
            let first_open = self.sealer.open_payload(&verified, &candidate);
            let second_open = self.sealer.open_payload(&verified, &candidate);
            assert_eq!(
                first_open, second_open,
                "payload authentication must be deterministic"
            );
            if let Ok(payload) = first_open {
                assert_eq!(payload.len() as u64, verified.header.content_len);
            }
        }
    }
}

thread_local! {
    static HARNESS: RefCell<Harness> = RefCell::new(Harness::new());
}

fuzz_target!(|input: &[u8]| {
    HARNESS.with(|harness| harness.borrow_mut().inspect(input));
});
