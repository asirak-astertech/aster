#![no_main]

use aster_mesh::wire::{Limits, decode_message, decode_value, encode_message, encode_value};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    let limits = Limits::default();

    if let Ok(value) = decode_value(input, limits) {
        let canonical = encode_value(&value, limits).expect("decoded value must re-encode");
        assert_eq!(canonical.as_slice(), input);
        assert_eq!(
            decode_value(&canonical, limits).expect("canonical value must decode"),
            value
        );
        assert_eq!(
            encode_value(&value, limits).expect("value must encode deterministically"),
            canonical
        );
    }

    if let Ok(message) = decode_message(input, limits) {
        let canonical = encode_message(&message, limits).expect("decoded message must re-encode");
        assert_eq!(canonical.as_slice(), input);
        assert_eq!(
            decode_message(&canonical, limits).expect("canonical message must decode"),
            message
        );
        assert_eq!(
            encode_message(&message, limits).expect("message must encode deterministically"),
            canonical
        );
    }
});
