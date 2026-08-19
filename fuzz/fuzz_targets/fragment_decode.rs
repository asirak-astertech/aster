#![no_main]

use aster_mesh::fragment::Fragment;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    if let Ok(fragment) = Fragment::decode(input) {
        let canonical = fragment.encode().expect("decoded fragment must re-encode");
        assert_eq!(canonical, input);
        assert_eq!(
            Fragment::decode(&canonical).expect("canonical fragment must decode"),
            fragment
        );
    }
});
