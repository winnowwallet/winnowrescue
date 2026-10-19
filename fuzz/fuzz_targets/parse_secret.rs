#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    rescue_core::fuzz_api::parse_secret(data);
});
