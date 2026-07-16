#![no_main]

use libfuzzer_sys::fuzz_target;

// Feeds arbitrary bytes to the DNS response parsers. A wire response is fully
// attacker-controlled, so no input may panic.
fuzz_target!(|data: &[u8]| {
    n0_dns_resolver::fuzz::parse_response(data);
});
