#![no_main]

use libfuzzer_sys::fuzz_target;

// Feeds arbitrary bytes to the hosts-file parser. The file is external input, so
// no content may panic.
fuzz_target!(|data: &[u8]| {
    n0_dns_resolver::fuzz::hosts(data);
});
