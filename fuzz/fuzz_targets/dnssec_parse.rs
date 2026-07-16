#![no_main]

use libfuzzer_sys::fuzz_target;

// Feeds arbitrary bytes to the DNSSEC wire and crypto toolkit: the NSEC3 RDATA
// parser, and the key-tag, DS, RRSIG, chain, and denial-of-existence code over a
// parsed packet. All of it runs on attacker-controlled wire data, so no input may
// panic.
fuzz_target!(|data: &[u8]| {
    n0_dns_resolver::fuzz::dnssec(data);
});
