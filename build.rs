// cfg_aliases expands each condition recursively, so the nested provider checks
// below (`all(feature, any(..))`) need a higher limit than the default.
#![recursion_limit = "4096"]

use cfg_aliases::cfg_aliases;

fn main() {
    cfg_aliases! {
        transport_udp: { feature = "transport-udp" },
        transport_tcp: { feature = "transport-tcp" },
        // DoT and DoH need both their transport and a rustls crypto provider (a
        // build with the transport but no provider is a hard error, see the
        // compile_error guards in lib.rs), so these are set only when both are on.
        transport_tls: {
            all(feature = "transport-tls", any(feature = "tls-ring", feature = "tls-aws-lc-rs"))
        },
        transport_https: {
            all(feature = "transport-https", any(feature = "tls-ring", feature = "tls-aws-lc-rs"))
        },
        // rustls (ClientConfig, the TLS server name plumbing) is shared by DoT and DoH.
        with_rustls: { any(transport_tls, transport_https) },
        // Any transport is compiled in (the shared query timeout applies to all).
        has_transport: { any(transport_udp, transport_tcp, transport_tls, transport_https) },
    }
}
