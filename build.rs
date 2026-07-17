//! Emits the transport cfgs from the enabled features and target, so the rest of
//! the crate can gate on short cfg names instead of long feature/target
//! expressions.

fn main() {
    let feature = |name: &str| std::env::var(format!("CARGO_FEATURE_{name}")).is_ok();
    let cfg = |name: &str| std::env::var(format!("CARGO_CFG_{name}")).unwrap_or_default();

    // The browser wasm target (wasm32-unknown-unknown): no UDP/TCP sockets and no
    // native TLS stack, so only DNS-over-HTTPS (through reqwest's fetch backend)
    // is available.
    let wasm_browser =
        cfg("TARGET_FAMILY").split(',').any(|f| f == "wasm") && cfg("TARGET_OS") == "unknown";

    // DoT is native-only. DoH works on both (rustls on native, fetch on wasm).
    let tls = feature("TRANSPORT_TLS") && !wasm_browser;
    let https = feature("TRANSPORT_HTTPS");
    // rustls (ClientConfig, the TLS server name plumbing) and a crypto provider
    // are native-only; on wasm the browser performs TLS through fetch.
    let with_rustls = (tls || https) && !wasm_browser;
    let with_crypto_provider = (feature("TLS_RING") || feature("TLS_AWS_LC_RS")) && !wasm_browser;

    for (name, enabled) in [
        ("wasm_browser", wasm_browser),
        ("transport_tls", tls),
        ("transport_https", https),
        ("with_rustls", with_rustls),
        ("with_crypto_provider", with_crypto_provider),
    ] {
        println!("cargo::rustc-check-cfg=cfg({name})");
        if enabled {
            println!("cargo::rustc-cfg={name}");
        }
    }
}
