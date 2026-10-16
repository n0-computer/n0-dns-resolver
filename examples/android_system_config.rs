//! Exercises the Android JNI system-DNS reader on a device or emulator.
//!
//! ```text
//! cargo apk run --example android_system_config
//! ```
//!
//! The reader needs a real `Context`, so no unit test can reach it; this is the
//! harness CI runs on an emulator instead. See `.github/workflows/ci.yaml`, job
//! `android_emulator`.
//!
//! It resolves one name, which forces the lazy system-configuration read, and
//! logs what came back. The resolver logs the configuration it assembled at
//! debug level ("configured DNS resolver"), which is what the CI script
//! asserts against, so nothing here needs a public accessor for it. The final
//! `android_system_config: done` line marks a complete run, so that a crash
//! partway through is not read as an empty configuration.

/// The NativeActivity entry point.
///
/// `android-activity` initializes [`ndk_context`] before calling this, which is
/// what lets the resolver read the device's DNS configuration over JNI.
///
/// [`ndk_context`]: https://docs.rs/ndk-context
#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
fn android_main(_app: android_activity::AndroidApp) {
    use n0_dns_resolver::DnsResolver;

    init_logging();

    // No fallback tier: a lookup must be answered by the system's own
    // nameservers, or not at all. Otherwise a reader that returned nothing
    // would still resolve, and the test would pass on a broken read.
    let resolver = DnsResolver::builder().use_system_config().build();

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let result = runtime.block_on(resolver.lookup_ipv4("dns.google"));

    match result {
        Ok(addrs) => tracing::info!("android_system_config: resolved {addrs:?}"),
        Err(err) => tracing::error!("android_system_config: lookup failed: {err:#}"),
    }
    tracing::info!("android_system_config: done");
}

/// Sends the harness output and the resolver's own debug logging to logcat.
#[cfg(target_os = "android")]
fn init_logging() {
    use tracing_subscriber::{
        filter::Targets, layer::SubscriberExt as _, util::SubscriberInitExt as _,
    };

    /// The resolver at debug, for its "configured DNS resolver" line.
    const DEFAULT_FILTER: &str =
        "warn,android_activity=off,n0_dns_resolver=debug,android_system_config=info";

    let filter: Targets = option_env!("RUST_LOG")
        .unwrap_or(DEFAULT_FILTER)
        .parse()
        .expect("RUST_LOG parses as a tracing filter");
    tracing_subscriber::registry()
        .with(paranoid_android::layer("n0_dns_android").with_target(false))
        .with(filter)
        .init();
}
