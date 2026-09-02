//! Runs [`compare_iroh_lookups`] on an Android device, with the JNI path to the
//! system's DNS servers live.
//!
//! ```text
//! cargo apk run --example compare_iroh_lookups_android
//! ```
//!
//! `cargo-apk` builds a NativeActivity out of a `cdylib`, and an example cannot
//! be both that and a runnable binary, so this is a separate target rather than
//! a `cfg` block: it compiles the example next door as a module and calls its
//! `run`.
//!
//! [`compare_iroh_lookups`]: ../compare_iroh_lookups.rs

/// Android discards a process's stdout, so send the example's `println!` to
/// logcat instead. Declared before the module, which is what puts it in scope
/// inside it.
#[cfg(target_os = "android")]
macro_rules! println {
    () => { tracing::info!("") };
    ($($arg:tt)*) => { tracing::info!($($arg)*) };
}

// Its `main` goes unused: this target enters at `android_main` below.
#[cfg(target_os = "android")]
#[allow(dead_code)]
#[path = "compare_iroh_lookups.rs"]
mod compare_iroh_lookups;

/// The NativeActivity entry point.
///
/// `android-activity` initializes [`ndk_context`] before calling this, which is
/// the whole point of running here: it is what lets both resolvers read the
/// device's DNS servers over JNI. The activity draws nothing, and output goes
/// to logcat, which `cargo apk run` streams.
///
/// [`ndk_context`]: https://docs.rs/ndk-context
#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
fn android_main(_app: android_activity::AndroidApp) {
    paranoid_android::init("compare_iroh_lookups");
    compare_iroh_lookups::run()
}
