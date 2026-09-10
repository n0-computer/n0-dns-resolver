//! Android system DNS reader.
//!
//! Android does not use `/etc/resolv.conf`. Instead the active network's DNS
//! servers are read from `LinkProperties.getDnsServers()` over the Java Native
//! Interface (JNI), going through [`ndk_context`]. This requires [`ndk_context`]
//! to be initialized before any [`DnsResolver`] is constructed, either by
//! ndk-glue or android-activity (both do this before `main`) or by an explicit
//! [`install_android_jni_context`] call.
//!
//! `getDnsServers()` returns plaintext servers even when Private DNS is in
//! strict mode, where Android's own resolver refuses cleartext, so
//! `getPrivateDnsServerName()` is read alongside it and those addresses are
//! queried over DoT under that name instead.
//!
//! Without an initialized [`ndk_context`] the JNI lookup panics. Debug builds
//! wrap the call in `std::panic::catch_unwind` so unit tests on Android (where
//! no Java Virtual Machine (JVM) is in scope) fall back to the resolver's
//! default servers instead of aborting the test binary. Release builds let the
//! panic propagate; uninitialized [`ndk_context`] in production is a programming
//! error and should surface loudly.
//!
//! The JNI implementation is adapted from `hickory_resolver`.
//!
//! [`DnsResolver`]: crate::DnsResolver
//! [`ndk_context`]: https://docs.rs/ndk-context

use std::ffi::c_void;
#[cfg(target_os = "android")]
use std::{
    net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6},
    panic::{AssertUnwindSafe, catch_unwind},
};

#[cfg(all(target_os = "android", transport_tls))]
use jni::objects::JObjectArray;
#[cfg(target_os = "android")]
use jni::{
    Env, jni_sig, jni_str,
    objects::{IntoAuto as _, JByteArray, JList, JObject, JString, JValue},
};
#[cfg(target_os = "android")]
use tracing::{trace, warn};

#[cfg(target_os = "android")]
use super::{Config, DnsProtocol, Hosts, Nameserver};

/// Reads the active network's DNS configuration via JNI, plus the hosts file.
#[cfg(target_os = "android")]
pub(super) fn read_system_dns() -> Result<Config, std::io::Error> {
    match catch_unwind(AssertUnwindSafe(read_system_dns_jni)) {
        Ok(res) => res,
        Err(_) => Err(std::io::Error::other(
            "ndk_context not initialized; call install_android_jni_context",
        )),
    }
}

/// Converts a `java.net.InetAddress` to a socket address on `port`.
///
/// Returns `None` for an address of neither length, which cannot happen for a
/// real `InetAddress`.
#[cfg(target_os = "android")]
fn socket_addr(
    env: &mut Env<'_>,
    address: &JObject<'_>,
    port: u16,
) -> jni::errors::Result<Option<SocketAddr>> {
    // https://developer.android.com/reference/java/net/InetAddress#getAddress()
    let bytes = env
        .call_method(address, jni_str!("getAddress"), jni_sig!("()[B"), &[])?
        .l()?;
    let bytes = env.cast_local::<JByteArray<'_>>(bytes)?;
    let bytes = env.convert_byte_array(bytes)?;

    Ok(match bytes.len() {
        4 => {
            let mut octets = [0u8; 4];
            octets.copy_from_slice(&bytes);
            Some(SocketAddr::new(IpAddr::from(octets), port))
        }
        16 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&bytes);
            // `getAddress` drops the zone, without which a link-local resolver
            // is unreachable. Sixteen bytes means an `Inet6Address`, which is
            // the only subclass with this method.
            // https://developer.android.com/reference/java/net/Inet6Address#getScopeId()
            let scope_id = env
                .call_method(address, jni_str!("getScopeId"), jni_sig!("()I"), &[])?
                .i()?;
            Some(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(octets),
                port,
                0,
                scope_id as u32,
            )))
        }
        len => {
            warn!(len, "ignoring InetAddress of unexpected length");
            None
        }
    })
}

/// Returns the strict-mode Private DNS hostname, if one is set.
///
/// `getPrivateDnsServerName` is API 28, above this crate's minimum of 24, so
/// the version is checked rather than letting the call fail: a missing method
/// raises a Java exception, which would abort the whole read and lose the
/// system nameservers on every device below 28.
///
/// https://developer.android.com/reference/android/net/LinkProperties#getPrivateDnsServerName()
#[cfg(target_os = "android")]
fn private_dns_name(
    env: &mut Env<'_>,
    link_properties: &JObject<'_>,
) -> jni::errors::Result<Option<String>> {
    const PRIVATE_DNS_API: i32 = 28;

    let sdk_int = env
        .get_static_field(
            jni_str!("android/os/Build$VERSION"),
            jni_str!("SDK_INT"),
            jni_sig!("I"),
        )?
        .i()?;
    if sdk_int < PRIVATE_DNS_API {
        return Ok(None);
    }

    let name = env
        .call_method(
            link_properties,
            jni_str!("getPrivateDnsServerName"),
            jni_sig!("()Ljava/lang/String;"),
            &[],
        )?
        .l()?;
    if name.is_null() {
        return Ok(None);
    }
    Ok(Some(
        env.cast_local::<JString<'_>>(name)?.try_to_string(env)?,
    ))
}

/// Resolves the Private DNS hostname and returns it as DoT nameservers.
///
/// The endpoint is a hostname whose addresses are not the link's DHCP servers,
/// so it has to be resolved. `Network.getAllByName` resolves on this network,
/// which in strict mode the OS does over DoT, so no bootstrap query leaks.
///
/// https://developer.android.com/reference/android/net/Network#getAllByName(java.lang.String)
#[cfg(all(target_os = "android", transport_tls))]
fn private_dns_nameservers(
    env: &mut Env<'_>,
    network: &JObject<'_>,
    name: &str,
) -> jni::errors::Result<Vec<Nameserver>> {
    let host = env.new_string(name)?;
    let addresses = env
        .call_method(
            network,
            jni_str!("getAllByName"),
            jni_sig!("(Ljava/lang/String;)[Ljava/net/InetAddress;"),
            &[JValue::Object(&host)],
        )?
        .l()?;
    let addresses = env.cast_local::<JObjectArray<'_>>(addresses)?;

    let mut nameservers = Vec::new();
    for i in 0..addresses.len(env)? {
        let address = addresses.get_element(env, i)?.auto();
        if let Some(addr) = socket_addr(env, &address, DnsProtocol::Tls.port())? {
            nameservers.push(Nameserver::with_server_name(
                addr,
                DnsProtocol::Tls,
                name.to_string(),
            ));
        }
    }
    Ok(nameservers)
}

/// Reads the active network's DNS servers through JNI.
#[cfg(target_os = "android")]
fn read_system_dns_jni() -> Result<Config, std::io::Error> {
    let ctx = ndk_context::android_context();
    let vm = unsafe { jni::JavaVM::from_raw(ctx.vm().cast()) };
    let nameservers = vm
        .attach_current_thread(|env| {
            let activity = unsafe { JObject::from_raw(env, ctx.context().cast()) };

            // https://developer.android.com/reference/android/content/Context#getSystemService(java.lang.String)
            let connectivity_service = env.new_string("connectivity")?;
            let connectivity_manager = env
                .call_method(
                    activity,
                    jni_str!("getSystemService"),
                    jni_sig!("(Ljava/lang/String;)Ljava/lang/Object;"),
                    &[JValue::Object(&connectivity_service)],
                )?
                .l()?;

            // https://developer.android.com/reference/android/net/ConnectivityManager#getActiveNetwork()
            let network = env
                .call_method(
                    &connectivity_manager,
                    jni_str!("getActiveNetwork"),
                    jni_sig!("()Landroid/net/Network;"),
                    &[],
                )?
                .l()?;

            // https://developer.android.com/reference/android/net/ConnectivityManager#getLinkProperties(android.net.Network)
            let link_properties = env
                .call_method(
                    &connectivity_manager,
                    jni_str!("getLinkProperties"),
                    jni_sig!("(Landroid/net/Network;)Landroid/net/LinkProperties;"),
                    &[JValue::Object(&network)],
                )?
                .l()?;

            // https://developer.android.com/reference/android/net/LinkProperties#getDnsServers()
            let dns_servers = env
                .call_method(
                    &link_properties,
                    jni_str!("getDnsServers"),
                    jni_sig!("()Ljava/util/List;"),
                    &[],
                )?
                .l()?;
            let dns_servers = env.cast_local::<JList<'_>>(dns_servers)?;
            let dns_servers = dns_servers.iter(env)?;

            let mut nameservers = Vec::<Nameserver>::new();
            while let Some(server) = dns_servers.next(env)? {
                if let Some(addr) = socket_addr(env, &server.auto(), DnsProtocol::Udp.port())? {
                    nameservers.push(Nameserver::new(addr, DnsProtocol::Udp));
                }
            }

            // In strict mode the servers above are the link's plaintext DHCP or
            // RA servers, which Android's own resolver refuses to use. The DoT
            // endpoint is a hostname, and it is not one of them.
            if let Some(name) = private_dns_name(env, &link_properties)? {
                trace!(%name, "Private DNS is in strict mode");
                #[cfg(transport_tls)]
                {
                    nameservers = private_dns_nameservers(env, &network, &name)?;
                }
                #[cfg(not(transport_tls))]
                warn!(
                    %name,
                    "Private DNS is in strict mode but this build has no DNS-over-TLS \
                     support, so queries stay in plaintext; enable the transport-tls feature",
                );
            }

            trace!("Got DNS servers: {:?}", nameservers);
            Ok(nameservers)
        })
        .map_err(|e: jni::errors::Error| std::io::Error::other(e.to_string()))?;

    Ok(Config {
        nameservers,
        search_domains: Vec::new(),
        ndots: None,
        hosts: Hosts::from_system(),
    })
}

/// Exposes a JVM to iroh so that we can read the system's DNS configuration.
///
/// This calls [`ndk_context::initialize_android_context`] to expose a
/// `JavaVM` and Application Context to Rust code so that we can use JNI.
/// This is required to get the configured nameservers on Android.
///
/// If this function is not called, fetching the configured nameservers will
/// fail, and a resolver built with [`Builder::use_system_config`] falls back to
/// whatever its fallback tier holds. For [`DnsResolver::system_with_fallback`]
/// that is the public resolvers.
///
/// [`Builder::use_system_config`]: crate::Builder::use_system_config
/// [`DnsResolver::system_with_fallback`]: crate::DnsResolver::system_with_fallback
///
/// If you call [`ndk_context::initialize_android_context`] already somewhere
/// up the stack in your app, or use a crate like `ndk-glue` or `android-activity`
/// that do this for you, then there's no need to call this function.
///
/// If you don't use a glue crate, a typical way to initialize the context is
/// via `JNI_OnLoad`:
///
/// `install_android_jni_context` is reexported from `iroh`, so you can substitute
/// `iroh_dns` for `iroh` in the example below.
///
/// ```ignore
/// #[cfg(target_os = "android")]
/// #[no_mangle]
/// pub extern "C" fn JNI_OnLoad(
///     vm: jni::JavaVM,
///     res: *mut std::os::raw::c_void,
/// ) -> jni::sys::jint {
///     use std::ffi::c_void;
///
///     let vm = vm.get_java_vm_pointer() as *mut c_void;
///     unsafe {
///         iroh_dns::install_android_jni_context(vm, res);
///     }
///     jni::JNIVersion::V6.into()
/// }
/// ```
///
/// # Safety
///
/// Both the `java_vm` and `context_jobject` pointers must remain valid until the process exits.
/// See also [`ndk_context::initialize_android_context`].
///
/// [`DnsResolver`]: crate::DnsResolver
/// [`ndk_context`]: https://docs.rs/ndk-context
/// [`ndk_context::initialize_android_context`]: https://docs.rs/ndk-context/latest/ndk_context/fn.initialize_android_context.html
pub unsafe fn install_android_jni_context(java_vm: *mut c_void, application_context: *mut c_void) {
    unsafe {
        ndk_context::initialize_android_context(java_vm, application_context);
    }
}
