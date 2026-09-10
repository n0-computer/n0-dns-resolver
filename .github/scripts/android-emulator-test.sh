#!/usr/bin/env bash
#
# Runs the `android_system_config` example on a booted emulator and asserts on
# what it logged. Driven by the `android_emulator` job in ci.yaml, which sets
# API_LEVEL and has already built the APK.
#
# The JNI reader needs a real Context, so this is the only place its behaviour
# is checked. Two cases:
#
#   1. As the emulator comes up: the link's plaintext resolver is read and a
#      lookup goes through it.
#   2. Private DNS in strict mode (API 28 and up, where the setting exists):
#      the resolver must query the DoT endpoint the hostname resolves to, not
#      the link's own DHCP servers, which serve no DoT and whose certificate
#      would not match. Getting that wrong fails every lookup, which is what
#      the "resolved" assertion catches.
#
# Case 2 is skipped below API 28, where the setting does not exist. The reader
# guards its getPrivateDnsServerName call on the same version for the same
# reason, but that guard is not covered here: the NativeActivity harness does
# not start on API 24, so there is no leg to run it on.

set -euo pipefail

PKG=rust.example.android_system_config
ACTIVITY="$PKG/android.app.NativeActivity"
APK=target/debug/apk/examples/android_system_config.apk
LOG_TAG=n0_dns_android

adb install -r "$APK"

# A fresh emulator has Private DNS off, but reset it anyway so the two cases
# below hold in either order and a re-run on a warm emulator still means
# something. The setting only exists from API 28.
if [ "${API_LEVEL:-0}" -ge 28 ]; then
    adb shell settings put global private_dns_mode off
    sleep 5
fi

# Runs the app and prints its log lines. The app is short-lived, so this waits
# for the terminating "done" line rather than for the process to exit.
run_app() {
    adb shell am force-stop "$PKG"
    adb logcat -c
    adb shell am start -n "$ACTIVITY" > /dev/null

    local waited=0
    while [ "$waited" -lt 60 ]; do
        if adb logcat -d -s "$LOG_TAG" | grep -q "android_system_config: done"; then
            break
        fi
        sleep 2
        waited=$((waited + 2))
    done
    adb logcat -d -s "$LOG_TAG"
}

# Fails with the log in view, so a CI failure needs no second run to diagnose.
assert_log() {
    local log="$1" pattern="$2" what="$3"
    if ! grep -q "$pattern" <<< "$log"; then
        echo "FAIL: $what"
        echo "--- log ---"
        echo "$log"
        exit 1
    fi
    echo "ok: $what"
}

echo "=== the link's own resolver ==="
log=$(run_app)
echo "$log"
assert_log "$log" "android_system_config: done" "the app ran to completion"
assert_log "$log" "configured DNS resolver" "the resolver logged its configuration"
assert_log "$log" "protocol: Udp" "the link's nameserver was read over JNI"
assert_log "$log" "android_system_config: resolved" "a lookup went through it"

if [ "${API_LEVEL:-0}" -lt 28 ]; then
    echo "=== API ${API_LEVEL}: no Private DNS setting, done ==="
    exit 0
fi

echo "=== Private DNS, strict mode ==="
adb shell settings put global private_dns_mode hostname
adb shell settings put global private_dns_specifier dns.google
# Give the platform a moment to validate the endpoint before reading it.
sleep 10

log=$(run_app)
echo "$log"
assert_log "$log" "android_system_config: done" "the app ran to completion"
assert_log "$log" "protocol: Tls" "the nameservers became DNS-over-TLS"
assert_log "$log" 'server_name: Some("dns.google")' "the configured name is used for TLS"
# The endpoint has to be the one the hostname resolves to. Pointing DoT at the
# link's own DHCP resolver instead yields a certificate that does not match,
# so a successful lookup is what distinguishes the two.
assert_log "$log" "android_system_config: resolved" "a lookup went through the DoT endpoint"

if grep -q "lookup failed" <<< "$log"; then
    echo "FAIL: the DoT lookup failed"
    echo "$log"
    exit 1
fi

echo "=== all assertions passed ==="
