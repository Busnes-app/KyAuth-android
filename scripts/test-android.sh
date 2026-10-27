#!/usr/bin/env bash
# Complete device suite on one disposable emulator, with real native TLS peers.
set -euo pipefail
ulimit -c 0 # Disposable fixture private keys must not enter a core dump.
ROOT=$(cd "$(dirname "$0")/.." && pwd)
serial=${1:-${ANDROID_SERIAL:-}}
channel=${2:-Play}
scope=${3:-all}
case $serial in emulator-*) ;; *) echo 'Name one disposable emulator (emulator-NNNN).' >&2; exit 1 ;; esac
case $scope in all|tls) ;; *) echo 'Scope must be all or tls.' >&2; exit 1 ;; esac
case $channel in Play|Github|Fdroid) ;; *) echo 'Channel must be Play, Github or Fdroid.' >&2; exit 1 ;; esac
case "$(adb -s "$serial" shell getprop ro.kernel.qemu | tr -d '\r'):$(adb -s "$serial" shell getprop ro.boot.qemu | tr -d '\r')" in
    1:*|*:1) ;;
    *) echo 'A disposable emulator is required.' >&2; exit 1 ;;
esac
export ANDROID_SERIAL=$serial
mkdir -p "$ROOT/.tls-fixtures"
work=$(mktemp -d "$ROOT/.tls-fixtures/run.XXXXXXXX")
fixture_pid=''
ports=''
control=''
# shellcheck disable=SC2329 # Invoked indirectly by the EXIT trap below.
cleanup() {
    # Counters contain public fixture traffic only and survive a failed device run.
    if [ -n "$control" ] && [ ! -s "$work/fixture-stats.json" ]; then
        curl --fail --silent --show-error --max-time 5 "http://127.0.0.1:$control/stats" >"$work/fixture-stats.json" || true
    fi
    if [ -n "$fixture_pid" ]; then kill "$fixture_pid" 2>/dev/null || true; wait "$fixture_pid" 2>/dev/null || true; fi
    for port in $ports; do adb -s "$serial" reverse --remove "tcp:$port" >/dev/null 2>&1 || true; done
}
trap cleanup EXIT
trap 'exit 143' TERM
trap 'exit 130' INT
(cd "$ROOT/scripts/tls-fixtures" && go build -o "$work/server" .)
GODEBUG=fips140=off "$work/server" -out "$work" >"$work/fixture.log" 2>&1 &
fixture_pid=$!
for _ in $(seq 100); do
    [ ! -s "$work/ready.json" ] || break
    kill -0 "$fixture_pid" 2>/dev/null || { cat "$work/fixture.log" >&2; exit 1; }
    sleep 0.1
done
[ -s "$work/ready.json" ] || { echo 'TLS fixture did not become ready.' >&2; exit 1; }
ports=$(python3 - "$work/ready.json" <<'PYPORTS'
import json, sys
with open(sys.argv[1]) as file: ready = json.load(file)
ports = [ready['control_port']] + [peer['port'] for peer in ready['cases'].values() if peer['port']]
assert all(type(port) is int and 1 <= port <= 65535 for port in ports)
print(' '.join(str(port) for port in dict.fromkeys(ports)))
PYPORTS
)
control=${ports%% *}
for port in $ports; do adb -s "$serial" reverse "tcp:$port" "tcp:$port" >/dev/null; done
adb -s "$serial" logcat -c
status=0
set -- "$ROOT/gradlew" --no-daemon --max-workers=2 -p "$ROOT" "connected${channel}DebugAndroidTest" \
    "-PtlsFixtureDir=$work" \
    "-Pandroid.testInstrumentationRunnerArguments.tlsFixtureControl=$control"
if [ "$scope" = tls ]; then
    set -- "$@" '-Pandroid.testInstrumentationRunnerArguments.class=org.kysecurity.authenticator.pairing.ServerHttpTLSDeviceTest'
fi
"$@" || status=$?
if ! curl --fail --silent --show-error --max-time 5 "http://127.0.0.1:$control/stats" >"$work/fixture-stats.json"; then status=1; fi
adb -s "$serial" logcat -d -s KyAuthTLS:I '*:S' >"$work/native-tls.log" || status=1
reports="$ROOT/app/build/outputs/androidTest-results/connected/debug/flavors/${channel,,}"
if [ -d "$reports" ]; then cp -pR "$reports" "$work/android-test-results"; fi
python3 "$ROOT/scripts/assert-native-tls.py" "$work" "$work/android-test-results" 2>&1 | tee "$work/native-tls-gate.txt" || status=1
printf '{"channel":"%s","scope":"%s","serial":"%s"}\n' "$channel" "$scope" "$serial" >"$work/run-info.json"
echo "Native TLS fixture evidence: $work"
exit "$status"
