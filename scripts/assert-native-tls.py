#!/usr/bin/env python3
"""Require executed native TLS assertions and fresh peer counters, not just Gradle's exit."""
import json
from pathlib import Path
import sys
import xml.etree.ElementTree as ET

CLASS = "org.kysecurity.authenticator.pairing.ServerHttpTLSDeviceTest"
METHODS = {
    "allPeersHonorKeyFloorAndNativeTrust",
    "selectedPlatformPathIncludesItsAnchor",
    "nativeCertificateAttributesDecideTheFloor",
    "namesPinsAndRedirectRefusalRemainEnforced",
}


def verify(work: Path, reports: Path) -> list[str]:
    cases = json.loads((work / "ready.json").read_text())["cases"]
    stats = json.loads((work / "fixture-stats.json").read_text())
    errors = []
    executed = set()
    started = (work / "ready.json").stat().st_mtime_ns
    for path in reports.rglob("*.xml"):
        suite = ET.parse(path).getroot()
        for test in suite.iter("testcase"):
            if test.get("classname", suite.get("name")) != CLASS:
                continue
            name = test.get("name", "").split("(", 1)[0]
            if path.stat().st_mtime_ns < started:
                errors.append(f"stale native TLS result: {name}")
                continue
            if any(test.find(tag) is not None for tag in ("failure", "error", "skipped")):
                errors.append(f"native TLS assertion did not pass: {name}")
            else:
                executed.add(name)
    if missing := METHODS - executed:
        errors.append("native TLS assertions missing: " + ", ".join(sorted(missing)))
    if stats.get("trusted_rsa2048", {}).get("requests", 0) < 1:
        errors.append("direct-trust control refused; weak direct-trust refusals are not key-floor evidence")
    for name, peer in cases.items():
        observed = stats[name]
        connections, requests, body = (observed[k] for k in ("connections", "requests", "bytes"))
        kind = peer["kind"]
        if kind == "certificate-only":
            if connections or requests or body:
                errors.append(f"certificate-only case unexpectedly received traffic: {name}")
            continue
        if kind == "redirect" and not peer.get("redirect_to"):
            if connections or requests or body:
                errors.append(f"redirect target was reached: {name}")
            continue
        if connections < 1:
            errors.append(f"TLS peer was never reached: {name}")
        if kind in ("weak", "trust") and (requests or body):
            errors.append(f"refused peer received HTTP/application bytes: {name}")
        if kind in ("positive", "redirect") and (requests < 1 or body < 1):
            errors.append(f"strong/control peer did not receive application data: {name}")
        if kind not in ("positive", "weak", "trust", "platform", "redirect"):
            errors.append(f"unknown fixture kind: {name} ({kind})")
    return errors


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: assert-native-tls.py FIXTURE_RUN ANDROID_TEST_REPORTS")
    work, reports = (Path(arg) for arg in sys.argv[1:])
    try:
        errors = verify(work, reports)
    except (OSError, ValueError, KeyError, TypeError, ET.ParseError) as error:
        raise SystemExit(f"Native TLS evidence is incomplete: {error}") from error
    if errors:
        raise SystemExit("\n".join(errors))
    print("Native TLS assertions executed and all peer counter checks passed.")
