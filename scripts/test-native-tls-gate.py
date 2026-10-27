#!/usr/bin/env python3
"""Keep incomplete or misleading native evidence from satisfying the TLS gate."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("gate", Path(__file__).with_name("assert-native-tls.py"))
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class EvidenceGateTest(unittest.TestCase):
    def test_requires_fresh_executed_assertions_and_discriminating_controls(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            reports = work / "android-test-results"
            reports.mkdir()
            ready = work / "ready.json"
            ready.write_text(json.dumps({"cases": {
                "rsa2047": {"kind": "weak"},
                "trusted_rsa2048": {"kind": "platform"},
            }}))
            report = reports / "TEST-device.xml"
            passed = "<testsuite>" + "".join(
                f'<testcase classname="{gate.CLASS}" name="{name}"/>' for name in sorted(gate.METHODS)
            ) + "</testsuite>"
            stats = {
                "rsa2047": {"connections": 1, "requests": 0, "bytes": 0},
                "trusted_rsa2048": {"connections": 1, "requests": 1, "bytes": 26},
            }
            report.write_text(passed)
            (work / "fixture-stats.json").write_text(json.dumps(stats))
            self.assertEqual([], gate.verify(work, reports))
            for field, value, expected in [
                ("connections", 0, "never reached"),
                ("requests", 1, "received HTTP"),
                ("bytes", 1, "received HTTP"),
            ]:
                with self.subTest(field=field):
                    altered = json.loads(json.dumps(stats))
                    altered["rsa2047"][field] = value
                    (work / "fixture-stats.json").write_text(json.dumps(altered))
                    self.assertTrue(any(expected in error for error in gate.verify(work, reports)))
            stats["trusted_rsa2048"]["requests"] = 0
            (work / "fixture-stats.json").write_text(json.dumps(stats))
            self.assertTrue(any("direct-trust control refused" in error for error in gate.verify(work, reports)))
            stats["trusted_rsa2048"]["requests"] = 1
            (work / "fixture-stats.json").write_text(json.dumps(stats))
            for content in ["<testsuite/>", passed.replace("/>", "><skipped/></testcase>")]:
                report.write_text(content)
                self.assertTrue(any("missing" in error for error in gate.verify(work, reports)))
            report.write_text(passed)
            old = ready.stat().st_mtime_ns - 1_000_000_000
            os.utime(report, ns=(old, old))
            self.assertTrue(any("stale" in error for error in gate.verify(work, reports)))


if __name__ == "__main__":
    unittest.main()
