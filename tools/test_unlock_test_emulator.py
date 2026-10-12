"""Deterministic tests for unlock_test_emulator: a scripted fake emulator and a fake clock."""
import time
import unittest
from unittest import mock

import unlock_test_emulator as unlock

PIN_XML = '<hierarchy><node resource-id="com.android.systemui:id/pinEntry" focused="true"/></hierarchy>'
NO_PIN_XML = '<hierarchy><node resource-id="other"/></hierarchy>'


class FakeEmulator:
    """outcomes[i] is attempt i+1: 'no_pin' (field never appears), 'stuck' (PIN ignored) or 'ok'."""

    def __init__(self, outcomes):
        self.outcomes = outcomes
        self.attempt = 0
        self.locked = True
        self.calls = []
        self.now = 0.0

    def adb(self, *args):
        self.calls.append(args)
        if args[:2] == ("shell", "getprop"):
            return "1\n"
        if args == ("shell", "input", "keyevent", "KEYCODE_WAKEUP"):
            self.attempt += 1
        if args[:2] == ("exec-out", "cat"):
            return PIN_XML if self.outcome() != "no_pin" else NO_PIN_XML
        if args == ("shell", "input", "keyevent", "KEYCODE_ENTER") and self.outcome() == "ok":
            self.locked = False
        if args[:3] == ("shell", "dumpsys", "window"):
            return "  KeyguardServiceDelegate\n    showing=%s\n" % ("true" if self.locked else "false")
        return ""

    def outcome(self):
        return self.outcomes[min(self.attempt, len(self.outcomes)) - 1]

    def sleep(self, seconds):
        self.now += seconds

    def run(self):
        with mock.patch.object(unlock, "adb", self.adb), \
                mock.patch.object(time, "sleep", self.sleep), \
                mock.patch.object(time, "monotonic", lambda: self.now):
            return unlock.main()


class UnlockTest(unittest.TestCase):
    def test_first_attempt_unlocks(self):
        emu = FakeEmulator(["ok"])
        self.assertEqual(emu.run(), 1)
        self.assertFalse(emu.locked)

    def test_retries_until_success(self):
        emu = FakeEmulator(["no_pin", "stuck", "no_pin", "ok"])
        self.assertEqual(emu.run(), 4)
        self.assertEqual(emu.attempt, 4)

    def test_gives_up_after_four_attempts(self):
        emu = FakeEmulator(["stuck"] * 4)
        with self.assertRaises(RuntimeError):
            emu.run()
        self.assertEqual(emu.attempt, 4)

    def test_each_attempt_has_its_own_budget(self):
        # 30 s for the PIN field, then 15 s for the keyguard; one slow phase must not starve the next attempt.
        emu = FakeEmulator(["no_pin", "stuck", "ok"])
        emu.run()
        waits = [c for c in emu.calls if c == ("shell", "input", "keyevent", "KEYCODE_WAKEUP")]
        self.assertEqual(len(waits), 3)
        self.assertGreaterEqual(emu.now, 1 + 30 + 15)  # sleep, a full PIN wait, a full unlock wait

    def test_field_is_cleared_before_the_pin(self):
        emu = FakeEmulator(["ok"])
        emu.run()
        text = emu.calls.index(("shell", "input", "text", unlock.PIN))
        self.assertIn("KEYCODE_DEL", emu.calls[text - 1])

    def test_always_locks_first_and_enters_the_pin(self):
        emu = FakeEmulator(["ok"])
        emu.run()
        self.assertIn(("shell", "input", "keyevent", "KEYCODE_SLEEP"), emu.calls)
        self.assertIn(("shell", "input", "text", unlock.PIN), emu.calls)

    def test_unlocked_matches_only_the_keyguard_line(self):
        with mock.patch.object(unlock, "adb", lambda *a: "  mFoo showing=false\n  showing=true\n"):
            self.assertFalse(unlock.unlocked())
        with mock.patch.object(unlock, "adb", lambda *a: "  KeyguardServiceDelegate\n    showing=false\n"):
            self.assertTrue(unlock.unlocked())


if __name__ == "__main__":
    unittest.main()
