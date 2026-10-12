"""Unlock the disposable CI emulator after configuring its fixture PIN.

SystemUI on a freshly booted CI emulator is slow and sometimes drops input, so the whole
wake / enter-PIN / confirm sequence is retried, each attempt with its own time budget.
"""
import subprocess
import time
import xml.etree.ElementTree as ET

PIN = "246810"
ATTEMPTS = 4


def adb(*args):
    return subprocess.check_output(["adb", *args], text=True)


def unlocked():
    # KeyguardServiceDelegate's own line; nothing else in the dump counts.
    lines = [line.strip() for line in adb("shell", "dumpsys", "window", "policy").splitlines()]
    return "showing=false" in lines and "showing=true" not in lines


def pin_entry_focused():
    try:
        adb("shell", "uiautomator", "dump", "/sdcard/ci-unlock.xml")
        root = ET.fromstring(adb("exec-out", "cat", "/sdcard/ci-unlock.xml"))
    except (ET.ParseError, subprocess.CalledProcessError):
        return False  # SystemUI can return no accessibility root while the screen is waking.
    return any(node.get("resource-id") == "com.android.systemui:id/pinEntry"
               and node.get("focused") == "true" for node in root.iter("node"))


def wait_for(condition, seconds):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(1)
    return False


def attempt():
    adb("shell", "input", "keyevent", "KEYCODE_WAKEUP")
    adb("shell", "input", "keyevent", "KEYCODE_MENU")

    def ready():
        adb("shell", "input", "keyevent", "KEYCODE_MENU")
        return pin_entry_focused()

    if not wait_for(ready, 30):
        return False
    # Clear anything a failed attempt left in the field: a wrong PIN counts toward lockout.
    adb("shell", "input", "keyevent", *["KEYCODE_DEL"] * 12)
    adb("shell", "input", "text", PIN)
    adb("shell", "input", "keyevent", "KEYCODE_ENTER")
    return wait_for(unlocked, 15)


assert adb("shell", "getprop", "ro.kernel.qemu").strip() == "1", "Emulator required"
adb("shell", "input", "keyevent", "KEYCODE_SLEEP")
time.sleep(1)
# No "already unlocked" shortcut: after KEYCODE_SLEEP a PIN device locks only once its
# lock-after-timeout delay passes, so an early check sees no keyguard and skips the PIN.
for n in range(1, ATTEMPTS + 1):
    if attempt():
        print(f"CI emulator unlocked (attempt {n})")
        break
    print(f"Unlock attempt {n} failed; retrying")
else:
    raise RuntimeError(f"The emulator did not unlock after {ATTEMPTS} attempts")
