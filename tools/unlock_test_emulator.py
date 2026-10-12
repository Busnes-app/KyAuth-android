"""Unlock the disposable CI emulator after configuring its fixture PIN.

SystemUI on a freshly booted CI emulator is slow and sometimes drops input, so the whole
wake / enter-PIN / confirm sequence is retried, each attempt with its own time budget.
"""
import subprocess
import time
import xml.etree.ElementTree as ET

PIN = "246810"
ATTEMPTS = 4


def log(message):
    print(message, flush=True)


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


def open_bouncer():
    # dismiss-keyguard opens the PIN pad on a secure keyguard; the swipe and MENU cover
    # SystemUI builds that ignore one or the other.
    adb("shell", "wm", "dismiss-keyguard")
    adb("shell", "input", "swipe", "540", "1800", "540", "600")
    adb("shell", "input", "keyevent", "KEYCODE_MENU")


def attempt():
    adb("shell", "input", "keyevent", "KEYCODE_WAKEUP")

    def ready():
        open_bouncer()
        return pin_entry_focused()

    # Field detection is a UI dump and has failed whole runs on its own; type the PIN
    # anyway when it times out. Keys sent with no PIN pad open go nowhere.
    if not wait_for(ready, 30):
        log("PIN field not detected; typing the PIN anyway")
    # Clear anything a failed attempt left in the field: a wrong PIN counts toward lockout.
    adb("shell", "input", "keyevent", *["KEYCODE_DEL"] * 12)
    adb("shell", "input", "text", PIN)
    adb("shell", "input", "keyevent", "KEYCODE_ENTER")
    return wait_for(unlocked, 15)


def diagnose():
    policy = [l.strip() for l in adb("shell", "dumpsys", "window", "policy").splitlines() if "showing" in l.lower()]
    focus = [l.strip() for l in adb("shell", "dumpsys", "window").splitlines() if "mCurrentFocus" in l]
    log(f"  keyguard: {policy}  focus: {focus}")


def main():
    assert adb("shell", "getprop", "ro.kernel.qemu").strip() == "1", "Emulator required"
    # Right after locksettings set-pin the device is unlocked with a secure lock screen set,
    # which is all the tests need. Check before sleeping: after sleep a PIN device locks
    # only once its delay passes, so a later check would see no keyguard yet.
    if unlocked():
        log("CI emulator already unlocked")
        return 0
    adb("shell", "input", "keyevent", "KEYCODE_SLEEP")
    time.sleep(1)
    for n in range(1, ATTEMPTS + 1):
        if attempt():
            log(f"CI emulator unlocked (attempt {n})")
            return n
        log(f"Unlock attempt {n} failed; retrying")
        diagnose()
    raise RuntimeError(f"The emulator did not unlock after {ATTEMPTS} attempts")


if __name__ == "__main__":
    main()
