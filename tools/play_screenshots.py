#!/usr/bin/env python3
"""Captures Play Store phone screenshots from demo mode on a running 1080x1920, 420dpi emulator.

Needs a debug build installed (release blocks screenshots) and an unpaired app.
Usage: tools/play_screenshots.py [out_dir]

The Vault tab re-renders its codes every second, so uiautomator never sees it idle: taps there use
fixed coordinates for this screen size, and waits follow DemoMode's timings.
"""
import io
import os
import re
import subprocess
import sys
import time

from PIL import Image

ADB = os.environ.get("ADB", os.path.expanduser("~/Android/Sdk/platform-tools/adb"))
PKG = "org.kysecurity.authenticator"
OUT = sys.argv[1] if len(sys.argv) > 1 else "fastlane/metadata/android/en-US/images/phoneScreenshots"

NAV_VAULT, NAV_SETTINGS = (262, 1668), (818, 1668)
ADD, APPROVE, ADD_CANCEL = (970, 402), (540, 1390), (540, 1190)
FIRST_PUSH_S, TOAST_S = 3, 4


def adb(*args, binary=False):
    out = subprocess.run([ADB, *args], check=True, capture_output=True).stdout
    return out if binary else out.decode()


def tap_xy(xy):
    adb("shell", "input", "tap", str(xy[0]), str(xy[1]))


def tap(text, timeout=20):
    """Taps the first node whose text contains [text]; only works on a screen that goes idle."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        xml = subprocess.run([ADB, "exec-out", "uiautomator", "dump", "/dev/tty"], capture_output=True).stdout.decode()
        for t, x1, y1, x2, y2 in re.findall(r'text="([^"]*)"[^>]*?bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', xml):
            if text in t:
                return tap_xy(((int(x1) + int(x2)) // 2, (int(y1) + int(y2)) // 2))
        time.sleep(0.5)
    raise SystemExit(f"timed out waiting for {text!r}")


def hide_keyboard():
    # Back with no keyboard up would leave the app, so check first.
    if "mInputShown=true" in adb("shell", "dumpsys", "input_method"):
        adb("shell", "input", "keyevent", "KEYCODE_BACK")
        time.sleep(0.5)


def shot(name):
    image = Image.open(io.BytesIO(adb("exec-out", "screencap", "-p", binary=True))).convert("RGB")  # Play rejects alpha
    assert image.size == (1080, 1920), image.size
    image.save(os.path.join(OUT, name))
    print(name, image.size)


def statusbar():
    adb("shell", "settings", "put", "global", "sysui_demo_allowed", "1")
    for cmd in (["enter"], ["clock", "-e", "hhmm", "0930"], ["battery", "-e", "level", "100", "-e", "plugged", "false"],
                ["network", "-e", "wifi", "show", "-e", "level", "4", "-e", "fully", "true"], ["network", "-e", "mobile", "hide"],
                ["notifications", "-e", "visible", "false"]):
        adb("shell", "am", "broadcast", "-a", "com.android.systemui.demo", "-e", "command", *cmd)


def set_theme(name):
    tap_xy(NAV_SETTINGS)
    tap("Select theme")
    tap(name)
    time.sleep(1)  # the dialog closing swallows an immediate tap
    tap_xy(NAV_VAULT)


def main():
    os.makedirs(OUT, exist_ok=True)
    adb("shell", "am", "force-stop", PKG)
    adb("shell", "am", "start", "-W", "-n", f"{PKG}/.MainActivity")
    statusbar()
    time.sleep(1)
    shot("05-pair.png")

    # Start 5 s before a 30 s TOTP period ends, so the code shots land early in the next one.
    time.sleep((25 - time.time()) % 30)
    tap("Try demo")
    time.sleep(FIRST_PUSH_S + TOAST_S)
    hide_keyboard()
    shot("02-sign-in-request.png")

    # Empty field: the demo denies it, and the next request is 15 s away. The code shots and the
    # add dialog all need the Vault tab without a request card.
    tap_xy(APPROVE)
    time.sleep(0.5)
    hide_keyboard()
    time.sleep(TOAST_S)  # also lets the re-render's scrollbar fade
    shot("01-codes.png")

    tap_xy(ADD)
    time.sleep(1)
    shot("04-add-account.png")
    tap_xy(ADD_CANCEL)
    time.sleep(1)

    set_theme("Busnes Dark")
    time.sleep(2)
    shot("03-codes-dark.png")
    set_theme("Busnes Light")


if __name__ == "__main__":
    main()
