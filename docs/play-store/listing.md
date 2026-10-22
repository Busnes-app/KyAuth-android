# Play Store listing

Plain text: Play does not render Markdown. Limits are 80 characters for the short description and
4,000 for the full one.

## Short description

```text
Approve KyIdentity sign-ins and keep one-time codes, locked to your phone.
```

## Full description

```text
KyAuth is the authenticator for KyIdentity, the self-hosted sign-in server in the KySecurity suite. Pair your phone with your KyIdentity server once, then approve sign-ins and keep one-time codes on a device that only you can unlock.

KyAuth needs a KyIdentity server to work. Without one, tap Try demo on the first screen to see codes and sign-in requests in action, with nothing sent anywhere.

SIGN-IN APPROVALS
• When you sign in to KyIdentity, KyAuth shows the request with the server and account it came from.
• Type the two-digit number shown on your sign-in screen, then confirm with your fingerprint or screen lock. A wrong number counts as a denial.
• Answer a request even while KyAuth is locked, with a single prompt.
• Requests come through Firebase or, if you prefer, UnifiedPush with a distributor you choose, such as ntfy. UnifiedPush requests are end-to-end encrypted: the distributor never sees what they say.
• Answers go only to the server this phone is paired with.

ONE-TIME CODES
• Add accounts by scanning a QR code or typing the secret key, with an optional website and notes.
• Codes are generated on the phone and stored in an encrypted vault that opens only with your biometrics or screen lock.
• Tap a code to copy it. The copy is marked sensitive and is cleared when the code expires.

SIGN IN TO SUITE APPS
KySecurity apps such as KyPost can sign you in through KyAuth, with one fingerprint per sign-in and no password to type.

BUILT TO STAY LOCKED
• KyAuth locks as soon as it leaves the screen, and after a period of inactivity you choose.
• Add an optional PIN as a second lock. After five wrong PINs, KyAuth erases its data.
• Screenshots and Android backup are blocked, and KyAuth connects to your server only over HTTPS.
• No ads and no analytics SDK. Firebase is used only to deliver sign-in requests, and you can switch to UnifiedPush instead.

GOOD TO KNOW
• Your codes have no backup, export or sync, by design: they exist only on this phone. Keep each site's recovery codes somewhere safe, and keep your KyIdentity recovery codes in case you lose the phone.
• KyAuth is not a password manager.
• Requires Android 12 or newer and a screen lock (PIN, pattern or password).
• Choose from 17 themes, light and dark.

KyAuth is open source under the MIT license.
```

## Privacy policy

https://busnes.app/privacy.html

## What's new (0.5.0)

```text
• Sign-in requests sent through Firebase are now end-to-end encrypted. A phone paired before this update switches over when it next reconnects or is paired again.
• The sign-in request card shows your account and server, and counts down the time left. Approve turns off when a request expires.
```

## What's new (0.4.2)

```text
First public release.
• Approve KyIdentity sign-ins with a two-digit number and your fingerprint or screen lock.
• One-time codes in an encrypted vault that opens only with your biometrics or screen lock.
• Sign-in requests over Firebase or UnifiedPush.
• Try demo on the first screen shows the app without a server.
```

## Images

Icon, feature graphic and phone screenshots live in `fastlane/metadata/android/en-US/images/`,
shared with F-Droid. `tools/` regenerates them.
