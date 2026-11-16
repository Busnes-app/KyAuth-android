# Getting started

## Choose a build

Play and GitHub builds support Firebase or UnifiedPush; F-Droid uses UnifiedPush and a built-in QR scanner. All KyAuth builds share one app ID and have different signing keys. Switching channel requires uninstalling and pairing again, so arrange TOTP recovery first.

## Pair

1. Set a secure Android screen lock.
2. For F-Droid, install a UnifiedPush distributor before pairing.
3. In KyIdentity, start a new device pairing.
4. In KyAuth, scan the QR code within 90 seconds, or enter the server URL and token manually.
5. Confirm with your fingerprint and test a sign-in request.

Keep another sign-in method and each service's recovery codes. TOTP secrets have no backup, export or sync.
