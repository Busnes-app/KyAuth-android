# Everyday tasks

## TOTP

Add accounts by scanning their setup QR codes or entering setup details. Unlock the vault to view/copy codes and verify an initial code with each service. Store recovery codes away from this phone.

## Sign-in approvals

Approve or deny a KyIdentity request and match the browser's two-digit number. Push MFA uses the device key without opening the TOTP vault. Reject a request you did not initiate.

## Delivery and suite sign-on

On Play/GitHub builds, Settings → Sign-in request delivery switches Firebase/UnifiedPush. A private-network distributor needs the explicit server opt-in documented in the product reference. Supported suite apps use the Android account sign-on service, with authentication for each sign-in.

## Device changes

Verify recovery access before uninstalling, changing distribution channel or resetting the screen lock. Removing the hardware-bound key can make local secrets unavailable.

## TOTP setup keys

Setup keys need at least 10 decoded bytes (80 bits). An issuer-provided key between 80 and 127 bits is accepted with a short-key warning. A retained account below 80 bits is unavailable for code generation; use the issuing service to replace its secret. Preserve its record until recovery is verified.
