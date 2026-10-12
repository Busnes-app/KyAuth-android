# Push v2 Binding (KyAuth) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** KyAuth signs `kyidentity-push-v2` approvals binding issuer origin, user, device, challenge, purpose and expiry, refuses pushes that do not match its pairing, and shows the purpose.

**Architecture:** `MfaMessage` builds v2 from the pairing plus the parsed challenge; the parser becomes strict (purpose and expiry required, device/user must match the pairing); the response names the device.

**Tech Stack:** Kotlin, JUnit 4, `org.json` (test), Android Keystore signing (unchanged).

**Spec:** `docs/superpowers/specs/2026-10-07-push-mfa-binding-design.md`

## Global Constraints

- Message exactly: `kyidentity-push-v2|{origin}|{userId}|{deviceId}|{challengeId}|{purpose}|{expiresAtMs}|{verb}|{digits}`; deny signs empty digits.
- Golden vectors, verbatim in a test:
  `kyidentity-push-v2|https://id.example.com|u-123|d-456|c-789|login|1791331200000|approve|42`
  `kyidentity-push-v2|https://id.example.com|u-123|d-456|c-789|step_up|1791331200000|deny|`
- Origin vectors: `https://ID.Example.com/`→`https://id.example.com`; `https://id.example.com:443`→`https://id.example.com`; `https://id.example.com:8443/kyidentity`→`https://id.example.com:8443`; `http://127.0.0.1:8080`→`http://127.0.0.1:8080`.
- `purpose` is `login` or `step_up`. Expiry in the past or more than 10 minutes ahead is refused, never clamped.
- Origin comes from the paired `serverUrl`, never from the push payload. A field containing `|` or an empty origin/user/device/challenge is refused.
- `kysignon-push-token-v1` and Keystore alias `kysignon-device-signing-v1` are unchanged.
- Do not run Gradle while an emulator runs. Verify with `./gradlew test assembleDebug lintDebug compileDebugAndroidTestSources`.

## Review Focus

1. **A push for another device or account on the same server.** Expect: refused at parse, never shown. Pinned in Task 2.
2. **A push whose expiry is 11 minutes out.** Expect: refused, not clamped. Pinned in Task 2.
3. **A pairing with no `userId` (older pairing).** Expect: push refused with a clear error, not a signature with an empty field. Pinned in Task 1/2.
4. **Deny.** Expect: signs empty digits even if the push carried match digits. Pinned in Task 1.
5. **Purpose text.** Expect: "Sign-in request" / "Confirm a sensitive action" on the card. Pinned in Task 3 (VaultTabTest).

---

### Task 1: v2 message and origin

**Files:**
- Modify: `app/src/main/java/org/kysecurity/authenticator/mfa/MfaChallenge.kt` (`MfaMessage`)
- Modify: `app/src/test/java/org/kysecurity/authenticator/mfa/MfaMessageTest.kt`
- Modify: `app/src/test/java/org/kysecurity/authenticator/pairing/DeviceSigningKeyTest.kt` (its literal v1 message becomes any v2 golden vector)

**Interfaces:**
- Produces: `MfaMessage.origin(serverUrl: String): String` (throws `IllegalArgumentException`); `MfaMessage.formatPayload(origin: String, userId: String, deviceId: String, challengeId: String, purpose: String, expiresAtMs: Long, approve: Boolean, selectedDigits: String): ByteArray`.

- [ ] **Step 1: Failing test** — replace `MfaMessageTest` with:

```kotlin
package org.kysecurity.authenticator.mfa

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class MfaMessageTest {
    private fun msg(purpose: String, approve: Boolean, digits: String) = String(
        MfaMessage.formatPayload("https://id.example.com", "u-123", "d-456", "c-789", purpose, 1791331200000, approve, digits),
        Charsets.UTF_8,
    )

    @Test fun goldenVectors() {
        assertEquals("kyidentity-push-v2|https://id.example.com|u-123|d-456|c-789|login|1791331200000|approve|42", msg("login", true, "42"))
        assertEquals("kyidentity-push-v2|https://id.example.com|u-123|d-456|c-789|step_up|1791331200000|deny|", msg("step_up", false, ""))
    }

    @Test fun refusesAmbiguousFields() {
        assertThrows(IllegalArgumentException::class.java) { msg("session", true, "42") }
        assertThrows(IllegalArgumentException::class.java) {
            MfaMessage.formatPayload("https://id.example.com", "u|1", "d", "c", "login", 1, true, "42")
        }
        assertThrows(IllegalArgumentException::class.java) {
            MfaMessage.formatPayload("https://id.example.com", "", "d", "c", "login", 1, true, "42")
        }
    }

    @Test fun originVectors() {
        assertEquals("https://id.example.com", MfaMessage.origin("https://ID.Example.com/"))
        assertEquals("https://id.example.com", MfaMessage.origin("https://id.example.com:443"))
        assertEquals("https://id.example.com:8443", MfaMessage.origin("https://id.example.com:8443/kyidentity"))
        assertEquals("http://127.0.0.1:8080", MfaMessage.origin("http://127.0.0.1:8080"))
        assertThrows(IllegalArgumentException::class.java) { MfaMessage.origin("not a url") }
    }
}
```

- [ ] **Step 2: Run** `./gradlew testDebugUnitTest --tests '*MfaMessageTest*'` — Expected: compile FAIL.

- [ ] **Step 3: Implement** (replace the `MfaMessage` object):

```kotlin
object MfaMessage {
    // Wire contract: must equal what KyIdentity's internal/mfa PushResponseMessage builds.
    private const val PREFIX = "kyidentity-push-v2"
    private val PURPOSES = setOf("login", "step_up")

    /** scheme://host[:port], lowercased, default port dropped; the same rule KyIdentity uses. */
    fun origin(serverUrl: String): String {
        val uri = runCatching { java.net.URI(serverUrl.trim()) }.getOrNull()
        val scheme = uri?.scheme?.lowercase()
        val host = uri?.host?.lowercase()
        require(scheme != null && !host.isNullOrBlank()) { "Server URL has no origin" }
        val port = uri.port.takeUnless { it == -1 || (scheme == "https" && it == 443) || (scheme == "http" && it == 80) }
        return if (port == null) "$scheme://$host" else "$scheme://$host:$port"
    }

    /** The exact bytes the device key signs to answer a challenge; see the push v2 spec. */
    fun formatPayload(
        origin: String, userId: String, deviceId: String, challengeId: String,
        purpose: String, expiresAtMs: Long, approve: Boolean, selectedDigits: String,
    ): ByteArray {
        require(purpose in PURPOSES) { "Unknown push purpose" }
        for (field in listOf(origin, userId, deviceId, challengeId)) {
            require(field.isNotEmpty() && '|' !in field) { "Invalid push binding field" }
        }
        require('|' !in selectedDigits) { "Invalid digits" }
        val verb = if (approve) "approve" else "deny"
        return listOf(PREFIX, origin, userId, deviceId, challengeId, purpose, expiresAtMs.toString(), verb, selectedDigits)
            .joinToString("|").toByteArray(Charsets.UTF_8)
    }
}
```

- [ ] **Step 4: Run** the test — Expected: PASS. (Other call sites break until Task 3.)

### Task 2: Strict parser

**Files:**
- Modify: `app/src/main/java/org/kysecurity/authenticator/mfa/MfaPushChallengeStore.kt` (`MfaPushChallengeParser.parse`)
- Modify: `app/src/main/java/org/kysecurity/authenticator/mfa/MfaChallenge.kt` (`purpose` has no default; drop the `"session"` default)
- Modify: `app/src/main/java/org/kysecurity/authenticator/mfa/KyAuthMessagingService.kt` (pass the paired account)
- Modify: `app/src/test/java/org/kysecurity/authenticator/mfa/MfaPushChallengeParserTest.kt`

**Interfaces:**
- Produces: `MfaPushChallengeParser.parse(data: Map<String, String>, paired: PairedAccount?, nowMs: Long = System.currentTimeMillis()): MfaChallenge`.

- [ ] **Step 1: Failing tests.** Rework the parser test fixtures to pass a `PairedAccount("https://id.example.com", "d-456", "Pixel", "alice", "u-123", canSignOn = false)` and a payload with `challengeId`, `deviceId=d-456`, `deviceUserId=u-123`, `purpose=login`, `expiresAtEpochMs=now+60_000`. Keep the existing tests that still apply (payload server URL ignored, digits/decoys validation). Add: missing `purpose` → throws; `purpose=session` → throws; missing `expiresAtEpochMs` → throws; expiry `now+11 min` → throws (not clamped); expiry in the past → throws; `deviceId=d-999` → throws; `deviceUserId=u-999` → throws; paired account with `userId = null` → throws; `null` pairing → throws; the seconds-based `expiresAt` alias is no longer accepted.
- [ ] **Step 2: Run** `./gradlew testDebugUnitTest --tests '*MfaPushChallengeParserTest*'` — Expected: FAIL.
- [ ] **Step 3: Implement.** `parse` requires `paired` with non-blank `serverUrl`, `deviceId`, `userId`; requires `data["deviceId"] == paired.deviceId` and `data["deviceUserId"] == paired.userId`; reads `purpose` ∈ {`login`,`step_up`} and `expiresAtEpochMs` (Long) with `nowMs < expiry <= nowMs + MAX_EXPIRES_AFTER_MS`; drops `DEFAULT_EXPIRES_AFTER_MS` and the clamp; keeps `serverUrl = paired.serverUrl`. Update the KDoc to say pushes for another device or account are refused. `KyAuthMessagingService` passes `PairingStore(this).account()` (inside its existing `runCatching`).
- [ ] **Step 4: Run** the test — Expected: PASS.

### Task 3: Respond with v2; show purpose

**Files:**
- Modify: `app/src/main/java/org/kysecurity/authenticator/mfa/MfaResponseClient.kt` (`respond` gains `deviceId: String`, sent as `"deviceId"`)
- Modify: `app/src/test/java/org/kysecurity/authenticator/mfa/MfaResponseClientTest.kt` (if it builds requests)
- Modify: `app/src/main/java/org/kysecurity/authenticator/MainActivity.kt` (`onNumberSelected`, `onDenyClicked`, `renderPendingChallenge`)
- Modify: `app/src/androidTest/java/org/kysecurity/authenticator/VaultTabTest.kt` (fixture challenge gets `purpose = "login"`; assert the card shows "Sign-in request")
- Modify: `AGENTS.md`

- [ ] **Step 1: Failing test.** In `VaultTabTest`, change the expected card title from "Sign-in Request" to "Sign-in request" and give fixture challenges `purpose = "login"`. Add a `step_up` fixture case asserting "Confirm a sensitive action".
- [ ] **Step 2: Run** `./gradlew compileDebugAndroidTestSources` — Expected: compiles; (device run is CI's).
- [ ] **Step 3: Implement.**
  - `onNumberSelected`: `val paired = store.account()` (fail with the existing error toast if null or `userId` null); payload = `MfaMessage.formatPayload(MfaMessage.origin(paired.serverUrl), paired.userId, paired.deviceId, challenge.challengeId, challenge.purpose, challenge.expiresAtEpochMs, approve = true, selectedDigit)`; call `respond(..., deviceId = paired.deviceId, ...)`.
  - `onDenyClicked`: same, `approve = false`, digits `""` (not `challenge.matchDigits`).
  - `renderPendingChallenge`: card title `if (challenge.purpose == "step_up") "Confirm a sensitive action" else "Sign-in request"`.
- [ ] **Step 4: AGENTS.md.** Frozen-identifiers bullet: the push prefix is now `kyidentity-push-v2` (must equal KyIdentity `internal/mfa` `PushResponseMessage`); `kysignon-push-token-v1` and the Keystore alias are unchanged. Push MFA bullet: pushes must name this device and account and carry `purpose` (`login`|`step_up`) and `expiresAtEpochMs` (≤ 10 minutes ahead), else they are refused; the card shows the purpose. Delete the "Push MFA payload binding" outstanding-work item.
- [ ] **Step 5: Run** `./gradlew test assembleDebug lintDebug compileDebugAndroidTestSources` — Expected: PASS. Then `./gradlew --stop`.
- [ ] **Step 6: Commit** (local only):

```bash
git add -A
git commit -m "feat(mfa): sign push v2 binding origin, user, device, purpose and expiry"
```
