package org.kysecurity.authenticator.totp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import java.nio.charset.StandardCharsets;

/**
 * Fuzzes {@link TotpUriParser}, which reads the {@code otpauth://} URI in any QR code the user
 * scans to add an account. Whoever made that QR code controls every byte of it.
 *
 * <p>Java on purpose: OpenSSF Scorecard detects Jazzer only in {@code .java} files.
 *
 * <p>A plain unit-test run replays the seeds in
 * {@code src/test/resources/org/kysecurity/authenticator/totp/TotpUriParserFuzzTestInputs/parse/}
 * plus an empty input. Fuzz it for real with {@code JAZZER_FUZZ=1}; see app/src/test/AGENTS.md.
 */
class TotpUriParserFuzzTest {

    @FuzzTest(maxDuration = "60s")
    void parse(FuzzedDataProvider data) {
        long now = data.consumeLong();
        String uri = new String(data.consumeRemainingAsBytes(), StandardCharsets.UTF_8);

        TotpEntry entry;
        try {
            entry = TotpUriParser.INSTANCE.parse(uri);
        } catch (Exception refused) {
            // MainActivity turns any exception into "Invalid OTP QR code". An Error (stack
            // overflow, out of memory) is not caught here and fails the fuzz test.
            return;
        }

        // What the scan admits must be an entry the vault can store and the code screen can show.
        assertFalse(entry.getTitle().isBlank());
        assertTrue(entry.getDigits() >= 6 && entry.getDigits() <= 8);
        assertTrue(entry.getPeriodSeconds() > 0);
        assertTrue(TotpGenerator.INSTANCE.isUsableSecret(entry.getSecretBase32()));

        String code = TotpGenerator.INSTANCE.generate(entry, now);
        assertEquals(entry.getDigits(), code.length(), code);
        assertTrue(code.chars().allMatch(c -> c >= '0' && c <= '9'), code);
        long remaining = TotpGenerator.INSTANCE.secondsRemaining(entry, Math.max(now, 0));
        assertTrue(remaining >= 1 && remaining <= entry.getPeriodSeconds());
    }
}
