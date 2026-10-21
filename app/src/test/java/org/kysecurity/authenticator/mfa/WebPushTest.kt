package org.kysecurity.authenticator.mfa

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test
import org.kysecurity.authenticator.pairing.PairedAccount
import org.kysecurity.authenticator.pairing.PushKeys

/** The vectors KyAuth iOS (`PushCryptoTests.swift`) and KyIdentity (`push_ubuntupush_test.go`) pin. */
object PushVectors {
    // RFC 8291 section 5: the receiver's private key, public key and auth secret.
    const val RECEIVER_PRIVATE = "q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94"
    const val RECEIVER_P256DH = "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4"
    const val AUTH = "BTBZMqHH6r4Tts7J_aSIgg"
    val keys: PushKeys get() = PushKeys.fromScalar(PushKeys.unb64(RECEIVER_PRIVATE), RECEIVER_P256DH, AUTH)

    // RFC 8291 appendix A: the encrypted body of "When I grow up, I want to be a watermelon".
    const val RFC_BODY = "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27ml" +
        "mlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPT" +
        "pK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN"

    // KyIdentity's RelaySender output for the receiver above: challengeData for device dev-1, user
    // user-1, challenge ch-1, purpose step_up, expiry 1791331200000, sealed by webPushEncrypt into
    // its fixed 640-byte record (968 characters, under the relay's 1024). Copied from KyAuth iOS.
    const val SERVER_SEALED = "d33DjOr9uO2oM7mddWPOWAAAAoBBBItc_L_nZrU3cfOUtB9bJioq9m6I3zMq4q0NPJe6LPUC3GIqIlT4aN9q8wJIHXEU6yV3" +
        "y8cmaV5HBtWvmNUwPOsbUf5LoRA3NOmyvJcRDABvPtaubVBJGIniwIu5fW3CgPaZIDrQaz2nEvVbJqStd8iRuEpDoZq7icd8jgkZT4gzY0wdVGwFMC4P" +
        "ki2_lWltLAz29alnTbbXLIG6pgTCORMk7EgOfEhf5a9quDgmEA151BIUvVgPl1AuNuFKnmyX48Obs3vb7keNlZZ25m9nRYe2I5RQEUj40IpKWOZX9yqA" +
        "0i7UrukRCRHgBF_MryFAWA3dOpQHIIXk0tod1xek_ZQkhgOIeg6m9pX2VDz8y1dryPRH9d6KXOewRIBEbi4rZvNm330ANRGuSXimOAqclcEHvArRatzg" +
        "loBB8LiYwosnXhpsjUvHwDOzGkW4GPlzRNIIBtLJzcCWoFSNu1KD-1AMAo3uBPmgG9UCi1g5OLd6K8_mkn_njMh_9_BSbjrf6kTiVoITgZ7cQSPEq6Uf" +
        "E8C0MJnL8uVvmy9cTpwBcfhQLDNOO21jFE4w2znDk9JnutWTF0A6QExhxLXmtmAyof19XOzNAHgq8NJ27kPDwqc85A2RbxbSBKPV34i5aXw-hwdtBxqe" +
        "02HrWy01gILm-SDh7u6SutG3QPgnO8zgjnPLz-KB5WMJC-6ybBt-L4X5MXH9eFpjxC2CHDLU_4OU9X-2qIK-QfhOY-6xQt5fOq7MG53QoqWg9Q0DwxoH" +
        "p8y_HTB7-EHbrYB7ukroZAbso9gPKsZZaWlFZ-0xE6BiEHgSE1IzZ28s10UHoRhvYGCTa2A6-rquFY4Jh8uTjaiWZCUrIgkHVY_TlDwnKsS-i2Ax0G5Q" +
        "9cQUu7upBB5-7EY3yg2IYN5AvqnvmN1BEkU58T2cG_YgWJfThuXUgIYavjvv"

    // The same challenge, platform android, with the username KyIdentity adds to sealed payloads
    // only (`sealedChallenge`, username alice), from its RelaySender into the same 640-byte record.
    const val SERVER_SEALED_WITH_USERNAME = "Dmlo7C6dU8cKAAnEew80OwAAAoBBBJXRNp_5ly-QvFfQ4b7zWuJHbFJXs0uoAKxksljotUC25RSje2xMbMGYDw3Cf_-EnKfS" +
        "xVEwaw40Ypl2mwH5eq3NWj3LglzNLBifPr2Sh5GGcNY7kA5cpRM2C2_x6yJHcM562QIHjUfKBNaWP3c2xBCmwoTRnoizuHhg_lt0d8kFEKBfDzr-Zl" +
        "OpNxFDMh3BDN037EDuqbWrDiI9tzKxj2f33czPKwDkqPB0IAoW4TYTrIv9e41Yb0HTQenBjKKZFHa0eQjt88jvtxIKGdicFH_XbYrSiOOrXzASg4BN" +
        "UNZAo8FrpcrhD8fnOwocD_0nVkaC0eUrDCl_-Z3bnxmhSJvjBw8vrz63qAcJRY7iZVOvjRU7KyNKXOcr-xOJOQ5WkpcV_WvksFSL1CZPFe7TsSDK8m" +
        "G3YgwzlvN2V3CaA_s7HC20Xqr8MwJliTHPZd9fqfFml2jug-AjndonpMryGnc4n6u8vEoIwrFPivWhhH93gNZhnVgyBDahTrHqrfExe_kn7kyMalzt" +
        "VvZVTyDjp7n8nkqq9lJFSjKW1y1FND0CU79Kaepg5HuQasfox9Fs3RFZjNii2k5EvNhbv0YDEYIasO7fyKF-vuPNmfuqazjWkD7qyDPSZBTdnEWhDw" +
        "1m4LO3XEPBhOhPv83uHbtu7q7uouI_eTpxYyY06R-qhDXPZ3SZbh6PBEP0PmIN0EYzVFCPuTy_j0pKrH7sAbT6YTFpRj0XiPqVWTTr2--rIZg3OzN8" +
        "f-YNLc-x_IaKNnqfpJSPdQoG7e6FCzcv_K42T9mPvX_fl-5Cr7_CMPYk1ANRVgm8y4iQW3WHDi7oDPsycFBONwB_V0-hFQboImYQeHKAuJvhvu0jEN" +
        "PU6rDRVtlZApgG_VXDG5kzsPn2hLAJLiddQJ_l_PJxLeLCc_lidei2ksMQzsxNdZwlyeXHqsh5"
}

class WebPushTest {
    private val keys = PushVectors.keys
    private val body = PushKeys.unb64(PushVectors.RFC_BODY)

    @Test
    fun decryptsRfc8291Example() {
        assertEquals(PushVectors.RECEIVER_P256DH, keys.p256dh)
        assertEquals(PushVectors.AUTH, keys.auth)
        assertEquals("When I grow up, I want to be a watermelon", String(WebPush.decrypt(body, keys), Charsets.UTF_8))
    }

    @Test
    fun refusesTamperingAndOtherKeys() {
        val flipped = body.copyOf().also { it[it.size - 20] = (it[it.size - 20].toInt() xor 1).toByte() }
        assertThrows(Exception::class.java) { WebPush.decrypt(flipped, keys) }
        val otherAuth = PushKeys(keys.privateKey, keys.publicPoint, ByteArray(16) { 7 })
        assertThrows(Exception::class.java) { WebPush.decrypt(body, otherAuth) }
        assertThrows(Exception::class.java) { WebPush.decrypt(body, PushKeys.generate()) }
        assertThrows(Exception::class.java) { WebPush.decrypt(body.copyOf(100), keys) }
    }

    @Test
    fun refusesMoreThanOneRecord() {
        val split = body.copyOf().also { it[16] = 0; it[17] = 0; it[18] = 0; it[19] = 32 } // record size 32; the record is 58 bytes
        assertThrows(Exception::class.java) { WebPush.decrypt(split, keys) }
    }

    @Test
    fun refusesSenderKeyOffTheCurve() {
        val offCurve = body.copyOf().also { it[85] = (it[85].toInt() xor 1).toByte() }
        assertThrows(IllegalArgumentException::class.java) { WebPush.decrypt(offCurve, keys) }
    }
}

class SealedFcmPushTest {
    private val keys = PushVectors.keys
    private val paired = PairedAccount("https://id.example.com", "dev-1", "Pixel", userId = "user-1")
    private val now = 1_791_331_140_000L
    private val plaintext = mapOf(
        "type" to "mfa_challenge", "deviceId" to "dev-1", "deviceUserId" to "user-1", "challengeId" to "ch-1",
        "purpose" to "login", "expiresAtEpochMs" to "1791331200000",
    )
    private val sealed = mapOf("type" to "mfa_challenge", "kyauth" to PushVectors.SERVER_SEALED)

    /** The whole FCM receive path against KyIdentity's own sealing. */
    @Test
    fun opensServerSealedChallenge() {
        val fields = IncomingPush.fcmData(sealed, keys, plaintextAllowed = false)!!
        assertEquals("mfa_challenge", fields["type"])
        val challenge = IncomingPush.challenge(fields, paired, now)!!
        assertEquals("ch-1", challenge.challengeId)
        assertEquals("step_up", challenge.purpose)
        assertEquals(1_791_331_200_000L, challenge.expiresAtEpochMs)
        assertNull(challenge.username)
    }

    @Test
    fun opensServerSealedUsername() {
        val fields = IncomingPush.fcmData(mapOf("type" to "mfa_challenge", "kyauth" to PushVectors.SERVER_SEALED_WITH_USERNAME), keys, plaintextAllowed = false)!!
        val challenge = IncomingPush.challenge(fields, paired, now)!!
        assertEquals("ch-1", challenge.challengeId)
        assertEquals("alice", challenge.username)
    }

    // KyIdentity never sends a username unsealed, so one in a plaintext push was put there in transit.
    @Test
    fun plaintextUsernameIsDropped() {
        val fields = IncomingPush.fcmData(plaintext + ("username" to "mallory") + ("user" to "mallory"), null, plaintextAllowed = true)!!
        assertNull(IncomingPush.challenge(fields, paired, now)!!.username)
    }

    @Test
    fun onlyTheSealedFieldsAreUsed() {
        val fields = IncomingPush.fcmData(sealed + ("purpose" to "login") + ("challengeId" to "injected"), keys, plaintextAllowed = true)!!
        assertEquals("ch-1", fields["challengeId"])
        assertEquals("step_up", fields["purpose"])
    }

    @Test
    fun pairingWithKeysRefusesPlaintext() {
        assertNull(IncomingPush.fcmData(plaintext, keys, plaintextAllowed = false))
        assertNull(IncomingPush.fcmData(plaintext, null, plaintextAllowed = false))
    }

    @Test
    fun keylessPairingReadsPlaintextButNotSealed() {
        assertEquals("ch-1", IncomingPush.fcmData(plaintext, null, plaintextAllowed = true)?.get("challengeId"))
        assertNull(IncomingPush.fcmData(sealed, null, plaintextAllowed = true))
    }

    @Test
    fun refusesUnreadableSealedPayload() {
        assertNull(IncomingPush.fcmData(mapOf("kyauth" to "not base64url!"), keys, plaintextAllowed = true))
        assertNull(IncomingPush.fcmData(mapOf("kyauth" to PushVectors.RFC_BODY), keys, plaintextAllowed = true)) // not JSON
        assertNull(IncomingPush.fcmData(sealed, PushKeys.generate(), plaintextAllowed = true))
    }

    @Test
    fun rfcKeysRoundTripTheirStoredForm() {
        val restored = PushKeys.decode(keys.encode())!!
        assertArrayEquals(keys.publicPoint, restored.publicPoint)
        assertEquals("ch-1", IncomingPush.fcmData(sealed, restored, plaintextAllowed = false)?.get("challengeId"))
    }
}
