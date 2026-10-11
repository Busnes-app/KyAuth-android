package org.kysecurity.authenticator.mfa

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/** Push services must hand data to IncomingPush; a service parsing it itself could skip a check. */
class PushServiceSourceRuleTest {
    private val services = File("src").walkTopDown().filter { it.name.endsWith("Service.kt") }.toList()

    @Test
    fun noServiceCallsTheParserDirectly() {
        assertTrue("no service sources found from ${File("").absolutePath}", services.isNotEmpty())
        services.forEach { assertFalse("${it.path} calls MfaPushChallengeParser", "MfaPushChallengeParser" in it.readText()) }
    }

    @Test
    fun bothPushServicesUseIncomingPush() {
        val push = services.filter { it.name in setOf("KyAuthMessagingService.kt", "KyAuthUnifiedPushService.kt") }
        assertEquals(2, push.size)
        push.forEach { assertTrue("${it.path} bypasses IncomingPush", "IncomingPush.handle(" in it.readText()) }
    }
}
