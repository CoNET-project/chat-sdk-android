package network.conet.chat.nativekey

import java.io.File
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * `firstIdentityStatus`: the five keys at most, the five states, the listed reasons, a terminal state not
 * overwritten, a failed read as retry_later (never a generation), and the QA-only capability name. (N-11 to N-13.)
 */
class FirstIdentityStatusTest {
    private val sent = ArrayList<JSONObject>()

    @Before
    fun install() {
        FirstIdentityEvents.resetForTests()
        FirstIdentityCoordinator.resetAttemptsForTests()
        sent.clear()
        FirstIdentityEvents.enabled = true
        FirstIdentityEvents.sink = { sent += it }
    }

    @After
    fun restore() {
        FirstIdentityEvents.enabled = network.conet.chat.BuildConfig.IDENTITY_STATE_EVENTS_QA
        FirstIdentityEvents.sink = null
        FirstIdentityEvents.resetForTests()
    }

    private val allowedKeys = setOf("type", "state", "reason", "attempt", "retryAfterMs")

    @Test
    fun theEventHasTheWhitelistedKeysAndTheFiveStatesOnly() {
        for (state in listOf("registering", "registered", "retry_later", "identity_pending", "failed")) {
            FirstIdentityEvents.resetForTests()
            FirstIdentityEvents.emit("0x" + "ab".repeat(20), FirstIdentityStatus(state, "read_unavailable", 2, 60_000))
        }
        assertEquals(5, sent.size)
        for (e in sent) {
            assertEquals("firstIdentityStatus", e.getString("type"))
            assertTrue(e.keys().asSequence().all { it in allowedKeys })
        }
        assertTrue("retryAfterMs only on retry_later", sent.filter { it.has("retryAfterMs") }.all { it.getString("state") == "retry_later" })
        FirstIdentityEvents.emit("0x" + "cd".repeat(20), FirstIdentityStatus("bogus"))
        assertEquals("an unknown state is not sent", 5, sent.size)
        // A reason outside the list is dropped, never sent.
        sent.clear()
        FirstIdentityEvents.emit("0x" + "ef".repeat(20), FirstIdentityStatus("retry_later", "secret detail", 1, 1))
        assertFalse(sent.single().has("reason"))
        assertEquals(setOf("no_record_confirmed", "read_unavailable", "submit_5xx", "submit_4xx", "conflict_other_key", "readback_timeout"), FirstIdentityEvents.REASONS)
    }

    @Test
    fun noAccountKeyArmorFingerprintSignatureTagOrPasswordIsEverInTheEvent() {
        val account = "0x" + "ab".repeat(20)
        FirstIdentityEvents.emit(account, FirstIdentityStatus("registering", "no_record_confirmed"))
        val text = sent.single().toString()
        assertFalse(text.contains(account) || text.contains("ab".repeat(20)))
        val src = File("src/main/java/network/conet/chat/nativekey/FirstIdentityEvents.kt").readText()
        assertFalse(src.contains("armor") && src.contains("put(\"armor"))
    }

    @Test
    fun aTerminalStateIsNotOverwrittenInTheSameProcess() {
        val a = "0x" + "11".repeat(20)
        FirstIdentityEvents.emit(a, FirstIdentityStatus("registering"))
        FirstIdentityEvents.emit(a, FirstIdentityStatus("registered"))
        FirstIdentityEvents.emit(a, FirstIdentityStatus("retry_later", "read_unavailable", 1, 1))
        FirstIdentityEvents.emit(a, FirstIdentityStatus("failed", "conflict_other_key"))
        assertEquals(listOf("registering", "registered"), sent.map { it.getString("state") })
        sent.clear()
        val b = "0x" + "22".repeat(20)
        FirstIdentityEvents.emit(b, FirstIdentityStatus("failed", "submit_4xx"))
        FirstIdentityEvents.emit(b, FirstIdentityStatus("registered"))
        assertEquals("failed is terminal too; another account is separate", listOf("failed"), sent.map { it.getString("state") })
    }

    @Test
    fun aDisabledBuildSendsNothing() {
        FirstIdentityEvents.enabled = false
        FirstIdentityEvents.emit("0x" + "33".repeat(20), FirstIdentityStatus("registered"))
        assertTrue(sent.isEmpty())
        assertEquals("a production build has the events off", false, network.conet.chat.BuildConfig.IDENTITY_STATE_EVENTS_QA)
    }

    @Test
    fun theQaCapabilityNameIsDeclaredOnlyInAQaBuild() {
        assertEquals("identity.first.status.v1", FirstIdentityEvents.CAPABILITY)
        assertFalse("not declared in this (production) build", network.conet.chat.BeamioConetChatProtocol.CAPABILITIES.contains(FirstIdentityEvents.CAPABILITY))
        val src = File("src/main/java/network/conet/chat/BeamioConetChatProtocol.kt").readText()
        assertTrue(src.contains("FirstIdentityEvents.CAPABILITY.takeIf { BuildConfig.IDENTITY_STATE_EVENTS_QA }"))
    }
}
