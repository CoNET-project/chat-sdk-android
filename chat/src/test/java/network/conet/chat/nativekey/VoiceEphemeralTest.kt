package network.conet.chat.nativekey

import java.security.SecureRandom
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Shell-mode temporary material (v105 §112, 2026-11-21): prepare returns only public fields and the channel keys; the temporary key is held by sid;
 * forget removes it and is idempotent; bad input and generation failures give the stated codes. The phrase and the main wallet are not inputs.
 */
class VoiceEphemeralTest {
    private val sid = "sid-ephemeral-0001"

    @Test
    fun prepareWithoutPgpReturnsPublicFieldsOnlyAndHoldsTheKeyBySid() {
        VoiceChannelKeys.clear()
        val r = VoiceEphemeral.prepare("caller", sid, false, SecureRandom())
        assertTrue(r.getBoolean("ok"))
        val c = r.getJSONObject("channel")
        assertEquals(sid, c.getString("sid"))
        assertTrue(Regex("^0x[0-9a-f]{40}$").matches(c.getString("temp")))
        // Standard base64 of 32 bytes: 44 characters with one = pad (v113 §130).
        assertTrue(Regex("^[A-Za-z0-9+/]{43}=$").matches(c.getString("key")))
        assertTrue(Regex("^[A-Za-z0-9+/]{43}=$").matches(c.getString("wk")))
        assertEquals(32, java.util.Base64.getDecoder().decode(c.getString("key")).size)
        assertFalse("no PGP fields without needPgp", c.has("tempPgpArmor") || c.has("tempPgpFpr"))
        assertTrue("the temporary wallet key is held", VoiceChannelKeys.lookup(sid) != null)
        VoiceChannelKeys.clear()
    }

    @Test
    fun prepareWithPgpReturnsThePublicArmorAndKeepsThePrivateInside() {
        VoiceChannelKeys.clear()
        val r = VoiceEphemeral.prepare("callee", sid, true, SecureRandom())
        val c = r.getJSONObject("channel")
        assertTrue(c.getString("tempPgpArmor").contains("BEGIN PGP PUBLIC KEY"))
        assertFalse("the private armor never leaves", c.getString("tempPgpArmor").contains("PRIVATE"))
        assertTrue(c.getString("tempPgpFpr").isNotEmpty())
        assertTrue(VoiceEphemeral.holdsPgpFor(sid))
        VoiceEphemeral.forget(sid)
        VoiceChannelKeys.clear()
    }

    @Test
    fun twoPreparesGiveIndependentTemporaryAddresses() {
        VoiceChannelKeys.clear()
        val a = VoiceEphemeral.prepare("caller", "sid-indep-0001", false, SecureRandom()).getJSONObject("channel").getString("temp")
        val b = VoiceEphemeral.prepare("caller", "sid-indep-0002", false, SecureRandom()).getJSONObject("channel").getString("temp")
        assertNotEquals(a, b)
        VoiceEphemeral.forget("sid-indep-0001")
        VoiceEphemeral.forget("sid-indep-0002")
        VoiceChannelKeys.clear()
    }

    @Test
    fun badInputIsBadRequest() {
        assertEquals("bad_request", VoiceEphemeral.prepare("host", sid, false).getString("error"))
        assertEquals("bad_request", VoiceEphemeral.prepare("caller", "", false).getString("error"))
        assertEquals("bad_request", VoiceEphemeral.prepare("caller", sid, "yes").getString("error"))
        assertEquals("bad_request", VoiceEphemeral.prepare(null, sid, false).getString("error"))
    }

    @Test
    fun aGenerationFailureIsKeygenFailedAndNothingIsHeld() {
        VoiceChannelKeys.clear()
        val r = VoiceEphemeral.prepare("caller", sid, true, SecureRandom()) { _, _ -> throw IllegalStateException("injected") }
        assertEquals("keygen_failed", r.getString("error"))
        assertNull(VoiceChannelKeys.lookup(sid))
        assertFalse(VoiceEphemeral.holdsPgpFor(sid))
    }

    @Test
    fun forgetRemovesTheMaterialAndIsIdempotent() {
        VoiceChannelKeys.clear()
        VoiceEphemeral.prepare("caller", sid, true, SecureRandom())
        assertTrue(VoiceEphemeral.forget(sid).getBoolean("ok"))
        assertNull(VoiceChannelKeys.lookup(sid))
        assertFalse(VoiceEphemeral.holdsPgpFor(sid))
        assertTrue("forget again is ok", VoiceEphemeral.forget(sid).getBoolean("ok"))
        assertTrue("forget of an unknown sid is ok", VoiceEphemeral.forget("sid-unknown-0001").getBoolean("ok"))
    }
}
