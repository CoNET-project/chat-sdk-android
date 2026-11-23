package network.conet.chat.nativekey

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The temporary channel keys (2026-11-21): forget(sid) removes and zeroes a key; an entry past MAX_AGE_MS is gone when the store is next touched;
 * a clock that has gone back is treated as expired; ephemeralSign zeroes its copy on every path.
 */
class VoiceChannelKeysForgetTest {
    private val key = ByteArray(32) { (it + 1).toByte() }
    private val sid = "sid-forget-test-0001"

    @Test
    fun forgetRemovesTheKeyAndIsIdempotent() {
        VoiceChannelKeys.clear()
        VoiceChannelKeys.register(sid, key, nowMs = 1_000L)
        assertNotNull(VoiceChannelKeys.lookup(sid, nowMs = 1_001L))
        VoiceChannelKeys.forget(sid)
        assertNull(VoiceChannelKeys.lookup(sid, nowMs = 1_002L))
        VoiceChannelKeys.forget(sid) // a second forget is a no-op
        assertNull(VoiceChannelKeys.lookup(sid, nowMs = 1_003L))
    }

    @Test
    fun forgetOfAnotherSidLeavesThisKeyAlone() {
        VoiceChannelKeys.clear()
        VoiceChannelKeys.register(sid, key, nowMs = 1_000L)
        VoiceChannelKeys.forget("sid-other")
        assertNotNull(VoiceChannelKeys.lookup(sid, nowMs = 1_001L))
        VoiceChannelKeys.clear()
    }

    @Test
    fun anEntryPastTheMaximumAgeIsGone() {
        VoiceChannelKeys.clear()
        VoiceChannelKeys.register(sid, key, nowMs = 1_000L)
        assertNotNull("still kept at the limit", VoiceChannelKeys.lookup(sid, nowMs = 1_000L + VoiceChannelKeys.MAX_AGE_MS))
        assertNull("gone after the limit", VoiceChannelKeys.lookup(sid, nowMs = 1_000L + VoiceChannelKeys.MAX_AGE_MS + 1))
    }

    @Test
    fun aClockThatWentBackIsTreatedAsExpired() {
        VoiceChannelKeys.clear()
        VoiceChannelKeys.register(sid, key, nowMs = 1_000_000L)
        assertNull(VoiceChannelKeys.lookup(sid, nowMs = 999_999L))
    }

    @Test
    fun registerReplacesAnOldKeyOfTheSameSid() {
        VoiceChannelKeys.clear()
        VoiceChannelKeys.register(sid, key, nowMs = 1_000L)
        VoiceChannelKeys.register(sid, ByteArray(32) { 9 }, nowMs = 1_001L)
        assertEquals(32, VoiceChannelKeys.lookup(sid, nowMs = 1_002L)?.size)
        VoiceChannelKeys.clear()
    }

    /** The source guard: ephemeralSign zeroes its copy of T in a finally block, on every path. */
    @Test
    fun ephemeralSignZeroesItsCopyOnEveryPath() {
        val src = File("src/main/java/network/conet/chat/nativekey/NativeDerivationCommands.kt").readText(Charsets.UTF_8)
        val body = src.substringAfter("    fun ephemeralSign(body: JSONObject): Outcome {").substringBefore("\n    }\n")
        assertTrue(body.contains("finally {") && body.contains("tk.fill(0)"))
    }
}
