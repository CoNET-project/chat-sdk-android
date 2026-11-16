package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * kPresent (25.48.4, 25.52Y.90, reviewer correction): a boolean on the identityPublic G0 `no_key` answer only. It is never part of the
 * ready answer. Unknown is left out, never sent as false.
 */
class IdentityPublicKPresentTest {
    private class FakeSource(private val k: Boolean?) : IdentityPublic.Source {
        override fun eoa(): String? = "0x" + "a".repeat(40)
        override fun pgp(): IdentityPublic.PgpRecord = IdentityPublic.PgpRecord.NotRead
        override fun kPresent(): Boolean? = k
    }

    private fun g0(k: Boolean?): org.json.JSONObject {
        val reply = IdentityPublic.answer(NoKeyGate.Gate.G0, { emptyList() }, "r1", FakeSource(k))
        return IdentityPublic.ackPayload("r1", reply)
    }

    /** K present on the device, no key for the account: kPresent is true, the answer is no_key. */
    @Test
    fun keyPresentWithoutAKeyReportsTrue() {
        val p = g0(true)
        assertEquals("no_key", p.getString("error"))
        assertFalse(p.getBoolean("ok"))
        assertTrue(p.getBoolean("kPresent"))
    }

    /** No K on the device, no key: kPresent is false (confirmed_none material, 25.52Y.89). */
    @Test
    fun noKeyOnTheDeviceReportsFalse() {
        val p = g0(false)
        assertEquals("no_key", p.getString("error"))
        assertFalse(p.getBoolean("kPresent"))
    }

    /** The K store cannot be read: kPresent is left out. Unknown is never false. */
    @Test
    fun unreadableStoreLeavesKPresentOut() {
        val p = g0(null)
        assertEquals("no_key", p.getString("error"))
        assertFalse("unknown is not sent as false", p.has("kPresent"))
    }

    /** The ready answer carries no kPresent, at the result or the top level. */
    @Test
    fun readyAnswerHasNoKPresent() {
        val reply = IdentityPublic.answer(NoKeyGate.Gate.G2, { emptyList() }, "r2", FakeSource(true))
        val p = IdentityPublic.ackPayload("r2", reply)
        assertTrue(p.getBoolean("ok"))
        assertFalse(p.has("kPresent"))
        assertFalse(p.getJSONObject("result").has("kPresent"))
    }

    /** G1 (not_ready) is not the no_key answer, so it carries no kPresent. */
    @Test
    fun notReadyAnswerHasNoKPresent() {
        val reply = IdentityPublic.answer(NoKeyGate.Gate.G1, { emptyList() }, "r3", FakeSource(true))
        val p = IdentityPublic.ackPayload("r3", reply)
        assertEquals("not_ready", p.getString("error"))
        assertFalse(p.has("kPresent"))
    }
}
