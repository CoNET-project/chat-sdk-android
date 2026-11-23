package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * The SRP-04 write-failure envelope (interface PROTOCOL-srp04-write-failed-reason-and-android-correction-2026-11-22): {ok:false, error:"write_failed"} with the
 * optional reason at the top level, from the closed set; a reason outside the set, or none, is internal_state. Other failures keep their shape.
 */
class NativeSyncAckWriteEnvelopeTest {

    @Test
    fun theReasonIsTopLevelAndFromTheClosedSet() {
        val storage = NativeSyncAck.writeFailedEnvelope("w1", NativeSyncAck.STORAGE_WRITE)
        assertEquals(false, storage.getBoolean("ok"))
        assertEquals("write_failed", storage.getString("error"))
        assertEquals("storage_write", storage.getString("reason"))
        assertFalse("the reason is not inside result", storage.has("result"))
        assertEquals("w1", storage.getString("reqId"))
        assertEquals(setOf("internal_state", "storage_write", "rollback_pending", "old_copy_unverified"), NativeSyncAck.WRITE_FAILURE_REASONS)
        for (r in NativeSyncAck.WRITE_FAILURE_REASONS) {
            assertEquals(r, NativeSyncAck.writeFailedEnvelope("w", r).getString("reason"))
        }
    }

    @Test
    fun aReasonOutsideTheSetOrNoneIsInternalState() {
        assertEquals("internal_state", NativeSyncAck.writeFailedEnvelope("w", "not_a_reason").getString("reason"))
        assertEquals("internal_state", NativeSyncAck.writeFailedEnvelope("w", null).getString("reason"))
        assertEquals("write_failed", NativeSyncAck.writeFailedEnvelope("w", null).getString("error"))
    }

    /** Source guard: every write-failure answer of pwaWalletSync goes through writeFailedAck, and no write failure still uses the old ack(reason) form. */
    @Test
    fun pwaWalletSyncWriteFailuresUseTheEnvelope() {
        val module = File("src/main/java/network/conet/chat/BeamioConetChatModule.kt").readText(Charsets.UTF_8)
        val start = module.indexOf("private fun pwaWalletSyncCommand(")
        val end = module.indexOf("private fun pwaWalletSyncCipher(")
        val sync = module.substring(start, end)
        assertFalse("no write failure is answered with the old ack reason form", sync.contains("error = NativeSyncAck.WRITE_FAILED, reason"))
        assertTrue("the write failures use writeFailedAck", sync.contains("writeFailedAck(reqId, NativeSyncAck.STORAGE_WRITE)"))
        assertTrue("the cipher write failure uses the envelope too", module.substring(module.indexOf("private fun pwaWalletSyncCipher(")).contains("writeFailedAck(reqId, NativeSyncAck.INTERNAL_STATE)"))
    }
}
