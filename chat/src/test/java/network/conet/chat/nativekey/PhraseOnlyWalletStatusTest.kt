package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The walletStatus answer of a readable phrase without the key record (spec §25.52Y.117, §25.52Y.118): at G2 it is `locked` with the
 * accountKey of the account pointer and `reason` `phrase_only`; at G1 it is `not_ready` with `g1_uninitialized`. Without a readable
 * pointer the G2 answer is unknown (`not_ready`, `unreadable`), never `no_key` and never a lock without its account.
 */
class PhraseOnlyWalletStatusTest {
    private val pointer = "0x" + "ab".repeat(20)
    private val phraseOnly = NativeWalletVault.State.Locked(NativeWalletVault.PHRASE_ONLY)

    @Test
    fun g2PhraseOnlyIsLockedWithThePointerAccountAndReason() {
        val ws = NoKeyGate.walletStatusFor(NoKeyGate.Gate.G2, phraseOnly) { pointer }
        assertEquals("locked", ws.getString("status"))
        assertEquals(pointer + ":default", ws.getString("accountKey"))
        assertEquals("phrase_only", ws.getString("reason"))
        assertFalse(ws.has("notReadyReason"))
    }

    @Test
    fun g2PhraseOnlyWithoutAPointerIsUnknownNotNoKeyNorLocked() {
        val ws = NoKeyGate.walletStatusFor(NoKeyGate.Gate.G2, phraseOnly) { null }
        assertEquals("not_ready", ws.getString("status"))
        assertEquals("unreadable", ws.getString("notReadyReason"))
        assertFalse(ws.has("accountKey"))
        assertFalse(ws.optString("status") == "no_key")
        assertFalse(ws.optString("status") == "locked")
    }

    @Test
    fun g2PhraseOnlyWithAnInvalidPointerIsUnknown() {
        for (bad in listOf("", "0x12", "not-an-address", "0x" + "zz".repeat(20))) {
            val ws = NoKeyGate.walletStatusFor(NoKeyGate.Gate.G2, phraseOnly) { bad }
            assertEquals("not_ready", ws.getString("status"))
            assertEquals("unreadable", ws.getString("notReadyReason"))
        }
    }

    @Test
    fun theGateG1PhraseOnlyAnswerIsUnchanged() {
        val ws = NoKeyGate.walletStatusFor(NoKeyGate.Gate.G1, phraseOnly) { error("the pointer is not read at G1") }
        assertEquals("not_ready", ws.getString("status"))
        assertEquals(NoKeyGate.NOT_READY_G1_UNINITIALIZED, ws.getString("notReadyReason"))
    }

    @Test
    fun thePointerIsReadOnlyForThePhraseOnlyG2Answer() {
        var reads = 0
        val ready = NoKeyGate.walletStatusFor(NoKeyGate.Gate.G2, NativeWalletVault.State.Ready(pointer)) {
            reads++
            null
        }
        assertEquals("unlocked", ready.getString("status"))
        val other = NoKeyGate.walletStatusFor(NoKeyGate.Gate.G2, NativeWalletVault.State.Locked("rollback_pending")) {
            reads++
            pointer
        }
        assertEquals("locked", other.getString("status"))
        assertFalse(other.has("accountKey"))
        assertFalse(other.has("reason"))
        assertEquals(0, reads)
    }

    @Test
    fun theLockedPhraseOnlyG2AnswerIsHas() {
        val ws = NoKeyGate.walletStatusFor(NoKeyGate.Gate.G2, phraseOnly) { pointer }
        val tri = NativeMnemonicTriState.classify(false, ws.getString("status"), ws.optString("notReadyReason").ifEmpty { null }, false)
        assertEquals(NativeMnemonicTriState.HAS, tri)
        assertTrue(ws.getString("accountKey").startsWith("0x"))
    }
}
