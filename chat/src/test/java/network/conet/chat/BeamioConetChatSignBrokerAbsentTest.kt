package network.conet.chat

import network.conet.chat.nativekey.NativeWalletVault
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * No held key (v187 §207.1): the answer follows the vault state. Only a confirmed absence is `no_key`; a locked vault is `locked`;
 * an unreadable, not-loaded or failed read is `not_ready`. The session alone never decides `no_key`.
 */
class BeamioConetChatSignBrokerAbsentTest {
    @Before
    fun setUp() {
        BeamioConetChatSignBroker.clearNativeSigner()
    }

    @After
    fun tearDown() {
        BeamioConetChatSignBroker.clearNativeSigner()
        BeamioConetChatSignBroker.setAbsentAnswer { BeamioConetChatSignBroker.NOT_READY }
    }

    private fun failureOf(sign: ((Result<String>) -> Unit) -> Unit): String {
        var message = ""
        sign { r -> message = r.exceptionOrNull()?.message ?: "" }
        return message
    }

    @Test
    fun theThreeVaultStatesGiveTheThreeAnswers() {
        assertEquals("no_key", BeamioConetChatSignBroker.absentAnswerOf(NativeWalletVault.State.NoKey))
        assertEquals("locked", BeamioConetChatSignBroker.absentAnswerOf(NativeWalletVault.State.Locked("record_missing")))
        assertEquals("not_ready", BeamioConetChatSignBroker.absentAnswerOf(NativeWalletVault.State.Ready("0x" + "1".repeat(40))))
    }

    @Test
    fun aNotLoadedSessionIsNotReadyNotNoKey() {
        // The session holds no key, but the vault is ready: this is not a confirmed absence, so the answer is not_ready.
        BeamioConetChatSignBroker.setAbsentAnswer { BeamioConetChatSignBroker.absentAnswerOf(NativeWalletVault.State.Ready("0x" + "1".repeat(40))) }
        val msg = failureOf { BeamioConetChatSignBroker.requestEip191("m", it) }
        assertEquals("not_ready", msg)
        assertTrue(msg != "no_key")
    }

    @Test
    fun aLockedVaultAnswersLocked() {
        BeamioConetChatSignBroker.setAbsentAnswer { BeamioConetChatSignBroker.absentAnswerOf(NativeWalletVault.State.Locked("x")) }
        assertEquals("locked", failureOf { BeamioConetChatSignBroker.requestEip191("m", it) })
    }

    @Test
    fun aConfirmedAbsenceAnswersNoKey() {
        BeamioConetChatSignBroker.setAbsentAnswer { BeamioConetChatSignBroker.absentAnswerOf(NativeWalletVault.State.NoKey) }
        assertEquals("no_key", failureOf { BeamioConetChatSignBroker.requestEip191("m", it) })
    }

    @Test
    fun aFailedReadAnswersNotReadyAndNeverNoKey() {
        BeamioConetChatSignBroker.setAbsentAnswer { throw IllegalStateException("unreadable") }
        assertEquals("not_ready", failureOf { BeamioConetChatSignBroker.requestEip191("m", it) })
    }

    @Test
    fun eip712FollowsTheSameRule() {
        BeamioConetChatSignBroker.setAbsentAnswer { BeamioConetChatSignBroker.absentAnswerOf(NativeWalletVault.State.Locked("x")) }
        assertEquals("locked", failureOf { BeamioConetChatSignBroker.requestEip712(org.json.JSONObject(), it) })
    }

    /** The snapshot is not known yet (or a write is in progress): not_ready, and the keystore is never read on this thread (review 2026-11-21). */
    @Test
    fun anUnknownSnapshotIsNotReady() {
        assertEquals("not_ready", BeamioConetChatSignBroker.absentAnswerOfSnapshot(null))
        assertEquals("no_key", BeamioConetChatSignBroker.absentAnswerOfSnapshot(NativeWalletVault.State.NoKey))
    }
}
