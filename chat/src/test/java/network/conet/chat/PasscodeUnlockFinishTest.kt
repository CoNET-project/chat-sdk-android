package network.conet.chat

import network.conet.chat.nativekey.MnemonicDerivation
import network.conet.chat.nativekey.NativeSessionState
import network.conet.chat.nativekey.WalletAddress
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * after a verified passcode unlock, the native session must be ready for the eoa before the UI gate is set. A phrase that does
 * not derive to the eoa, or cannot be derived, answers not_ready and leaves the gate unset. The phrase is the BIP-39 test phrase (no real funds).
 */
class PasscodeUnlockFinishTest {
    private val phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    private val eoa: String = checkNotNull(WalletAddress.fromPrivateKey(checkNotNull(MnemonicDerivation.deriveKey(phrase)))).lowercase()
    private val otherEoa = "0x0cf9000000000000000000000000000000002022"

    @Before
    fun setUp() {
        NativeSessionState.reset()
    }

    @After
    fun tearDown() {
        NativeSessionState.reset()
    }

    @Test
    fun aPhraseThatDoesNotDeriveToTheEoaAnswersNotReadyAndLeavesTheSessionUnset() {
        val r = BeamioConetChatModule.finishUnlock(otherEoa, phrase.toByteArray(Charsets.UTF_8), "call-finish-0001")
        assertFalse(r.ok)
        assertEquals("not_ready", r.error)
        assertFalse(NativeSessionState.isReadyFor(otherEoa))
    }

    @Test
    fun aPhraseThatCannotBeDerivedAnswersNotReadyAndLeavesTheSessionUnset() {
        val r = BeamioConetChatModule.finishUnlock(eoa, "not a valid mnemonic phrase".toByteArray(Charsets.UTF_8), "call-finish-0002")
        assertFalse(r.ok)
        assertEquals("not_ready", r.error)
        assertFalse(NativeSessionState.isReadyFor(eoa))
    }

    @Test
    fun aMatchingPhraseMarksTheSessionReady() {
        val r = BeamioConetChatModule.finishUnlock(eoa, phrase.toByteArray(Charsets.UTF_8), "call-finish-0003")
        assertTrue(r.ok)
        assertEquals(eoa, r.result?.getString("eoa"))
        assertTrue(NativeSessionState.isReadyFor(eoa))
    }
}
