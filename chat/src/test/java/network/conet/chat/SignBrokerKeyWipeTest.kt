package network.conet.chat

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * T-49 for the wallet key held by the sign broker (long-lived keys are ByteArray and zeroed at each clear). The
 * test reads the held buffer through the field, so the zero check looks at the bytes the broker actually kept.
 */
class SignBrokerKeyWipeTest {
    private fun heldBuffer(): ByteArray? {
        val f = BeamioConetChatSignBroker::class.java.getDeclaredField("localKey")
        f.isAccessible = true
        return f.get(BeamioConetChatSignBroker) as ByteArray?
    }

    @Test
    fun setKeepsACopyAndTheCallerBufferIsNotHeld() {
        val key = ByteArray(32) { (it + 1).toByte() }
        BeamioConetChatSignBroker.setNativeSigner(key)
        val held = heldBuffer()
        assertTrue("the broker holds a buffer", held != null)
        assertTrue("the held buffer is a copy, not the caller's array", held !== key)
        assertArrayEquals(key, held)
        BeamioConetChatSignBroker.clearNativeSigner()
    }

    @Test
    fun clearZeroesTheHeldBufferInPlaceAndDropsTheReference() {
        val key = ByteArray(32) { 0x3c }
        BeamioConetChatSignBroker.setNativeSigner(key)
        val held = heldBuffer()!!
        BeamioConetChatSignBroker.clearNativeSigner()
        assertTrue("every byte of the held key is zero after the clear", held.all { it == 0.toByte() })
        assertNull("the broker no longer holds a key", heldBuffer())
        assertTrue("no native signer is held", !BeamioConetChatSignBroker.hasNativeSigner())
    }

    @Test
    fun aReplacementZeroesThePreviousBuffer() {
        BeamioConetChatSignBroker.setNativeSigner(ByteArray(32) { 0x11 })
        val first = heldBuffer()!!
        BeamioConetChatSignBroker.setNativeSigner(ByteArray(32) { 0x22 })
        assertTrue("the replaced buffer is zero", first.all { it == 0.toByte() })
        BeamioConetChatSignBroker.clearNativeSigner()
    }
}
