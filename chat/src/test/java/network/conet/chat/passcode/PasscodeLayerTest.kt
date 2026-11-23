package network.conet.chat.passcode

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** Synthetic values only: the passcode, the account and the inner bytes are test fixtures. */
class PasscodeLayerTest {
    private val eoa = "0x1111111111111111111111111111111111111111"
    private val otherEoa = "0x2222222222222222222222222222222222222222"
    private val pass = "24681357"
    private val inner = "fixture-inner-bytes".toByteArray(Charsets.UTF_8)

    @Test
    fun aSealedBlobOpensWithTheSamePasscodeSaltAndAccount() {
        val salt = PasscodeLayer.newSalt()
        val blob = PasscodeLayer.seal(pass, salt, PasscodeLayer.aadForAccountKey(eoa), inner)
        assertArrayEquals(inner, PasscodeLayer.open(pass, salt, PasscodeLayer.aadForAccountKey(eoa), blob))
    }

    @Test
    fun aWrongPasscodeDoesNotOpen() {
        val salt = PasscodeLayer.newSalt()
        val blob = PasscodeLayer.seal(pass, salt, PasscodeLayer.aadForAccountKey(eoa), inner)
        assertNull(PasscodeLayer.open("13572468", salt, PasscodeLayer.aadForAccountKey(eoa), blob))
    }

    @Test
    fun aBlobMovedToAnotherAccountDoesNotOpen() {
        val salt = PasscodeLayer.newSalt()
        val blob = PasscodeLayer.seal(pass, salt, PasscodeLayer.aadForAccountKey(eoa), inner)
        assertNull(PasscodeLayer.open(pass, salt, PasscodeLayer.aadForAccountKey(otherEoa), blob))
    }

    @Test
    fun thePhraseAadIsDistinctFromTheAccountKeyAad() {
        val salt = PasscodeLayer.newSalt()
        val blob = PasscodeLayer.seal(pass, salt, PasscodeLayer.aadForAccountKey(eoa), inner)
        assertNull("a phrase blob cannot be read as the account key", PasscodeLayer.open(pass, salt, PasscodeLayer.aadForPhrase(eoa), blob))
    }

    @Test
    fun aTamperedBlobDoesNotOpen() {
        val salt = PasscodeLayer.newSalt()
        val blob = PasscodeLayer.seal(pass, salt, PasscodeLayer.aadForAccountKey(eoa), inner)
        blob[blob.size - 1] = (blob[blob.size - 1].toInt() xor 1).toByte()
        assertNull(PasscodeLayer.open(pass, salt, PasscodeLayer.aadForAccountKey(eoa), blob))
    }

    @Test
    fun theLayoutAndSaltAreTheSpecifiedOnes() {
        val salt = PasscodeLayer.newSalt()
        assertEquals(16, salt.size)
        val blob = PasscodeLayer.seal(pass, salt, PasscodeLayer.aadForAccountKey(eoa), inner)
        assertEquals(PasscodeLayer.IV_BYTES + inner.size + PasscodeLayer.TAG_BITS / 8, blob.size)
    }

    @Test
    fun everyWriteUsesANewSaltAndIv() {
        val salt1 = PasscodeLayer.newSalt()
        val salt2 = PasscodeLayer.newSalt()
        assertNotEquals(salt1.toList(), salt2.toList())
        val b1 = PasscodeLayer.seal(pass, salt1, PasscodeLayer.aadForAccountKey(eoa), inner)
        val b2 = PasscodeLayer.seal(pass, salt1, PasscodeLayer.aadForAccountKey(eoa), inner)
        assertNotEquals("the IV is random per seal", b1.toList(), b2.toList())
    }
}
