package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Test
import java.io.IOException

/**
 * Preconditions of the legacy PGP adoption. A stored read that cannot be made is unknown: the adoption is refused, and the
 * PGP state is not read when the wallet state is unknown.
 */
class LegacyAdoptionTest {

    @Test
    fun anUnreadableWalletStateRefusesAndThePgpStateIsNotRead() {
        var pgpRead = false
        val eoa = legacyAdoptionEoa(
            readWalletEoa = { throw IOException("vault state unreadable") },
            readPgpIsNoKey = {
                pgpRead = true
                true
            },
        )
        assertNull(eoa)
        assertFalse(pgpRead)
    }

    @Test
    fun anUnreadablePgpStateRefuses() {
        val eoa = legacyAdoptionEoa(
            readWalletEoa = { "0xabc" },
            readPgpIsNoKey = { throw IOException("pgp state unreadable") },
        )
        assertNull(eoa)
    }

    @Test
    fun noReadyWalletRefuses() {
        val eoa = legacyAdoptionEoa(readWalletEoa = { null }, readPgpIsNoKey = { true })
        assertNull(eoa)
    }

    @Test
    fun aPgpKeyAlreadyPresentRefuses() {
        val eoa = legacyAdoptionEoa(readWalletEoa = { "0xabc" }, readPgpIsNoKey = { false })
        assertNull(eoa)
    }

    @Test
    fun aReadyWalletWithoutAPgpKeyAdopts() {
        val eoa = legacyAdoptionEoa(readWalletEoa = { "0xabc" }, readPgpIsNoKey = { true })
        assertEquals("0xabc", eoa)
    }
}
