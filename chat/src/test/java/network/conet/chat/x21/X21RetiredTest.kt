package network.conet.chat.x21

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** The retired X-21 command names and their single answer. */
class X21RetiredTest {
    @Test
    fun theThreeCommandNamesAreRetiredAndNothingElse() {
        assertEquals(setOf("walletTransferOnce", "walletTransferStatus", "walletTransferSwitched"), X21Retired.COMMANDS)
        assertTrue(X21Retired.handles("walletTransferOnce"))
        assertTrue(X21Retired.handles("walletTransferStatus"))
        assertTrue(X21Retired.handles("walletTransferSwitched"))
        assertFalse(X21Retired.handles("init"))
        assertFalse(X21Retired.handles("provisionIdentity"))
    }

    @Test
    fun theAnswerIsNotSupported() {
        assertEquals("not_supported", X21Retired.ERROR)
    }
}
