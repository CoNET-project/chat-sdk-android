package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Test
import java.io.IOException

/**
 * The public migration state never reports an unknown account as absent: a locked account throws, and only a confirmed absent
 * account is `none` (25.52Y.84).
 */
class ShellRecordMigrationStateTest {

    @Test
    fun aLockedAccountIsUnknownAndThrows() {
        var pgpRead = false
        try {
            migrationStateOfVault(NativeWalletVault.State.Locked("record_missing")) {
                pgpRead = true
                "pending"
            }
            fail("a locked account must not read as a migration state")
        } catch (expected: IOException) {
            // expected: unknown, not "none"
        }
        assertEquals(false, pgpRead)
    }

    @Test
    fun aConfirmedAbsentAccountIsNone() {
        var pgpRead = false
        val state = migrationStateOfVault(NativeWalletVault.State.NoKey) {
            pgpRead = true
            "pending"
        }
        assertEquals("none", state)
        assertEquals(false, pgpRead)
    }

    @Test
    fun aReadyAccountTakesThePgpMigrationState() {
        val state = migrationStateOfVault(NativeWalletVault.State.Ready("0xabc")) { eoa ->
            assertEquals("0xabc", eoa)
            "verified"
        }
        assertEquals("verified", state)
    }
}
