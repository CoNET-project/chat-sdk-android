package network.conet.chat.nativekey

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * 2026-11-22 (same as iOS ): the pre-upgrade wallet key (`BeamioChatWalletKeyStore`, shipped data) is never
 * read into the vault, never removed, and is not a basis for the account. Source guards on the adoption, plus the behaviour of the gate.
 */
class LegacyWalletKeyStopTest {

    private val wallet = File("src/main/java/network/conet/chat/nativekey/AndroidNativeWallet.kt").readText(Charsets.UTF_8)

    /** The body of migrateLegacyOutcome, from its signature to the next top-level member. */
    private val outcome: String = wallet.substringAfter("private fun migrateLegacyOutcome(app: Context): MigrationGate.Outcome")
        .substringBefore("\n    /**")

    /** Positive: the stopped adoption resolves to nothing, so the vault is left as it is. */
    @Test
    fun theLegacyAdoptionResolvesToNothing() {
        assertTrue("migrateLegacyOutcome must return RESOLVED_NOTHING", outcome.contains("MigrationGate.Outcome.RESOLVED_NOTHING"))
    }

    /** Negative: the shipped wallet key is never read, imported, or removed by the adoption. */
    @Test
    fun theLegacyWalletKeyIsNeverReadImportedOrRemoved() {
        assertFalse("no read of the legacy store", outcome.contains("BeamioChatWalletKeyStore.load"))
        assertFalse("no import into the vault", outcome.contains("importKey"))
        assertFalse("no removal of the legacy store", outcome.contains("BeamioChatWalletKeyStore.clear"))
        assertFalse("the adoption outcome never reports adopted", outcome.contains("RESOLVED_ADOPTED"))
    }
}
