package network.conet.chat.nativekey

import java.io.File
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * F2 and F3 (2026-11-20): the legacy PGP adoption reads the armor strictly, runs the precheck before the wallet dependency, and never
 * clears or rewrites the legacy armor on the settle path. Source guards on the function body; the behaviour is in PgpPrecheckBehaviourTest.
 */
class PgpAdoptionArmorFirstTest {
    private val outcome: String by lazy {
        File("src/main/java/network/conet/chat/nativekey/AndroidNativeWallet.kt").readText(Charsets.UTF_8)
            .substringAfter("private fun migrateLegacyPgpOutcome(app: Context): MigrationGate.Outcome {")
            .substringBefore("\n    }\n")
    }

    @Test
    fun theArmorIsReadStrictlyBeforeAnyWalletDependency() {
        val strict = outcome.indexOf("BeamioChatPgpStore.legacyPrivateArmorStrict(app)")
        val precheck = outcome.indexOf("legacyPgpPrecheck(armorRead")
        val walletDependency = outcome.indexOf("legacyAdoptionEoa(")
        assertTrue("the strict read exists", strict > 0)
        // 2026-11-22: the stopped adoption has no wallet dependency; the precheck follows the strict read.
        assertTrue("the precheck follows the strict read", strict < precheck)
        assertTrue("no wallet EOA dependency on the stopped adoption", walletDependency < 0)
        assertFalse("no lenient read on this path", outcome.contains("BeamioChatPgpStore.legacyPrivateArmor(app)"))
    }

    @Test
    fun aNullArmorDoesNotSettleAsNothing() {
        // The armor value used for the adoption is the one the precheck accepted (not null).
        assertTrue("the armor is unwrapped or unknown, never defaulted to empty", outcome.contains("if (armorRead == null) return MigrationGate.Outcome.UNKNOWN"))
    }
}
