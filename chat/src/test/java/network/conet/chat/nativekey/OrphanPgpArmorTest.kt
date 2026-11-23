package network.conet.chat.nativekey

import java.io.File
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * F3 (2026-11-20): an orphan legacy PGP armor with a confirmed no-wallet state settles, and the armor is kept as it
 * is: the adoption path never clears, rewrites or adopts it on that path. Source guards; the decision is in PgpPrecheckBehaviourTest.
 */
class OrphanPgpArmorTest {
    private val body: String by lazy {
        File("src/main/java/network/conet/chat/nativekey/AndroidNativeWallet.kt").readText(Charsets.UTF_8)
            .substringAfter("private fun migrateLegacyPgpOutcome(app: Context): MigrationGate.Outcome {")
            .substringBefore("\n    }\n")
    }

    @Test
    fun theNoWalletSettleComesBeforeAnyPgpWrite() {
        val precheck = body.indexOf("legacyPgpPrecheck(armorRead")
        assertTrue("the precheck exists", precheck > 0)
        // 2026-11-22: the adoption writes no PGP record at all (no put into the native vault).
        assertFalse("no PGP write on the adoption path", body.contains("pgpVault.put("))
    }

    @Test
    fun theArmorIsNeverClearedOrRewrittenByTheAdoptionPath() {
        assertFalse("no legacy armor removal", body.contains("clearLegacyPrivateArmor") || body.contains("clearLegacyRecord"))
        assertFalse("no legacy armor clear", body.contains("BeamioChatPgpStore.clear"))
    }

    @Test
    fun aWalletReadFailureIsNotCaughtAsNothing() {
        val beforeRead = body.substring(0, body.indexOf("noWalletConfirmed = {"))
        assertFalse("no catch before the wallet read", beforeRead.contains("catch ("))
        assertFalse("no runCatching before the wallet read", beforeRead.contains("runCatching"))
    }
}
