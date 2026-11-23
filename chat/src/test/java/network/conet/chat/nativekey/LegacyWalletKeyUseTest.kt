package network.conet.chat.nativekey

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * 2026-11-22: the shipped wallet key (BeamioChatWalletKeyStore) and the shipped PGP store are kept as they are. No chat or signing path
 * reads the wallet key (the PWA's first sync is the source; the old copy is read-only and not a basis for the account). The identity clear
 * never removes either store. Source guards: the module and the adoption (the stores themselves need an Android Context).
 */
class LegacyWalletKeyUseTest {

    private val wallet = File("src/main/java/network/conet/chat/nativekey/AndroidNativeWallet.kt").readText(Charsets.UTF_8)
    private val module = File("src/main/java/network/conet/chat/BeamioConetChatModule.kt").readText(Charsets.UTF_8)

    /** Negative: the adoption imports nothing into the vault and removes nothing. */
    @Test
    fun theAdoptionCreatesNoVaultRecordAndRemovesNothing() {
        val body = wallet.substringAfter("private fun migrateLegacyOutcome(app: Context): MigrationGate.Outcome").substringBefore("\n    /**")
        assertFalse(body.contains("importKey"))
        assertFalse(body.contains("BeamioChatWalletKeyStore.clear"))
        assertFalse(body.contains("BeamioChatWalletKeyStore.load"))
    }

    /** Negative: no chat listen, init, or signing path reads the shipped wallet key (2026-11-22: the fallback is not added). */
    @Test
    fun noChatOrSigningPathReadsTheShippedWalletKey() {
        assertFalse("no read of the shipped wallet key in the module", module.contains("BeamioChatWalletKeyStore.load("))
        assertFalse("no read-only fallback in the module", module.contains("LegacyWalletKeyReader"))
    }

    /** Positive: the identity clear never removes the shipped wallet key, and keeps the shipped PGP store. */
    @Test
    fun theIdentityClearKeepsBothShippedStores() {
        assertFalse("no clear of the shipped wallet key anywhere in the module", module.contains("BeamioChatWalletKeyStore.clear("))
        assertTrue("the identity clear keeps the wallet store", module.contains("val keystoreOk = true"))
        assertFalse("B4: the identity clear does not call clearKeepingLegacy", module.contains("clearKeepingLegacy"))
    }
}
