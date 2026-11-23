package network.conet.chat.nativekey

import java.io.File
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * F1 (2026-11-20): the snapshot is cleared by refreshVaultSnapshotAfterLegacy. It must run only when a legacy adoption
 * actually wrote something. An unsettled gate (no key yet, retry window, unknown result) must not clear the snapshot on every command,
 * or walletStatus reads an empty snapshot and answers not_ready forever (EVIDENCE-fresh-install-nokey-2026-11-20.md).
 * Source guards (the same convention as LegacyAdoptionAsyncTest).
 */
class LegacyAdoptionRefreshTest {
    private val wallet: String by lazy {
        File("src/main/java/network/conet/chat/nativekey/AndroidNativeWallet.kt").readText(Charsets.UTF_8)
    }

    private fun body(src: String, header: String, nextHeader: String): String =
        src.substringAfter(header).substringBefore(nextHeader)

    @Test
    fun migrateLegacyRefreshesOnlyWhenItAdopted() {
        val fn = body(wallet, "fun migrateLegacy(context: Context): Boolean {", "/** True when the once-per-process")
        assertTrue("the refresh is conditional on the adoption result", fn.contains(".also { if (it) refreshVaultSnapshotAfterLegacy(app) }"))
        assertFalse("no unconditional refresh after the wallet gate", fn.contains(".also { refreshVaultSnapshotAfterLegacy(app) }"))
    }

    @Test
    fun migrateLegacyPgpRefreshesOnlyWhenItAdopted() {
        val fn = body(wallet, "fun migrateLegacyPgp(context: Context): Boolean {", "private fun migrateLegacyPgpOutcome")
        assertTrue("the refresh is conditional on the adoption result", fn.contains(".also { if (it) refreshVaultSnapshotAfterLegacy(app) }"))
        assertFalse("no unconditional refresh after the PGP gate", fn.contains(".also { refreshVaultSnapshotAfterLegacy(app) }"))
    }

    @Test
    fun theScheduledAdoptionRefreshesOnlyWhenAnyGateAdopted() {
        val fn = body(wallet, "private fun scheduleLegacyAdoptionOffMain(app: Context) {", "private fun refreshVaultSnapshotAfterLegacy")
        assertTrue("both gates are run and their results kept", fn.contains("val walletAdopted = legacyGate.run") && fn.contains("val pgpAdopted = legacyPgpGate.run"))
        assertTrue("the refresh needs an adoption", fn.contains("if (walletAdopted || pgpAdopted) refreshVaultSnapshotAfterLegacy(app)"))
    }
}
