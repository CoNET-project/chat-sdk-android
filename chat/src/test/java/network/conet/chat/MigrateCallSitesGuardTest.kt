package network.conet.chat

import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Source guards on the module. Every legacy adoption call (NativeWallet.migrateLegacy and migrateLegacyPgp) must sit inside a
 * try or runCatching, so an unreadable stored state never escapes a command or the start path. The derivation read of the
 * vault is guarded too: an unreadable vault there is locked.
 */
class MigrateCallSitesGuardTest {

    private val module = File("src/main/java/network/conet/chat/BeamioConetChatModule.kt").readText(Charsets.UTF_8)

    @Test
    fun everyLegacyAdoptionCallInTheModuleIsGuarded() {
        val lines = module.lines()
        val calls = lines.indices.filter { Regex("""NativeWallet\.migrateLegacy(Pgp)?\(""").containsMatchIn(lines[it]) }
        assertTrue("expected the module to call the legacy adoptions", calls.size >= 4)
        for (i in calls) {
            val window = lines.subList(maxOf(0, i - 3), i + 1).joinToString("\n")
            assertTrue(
                "unguarded legacy adoption at line ${i + 1}: ${lines[i].trim()}",
                window.contains("runCatching") || window.contains("try {"),
            )
        }
    }

    @Test
    fun theDerivationVaultReadsAreGuarded() {
        assertTrue(module.contains("(try { vault.state() } catch (_: Exception) { null }) as? NativeWalletVault.State.Ready"))
        assertTrue(module.contains("(try { vault.unlock() } catch (_: Exception) { null }) ?: return locked"))
    }
}
