package network.conet.chat

import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Source guard: every legacy adoption call in the module (NativeWallet.migrateLegacy and migrateLegacyPgp) must sit inside a
 * try or runCatching, so an unreadable stored state never escapes a command or the start path.
 */
class MigrateCallSitesGuardTest {

    @Test
    fun everyLegacyAdoptionCallInTheModuleIsGuarded() {
        val lines = File("src/main/java/network/conet/chat/BeamioConetChatModule.kt").readLines()
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
}
