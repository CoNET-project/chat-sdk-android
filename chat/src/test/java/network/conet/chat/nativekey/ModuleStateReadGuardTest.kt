package network.conet.chat.nativekey

import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * The module's direct vault reads (Y.104 第 3 条, Y.106; the outer handlers of 25.52Y.84): a vault that cannot be read answers not_ready for the
 * request, once, and never no_key. The module cannot be built on the JVM, so the source of the two handlers is checked for the mapping.
 */
class ModuleStateReadGuardTest {
    private val module = File("src/main/java/network/conet/chat/BeamioConetChatModule.kt").readText(Charsets.UTF_8)

    @Test
    fun pgpRestoreAnswersNotReadyWhenTheVaultCannotBeRead() {
        assertTrue(module.contains("NativeWallet.vault(ctx).state()\n        } catch (_: Exception) {\n            return answer(false, \"not_ready\")"))
    }

    @Test
    fun pgpMigrateAnswersNotReadyWhenTheVaultCannotBeRead() {
        assertTrue(module.contains("ctx?.let { NativeWallet.vault(it).state() }\n        } catch (_: Exception) {\n            return answer(false, \"not_ready\")"))
    }
}
