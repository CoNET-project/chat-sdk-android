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

    /** The restore workers answer every request once: an unreadable store is not_ready on the evaluate answer and on the restore result (25.52Y.84). */
    @Test
    fun pgpRestoreWorkersAnswerOnceWithNotReadyOnAnUnreadableStore() {
        assertTrue(module.contains("pgpRestore evaluate failed"))
        assertTrue(module.contains("answer(false, \"not_ready\")"))
        assertTrue(module.contains("pgpRestore restore failed"))
        assertTrue(module.contains("JSONObject().put(\"code\", \"not_ready\")"))
        // Each reply goes through a single-reply guard, so a failing emit is never followed by a second reply (25.52Y.84).
        assertTrue(module.contains("once.once { if (reply != null)"))
        assertTrue(module.contains("resultOnce.once { emitEvent("))
        assertTrue(module.contains("SingleReply().once { emitEvent(payload) }"))
    }

    /** The migration worker sends one result on any unreadable store: the reread code, never a success or a confirmed none. */
    @Test
    fun pgpMigrateWorkerSendsTheRereadCodeOnAnUnreadableStore() {
        assertTrue(module.contains("MigrationResult(MigrationCode.REREAD_FAILED)"))
    }

    /** The no-page listen does not start on an unreadable vault or PGP store. */
    @Test
    fun noPageListenDoesNotStartOnAnUnreadableStore() {
        assertTrue(module.contains("the listen does not start (false), never taken for an absent account"))
        assertTrue(module.contains("val pgpReady = try {"))
    }

    /** The identity-clear holds check is unknown (null) on an unreadable vault, page or keystore, so the accounts are kept. */
    @Test
    fun holdsWalletIsUnknownOnAnUnreadableVault() {
        assertTrue(module.contains(".any { vaultFiles.read(it) != null }\n        } catch (_: Exception) {\n            return null"))
    }
}
