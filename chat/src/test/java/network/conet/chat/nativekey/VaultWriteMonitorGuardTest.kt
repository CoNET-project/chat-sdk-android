package network.conet.chat.nativekey

import java.io.File
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Guard: the vault's public write entry points carry @Synchronized, so the wallet-file removal, which takes the same monitor, is
 * serialized with them. This checks the listed entry points by text; it is not an exhaustive call-graph proof. A refactor that drops the annotation fails here.
 */
class VaultWriteMonitorGuardTest {
    private val src = File("src/main/java/network/conet/chat/nativekey/NativeWalletVault.kt").readText(Charsets.UTF_8)

    private fun annotatedBefore(fn: String): Boolean {
        val at = src.indexOf("fun $fn(")
        assertTrue("$fn is declared", at >= 0)
        val before = src.substring(0, at).trimEnd()
        // A private entry (syncPhraseLocked) carries its modifier between the annotation and `fun`.
        return before.removeSuffix("private").trimEnd().endsWith("@Synchronized")
    }

    @Test
    fun theVaultWriteEntryPointsAreSynchronized() {
        for (fn in listOf("importKey", "importMnemonicKey", "syncPhraseLocked", "discardPrivateOnly", "completeDiscardAtStartup")) {
            assertTrue("$fn must carry @Synchronized (the wallet-file removal takes the same monitor)", annotatedBefore(fn))
        }
    }

    @Test
    fun theUnlockedSyncPhraseEntryOnlyChecksItsInputAndDelegatesToTheLockedOne() {
        val body = src.substringAfter("    fun syncPhrase(").substringBefore("    /** The control files whose change")
        assertTrue("it calls the locked entry", body.contains("syncPhraseLocked("))
        for (h in listOf("store(", "storeWrite(", "writeFresh(", "writeNewSlot(", "replaceWithIsolation(", "importMnemonicKey(", "importKey(", "settleForWrite(", "snapshot = null")) {
            assertTrue("the unlocked entry does not call $h", !body.contains(h))
        }
    }

    /**
     * The internal write helpers, and the only functions that may call them: the @Synchronized entry points, and the helpers themselves (and the local
     * function sealFailed, nested in writeNewSlot). A call from any other function fails this guard. Text-based, not a call-graph proof.
     */
    @Test
    fun theInternalWriteHelpersAreCalledOnlyFromTheSynchronizedEntries() {
        val helpers = listOf("store", "storeWrite", "writeFresh", "writeNewSlot", "replaceWithIsolation")
        // SyncPhrase checks its input outside the monitor and then calls syncPhraseLocked, the @Synchronized entry that holds every write.
        val allowed = setOf("importKey", "importMnemonicKey", "syncPhraseLocked") + helpers + "sealFailed"
        val lines = src.split("\n")
        val funRe = Regex("""fun (\w+)\(""")
        for (h in helpers) {
            val callRe = Regex("""(?<![\w.])${h}\(""")
            for ((i, line) in lines.withIndex()) {
                if (funRe.containsMatchIn(line) && line.contains("fun $h(")) continue
                if (!callRe.containsMatchIn(line) || line.contains("fun $h(")) continue
                var enclosing: String? = null
                for (j in i downTo 0) {
                    val m = funRe.find(lines[j])
                    if (m != null) { enclosing = m.groupValues[1]; break }
                }
                assertTrue("$h is called from ${enclosing} (line ${i + 1}), which is not an allowed entry", enclosing != null && enclosing in allowed)
            }
        }
    }
}
