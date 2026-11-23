package network.conet.chat.passcode

import java.io.File
import network.conet.chat.BridgeCommandTable
import network.conet.chat.nativekey.NoKeyGate
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Negative tests (high-priority defect, 2026-11-20): `incomingCallBind` and `incomingCallUnbind` are native calls of the shell, not bridge
 * commands. A page that sends either name through the bridge must be refused in every state, including locked. These tests fail if either name
 * is ever registered in a bridge table, the allowlist, or the dispatch source.
 */
class IncomingCallNotBridgeTest {
    private val names = listOf("incomingCallBind", "incomingCallUnbind", "incomingCallAuthorizeAnswer")

    private val mainSources: List<File> by lazy {
        File("src/main/java").walkTopDown().filter { it.isFile && it.extension == "kt" }.toList()
    }

    @Test
    fun neitherNameIsARegisteredBridgeCommand() {
        for (name in names) {
            assertFalse("$name must not be a bridge command", BridgeCommandTable.isRegistered(name))
        }
    }

    @Test
    fun neitherNameIsInAnyBridgeTable() {
        for (name in names) {
            assertFalse(name in BridgeCommandTable.DISPATCH)
            assertFalse(name in BridgeCommandTable.DECIDED_BEFORE_DISPATCH)
            assertFalse(name in BridgeCommandTable.GATE_STATUS)
            assertFalse(name in NoKeyGate.RETIRED)
            assertFalse(name in BridgeCommandTable.CHAT_CHANNEL_SHELL_RECORD)
            assertFalse(name in BridgeCommandTable.WINDOW_CHANNEL)
        }
    }

    @Test
    fun theFieldAllowlistOfPasscodeUnlockDoesNotAdmitTheseNames() {
        for (name in names) {
            assertFalse("$name must not be an allowed field", name in PasscodeUnlockEntry.ALLOWED_FIELDS)
        }
    }

    @Test
    fun noMainSourceRegistersTheNamesAsAString() {
        // A string literal of either name would mean a dispatch, a table or a whitelist entry. Only this kind of literal is checked: the Kotlin
        // functions are named bind and unbind, and no source file may name them as bridge commands.
        val hits = mainSources.filter { f -> names.any { f.readText(Charsets.UTF_8).contains("\"$it\"") } }
        assertTrue("no main source may register the names as bridge commands: ${hits.map { it.path }}", hits.isEmpty())
    }
}
