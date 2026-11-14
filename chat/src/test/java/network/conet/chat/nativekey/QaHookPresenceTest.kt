package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test
import java.io.File

/**
 * HK-01 to HK-03 (spec §25.52AA.5): the QA hook exists only in a QA build (`-PchatQaHooks`); the production build has no such class; and no
 * bridge or main source refers to it.
 */
class QaHookPresenceTest {
    private val qaBuild = System.getProperty("chatQaHooks") != null

    private fun hookPresent(): Boolean = try {
        Class.forName("network.conet.chat.nativekey.NativeQaHooks")
        true
    } catch (_: ClassNotFoundException) {
        false
    }

    @Test
    fun hk01AndHk02TheHookExistsOnlyInTheQaBuild() {
        assertEquals("the hook is present exactly in the QA build", qaBuild, hookPresent())
    }

    @Test
    fun hk03TheHookIsNotReferencedFromAnyBridgeOrMainSource() {
        val main = File("src/main/java")
        val refs = main.walkTopDown().filter { it.isFile && it.name.endsWith(".kt") }
            .filter { it.readText().contains("NativeQaHooks") || it.readText().contains("dropEoaKey") }
            .map { it.name }
            .toList()
        assertFalse("no main source names the hook: $refs", refs.isNotEmpty())
    }
}
