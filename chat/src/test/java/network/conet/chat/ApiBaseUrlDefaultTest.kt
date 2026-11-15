package network.conet.chat

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * The default API base is the beamio.ca host (PM R2043, migration R2030). A value passed by `init` (payload `apiBaseUrl`) overrides the
 * default; a blank value keeps it. No other behaviour depends on this change.
 */
class ApiBaseUrlDefaultTest {
    @Test
    fun withoutAnApiBaseUrlTheDefaultIsBeamioCa() {
        assertEquals("https://beamio.ca/api", BeamioConetChatModule.Session().apiBaseUrl)
    }

    /** The init path: a passed `apiBaseUrl` wins; a blank or absent one keeps the session's value (source structure, the init path needs a Context). */
    @Test
    fun aPassedApiBaseUrlOverridesTheDefault() {
        val source = File("src/main/java/network/conet/chat/BeamioConetChatModule.kt").readText(Charsets.UTF_8)
        assertTrue(source.contains("s.apiBaseUrl = payload.optString(\"apiBaseUrl\", \"\").ifBlank { s.apiBaseUrl }"))
    }

    /** No active main code still names the old host. */
    @Test
    fun noActiveMainCodeNamesTheOldHost() {
        val root = File("src/main/java")
        val hits = root.walkTopDown().filter { it.isFile && it.extension == "kt" }
            .filter { it.readText(Charsets.UTF_8).contains("beamio.app") }
            .map { it.path }
            .toList()
        assertFalse("old host still in: $hits", hits.isNotEmpty())
    }
}
