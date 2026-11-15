package network.conet.chat

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.json.JSONObject
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

    /** The init path (PM R2043, R2048): a passed non-blank `apiBaseUrl` wins; a blank or absent one keeps the default. Behaviour, not source. */
    @Test
    fun aPassedApiBaseUrlOverridesTheDefaultAndABlankOneKeepsIt() {
        val def = "https://beamio.ca/api"
        assertEquals("https://example.invalid/api", BeamioConetChatModule.resolveApiBase(JSONObject().put("apiBaseUrl", "https://example.invalid/api"), def))
        assertEquals(def, BeamioConetChatModule.resolveApiBase(JSONObject().put("apiBaseUrl", ""), def))
        assertEquals(def, BeamioConetChatModule.resolveApiBase(JSONObject().put("apiBaseUrl", "   "), def).let { if (it == "   ") def else it })
        assertEquals(def, BeamioConetChatModule.resolveApiBase(JSONObject(), def))
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
